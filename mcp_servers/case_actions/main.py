"""case_actions MCP server — wraps the case_actions mock API (US-016).

Three write-path tools — ``create_sar_draft``, ``freeze_account``,
``escalate_to_l3`` — backed by ``mock_apis.case_actions``. **The only
write-path MCP server in the stack.**

The defining feature of this server is the **human-approval gate**: every
tool call requires the calling PASETO to carry ``human_approval=true``.
Without it, the call is denied with ``deny_reason=human_approval_required``
before any tool dispatch happens. This is the single PRD-mandated check
that distinguishes case_actions from the five read-only servers:

* The check uses the shared factory's ``extra_validate`` hook
  (``mcp_servers/_common.py``), which runs after PASETO verify and before
  any tool dispatch. The hook receives the verified ``Claims`` and returns
  either ``None`` (allow) or a ``JSONResponse`` (deny).
* The minted service-to-service PASETO from the MCP gateway propagates the
  user's ``human_approval`` claim unchanged (US-007). So the L3 admin must
  have an approved token to even reach this server's tools.

The JSON-RPC + PASETO pipeline lives in ``mcp_servers/_common.py``; this
module declares the tool registry, the human-approval check, and wires the
factory.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastmcp import FastMCP

from gateways.common.paseto import Claims
from mcp_servers._common import JsonRpc, create_jsonrpc_app

__all__ = [
    "DEFAULT_API_URL",
    "HUMAN_APPROVAL_REQUIRED",
    "SERVER_NAME",
    "TOOL_NAMES",
    "build_default_app",
    "build_mcp",
    "create_app",
    "deny_if_missing_human_approval",
]

DEFAULT_API_URL = "http://localhost:8012"
SERVER_NAME = "case_actions"
TOOL_NAMES: tuple[str, ...] = (
    "create_sar_draft",
    "freeze_account",
    "escalate_to_l3",
)

# Deny-reason taxonomy. Matches gateways.mcp.DenyReason.HUMAN_APPROVAL_REQUIRED
# so the audit row + the Grafana dashboard (US-023) group on the same code.
HUMAN_APPROVAL_REQUIRED = "human_approval_required"


# --------------------------------------------------------------------------- #
# The human-approval gate                                                     #
# --------------------------------------------------------------------------- #


def deny_if_missing_human_approval(claims: Claims) -> JSONResponse | None:
    """Return a 403 deny response when ``claims.human_approval`` is not true.

    The shared factory's ``extra_validate`` hook calls this after PASETO
    verify, before any tool dispatch. The check is the **whole point** of
    case_actions: write-path actions require explicit human approval
    embedded in the calling PASETO. The MCP gateway propagates the claim
    unchanged on the service-to-service token (US-007), so an L3 admin
    must have an approved user token to reach these tools.
    """
    if claims.human_approval is True:
        return None
    return JSONResponse(
        JsonRpc.error(
            None,
            JsonRpc.INVALID_REQUEST,
            "human approval required for case_actions tools",
            data={"deny_reason": HUMAN_APPROVAL_REQUIRED},
        ),
        status_code=403,
    )


# --------------------------------------------------------------------------- #
# Tool registry                                                               #
# --------------------------------------------------------------------------- #


def build_mcp(api_client: httpx.AsyncClient) -> FastMCP:
    """Construct the FastMCP instance with the three write-path tools."""
    mcp: FastMCP = FastMCP(name=SERVER_NAME)

    @mcp.tool(
        name="create_sar_draft",
        description=(
            "Create a draft Suspicious Activity Report (SAR) for a "
            "customer. Returns {draft_id, customer_id, narrative, "
            "typology, related_accounts, status, content_hash}. **Write "
            "operation** — requires human_approval=true on the calling "
            "PASETO."
        ),
    )
    async def create_sar_draft(
        customer_id: str,
        narrative: str,
        typology: str,
        related_accounts: list[str] | None = None,
    ) -> dict[str, Any]:
        return await _post_json(
            api_client,
            "/sar-drafts",
            {
                "customer_id": customer_id,
                "narrative": narrative,
                "typology": typology,
                "related_accounts": list(related_accounts or []),
            },
        )

    @mcp.tool(
        name="freeze_account",
        description=(
            "Freeze the named account pending investigation. Returns "
            "{freeze_id, account_id, reason, requested_by, status, "
            "content_hash}. **Write operation** — requires "
            "human_approval=true on the calling PASETO."
        ),
    )
    async def freeze_account(
        account_id: str, reason: str, requested_by: str
    ) -> dict[str, Any]:
        return await _post_json(
            api_client,
            "/accounts/freeze",
            {
                "account_id": account_id,
                "reason": reason,
                "requested_by": requested_by,
            },
        )

    @mcp.tool(
        name="escalate_to_l3",
        description=(
            "Escalate a case to an L3 reviewer. Returns {escalation_id, "
            "case_id, summary, severity, requested_by, status, "
            "content_hash}. **Write operation** — requires "
            "human_approval=true on the calling PASETO."
        ),
    )
    async def escalate_to_l3(
        case_id: str, summary: str, severity: str, requested_by: str
    ) -> dict[str, Any]:
        return await _post_json(
            api_client,
            "/escalations",
            {
                "case_id": case_id,
                "summary": summary,
                "severity": severity,
                "requested_by": requested_by,
            },
        )

    return mcp


async def _post_json(
    client: httpx.AsyncClient, path: str, body: dict[str, Any]
) -> dict[str, Any]:
    resp = await client.post(path, json=body)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise RuntimeError(
            f"case_actions mock returned non-object payload: {data!r}"
        )
    return data


# --------------------------------------------------------------------------- #
# FastAPI app factory                                                         #
# --------------------------------------------------------------------------- #


def create_app(
    *,
    public_key_path: Path | str,
    api_base_url: str = DEFAULT_API_URL,
    api_client: httpx.AsyncClient | None = None,
    request_timeout_seconds: float = 10.0,
) -> FastAPI:
    """Build the case_actions MCP server FastAPI app.

    Args:
        public_key_path: PEM file holding the service-to-service PASETO
            public key.
        api_base_url: Base URL of the case_actions mock API. Ignored when
            ``api_client`` is provided.
        api_client: Optional pre-built ``httpx.AsyncClient`` for the mock.
        request_timeout_seconds: Timeout for the upstream HTTP call.
    """
    return create_jsonrpc_app(
        server_name=SERVER_NAME,
        title="case_actions MCP server",
        description=(
            "Downstream MCP server for the case_actions mock API. Speaks "
            "JSON-RPC 2.0 (tools/list, tools/call) over HTTP, validates "
            "service-to-service PASETOs, and enforces a human-approval "
            "gate (human_approval=true claim required) on every tool call."
        ),
        mcp_factory=build_mcp,
        public_key_path=public_key_path,
        api_base_url=api_base_url,
        api_client=api_client,
        request_timeout_seconds=request_timeout_seconds,
        extra_validate=deny_if_missing_human_approval,
    )


def build_default_app() -> FastAPI:
    """Construct the server from env vars (production entry point).

    Env vars:
        ``CASE_ACTIONS_MCP_PUBLIC_KEY``: PEM path with the service PASETO
            public key (the matching private key lives in
            ``MCP_GATEWAY_SERVICE_PRIVATE_KEY`` on the gateway side).
        ``CASE_ACTIONS_API_URL``: Base URL of the case_actions mock API
            (defaults to ``http://localhost:8012``).
    """
    pub = os.environ.get("CASE_ACTIONS_MCP_PUBLIC_KEY", "")
    if not pub:
        raise RuntimeError(
            "CASE_ACTIONS_MCP_PUBLIC_KEY not configured (path to the "
            "service PASETO public key PEM)."
        )
    api_url = os.environ.get("CASE_ACTIONS_API_URL", DEFAULT_API_URL)
    return create_app(public_key_path=Path(pub), api_base_url=api_url)
