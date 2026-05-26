"""OSINT MCP server — wraps the osint mock API (US-015).

Three tools — ``web_search``, ``fetch_page``, ``lookup_company`` — backed
by ``mock_apis.osint``.

The defining feature of this server is the **outbound allowlist**: any URL
``fetch_page`` is asked to retrieve must have a host on the configured
allowlist, otherwise the call is denied. The allowlist comes from the
``OSINT_ALLOWLIST`` environment variable as a comma-separated list of
hostnames (e.g. ``OSINT_ALLOWLIST=ofac.example,sec.example``). The default
is **empty**, so by default every ``fetch_page`` call is blocked — this is
deliberate. Operators must opt-in to specific upstream sources.

The block decision happens **before** any upstream HTTP call is made; the
mock never has a chance to manufacture the page. The deny is returned via
the standard JSON-RPC error shape with
``error.data.deny_reason="domain_not_allowed"`` so the MCP gateway's audit
row (US-006/US-007) can group on the same deny-reason taxonomy that
``gateways.mcp.DenyReason`` uses.

The JSON-RPC + PASETO pipeline lives in ``mcp_servers/_common.py``; this
module declares the tool registry, the allowlist check, and wires the
factory.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI
from fastmcp import FastMCP

from mcp_servers._common import ToolDispatchError, create_jsonrpc_app

__all__ = [
    "DEFAULT_API_URL",
    "SERVER_NAME",
    "TOOL_NAMES",
    "build_default_app",
    "build_mcp",
    "create_app",
    "is_url_allowed",
    "parse_allowlist",
]

_LOG = logging.getLogger(__name__)

DEFAULT_API_URL = "http://localhost:8010"
SERVER_NAME = "osint"
TOOL_NAMES: tuple[str, ...] = (
    "web_search",
    "fetch_page",
    "lookup_company",
)


# --------------------------------------------------------------------------- #
# Allowlist                                                                   #
# --------------------------------------------------------------------------- #


def parse_allowlist(raw: str | None) -> frozenset[str]:
    """Parse a comma-separated allowlist string into a normalized frozenset.

    Hosts are lowercased and stripped. Empty entries are dropped. A None or
    empty input yields an empty set — meaning **every** URL is rejected by
    ``fetch_page``. Operators must opt-in explicitly.
    """
    if not raw:
        return frozenset()
    parts = [p.strip().lower() for p in raw.split(",")]
    return frozenset(p for p in parts if p)


def is_url_allowed(url: str, allowlist: frozenset[str]) -> bool:
    """Check whether ``url``'s host is in ``allowlist``.

    The check is **exact-host** (no wildcards, no path-based matching). A
    URL with no host (e.g. ``data:`` URIs, malformed input) is rejected.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    if not host:
        return False
    return host in allowlist


# --------------------------------------------------------------------------- #
# Tool registry                                                               #
# --------------------------------------------------------------------------- #


def build_mcp(api_client: httpx.AsyncClient, allowlist: frozenset[str]) -> FastMCP:
    """Construct the FastMCP instance with the three tools.

    ``allowlist`` is captured by ``fetch_page`` and consulted on every call.
    """
    mcp: FastMCP = FastMCP(name=SERVER_NAME)

    @mcp.tool(
        name="web_search",
        description=(
            "Run a synthetic web search for the given query. Returns a list "
            "of results with url, title, snippet, published_year, source, "
            "and adverse flag. Use this to find adverse media or industry "
            "context on a person/entity. Read-only; does NOT fetch any "
            "external page (use fetch_page for that, subject to the "
            "outbound allowlist)."
        ),
    )
    async def web_search(
        query: str, scenario: str | None = None
    ) -> dict[str, Any]:
        params: dict[str, str] = {"query": query}
        if scenario is not None:
            params["scenario"] = scenario
        return await _get_json(api_client, "/web/search", params)

    @mcp.tool(
        name="fetch_page",
        description=(
            "Fetch the page at the given URL via the OSINT mock. The URL's "
            "host must be in the operator-configured OSINT_ALLOWLIST. "
            "Returns {url, title, text, language, captured_year, "
            "byte_size, adverse, content_digest}. Read-only. URLs not in "
            "the allowlist are rejected with deny_reason=domain_not_allowed "
            "and never reach the upstream mock."
        ),
    )
    async def fetch_page(url: str, scenario: str | None = None) -> dict[str, Any]:
        if not is_url_allowed(url, allowlist):
            host = (urlsplit(url).hostname or "").lower()
            raise ToolDispatchError(
                f"host '{host}' not in OSINT_ALLOWLIST",
                status_code=403,
                data={
                    "deny_reason": "domain_not_allowed",
                    "host": host,
                    "url": url,
                },
            )
        params: dict[str, str] = {"url": url}
        if scenario is not None:
            params["scenario"] = scenario
        return await _get_json(api_client, "/web/fetch", params)

    @mcp.tool(
        name="lookup_company",
        description=(
            "Look up a company record by name. Returns {company_name, "
            "jurisdiction, incorporated_year, status, directors, "
            "beneficial_owners, risk_signals}. Surfaces shell-company "
            "indicators in the synthetic_id scenario and "
            "sanctioned_owner/pep_director in the sanctions_hit scenario. "
            "Read-only."
        ),
    )
    async def lookup_company(
        company_name: str, scenario: str | None = None
    ) -> dict[str, Any]:
        params: dict[str, str] = {}
        if scenario is not None:
            params["scenario"] = scenario
        return await _get_json(
            api_client, f"/companies/{company_name}", params
        )

    return mcp


async def _get_json(
    client: httpx.AsyncClient, path: str, params: dict[str, str]
) -> dict[str, Any]:
    resp = await client.get(path, params=params)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise RuntimeError(f"osint mock returned non-object payload: {data!r}")
    return data


# --------------------------------------------------------------------------- #
# FastAPI app factory                                                         #
# --------------------------------------------------------------------------- #


def create_app(
    *,
    public_key_path: Path | str,
    api_base_url: str = DEFAULT_API_URL,
    allowlist: frozenset[str] | None = None,
    api_client: httpx.AsyncClient | None = None,
    request_timeout_seconds: float = 10.0,
) -> FastAPI:
    """Build the osint MCP server FastAPI app.

    Args:
        public_key_path: PEM file holding the service-to-service PASETO
            public key.
        api_base_url: Base URL of the osint mock API (US-015). Ignored when
            ``api_client`` is provided.
        allowlist: Frozenset of allowed hostnames for ``fetch_page``. When
            ``None``, the value is read from ``OSINT_ALLOWLIST`` at
            factory-build time. Default is empty (every URL rejected).
        api_client: Optional pre-built ``httpx.AsyncClient`` for the mock.
        request_timeout_seconds: Timeout for the upstream HTTP call.
    """
    effective_allowlist = (
        allowlist
        if allowlist is not None
        else parse_allowlist(os.environ.get("OSINT_ALLOWLIST"))
    )

    def _mcp_factory(client: httpx.AsyncClient) -> FastMCP:
        return build_mcp(client, effective_allowlist)

    return create_jsonrpc_app(
        server_name=SERVER_NAME,
        title="osint MCP server",
        description=(
            "Downstream MCP server for the osint mock API. Speaks JSON-RPC "
            "2.0 (tools/list, tools/call) over HTTP, validates "
            "service-to-service PASETOs, and enforces an outbound allowlist "
            "for fetch_page."
        ),
        mcp_factory=_mcp_factory,
        public_key_path=public_key_path,
        api_base_url=api_base_url,
        api_client=api_client,
        request_timeout_seconds=request_timeout_seconds,
    )


def build_default_app() -> FastAPI:
    """Construct the server from env vars (production entry point).

    Env vars:
        ``OSINT_MCP_PUBLIC_KEY``: PEM path with the service PASETO public
            key (the matching private key lives in
            ``MCP_GATEWAY_SERVICE_PRIVATE_KEY`` on the gateway side).
        ``OSINT_API_URL``: Base URL of the osint mock API (defaults to
            ``http://localhost:8010``).
        ``OSINT_ALLOWLIST``: Comma-separated list of allowed hostnames for
            ``fetch_page``. Default is empty (every URL rejected).
    """
    pub = os.environ.get("OSINT_MCP_PUBLIC_KEY", "")
    if not pub:
        raise RuntimeError(
            "OSINT_MCP_PUBLIC_KEY not configured (path to the service PASETO "
            "public key PEM)."
        )
    api_url = os.environ.get("OSINT_API_URL", DEFAULT_API_URL)
    return create_app(public_key_path=Path(pub), api_base_url=api_url)
