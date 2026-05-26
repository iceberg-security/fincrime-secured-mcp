"""kyc MCP server — wraps the kyc mock API (US-013).

Three tools — ``get_kyc_record``, ``get_document``, ``get_ubo_tree`` —
backed by ``mock_apis.kyc``.

The JSON-RPC + PASETO pipeline lives in ``mcp_servers/_common.py``; this
module just declares the tool registry and wires the factory.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI
from fastmcp import FastMCP

from mcp_servers._common import create_jsonrpc_app

__all__ = [
    "DEFAULT_API_URL",
    "SERVER_NAME",
    "TOOL_NAMES",
    "build_default_app",
    "build_mcp",
    "create_app",
]

DEFAULT_API_URL = "http://localhost:8006"
SERVER_NAME = "kyc"
TOOL_NAMES: tuple[str, ...] = (
    "get_kyc_record",
    "get_document",
    "get_ubo_tree",
)


def build_mcp(api_client: httpx.AsyncClient) -> FastMCP:
    """Construct the FastMCP instance with the three tools bound to ``api_client``."""
    mcp: FastMCP = FastMCP(name=SERVER_NAME)

    @mcp.tool(
        name="get_kyc_record",
        description=(
            "Fetch the customer's KYC (Know Your Customer) record: full_name, "
            "dob, ssn_last4, id_document_type, id_document_number, "
            "issuer_country, verification_method, verified_at_year, "
            "kyc_status, pep_flag, sanctions_match, entity_type, and a list "
            "of inconsistencies. Deterministic from customer_id; scenario "
            "shapes pep/sanctions/synthetic_id signals. Read-only."
        ),
    )
    async def get_kyc_record(
        customer_id: str, scenario: str | None = None
    ) -> dict[str, Any]:
        params: dict[str, str] = {}
        if scenario is not None:
            params["scenario"] = scenario
        return await _get_json(api_client, f"/customers/{customer_id}/kyc", params)

    @mcp.tool(
        name="get_document",
        description=(
            "Fetch metadata for one identity document on file for the customer "
            "(kind, issuer_country, expiry_year, verification_method, "
            "on_file). The document_id must match one of the IDs returned by "
            "the kyc record's documents list. Read-only."
        ),
    )
    async def get_document(
        customer_id: str, document_id: str, scenario: str | None = None
    ) -> dict[str, Any]:
        params: dict[str, str] = {}
        if scenario is not None:
            params["scenario"] = scenario
        return await _get_json(
            api_client,
            f"/customers/{customer_id}/documents/{document_id}",
            params,
        )

    @mcp.tool(
        name="get_ubo_tree",
        description=(
            "Fetch the customer's UBO (Ultimate Beneficial Owner) tree: a "
            "list of owners with ownership_pct, country, owner_type "
            "(natural_person | entity), is_natural_person_at_top, and any "
            "deeper layers for layered/shell-company structures. Surfaces "
            "flags like no_natural_person_at_top + multi_layer_ownership for "
            "shell entities. Read-only."
        ),
    )
    async def get_ubo_tree(
        customer_id: str, scenario: str | None = None
    ) -> dict[str, Any]:
        params: dict[str, str] = {}
        if scenario is not None:
            params["scenario"] = scenario
        return await _get_json(api_client, f"/customers/{customer_id}/ubo", params)

    return mcp


async def _get_json(
    client: httpx.AsyncClient, path: str, params: dict[str, str]
) -> dict[str, Any]:
    resp = await client.get(path, params=params)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise RuntimeError(f"kyc mock returned non-object payload: {data!r}")
    return data


def create_app(
    *,
    public_key_path: Path | str,
    api_base_url: str = DEFAULT_API_URL,
    api_client: httpx.AsyncClient | None = None,
    request_timeout_seconds: float = 10.0,
) -> FastAPI:
    """Build the kyc MCP server FastAPI app."""
    return create_jsonrpc_app(
        server_name=SERVER_NAME,
        title="kyc MCP server",
        description=(
            "Downstream MCP server for the kyc mock API. Speaks JSON-RPC 2.0 "
            "(tools/list, tools/call) over HTTP and validates service-to-"
            "service PASETOs."
        ),
        mcp_factory=build_mcp,
        public_key_path=public_key_path,
        api_base_url=api_base_url,
        api_client=api_client,
        request_timeout_seconds=request_timeout_seconds,
    )


def build_default_app() -> FastAPI:
    """Construct the server from env vars (production entry point).

    Env vars:
        ``KYC_MCP_PUBLIC_KEY``: PEM path with the service PASETO public key
            (the matching private key lives in
            ``MCP_GATEWAY_SERVICE_PRIVATE_KEY`` on the gateway side).
        ``KYC_API_URL``: Base URL of the kyc mock API (defaults to
            ``http://localhost:8006``).
    """
    pub = os.environ.get("KYC_MCP_PUBLIC_KEY", "")
    if not pub:
        raise RuntimeError(
            "KYC_MCP_PUBLIC_KEY not configured (path to the service PASETO "
            "public key PEM)."
        )
    api_url = os.environ.get("KYC_API_URL", DEFAULT_API_URL)
    return create_app(public_key_path=Path(pub), api_base_url=api_url)
