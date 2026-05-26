"""customer_data MCP server — wraps the customer_data mock API.

Speaks MCP JSON-RPC 2.0 over HTTP (the same "streamable HTTP" transport the
gateway forwards into). Three tools are exposed:

    get_customer(customer_id: str, scenario: str | None = None)
        -> profile dict from GET /customers/{customer_id}.

    list_accounts(customer_id: str, scenario: str | None = None)
        -> {customer_id, scenario, accounts: [...]} from
           GET /customers/{customer_id}/accounts.

    get_device_history(customer_id: str, scenario: str | None = None)
        -> {customer_id, scenario, devices: [...]} from
           GET /customers/{customer_id}/devices.

The downstream mock API is called over HTTP. The base URL is configured via
``CUSTOMER_DATA_API_URL`` (defaults to ``http://localhost:8001``) and the
``httpx.AsyncClient`` is injectable so integration tests can stitch the server
on top of an in-process mock app via ``httpx.ASGITransport``.

The JSON-RPC + PASETO pipeline lives in ``mcp_servers/_common.py`` — this
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

DEFAULT_API_URL = "http://localhost:8001"
SERVER_NAME = "customer_data"
TOOL_NAMES: tuple[str, ...] = ("get_customer", "list_accounts", "get_device_history")


def build_mcp(api_client: httpx.AsyncClient) -> FastMCP:
    """Construct the FastMCP instance with the three tools bound to ``api_client``."""
    mcp: FastMCP = FastMCP(name=SERVER_NAME)

    @mcp.tool(
        name="get_customer",
        description=(
            "Fetch the customer profile (name, dob, country, kyc_status, pep, "
            "risk_score, flags). Deterministic from customer_id; scenario "
            "overrides the persona shape. Read-only."
        ),
    )
    async def get_customer(
        customer_id: str, scenario: str | None = None
    ) -> dict[str, Any]:
        return await _get_json(api_client, f"/customers/{customer_id}", scenario)

    @mcp.tool(
        name="list_accounts",
        description=(
            "List the customer's bank accounts (account_id, type, currency, "
            "opened_year, balance, status). Same determinism + scenario rules "
            "as get_customer. Read-only."
        ),
    )
    async def list_accounts(
        customer_id: str, scenario: str | None = None
    ) -> dict[str, Any]:
        return await _get_json(
            api_client, f"/customers/{customer_id}/accounts", scenario
        )

    @mcp.tool(
        name="get_device_history",
        description=(
            "Return known login devices for the customer (device_id, os, type, "
            "first_seen_year, last_login_country, suspicious). Read-only."
        ),
    )
    async def get_device_history(
        customer_id: str, scenario: str | None = None
    ) -> dict[str, Any]:
        return await _get_json(
            api_client, f"/customers/{customer_id}/devices", scenario
        )

    return mcp


async def _get_json(
    client: httpx.AsyncClient, path: str, scenario: str | None
) -> dict[str, Any]:
    params: dict[str, str] = {}
    if scenario is not None:
        params["scenario"] = scenario
    resp = await client.get(path, params=params)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise RuntimeError(f"customer_data mock returned non-object payload: {data!r}")
    return data


def create_app(
    *,
    public_key_path: Path | str,
    api_base_url: str = DEFAULT_API_URL,
    api_client: httpx.AsyncClient | None = None,
    request_timeout_seconds: float = 10.0,
) -> FastAPI:
    """Build the customer_data MCP server FastAPI app."""
    return create_jsonrpc_app(
        server_name=SERVER_NAME,
        title="customer_data MCP server",
        description=(
            "Downstream MCP server for the customer_data mock API. Speaks "
            "JSON-RPC 2.0 (tools/list, tools/call) over HTTP and validates "
            "service-to-service PASETOs."
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
        ``CUSTOMER_DATA_MCP_PUBLIC_KEY``: PEM path with the service PASETO
            public key (the matching private key lives in
            ``MCP_GATEWAY_SERVICE_PRIVATE_KEY`` on the gateway side).
        ``CUSTOMER_DATA_API_URL``: Base URL of the customer_data mock API
            (defaults to ``http://localhost:8001``).
    """
    pub = os.environ.get("CUSTOMER_DATA_MCP_PUBLIC_KEY", "")
    if not pub:
        raise RuntimeError(
            "CUSTOMER_DATA_MCP_PUBLIC_KEY not configured (path to the service "
            "PASETO public key PEM)."
        )
    api_url = os.environ.get("CUSTOMER_DATA_API_URL", DEFAULT_API_URL)
    return create_app(public_key_path=Path(pub), api_base_url=api_url)
