"""transactions MCP server — wraps the transactions mock API (US-012).

Three tools — ``get_transactions``, ``get_counterparties``,
``flag_velocity_anomalies`` — backed by ``mock_apis.transactions``.

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

DEFAULT_API_URL = "http://localhost:8003"
SERVER_NAME = "transactions"
TOOL_NAMES: tuple[str, ...] = (
    "get_transactions",
    "get_counterparties",
    "flag_velocity_anomalies",
)


def build_mcp(api_client: httpx.AsyncClient) -> FastMCP:
    """Construct the FastMCP instance with the three tools bound to ``api_client``."""
    mcp: FastMCP = FastMCP(name=SERVER_NAME)

    @mcp.tool(
        name="get_transactions",
        description=(
            "List the customer's transactions (tx_id, amount, currency, "
            "direction, type, merchant_category, counterparty_id, "
            "counterparty_country, days_ago, status). Deterministic from "
            "customer_id; scenario shapes the volume + composition. "
            "Use ``limit`` (1..500) to bound the response. Read-only."
        ),
    )
    async def get_transactions(
        customer_id: str,
        scenario: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        params: dict[str, str] = {}
        if scenario is not None:
            params["scenario"] = scenario
        if limit is not None:
            params["limit"] = str(limit)
        return await _get_json(
            api_client, f"/customers/{customer_id}/transactions", params
        )

    @mcp.tool(
        name="get_counterparties",
        description=(
            "Aggregated counterparty rollup for the customer "
            "(counterparty_id, country, tx_count, inbound_total, "
            "outbound_total, first_seen_days_ago, last_seen_days_ago). "
            "Derived from the full tx set — not the windowed get_transactions "
            "response. Read-only."
        ),
    )
    async def get_counterparties(
        customer_id: str, scenario: str | None = None
    ) -> dict[str, Any]:
        params: dict[str, str] = {}
        if scenario is not None:
            params["scenario"] = scenario
        return await _get_json(
            api_client, f"/customers/{customer_id}/counterparties", params
        )

    @mcp.tool(
        name="flag_velocity_anomalies",
        description=(
            "Compute velocity-based fraud heuristics for the customer: "
            "transaction_count, inbound_count, structuring_candidate_count, "
            "cross_border_count, distinct_counterparty_countries, and a "
            "flags[] list drawn from {burst_inbound, structuring_pattern, "
            "cross_border_burst, mule_hub_inflow}. Read-only."
        ),
    )
    async def flag_velocity_anomalies(
        customer_id: str, scenario: str | None = None
    ) -> dict[str, Any]:
        params: dict[str, str] = {}
        if scenario is not None:
            params["scenario"] = scenario
        return await _get_json(
            api_client, f"/customers/{customer_id}/velocity-anomalies", params
        )

    return mcp


async def _get_json(
    client: httpx.AsyncClient, path: str, params: dict[str, str]
) -> dict[str, Any]:
    resp = await client.get(path, params=params)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise RuntimeError(f"transactions mock returned non-object payload: {data!r}")
    return data


def create_app(
    *,
    public_key_path: Path | str,
    api_base_url: str = DEFAULT_API_URL,
    api_client: httpx.AsyncClient | None = None,
    request_timeout_seconds: float = 10.0,
) -> FastAPI:
    """Build the transactions MCP server FastAPI app."""
    return create_jsonrpc_app(
        server_name=SERVER_NAME,
        title="transactions MCP server",
        description=(
            "Downstream MCP server for the transactions mock API. Speaks "
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
        ``TRANSACTIONS_MCP_PUBLIC_KEY``: PEM path with the service PASETO
            public key (the matching private key lives in
            ``MCP_GATEWAY_SERVICE_PRIVATE_KEY`` on the gateway side).
        ``TRANSACTIONS_API_URL``: Base URL of the transactions mock API
            (defaults to ``http://localhost:8003``).
    """
    pub = os.environ.get("TRANSACTIONS_MCP_PUBLIC_KEY", "")
    if not pub:
        raise RuntimeError(
            "TRANSACTIONS_MCP_PUBLIC_KEY not configured (path to the service "
            "PASETO public key PEM)."
        )
    api_url = os.environ.get("TRANSACTIONS_API_URL", DEFAULT_API_URL)
    return create_app(public_key_path=Path(pub), api_base_url=api_url)
