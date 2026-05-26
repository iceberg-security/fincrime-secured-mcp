"""sanctions MCP server — wraps the sanctions mock API (US-014).

Three tools — ``screen_name``, ``screen_entity``, ``get_watchlist_hit`` —
backed by ``mock_apis.sanctions``.

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

DEFAULT_API_URL = "http://localhost:8008"
SERVER_NAME = "sanctions"
TOOL_NAMES: tuple[str, ...] = (
    "screen_name",
    "screen_entity",
    "get_watchlist_hit",
)


def build_mcp(api_client: httpx.AsyncClient) -> FastMCP:
    """Construct the FastMCP instance with the three tools bound to ``api_client``."""
    mcp: FastMCP = FastMCP(name=SERVER_NAME)

    @mcp.tool(
        name="screen_name",
        description=(
            "Screen a natural person's name against OFAC-style watchlists "
            "(SDN, EU consolidated, UN sanctions, UK HMT). Returns "
            "{query, matched, hits: [...]}. Only the sanctions_hit scenario "
            "produces real matches; all other scenarios return matched=false. "
            "Read-only."
        ),
    )
    async def screen_name(
        name: str, scenario: str | None = None
    ) -> dict[str, Any]:
        params: dict[str, str] = {"name": name}
        if scenario is not None:
            params["scenario"] = scenario
        return await _get_json(api_client, "/screen/name", params)

    @mcp.tool(
        name="screen_entity",
        description=(
            "Screen an entity / corporation / trust / foundation name against "
            "OFAC-style watchlists. Same shape as screen_name. Use this when "
            "screening a counterparty company or a UBO holdco rather than a "
            "natural person. Read-only."
        ),
    )
    async def screen_entity(
        entity_name: str, scenario: str | None = None
    ) -> dict[str, Any]:
        params: dict[str, str] = {"entity_name": entity_name}
        if scenario is not None:
            params["scenario"] = scenario
        return await _get_json(api_client, "/screen/entity", params)

    @mcp.tool(
        name="get_watchlist_hit",
        description=(
            "Fetch the detailed record for a single watchlist hit by its "
            "hit_id (program, listed_on, listed_name, aliases, addresses, "
            "country, match_score, hit_type). The hit_id must come from a "
            "prior screen_name or screen_entity result. Read-only."
        ),
    )
    async def get_watchlist_hit(hit_id: str) -> dict[str, Any]:
        return await _get_json(api_client, f"/hits/{hit_id}", {})

    return mcp


async def _get_json(
    client: httpx.AsyncClient, path: str, params: dict[str, str]
) -> dict[str, Any]:
    resp = await client.get(path, params=params)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise RuntimeError(f"sanctions mock returned non-object payload: {data!r}")
    return data


def create_app(
    *,
    public_key_path: Path | str,
    api_base_url: str = DEFAULT_API_URL,
    api_client: httpx.AsyncClient | None = None,
    request_timeout_seconds: float = 10.0,
) -> FastAPI:
    """Build the sanctions MCP server FastAPI app."""
    return create_jsonrpc_app(
        server_name=SERVER_NAME,
        title="sanctions MCP server",
        description=(
            "Downstream MCP server for the sanctions mock API. Speaks "
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
        ``SANCTIONS_MCP_PUBLIC_KEY``: PEM path with the service PASETO public
            key (the matching private key lives in
            ``MCP_GATEWAY_SERVICE_PRIVATE_KEY`` on the gateway side).
        ``SANCTIONS_API_URL``: Base URL of the sanctions mock API (defaults to
            ``http://localhost:8008``).
    """
    pub = os.environ.get("SANCTIONS_MCP_PUBLIC_KEY", "")
    if not pub:
        raise RuntimeError(
            "SANCTIONS_MCP_PUBLIC_KEY not configured (path to the service "
            "PASETO public key PEM)."
        )
    api_url = os.environ.get("SANCTIONS_API_URL", DEFAULT_API_URL)
    return create_app(public_key_path=Path(pub), api_base_url=api_url)
