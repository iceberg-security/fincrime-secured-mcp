"""Stdio MCP server that proxies tool calls to the fraud-copilot HTTP MCP gateway.

Bridges Claude Code's stdio-based MCP client to the streamable-HTTP MCP gateway
that lives at FRAUD_MCP_GATEWAY_URL (default http://localhost:8100). Handles the
mock-OIDC -> auth-gateway -> PASETO mint dance transparently so Claude Code never
sees the auth machinery.

Each downstream MCP server (customer_data, transactions, kyc, sanctions, osint)
is exposed here as a flat namespace: e.g. `customer_data__get_customer`. We
namespace this way because Claude Code's MCP client treats tools as a flat list
per server and we want one stdio server fronting all six federated servers.

Configuration (env vars, all optional with demo-friendly defaults):
  FRAUD_MCP_GATEWAY_URL   - http://localhost:8100
  FRAUD_AUTH_GATEWAY_URL  - http://localhost:8080
  FRAUD_OIDC_URL          - http://localhost:9000
  FRAUD_OIDC_EMAIL        - alice@example.com
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

GATEWAY_URL = os.environ.get("FRAUD_MCP_GATEWAY_URL", "http://localhost:8100").rstrip("/")
AUTH_URL = os.environ.get("FRAUD_AUTH_GATEWAY_URL", "http://localhost:8080").rstrip("/")
OIDC_URL = os.environ.get("FRAUD_OIDC_URL", "http://localhost:9000").rstrip("/")
OIDC_EMAIL = os.environ.get("FRAUD_OIDC_EMAIL", "alice@example.com")

DOWNSTREAM_SERVERS = ("customer_data", "transactions", "kyc", "sanctions", "osint")

def _log(msg: str) -> None:
    print(f"[fraud-mcp-proxy] {msg}", file=sys.stderr, flush=True)


def _http_post(url: str, body: dict[str, Any] | None, headers: dict[str, str]) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else b""
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_get(url: str) -> dict[str, Any]:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _mint_paseto() -> str:
    # The gateway tracks jti replay (LRU 10 000), so every gateway call needs a
    # fresh PASETO. No caching here on purpose.
    oidc_token = _http_get(f"{OIDC_URL}/login?email={urllib.parse.quote(OIDC_EMAIL)}")["access_token"]
    paseto_resp = _http_post(
        f"{AUTH_URL}/token",
        None,
        {"Authorization": f"Bearer {oidc_token}"},
    )
    return paseto_resp["access_token"]


def _call_gateway(server: str, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    paseto = _mint_paseto()
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    return _http_post(
        f"{GATEWAY_URL}/mcp/{server}",
        body,
        {"Authorization": f"Bearer {paseto}", "Content-Type": "application/json"},
    )


def _discover_tools() -> list[dict[str, Any]]:
    """List every tool across every downstream server, prefixed with the server name."""
    tools: list[dict[str, Any]] = []
    for server in DOWNSTREAM_SERVERS:
        try:
            resp = _call_gateway(server, "tools/list")
        except Exception as e:
            _log(f"tools/list failed for {server}: {e}")
            continue
        for tool in resp.get("result", {}).get("tools", []):
            name = tool.get("name", "")
            tools.append(
                {
                    "name": f"{server}__{name}",
                    "description": f"[{server}] {tool.get('description', '')}",
                    "inputSchema": tool.get("inputSchema", {"type": "object", "properties": {}}),
                }
            )
    return tools


def _route_tool_call(prefixed_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if "__" not in prefixed_name:
        return {
            "content": [{"type": "text", "text": f"unknown tool: {prefixed_name}"}],
            "isError": True,
        }
    server, tool_name = prefixed_name.split("__", 1)
    if server not in DOWNSTREAM_SERVERS:
        return {
            "content": [{"type": "text", "text": f"unknown server: {server}"}],
            "isError": True,
        }
    try:
        resp = _call_gateway(
            server,
            "tools/call",
            {"name": tool_name, "arguments": arguments},
        )
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"gateway call failed: {e}"}],
            "isError": True,
        }
    if "error" in resp:
        return {
            "content": [{"type": "text", "text": json.dumps(resp["error"])}],
            "isError": True,
        }
    return resp.get("result", {})


def _write_response(msg_id: Any, result: dict[str, Any] | None = None, error: dict[str, Any] | None = None) -> None:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        payload["error"] = error
    else:
        payload["result"] = result or {}
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def _handle(msg: dict[str, Any]) -> None:
    method = msg.get("method")
    msg_id = msg.get("id")
    params = msg.get("params", {}) or {}

    if method == "initialize":
        _write_response(
            msg_id,
            {
                "protocolVersion": params.get("protocolVersion", "2024-11-05"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fraud-investigator", "version": "0.1.0"},
            },
        )
    elif method in ("notifications/initialized", "initialized"):
        return  # notification, no response
    elif method == "tools/list":
        _write_response(msg_id, {"tools": _discover_tools()})
    elif method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments", {}) or {}
        _write_response(msg_id, _route_tool_call(name, args))
    elif method == "ping":
        _write_response(msg_id, {})
    else:
        if msg_id is not None:
            _write_response(msg_id, error={"code": -32601, "message": f"method not found: {method}"})


def main() -> int:
    _log(
        f"starting; gateway={GATEWAY_URL} auth={AUTH_URL} oidc={OIDC_URL} email={OIDC_EMAIL}"
    )
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            _log(f"bad JSON: {e}")
            continue
        try:
            _handle(msg)
        except Exception as e:
            _log(f"handler crash: {e}")
            if msg.get("id") is not None:
                _write_response(msg["id"], error={"code": -32603, "message": str(e)})
    return 0


if __name__ == "__main__":
    sys.exit(main())
