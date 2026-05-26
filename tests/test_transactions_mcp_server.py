"""Tests for the transactions MCP server (mcp_servers/transactions/main.py).

Covers:
    * Service PASETO validation (rejects unsigned/expired/wrong-keypair).
    * Contract: tool names + input schemas match what the analyze-transactions
      SKILL.md will declare for US-017.
    * Tool dispatch: ``get_transactions`` / ``get_counterparties`` /
      ``flag_velocity_anomalies`` each hit the transactions mock API and
      return MCP-shaped results (text + structured data).
    * End-to-end integration: MCP gateway -> transactions MCP server ->
      transactions mock API yields the expected payload.

All HTTP plumbing is hermetic: the mock API runs in-process via
``httpx.ASGITransport``, the server runs via ``fastapi.testclient.TestClient``,
and the MCP gateway forwards through a third ``ASGITransport`` mounted on the
server app.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from gateways.common import audit as audit_mod
from gateways.common import paseto as paseto_mod
from gateways.common.audit import SQLiteAuditBackend
from gateways.common.paseto import Claims, mint
from gateways.mcp.main import create_app as create_gateway_app
from mcp_servers.transactions.main import (
    DEFAULT_API_URL,
    SERVER_NAME,
    TOOL_NAMES,
    build_mcp,
    create_app,
)
from mock_apis.transactions.main import create_app as create_mock_app

# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clear_paseto_key_cache() -> Iterator[None]:
    paseto_mod._load_private_key_cached.cache_clear()
    paseto_mod._load_public_key_cached.cache_clear()
    yield
    paseto_mod._load_private_key_cached.cache_clear()
    paseto_mod._load_public_key_cached.cache_clear()


def _write_keypair(tmp_path: Path, name: str) -> tuple[Path, Path]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = tmp_path / f"{name}_priv.pem"
    pub_path = tmp_path / f"{name}_pub.pem"
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    return priv_path, pub_path


@pytest.fixture()
def service_keys(tmp_path: Path) -> tuple[Path, Path]:
    """Service-to-service PASETO keypair (gateway mints, server verifies)."""
    return _write_keypair(tmp_path, "service")


@pytest.fixture()
def inbound_keys(tmp_path: Path) -> tuple[Path, Path]:
    """Inbound user PASETO keypair (auth gateway mints, MCP gateway verifies)."""
    return _write_keypair(tmp_path, "inbound")


@pytest.fixture()
def mock_api_client() -> Iterator[httpx.AsyncClient]:
    """In-process ASGI client into the transactions mock API (US-012)."""
    mock_app = create_mock_app()
    transport = httpx.ASGITransport(app=mock_app)
    client = httpx.AsyncClient(transport=transport, base_url="http://mock")
    yield client


@pytest.fixture()
def memory_audit_backend() -> Iterator[SQLiteAuditBackend]:
    backend = SQLiteAuditBackend(":memory:")
    audit_mod.set_backend(backend)
    yield backend
    audit_mod.reset_default_backend()


def _service_token(
    *, service_priv: Path, sub: str = "alice@example.com", ttl: int = 60
) -> str:
    claims = Claims(
        sub=sub,
        roles=["analyst"],
        allowed_servers=["transactions"],
        allowed_tools={
            "transactions": [
                "get_transactions",
                "get_counterparties",
                "flag_velocity_anomalies",
            ]
        },
        trace_id="trace-abc",
    )
    return mint(claims, ttl_seconds=ttl, private_key_path=service_priv)


def _rpc_call(tool: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args or {}},
    }


def _server_client(
    *, service_pub: Path, mock_client: httpx.AsyncClient
) -> TestClient:
    app = create_app(public_key_path=service_pub, api_client=mock_client)
    return TestClient(app)


# --------------------------------------------------------------------------- #
# Module-level sanity                                                         #
# --------------------------------------------------------------------------- #


def test_tool_names_constant_matches_prd() -> None:
    """PRD US-012: server must expose three tools."""
    assert set(TOOL_NAMES) == {
        "get_transactions",
        "get_counterparties",
        "flag_velocity_anomalies",
    }


def test_server_name_matches_gateway_url_segment() -> None:
    """Server name MUST equal the gateway's f'{downstream_url}/{server}' suffix."""
    assert SERVER_NAME == "transactions"


def test_default_api_url_constant() -> None:
    assert DEFAULT_API_URL.startswith("http://")


def test_build_mcp_registers_three_tools() -> None:
    """FastMCP registry holds exactly the three PRD-required tools."""
    import asyncio

    transport = httpx.ASGITransport(app=create_mock_app())
    client = httpx.AsyncClient(transport=transport, base_url="http://mock")
    try:
        mcp = build_mcp(client)
        tools = asyncio.run(mcp.list_tools(run_middleware=False))
        names = {t.name for t in tools}
        assert names == set(TOOL_NAMES)
    finally:
        asyncio.run(client.aclose())


# --------------------------------------------------------------------------- #
# /healthz                                                                    #
# --------------------------------------------------------------------------- #


def test_healthz_ok(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    _, service_pub = service_keys
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# --------------------------------------------------------------------------- #
# PASETO validation                                                           #
# --------------------------------------------------------------------------- #


def test_missing_authorization_is_rejected(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    _, service_pub = service_keys
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call("get_transactions", {"customer_id": "c-1"}),
    )
    assert resp.status_code == 401
    body = resp.json()
    assert "error" in body
    assert "bearer" in body["error"]["message"].lower()


def test_invalid_authorization_scheme_is_rejected(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    _, service_pub = service_keys
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call("get_transactions", {"customer_id": "c-1"}),
        headers={"Authorization": "Basic deadbeef"},
    )
    assert resp.status_code == 401


def test_garbage_token_is_rejected(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    _, service_pub = service_keys
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call("get_transactions", {"customer_id": "c-1"}),
        headers={"Authorization": "Bearer not-a-paseto"},
    )
    assert resp.status_code == 401
    assert "invalid" in resp.json()["error"]["message"].lower()


def test_expired_token_is_rejected(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv, ttl=1)
    time.sleep(2)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call("get_transactions", {"customer_id": "c-1"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
    assert "expired" in resp.json()["error"]["message"].lower()


def test_wrong_keypair_token_is_rejected(
    tmp_path: Path,
    service_keys: tuple[Path, Path],
    mock_api_client: httpx.AsyncClient,
) -> None:
    _, service_pub = service_keys
    other_priv, _ = _write_keypair(tmp_path, "other")
    token = _service_token(service_priv=other_priv)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call("get_transactions", {"customer_id": "c-1"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


def test_bad_json_body_returns_400(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        content="{not json",
        headers={
            "Authorization": f"Bearer {token}",
            "content-type": "application/json",
        },
    )
    assert resp.status_code == 400


# --------------------------------------------------------------------------- #
# Contract: tools/list                                                        #
# --------------------------------------------------------------------------- #


def test_tools_list_returns_three_tools_with_schemas(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json={"jsonrpc": "2.0", "id": 9, "method": "tools/list"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 9
    tools = body["result"]["tools"]
    assert {t["name"] for t in tools} == set(TOOL_NAMES)
    for tool in tools:
        assert tool["description"]
        schema = tool["inputSchema"]
        assert schema["type"] == "object"
        assert "customer_id" in schema["properties"]
        assert schema["properties"]["customer_id"]["type"] == "string"
        assert "scenario" in schema["properties"]
        assert "customer_id" in schema["required"]
        assert "scenario" not in schema["required"]


def test_tools_list_schemas_match_analyze_transactions_skill_contract(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    """Contract test for US-017: analyze-transactions SKILL.md will declare these.

    If the SKILL.md adds/renames a tool or changes a required param, this
    test must change in lockstep with the SKILL.md frontmatter. Two-way fence.
    """
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    tools = {t["name"]: t for t in resp.json()["result"]["tools"]}

    expected_contract = {
        "get_transactions": {
            "required": ["customer_id"],
            "optional": ["scenario", "limit"],
        },
        "get_counterparties": {
            "required": ["customer_id"],
            "optional": ["scenario"],
        },
        "flag_velocity_anomalies": {
            "required": ["customer_id"],
            "optional": ["scenario"],
        },
    }
    for name, contract in expected_contract.items():
        assert name in tools, f"missing tool: {name}"
        schema = tools[name]["inputSchema"]
        for req in contract["required"]:
            assert req in schema["required"], f"{name}: missing required '{req}'"
            assert req in schema["properties"]
        for opt in contract["optional"]:
            assert opt in schema["properties"]
            assert opt not in schema["required"]


# --------------------------------------------------------------------------- #
# tools/call: each tool hits the mock and returns MCP-shaped result           #
# --------------------------------------------------------------------------- #


def _assert_mcp_shape(body: dict[str, Any]) -> dict[str, Any]:
    """JSON-RPC result wraps {content: [...], structuredContent: {...}}."""
    assert body["jsonrpc"] == "2.0"
    assert "result" in body, body
    result = body["result"]
    assert isinstance(result["content"], list)
    assert len(result["content"]) >= 1
    assert result["content"][0]["type"] == "text"
    assert isinstance(result["structuredContent"], dict)
    return result["structuredContent"]


def test_get_transactions_returns_tx_list(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "get_transactions", {"customer_id": "c-1", "scenario": "clean"}
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    structured = _assert_mcp_shape(resp.json())
    assert structured["customer_id"] == "c-1"
    assert structured["scenario"] == "clean"
    assert isinstance(structured["transactions"], list)
    assert structured["transactions"]


def test_get_transactions_respects_limit(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "get_transactions",
            {"customer_id": "c-mule", "scenario": "mule", "limit": 7},
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    structured = _assert_mcp_shape(resp.json())
    assert len(structured["transactions"]) == 7


def test_get_counterparties_returns_rollup(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "get_counterparties", {"customer_id": "c-7", "scenario": "mule"}
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    structured = _assert_mcp_shape(resp.json())
    assert structured["scenario"] == "mule"
    cps = structured["counterparties"]
    assert cps
    for cp in cps:
        assert {
            "counterparty_id",
            "country",
            "tx_count",
            "inbound_total",
            "outbound_total",
        }.issubset(cp.keys())


def test_flag_velocity_anomalies_returns_flags(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "flag_velocity_anomalies",
            {"customer_id": "c-9", "scenario": "structuring"},
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    structured = _assert_mcp_shape(resp.json())
    assert "structuring_pattern" in structured["flags"]
    assert structured["structuring_candidate_count"] >= 5


def test_scenario_omitted_uses_mock_default(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call("get_transactions", {"customer_id": "c-default-test"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    structured = _assert_mcp_shape(resp.json())
    assert structured["scenario"] in {
        "clean",
        "mule",
        "sanctions_hit",
        "ato",
        "structuring",
        "synthetic_id",
    }


# --------------------------------------------------------------------------- #
# Error paths                                                                 #
# --------------------------------------------------------------------------- #


def test_unknown_tool_returns_method_not_found(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call("nope", {"customer_id": "c-1"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404
    assert "unknown tool" in resp.json()["error"]["message"]


def test_unsupported_method_returns_400(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/eat"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400


def test_unknown_scenario_surfaces_as_upstream_error(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    """The mock returns HTTP 400 for unknown scenarios; the server forwards it."""
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "get_transactions", {"customer_id": "c-1", "scenario": "nonsense"}
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400
    body = resp.json()
    assert "error" in body
    assert body["error"]["data"]["upstream_status"] == 400


# --------------------------------------------------------------------------- #
# End-to-end: MCP gateway -> transactions server -> transactions mock         #
# --------------------------------------------------------------------------- #


def test_gateway_to_server_to_mock_end_to_end(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    mock_api_client: httpx.AsyncClient,
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    """User PASETO -> gateway -> transactions server -> mock returns expected payload.

    The gateway re-signs a service PASETO that the transactions MCP server
    accepts; the server then calls the mock API and returns the MCP-shaped
    result back through the gateway to the caller. One audit row recorded.
    """
    inbound_priv, inbound_pub = inbound_keys
    service_priv, service_pub = service_keys

    server_app = create_app(
        public_key_path=service_pub,
        api_client=mock_api_client,
    )
    server_transport = httpx.ASGITransport(app=server_app)
    gateway_http_client = httpx.AsyncClient(
        transport=server_transport, base_url="http://downstream"
    )

    gateway_app = create_gateway_app(
        downstream_url="http://downstream",
        service_private_key_path=service_priv,
        inbound_public_key_path=inbound_pub,
        http_client=gateway_http_client,
    )
    gateway_client = TestClient(gateway_app)

    user_claims = Claims(
        sub="alice@example.com",
        roles=["analyst"],
        allowed_servers=["transactions"],
        allowed_tools={
            "transactions": [
                "get_transactions",
                "get_counterparties",
                "flag_velocity_anomalies",
            ]
        },
        trace_id="trace-e2e-tx",
    )
    user_token = mint(user_claims, ttl_seconds=300, private_key_path=inbound_priv)

    resp = gateway_client.post(
        f"/mcp/{SERVER_NAME}",
        json=_rpc_call(
            "flag_velocity_anomalies",
            {"customer_id": "c-e2e", "scenario": "mule"},
        ),
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 200, resp.text
    structured = _assert_mcp_shape(resp.json())
    assert structured["customer_id"] == "c-e2e"
    assert structured["scenario"] == "mule"
    assert "mule_hub_inflow" in structured["flags"]
    assert "burst_inbound" in structured["flags"]

    memory_audit_backend.flush()
    rows = memory_audit_backend.query(sub="alice@example.com")
    assert len(rows) == 1
    row = rows[0]
    assert row["server"] == "transactions"
    assert row["tool"] == "flag_velocity_anomalies"
    assert row["status"] == "ok"
    assert row["trace_id"] == "trace-e2e-tx"


def test_end_to_end_get_transactions_for_sanctions_hit(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    mock_api_client: httpx.AsyncClient,
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    """get_transactions path through the gateway for the sanctions_hit scenario."""
    inbound_priv, inbound_pub = inbound_keys
    service_priv, service_pub = service_keys

    server_app = create_app(public_key_path=service_pub, api_client=mock_api_client)
    server_transport = httpx.ASGITransport(app=server_app)
    gateway_http_client = httpx.AsyncClient(
        transport=server_transport, base_url="http://downstream"
    )
    gateway_app = create_gateway_app(
        downstream_url="http://downstream",
        service_private_key_path=service_priv,
        inbound_public_key_path=inbound_pub,
        http_client=gateway_http_client,
    )
    gateway_client = TestClient(gateway_app)

    user_claims = Claims(
        sub="bob@example.com",
        roles=["analyst"],
        allowed_servers=["transactions"],
        allowed_tools={"transactions": ["get_transactions"]},
        trace_id="trace-sanc",
    )
    user_token = mint(user_claims, ttl_seconds=300, private_key_path=inbound_priv)

    resp = gateway_client.post(
        f"/mcp/{SERVER_NAME}",
        json=_rpc_call(
            "get_transactions",
            {"customer_id": "c-sanc", "scenario": "sanctions_hit", "limit": 25},
        ),
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 200, resp.text
    structured = _assert_mcp_shape(resp.json())
    assert structured["scenario"] == "sanctions_hit"
    # At least one transaction should touch a high-risk country.
    high_risk = {"IR", "KP", "SY", "CU", "VE"}
    countries = {t["counterparty_country"] for t in structured["transactions"]}
    assert high_risk & countries


def test_end_to_end_determinism(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    mock_api_client: httpx.AsyncClient,
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    """Same (customer_id, scenario) yields identical payloads through the stack."""
    inbound_priv, inbound_pub = inbound_keys
    service_priv, service_pub = service_keys

    server_app = create_app(public_key_path=service_pub, api_client=mock_api_client)
    server_transport = httpx.ASGITransport(app=server_app)
    gateway_http_client = httpx.AsyncClient(
        transport=server_transport, base_url="http://downstream"
    )
    gateway_app = create_gateway_app(
        downstream_url="http://downstream",
        service_private_key_path=service_priv,
        inbound_public_key_path=inbound_pub,
        http_client=gateway_http_client,
    )
    gateway_client = TestClient(gateway_app)

    user_claims = Claims(
        sub="alice@example.com",
        roles=["analyst"],
        allowed_servers=["transactions"],
        allowed_tools={"transactions": ["get_counterparties"]},
        trace_id="trace-det-tx",
    )

    def _call() -> dict[str, Any]:
        token = mint(user_claims, ttl_seconds=300, private_key_path=inbound_priv)
        resp = gateway_client.post(
            f"/mcp/{SERVER_NAME}",
            json=_rpc_call(
                "get_counterparties",
                {"customer_id": "c-d1", "scenario": "clean"},
            ),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        return _assert_mcp_shape(resp.json())

    first = _call()
    second = _call()
    assert first == second
