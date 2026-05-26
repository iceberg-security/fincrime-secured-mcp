"""Integration tests for the MCP gateway (gateways/mcp/main.py)."""

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
from gateways.common.paseto import Claims, mint, verify
from gateways.mcp.main import DenyReason, create_app
from gateways.mcp.replay_cache import ReplayCache

# --------------------------------------------------------------------------- #
# Fixtures
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
def inbound_keys(tmp_path: Path) -> tuple[Path, Path]:
    """User PASETO keypair — same one the auth gateway would publish."""
    return _write_keypair(tmp_path, "inbound")


@pytest.fixture()
def service_keys(tmp_path: Path) -> tuple[Path, Path]:
    """Service-to-service PASETO keypair (separate from inbound)."""
    return _write_keypair(tmp_path, "service")


@pytest.fixture()
def memory_audit_backend() -> Iterator[SQLiteAuditBackend]:
    """Drop a fresh in-memory SQLite audit backend in as the module default."""
    backend = SQLiteAuditBackend(":memory:")
    audit_mod.set_backend(backend)
    yield backend
    audit_mod.reset_default_backend()


def _mint_user_token(
    *,
    inbound_priv: Path,
    sub: str = "alice@example.com",
    roles: list[str] | None = None,
    allowed_servers: list[str] | None = None,
    allowed_tools: dict[str, list[str]] | None = None,
    ttl_seconds: int = 300,
    trace_id: str = "trace-abc",
) -> tuple[str, Claims]:
    claims = Claims(
        sub=sub,
        roles=roles if roles is not None else ["analyst"],
        allowed_servers=allowed_servers
        if allowed_servers is not None
        else ["customer_data", "transactions"],
        allowed_tools=allowed_tools
        if allowed_tools is not None
        else {
            "customer_data": ["get_customer", "list_accounts"],
            "transactions": ["get_transactions"],
        },
        trace_id=trace_id,
    )
    token = mint(claims, ttl_seconds=ttl_seconds, private_key_path=inbound_priv)
    # mint() populates jti/exp on the encoded payload, not the in-memory dataclass.
    # Verify-roundtrip the freshly minted token (against the same key, ignoring
    # expiry) so callers see the populated jti/exp the way the gateway will.
    # Use a separate pub-key file derived from the priv-key's directory.
    pub_path = inbound_priv.with_name(inbound_priv.name.replace("_priv", "_pub"))
    verified = verify(token, public_key_path=pub_path)
    return token, verified


def _build_downstream_recorder() -> tuple[list[httpx.Request], httpx.MockTransport]:
    """Return a transport that records every request and replies 200 by default.

    The factory function inside lets individual tests override the response by
    mutating the closure-bound ``response`` ref.
    """
    captured: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [{"type": "text", "text": "ok"}],
                    "structuredContent": {"customer_id": "c-1"},
                },
            },
        )

    transport = httpx.MockTransport(_handler)
    return captured, transport


def _client(
    *,
    inbound_pub: Path,
    service_priv: Path,
    transport: httpx.MockTransport,
    downstream_url: str = "http://downstream",
    replay_cache: ReplayCache | None = None,
) -> TestClient:
    http_client = httpx.AsyncClient(transport=transport, base_url="http://downstream")
    app = create_app(
        downstream_url=downstream_url,
        service_private_key_path=service_priv,
        inbound_public_key_path=inbound_pub,
        http_client=http_client,
        replay_cache=replay_cache,
    )
    return TestClient(app)


def _rpc_call(tool: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args or {}},
    }


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_allowed_call_succeeds_and_is_audited(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, inbound_pub = inbound_keys
    service_priv, service_pub = service_keys
    captured, transport = _build_downstream_recorder()
    token, claims = _mint_user_token(inbound_priv=inbound_priv)

    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    resp = client.post(
        "/mcp/customer_data",
        json=_rpc_call("get_customer", {"customer_id": "c-1"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["jsonrpc"] == "2.0"
    assert "result" in body

    # Downstream call was made with a re-signed service token.
    assert len(captured) == 1
    sent_authz = captured[0].headers.get("authorization", "")
    assert sent_authz.lower().startswith("bearer v4.public.")
    service_token = sent_authz.split(" ", 1)[1]
    assert service_token != token  # re-signed, not pass-through

    # Service token verifies under the service public key (separate keypair).
    service_claims = verify(service_token, public_key_path=service_pub)
    assert service_claims.sub == claims.sub
    assert service_claims.trace_id == claims.trace_id
    assert service_claims.jti != claims.jti  # fresh jti

    # Audit row written.
    memory_audit_backend.flush()
    rows = memory_audit_backend.query(sub=claims.sub)
    assert len(rows) == 1
    row = rows[0]
    assert row["server"] == "customer_data"
    assert row["tool"] == "get_customer"
    assert row["status"] == "ok"
    assert row["deny_reason"] is None
    assert row["jti"] == claims.jti
    assert row["trace_id"] == claims.trace_id
    assert row["result_hash"]
    assert row["latency_ms"] >= 0


def test_tools_list_passes_through_and_audits(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    captured, transport = _build_downstream_recorder()
    token, _ = _mint_user_token(inbound_priv=inbound_priv)
    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    resp = client.post(
        "/mcp/customer_data",
        json={"jsonrpc": "2.0", "id": 7, "method": "tools/list"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert len(captured) == 1


# --------------------------------------------------------------------------- #
# Denials
# --------------------------------------------------------------------------- #


def test_denied_tool_returns_403_with_deny_reason_and_is_audited(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    captured, transport = _build_downstream_recorder()
    token, claims = _mint_user_token(inbound_priv=inbound_priv)

    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    # 'freeze_account' is not in the analyst's allowed_tools.
    resp = client.post(
        "/mcp/customer_data",
        json=_rpc_call("freeze_account", {"customer_id": "c-1"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body["error"]["data"]["deny_reason"] == DenyReason.TOOL_NOT_ALLOWED
    # Downstream was NOT called.
    assert captured == []

    memory_audit_backend.flush()
    rows = memory_audit_backend.query(sub=claims.sub)
    assert len(rows) == 1
    assert rows[0]["status"] == "denied"
    assert rows[0]["deny_reason"] == DenyReason.TOOL_NOT_ALLOWED


def test_denied_server_returns_403_with_server_not_allowed(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    captured, transport = _build_downstream_recorder()
    token, _ = _mint_user_token(
        inbound_priv=inbound_priv,
        allowed_servers=["customer_data"],
        allowed_tools={"customer_data": ["get_customer"]},
    )
    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    resp = client.post(
        "/mcp/case_actions",
        json=_rpc_call("freeze_account"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["data"]["deny_reason"] == DenyReason.SERVER_NOT_ALLOWED
    assert captured == []


def test_wildcard_super_admin_can_call_anything(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    captured, transport = _build_downstream_recorder()
    token, _ = _mint_user_token(
        inbound_priv=inbound_priv,
        allowed_servers=["*"],
        allowed_tools={"*": ["*"]},
    )
    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    resp = client.post(
        "/mcp/case_actions",
        json=_rpc_call("freeze_account"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    assert len(captured) == 1


def test_per_server_wildcard_allows_any_tool_on_that_server(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    _, transport = _build_downstream_recorder()
    token, _ = _mint_user_token(
        inbound_priv=inbound_priv,
        allowed_servers=["customer_data"],
        allowed_tools={"customer_data": ["*"]},
    )
    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    resp = client.post(
        "/mcp/customer_data",
        json=_rpc_call("get_device_history"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200


# --------------------------------------------------------------------------- #
# Token verification failures
# --------------------------------------------------------------------------- #


def test_missing_authorization_returns_401(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    _, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    _, transport = _build_downstream_recorder()
    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    resp = client.post("/mcp/customer_data", json=_rpc_call("get_customer"))
    assert resp.status_code == 401
    assert resp.json()["error"]["data"]["deny_reason"] == DenyReason.TOKEN_MISSING


def test_invalid_token_returns_401(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    _, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    _, transport = _build_downstream_recorder()
    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    resp = client.post(
        "/mcp/customer_data",
        json=_rpc_call("get_customer"),
        headers={"Authorization": "Bearer not-a-paseto"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["data"]["deny_reason"] == DenyReason.TOKEN_INVALID


def test_expired_token_returns_401(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    _, transport = _build_downstream_recorder()
    token, _ = _mint_user_token(inbound_priv=inbound_priv, ttl_seconds=1)
    time.sleep(2)
    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    resp = client.post(
        "/mcp/customer_data",
        json=_rpc_call("get_customer"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["data"]["deny_reason"] == DenyReason.TOKEN_EXPIRED


def test_wrong_keypair_token_returns_401(
    tmp_path: Path,
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    """A token minted with a different keypair should not verify."""
    _, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    wrong_priv, _ = _write_keypair(tmp_path, "wrong")
    token, _ = _mint_user_token(inbound_priv=wrong_priv)
    _, transport = _build_downstream_recorder()
    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    resp = client.post(
        "/mcp/customer_data",
        json=_rpc_call("get_customer"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


def test_replay_returns_401_token_replay(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    _, transport = _build_downstream_recorder()
    token, _ = _mint_user_token(inbound_priv=inbound_priv)
    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    resp1 = client.post(
        "/mcp/customer_data",
        json=_rpc_call("get_customer"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp1.status_code == 200, resp1.text
    resp2 = client.post(
        "/mcp/customer_data",
        json=_rpc_call("get_customer"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp2.status_code == 401
    assert resp2.json()["error"]["data"]["deny_reason"] == DenyReason.TOKEN_REPLAY


# --------------------------------------------------------------------------- #
# Downstream error surfacing
# --------------------------------------------------------------------------- #


def test_downstream_5xx_returns_502_and_audits_error(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    token, claims = _mint_user_token(inbound_priv=inbound_priv)

    def _handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "service unavailable"})

    transport = httpx.MockTransport(_handler)
    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    resp = client.post(
        "/mcp/customer_data",
        json=_rpc_call("get_customer"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 502
    assert resp.json()["error"]["data"]["deny_reason"] == DenyReason.DOWNSTREAM_ERROR

    memory_audit_backend.flush()
    rows = memory_audit_backend.query(sub=claims.sub)
    assert len(rows) == 1
    assert rows[0]["status"] == "error"
    assert rows[0]["deny_reason"] == DenyReason.DOWNSTREAM_ERROR


def test_downstream_4xx_passthrough_audits_error(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    token, claims = _mint_user_token(inbound_priv=inbound_priv)

    def _handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "customer not found"})

    transport = httpx.MockTransport(_handler)
    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    resp = client.post(
        "/mcp/customer_data",
        json=_rpc_call("get_customer"),
        headers={"Authorization": f"Bearer {token}"},
    )
    # 4xx is surfaced cleanly with the downstream's status preserved.
    assert resp.status_code == 404
    assert resp.json()["error"] == "customer not found"

    memory_audit_backend.flush()
    rows = memory_audit_backend.query(sub=claims.sub)
    assert len(rows) == 1
    assert rows[0]["status"] == "error"


def test_downstream_network_failure_returns_502(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    token, _ = _mint_user_token(inbound_priv=inbound_priv)

    def _handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    transport = httpx.MockTransport(_handler)
    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    resp = client.post(
        "/mcp/customer_data",
        json=_rpc_call("get_customer"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 502
    assert resp.json()["error"]["data"]["deny_reason"] == DenyReason.DOWNSTREAM_ERROR


# --------------------------------------------------------------------------- #
# Misc
# --------------------------------------------------------------------------- #


def test_healthz(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
) -> None:
    _, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    _, transport = _build_downstream_recorder()
    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_bad_json_returns_parse_error(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    token, _ = _mint_user_token(inbound_priv=inbound_priv)
    _, transport = _build_downstream_recorder()
    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    resp = client.post(
        "/mcp/customer_data",
        content=b"not-json",
        headers={"Authorization": f"Bearer {token}", "content-type": "application/json"},
    )
    assert resp.status_code == 400


def test_unsupported_method_returns_400(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    token, _ = _mint_user_token(inbound_priv=inbound_priv)
    _, transport = _build_downstream_recorder()
    client = _client(inbound_pub=inbound_pub, service_priv=service_priv, transport=transport)
    resp = client.post(
        "/mcp/customer_data",
        json={"jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32601


def test_replay_cache_capacity_enforced() -> None:
    cache = ReplayCache(capacity=3)
    far_future = time.time() + 3600
    assert cache.seen("a", far_future) is False
    assert cache.seen("b", far_future) is False
    assert cache.seen("c", far_future) is False
    assert cache.seen("a", far_future) is True  # still tracked
    # Inserting "d" should evict the LRU entry (which is now "b" — "a" was touched).
    assert cache.seen("d", far_future) is False
    assert len(cache) == 3
    # "b" got evicted, so seen() returns False (and re-records it).
    assert cache.seen("b", far_future) is False


def test_replay_cache_expired_entry_treated_as_unseen() -> None:
    cache = ReplayCache(capacity=10)
    past = time.time() - 1
    assert cache.seen("a", past) is False
    # Now seen again — the previous entry is expired and dropped.
    far_future = time.time() + 3600
    assert cache.seen("a", far_future) is False
    assert cache.seen("a", far_future) is True


# --------------------------------------------------------------------------- #
# Per-server downstream URL routing (US-024)                                  #
# --------------------------------------------------------------------------- #


def test_downstream_urls_map_routes_each_server_to_its_own_host(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    """When the gateway is configured with a per-server URL map, each call
    must hit the URL keyed by the server segment in the request path."""
    inbound_priv, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    captured: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {"content": [], "structuredContent": {}}},
        )

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    app = create_app(
        downstream_urls={
            "customer_data": "http://cust-host:1111",
            "transactions": "http://tx-host:2222",
        },
        service_private_key_path=service_priv,
        inbound_public_key_path=inbound_pub,
        http_client=http_client,
    )
    client = TestClient(app)

    token1, _ = _mint_user_token(inbound_priv=inbound_priv, trace_id="trace-A")
    resp = client.post(
        "/mcp/customer_data",
        json=_rpc_call("get_customer", {"customer_id": "c-1"}),
        headers={"Authorization": f"Bearer {token1}"},
    )
    assert resp.status_code == 200

    token2, _ = _mint_user_token(inbound_priv=inbound_priv, trace_id="trace-B")
    resp = client.post(
        "/mcp/transactions",
        json=_rpc_call("get_transactions", {"customer_id": "c-1"}),
        headers={"Authorization": f"Bearer {token2}"},
    )
    assert resp.status_code == 200

    assert len(captured) == 2
    assert str(captured[0].url) == "http://cust-host:1111/customer_data"
    assert str(captured[1].url) == "http://tx-host:2222/transactions"


def test_downstream_url_acts_as_fallback_when_server_not_in_map(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    """A server name absent from the map falls back to ``downstream_url`` —
    same behavior as before US-024 but expressed via the map fallback."""
    inbound_priv, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    captured: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {"content": [], "structuredContent": {}}},
        )

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    app = create_app(
        downstream_url="http://fallback-host:9999",
        downstream_urls={"customer_data": "http://cust-host:1111"},
        service_private_key_path=service_priv,
        inbound_public_key_path=inbound_pub,
        http_client=http_client,
    )
    client = TestClient(app)

    token, _ = _mint_user_token(
        inbound_priv=inbound_priv,
        allowed_servers=["customer_data", "kyc"],
        allowed_tools={"customer_data": ["get_customer"], "kyc": ["get_kyc_record"]},
    )
    # kyc is NOT in the map -> falls back.
    resp = client.post(
        "/mcp/kyc",
        json=_rpc_call("get_kyc_record", {"customer_id": "c-1"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert str(captured[0].url) == "http://fallback-host:9999/kyc"


def test_unknown_server_with_no_fallback_returns_502(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    """If a server is allowed by RBAC but absent from the URL map AND no
    fallback URL is set, the gateway must surface a clean structured 502
    rather than crashing or attempting an empty URL request."""
    inbound_priv, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    _, transport = _build_downstream_recorder()
    http_client = httpx.AsyncClient(transport=transport)
    app = create_app(
        downstream_urls={"customer_data": "http://cust-host:1111"},
        service_private_key_path=service_priv,
        inbound_public_key_path=inbound_pub,
        http_client=http_client,
    )
    client = TestClient(app)

    token, _ = _mint_user_token(
        inbound_priv=inbound_priv,
        allowed_servers=["transactions"],
        allowed_tools={"transactions": ["get_transactions"]},
    )
    resp = client.post(
        "/mcp/transactions",
        json=_rpc_call("get_transactions", {"customer_id": "c-1"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 502
    body = resp.json()
    assert body["error"]["data"]["deny_reason"] == DenyReason.DOWNSTREAM_ERROR


def test_create_app_requires_at_least_one_downstream_form(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
) -> None:
    _, inbound_pub = inbound_keys
    service_priv, _ = service_keys
    with pytest.raises(ValueError):
        create_app(
            service_private_key_path=service_priv,
            inbound_public_key_path=inbound_pub,
        )
