"""Tests for the osint MCP server (mcp_servers/osint/main.py).

Covers:
    * Service PASETO validation (rejects unsigned/expired/wrong-keypair).
    * Contract: tool names + input schemas (US-015 acceptance).
    * Tool dispatch: ``web_search`` / ``fetch_page`` / ``lookup_company``
      hit the osint mock API and return MCP-shaped results.
    * The **outbound allowlist** — the single most load-bearing requirement
      of US-015. Non-allowlisted URLs are rejected before any upstream
      fetch happens; allowlisted URLs pass through.
    * End-to-end: MCP gateway -> osint MCP server -> osint mock API
      yields the expected payload + an audit row.
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
from mcp_servers.osint.main import (
    DEFAULT_API_URL,
    SERVER_NAME,
    TOOL_NAMES,
    build_mcp,
    create_app,
    is_url_allowed,
    parse_allowlist,
)
from mock_apis.osint.main import create_app as create_mock_app

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
    return _write_keypair(tmp_path, "service")


@pytest.fixture()
def inbound_keys(tmp_path: Path) -> tuple[Path, Path]:
    return _write_keypair(tmp_path, "inbound")


@pytest.fixture()
def mock_api_client() -> Iterator[httpx.AsyncClient]:
    """In-process ASGI client into the osint mock API (US-015)."""
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
        allowed_servers=["osint"],
        allowed_tools={
            "osint": ["web_search", "fetch_page", "lookup_company"],
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
    *,
    service_pub: Path,
    mock_client: httpx.AsyncClient,
    allowlist: frozenset[str] | None = None,
) -> TestClient:
    app = create_app(
        public_key_path=service_pub,
        api_client=mock_client,
        allowlist=allowlist if allowlist is not None else frozenset(),
    )
    return TestClient(app)


# --------------------------------------------------------------------------- #
# Module-level sanity                                                         #
# --------------------------------------------------------------------------- #


def test_tool_names_constant_matches_prd() -> None:
    """PRD US-015: server must expose three tools."""
    assert set(TOOL_NAMES) == {"web_search", "fetch_page", "lookup_company"}


def test_server_name_matches_gateway_url_segment() -> None:
    assert SERVER_NAME == "osint"


def test_default_api_url_constant() -> None:
    assert DEFAULT_API_URL.startswith("http://")


def test_build_mcp_registers_three_tools() -> None:
    import asyncio

    transport = httpx.ASGITransport(app=create_mock_app())
    client = httpx.AsyncClient(transport=transport, base_url="http://mock")
    try:
        mcp = build_mcp(client, frozenset())
        tools = asyncio.run(mcp.list_tools(run_middleware=False))
        names = {t.name for t in tools}
        assert names == set(TOOL_NAMES)
    finally:
        asyncio.run(client.aclose())


# --------------------------------------------------------------------------- #
# Allowlist parsing                                                           #
# --------------------------------------------------------------------------- #


def test_parse_allowlist_empty_string_is_empty_set() -> None:
    assert parse_allowlist("") == frozenset()
    assert parse_allowlist(None) == frozenset()


def test_parse_allowlist_normalizes_case_and_whitespace() -> None:
    assert parse_allowlist("  Ofac.Example, sec.example ") == frozenset(
        {"ofac.example", "sec.example"}
    )


def test_parse_allowlist_drops_empty_entries() -> None:
    assert parse_allowlist("ofac.example,,sec.example,") == frozenset(
        {"ofac.example", "sec.example"}
    )


def test_is_url_allowed_exact_host_match() -> None:
    allow = frozenset({"ofac.example"})
    assert is_url_allowed("https://ofac.example/sdn/x", allow) is True
    # Different host.
    assert is_url_allowed("https://reuters.example/x", allow) is False
    # Subdomain — exact match only, no wildcards.
    assert is_url_allowed("https://api.ofac.example/x", allow) is False


def test_is_url_allowed_rejects_no_host_urls() -> None:
    allow = frozenset({"ofac.example"})
    assert is_url_allowed("data:text/plain,hi", allow) is False
    assert is_url_allowed("not-a-url", allow) is False
    assert is_url_allowed("", allow) is False


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
        json=_rpc_call("web_search", {"query": "x"}),
    )
    assert resp.status_code == 401


def test_garbage_token_is_rejected(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    _, service_pub = service_keys
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call("web_search", {"query": "x"}),
        headers={"Authorization": "Bearer not-a-paseto"},
    )
    assert resp.status_code == 401


def test_expired_token_is_rejected(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv, ttl=1)
    time.sleep(2)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call("web_search", {"query": "x"}),
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
        json=_rpc_call("web_search", {"query": "x"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


def test_invalid_authorization_scheme_is_rejected(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    _, service_pub = service_keys
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call("web_search", {"query": "x"}),
        headers={"Authorization": "Basic deadbeef"},
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


def test_tools_list_schemas_match_osint_contract(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    """Contract fence for the check-osint SKILL.md (US-018).

    Two-way: this test pins the server-side schema; when US-018 lands its
    SKILL.md frontmatter must agree, and the SKILL.md must declare exactly
    these tools with the same required/optional split.
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

    expected = {
        "web_search": {"required": ["query"], "optional": ["scenario"]},
        "fetch_page": {"required": ["url"], "optional": ["scenario"]},
        "lookup_company": {
            "required": ["company_name"],
            "optional": ["scenario"],
        },
    }
    for name, contract in expected.items():
        assert name in tools, name
        schema = tools[name]["inputSchema"]
        for req in contract["required"]:
            assert req in schema["required"], f"{name} missing required {req}"
            assert req in schema["properties"]
        for opt in contract["optional"]:
            assert opt in schema["properties"]
            assert opt not in schema["required"]


# --------------------------------------------------------------------------- #
# tools/call: web_search, lookup_company                                      #
# --------------------------------------------------------------------------- #


def _assert_mcp_shape(body: dict[str, Any]) -> dict[str, Any]:
    assert body["jsonrpc"] == "2.0"
    assert "result" in body, body
    result = body["result"]
    assert isinstance(result["content"], list)
    assert len(result["content"]) >= 1
    assert result["content"][0]["type"] == "text"
    assert isinstance(result["structuredContent"], dict)
    return result["structuredContent"]


def test_web_search_returns_results(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "web_search",
            {"query": "Alice Smith", "scenario": "sanctions_hit"},
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    structured = _assert_mcp_shape(resp.json())
    assert structured["adverse_count"] >= 1
    assert len(structured["results"]) >= 1


def test_lookup_company_returns_record(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "lookup_company",
            {"company_name": "Acme", "scenario": "sanctions_hit"},
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    structured = _assert_mcp_shape(resp.json())
    assert "sanctioned_owner" in structured["risk_signals"]


# --------------------------------------------------------------------------- #
# fetch_page allowlist enforcement — the load-bearing US-015 test             #
# --------------------------------------------------------------------------- #


def test_fetch_page_non_allowlisted_domain_is_blocked(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    """US-015 acceptance: a request to a non-allowlisted domain is blocked.

    Default allowlist is empty, so any URL is rejected. The deny carries
    ``deny_reason="domain_not_allowed"`` so the gateway's audit row can
    group on it alongside the other DenyReason codes.
    """
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(
        service_pub=service_pub,
        mock_client=mock_api_client,
        allowlist=frozenset(),  # empty allowlist
    )
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "fetch_page",
            {"url": "https://attacker.example/exfil", "scenario": "clean"},
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body["error"]["data"]["deny_reason"] == "domain_not_allowed"
    assert body["error"]["data"]["host"] == "attacker.example"


def test_fetch_page_allowlisted_domain_passes_through(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    """When the URL's host is on the allowlist, fetch_page succeeds."""
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(
        service_pub=service_pub,
        mock_client=mock_api_client,
        allowlist=frozenset({"ofac.example"}),
    )
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "fetch_page",
            {
                "url": "https://ofac.example/actions/alice-smith",
                "scenario": "sanctions_hit",
            },
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    structured = _assert_mcp_shape(resp.json())
    assert structured["adverse"] is True
    assert structured["url"] == "https://ofac.example/actions/alice-smith"


def test_fetch_page_subdomain_is_not_allowed(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    """Allowlist matching is exact-host — no subdomain wildcards."""
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(
        service_pub=service_pub,
        mock_client=mock_api_client,
        allowlist=frozenset({"ofac.example"}),
    )
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "fetch_page",
            {"url": "https://api.ofac.example/x", "scenario": "clean"},
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["data"]["deny_reason"] == "domain_not_allowed"


def test_fetch_page_malformed_url_is_blocked(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(
        service_pub=service_pub,
        mock_client=mock_api_client,
        allowlist=frozenset({"ofac.example"}),
    )
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call("fetch_page", {"url": "not-a-url"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


def test_fetch_page_env_var_allowlist(
    monkeypatch: pytest.MonkeyPatch,
    service_keys: tuple[Path, Path],
    mock_api_client: httpx.AsyncClient,
) -> None:
    """When ``allowlist=None``, the factory reads OSINT_ALLOWLIST."""
    monkeypatch.setenv("OSINT_ALLOWLIST", "ofac.example, sec.example")
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    # Pass allowlist=None to force the env-var path.
    app = create_app(
        public_key_path=service_pub,
        api_client=mock_api_client,
        allowlist=None,
    )
    client = TestClient(app)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "fetch_page",
            {"url": "https://sec.example/filing/123", "scenario": "clean"},
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200


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
        json=_rpc_call("nope", {"query": "x"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


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


def test_unknown_scenario_surfaces_as_upstream_400(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "web_search", {"query": "x", "scenario": "nonsense"}
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"]["data"]["upstream_status"] == 400


def test_scenario_omitted_uses_mock_default(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call("web_search", {"query": "Alice Smith"}),
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
# End-to-end: MCP gateway -> osint server -> osint mock                       #
# --------------------------------------------------------------------------- #


def test_gateway_to_server_to_mock_end_to_end(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    mock_api_client: httpx.AsyncClient,
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    """User PASETO -> gateway -> osint server -> mock returns expected payload."""
    inbound_priv, inbound_pub = inbound_keys
    service_priv, service_pub = service_keys

    server_app = create_app(
        public_key_path=service_pub,
        api_client=mock_api_client,
        allowlist=frozenset({"ofac.example"}),
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
        allowed_servers=["osint"],
        allowed_tools={
            "osint": ["web_search", "fetch_page", "lookup_company"],
        },
        trace_id="trace-e2e-osint",
    )
    user_token = mint(user_claims, ttl_seconds=300, private_key_path=inbound_priv)

    resp = gateway_client.post(
        f"/mcp/{SERVER_NAME}",
        json=_rpc_call(
            "web_search",
            {"query": "Alice Smith", "scenario": "sanctions_hit"},
        ),
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 200, resp.text
    structured = _assert_mcp_shape(resp.json())
    assert structured["adverse_count"] >= 1

    memory_audit_backend.flush()
    rows = memory_audit_backend.query(sub="alice@example.com")
    assert len(rows) == 1
    row = rows[0]
    assert row["server"] == "osint"
    assert row["tool"] == "web_search"
    assert row["status"] == "ok"
    assert row["trace_id"] == "trace-e2e-osint"


def test_gateway_blocks_non_allowlisted_fetch_page_e2e(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    mock_api_client: httpx.AsyncClient,
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    """End-to-end: a non-allowlisted fetch_page deny propagates through the gateway."""
    inbound_priv, inbound_pub = inbound_keys
    service_priv, service_pub = service_keys

    server_app = create_app(
        public_key_path=service_pub,
        api_client=mock_api_client,
        allowlist=frozenset({"ofac.example"}),
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
        allowed_servers=["osint"],
        allowed_tools={
            "osint": ["web_search", "fetch_page", "lookup_company"],
        },
        trace_id="trace-e2e-osint-block",
    )
    user_token = mint(user_claims, ttl_seconds=300, private_key_path=inbound_priv)

    resp = gateway_client.post(
        f"/mcp/{SERVER_NAME}",
        json=_rpc_call(
            "fetch_page",
            {"url": "https://attacker.example/exfil", "scenario": "clean"},
        ),
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 403, resp.text
    body = resp.json()
    assert body["error"]["data"]["deny_reason"] == "domain_not_allowed"
    assert body["error"]["data"]["host"] == "attacker.example"
