"""Tests for the case_actions MCP server (mcp_servers/case_actions/main.py).

Covers:
    * Service PASETO validation (rejects unsigned/expired/wrong-keypair).
    * **The human-approval gate** — calls without ``human_approval=true``
      claim are denied with ``deny_reason=human_approval_required`` before
      any tool dispatch.
    * Contract: tool names + input schemas (US-016 acceptance).
    * Tool dispatch: ``create_sar_draft`` / ``freeze_account`` /
      ``escalate_to_l3`` write to the mock and return MCP-shaped results.
    * End-to-end: MCP gateway -> case_actions MCP server -> mock yields the
      expected payload + an audit row + a deny when the user token lacks
      ``human_approval=true``.
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
from mcp_servers.case_actions.main import (
    DEFAULT_API_URL,
    HUMAN_APPROVAL_REQUIRED,
    SERVER_NAME,
    TOOL_NAMES,
    build_mcp,
    create_app,
    deny_if_missing_human_approval,
)
from mock_apis.case_actions.main import CaseStore
from mock_apis.case_actions.main import create_app as create_mock_app

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
def mock_store() -> CaseStore:
    return CaseStore()


@pytest.fixture()
def mock_api_client(mock_store: CaseStore) -> Iterator[httpx.AsyncClient]:
    """In-process ASGI client into the case_actions mock API."""
    mock_app = create_mock_app(store=mock_store)
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
    *,
    service_priv: Path,
    sub: str = "bob@example.com",
    ttl: int = 60,
    human_approval: bool = True,
) -> str:
    claims = Claims(
        sub=sub,
        roles=["l3_admin"],
        allowed_servers=["case_actions"],
        allowed_tools={
            "case_actions": [
                "create_sar_draft",
                "freeze_account",
                "escalate_to_l3",
            ],
        },
        trace_id="trace-abc",
        human_approval=human_approval,
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
    """PRD US-016: server must expose three write-path tools."""
    assert set(TOOL_NAMES) == {
        "create_sar_draft",
        "freeze_account",
        "escalate_to_l3",
    }


def test_server_name_matches_gateway_url_segment() -> None:
    assert SERVER_NAME == "case_actions"


def test_default_api_url_constant() -> None:
    assert DEFAULT_API_URL.startswith("http://")


def test_human_approval_required_constant() -> None:
    assert HUMAN_APPROVAL_REQUIRED == "human_approval_required"


def test_build_mcp_registers_three_tools(
    mock_api_client: httpx.AsyncClient,
) -> None:
    import asyncio

    mcp = build_mcp(mock_api_client)
    tools = asyncio.run(mcp.list_tools(run_middleware=False))
    names = {t.name for t in tools}
    assert names == set(TOOL_NAMES)


# --------------------------------------------------------------------------- #
# deny_if_missing_human_approval unit                                         #
# --------------------------------------------------------------------------- #


def test_deny_helper_passes_when_approval_present() -> None:
    claims = Claims(sub="bob@example.com", human_approval=True)
    assert deny_if_missing_human_approval(claims) is None


def test_deny_helper_denies_when_approval_missing() -> None:
    claims = Claims(sub="bob@example.com", human_approval=False)
    resp = deny_if_missing_human_approval(claims)
    assert resp is not None
    assert resp.status_code == 403


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
        json=_rpc_call("freeze_account", {"account_id": "x", "reason": "y", "requested_by": "z"}),
    )
    assert resp.status_code == 401


def test_garbage_token_is_rejected(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    _, service_pub = service_keys
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call("freeze_account", {"account_id": "x", "reason": "y", "requested_by": "z"}),
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
        json=_rpc_call("freeze_account", {"account_id": "x", "reason": "y", "requested_by": "z"}),
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
        json=_rpc_call("freeze_account", {"account_id": "x", "reason": "y", "requested_by": "z"}),
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
        json=_rpc_call("freeze_account", {"account_id": "x", "reason": "y", "requested_by": "z"}),
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
# Human-approval gate — the load-bearing US-016 acceptance                    #
# --------------------------------------------------------------------------- #


def test_call_without_human_approval_is_denied(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    """US-016 acceptance: call without human_approval=true claim is denied."""
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv, human_approval=False)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "freeze_account",
            {"account_id": "acct_x", "reason": "test", "requested_by": "bob"},
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403, resp.text
    body = resp.json()
    assert body["error"]["data"]["deny_reason"] == HUMAN_APPROVAL_REQUIRED


def test_call_with_human_approval_succeeds(
    service_keys: tuple[Path, Path],
    mock_api_client: httpx.AsyncClient,
    mock_store: CaseStore,
) -> None:
    """US-016 acceptance: call WITH human_approval=true claim succeeds."""
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv, human_approval=True)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "freeze_account",
            {
                "account_id": "acct_cust_x_00",
                "reason": "structuring deposits",
                "requested_by": "bob@example.com",
            },
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    structured = _assert_mcp_shape(resp.json())
    assert structured["status"] == "frozen"
    assert "acct_cust_x_00" in mock_store.freezes


def test_human_approval_gate_runs_before_tool_dispatch(
    service_keys: tuple[Path, Path],
    mock_api_client: httpx.AsyncClient,
    mock_store: CaseStore,
) -> None:
    """A denied call must NOT have written anything to the mock."""
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv, human_approval=False)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "create_sar_draft",
            {
                "customer_id": "cust_z",
                "narrative": "n",
                "typology": "t",
            },
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    # Mock journal is untouched.
    assert mock_store.sar_drafts == {}


def test_tools_list_also_requires_human_approval(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    """The gate runs once per request — tools/list is also gated."""
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv, human_approval=False)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["data"]["deny_reason"] == HUMAN_APPROVAL_REQUIRED


# --------------------------------------------------------------------------- #
# Contract: tools/list                                                        #
# --------------------------------------------------------------------------- #


def test_tools_list_schemas_match_case_actions_contract(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    """Contract fence for case_actions skills (US-019/US-020).

    Two-way: this test pins the server-side schema; future SKILL.md files
    that invoke these tools must declare the same required/optional split.
    """
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv, human_approval=True)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    tools = {t["name"]: t for t in resp.json()["result"]["tools"]}

    expected: dict[str, dict[str, list[str]]] = {
        "create_sar_draft": {
            "required": ["customer_id", "narrative", "typology"],
            "optional": ["related_accounts"],
        },
        "freeze_account": {
            "required": ["account_id", "reason", "requested_by"],
            "optional": [],
        },
        "escalate_to_l3": {
            "required": ["case_id", "summary", "severity", "requested_by"],
            "optional": [],
        },
    }
    for name, contract in expected.items():
        assert name in tools, name
        schema = tools[name]["inputSchema"]
        for req in contract["required"]:
            assert req in schema.get("required", []), (
                f"{name} missing required {req}"
            )
            assert req in schema["properties"]
        for opt in contract["optional"]:
            assert opt in schema["properties"]
            assert opt not in schema.get("required", [])


# --------------------------------------------------------------------------- #
# tools/call: happy path                                                      #
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


def test_create_sar_draft_writes_to_mock(
    service_keys: tuple[Path, Path],
    mock_api_client: httpx.AsyncClient,
    mock_store: CaseStore,
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv, human_approval=True)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "create_sar_draft",
            {
                "customer_id": "cust_abc",
                "narrative": "Mule typology suspected.",
                "typology": "money_mule",
                "related_accounts": ["acct_cust_abc_00"],
            },
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    structured = _assert_mcp_shape(resp.json())
    assert structured["status"] == "draft"
    assert structured["customer_id"] == "cust_abc"
    assert structured["draft_id"] in mock_store.sar_drafts


def test_escalate_to_l3_writes_to_mock(
    service_keys: tuple[Path, Path],
    mock_api_client: httpx.AsyncClient,
    mock_store: CaseStore,
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv, human_approval=True)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "escalate_to_l3",
            {
                "case_id": "case_2025_xyz",
                "summary": "Sanctions hit + mule pattern.",
                "severity": "high",
                "requested_by": "bob@example.com",
            },
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    structured = _assert_mcp_shape(resp.json())
    assert structured["status"] == "escalated_l3"
    assert structured["case_id"] == "case_2025_xyz"
    assert structured["escalation_id"] in mock_store.escalations


# --------------------------------------------------------------------------- #
# Error paths                                                                 #
# --------------------------------------------------------------------------- #


def test_unknown_tool_returns_method_not_found(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv, human_approval=True)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call("nope", {"x": "y"}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


def test_unsupported_method_returns_400(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv, human_approval=True)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/eat"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400


def test_missing_required_arg_surfaces_upstream_422(
    service_keys: tuple[Path, Path], mock_api_client: httpx.AsyncClient
) -> None:
    """Mock returns 422 when a required body field is missing — server
    surfaces it via the upstream-status passthrough."""
    service_priv, service_pub = service_keys
    token = _service_token(service_priv=service_priv, human_approval=True)
    client = _server_client(service_pub=service_pub, mock_client=mock_api_client)
    resp = client.post(
        f"/{SERVER_NAME}",
        json=_rpc_call(
            "create_sar_draft",
            {"customer_id": "x", "narrative": "", "typology": "t"},
        ),
        headers={"Authorization": f"Bearer {token}"},
    )
    # Server passes the upstream 422 through; body carries upstream_status.
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["data"]["upstream_status"] == 422


# --------------------------------------------------------------------------- #
# End-to-end: MCP gateway -> case_actions server -> mock                      #
# --------------------------------------------------------------------------- #


def test_human_approval_claim_propagates_through_gateway_e2e(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    mock_api_client: httpx.AsyncClient,
    mock_store: CaseStore,
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    """User PASETO with human_approval=true -> gateway -> server -> mock
    yields expected payload + an audit row."""
    inbound_priv, inbound_pub = inbound_keys
    service_priv, service_pub = service_keys

    server_app = create_app(
        public_key_path=service_pub, api_client=mock_api_client
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
        sub="bob@example.com",
        roles=["l3_admin"],
        allowed_servers=["case_actions"],
        allowed_tools={
            "case_actions": [
                "create_sar_draft",
                "freeze_account",
                "escalate_to_l3",
            ],
        },
        trace_id="trace-e2e-case-actions",
        human_approval=True,
    )
    user_token = mint(user_claims, ttl_seconds=300, private_key_path=inbound_priv)

    resp = gateway_client.post(
        f"/mcp/{SERVER_NAME}",
        json=_rpc_call(
            "freeze_account",
            {
                "account_id": "acct_cust_e2e_00",
                "reason": "sanctions hit confirmed",
                "requested_by": "bob@example.com",
            },
        ),
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 200, resp.text
    structured = _assert_mcp_shape(resp.json())
    assert structured["status"] == "frozen"
    assert "acct_cust_e2e_00" in mock_store.freezes

    memory_audit_backend.flush()
    rows = memory_audit_backend.query(sub="bob@example.com")
    assert len(rows) == 1
    row = rows[0]
    assert row["server"] == "case_actions"
    assert row["tool"] == "freeze_account"
    assert row["status"] == "ok"
    assert row["trace_id"] == "trace-e2e-case-actions"


def test_user_without_human_approval_is_denied_at_server_e2e(
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    mock_api_client: httpx.AsyncClient,
    mock_store: CaseStore,
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    """End-to-end: user token WITHOUT human_approval=true is denied by the
    case_actions server (the gateway forwards happily because RBAC passes).
    The mock is never touched.
    """
    inbound_priv, inbound_pub = inbound_keys
    service_priv, service_pub = service_keys

    server_app = create_app(
        public_key_path=service_pub, api_client=mock_api_client
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
        sub="bob@example.com",
        roles=["l3_admin"],
        allowed_servers=["case_actions"],
        allowed_tools={
            "case_actions": [
                "create_sar_draft",
                "freeze_account",
                "escalate_to_l3",
            ],
        },
        trace_id="trace-e2e-case-actions-denied",
        human_approval=False,
    )
    user_token = mint(user_claims, ttl_seconds=300, private_key_path=inbound_priv)

    resp = gateway_client.post(
        f"/mcp/{SERVER_NAME}",
        json=_rpc_call(
            "freeze_account",
            {
                "account_id": "acct_should_not_exist",
                "reason": "no approval",
                "requested_by": "bob@example.com",
            },
        ),
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 403, resp.text
    body = resp.json()
    assert body["error"]["data"]["deny_reason"] == HUMAN_APPROVAL_REQUIRED

    # Mock untouched.
    assert mock_store.freezes == {}
