"""Tests for gateways.common.rbac."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from gateways.common.rbac import (
    RBACConfigError,
    RBACLoader,
    UnknownUserError,
    get_loader,
    reset_default_loader,
    resolve_user,
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _reset_default_loader():
    reset_default_loader()
    yield
    reset_default_loader()


# --------------------------------------------------------------------------- #
# Schema parsing & basic resolution
# --------------------------------------------------------------------------- #


def test_simple_role(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "rbac.yaml",
        """
roles:
  analyst:
    allowed_servers: [customer_data]
    allowed_tools:
      customer_data: [get_customer, list_accounts]
users:
  alice@example.com:
    roles: [analyst]
""",
    )
    loader = RBACLoader(cfg)
    out = loader.resolve_user("alice@example.com")
    assert out.email == "alice@example.com"
    assert out.roles == ["analyst"]
    assert out.allowed_servers == ["customer_data"]
    assert out.allowed_tools == {"customer_data": ["get_customer", "list_accounts"]}


def test_inherited_role_merges_servers_and_tools(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "rbac.yaml",
        """
roles:
  base:
    allowed_servers: [customer_data]
    allowed_tools:
      customer_data: [get_customer]
  analyst:
    inherits: [base]
    allowed_servers: [transactions]
    allowed_tools:
      customer_data: [list_accounts]
      transactions: [get_transactions]
users:
  bob@example.com:
    roles: [analyst]
""",
    )
    loader = RBACLoader(cfg)
    out = loader.resolve_user("bob@example.com")
    assert out.allowed_servers == ["customer_data", "transactions"]
    assert out.allowed_tools == {
        "customer_data": ["get_customer", "list_accounts"],
        "transactions": ["get_transactions"],
    }


def test_denied_tool_not_in_allowlist(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "rbac.yaml",
        """
roles:
  read_only:
    allowed_servers: [customer_data]
    allowed_tools:
      customer_data: [get_customer]
users:
  carol@example.com:
    roles: [read_only]
""",
    )
    loader = RBACLoader(cfg)
    out = loader.resolve_user("carol@example.com")
    # The loader's job is to return the allowlist; the gateway enforces. We
    # assert that an excluded tool is *not* in the resolved map.
    assert "list_accounts" not in out.allowed_tools["customer_data"]


def test_group_mapped_role(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "rbac.yaml",
        """
roles:
  analyst:
    allowed_servers: [customer_data]
    allowed_tools:
      customer_data: [get_customer]
  l3_admin:
    allowed_servers: [case_actions]
    allowed_tools:
      case_actions: [freeze_account]
users: {}
groups:
  fraud-analysts:
    roles: [analyst]
  fraud-l3:
    roles: [l3_admin]
""",
    )
    loader = RBACLoader(cfg)
    out = loader.resolve_user(
        "dora@example.com", groups=["fraud-analysts", "fraud-l3"]
    )
    assert out.roles == ["analyst", "l3_admin"]
    assert out.allowed_servers == ["case_actions", "customer_data"]
    assert out.allowed_tools["case_actions"] == ["freeze_account"]


def test_user_and_group_roles_combined(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "rbac.yaml",
        """
roles:
  analyst:
    allowed_servers: [customer_data]
    allowed_tools:
      customer_data: [get_customer]
  on_call:
    allowed_servers: [transactions]
    allowed_tools:
      transactions: [get_transactions]
users:
  eve@example.com:
    roles: [analyst]
groups:
  oncall:
    roles: [on_call]
""",
    )
    loader = RBACLoader(cfg)
    out = loader.resolve_user("eve@example.com", groups=["oncall"])
    assert out.roles == ["analyst", "on_call"]
    assert set(out.allowed_servers) == {"customer_data", "transactions"}


def test_wildcard_per_server(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "rbac.yaml",
        """
roles:
  data_reader:
    allowed_servers: [customer_data]
    allowed_tools:
      customer_data: "*"
users:
  faye@example.com:
    roles: [data_reader]
""",
    )
    out = RBACLoader(cfg).resolve_user("faye@example.com")
    assert out.allowed_tools == {"customer_data": ["*"]}


def test_wildcard_top_level(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "rbac.yaml",
        """
roles:
  super:
    allowed_servers: [customer_data, transactions]
    allowed_tools: "*"
users:
  root@example.com:
    roles: [super]
""",
    )
    out = RBACLoader(cfg).resolve_user("root@example.com")
    assert out.allowed_tools == {"*": ["*"]}


def test_wildcard_absorbs_specific_tools_when_merged(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "rbac.yaml",
        """
roles:
  reader:
    allowed_servers: [customer_data]
    allowed_tools:
      customer_data: [get_customer]
  reader_plus:
    inherits: [reader]
    allowed_tools:
      customer_data: "*"
users:
  gwen@example.com:
    roles: [reader_plus]
""",
    )
    out = RBACLoader(cfg).resolve_user("gwen@example.com")
    assert out.allowed_tools == {"customer_data": ["*"]}


# --------------------------------------------------------------------------- #
# Error paths
# --------------------------------------------------------------------------- #


def test_conflicting_inheritance_cycle_rejected(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "rbac.yaml",
        """
roles:
  a:
    inherits: [b]
  b:
    inherits: [a]
""",
    )
    with pytest.raises(RBACConfigError, match="cycle"):
        RBACLoader(cfg)


def test_self_referential_inheritance_rejected(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "rbac.yaml",
        """
roles:
  a:
    inherits: [a]
""",
    )
    with pytest.raises(RBACConfigError, match="cycle"):
        RBACLoader(cfg)


def test_unknown_role_reference_rejected(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "rbac.yaml",
        """
roles:
  analyst: {}
users:
  alice@example.com:
    roles: [nonexistent]
""",
    )
    with pytest.raises(RBACConfigError, match="unknown role"):
        RBACLoader(cfg)


def test_unknown_user_raises(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "rbac.yaml",
        """
roles:
  analyst:
    allowed_servers: [customer_data]
users:
  alice@example.com:
    roles: [analyst]
""",
    )
    loader = RBACLoader(cfg)
    with pytest.raises(UnknownUserError):
        loader.resolve_user("ghost@example.com")


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(RBACConfigError, match="not found"):
        RBACLoader(tmp_path / "does-not-exist.yaml")


# --------------------------------------------------------------------------- #
# Diamond inheritance (a inherits b,c; b and c both inherit base)
# --------------------------------------------------------------------------- #


def test_diamond_inheritance(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / "rbac.yaml",
        """
roles:
  base:
    allowed_servers: [customer_data]
    allowed_tools:
      customer_data: [get_customer]
  left:
    inherits: [base]
    allowed_tools:
      customer_data: [list_accounts]
  right:
    inherits: [base]
    allowed_servers: [transactions]
    allowed_tools:
      transactions: [get_transactions]
  combo:
    inherits: [left, right]
users:
  hugo@example.com:
    roles: [combo]
""",
    )
    out = RBACLoader(cfg).resolve_user("hugo@example.com")
    assert out.allowed_servers == ["customer_data", "transactions"]
    assert out.allowed_tools == {
        "customer_data": ["get_customer", "list_accounts"],
        "transactions": ["get_transactions"],
    }


# --------------------------------------------------------------------------- #
# Hot reload
# --------------------------------------------------------------------------- #


def test_hot_reload_within_5_seconds(tmp_path: Path) -> None:
    cfg = tmp_path / "rbac.yaml"
    _write(
        cfg,
        """
roles:
  analyst:
    allowed_servers: [customer_data]
    allowed_tools:
      customer_data: [get_customer]
users:
  alice@example.com:
    roles: [analyst]
""",
    )
    loader = RBACLoader(cfg)
    assert loader.resolve_user("alice@example.com").allowed_tools == {
        "customer_data": ["get_customer"]
    }

    # Modify the file and bump its mtime forward — the loader watches mtime,
    # so we don't actually have to wait 5 seconds for it to notice.
    start = time.monotonic()
    _write(
        cfg,
        """
roles:
  analyst:
    allowed_servers: [customer_data, transactions]
    allowed_tools:
      customer_data: [get_customer, list_accounts]
      transactions: [get_transactions]
users:
  alice@example.com:
    roles: [analyst]
""",
    )
    # Guarantee mtime moves on filesystems with 1s resolution (e.g. some
    # macOS configurations) without making the test slow.
    new_mtime = cfg.stat().st_mtime + 1
    os.utime(cfg, (new_mtime, new_mtime))

    out = loader.resolve_user("alice@example.com")
    elapsed = time.monotonic() - start
    assert elapsed < 5.0
    assert out.allowed_servers == ["customer_data", "transactions"]
    assert out.allowed_tools == {
        "customer_data": ["get_customer", "list_accounts"],
        "transactions": ["get_transactions"],
    }


# --------------------------------------------------------------------------- #
# Module-level convenience / env var
# --------------------------------------------------------------------------- #


def test_module_resolve_uses_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _write(
        tmp_path / "rbac.yaml",
        """
roles:
  analyst:
    allowed_servers: [customer_data]
    allowed_tools:
      customer_data: [get_customer]
users:
  alice@example.com:
    roles: [analyst]
""",
    )
    monkeypatch.setenv("RBAC_CONFIG_PATH", str(cfg))
    reset_default_loader()
    out = resolve_user("alice@example.com")
    assert out.roles == ["analyst"]
    # get_loader should return the same instance.
    assert get_loader().path == cfg
