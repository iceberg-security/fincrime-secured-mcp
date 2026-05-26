"""Unit tests for gateways/common/audit.py."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from gateways.common import audit as audit_mod
from gateways.common.audit import (
    AuditEvent,
    Redactor,
    SQLiteAuditBackend,
    build_default_backend,
)


@pytest.fixture(autouse=True)
def _reset_default() -> None:
    """Drop any process-wide default backend between tests."""
    audit_mod.reset_default_backend()
    yield
    audit_mod.reset_default_backend()


def _make_event(
    *,
    jti: str,
    sub: str = "alice@example.com",
    role: str = "analyst",
    server: str = "customer_data",
    tool: str = "get_customer",
    args: dict | None = None,
    status: str = "ok",
    deny_reason: str | None = None,
    trace_id: str = "trace-1",
) -> AuditEvent:
    return AuditEvent(
        sub=sub,
        role=role,
        server=server,
        tool=tool,
        jti=jti,
        trace_id=trace_id,
        args_preview=args if args is not None else {"customer_id": "c-1"},
        result_hash="r-1",
        status=status,
        deny_reason=deny_reason,
        latency_ms=12,
    )


# --------------------------------------------------------------------------- #
# Module-level invariants                                                     #
# --------------------------------------------------------------------------- #


def test_module_does_not_expose_delete_in_public_api() -> None:
    """Append-only invariant: no public symbol or method mentions delete/purge."""
    public = [s for s in audit_mod.__all__ if not s.startswith("_")]
    assert not any("delete" in s.lower() or "purge" in s.lower() for s in public)

    backend_cls_names = ("SQLiteAuditBackend", "ClickHouseAuditBackend")
    for name in backend_cls_names:
        cls = getattr(audit_mod, name)
        for attr in dir(cls):
            if attr.startswith("_"):
                continue
            assert "delete" not in attr.lower(), f"{name}.{attr} suggests deletion"
            assert "purge" not in attr.lower(), f"{name}.{attr} suggests purge"


def test_module_source_contains_no_delete_sql_statements() -> None:
    """No raw SQL DELETE statements in the source.

    Comments and docstrings may discuss the invariant, so we look for the SQL
    keyword in a context that suggests an actual statement.
    """
    import re

    source = Path(audit_mod.__file__).read_text()
    # Forbidden: 'DELETE FROM' (SQL statement) anywhere in the source.
    assert not re.search(r"DELETE\s+FROM", source, flags=re.IGNORECASE), (
        "audit module must not contain DELETE FROM statements"
    )


# --------------------------------------------------------------------------- #
# Redactor                                                                    #
# --------------------------------------------------------------------------- #


def test_redactor_default_hashes_known_fields() -> None:
    r = Redactor()
    out = r.redact({"customer_id": "c-1", "pan": "4111111111111111", "ssn": "123-45-6789"})
    assert out["customer_id"] == "c-1"
    expected_pan = "sha256:" + hashlib.sha256(b"4111111111111111").hexdigest()
    expected_ssn = "sha256:" + hashlib.sha256(b"123-45-6789").hexdigest()
    assert out["pan"] == expected_pan
    assert out["ssn"] == expected_ssn


def test_redactor_redact_mode_replaces_value() -> None:
    r = Redactor(mode="redact")
    out = r.redact({"customer_id": "c-1", "password": "hunter2"})
    assert out == {"customer_id": "c-1", "password": "[REDACTED]"}


def test_redactor_recurses_into_nested_structures() -> None:
    r = Redactor(mode="redact")
    out = r.redact(
        {
            "customer_id": "c-1",
            "contact": {"email": "alice@example.com", "name": "Alice"},
            "history": [{"phone": "555-1234"}, {"phone": "555-5678"}],
        }
    )
    assert out["contact"]["email"] == "[REDACTED]"
    assert out["contact"]["name"] == "Alice"
    assert out["history"][0]["phone"] == "[REDACTED]"
    assert out["history"][1]["phone"] == "[REDACTED]"


def test_redactor_custom_fields_override_defaults() -> None:
    r = Redactor(fields=["account_number"], mode="redact")
    out = r.redact({"account_number": "ACC-001", "pan": "4111111111111111"})
    assert out["account_number"] == "[REDACTED]"
    # PAN is not in the custom field list -> passes through untouched.
    assert out["pan"] == "4111111111111111"


def test_redactor_rejects_unknown_mode() -> None:
    with pytest.raises(ValueError):
        Redactor(mode="encrypt")


# --------------------------------------------------------------------------- #
# SQLite backend                                                              #
# --------------------------------------------------------------------------- #


def test_sqlite_write_then_query_roundtrip(tmp_path: Path) -> None:
    backend = SQLiteAuditBackend(tmp_path / "audit.db")
    try:
        backend.write(_make_event(jti="j-1"))
        backend.flush()
        rows = backend.query()
        assert len(rows) == 1
        row = rows[0]
        assert row["jti"] == "j-1"
        assert row["sub"] == "alice@example.com"
        assert row["server"] == "customer_data"
        assert row["tool"] == "get_customer"
        assert row["status"] == "ok"
        assert row["latency_ms"] == 12
        assert row["args_preview"] == {"customer_id": "c-1"}
        assert row["ts"]  # auto-populated
    finally:
        backend.close()


def test_sqlite_one_hundred_writes_produce_one_hundred_rows(tmp_path: Path) -> None:
    backend = SQLiteAuditBackend(tmp_path / "audit.db")
    try:
        for i in range(100):
            backend.write(_make_event(jti=f"j-{i:03d}"))
        backend.flush()
        rows = backend.query(limit=1000)
        assert len(rows) == 100
        jtis = {r["jti"] for r in rows}
        assert len(jtis) == 100, "jti must be unique across all 100 rows"
    finally:
        backend.close()


def test_sqlite_timestamps_are_monotonic_non_decreasing(tmp_path: Path) -> None:
    backend = SQLiteAuditBackend(tmp_path / "audit.db")
    try:
        for i in range(50):
            backend.write(_make_event(jti=f"j-{i:03d}"))
        backend.flush()
        rows = backend.query(limit=1000)
        timestamps = [r["ts"] for r in rows]
        assert timestamps == sorted(timestamps), "ts must be non-decreasing"
    finally:
        backend.close()


def test_sqlite_pii_redaction_happens_at_write_time(tmp_path: Path) -> None:
    backend = SQLiteAuditBackend(tmp_path / "audit.db")
    try:
        evt = _make_event(
            jti="j-pii",
            args={"customer_id": "c-1", "pan": "4111111111111111", "password": "hunter2"},
        )
        backend.write(evt)
        backend.flush()
        rows = backend.query()
        assert len(rows) == 1
        stored = rows[0]["args_preview"]
        # customer_id is not in the default redaction list.
        assert stored["customer_id"] == "c-1"
        # pan and password are hashed by default.
        assert stored["pan"].startswith("sha256:")
        assert stored["password"].startswith("sha256:")
    finally:
        backend.close()


def test_sqlite_redact_mode_replaces_with_literal(tmp_path: Path) -> None:
    backend = SQLiteAuditBackend(tmp_path / "audit.db", redactor=Redactor(mode="redact"))
    try:
        backend.write(
            _make_event(
                jti="j-redact",
                args={"customer_id": "c-1", "ssn": "123-45-6789"},
            )
        )
        backend.flush()
        rows = backend.query()
        assert rows[0]["args_preview"]["ssn"] == "[REDACTED]"
    finally:
        backend.close()


def test_sqlite_query_filters(tmp_path: Path) -> None:
    backend = SQLiteAuditBackend(tmp_path / "audit.db")
    try:
        backend.write(_make_event(jti="a", sub="alice@example.com", tool="get_customer"))
        backend.write(_make_event(jti="b", sub="bob@example.com", tool="get_customer"))
        backend.write(
            _make_event(
                jti="c",
                sub="bob@example.com",
                server="transactions",
                tool="get_transactions",
                status="denied",
                deny_reason="tool_not_allowed",
            )
        )
        backend.flush()

        all_rows = backend.query()
        assert {r["jti"] for r in all_rows} == {"a", "b", "c"}

        alice_only = backend.query(sub="alice@example.com")
        assert [r["jti"] for r in alice_only] == ["a"]

        tx_only = backend.query(server="transactions")
        assert [r["jti"] for r in tx_only] == ["c"]

        denied_only = backend.query(status="denied")
        assert [r["jti"] for r in denied_only] == ["c"]
        assert denied_only[0]["deny_reason"] == "tool_not_allowed"
    finally:
        backend.close()


def test_sqlite_primary_key_enforces_unique_jti(tmp_path: Path) -> None:
    """A duplicate-jti write fails inside the worker; subsequent writes still land."""
    import sqlite3

    backend = SQLiteAuditBackend(tmp_path / "audit.db")
    try:
        backend.write(_make_event(jti="dup"))
        backend.flush()
        # Inserting the same jti directly through the sync helper raises.
        with pytest.raises(sqlite3.IntegrityError):
            backend._insert(_make_event(jti="dup"))
        # Distinct jtis still succeed.
        backend.write(_make_event(jti="dup-2"))
        backend.flush()
        rows = backend.query()
        assert {r["jti"] for r in rows} == {"dup", "dup-2"}
    finally:
        backend.close()


def test_sqlite_query_respects_limit(tmp_path: Path) -> None:
    backend = SQLiteAuditBackend(tmp_path / "audit.db")
    try:
        for i in range(20):
            backend.write(_make_event(jti=f"j-{i:03d}"))
        backend.flush()
        rows = backend.query(limit=5)
        assert len(rows) == 5
    finally:
        backend.close()


# --------------------------------------------------------------------------- #
# Module-level wiring                                                         #
# --------------------------------------------------------------------------- #


def test_module_write_event_and_query_use_default_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AUDIT_BACKEND", "sqlite")
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "audit.db"))
    audit_mod.write_event(_make_event(jti="env-1"))
    # Flush via the default backend handle.
    backend = audit_mod.get_backend()
    assert isinstance(backend, SQLiteAuditBackend)
    backend.flush()
    rows = audit_mod.query()
    assert [r["jti"] for r in rows] == ["env-1"]


def test_module_set_backend_overrides_default(tmp_path: Path) -> None:
    backend = SQLiteAuditBackend(tmp_path / "audit.db")
    try:
        audit_mod.set_backend(backend)
        audit_mod.write_event(_make_event(jti="set-1"))
        backend.flush()
        rows = audit_mod.query()
        assert [r["jti"] for r in rows] == ["set-1"]
    finally:
        audit_mod.reset_default_backend()


def test_build_default_backend_rejects_unknown_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUDIT_BACKEND", "redis")
    with pytest.raises(ValueError):
        build_default_backend()


def test_args_preview_stored_as_json_string(tmp_path: Path) -> None:
    """args_preview round-trips through JSON, including booleans/numbers."""
    backend = SQLiteAuditBackend(tmp_path / "audit.db")
    try:
        backend.write(
            _make_event(
                jti="json-1",
                args={"count": 42, "active": True, "tags": ["a", "b"], "ratio": 1.5},
            )
        )
        backend.flush()
        rows = backend.query()
        stored = rows[0]["args_preview"]
        assert stored == {"count": 42, "active": True, "tags": ["a", "b"], "ratio": 1.5}
    finally:
        backend.close()


def test_event_as_row_with_sort_stable_json(tmp_path: Path) -> None:
    """The JSON serialization is sort_keys=True so equal dicts compare bytewise."""
    r = Redactor(mode="redact")
    evt = _make_event(jti="x", args={"b": 1, "a": 2})
    row = evt.as_row(r)
    args_blob = row[7]
    parsed = json.loads(args_blob)
    assert parsed == {"a": 2, "b": 1}
    assert list(parsed.keys()) == ["a", "b"]
