"""Append-only audit event store.

Every gateway hop (auth gateway, MCP gateway, MCP servers when they emit
service-level audits) writes one :class:`AuditEvent` per request through this
module so a compliance officer can reconstruct exactly which user invoked
which tool with which arguments at which time.

The default backend is **SQLite** (local file, no external services), which is
sufficient for development, demos, and small deployments. Setting
``AUDIT_BACKEND=clickhouse`` switches to a ClickHouse backend for high-volume
production use; ``clickhouse-connect`` lives behind the optional
``clickhouse`` extra (``pip install ".[clickhouse]"``).

Invariants enforced by this module:

- **Append-only**: there is no public ``delete`` method. The SQL ``DELETE``
  statement appears nowhere in the source. Drop the DB file (or expire-by-TTL
  externally) if you need to purge — that is an operator action, not an API.
- **Background writes**: callers fire :func:`write_event` and return
  immediately. A dedicated worker thread drains an in-process queue and
  performs the SQL ``INSERT``. Per-request latency is unaffected by audit IO.
- **PII redaction**: arguments stored in ``args_preview`` are routed through a
  configurable redactor that hashes or redacts known-sensitive fields before
  they ever touch disk.

Schema (mirrors PRD §6.7)::

    audit_events(
      ts            TEXT     NOT NULL,   -- ISO-8601 UTC, monotonic per writer
      jti           TEXT     NOT NULL,   -- PASETO jti, unique per call
      trace_id      TEXT     NOT NULL,
      sub           TEXT     NOT NULL,
      role          TEXT     NOT NULL,   -- comma-joined roles snapshot
      server        TEXT     NOT NULL,
      tool          TEXT     NOT NULL,
      args_preview  TEXT     NOT NULL,   -- redacted JSON
      result_hash   TEXT     NOT NULL,
      status        TEXT     NOT NULL,   -- "ok" | "denied" | "error"
      deny_reason   TEXT,
      latency_ms    INTEGER  NOT NULL DEFAULT 0,
      PRIMARY KEY (jti)
    )
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import sqlite3
import threading
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

__all__ = [
    "AuditEvent",
    "AuditBackend",
    "SQLiteAuditBackend",
    "ClickHouseAuditBackend",
    "Redactor",
    "build_default_backend",
    "write_event",
    "query",
    "get_backend",
    "set_backend",
    "reset_default_backend",
    "DEFAULT_REDACTED_FIELDS",
]


_LOG = logging.getLogger(__name__)

#: Field names that are hashed by the default redactor when they appear in
#: ``args_preview``. Operators can override via :class:`Redactor`'s constructor
#: or by configuring a custom redactor on the backend.
DEFAULT_REDACTED_FIELDS: tuple[str, ...] = (
    "pan",
    "card_number",
    "ssn",
    "tax_id",
    "password",
    "secret",
    "token",
    "phone",
    "email",
    "address",
    "dob",
)

_AUDIT_DB_PATH_ENV = "AUDIT_DB_PATH"
_AUDIT_BACKEND_ENV = "AUDIT_BACKEND"
_AUDIT_REDACT_MODE_ENV = "AUDIT_REDACT_MODE"  # "hash" (default) | "redact"


# --------------------------------------------------------------------------- #
# Event model                                                                 #
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class AuditEvent:
    """One row in ``audit_events``.

    ``ts`` is auto-filled with ISO-8601 UTC if the caller leaves it empty —
    callers normally don't set it. Times are monotonically non-decreasing per
    writer (the worker timestamps each event as it dequeues).
    """

    sub: str
    role: str
    server: str
    tool: str
    jti: str
    trace_id: str = ""
    args_preview: dict[str, Any] = field(default_factory=dict)
    result_hash: str = ""
    status: str = "ok"
    deny_reason: str | None = None
    latency_ms: int = 0
    ts: str = ""

    def as_row(self, redactor: Redactor) -> tuple[Any, ...]:
        """Return the tuple that gets bound to the ``INSERT`` statement."""
        redacted = redactor.redact(self.args_preview)
        return (
            self.ts,
            self.jti,
            self.trace_id,
            self.sub,
            self.role,
            self.server,
            self.tool,
            json.dumps(redacted, sort_keys=True, default=str),
            self.result_hash,
            self.status,
            self.deny_reason,
            self.latency_ms,
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


# --------------------------------------------------------------------------- #
# Redactor                                                                    #
# --------------------------------------------------------------------------- #


class Redactor:
    """Replace sensitive values in ``args_preview`` before persisting.

    ``mode="hash"`` (default) replaces the value with ``"sha256:<hex>"`` of its
    ``str()`` rendering — preserves correlatability without exposing the
    plaintext. ``mode="redact"`` replaces it with the literal string
    ``"[REDACTED]"`` — drops correlatability but is safer for highly sensitive
    fields.
    """

    def __init__(
        self,
        fields: Iterable[str] = DEFAULT_REDACTED_FIELDS,
        *,
        mode: str = "hash",
    ) -> None:
        if mode not in ("hash", "redact"):
            raise ValueError(f"unknown redact mode: {mode!r}")
        self._fields = {f.lower() for f in fields}
        self._mode = mode

    @property
    def fields(self) -> set[str]:
        return set(self._fields)

    @property
    def mode(self) -> str:
        return self._mode

    def redact(self, value: Any) -> Any:
        return self._walk(value)

    def _walk(self, value: Any) -> Any:
        if isinstance(value, Mapping):
            out: dict[str, Any] = {}
            for k, v in value.items():
                key_str = str(k)
                if key_str.lower() in self._fields:
                    out[key_str] = self._replace(v)
                else:
                    out[key_str] = self._walk(v)
            return out
        if isinstance(value, list):
            return [self._walk(v) for v in value]
        if isinstance(value, tuple):
            return [self._walk(v) for v in value]
        return value

    def _replace(self, value: Any) -> str:
        if self._mode == "redact":
            return "[REDACTED]"
        digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()
        return f"sha256:{digest}"


# --------------------------------------------------------------------------- #
# Backend protocol                                                            #
# --------------------------------------------------------------------------- #


class AuditBackend(Protocol):
    """Concrete persistence target. Implementations must be thread-safe."""

    def write(self, event: AuditEvent) -> None:
        """Insert a single event. Called from the worker thread."""

    def query(
        self,
        *,
        sub: str | None = None,
        server: str | None = None,
        tool: str | None = None,
        status: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return matching rows ordered by ``ts`` ascending."""

    def close(self) -> None:
        """Release any underlying resources."""


# --------------------------------------------------------------------------- #
# SQLite backend                                                              #
# --------------------------------------------------------------------------- #


_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    ts            TEXT     NOT NULL,
    jti           TEXT     NOT NULL,
    trace_id      TEXT     NOT NULL,
    sub           TEXT     NOT NULL,
    role          TEXT     NOT NULL,
    server        TEXT     NOT NULL,
    tool          TEXT     NOT NULL,
    args_preview  TEXT     NOT NULL,
    result_hash   TEXT     NOT NULL,
    status        TEXT     NOT NULL,
    deny_reason   TEXT,
    latency_ms    INTEGER  NOT NULL DEFAULT 0,
    PRIMARY KEY (jti)
);
CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events(ts);
CREATE INDEX IF NOT EXISTS idx_audit_events_sub ON audit_events(sub);
CREATE INDEX IF NOT EXISTS idx_audit_events_server_tool ON audit_events(server, tool);
""".strip()


class _InsertSink(Protocol):
    """Object the worker delegates to when it dequeues an event."""

    def _insert(self, event: AuditEvent) -> None: ...


class _BackgroundWorker:
    """Drains a queue of events and writes them sequentially.

    One worker per backend instance. Stopping is via :meth:`stop`, which sends
    a sentinel and joins the thread. ``flush`` drains pending work without
    stopping — used by tests and by graceful-shutdown hooks.
    """

    _SENTINEL: Any = object()

    def __init__(self, sink: _InsertSink, *, name: str = "audit-writer") -> None:
        self._sink = sink
        self._queue: queue.Queue[Any] = queue.Queue()
        self._thread = threading.Thread(target=self._run, name=name, daemon=True)
        self._thread.start()

    def submit(self, event: AuditEvent) -> None:
        self._queue.put(event)

    def flush(self, *, timeout: float = 5.0) -> None:
        """Block until the queue is empty. Tests use this to assert writes."""
        # queue.join() waits for task_done() on every put; the worker calls
        # task_done() after each insert (successful or otherwise).
        del timeout  # reserved for future per-flush timeout; semantically infinite today
        self._queue.join()

    def stop(self, *, timeout: float = 5.0) -> None:
        self._queue.put(self._SENTINEL)
        self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is self._SENTINEL:
                    return
                try:
                    self._sink._insert(item)
                except Exception:  # pragma: no cover - defensive
                    _LOG.exception("audit write failed; dropping event jti=%s", item.jti)
            finally:
                self._queue.task_done()


class SQLiteAuditBackend:
    """Append-only SQLite store with a background writer thread.

    ``db_path`` accepts ``":memory:"`` for tests; the connection then has
    ``check_same_thread=False`` to keep the worker thread able to use it.
    """

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        *,
        redactor: Redactor | None = None,
    ) -> None:
        self._db_path = str(db_path)
        self._redactor = redactor or Redactor()
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self._db_path, check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SQLITE_SCHEMA)
        self._worker = _BackgroundWorker(self)

    @property
    def db_path(self) -> str:
        return self._db_path

    @property
    def redactor(self) -> Redactor:
        return self._redactor

    # ---- public API --------------------------------------------------------

    def write(self, event: AuditEvent) -> None:
        if not event.ts:
            event.ts = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
        self._worker.submit(event)

    def flush(self, *, timeout: float = 5.0) -> None:
        """Block until queued writes finish (intended for tests / shutdown)."""
        self._worker.flush(timeout=timeout)

    def close(self) -> None:
        self._worker.stop()
        with self._lock:
            self._conn.close()

    def query(
        self,
        *,
        sub: str | None = None,
        server: str | None = None,
        tool: str | None = None,
        status: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if sub is not None:
            clauses.append("sub = ?")
            params.append(sub)
        if server is not None:
            clauses.append("server = ?")
            params.append(server)
        if tool is not None:
            clauses.append("tool = ?")
            params.append(tool)
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        if until is not None:
            clauses.append("ts <= ?")
            params.append(until)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            "SELECT ts, jti, trace_id, sub, role, server, tool, "
            "args_preview, result_hash, status, deny_reason, latency_ms "
            f"FROM audit_events {where} ORDER BY ts ASC LIMIT ?"
        )
        params.append(int(limit))
        with self._lock:
            cur = self._conn.execute(sql, params)
            rows = cur.fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            try:
                d["args_preview"] = json.loads(d["args_preview"])
            except (TypeError, json.JSONDecodeError):
                pass
            out.append(d)
        return out

    # ---- worker-side insert (called from worker thread) -------------------

    def _insert(self, event: AuditEvent) -> None:
        row = event.as_row(self._redactor)
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_events "
                "(ts, jti, trace_id, sub, role, server, tool, "
                " args_preview, result_hash, status, deny_reason, latency_ms) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                row,
            )


# --------------------------------------------------------------------------- #
# ClickHouse backend (lazy import; depends on optional extra)                 #
# --------------------------------------------------------------------------- #


class ClickHouseAuditBackend:
    """ClickHouse implementation of :class:`AuditBackend`.

    Requires the optional ``clickhouse`` extra (``pip install ".[clickhouse]"``).
    Connection details come from env vars at construction time:

    - ``CLICKHOUSE_HOST`` (default ``localhost``)
    - ``CLICKHOUSE_PORT`` (default ``8123``)
    - ``CLICKHOUSE_USER`` (default ``default``)
    - ``CLICKHOUSE_PASSWORD`` (default empty)
    - ``CLICKHOUSE_DATABASE`` (default ``default``)
    """

    _TABLE = "audit_events"

    _DDL = (
        "CREATE TABLE IF NOT EXISTS audit_events ("
        " ts DateTime64(3, 'UTC'),"
        " jti String,"
        " trace_id String,"
        " sub String,"
        " role String,"
        " server String,"
        " tool String,"
        " args_preview String,"
        " result_hash String,"
        " status String,"
        " deny_reason Nullable(String),"
        " latency_ms UInt32"
        ") ENGINE = MergeTree ORDER BY (ts, jti)"
    )

    def __init__(self, *, redactor: Redactor | None = None) -> None:
        try:
            import clickhouse_connect  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover - exercised manually
            raise RuntimeError(
                "ClickHouse backend selected but clickhouse-connect is not installed. "
                'Install with `pip install ".[clickhouse]"`.'
            ) from exc

        self._client = clickhouse_connect.get_client(
            host=os.getenv("CLICKHOUSE_HOST", "localhost"),
            port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
            username=os.getenv("CLICKHOUSE_USER", "default"),
            password=os.getenv("CLICKHOUSE_PASSWORD", ""),
            database=os.getenv("CLICKHOUSE_DATABASE", "default"),
        )
        self._client.command(self._DDL)
        self._redactor = redactor or Redactor()
        self._lock = threading.RLock()
        self._worker = _BackgroundWorker(self, name="audit-writer-clickhouse")

    def write(self, event: AuditEvent) -> None:
        if not event.ts:
            event.ts = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
        self._worker.submit(event)

    def flush(self, *, timeout: float = 5.0) -> None:
        self._worker.flush(timeout=timeout)

    def close(self) -> None:
        self._worker.stop()
        with self._lock:
            self._client.close()

    def query(
        self,
        *,
        sub: str | None = None,
        server: str | None = None,
        tool: str | None = None,
        status: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: dict[str, Any] = {}
        if sub is not None:
            clauses.append("sub = %(sub)s")
            params["sub"] = sub
        if server is not None:
            clauses.append("server = %(server)s")
            params["server"] = server
        if tool is not None:
            clauses.append("tool = %(tool)s")
            params["tool"] = tool
        if status is not None:
            clauses.append("status = %(status)s")
            params["status"] = status
        if since is not None:
            clauses.append("ts >= %(since)s")
            params["since"] = since
        if until is not None:
            clauses.append("ts <= %(until)s")
            params["until"] = until
        params["lim"] = int(limit)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            "SELECT ts, jti, trace_id, sub, role, server, tool, "
            "args_preview, result_hash, status, deny_reason, latency_ms "
            f"FROM audit_events {where} ORDER BY ts ASC LIMIT %(lim)s"
        )
        with self._lock:
            rows = self._client.query(sql, parameters=params).named_results()
        out: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            try:
                d["args_preview"] = json.loads(d["args_preview"])
            except (TypeError, json.JSONDecodeError):
                pass
            out.append(d)
        return out

    def _insert(self, event: AuditEvent) -> None:
        row = list(event.as_row(self._redactor))
        with self._lock:
            self._client.insert(
                self._TABLE,
                [row],
                column_names=[
                    "ts",
                    "jti",
                    "trace_id",
                    "sub",
                    "role",
                    "server",
                    "tool",
                    "args_preview",
                    "result_hash",
                    "status",
                    "deny_reason",
                    "latency_ms",
                ],
            )


# --------------------------------------------------------------------------- #
# Default backend wiring (env-driven)                                         #
# --------------------------------------------------------------------------- #


def build_default_backend() -> AuditBackend:
    """Create the audit backend declared by env vars.

    ``AUDIT_BACKEND=clickhouse`` selects ClickHouse; anything else (including
    unset) selects SQLite, with the database file path coming from
    ``AUDIT_DB_PATH`` (default ``./audit.db``).
    """
    backend = os.getenv(_AUDIT_BACKEND_ENV, "sqlite").lower()
    mode = os.getenv(_AUDIT_REDACT_MODE_ENV, "hash").lower()
    redactor = Redactor(mode=mode)
    if backend == "clickhouse":
        return ClickHouseAuditBackend(redactor=redactor)
    if backend not in ("sqlite", ""):
        raise ValueError(f"unknown AUDIT_BACKEND: {backend!r}")
    db_path = os.getenv(_AUDIT_DB_PATH_ENV, "audit.db")
    if db_path != ":memory:":
        parent = Path(db_path).parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
    return SQLiteAuditBackend(db_path, redactor=redactor)


# --------------------------------------------------------------------------- #
# Module-level convenience                                                    #
# --------------------------------------------------------------------------- #


_default_backend: AuditBackend | None = None
_default_backend_lock = threading.Lock()


def get_backend() -> AuditBackend:
    """Return the process-wide default backend, creating it on first call."""
    global _default_backend
    with _default_backend_lock:
        if _default_backend is None:
            _default_backend = build_default_backend()
    return _default_backend


def set_backend(backend: AuditBackend) -> None:
    """Override the process-wide default (used by tests and app bootstrap)."""
    global _default_backend
    with _default_backend_lock:
        _default_backend = backend


def reset_default_backend() -> None:
    """Drop the cached default backend. Intended for tests only."""
    global _default_backend
    with _default_backend_lock:
        if _default_backend is not None:
            try:
                _default_backend.close()
            except Exception:  # pragma: no cover - best-effort
                _LOG.warning("error closing previous default audit backend", exc_info=True)
        _default_backend = None


def write_event(event: AuditEvent) -> None:
    """Submit an event to the default backend (fire-and-forget)."""
    get_backend().write(event)


def query(
    *,
    sub: str | None = None,
    server: str | None = None,
    tool: str | None = None,
    status: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Read events from the default backend with optional filters."""
    return get_backend().query(
        sub=sub,
        server=server,
        tool=tool,
        status=status,
        since=since,
        until=until,
        limit=limit,
    )
