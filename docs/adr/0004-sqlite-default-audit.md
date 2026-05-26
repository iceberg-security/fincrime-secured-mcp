# ADR 0004 — SQLite default for the audit store, ClickHouse as opt-in

- **Status**: Accepted
- **Date**: 2026-05-26
- **Story**: US-033 (decision originally implemented in US-006)

## Context

Every gateway call writes one row to the audit log. The schema (PRD
§6.7) is fixed and modest: `ts`, `jti`, `sub`, `roles`, `server`,
`tool`, `args_preview`, `status`, `deny_reason`, `latency_ms`,
`trace_id`. The append-only invariant is structural — the audit
module exposes no public `DELETE` and the source is grepped for
`DELETE FROM` in a test (see
[US-006 prd.json entry](../../prd.json) AC). Reads come from two
places: the verify-output meta-skill
[US-021](../../prd.json) (per-investigation slice filtered by
`trace_id` or `(sub, since)`) and the Grafana dashboard
[US-023](../../prd.json) (aggregated panels).

Two backend options were on the table:

1. **SQLite.** Single file, zero configuration, ships with Python's
   stdlib, runs as an embedded process, well-understood for
   append-mostly workloads at our scale.
2. **ClickHouse.** Purpose-built columnar OLAP store, excellent for
   the per-user/per-tool aggregation the Grafana panels do, handles
   billions of rows comfortably.

The forcing functions for the decision:

- **Quickstart cost.** The PRD pins "make compose-up brings the stack
  up" (US-011) and "cold start <30s" (US-024). Adding ClickHouse to
  the default compose puts a heavyweight service on the critical
  path for every contributor's first run.
- **Default footprint.** Production deployments will want
  ClickHouse for retention and analytics. Demo / eval / contributor
  runs only need to write a few hundred to a few thousand rows per
  session — SQLite handles that with room to spare.
- **Append-only enforcement is at the API layer, not the DB.** Both
  backends respect the no-DELETE invariant because the audit module
  itself does not expose one. The choice between them is about
  ergonomics and analytics, not about the security property.
- **Test ergonomics.** Unit tests spin up a fresh DB per test. SQLite
  + a tmp_path file is two lines; ClickHouse requires Docker even in
  unit tests.

The downside of defaulting to SQLite is that the Grafana panels need
two SQL flavors (SQLite's window-function p50/p95 approximation vs
ClickHouse's native `quantile()`), which the US-023 dashboard
absorbs by shipping both targets per panel.

## Decision

**SQLite is the default audit backend. ClickHouse is opt-in via
`AUDIT_BACKEND=clickhouse` and the `clickhouse` extra.**

Concretely:

- `gateways/common/audit.py` exposes
  `write_event(AuditEvent)` and `query(...)` over a process-wide
  default backend selected by `AUDIT_BACKEND`. Default `sqlite`
  reads `AUDIT_DB_PATH` (default `./audit.db`).
- `AUDIT_BACKEND=clickhouse` swaps to the ClickHouse backend; the
  driver import is lazy (only loaded when actually selected) and the
  driver is gated behind the `clickhouse` extra
  (`pip install ".[clickhouse]"`).
- Writes go through a background `_BackgroundWorker` thread that
  drains a `queue.Queue`, so `write_event()` is fire-and-forget and
  per-call latency is unaffected.
- The Grafana dashboard
  ([`config/grafana/dashboards/fraud-copilot.json`](../../config/grafana/dashboards/fraud-copilot.json))
  ships two targets per panel — one against
  `frser-sqlite-datasource`, one against `grafana-clickhouse-datasource`
  — and Grafana fires only the one matching the provisioned default.
  Flipping the default datasource is an env-var change
  (`${AUDIT_BACKEND_IS_SQLITE}` vs `${AUDIT_BACKEND_IS_CLICKHOUSE}`)
  in `config/grafana/provisioning/datasources/audit.yaml`, not a YAML
  edit.
- Primary key on `jti` and indexes on `ts`, `sub`, `(server, tool)`.
- `_BackgroundWorker.flush()` is the test hook — every audit test
  calls it before asserting on `query()`.

## Consequences

**Positive:**

- `make compose-up` boots a working stack with the audit gate live
  in seconds. No external dependency for the default path.
- Contributors do not need to learn ClickHouse to ship a story.
  Every PR runs against the SQLite backend in CI; the test surface is
  hermetic.
- ClickHouse is a one-env-var migration when an operator's retention
  / analytics needs outgrow SQLite. The audit module's public API
  does not change — `write_event(...)` / `query(...)` work
  identically under either backend.
- Grafana panels render against either backend without dashboard
  edits because both targets are shipped per panel.

**Negative:**

- The SQLite p50/p95 SQL is an ordinal approximation (`ROW_NUMBER OVER
  (PARTITION BY server, tool ORDER BY latency_ms)` + a percentile
  selector). ClickHouse's `quantile(0.5)` / `quantile(0.95)` are
  exact. For dev / eval the approximation is acceptable; production
  operators who care about exact percentiles should flip to
  ClickHouse.
- SQLite concurrency under heavy write load is the classic
  per-database-file lock. For the volumes we model (one row per MCP
  call, peak ~10/s in dev) this never matters; production-scale
  deployments will hit it and should already be on ClickHouse.
- Two SQL dialects in the dashboard means dashboard maintainers
  must update both targets in lockstep when a panel changes. The
  `tests/test_grafana_dashboard.py` fences cover the structural
  contract; SQL semantics still need eyes.

**Risk acceptance:**

- The default backend choice is a contributor-experience decision,
  not a security one. The append-only invariant lives at the module
  API level — `gateways/common/audit.py.__all__` exposes no `delete`
  / `purge` / etc., and a test greps the module source for
  `DELETE FROM`. See
  [US-006 prd.json entry](../../prd.json).

## Alternatives considered

- **ClickHouse default.** Rejected — pushes the contributor cold-start
  past the 30-second budget, adds a service to the critical path, and
  forces every test to either mock the driver or start a container.
- **PostgreSQL default.** Rejected — same heavyweight-default problem
  as ClickHouse, and the analytics queries (per-day audit volume,
  per-tool p95) get worse not better than ClickHouse's columnar shape.
- **Append-only flat-file log (JSON lines on disk).** Rejected —
  Grafana cannot query it directly, and the in-process `query(...)`
  helper that the verifier meta-skill needs would have to scan the
  whole file. Indexes are the wrong primitive at this layer.
- **AWS DynamoDB / GCS append blob.** Rejected — couples local dev
  to a cloud account. Production operators are free to write a
  separate backend implementing the same `write_event`/`query`
  protocol.

## Cross-links

- [US-006 prd.json entry](../../prd.json) — audit module
  acceptance criteria, no-DELETE invariant.
- [US-023 prd.json entry](../../prd.json) — Grafana dashboard.
- [US-024 prd.json entry](../../prd.json) — full 14-service
  compose + load-fixtures.
- `gateways/common/audit.py` — backend selection,
  `_BackgroundWorker`, `Redactor`.
- [`config/grafana/dashboards/fraud-copilot.json`](../../config/grafana/dashboards/fraud-copilot.json)
  — dual SQLite + ClickHouse targets.
- [`docs/threat-model.md`](../threat-model.md) §4.4 — audit
  tampering threat + mitigations.
