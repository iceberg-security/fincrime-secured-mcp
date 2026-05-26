# gateways/common/

Shared utilities used by both the auth gateway (`gateways/auth/`) and the MCP gateway (`gateways/mcp/`).

## Modules

- `paseto.py` — PASETO v4.public mint/verify on top of `pyseto`. Use this for all token signing and verification. Do not call `pyseto.encode` / `pyseto.decode` directly elsewhere.
- `rbac.py` — YAML-driven RBAC loader with role inheritance and mtime-based hot reload. Use `resolve_user(email, groups=...)` (module-level helper) or instantiate `RBACLoader(path)` directly in tests. Config path comes from `RBAC_CONFIG_PATH` env var (default `config/rbac.yaml`).
- `audit.py` — append-only audit event store. `write_event(AuditEvent)` enqueues an event to a worker thread; `query(...)` reads back filtered rows. Default backend is SQLite (`AUDIT_DB_PATH` env var, default `audit.db`); set `AUDIT_BACKEND=clickhouse` to switch (requires the `clickhouse` optional extra). Per-call latency is unaffected by IO — the worker thread does the `INSERT`. `args_preview` is sanitized through a `Redactor` (default fields include `pan`, `ssn`, `password`, etc.; configurable). There is intentionally **no public delete method** — append-only is enforced at the API boundary.
- `otel.py` — OpenTelemetry tracing helpers (US-022). `configure_tracing(service_name)` is **idempotent** and installs a process-wide `TracerProvider`; `instrument_fastapi(app, service_name=...)` is the standard knob each FastAPI factory calls to get HTTP server spans. Span attributes are constrained: `ATTR_MCP_SERVER`, `ATTR_MCP_TOOL`, `ATTR_USER_ROLE` MUST be set; `FORBIDDEN_ATTRIBUTES = {user.email, user.sub}` MUST NEVER appear. Use `tool_span_attributes(...)` to build attribute dicts — it raises `ValueError` on forbidden extras. PASETO `trace_id` claims are 32-char hex; `trace_context_from_id(trace_id)` lifts them into an OTel `Context` so spans started under that context all share the trace.

## Conventions

- Key paths come from env vars by default (`PASETO_PRIVATE_KEY_PATH`, `PASETO_PUBLIC_KEY_PATH`). Pass `private_key_path=` / `public_key_path=` explicitly when a caller maintains its own keypair (the MCP gateway uses a separate keypair for service-to-service tokens — see US-007).
- Key loaders use `functools.lru_cache` keyed on the path string. Adding a test that injects new keys requires clearing the cache; see the `_clear_key_cache` autouse fixture in `tests/test_paseto.py`.
- All verify failures raise a `PasetoError` subclass (`ExpiredTokenError`, `InvalidTokenError`, `MalformedTokenError`) — never let a raw `pyseto.VerifyError` leak past this module.
- Claims live in the `Claims` dataclass. When adding a new claim field, update both `to_payload()` and `from_payload()` so the roundtrip stays symmetric.

## Pitfalls

- `pyseto.Key.new(purpose="public", ...)` is used for **both** the Ed25519 private and the public PEM. `purpose` here means "PASETO purpose (signed)", not "key half". There is no `purpose="private"`.
- pyseto signals expiration via `VerifyError("Token expired.")` — string-matched in `verify()`. If the upstream wording changes, the expired-token test will fail loudly.
- `rbac.py` uses a process-wide default loader cached in a module global. Tests that touch `RBAC_CONFIG_PATH` or call `resolve_user()` must reset it (see the autouse `_reset_default_loader` fixture in `tests/test_rbac.py`).
- The RBAC loader's hot reload is mtime-based, checked on every `resolve_user()` call. On filesystems with 1-second mtime resolution (some macOS configs), tests that edit and immediately re-read the YAML should bump mtime via `os.utime(path, (t+1, t+1))` rather than `time.sleep(1)`.
- Wildcards in `allowed_tools`: per-server `"*"` is stored as `{"server": ["*"]}`; top-level `"*"` as `{"*": ["*"]}`. The MCP gateway must check both shapes when enforcing.
- `SQLiteAuditBackend` writes happen on a background thread. In tests, always call `backend.flush()` (or `backend.close()`) before asserting on `backend.query(...)` — otherwise the worker hasn't drained yet and you'll see empty results. `audit.reset_default_backend()` in an autouse fixture is the standard way to keep the module-level singleton from leaking across tests.
- `Redactor` traverses dicts/lists/tuples recursively, but only matches **keys** (not values). If a sensitive value lives in a positional list (`["4111111111111111"]` rather than `{"pan": "4111111111111111"}`), it won't be redacted — caller is responsible for keying sensitive args.
- OTel: OTel's global `TracerProvider` is **set-once** — `set_tracer_provider()` after the first install logs `"Overriding of current TracerProvider is not allowed"` and is silently ignored. `configure_tracing` early-returns when a `TracerProvider` is already installed; tests that need a fresh exporter attach a processor (`provider.add_span_processor(SimpleSpanProcessor(InMemorySpanExporter()))`) rather than try to replace the provider. Don't use OTel's `OTEL_SDK_DISABLED=true` to quiet tests — it swaps in a `NoOpTracer` that breaks downstream test-fixture exporter attachment. Use `FRAUD_OTEL_NOOP=true` instead (handled by `otel._sdk_disabled()`) to install a real provider with no processors — spans still record but never export. Default in `tests/conftest.py`.
