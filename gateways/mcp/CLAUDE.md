# gateways/mcp/

The **MCP Gateway**. Verifies user PASETOs minted by the auth gateway,
enforces the embedded RBAC snapshot, re-signs a service-to-service PASETO
with a separate keypair, forwards the JSON-RPC payload to the downstream
MCP server, and emits one audit row per call.

## Modules

- `main.py` — FastAPI app factory `create_app(...)`. Exposes `POST /mcp/{server}` for JSON-RPC `tools/list` and `tools/call`, plus `GET /healthz`.
- `replay_cache.py` — thread-safe LRU set keyed on PASETO `jti` (capacity 10_000 by default). Drops the LRU entry on overflow; expired entries are pruned lazily on lookup.

## Endpoints

| Method | Path                | Purpose                                                                 |
| ------ | ------------------- | ----------------------------------------------------------------------- |
| `POST` | `/mcp/{server}`     | JSON-RPC `tools/list` / `tools/call` — verified, RBAC-checked, forwarded |
| `GET`  | `/healthz`          | Liveness probe                                                          |

## Env vars (production entry point `build_default_app()`)

- `MCP_GATEWAY_DOWNSTREAM_URLS` — JSON-encoded `{server_name: base_url}` map. The gateway POSTs to `{base}/{server}`, so each value must point at the MCP server for that server name. This is the canonical shape for the 14-service M1 stack (US-024). Adding a new MCP server = one entry here + one entry in `config/rbac.yaml`.
- `MCP_GATEWAY_DOWNSTREAM_URL` — Single-base-URL fallback. Used when no map entry matches the requested server, or when the deployment fronts every MCP server with a single reverse proxy. Either this env var or `MCP_GATEWAY_DOWNSTREAM_URLS` must be set.
- `MCP_GATEWAY_SERVICE_PRIVATE_KEY` — Ed25519 PEM for service-to-service PASETO mint. **Separate from the auth gateway's keypair.**
- `MCP_GATEWAY_INBOUND_PUBLIC_KEY` — Ed25519 PEM to verify inbound user PASETOs (fetched from the auth gateway's `/.well-known/paseto-key`).

## Conventions

- The minted service-to-service PASETO carries TTL = 60s (per PRD §6.3) and a **fresh** `jti`. The user's `trace_id` propagates so downstream OTel spans correlate.
- RBAC enforcement order: server allowance → tool allowance. Top-level wildcard `{"*": ["*"]}` short-circuits to allow-everything (super-admin).
- `deny_reason` values are stable strings exposed on `DenyReason` (e.g. `tool_not_allowed`, `server_not_allowed`, `token_replay`). Grafana (US-023) groups on these — do not rename without coordinating.
- Downstream 5xx → HTTP 502 with `deny_reason="downstream_error"`. Downstream 4xx → passthrough of the original status + body (no extra wrapping; the downstream typically returns its own JSON-RPC error).
- Audit emission is **best-effort**: any exception inside `_emit_audit` is logged but never propagated. We never want the audit pipeline to break a tool call.

## Pitfalls

- `mint()` populates `jti` / `exp` on the **encoded payload**, not the in-memory `Claims` dataclass. Tests that need the post-mint `jti` must verify-roundtrip the freshly minted token. See `_mint_user_token` in `tests/test_mcp_gateway.py`.
- The replay cache is **in-memory only** — restarting the gateway resets the seen set. The user-token TTL (≤300s) bounds the exposure; cross-instance deployments must accept this best-effort guarantee or front the gateway with sticky sessions.
- `claims.allowed_tools` is `dict[str, list[str]]` (from US-002/US-004). The gateway checks **both** the `"*"` top-level shape AND the per-server `"*"` shape. Both must be honored or you'll silently break the wildcard roles in `config/rbac.yaml`.
- The downstream URL is composed as `f"{base}/{server}"` where `base` comes from the per-server `MCP_GATEWAY_DOWNSTREAM_URLS` map (US-024) or `MCP_GATEWAY_DOWNSTREAM_URL` as fallback. When neither resolves to a value for the requested server the gateway returns a structured 502 with `deny_reason="downstream_error"` rather than attempting an empty URL.
- `httpx.MockTransport` is the cleanest way to write integration tests against this gateway without spinning up a real downstream. Inject the mock-transport-backed `AsyncClient` via `create_app(http_client=...)`.
- `audit.set_backend(SQLiteAuditBackend(":memory:"))` + `audit.reset_default_backend()` in an autouse fixture keeps audit state hermetic across tests. Always `backend.flush()` before asserting on `query(...)` — the worker is a background thread.
