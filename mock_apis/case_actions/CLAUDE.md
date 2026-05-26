# mock_apis/case_actions/

Mock case-management / compliance-action write-path API. **The only
write-path mock in the stack** — the prior five (customer_data,
transactions, kyc, sanctions, osint) are read-only. Sixth concrete
downstream the gateway federates to (US-007 → US-009 → US-012 → US-013 →
US-014 → US-015 → **US-016**).

## Endpoints

| Method | Path                                | Returns                                                                                |
| ------ | ----------------------------------- | -------------------------------------------------------------------------------------- |
| `POST` | `/sar-drafts`                       | `{draft_id, customer_id, narrative, typology, related_accounts, status, content_hash}` |
| `POST` | `/accounts/freeze`                  | `{freeze_id, account_id, reason, requested_by, status, content_hash}`                  |
| `POST` | `/escalations`                      | `{escalation_id, case_id, summary, severity, requested_by, status, content_hash}`     |
| `GET`  | `/sar-drafts/{draft_id}`            | The SAR draft (404 if unknown).                                                        |
| `GET`  | `/accounts/{account_id}/freeze`     | The freeze record for an account (404 if unfrozen).                                    |
| `GET`  | `/escalations/{escalation_id}`      | The escalation record (404 if unknown).                                                |
| `GET`  | `/healthz`                          | Liveness.                                                                              |

## Determinism contract

- **Record ids are deterministic** — derived from
  `sha256(prefix|...|content)` and truncated to 12 hex chars. The full
  hash lives in `content_hash` on the record. **No UUID, no clock.** Two
  identical POSTs produce two records with the same id (idempotent shape
  — the second POST overwrites the first in the journal; the body shape
  is what matters).
- **In-memory journal per app instance.** `create_app(store=...)` accepts
  a pre-built `CaseStore`; if none is passed, a fresh empty store is
  created. Tests that want to inspect what was recorded should build
  their own `CaseStore` and pass it in.
- **No clock.** Records carry no `created_at` field — this would break
  determinism. If a future US needs ordering, derive it from the
  audit log's `ts` column (US-006) where the clock lives.

## The human-approval gate lives at the MCP server, NOT here

The PRD-mandated `human_approval=true` claim check is enforced by
`mcp_servers/case_actions` (US-016). This mock accepts any well-formed
body — the gate is the server's job. Why?

- **Defense in depth via the gateway → server → mock chain.** The gateway
  enforces RBAC, the server enforces the human-approval claim, and the
  mock validates the body shape. Each layer has a single concern.
- **Mocks stay pure.** No PASETO, no env vars. `build_default_app()`
  consumes nothing — same shape as the five read-only mocks.
- **Reusability for the verifier (US-021).** The verify-output meta-skill
  re-reads the audit log AND the mock's journal to cross-reference
  claims. The mock needs to be reachable without a PASETO so the
  verifier can query the journal during local-dev workflows.

## Adding a new action

1. Add a Pydantic request model + a POST route.
2. Derive the new id via `_deterministic_id(prefix, *content_parts)`.
3. Add a GET route for lookups.
4. Mirror the change in `mcp_servers/case_actions/main.py` — register a
   new FastMCP tool that POSTs to the new endpoint.
5. Add a contract entry in `mcp_servers/case_actions/CLAUDE.md`.

## Pitfalls

- **No clock.** Don't add `created_at` / `updated_at` fields without
  passing a time provider — the determinism tests will fail. The audit
  log (US-006) is where `ts` lives.
- **The journal is per-app-instance.** Two `create_app()` calls produce
  two independent journals. Tests that span multiple HTTP clients must
  share a `CaseStore` explicitly: build it once, pass it to both apps.
- **No PASETO validation here.** That's the MCP server's job. If you
  ever need request-level auth on the mock itself (for some integration
  pattern), add it — but the human-approval gate stays at the server.
- **content_hash is computed BEFORE the hash field is added to the
  payload**, so re-hashing the stored record (which includes
  content_hash) would yield a different value. The hash pins the
  fields-at-write-time; it's a content sentinel, not a recursive digest.
