# mcp_servers/case_actions/

Sixth downstream MCP server (US-016). Wraps the case_actions mock API and
sits behind the MCP gateway (US-007). **The only write-path MCP server in
the stack** — every prior downstream is read-only.

Three tools — `create_sar_draft`, `freeze_account`, `escalate_to_l3` — all
gated by the **human-approval claim**.

Uses the shared `mcp_servers/_common.py` factory like every other server
since US-015. The wrinkle is the `extra_validate` hook, which case_actions
plugs in for the human-approval check.

## Endpoints

| Method | Path             | Purpose                                                                                                                |
| ------ | ---------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `POST` | `/case_actions`  | MCP JSON-RPC 2.0. Supports `tools/list` and `tools/call`. Requires a valid service PASETO with `human_approval=true`. |
| `GET`  | `/healthz`       | Liveness probe.                                                                                                        |

The path is `/case_actions` because the gateway POSTs to
`f"{downstream_url}/{server}"` and `SERVER_NAME = "case_actions"`.

## Tools (contract for orchestrator skills, US-019/US-020)

| Tool                | Required args                                          | Optional args        | Returns                                                                                |
| ------------------- | ------------------------------------------------------ | -------------------- | -------------------------------------------------------------------------------------- |
| `create_sar_draft`  | `customer_id`, `narrative`, `typology`                 | `related_accounts`   | `{draft_id, customer_id, narrative, typology, related_accounts, status, content_hash}` |
| `freeze_account`    | `account_id`, `reason`, `requested_by`                 | —                    | `{freeze_id, account_id, reason, requested_by, status, content_hash}`                  |
| `escalate_to_l3`    | `case_id`, `summary`, `severity`, `requested_by`       | —                    | `{escalation_id, case_id, summary, severity, requested_by, status, content_hash}`     |

Tool input schemas are FastMCP-generated; don't change them without
updating `test_tools_list_schemas_match_case_actions_contract` in lockstep.

## The HUMAN-APPROVAL GATE — the load-bearing US-016 requirement

Every tool call requires the calling PASETO to carry `human_approval=true`.
Without it, the request is rejected **before any tool dispatch** with:

```
HTTP 403
{"jsonrpc": "2.0", "id": ..., "error": {
    "code": -32600,
    "message": "human approval required for case_actions tools",
    "data": {"deny_reason": "human_approval_required"}
}}
```

Mechanism:

- `deny_if_missing_human_approval(claims)` returns a 403 `JSONResponse`
  when `claims.human_approval` is not `True`.
- The shared factory's `extra_validate` hook calls this after PASETO
  verify, before any tool dispatch. The check runs **once per request**,
  not per tool.
- The MCP gateway (US-007) propagates the `human_approval` claim from the
  user's PASETO into the minted service-to-service PASETO unchanged. So
  the L3 admin's calling token must carry `human_approval=true` for the
  call to reach these tools.
- The deny-reason string matches `gateways.mcp.DenyReason.HUMAN_APPROVAL_REQUIRED`
  so the Grafana dashboard (US-023) groups blocked case_actions calls
  alongside other policy denies.

**Why is the gate here and not at the gateway?** Two reasons:
1. The gateway already enforces RBAC. Adding the human-approval check
   there couples the gateway to per-server policy.
2. Future case_actions tools may want per-tool nuance (e.g. allow
   `escalate_to_l3` without approval but require it for `freeze_account`).
   The check at the server gives that room without re-touching the
   gateway.

For v1 the policy is uniform: any tool on this server requires the claim.

## Env vars (production entry point `build_default_app()`)

- `CASE_ACTIONS_MCP_PUBLIC_KEY` — PEM path with the service PASETO public
  key. Same keypair as all other downstream MCP servers use.
- `CASE_ACTIONS_API_URL` — Base URL of the case_actions mock API
  (defaults to `http://localhost:8012`).

## Conventions

- Service PASETO validation runs **before** anything else — handled by
  `mcp_servers._common.create_jsonrpc_app`. The human-approval check runs
  **after** the PASETO is verified — a forged token can't slip approval.
- `httpx.AsyncClient` is **injectable** so tests stitch the mock app
  in-process via `httpx.ASGITransport`.
- FastMCP is used **as a tool registry only**.
- Tool params are typed (`list[str] | None`, `str`) — FastMCP infers the
  JSON schema; tests pin the required/optional split.

## US-024 docker-compose wiring

Two services to add: `case-actions-mock` (port 8012) +
`case-actions-mcp` (port 8013). The MCP gateway's `MCP_GATEWAY_SERVERS`
env var (when it lands) should include
`case_actions=http://case-actions-mcp:8013`. The mock is stateless from
docker-compose's perspective (no volume needed — the journal is
in-memory and rebuilt on container restart).

## Pitfalls

- **The human-approval gate runs once per request.** A `tools/list`
  request also requires `human_approval=true`. If you want listing
  to be ungated (so an analyst can discover the tools without approval),
  move the check inside the `tools/call` branch — but that's a policy
  change, not a bug.
- **`human_approval` is a top-level claim on the PASETO**, not a
  parameter to the tool. The MCP gateway propagates it through the
  service-to-service mint; if the gateway ever drops it, tests
  here will fail loudly. Pinned by
  `test_human_approval_claim_propagates_through_gateway_e2e`.
- **The mock has no auth.** The human-approval gate is purely the
  server's responsibility. Tests that call the mock directly (bypassing
  the MCP server) need no token. This is intentional — see
  `mock_apis/case_actions/CLAUDE.md` for the layering rationale.
