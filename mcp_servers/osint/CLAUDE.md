# mcp_servers/osint/

Fifth downstream MCP server (US-015). Wraps the osint mock API and sits
behind the MCP gateway (US-007). Three tools — `web_search`, `fetch_page`,
`lookup_company` — all read-only.

**This is the first MCP server to use the consolidated
`mcp_servers/_common.py`** factory. The four prior servers
(customer_data/transactions/kyc/sanctions) were refactored to use the same
shared pipeline as part of US-015. If you fork another downstream from
here, follow the thin-shell pattern: declare constants + a `build_mcp()`
that registers tools + a `create_app()` that calls
`create_jsonrpc_app(...)`.

## Endpoints

| Method | Path        | Purpose                                                                                                              |
| ------ | ----------- | -------------------------------------------------------------------------------------------------------------------- |
| `POST` | `/osint`    | MCP JSON-RPC 2.0. Supports `tools/list` and `tools/call`. Requires a valid service-to-service PASETO bearer header. |
| `GET`  | `/healthz`  | Liveness probe.                                                                                                      |

The path is `/osint` because the gateway POSTs to
`f"{downstream_url}/{server}"` and `SERVER_NAME = "osint"`.

## Tools (contract for the check-osint SKILL.md, US-018)

| Tool             | Required args    | Optional args | Returns                                                                                                                                          |
| ---------------- | ---------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `web_search`     | `query`          | `scenario`    | `{query, scenario, results: [...], adverse_count}`                                                                                              |
| `fetch_page`     | `url`            | `scenario`    | `{url, scenario, title, text, language, captured_year, byte_size, adverse, content_digest, fetched_from}` — **gated by OSINT_ALLOWLIST**         |
| `lookup_company` | `company_name`   | `scenario`    | `{company_name, jurisdiction, incorporated_year, status, directors, beneficial_owners, risk_signals}`                                            |

Tool input schemas are FastMCP-generated; don't change them without updating
`test_tools_list_schemas_match_osint_contract` in lockstep.

## The OUTBOUND ALLOWLIST — the load-bearing US-015 requirement

`fetch_page` is the only tool in the entire codebase that could plausibly
touch real upstream URLs in a future production deploy. To make sure it
never reaches an attacker-supplied host, every call goes through a
configurable allowlist:

- **Env var: `OSINT_ALLOWLIST`** — comma-separated lowercase hostnames
  (e.g. `OSINT_ALLOWLIST=ofac.example,sec.example,fca.example`).
- **Default: empty** — every URL is rejected. Operators MUST opt-in.
- **Match: exact-host, no wildcards** — `api.ofac.example` is NOT allowed
  by an entry of `ofac.example`. Promote to suffix-matching only if
  operationally needed; deny-by-default is the safer footing.
- **Deny shape:** HTTP 403 + JSON-RPC error body with
  `error.data.deny_reason="domain_not_allowed"` and `error.data.host=<host>`.
  The deny taxonomy lines up with `gateways.mcp.DenyReason` so US-023's
  Grafana dashboard can group blocked OSINT fetches alongside other
  policy denies.
- **No upstream call happens on deny** — the check runs inside the tool
  coroutine before the httpx GET, so the mock never sees a non-allowlisted
  URL.

Mechanism: the tool raises `mcp_servers._common.ToolDispatchError(...,
status_code=403, data={"deny_reason": "domain_not_allowed", ...})`. The
shared factory catches it and surfaces the structured error. **This is
the pattern any future tool with a caller-facing deny should use.**

## Env vars (production entry point `build_default_app()`)

- `OSINT_MCP_PUBLIC_KEY` — PEM path with the service PASETO public key.
  Same keypair as all other downstream MCP servers use.
- `OSINT_API_URL` — Base URL of the osint mock API (defaults to
  `http://localhost:8010`).
- `OSINT_ALLOWLIST` — Comma-separated hostnames. Default: empty.

## Conventions

- Service PASETO validation runs **before** anything else — handled by
  `mcp_servers._common.create_jsonrpc_app`.
- `httpx.AsyncClient` is **injectable** so tests stitch the mock app
  in-process via `httpx.ASGITransport`.
- FastMCP is used **as a tool registry only**.
- The allowlist is captured by the tool closure at `build_mcp()` time. To
  reload it at runtime, restart the server. (Hot-reload would require a
  mutable container; current ops model is restart-on-change.)

## US-024 docker-compose wiring

Two services to add: `osint-mock` (port 8010) + `osint-mcp` (port 8011).
The MCP gateway's `MCP_GATEWAY_SERVERS` env var (when it lands) should
include `osint=http://osint-mcp:8011`. `osint-mcp` needs
`OSINT_ALLOWLIST=` set explicitly (even if empty) so an operator who
forgets the variable doesn't get a silently-different default.

## Pitfalls

- **Default allowlist is empty.** A test that drops the allowlist and
  expects `fetch_page` to succeed will get a 403. Pass
  `allowlist=frozenset({"ofac.example"})` to `create_app(...)` in tests
  that exercise the happy path.
- **Exact-host match.** Anyone shipping a wildcard variant should update
  `is_url_allowed` AND the deny-reason taxonomy at the same time so
  audit/dashboard semantics stay legible.
- **Allowlist is NOT case-sensitive** — `parse_allowlist` lowercases on
  entry; `is_url_allowed` lowercases the URL's host. Hex-encoded hosts /
  punycode are NOT normalized here — feed them in already-encoded.
- **The mock never validates URLs.** A non-allowlisted URL is rejected by
  the MCP server before reaching the mock; an allowlisted URL is
  manufactured by the mock regardless of whether it would actually be
  fetchable.
- The MCP gateway's replay cache still tracks user `jti` values — multi-hop
  e2e tests must mint a fresh user token per call (same pattern as
  `test_sanctions_mcp_server.py`).
