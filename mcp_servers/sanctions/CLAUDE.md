# mcp_servers/sanctions/

Fourth downstream MCP server. Wraps the sanctions mock API (US-014) and sits
behind the MCP gateway (US-007). Three tools — `screen_name`,
`screen_entity`, `get_watchlist_hit` — all read-only. Same shape as the three
prior downstream MCP servers; this is the **fourth** copy of the JSON-RPC +
PASETO pipeline.

## Endpoints

| Method | Path           | Purpose                                                                                                                |
| ------ | -------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `POST` | `/sanctions`   | MCP JSON-RPC 2.0. Supports `tools/list` and `tools/call`. Requires a valid service-to-service PASETO bearer header. |
| `GET`  | `/healthz`     | Liveness probe.                                                                                                       |

The URL suffix is `/sanctions` because the gateway POSTs to
`f"{downstream_url}/{server}"` and `SERVER_NAME = "sanctions"`.

## Tools (contract for the future screen-sanctions SKILL.md, US-019)

| Tool                | Required args | Optional args | Returns                                                                                                |
| ------------------- | ------------- | ------------- | ------------------------------------------------------------------------------------------------------ |
| `screen_name`       | `name`        | `scenario`    | `{query, scenario, matched, hits: [...]}`                                                              |
| `screen_entity`     | `entity_name` | `scenario`    | Same shape, `entity_type="entity"` on every hit.                                                       |
| `get_watchlist_hit` | `hit_id`      | —             | `{hit_id, queried_name, listed_name, entity_type, program, hit_type, listed_on, country, match_score, aliases, addresses}` |

`get_watchlist_hit` does NOT take `scenario` — the hit_id encodes the
scenario internally so the call is unambiguous.

Tool input schemas come from the FastMCP python signatures. Don't change a
tool's parameter set without updating `test_tools_list_schemas_match_sanctions_contract`
in lockstep.

## Env vars (production entry point `build_default_app()`)

- `SANCTIONS_MCP_PUBLIC_KEY` — PEM path with the service PASETO public key.
  Same keypair as customer_data + transactions + kyc use — the gateway holds
  the private half once and every downstream verifies against the same
  public half.
- `SANCTIONS_API_URL` — Base URL of the sanctions mock API (defaults to
  `http://localhost:8008`).

## Conventions

- Service PASETO validation runs **before** anything else. Same five failure
  modes as the prior MCP servers: missing / wrong-scheme / garbage / expired
  / wrong-keypair → 401 + JSON-RPC error body.
- `httpx.AsyncClient` is **injectable** so tests stitch the mock app
  in-process via `httpx.ASGITransport`.
- FastMCP is used **as a tool registry only**. `tool.run(args)` is the
  execution entry point — don't mount FastMCP's built-in HTTP transport
  because we need PASETO validation in front of any tool call.

## US-024 docker-compose wiring

Two services to add: `sanctions-mock` (port 8008) + `sanctions-mcp` (port
8009). The MCP gateway's `MCP_GATEWAY_SERVERS` env var (when it lands)
should include `sanctions=http://sanctions-mcp:8009`.

## Consolidation note (DONE in US-015)

US-015 lifted the duplicated pipeline (PASETO middleware,
`_jsonrpc_error/_result`, `_list_tools`, `_tool_result_to_mcp`, JSON-RPC
body parsing) into `mcp_servers/_common.py`. The sanctions server's
`create_app` is now a thin shell that calls `create_jsonrpc_app(...)`.
case_actions (US-016) can plug in the `human_approval=true` claim check
via the `extra_validate` parameter on `create_jsonrpc_app`.

## Pitfalls

- `FastMCP.get_tool(name)` returns `None` on miss — it does NOT raise.
- `tool.run(arguments)` is awaitable — don't `asyncio.run()` it inside a
  request handler.
- The mock returns HTTP 404 for unknown `hit_id` and HTTP 400 for unknown
  `?scenario=`. Both surface via `httpx.HTTPStatusError` → passthrough with
  `upstream_status` / `upstream_body` in `error.data`. Don't smuggle either
  into a 500 — the eval harness distinguishes them.
- `get_watchlist_hit` is the only sanctions tool that takes a single arg
  that isn't a name or customer_id. Its hit_id must come from a prior
  `screen_name` / `screen_entity` result; constructing one by hand will
  almost always 404.
- The MCP gateway's replay cache tracks user `jti` values. In end-to-end
  tests that make two calls (screen, then get_watchlist_hit), mint a fresh
  user token per call — re-using one token = 401 token_replay.
