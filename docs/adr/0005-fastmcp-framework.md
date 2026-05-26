# ADR 0005 — FastMCP for downstream MCP servers

- **Status**: Accepted
- **Date**: 2026-05-26
- **Story**: US-033 (decision originally implemented in US-009 ..
  US-016 and consolidated in US-015's `mcp_servers/_common.py`)

## Context

Each downstream service in the stack — `customer_data`,
`transactions`, `kyc`, `sanctions`, `osint`, `case_actions` — fronts a
small mock API behind an MCP server. The MCP server wraps three tools
per service (PRD §6.6), validates the service-to-service PASETO,
forwards to the mock API via `httpx`, and returns an MCP-shaped
`tools/call` response.

We had three plausible MCP server implementations:

1. **FastMCP** (`mcp.server.fastmcp`). A decorator-style server from
   the official Anthropic MCP Python SDK ecosystem. `@mcp.tool(...)`
   registers a tool with introspected JSON-schema parameters; the
   resulting `FunctionTool` exposes `.run(arguments_dict)` and
   `.parameters` (the JSON schema for `inputSchema`).
2. **Raw MCP Python SDK.** Lower-level, manual handler registration,
   manual JSON-schema construction.
3. **Hand-rolled JSON-RPC handler.** Drop both libraries entirely,
   accept POST bodies, dispatch by `method`, return MCP wire shapes
   directly.

The forcing functions:

- **The MCP gateway controls the transport.** Auth (PASETO verify),
  RBAC, audit, and replay defense all live in
  `gateways/mcp/main.py`. Downstream servers do not need to speak the
  full streamable-HTTP MCP transport — they only need to accept a
  JSON-RPC body the gateway has already authenticated.
- **Six near-identical servers.** Code duplication across the six
  services would be a maintenance hazard. The interesting per-server
  surface is the three tool callables; the shared scaffolding (PASETO
  verify, JSON-RPC dispatch, MCP wire-shape coercion, upstream HTTP
  error mapping) is the same everywhere.
- **The two-way fence between SKILL.md and tool schemas.** Each
  subskill declares its MCP-server dependencies in an HTML comment;
  each server's `tools/list` response is the wire-format truth.
  `tests/test_<server>_mcp_server.py::test_tools_list_schemas_match_<skill>_contract`
  pins the contract from the server side. Whatever produces the
  `inputSchema` must accept the test's introspection.
- **Tool dispatch must happen inside our auth gate.** FastMCP ships
  an HTTP transport; using it would put auth somewhere other than
  the gateway. We bypass the transport and call `tool.run(args)`
  directly after our own PASETO check.

We picked FastMCP for the tool-registry layer and built our own
JSON-RPC framing on top of it.

## Decision

**Use FastMCP as a tool registry only. Wrap every server in a thin
FastAPI shell that owns transport, PASETO verify, JSON-RPC framing,
and the upstream HTTP call.**

Concretely:

- Each `mcp_servers/<name>/main.py` declares `SERVER_NAME`,
  `TOOL_NAMES`, and `DEFAULT_API_URL` at module scope, then writes a
  `build_mcp(api_client) -> FastMCP` that registers tools via
  `@mcp.tool(...)`.
- The consolidated higher-order factory
  `mcp_servers/_common.create_jsonrpc_app(server_name=, title=,
  description=, mcp_factory=, public_key_path=, api_base_url=,
  api_client=, extra_validate=...)` returns the FastAPI app.
- Per-call pipeline inside the factory: PASETO verify (via
  `verify_service_paseto_header`) → optional `extra_validate(claims)`
  hook → JSON-RPC body parse → `tools/list` schema dump (via
  `list_tools_response`) or `tools/call` dispatch
  (via `tool.run(arguments_dict)`) → MCP wire-shape coercion (via
  `tool_result_to_mcp`) → upstream HTTP error mapping (via the
  factory's `httpx.HTTPStatusError` handler — `upstream_status` and
  `upstream_body` carried in `error.data`, 5xx → 502, 4xx
  passthrough).
- Two policy seams for tool denies:
  - `extra_validate(claims)` — for denies that depend only on
    claims (e.g., case_actions' `human_approval_required`).
  - `ToolDispatchError(message, *, status_code=400, data=...)` —
    raised from inside `tool.run()` for denies that depend on tool
    arguments (e.g., osint's `domain_not_allowed`). The factory
    catches it and emits a structured JSON-RPC error.
- Each per-server module ends up ~80 lines. The factory is ~250
  lines and is the single point of change for transport-layer
  contracts.

## Consequences

**Positive:**

- Per-server modules contain only domain logic: three tool
  callables and one `create_app(...)` wrapper. Adding a new server
  is a 100-line PR (see [`docs/adding-a-data-source.md`](../adding-a-data-source.md)
  Step 2).
- The two-way fence between SKILL.md and `tools/list` schemas is
  enforced by FastMCP's introspection — `tool.parameters` is the
  JSON schema, and the contract test reads it directly. There is no
  separate "schema document" to drift.
- Cross-cutting changes (e.g., adding `human_approval` to the PASETO
  claims and the `extra_validate` seam in US-016) happened in one
  file plus six trivial wiring lines. The osint allowlist deny
  (US-015) introduced `ToolDispatchError` without touching any other
  server.
- All servers share one upstream error mapping. When the
  case_actions mock returns 422 for a malformed write, the
  `upstream_status` passthrough goes through unmodified to the
  caller.

**Negative:**

- FastMCP is part of the official MCP Python SDK ecosystem, but the
  surface evolves. The patterns documented in the Codebase Patterns
  section of `progress.txt` (`mcp.tool(name=, description=)`,
  `mcp.list_tools(run_middleware=False)`, `mcp.get_tool(name)`
  returning `Tool | None` rather than raising,
  `tool.run(arguments_dict)` returning `ToolResult`) are pinned to
  FastMCP 3.3.1. Major-version bumps are a contained change because
  the factory is the only consumer, but tests must be updated in
  lockstep.
- We do not use FastMCP's HTTP transport. A contributor reading the
  upstream FastMCP examples will see `mcp.run()` and `mcp.app`
  references that do not apply here. Pattern docs in
  `mcp_servers/<name>/CLAUDE.md` call this out.
- `tools/call` arguments arrive as a dict (Anthropic schema) with an
  `arguments` envelope; we unwrap it in the harness for symmetry.
  The factory exposes `tool.run(arguments_dict)` directly, so the
  envelope handling lives at the caller, not in the factory.

**Risk acceptance:**

- If FastMCP is superseded by an official Anthropic transport that
  cleanly separates auth from dispatch, we would migrate to it. The
  isolation today (FastMCP is touched only by `_common.py` and the
  six `build_mcp` helpers) makes that migration plausible without
  touching skills, gateway, or audit.

## Alternatives considered

- **Use FastMCP's HTTP transport directly.** Rejected — auth would
  have to live inside the FastMCP transport or in front of it via a
  separate middleware library. We want PASETO verify to be the
  first thing every request hits, and JSON-RPC framing to be a
  single boring code path we own.
- **Raw MCP Python SDK with hand-rolled tool schemas.** Rejected —
  every tool's JSON schema would be hand-written and prone to drift
  from the Python signature. FastMCP's introspection collapses the
  drift surface.
- **Hand-rolled JSON-RPC handler, no MCP libraries.** Rejected for
  the wire format — even if our consumers are limited to the MCP
  gateway today, conforming to the MCP `tools/list` and `tools/call`
  shapes means future Anthropic SDK consumers can talk to our
  servers without translation.

## Cross-links

- [US-009 prd.json entry](../../prd.json) — first MCP server
  acceptance criteria.
- [US-015 prd.json entry](../../prd.json) — the consolidation
  that lifted shared pipeline into `mcp_servers/_common.py` and
  introduced `ToolDispatchError`.
- [US-016 prd.json entry](../../prd.json) — `extra_validate` seam
  for `human_approval_required`.
- `mcp_servers/_common.py` — the higher-order factory.
- `mcp_servers/<service>/main.py` — six near-identical thin shells.
- [`docs/adding-a-data-source.md`](../adding-a-data-source.md)
  Step 2 — copy-this-pattern guide for new servers.
