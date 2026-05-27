# Launch post: fraud-copilot-oss — a reference agentic copilot with the auth, RBAC, and audit layer that regulated industries need

- **Status**: Draft (US-034, M3)
- **Date**: 2026-05-26
- **Story**: US-034
- **Audience**: compliance officers, detection engineers, platform engineers,
  founders building on the Anthropic stack.

---

## TL;DR

Today we are open-sourcing **fraud-copilot-oss**: a Python reference
implementation of an agentic fraud-investigation copilot that ships the
load-bearing security plumbing — OIDC, PASETO, RBAC, audit, OpenTelemetry —
so a small team can prototype a regulated AI workflow in a day instead of
six months.

It mirrors the Qonto anti-financial-crime architecture (Stephano
Amorelli's talk gave us the blueprint): a Claude Cowork plugin talks
through an MCP gateway that mints short-lived PASETO tokens, enforces
declarative role-based access control, audits every call, and federates
to six downstream MCP servers — each wrapping a mock data source that
integrators swap for their real backend.

`docker compose up` brings up the full stack in under 30 seconds. The
eval suite ships with the repo. Apache 2.0.

- **Repo**: <https://github.com/iceberg-security/fincrime-secured-mcp>
- **Site**: <https://iceberg-security.github.io/fincrime-secured-mcp/>
- **Quickstart**: `make install && make compose-up && make load-fixtures`
- **PRD**: [`tasks/prd-fraud-investigator-plugin.md`](../tasks/prd-fraud-investigator-plugin.md)
- **Threat model**: [`docs/threat-model.md`](threat-model.md)
- **ADRs**: [`docs/adr/`](adr/)

---

## Why we built this

Most open-source MCP demos skip the auth, RBAC, and audit layer. That is
exactly the layer regulated industries — banks, brokers, fintech
platforms — require before they will put an agent into production.

Detection teams we talked to had the same shape of problem:

1. Analysts pivot across 8–12 tabs to assemble context for a single
   alert.
2. Their security and compliance teams require a paper trail per
   tool call (who, when, why, what came back).
3. Off-the-shelf agent demos either ignore the paper trail or build it on
   homegrown crypto that does not survive a security review.
4. By the time the security review is over, the prototype has been
   shelved.

We wanted to collapse that loop. Not by building a finished product, but
by shipping the load-bearing security pieces — gateway, claims, replay
protection, RBAC, audit — that every regulated agent rebuilds badly. With
those in place, an integrator can focus on what is actually proprietary:
their data sources, their alert taxonomy, their narrative voice.

## What's in the box

| Layer | What ships | Where |
| --- | --- | --- |
| **Auth gateway** | FastAPI service that validates an OIDC bearer and mints 5-min user PASETO v4.public tokens | `gateways/auth/` |
| **MCP gateway** | Streamable-HTTP MCP gateway: PASETO verify, jti replay cache, RBAC enforce, re-sign service-to-service PASETO (separate keypair, 60s TTL), forward, audit emit. ≤500 LOC core. | `gateways/mcp/` |
| **6 downstream MCP servers** | FastMCP wrappers for `customer_data`, `transactions`, `kyc`, `sanctions`, `osint`, `case_actions`. `case_actions` requires `human_approval=true` on the claim | `mcp_servers/` |
| **6 mock APIs** | Pure in-memory FastAPI mocks, deterministic per `customer_id`, six scenario personas returning cross-server-consistent shapes | `mock_apis/` |
| **Cowork plugin** | Orchestrator (≤100 lines, routes only), five investigation subskills, and a `verify-output` meta-skill that annotates unsupported claims | `plugin/` |
| **Eval suite** | Declarative YAML datasets per persona, four scorers (tool correctness, ordering, grounding, reasoning), headless harness, GitHub Actions CI | `evals/` |
| **Grafana dashboard** | Provisioned dashboard for audit volume, latency, denied-by-role, tool-calls-per-user | `config/grafana/` |
| **Docs** | Threat model, "add your data source in 1 hour" tutorial, agent testing guide, ADRs for every load-bearing choice | `docs/` |

See the [README](../README.md) for the full table and the
[ADR index](adr/README.md) for the rationale behind each row.

## The security spine

Two things make the gateway worth reading even if you never run it.

**One algorithm, one path.** We use PASETO v4.public (Ed25519) exclusively
— not JWT. There is no algorithm-confusion surface, claims are typed, and
we keep two distinct keypairs: one for the user token (auth gateway →
plugin → MCP gateway) and one for the service-to-service token (MCP
gateway → downstream MCP servers). The MCP gateway never reissues the
user token; it re-signs a fresh service token with its own private key.
That separation is load-bearing and is documented in
[ADR-0002](adr/0002-paseto-over-jwt.md).

**Replay protection by default.** Every gateway request carries a `jti`.
The gateway holds an in-memory LRU (capacity 10 000) keyed by `jti` and
rejects the second sighting inside the token's TTL. The cache exists in
the gateway and only the gateway, which keeps the design clean.

**Declarative RBAC.** Roles live in `config/rbac.yaml` with inheritance
and group-claim mapping. The file is hot-reloaded via `mtime` on every
resolve. PRs against the YAML are reviewable by a compliance officer in
the normal code-review flow — no Terraform indirection, no UI panel to
audit ([ADR-0003](adr/0003-yaml-rbac.md)).

**Audit by default, no `DELETE`.** Every gateway call lands in an
audit store: SQLite by default ([ADR-0004](adr/0004-sqlite-default-audit.md)),
ClickHouse opt-in via `AUDIT_BACKEND=clickhouse`. The module's public
surface has no `DELETE` method; append-only is enforced by absence rather
than by SQL trigger.

**Skills are repo-resident files.** The `SKILL.md` files are read
verbatim — never templated — and tied to a git commit hash in the audit
log. The model never writes its own skill. The
[threat model](threat-model.md) calls out skill spoofing as a named
boundary.

The [threat model](threat-model.md) walks all seven trust boundaries and
maps each one to its mitigation.

## The agent half

The plugin is an opinionated XML structure: every `SKILL.md` has the
same six sections (`<goal>`, `<inputs>`, `<tools>`, `<steps>`,
`<output_format>`, `<constraints>`) and declares its MCP-server
dependencies at the top of the file. The orchestrator is short (≤100
lines), routes-only, and always invokes `verify-output` last. The
verifier ([ADR-0006](adr/0006-annotate-not-block-verifier.md)) flags
factual claims that no logged tool result supports — annotate-not-block
in v1 — so analysts learn where the model fabricated without losing the
investigation.

Default model is Claude Opus 4.7
([ADR-0007](adr/0007-opus-default-model.md)). The eval harness defaults
to a deterministic stub so CI never needs an API key; integrators swap
in `AnthropicAgent` and `AnthropicJudge` for nightly runs.

## The eval surface

Six declarative datasets — `clean_customer`, `mule_account`,
`sanctions_hit`, `account_takeover`, `structuring`, `synthetic_id` — each
pinning the expected tool calls, ordering constraints, verdict, and the
facts the report must support. Four scorers:

- **tool_correctness** — set comparison of expected vs. audited calls.
- **tool_ordering** — dependent-ordering checks (screen before drafting).
- **grounding** — LLM judge over each claim, with `cache_control` on the
  system rubric for cost.
- **reasoning** — five-dimension rubric, 1–5 each, mean ≥ 4.0 to pass.

The PR-gate runs the smoke subset deterministically. Nightly runs
exercise the full suite against the live model. See
[`docs/agent-testing.md`](agent-testing.md) and
[ADR-0001](adr/0001-headless-cowork-harness.md) for the harness design.

## Add your own data source in an hour

The whole point is that an integrator can wire in their own neobank API,
their own KYC vendor, their own watchlist provider, and have the gateway
treat it the same as the mock. The walk-through is in
[`docs/adding-a-data-source.md`](adding-a-data-source.md): define the
MCP tool schema, drop a `mcp_servers/<name>/main.py` on top of the
shared `_common.create_jsonrpc_app` factory, declare the server in
`config/rbac.yaml`, reference it from a subskill. Each step has a
verification command.

## What's intentionally not here

- **No real production OIDC provider.** Bring your own — the mock IdP
  ships for dev only and is labelled "do not use in production" in
  source.
- **No long-lived secrets.** PASETO TTLs are 5 minutes (user) and 60
  seconds (service-to-service) and are not configurable in v1; the
  short windows bound the leak blast radius.
- **No write-path evals.** `case_actions` requires `human_approval=true`
  and the harness does not mint approved tokens by design. The
  human-approval gate is not a soft suggestion.
- **No telemetry from spans containing PII.** OpenTelemetry attributes
  carry `mcp.server`, `mcp.tool`, `user.role`; `user.email` and
  `user.sub` are explicitly forbidden and the helper raises on
  violation.

## Where to start

```bash
git clone https://github.com/iceberg-security/fincrime-secured-mcp
cd fincrime-secured-mcp
make install
make compose-up
make load-fixtures
```

Then open Grafana at `http://localhost:3000` and watch the audit volume
panel fill in as you run an investigation.

Read the threat model first. Read [ADR-0002](adr/0002-paseto-over-jwt.md)
second. Then read `gateways/mcp/main.py` — the entire MCP gateway is
under 500 LOC and is structured to be readable in one sitting.

## How to contribute

We are looking for:

- **Detection engineers** willing to PR a new persona or scenario.
- **Compliance officers** to red-team the RBAC schema and audit fields.
- **Platform folks** to PR additional downstream MCP servers (we expect
  ledger, watchlist providers, internal case-management systems to be
  the early shapes).

Open an issue if you are integrating against a real backend and hit a
sharp edge — the goal is to round those off before v1.0.

## Credits

Inspired by Stephano Amorelli's talk on Qonto's anti-financial-crime
architecture. Built on Anthropic's Claude Opus, the official Python MCP
SDK (FastMCP), FastAPI, pyseto, pyjwt, opentelemetry-python, and a stack
of community Python libraries we depend on every day.

---

## Change log

| Date | Change | Author |
| --- | --- | --- |
| 2026-05-26 | Initial draft (US-034) | ralph + Amit |
