# ADR 0001 — Headless Cowork harness

- **Status**: Accepted
- **Date**: 2026-05-26
- **Story**: US-029

## Context

The fraud-investigator plugin (`plugin/`) ships as a Claude Cowork
plugin: orchestrator + subskills + meta-skill verifier, talking to the
mock stack through the MCP gateway. The eval loop (US-027 → US-030)
must drive this plugin end-to-end and produce a tool-call trace that
the programmatic + LLM-judge scorers can consume.

We have two plausible paths to a headless eval driver:

1. **Cowork CLI/SDK** — invoke the actual Cowork agent runner from the
   command line or via its SDK. The orchestrator + subskills are
   loaded by the real product surface; we observe tool calls through
   the MCP gateway's audit log.
2. **Custom Python harness** — implement a small agent loop in this
   repo. The harness reads the orchestrator SKILL.md as a system
   prompt, binds the MCP-server tools as Anthropic tool-use
   definitions, and drives Claude through a tool-call loop. Tool calls
   are routed to the MCP gateway over HTTP; the audit log captures
   the same trace.

Decision drivers:

- **Stability of the dependency.** Cowork is an unreleased Anthropic
  product in 2026. Its CLI surface, SDK shape, and plugin contract
  are all in active flux. Pinning the eval gate to a moving target
  slows the launch.
- **CI ergonomics.** US-030 wires `make evals-smoke` into GitHub
  Actions. CI must be able to install dependencies, mint PASETOs, run
  the harness, and tear down — all without requiring an installed
  Cowork CLI or a CLI-internal credential flow.
- **Test isolation.** The scorers (US-027 / US-028) consume a
  tool-call trace + a final report. They do not care which runner
  produced them. As long as the harness drives the same plugin and
  produces the same trace shape (audit-log rows + draft-narrative
  artifact), the scorers run unchanged.
- **Open-source posture.** The PRD's goal is to ship a fully
  reproducible fraud-investigator stack. A custom harness keeps the
  whole eval loop within the repo; contributors can clone, install,
  and run the gate locally without provisioning Cowork access.
- **Future portability.** When Cowork stabilizes a public headless
  surface, swapping the runner shim is a one-file change. The skill
  files (`plugin/skills/*/SKILL.md`), the dataset YAMLs, the gateway
  contract, and the scorers are all unchanged.

## Decision

**Option 2 — Custom Python harness in `evals/harness/`.**

Concretely:

- `evals/harness/agent.py` defines an `Agent` Protocol — any callable
  with `agent(*, skill_md, alert, tools, tool_results) -> AgentStep`.
  The protocol is `runtime_checkable` so tests can inject deterministic
  stubs without depending on the Anthropic SDK.
- `evals/harness/agent.py::AnthropicAgent` is the production
  implementation. It calls the Anthropic Messages API, binds MCP tools
  as Claude tool-use definitions, and parses the response into
  `AgentStep` (either `ToolCall(name, args)` or
  `FinalAnswer(report_json)`).
- `evals/harness/runner.py::run_dataset(...)` orchestrates one eval
  case: load the orchestrator SKILL.md, derive the allowed tool list
  from the dataset's `expected_tool_calls`, loop the agent until it
  produces a final answer or exceeds `max_steps`, and return a
  `HarnessResult` containing the audit-log slice + the final report.
- The audit-log slice is filtered by the harness-minted PASETO's
  `trace_id` so the scorers (US-027 / US-028) see only this run's
  rows.
- For tests, a `StubAgent` returns a scripted sequence of `ToolCall` /
  `FinalAnswer` steps; the smoke test in `tests/test_harness.py` uses
  it to drive `clean_customer.yaml` end-to-end through the in-process
  gateway → MCP server → mock chain.

## Consequences

**Positive:**

- The eval gate has no runtime dependency on the Cowork product.
  Contributors can run `make evals-smoke` against the local stack
  without an Anthropic account if they inject a `StubAgent`.
- The harness produces the same audit-log trace the real Cowork
  runtime would (because both go through the MCP gateway), so the
  US-027 / US-028 scorers stay unchanged.
- The `Agent` Protocol mirrors the `Judge` Protocol introduced in
  US-028. Production code uses the Anthropic-backed implementation;
  tests inject deterministic fakes. One pattern, two seams.
- Skills remain audited by commit hash — the harness reads SKILL.md
  files from disk rather than re-generating them, so a malicious LLM
  cannot smuggle in a different orchestrator.

**Negative:**

- The harness has to maintain its own translation layer between the
  plugin's `<tools>` declaration block and Anthropic's tool-use
  schema. Until Cowork exposes a stable headless API, this layer is
  load-bearing and must be kept aligned with `plugin.json` /
  `SKILL.md` changes. The `ALLOWED_TOOLS` table in
  `evals/datasets/schema.py` is the existing single source of truth;
  the harness reuses it to derive the tool list.
- The harness's agent loop is simpler than Cowork's (no subskill
  dispatch, no built-in safety filters). We document this as a known
  delta in `docs/agent-testing.md`. The verifier meta-skill (US-021)
  remains the cross-cutting safety net regardless of runner.

**Risk acceptance:**

- The harness drives an Anthropic-backed agent; that agent could in
  principle deviate from the orchestrator skill. We mitigate by (a)
  pinning the skill content into the `system` prompt verbatim and
  (b) limiting the tool list to the dataset's `expected_tool_calls`
  surface plus an explicit `final_answer` tool. This keeps the
  attack surface small enough for the LLM-judge scorers in US-028 to
  catch deviations.

## Alternatives considered

- **Cowork CLI subprocess.** Rejected — couples CI to the Cowork
  installer.
- **Cowork SDK direct calls.** Rejected — the SDK surface is not
  stable as of 2026-05-26.
- **No headless harness; run plugin only via the Cowork desktop
  app and capture audit logs out of band.** Rejected — the PRD
  pins CI integration (US-030), which requires a non-interactive
  runner.
- **MCP Python SDK + handcrafted tool loop, no LLM.** Rejected for
  the production gate — without an LLM the grounding + reasoning
  scorers cannot run. Kept as a `StubAgent` for unit tests.

## Cross-links

- [US-029 prd.json entry](../../prd.json) — acceptance criteria.
- `evals/harness/` — implementation.
- `docs/agent-testing.md` — worked example for contributors.
- `evals/scorers/judge.py` — sibling Protocol pattern (US-028).
