# Agent testing — the headless harness

This guide shows how to drive the fraud-investigator plugin end-to-end
without the Cowork desktop app, using the Python harness in
`evals/harness/`. See
[`docs/adr/0001-headless-cowork-harness.md`](adr/0001-headless-cowork-harness.md)
for the decision behind the harness.

## What the harness does

The harness runs one or more `evals/datasets/*.yaml` cases through a
local agent loop and produces a structured result the US-027 /
US-028 scorers can consume:

1. Loads `plugin/skills/orchestrator/SKILL.md` from disk.
2. Mints (or accepts) a user PASETO scoped to the case.
3. Builds an Anthropic-style tool list from the dataset's
   `expected_tool_calls`. The agent only sees the surface the case
   sanctioned.
4. Loops the agent:
   - Pass the SKILL.md (system prompt), the input alert, the tool
     definitions, and the running tool-result history.
   - Receive either a `ToolCall` or a `FinalAnswer`.
   - On `ToolCall`: POST a JSON-RPC `tools/call` to the MCP gateway
     with the user PASETO. Append the result to the history.
   - On `FinalAnswer`: stop with the report.
5. Filter the audit log by the run's `trace_id` and return everything
   in one `HarnessResult`.

## Quick example

```python
from pathlib import Path

import httpx

from evals.datasets.schema import validate_dataset_file
from evals.harness import (
    AnthropicAgent,
    StubAgent,
    ToolCall,
    FinalAnswer,
    run_dataset,
)

dataset = validate_dataset_file(Path("evals/datasets/clean_customer.yaml"))

# Live run: drive Anthropic's API. Requires ANTHROPIC_API_KEY +
# the M1 docker stack already up.
agent = AnthropicAgent()  # uses claude-opus-4-7 + prompt caching

def fresh_paseto() -> str:
    """Mint a brand-new PASETO via mock OIDC -> auth gateway.

    The MCP gateway tracks ``jti`` to prevent replay, so every tool
    call needs its own token. Wrap the auth flow in a zero-arg
    factory and pass it in.
    """
    oidc_token = httpx.get(
        "http://localhost:9000/login?email=alice@example.com"
    ).json()["access_token"]
    return httpx.post(
        "http://localhost:8080/token",
        headers={"Authorization": f"Bearer {oidc_token}"},
    ).json()["access_token"]


result = run_dataset(
    dataset,
    skill_path=Path("plugin/skills/orchestrator/SKILL.md"),
    agent=agent,
    http_client=httpx.Client(),
    gateway_url="http://localhost:8000",
    paseto_factory=fresh_paseto,  # mints one PASETO per tool call
    trace_id="trace-clean-001",
    sub="alice@example.com",
)
print(f"terminated: {result.terminated}")
print(f"steps: {result.steps_used}")
print(f"audit rows: {len(result.audit_rows)}")
print(f"report: {result.report}")
```

The same call shape works with a deterministic `StubAgent` for
unit tests:

```python
stub = StubAgent(steps=[
    ToolCall(id="t1", name="customer_data__get_customer",
             arguments={"arguments": {"customer_id": "cust-clean-01"}}),
    ToolCall(id="t2", name="customer_data__list_accounts",
             arguments={"arguments": {"customer_id": "cust-clean-01"}}),
    ToolCall(id="t3", name="customer_data__get_device_history",
             arguments={"arguments": {"customer_id": "cust-clean-01"}}),
    FinalAnswer(report={
        "alert_id": "alert-clean-0001",
        "customer_id": "cust-clean-01",
        "verdict": "low_risk",
        "evidence": [],
        "recommended_actions": [],
        "evidence_gaps": [],
    }),
])

result = run_dataset(dataset, skill_path=..., agent=stub, ...)
```

## The Agent Protocol

Any callable with this signature is a valid `Agent`:

```python
def my_agent(
    *,
    skill_md: str,                     # orchestrator SKILL.md contents
    alert: Mapping[str, Any],          # dataset.input_alert + _scenario
    tools: Sequence[Mapping[str, Any]],# tool definitions (Anthropic schema)
    tool_results: Sequence[Mapping[str, Any]],  # past calls + their results
) -> ToolCall | FinalAnswer: ...
```

The Protocol mirrors `evals.scorers.judge.Judge` from US-028: one
seam, two implementations (production + test fake).

### Tool definition shape

The harness builds tool definitions from the dataset's
`expected_tool_calls`. Names are encoded as `<server>__<tool>`
(double underscore) so the agent's tool calls round-trip cleanly
without needing a side table — the runner splits the name back into
`(server, tool)` before posting to the gateway.

Each definition carries a sidecar `_meta` block the runner uses for
routing:

```python
{
    "name": "customer_data__get_customer",
    "description": "Call the customer_data MCP server's get_customer tool...",
    "input_schema": {
        "type": "object",
        "properties": {
            "arguments": {"type": "object", "additionalProperties": True}
        },
        "required": ["arguments"],
        "additionalProperties": False,
    },
    "_meta": {"server": "customer_data", "tool": "get_customer"},
}
```

The synthetic `final_answer` tool terminates the loop with the
draft-narrative report payload.

### Anthropic SDK and prompt caching

`AnthropicAgent` pins SKILL.md in the `system` channel with
`cache_control={"type": "ephemeral"}` so the static orchestrator
prompt is cached for the 5-minute Anthropic TTL. Every step within
one `run_dataset(...)` call hits the cache. This mirrors the
`AnthropicJudge` pattern (US-028).

The SDK is an **optional** dependency
(`pip install fraud-copilot-oss[evals]`). If you don't install it,
`AnthropicAgent()` raises on construction — inject a
`StubAgent` or your own `Agent` fake for offline runs.

## What the harness DOES NOT do

- **No auth-flow handling.** Callers mint the user PASETO themselves
  (via the mock OIDC + auth gateway, or by minting directly in test
  setup). The harness only consumes the token.
- **No replay-cache reset.** The MCP gateway tracks `jti` to prevent
  replay; the harness mints one PASETO per `run_dataset` call so
  consecutive calls within one process need fresh tokens. For batch
  runs, mint per-case.
- **No subskill dispatch.** The harness loops the orchestrator's
  system prompt; the agent decides which tools to call based on the
  prompt + the tool surface. Subskill files (`gather-customer-profile`,
  `analyze-transactions`, etc.) are loaded by Cowork in production —
  the harness gives the agent access to the union of their tool
  surfaces via the dataset's `expected_tool_calls`.
- **No safety filters beyond RBAC.** The MCP gateway's RBAC check is
  the perimeter; the verifier meta-skill (US-021) is the cross-cutting
  safety net. The harness does not re-implement either.

## Wiring the audit log

The runner filters audit rows by `(sub, trace_id)`. For in-process
tests, install a fresh in-memory SQLite backend before each run:

```python
from gateways.common import audit as audit_mod
from gateways.common.audit import SQLiteAuditBackend

audit_mod.set_backend(SQLiteAuditBackend(":memory:"))
try:
    result = run_dataset(...)
finally:
    audit_mod.reset_default_backend()
```

Production deployments default to the file-backed audit DB at
`/app/audit/audit.db`. Set `AUDIT_BACKEND=clickhouse` to point at
ClickHouse (requires the `clickhouse` optional dep).

## Scoring the result

The harness's `HarnessResult.audit_rows` is the shape the US-027
scorers expect:

```python
from evals.scorers import score_tool_correctness, score_tool_ordering

result = run_dataset(dataset, ...)

correctness = score_tool_correctness(dataset, result.audit_rows)
ordering = score_tool_ordering(dataset, result.audit_rows)
```

The US-028 LLM-judge scorers (`score_grounding`, `score_reasoning`)
take `result.report` + `result.audit_rows` plus a `Judge` (production
or stub). The eval runner (US-030) will compose all four into a
scorecard.

## Smoke test

`tests/test_harness.py::test_harness_drives_clean_customer_smoke`
spins up the full in-process gateway → server → mock chain with a
scripted `StubAgent` and asserts:

- All three `customer_data` tools were invoked.
- Every invocation was `status="ok"` in the audit log.
- The `trace_id` filter pulls back exactly the three rows.
- `HarnessResult.report.verdict == "low_risk"` (the dataset's
  `expected_verdict`).

This is the load-bearing US-029 acceptance: the harness drives the
orchestrator skill against the mock stack and produces a trace
consumable by the scorers from US-027 / US-028.
