# evals/

Eval-driven development harness for the fraud-investigator plugin. The
eval suite lives outside both the plugin and the runtime gateways so it
can drive the orchestrator from the outside (US-029) and score the
resulting tool-call trace + report (US-027/US-028) without touching the
production code paths.

## Layout

| Path                          | Purpose                                                                                   |
| ----------------------------- | ----------------------------------------------------------------------------------------- |
| `datasets/schema.py`          | Pydantic v2 schema for `*.yaml` cases (US-025). Source of truth for case validation.      |
| `datasets/<case>.yaml`        | One eval case per file. Declarative — no Python.                                          |
| `scorers/`                    | Per-dimension scorers (tool-correctness, ordering, grounding, reasoning — US-027/US-028). |
| `scorers/types.py`            | `ScorerResult` dataclass — the uniform return type every scorer produces (US-027).        |
| `scorers/tool_correctness.py` | Set comparison of expected vs actual `(server, tool)` pairs from the audit log (US-027).  |
| `scorers/tool_ordering.py`    | Audit-log timestamp check for `ordering_constraints[]` (US-027).                          |
| `scorers/grounding.py`        | LLM-judge: every claim in the report MUST trace to an audit row (US-028).                 |
| `scorers/reasoning.py`        | LLM-judge: 1-5 rubric across relevance/soundness/completeness/calibration (US-028).       |
| `scorers/judge.py`            | `Judge` Protocol + production `AnthropicJudge` with prompt caching on the rubric (US-028).|
| `harness/`                    | Headless harness that drives the orchestrator skill against the mock stack (US-029).      |
| `harness/agent.py`            | `Agent` Protocol + production `AnthropicAgent` (prompt-cached system) + `StubAgent` test fake. |
| `harness/runner.py`           | `run_dataset(...)` — the loop. Returns `HarnessResult` (audit trace + report) for scorers. |
| `validate.py`                 | `python -m evals.validate` — lints every dataset against the schema. Wired by Makefile.   |
| `run.py`                      | `python -m evals.run [--smoke]` — full suite orchestrator + CI gate (US-030).             |

## Dataset schema (US-025)

Every YAML under `datasets/` MUST have exactly these top-level keys:

- `id` (kebab/snake-case): filename stem, used by the runner as the case
  identifier in the scorecard.
- `description`: human prose.
- `scenario`: one of `clean | mule | sanctions_hit | ato | structuring |
  synthetic_id` — the same six personas the mocks bake into deterministic
  data and that `scripts/load_fixtures.py` exercises. KEEP IN SYNC: this
  literal is mirrored from `mock_apis/customer_data/main.py::Scenario`.
- `input_alert`: the alert payload the orchestrator receives. Mirrors
  `plugin/skills/orchestrator/SKILL.md`'s `<inputs>` block.
- `expected_tool_calls`: set of `{server, tool}` pairs the agent MUST
  invoke. The tool-correctness scorer (US-027) does set-diff against the
  audit log.
- `ordering_constraints`: list of `{before, after}` pairs naming tool
  calls that MUST appear in that order. The tool-ordering scorer
  (US-027) checks the audit-log timestamps.
- `expected_verdict`: one of the four draft-narrative verdicts —
  `high_risk | elevated_risk | low_risk | insufficient_evidence`. Mirrored
  from `plugin/skills/draft-narrative/SKILL.md`.
- `required_facts`: list of `{claim, supporting_tool}` pairs. The
  grounding scorer (US-028) treats each claim as ungrounded unless its
  supporting tool produced an audit row.

The schema's `ALLOWED_TOOLS` table is the bridge between the declarative
dataset YAMLs and the live MCP-server contracts. If you add a new tool
to an MCP server, you MUST add it here too — otherwise a dataset that
references it will fail validation. The table is currently 6 servers x 3
tools = 18 entries; the `test_allowed_tools_covers_every_mcp_server`
test pins both the server set and the per-server count.

## Adding a new dataset

1. Create `datasets/<id>.yaml` with all top-level keys filled in.
2. Run `make validate-evals` — should print `OK` and list your case.
3. If your case fans out to a server not yet seeded by
   `scripts/load_fixtures.py`, the harness will surface the gap when the
   federated read path is exercised. Either extend `load_fixtures.py` or
   pin the gap in `required_facts` with a `tool_failed` expectation.

## Why YAML, not Python

The PRD (US-025 AC) requires datasets be declarative so detection
engineers can add a new fraud pattern without writing Python. The schema
is opinionated on purpose:

- Unknown server names are rejected (`unknown MCP server`).
- Unknown tool names on a known server are rejected (`unknown tool`).
- Each `required_facts[].supporting_tool` MUST appear in
  `expected_tool_calls` (transitive closure: facts come from tools we
  expect to call).
- Each `ordering_constraints[].before/.after` MUST appear in
  `expected_tool_calls`.
- Duplicate `expected_tool_calls` entries are rejected.
- `extra="forbid"` on every Pydantic model — typos fail loudly.

## Scorers (US-027)

Every scorer returns a `ScorerResult` (immutable dataclass) with:

- `name: str` — short identifier (e.g. `"tool_correctness"`).
- `score: float` — on `[0.0, 1.0]`, validated at construction. Each
  scorer documents its own rubric; the constructor raises
  `ValueError` if you pass anything outside that range.
- `passed: bool` — whether the case passes this dimension's gate.
- `details: dict[str, Any]` — free-form scorer-specific payload.

Both shipped scorers only count `status='ok'` audit rows by default
(via the `only_ok=` keyword). Denied or errored attempts mean the
agent tried but did not observe a result; counting them would let
the agent satisfy `expected_tool_calls` purely by failing every
call. Pass `only_ok=False` if you need a looser scorer (e.g. for
the runner to surface denied calls separately).

The ordering scorer reads `ts` as an ISO-8601 string — `audit.py`
enforces ISO-8601 UTC on every insert, so lexical ordering equals
chronological ordering. If you change the audit log's `ts` format,
the ordering scorer will silently break — pin the format in
`gateways/common/audit.py` instead.

## LLM-judge scorers (US-028)

`scorers/grounding.py` and `scorers/reasoning.py` use an LLM judge
via the `Judge` Protocol in `scorers/judge.py`:

- **Production**: `AnthropicJudge` calls the Anthropic Messages API
  with the rubric in the `system` channel + `cache_control:
  ephemeral`. The static rubric is then cached for 5 minutes; every
  subsequent claim/report in the same eval run hits the cache.
- **Tests**: inject a fake `Judge` (any callable with
  `__call__(*, system, user) -> JudgeResponse`). The Protocol is
  `runtime_checkable`, so `isinstance(stub, Judge)` works.

Why a Protocol and not a direct SDK import:

1. The PRD pins LLM-judge scorers as a CI gate (US-030). Coupling
   each scorer to `anthropic.Anthropic` would force every test to
   set `ANTHROPIC_API_KEY` or skip.
2. Future judges (a local model for offline runs, a cached-result
   replayer) drop in by satisfying the same Protocol.

The grounding scorer matches each evidence entry's citation against
the audit log by `(server, tool)` ONLY when the citation declares a
server hint; tool-name-only match is the fallback because the
`ALLOWED_TOOLS` table guarantees tool names are unique across MCP
servers (no two servers expose a tool with the same name). If you
add a tool to two servers, fix the grounding scorer's `_match_rows`
helper too.

The reasoning scorer's passing threshold is `mean_score >= 4.0`
across the four dimensions (relevance / soundness / completeness /
calibration). The PRD AC says "high-quality reasoning scored >=4".
`PASSING_OVERALL_SCORE` is exported so the runner can surface the
threshold in the scorecard.

Both scorers **fail closed** on judge-side malformations: empty
text, non-JSON replies, invalid verdicts, missing dimensions, and
out-of-range scores all produce `passed=False` with the reason in
`details`. The judge MUST reply with strict JSON (no markdown
fences) — the prompts pin this in `system` and tests pin the prompt
wording.

The `anthropic` SDK is an OPTIONAL dependency
(`pip install fraud-copilot-oss[evals]`). Production callers
construct `AnthropicJudge()` directly; the import is lazy so the
SDK absence doesn't break test collection.

## Headless harness (US-029)

`evals/harness/` is the **non-Cowork** runner that drives the
orchestrator skill against the mock stack. See
[`docs/adr/0001-headless-cowork-harness.md`](../docs/adr/0001-headless-cowork-harness.md)
for the decision and [`docs/agent-testing.md`](../docs/agent-testing.md)
for the worked example.

Key contracts:

- **`Agent` Protocol** mirrors the `Judge` Protocol from US-028. Any
  callable with the signature `agent(*, skill_md, alert, tools,
  tool_results) -> ToolCall | FinalAnswer` is a valid Agent. Production
  uses `AnthropicAgent`; tests use `StubAgent`. One pattern, two
  implementations.
- **Tool name encoding** is `<server>__<tool>` (double underscore).
  The runner splits the name back into `(server, tool)` before
  posting to the MCP gateway. Don't change the separator without
  updating `_split_tool_name` in `harness/runner.py`.
- **Tool definitions** wrap the actual MCP arguments inside an
  `{"arguments": <obj>}` envelope so the Anthropic tool-use input
  schema can carry an arbitrary args object. The runner unwraps the
  envelope before posting to the gateway — DON'T forget the unwrap
  if you handcraft tool calls.
- **`paseto_factory` instead of `paseto`**: the MCP gateway tracks
  `jti` to prevent replay, so every tool call needs a fresh token.
  `run_dataset(...)` takes a zero-arg callable that returns a new
  PASETO; production wires this to the mock OIDC -> auth gateway flow,
  tests wrap a closure over `mint(...)`.
- **`trace_id` filter**: the harness filters the audit log by
  `(sub, trace_id)` so multiple harness runs in one process produce
  hermetic per-run result objects. The trace_id is the user-token
  claim; the gateway propagates it into the service-to-service mint
  and the audit row.
- **`HarnessResult.audit_rows`** is the shape the US-027 scorers
  expect — no transformation needed.
- The synthetic `final_answer` tool terminates the loop with the
  draft-narrative report payload. Constant lives at
  `evals.harness.DEFAULT_FINAL_ANSWER_TOOL`.

## Eval runner (US-030)

`evals/run.py` is the top-level CI gate. It loads the declarative
datasets, stands up an in-process federated mock stack (every
read-only MCP server + the gateway, all wired through ASGI transport
into one `TestClient`), drives each dataset through the harness, and
scores the resulting audit log + report on all four dimensions.

CLI:

- `python -m evals.run` — full suite (6 datasets).
- `python -m evals.run --smoke` — clean_customer + mule_account.
- `python -m evals.run --datasets <id> [<id> ...]` — explicit subset.
- `python -m evals.run --output evals-scorecard.json` — write JSON.

Exit code is `0` iff every case passes every dimension; `1` on any
dataset selection error or any case failure.

Two agent implementations:

- **`OracleAgent`** (default): scripts exactly the
  `expected_tool_calls` from the dataset, then a synthetic
  `FinalAnswer`. Deterministic, free, CI-friendly. The scorers still
  verify the audit log against the dataset's contract — drift between
  the script and the live stack surfaces as denied / errored rows.
- **`AnthropicAgent`** (when `ANTHROPIC_API_KEY` + `--use-llm`):
  drives the orchestrator skill through real Claude calls.
  Nightly only.

Two judge implementations:

- **`StubJudge`** (default): deterministic grounding/reasoning
  verdicts derived from the audit-row shape (`status='ok'` → grounded
  + reasoning 4-of-5; non-ok rows → ungrounded + reasoning 2-of-5).
  The CI gate.
- **`AnthropicJudge`** (US-028 production class): real Opus calls.
  Nightly only.

Per-tool argument shapes the OracleAgent ships (anything outside
`{customer_id, scenario}`):

| Tool                          | Arguments shape                                                              |
| ----------------------------- | ---------------------------------------------------------------------------- |
| `sanctions.screen_name`       | `{name, scenario}` (no `customer_id`)                                        |
| `sanctions.screen_entity`     | `{entity_name, scenario}`                                                    |
| `sanctions.get_watchlist_hit` | `{hit_id}` — only `sanctions_hit` scenario produces a 200; others 404 OK     |
| `osint.web_search`            | `{query, scenario}`                                                          |
| `osint.fetch_page`            | `{url, scenario}` — url is `https://compliance.example/<customer_id>`        |
| `osint.lookup_company`        | `{company_name, scenario}`                                                   |
| `kyc.get_document`            | `{customer_id, document_id, scenario}` — id is `doc_<customer_id>_id`         |

When adding a new MCP server tool with non-standard arguments, update
`OracleAgent._args_for(...)` in lockstep or any dataset referencing it
will surface drift on the tool_correctness scorer.

CI workflows:

- `.github/workflows/evals.yml` — runs on every PR + push to main.
  Validates schemas + runs the smoke subset. Artifact uploaded
  regardless of success/failure (14-day retention).
- `.github/workflows/evals-nightly.yml` — runs at 07:15 UTC daily.
  Validates schemas + runs the FULL suite. Artifact retained 90 days.

The smoke set is intentionally minimal so PRs don't pay a steep CI
tax; the nightly run catches drift on the four scenario-rich cases
(account_takeover, sanctions_hit, structuring, synthetic_id) that
exercise the full read-only fan-out.

## Write-path datasets (case_actions)

Datasets that exercise the write-path tools (`case_actions.*`) are
intentionally out of scope for the initial set. The `case_actions` MCP
server requires `human_approval=true` on the PASETO (US-016); the
load-fixtures script and the harness mint regular (non-approved) PASETOs.
When write-path evals land, they will need their own approval-bearing
PASETO mint path; this is a deliberate design choice, not an oversight.

## Pitfalls

- **The four-server `ALLOWED_TOOLS` table is hand-maintained.** It does
  not (yet) introspect the FastMCP tool registry. If you add a tool to a
  server's `main.py`, add it to `evals/datasets/schema.py` in the same
  PR or schema validation will reject any dataset that references it.
- **The `id` regex is `^[a-z][a-z0-9_]*$`** — kebab-case is NOT allowed
  (the hyphen makes it ambiguous with subskill ids). Use `snake_case`.
- **Don't add new top-level keys to the schema without updating the
  `extra="forbid"` test.** The schema is the contract — adding a key
  silently turns into "extra field accepted" if the test isn't updated.
- **Pydantic v2's `model_validator(mode="after")`** runs once per
  instance. Cross-field checks (e.g. "every required_fact references an
  expected_tool_call") belong here, not in field validators.
