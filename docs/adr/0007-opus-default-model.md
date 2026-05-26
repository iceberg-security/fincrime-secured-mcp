# ADR 0007 — Claude Opus 4.7 as the default model for harness + judges

- **Status**: Accepted
- **Date**: 2026-05-26
- **Story**: US-033 (decision originally referenced in US-028 /
  US-029, codified here as the project-wide default)

## Context

Two production code paths in this repo call an LLM:

1. **Eval harness** (`evals/harness/agent.py::AnthropicAgent`,
   [US-029](../../prd.json)). Drives the orchestrator skill against
   the federated mock stack inside `make evals` and the nightly CI
   job.
2. **LLM-judge scorers** (`evals/scorers/judge.py::AnthropicJudge`,
   [US-028](../../prd.json)). Score grounding and reasoning quality
   of investigator reports against the rubric.

Both modules expose a `DEFAULT_MODEL` constant that the rest of the
codebase imports. Picking the constant pin is the decision this ADR
records.

The candidates were the three published Claude 4.x model IDs:

- `claude-haiku-4-5` — cheapest, fastest, smallest.
- `claude-sonnet-4-6` — mid-tier; the previous-generation default.
- `claude-opus-4-7` — most capable; the model intended for complex
  reasoning, ambiguous text-grounding, and multi-step planning.

The relevant decision drivers:

- **Reasoning quality.** The harness has to interleave six MCP-server
  tool surfaces, follow the orchestrator skill's six XML sections,
  pick the right subskill, format arguments correctly, and
  synthesize a draft-narrative artifact. Tool-use orchestration of
  this depth distinguishes Opus from Sonnet — we observed Sonnet
  occasionally skipping the verifier step or fabricating a
  `recommended_action` outside the allowlist on harder personas
  (`sanctions_hit`, `synthetic_id`).
- **Grounding-judge fidelity.** The grounding scorer asks "does this
  audit row justify this claim?" The rubric is short but the
  judgement is subtle (e.g., does a counterparty rollup justify a
  "mule-hub inflow" claim?). Opus's better instruction-following
  reduces the "judge said grounded when it shouldn't have"
  failure mode.
- **Reasoning-judge calibration.** The reasoning scorer scores 1-5
  across four dimensions (relevance, soundness, completeness,
  calibration). Opus's calibration on multi-dimension rubrics held
  closer to the rubric description than Sonnet's in our spot checks.
- **Prompt caching makes Opus cost-tractable.** Both
  `AnthropicAgent` and `AnthropicJudge` set
  `cache_control={'type':'ephemeral'}` on the static system block
  (the SKILL.md for the harness; the rubric for the judges). One eval
  run pays the cache-miss once and amortizes across every
  subsequent step / claim — see
  [`evals/scorers/judge.py`](../../evals/scorers/judge.py) and the
  US-028 / US-029 progress entries for the implementation.
- **Override path is the cheap escape valve.** Both modules accept
  an explicit `model=` argument, and the runner exposes
  `--use-llm` + env-var configuration. Picking Opus as the default
  does not preclude using Sonnet for cost-sensitive nightly runs;
  it just makes the right choice the lazy choice.

## Decision

**`claude-opus-4-7` is the project-wide default model.**

Concretely:

- `evals/harness/agent.py::AnthropicAgent.DEFAULT_MODEL =
  "claude-opus-4-7"`.
- `evals/scorers/judge.py::AnthropicJudge.DEFAULT_MODEL =
  "claude-opus-4-7"`.
- Both classes accept an explicit `model=` keyword, so callers can
  override per call.
- Both classes set `cache_control={'type':'ephemeral'}` on the
  static system block so the rubric / skill bytes are cached for
  the 5-minute TTL.
- The runner (`evals/run.py`) defaults to `OracleAgent` +
  `StubJudge` — Opus is only invoked when `--use-llm` is passed and
  `ANTHROPIC_API_KEY` is set. CI smoke runs do not hit the model;
  nightly full-suite runs do.

## Consequences

**Positive:**

- The "obvious" eval flow uses the strongest model available. Eval
  failures are most likely the agent or the rubric — not the
  model's reasoning capacity.
- Default model choice is a one-line edit in two files when a new
  Claude major lands. Migration path is trivial: change both
  constants, run the full eval suite once to confirm the rubrics
  still calibrate, ship.
- The deterministic `OracleAgent` + `StubJudge` keep CI free. The
  paid model is only on the nightly path.

**Negative:**

- Per-call cost is higher than Sonnet or Haiku. Operators running
  the full suite without prompt caching see this clearly; the cache
  + the override path mitigate but do not eliminate the cost
  delta.
- Opus's pre-cache latency (first call in a run) is higher. The
  cache amortizes; cold first calls in interactive use feel slow.
  Documented in [`docs/agent-testing.md`](../agent-testing.md).
- The default ties us to Anthropic's Claude family. Calling a
  different vendor's model would require a separate `Agent` /
  `Judge` implementation behind the same Protocol — the seam
  exists (see [US-029 ADR](0001-headless-cowork-harness.md) for the
  Protocol shape), but the work is not zero.

**Risk acceptance:**

- A future Claude release may rename or deprecate `claude-opus-4-7`.
  The two constants are the only references; bumping them is a
  contained change. The CLAUDE.md memory note ("most capable Claude
  models") is the operator hint for picking the right default at
  the time of edit.

## Alternatives considered

- **Default to `claude-sonnet-4-6`.** Rejected — observed worse
  harness behavior on the harder personas (specifically
  `sanctions_hit` and `synthetic_id`, which require chained
  reasoning across customer_data → kyc → sanctions → osint). The
  rubric-calibration gap is smaller for the judges but still
  measurable.
- **Default to `claude-haiku-4-5`.** Rejected for both surfaces —
  Haiku is a great cost-optimized choice for narrow tasks but the
  multi-tool orchestration and multi-dimension judgment surfaces
  here are not narrow. Haiku remains a reasonable choice for
  operators who want a "smoke test" eval run; the override path
  supports it.
- **Multi-model: Sonnet for harness, Opus for judges.** Rejected
  for v1 — adds a configuration axis without a clear win. The
  judges only run when the harness produces a report worth judging,
  so a weaker harness model is the binding constraint.
- **Model-agnostic via OpenAI / Vertex.** Rejected for v1 — both
  Protocol seams exist and a contributor could ship an alternate
  implementation, but the default ships against the SDK the rest of
  the codebase imports (`anthropic>=0.40`).

## Cross-links

- [US-028 prd.json entry](../../prd.json) — `AnthropicJudge`
  acceptance criteria (prompt caching on the system block, JSON-
  only replies, rubric calibration).
- [US-029 prd.json entry](../../prd.json) — `AnthropicAgent` and
  the `Agent` Protocol seam.
- [US-030 prd.json entry](../../prd.json) — `--use-llm` flag and
  the OracleAgent / StubJudge defaults for CI.
- [ADR 0001 — Headless Cowork harness](0001-headless-cowork-harness.md) —
  the Protocol pattern that lets us swap the model implementation
  without touching the runner.
- [`docs/agent-testing.md`](../agent-testing.md) — worked
  contributor example for running the LLM path.
