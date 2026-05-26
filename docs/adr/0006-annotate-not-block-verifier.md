# ADR 0006 — Annotate-not-block verifier meta-skill (v1)

- **Status**: Accepted
- **Date**: 2026-05-26
- **Story**: US-033 (decision originally implemented in US-021)

## Context

The fraud-investigator plugin produces a structured report
(`plugin/skills/draft-narrative`) summarizing an investigation. Every
factual claim in the report must cite the tool call that produced it
([US-020](../../prd.json) AC). The verifier meta-skill
(`plugin/skills/verify-output`, US-021) re-reads the report, queries
the audit log, and cross-checks each claim against a logged tool
result.

The unavoidable question at v1: what should the verifier *do* when it
finds an unsupported claim?

Two options:

1. **Block.** Refuse to surface the report to the analyst until the
   draft-narrative subskill regenerates it without the unsupported
   claim. This is the strict capability-style answer: an unsupported
   factual statement in a compliance artifact is a defect, full stop.
2. **Annotate.** Surface the report alongside a structured list of
   verifier annotations (`unsupported_claim`, `verdict_disagreement`,
   `unknown_recommended_action`, `malformed_report`). The analyst
   sees both the model's draft and the verifier's flags and makes
   the call.

The constraints that drove the decision:

- **LLM-judge false positives.** The verifier is intentionally
  conservative: it matches citations to audit rows by
  `(server, tool)`, NOT by re-executing tool calls or re-hashing
  results (re-executing would be privilege escalation; re-hashing
  would couple to mock-API determinism that is not guaranteed in
  production). A blocking verdict on a citation-mismatch in v1 risks
  rejecting reports that are factually correct but cite the wrong
  field name or have minor wording skew the matcher does not handle.
- **Compliance workflow expectations.** L3 analysts and compliance
  reviewers expect to see what the model said *and* what the system
  flagged. A blocked report is a black box; an annotated report is
  evidence both ways.
- **Audit story.** Either way the verifier's pass produces a logged
  artifact (the annotations are persisted alongside the report). A
  blocking verifier would also have to log "I blocked this report
  because of X" — same audit footprint, less analyst signal.
- **Iteration cadence.** The verifier's heuristics will improve. v2
  may strengthen the citation matcher; v3 may add LLM-judged claim
  scoring. Starting in annotate mode lets us tune the
  false-positive rate from real investigations without analyst-side
  outages every time the verifier gets stricter.

The PRD pins this explicitly at §6.5 ("verifier annotates the report
with unsupported-claim warnings; does NOT block in v1").

## Decision

**The verifier meta-skill annotates. It never blocks.**

Concretely
(`plugin/skills/verify-output/SKILL.md`, [US-021](../../prd.json)):

- The report is returned **verbatim** alongside a list of structured
  annotations. The constraints section says verbatim
  "report `unchanged`/`verbatim`" and "annotate" + "block" — pinned
  by `tests/test_plugin_bundle.py::test_verify_output_constraints_say_annotate_not_block`.
- Annotation kinds (fixed):
  - `unsupported_claim` — a report.evidence entry references a tool
    that has no matching audit row.
  - `tool_call_denied_or_errored` — the audit row exists but its
    status is `denied` or `error`, so it is not a valid citation.
  - `verdict_disagreement` — re-running draft-narrative's verdict
    logic against `report.evidence` produces a different
    `{high_risk, elevated_risk, low_risk, insufficient_evidence}`
    tier.
  - `unknown_recommended_action` — a recommended action falls
    outside the fixed per-tier allowlist.
  - `malformed_report` — the report shape itself does not match
    draft-narrative's `<output_format>`.
- Match strategy: `(server, tool)` only. Never re-execute. Never
  re-hash. The matcher is intentionally claim-shape-agnostic — it
  asks "was there a successful audit row for this server+tool in
  this investigation's trace_id window?"
- The skill is offline (no MCP tools declared). Its only data source
  is the in-process `gateways.common.audit.query(...)` API filtered
  by `trace_id` (preferred) or `sub + since`.
- Runs **last** in the orchestrator flow
  (`plugin/skills/orchestrator/SKILL.md` step 6).

## Consequences

**Positive:**

- The analyst sees both the model's draft and the verifier's flags.
  Compliance decisions remain human-in-the-loop while the audit log
  records both surfaces.
- The verifier can evolve heuristics without forcing analyst-side
  outages on every iteration. v2 stricter matchers ship as new
  annotation kinds; v1 reports remain comparable.
- The verifier has no privileged tool surface — no MCP server
  declared, no write path. The
  `tests/test_plugin_bundle.py::test_verify_output_declared_servers_empty`
  fence pins it.

**Negative:**

- A determined model could produce a report full of unsupported
  claims and the verifier would surface every one of them as
  annotations rather than refuse the report. The human-approval gate
  on `case_actions.*` ([ADR
  0002](0002-paseto-over-jwt.md)) is the true backstop for write-
  path actions: the model's report is evidence, not action.
- "Annotate" implies a downstream UI surfaces the annotations
  prominently. The plugin ships data, not UI; operators integrating
  with a case-management tool must read `verifier_annotations` and
  render them next to the report. This is documented in
  [`docs/threat-model.md`](../threat-model.md) §7 (operator
  responsibilities).
- The verifier's verdict-disagreement check re-runs draft-narrative's
  logic. If draft-narrative's verdict logic drifts, the verifier
  must update in lockstep. Pinned by
  `tests/test_plugin_bundle.py` cross-checks.

**Risk acceptance:**

- v2 may add a `block_on_kind: [...]` configuration knob so
  operators can opt specific annotation kinds into blocking mode.
  v1 ships pure-annotate to establish the false-positive baseline.

## Alternatives considered

- **Blocking verifier v1.** Rejected — see Context. The
  false-positive rate from a citation matcher we have not yet tuned
  is too high to gate analyst output on at launch.
- **Annotate + add to recommended_actions.** Rejected — would let
  the verifier inject `escalate_to_l3` or similar into the
  downstream action surface. The recommended-actions list is a
  draft-narrative responsibility; the verifier's job is to fact-
  check, not to act.
- **Re-execute tool calls to verify report claims.** Rejected — re-
  execution is privilege escalation. The verifier would have to
  mint its own tokens or reuse the analyst's, both of which create
  audit-trail and replay-cache hazards. The
  `(server, tool)`-match-only rule keeps the verifier observational.
- **LLM-judge the report directly with the audit log as context.**
  Rejected for v1 — adds an LLM dependency to a meta-skill that
  must be cheap and deterministic to run on every investigation.
  The LLM judges in [US-028](../../prd.json) live in the
  evals/scorers/ layer, not in the production verifier.

## Cross-links

- [US-020 prd.json entry](../../prd.json) — `draft-narrative`
  artifact shape and "every factual claim must cite the tool call"
  rule.
- [US-021 prd.json entry](../../prd.json) — verifier acceptance
  criteria (annotate, not block).
- `plugin/skills/verify-output/SKILL.md` — implementation.
- `gateways/common/audit.py::query(...)` — the only data source
  the verifier consumes.
- [`docs/threat-model.md`](../threat-model.md) §4.1 — prompt-
  injection threat + the verifier's role as the cross-cutting
  fact-check.
- [ADR 0002 — PASETO over JWT](0002-paseto-over-jwt.md) — the
  `human_approval` claim that gates write-path actions
  independently of the verifier.
