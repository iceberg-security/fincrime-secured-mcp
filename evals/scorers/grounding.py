"""Grounding scorer (US-028).

Parses the draft-narrative report's ``evidence`` list and uses an LLM
judge to decide whether each factual claim is backed by a tool result
in the audit log. A claim with no supporting tool result is *flagged*
as ungrounded.

Rubric (PRD US-028 AC):

- For each claim in ``report.evidence``, locate audit rows whose
  ``(server, tool)`` matches ``citation.{subskill→server?, tool}``.
  The draft-narrative SKILL.md pins citations to the upstream tool;
  the matching is server-and-tool, not subskill-level.
- Build an LLM prompt that pairs the claim+value with the matching
  audit rows' args_preview / result_hash and asks Opus to decide
  whether the claim is *grounded*, *partial*, or *ungrounded*.
- ``score`` = grounded_count / total_claims (or 1.0 when there are
  zero claims — degenerate but valid for the
  ``insufficient_evidence`` verdict tier).
- ``passed`` = every claim grounded.

When the report has zero claims, the scorer returns ``score=1.0``
and ``passed=True`` — the verifier (US-021) handles the case where
the verdict requires evidence but the evidence list is empty; the
grounding scorer is purely about claim-to-tool linkage.

Only ``status='ok'`` audit rows count as supporting evidence, for
the same reason the US-027 scorers ignore denied / errored rows: a
denied call produced no observable result the report could ground a
claim against.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any

from evals.scorers.judge import Judge, JudgeResponse
from evals.scorers.types import ScorerResult

__all__ = [
    "GROUNDING_PROMPT",
    "SCORER_NAME",
    "score_grounding",
]

SCORER_NAME = "grounding"

# The judge's static rubric. Goes in the ``system`` channel so the
# Anthropic prompt cache holds it for the 5-minute TTL — every claim in
# a single eval run hits the cache, slashing token cost on busy
# datasets like mule_account (8 claims) and account_takeover (7).
GROUNDING_PROMPT = """\
You are a strict grounding judge for a fraud-investigation copilot.

You receive ONE factual claim from an investigation report and the
audit-log rows for the tool calls the agent actually made. Decide
whether the claim is grounded in the tool results.

Definitions:

- "grounded"   — the claim's value or substance can be traced back to
                 at least one audit row's args_preview / result_hash /
                 latency_ms, AND the audit row's (server, tool) matches
                 the claim's citation, AND at least one matching row
                 has status="ok".
- "partial"    — the citation matches a tool call but the audit row's
                 args_preview does not unambiguously support the claim
                 (e.g. citation points at the right tool but the value
                 isn't visible in args_preview).
- "ungrounded" — no audit row with status="ok" matches the citation,
                 or matching rows exist but their args_preview /
                 result_hash contradict the claim's value.

You MUST reply with a single JSON object and NOTHING else. Schema:

{
  "verdict": "grounded" | "partial" | "ungrounded",
  "reason": <short human-readable string, max 200 chars>
}

Do not include any prose outside the JSON object. Do not include
markdown fences. The JSON object MUST parse with a strict JSON parser.
"""


def _build_user_prompt(
    claim: Mapping[str, Any],
    matching_rows: list[Mapping[str, Any]],
) -> str:
    """Pair one claim with its matching audit rows, serialized to JSON
    for the judge."""
    return json.dumps(
        {
            "claim": claim.get("claim"),
            "value": claim.get("value"),
            "citation": claim.get("citation"),
            "matching_audit_rows": [
                {
                    "ts": row.get("ts"),
                    "server": row.get("server"),
                    "tool": row.get("tool"),
                    "status": row.get("status"),
                    "args_preview": row.get("args_preview"),
                    "result_hash": row.get("result_hash"),
                    "latency_ms": row.get("latency_ms"),
                }
                for row in matching_rows
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def _match_rows(
    citation: Mapping[str, Any] | None,
    audit_rows: Iterable[Mapping[str, Any]],
    *,
    only_ok: bool,
) -> list[Mapping[str, Any]]:
    """Find audit rows whose (server, tool) matches the citation.

    The draft-narrative citation shape is
    ``{subskill, tool, field}``. The ``subskill`` is the plugin-side
    surface (``analyze-transactions``, ``gather-customer-profile``,
    ...); the audit log carries the MCP-server name
    (``transactions``, ``customer_data``, ...). We match by **tool
    name only** when the citation lacks a server hint — the tool
    names in ALLOWED_TOOLS are unique across servers (no two MCP
    servers expose a tool with the same name), so this matching is
    unambiguous.
    """
    if not isinstance(citation, Mapping):
        return []
    tool = citation.get("tool")
    if not isinstance(tool, str) or not tool:
        return []
    cited_server = citation.get("server")
    matches: list[Mapping[str, Any]] = []
    for row in audit_rows:
        if only_ok and row.get("status") != "ok":
            continue
        if row.get("tool") != tool:
            continue
        if (
            isinstance(cited_server, str)
            and cited_server
            and row.get("server") != cited_server
        ):
            continue
        matches.append(row)
    return matches


def _parse_judge_verdict(resp: JudgeResponse) -> tuple[str, str]:
    """Parse the judge's reply. Returns ``(verdict, reason)``. On any
    parse failure the verdict is ``"ungrounded"`` with the parse error
    as the reason — fail closed."""
    text = (resp.text or "").strip()
    if not text:
        return ("ungrounded", "judge returned empty response")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return ("ungrounded", f"judge response not JSON ({exc.msg})")
    if not isinstance(parsed, dict):
        return ("ungrounded", "judge response not an object")
    verdict = parsed.get("verdict")
    reason = parsed.get("reason", "")
    if verdict not in {"grounded", "partial", "ungrounded"}:
        return ("ungrounded", f"judge returned invalid verdict {verdict!r}")
    return (str(verdict), str(reason)[:200])


def score_grounding(
    report: Mapping[str, Any],
    audit_rows: Iterable[Mapping[str, Any]],
    *,
    judge: Judge,
    only_ok: bool = True,
) -> ScorerResult:
    """Score the report's evidence list for grounding against the audit
    log.

    Parameters
    ----------
    report:
        The draft-narrative output (US-020). Required key:
        ``evidence`` (list of ``{claim, value, citation}``).
    audit_rows:
        Iterable of audit log rows (the
        :func:`gateways.common.audit.query` shape).
    judge:
        Any :class:`evals.scorers.judge.Judge`. Tests inject a fake.
    only_ok:
        When ``True`` (default), only ``status='ok'`` audit rows are
        considered as supporting evidence.
    """
    rows = list(audit_rows)  # We iterate it once per claim.
    evidence = report.get("evidence", [])
    if not isinstance(evidence, list):
        return ScorerResult(
            name=SCORER_NAME,
            score=0.0,
            passed=False,
            details={
                "error": "report.evidence is not a list",
                "type": type(evidence).__name__,
            },
        )

    if not evidence:
        # Degenerate but valid: no claims to ground. The verifier
        # (US-021) flags reports that should have evidence; the
        # grounding scorer is purely about claim-to-tool linkage.
        return ScorerResult(
            name=SCORER_NAME,
            score=1.0,
            passed=True,
            details={"total": 0, "grounded": [], "partial": [], "ungrounded": []},
        )

    grounded: list[dict[str, Any]] = []
    partial: list[dict[str, Any]] = []
    ungrounded: list[dict[str, Any]] = []

    for idx, entry in enumerate(evidence):
        if not isinstance(entry, Mapping):
            ungrounded.append(
                {
                    "claim_index": idx,
                    "reason": "evidence entry is not an object",
                }
            )
            continue
        citation = entry.get("citation")
        matches = _match_rows(citation, rows, only_ok=only_ok)
        if not matches:
            # No matching audit row at all -> ungrounded without
            # asking the judge (saves a token round-trip).
            ungrounded.append(
                {
                    "claim_index": idx,
                    "claim": entry.get("claim"),
                    "citation": citation,
                    "reason": "no_audit_row_matches_citation",
                }
            )
            continue

        user_prompt = _build_user_prompt(entry, matches)
        resp = judge(system=GROUNDING_PROMPT, user=user_prompt)
        verdict, reason = _parse_judge_verdict(resp)
        record = {
            "claim_index": idx,
            "claim": entry.get("claim"),
            "citation": citation,
            "verdict": verdict,
            "reason": reason,
        }
        if verdict == "grounded":
            grounded.append(record)
        elif verdict == "partial":
            partial.append(record)
        else:
            ungrounded.append(record)

    total = len(evidence)
    # Partial = half credit. PRD doesn't pin the exact arithmetic, so
    # we use the rubric the draft-narrative skill encodes: a partial
    # claim is "evidence exists but is weak" — not a pass, not a full
    # fail. The scorer is deterministic given the judge's verdicts.
    score = (len(grounded) + 0.5 * len(partial)) / total
    passed = not ungrounded and not partial

    return ScorerResult(
        name=SCORER_NAME,
        score=score,
        passed=passed,
        details={
            "total": total,
            "grounded": grounded,
            "partial": partial,
            "ungrounded": ungrounded,
        },
    )
