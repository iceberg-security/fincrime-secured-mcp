"""Reasoning scorer (US-028).

LLM-as-judge scorer that grades the reasoning chain behind the
investigation report on a 1-5 rubric. Inputs are the report's
``summary`` + ``evidence`` + ``verdict`` + ``recommended_actions``
plus the audit log; the judge returns a per-dimension score
(relevance, soundness, completeness, calibration), an overall
score, and a short justification.

Rubric (PRD US-028 AC):

- ``relevance``     — does the reasoning address the alert?
- ``soundness``     — does the verdict follow from the evidence?
- ``completeness``  — are obvious investigation paths covered?
- ``calibration``   — is the verdict's strength matched to the evidence?

Each dimension is scored 1-5; the overall score is the mean. The
:class:`ScorerResult`'s ``score`` is normalized to ``[0, 1]`` by
``(mean - 1) / 4`` so a perfect 5/5 maps to 1.0 and the minimum 1/5
maps to 0.0. ``passed`` is ``True`` when the overall score is
``>= 4.0`` (the AC's "high-quality reasoning scored >=4").

Only ``status='ok'`` audit rows are surfaced to the judge by default —
denied / errored attempts pollute the judge's view of what evidence
the agent actually observed.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any

from evals.scorers.judge import Judge, JudgeResponse
from evals.scorers.types import ScorerResult

__all__ = [
    "DIMENSIONS",
    "PASSING_OVERALL_SCORE",
    "REASONING_PROMPT",
    "SCORER_NAME",
    "score_reasoning",
]

SCORER_NAME = "reasoning"
PASSING_OVERALL_SCORE = 4.0
DIMENSIONS: tuple[str, ...] = (
    "relevance",
    "soundness",
    "completeness",
    "calibration",
)

REASONING_PROMPT = """\
You are a strict reasoning judge for a fraud-investigation copilot.

You receive ONE complete investigation report plus the audit log of
tool calls the agent made. Score the reasoning chain on a 1-5 scale
across four dimensions:

- relevance     (1-5) — does the reasoning address the input alert,
                        or wander off into unrelated checks?
- soundness     (1-5) — does the verdict follow from the cited
                        evidence under the rubric in the report?
- completeness  (1-5) — are obvious investigation paths covered
                        (e.g. high-value alert with no transaction
                        review = incomplete)?
- calibration   (1-5) — is the verdict's strength matched to the
                        evidence? high_risk with only one weak signal
                        is over-confident; low_risk when sanctions
                        hit is under-confident.

Scoring guide:

- 5 — exemplary; the reasoning is tight, every claim is sourced,
      the verdict is well-calibrated to the strongest evidence.
- 4 — solid; minor weakness but no fundamental flaw.
- 3 — uneven; meaningful gaps OR one calibration error.
- 2 — weak; multiple gaps or a substantive miscalibration.
- 1 — broken; verdict contradicts the evidence, or the reasoning
      chain is missing entirely.

You MUST reply with a single JSON object and NOTHING else. Schema:

{
  "relevance":    {"score": 1|2|3|4|5, "reason": <string max 240>},
  "soundness":    {"score": 1|2|3|4|5, "reason": <string max 240>},
  "completeness": {"score": 1|2|3|4|5, "reason": <string max 240>},
  "calibration":  {"score": 1|2|3|4|5, "reason": <string max 240>},
  "overall_reason": <string max 240>
}

Do not include any prose outside the JSON object. Do not include
markdown fences. The JSON object MUST parse with a strict JSON parser.
"""


def _build_user_prompt(
    report: Mapping[str, Any],
    audit_rows: list[Mapping[str, Any]],
) -> str:
    """Pack the report + audit log into the judge's user prompt."""
    return json.dumps(
        {
            "report": {
                "alert_id": report.get("alert_id"),
                "customer_id": report.get("customer_id"),
                "alert_type": report.get("alert_type"),
                "summary": report.get("summary"),
                "evidence": report.get("evidence"),
                "verdict": report.get("verdict"),
                "recommended_actions": report.get("recommended_actions"),
                "evidence_gaps": report.get("evidence_gaps"),
            },
            "audit_log": [
                {
                    "ts": row.get("ts"),
                    "server": row.get("server"),
                    "tool": row.get("tool"),
                    "status": row.get("status"),
                    "args_preview": row.get("args_preview"),
                    "deny_reason": row.get("deny_reason"),
                    "latency_ms": row.get("latency_ms"),
                }
                for row in audit_rows
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def _parse_judge_scores(
    resp: JudgeResponse,
) -> tuple[dict[str, dict[str, Any]] | None, str]:
    """Parse the judge's reply. Returns ``(per_dimension, overall_reason)``
    or ``(None, error_reason)`` on any failure."""
    text = (resp.text or "").strip()
    if not text:
        return (None, "judge returned empty response")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return (None, f"judge response not JSON ({exc.msg})")
    if not isinstance(parsed, dict):
        return (None, "judge response not an object")
    per_dim: dict[str, dict[str, Any]] = {}
    for dim in DIMENSIONS:
        entry = parsed.get(dim)
        if not isinstance(entry, dict):
            return (None, f"missing or malformed dimension {dim!r}")
        score = entry.get("score")
        if not isinstance(score, int) or not 1 <= score <= 5:
            return (None, f"{dim}.score must be int 1-5; got {score!r}")
        reason = str(entry.get("reason", ""))[:240]
        per_dim[dim] = {"score": score, "reason": reason}
    overall_reason = str(parsed.get("overall_reason", ""))[:240]
    return (per_dim, overall_reason)


def score_reasoning(
    report: Mapping[str, Any],
    audit_rows: Iterable[Mapping[str, Any]],
    *,
    judge: Judge,
    only_ok: bool = True,
) -> ScorerResult:
    """Score the reasoning chain behind the report.

    Parameters
    ----------
    report:
        The draft-narrative output (US-020). Read fields:
        ``summary``, ``evidence``, ``verdict``, ``recommended_actions``,
        ``evidence_gaps``.
    audit_rows:
        Iterable of audit log rows.
    judge:
        Any :class:`evals.scorers.judge.Judge`. Tests inject a fake.
    only_ok:
        When ``True`` (default), only ``status='ok'`` audit rows are
        surfaced to the judge.
    """
    rows = [
        row
        for row in audit_rows
        if (not only_ok) or row.get("status") == "ok"
    ]
    if not isinstance(report.get("evidence"), list):
        return ScorerResult(
            name=SCORER_NAME,
            score=0.0,
            passed=False,
            details={"error": "report.evidence is not a list"},
        )

    user_prompt = _build_user_prompt(report, rows)
    resp = judge(system=REASONING_PROMPT, user=user_prompt)
    per_dim, overall_reason = _parse_judge_scores(resp)
    if per_dim is None:
        return ScorerResult(
            name=SCORER_NAME,
            score=0.0,
            passed=False,
            details={
                "error": "judge_response_parse_failed",
                "reason": overall_reason,
                "raw_text": (resp.text or "")[:1000],
            },
        )

    mean_score = sum(per_dim[d]["score"] for d in DIMENSIONS) / len(DIMENSIONS)
    normalized = max(0.0, min(1.0, (mean_score - 1.0) / 4.0))
    passed = mean_score >= PASSING_OVERALL_SCORE

    return ScorerResult(
        name=SCORER_NAME,
        score=normalized,
        passed=passed,
        details={
            "per_dimension": per_dim,
            "mean_score": mean_score,
            "passing_threshold": PASSING_OVERALL_SCORE,
            "overall_reason": overall_reason,
        },
    )
