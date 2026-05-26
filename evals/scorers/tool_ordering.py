"""Tool-ordering scorer (US-027).

Checks every ``ordering_constraints[].(before, after)`` pair in the
dataset against the audit log's timestamps. A constraint
``screen_sanctions before create_sar_draft`` is satisfied if the
*earliest* ``screen_sanctions`` audit row sorts before the *earliest*
``create_sar_draft`` row.

Rubric (PRD US-027 AC):

- Constraints with both endpoints absent are recorded as
  ``unobserved`` and do NOT pass the gate (the agent didn't exercise
  the dependency at all).
- Constraints with one endpoint absent are recorded as
  ``unobserved_one_side`` and do NOT pass — the dependency wasn't
  fully exercised.
- ``score`` = ``satisfied / total`` (or 1.0 when the dataset
  declares no constraints).
- ``passed`` = every constraint satisfied (score == 1.0).

Only ``status='ok'`` audit rows count, matching :mod:`tool_correctness`.

Audit rows are sorted by their ISO-8601 ``ts`` string. The PRD pins
``ts`` to ISO-8601 UTC (``audit.py`` enforces this on every insert)
so lexical ordering equals chronological ordering.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from evals.datasets.schema import EvalDataset
from evals.scorers.types import ScorerResult

__all__ = [
    "SCORER_NAME",
    "score_tool_ordering",
]

SCORER_NAME = "tool_ordering"


def _earliest_ts_by_pair(
    audit_rows: Iterable[Mapping[str, Any]],
    *,
    only_ok: bool = True,
) -> dict[tuple[str, str], str]:
    """Return the earliest ``ts`` per ``(server, tool)`` pair. Filters
    on ``status='ok'`` by default."""
    earliest: dict[tuple[str, str], str] = {}
    for row in audit_rows:
        if only_ok and row.get("status") != "ok":
            continue
        server = row.get("server")
        tool = row.get("tool")
        ts = row.get("ts")
        if not (isinstance(server, str) and isinstance(tool, str) and isinstance(ts, str)):
            continue
        key = (server, tool)
        prior = earliest.get(key)
        if prior is None or ts < prior:
            earliest[key] = ts
    return earliest


def score_tool_ordering(
    dataset: EvalDataset,
    audit_rows: Iterable[Mapping[str, Any]],
    *,
    only_ok: bool = True,
) -> ScorerResult:
    """Score the agent's audit log against the dataset's
    ``ordering_constraints``."""
    constraints = dataset.ordering_constraints
    earliest = _earliest_ts_by_pair(audit_rows, only_ok=only_ok)

    satisfied: list[dict[str, Any]] = []
    violated: list[dict[str, Any]] = []
    unobserved: list[dict[str, Any]] = []

    for oc in constraints:
        before_pair = oc.before.as_pair()
        after_pair = oc.after.as_pair()
        before_ts = earliest.get(before_pair)
        after_ts = earliest.get(after_pair)

        entry: dict[str, Any] = {
            "before": before_pair,
            "after": after_pair,
            "before_ts": before_ts,
            "after_ts": after_ts,
        }

        if before_ts is None and after_ts is None:
            entry["reason"] = "unobserved"
            unobserved.append(entry)
        elif before_ts is None or after_ts is None:
            entry["reason"] = "unobserved_one_side"
            unobserved.append(entry)
        elif before_ts < after_ts:
            satisfied.append(entry)
        else:
            entry["reason"] = "before_at_or_after_after"
            violated.append(entry)

    total = len(constraints)
    score = 1.0 if total == 0 else len(satisfied) / total
    passed = not violated and not unobserved

    return ScorerResult(
        name=SCORER_NAME,
        score=score,
        passed=passed,
        details={
            "total": total,
            "satisfied": satisfied,
            "violated": violated,
            "unobserved": unobserved,
        },
    )
