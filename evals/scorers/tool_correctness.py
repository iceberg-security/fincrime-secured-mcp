"""Tool-correctness scorer (US-027).

Compares the set of ``(server, tool)`` pairs the agent actually invoked
(read from the audit log) against the set declared in the dataset's
``expected_tool_calls``.

Rubric (PRD US-027 AC):

- ``missing`` = expected pairs not present in actual.
- ``extra``   = actual pairs not present in expected.
- ``score``   = ``|expected ∩ actual| / |expected ∪ actual|`` (Jaccard).
  By convention an empty expected+actual yields 1.0; an empty expected
  with non-empty actual is treated as a degenerate case the scorer
  rejects (datasets MUST declare at least one expected call — the
  schema in US-025 enforces ``min_length=1``).
- ``passed`` = ``missing`` and ``extra`` are both empty (i.e. score
  == 1.0).

Only ``status='ok'`` rows in the audit log count as an "actual"
invocation. Denied / errored rows mean the agent *attempted* the
tool but never observed a result — counting them would let an agent
satisfy ``expected_tool_calls`` purely by failing every call. The
ordering scorer also filters on ``status='ok'`` for the same reason.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from evals.datasets.schema import EvalDataset
from evals.scorers.types import ScorerResult

__all__ = [
    "SCORER_NAME",
    "score_tool_correctness",
    "extract_actual_pairs",
]

SCORER_NAME = "tool_correctness"


def extract_actual_pairs(
    audit_rows: Iterable[Mapping[str, Any]],
    *,
    only_ok: bool = True,
) -> set[tuple[str, str]]:
    """Pull the set of ``(server, tool)`` pairs out of an audit-log
    iterable. Filters on ``status='ok'`` by default so denied/errored
    attempts don't credit the agent for an invocation it didn't
    actually observe."""
    pairs: set[tuple[str, str]] = set()
    for row in audit_rows:
        if only_ok and row.get("status") != "ok":
            continue
        server = row.get("server")
        tool = row.get("tool")
        if isinstance(server, str) and isinstance(tool, str):
            pairs.add((server, tool))
    return pairs


def score_tool_correctness(
    dataset: EvalDataset,
    audit_rows: Iterable[Mapping[str, Any]],
    *,
    only_ok: bool = True,
) -> ScorerResult:
    """Score the agent's tool-call set against the dataset's
    ``expected_tool_calls``.

    ``audit_rows`` is any iterable of dict-shaped audit events — the
    in-process :func:`gateways.common.audit.query` shape, the rows
    returned by a backend's ``query()``, or test fixtures of the same
    shape. Only the ``server``, ``tool``, and ``status`` keys are
    consulted.
    """
    expected = {tc.as_pair() for tc in dataset.expected_tool_calls}
    actual = extract_actual_pairs(audit_rows, only_ok=only_ok)

    missing = expected - actual
    extra = actual - expected

    union = expected | actual
    score = 1.0 if not union else len(expected & actual) / len(union)
    passed = not missing and not extra

    return ScorerResult(
        name=SCORER_NAME,
        score=score,
        passed=passed,
        details={
            "expected": sorted(expected),
            "actual": sorted(actual),
            "missing": sorted(missing),
            "extra": sorted(extra),
        },
    )
