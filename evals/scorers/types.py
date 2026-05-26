"""Shared types for the eval scorers (US-027 / US-028).

Every scorer returns a :class:`ScorerResult` so the eval runner (US-030)
can aggregate scores across dimensions uniformly.

The PRD pins the contract: ``score`` is a float in ``[0.0, 1.0]``,
``passed`` is a boolean (the runner uses it for the scorecard
pass/fail column), and ``details`` is a free-form dict the scorer
populates with the evidence the operator needs to debug a failure
(missing tools, ordering violations, ungrounded claims, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = ["ScorerResult"]


@dataclass(frozen=True, slots=True)
class ScorerResult:
    """The uniform return value of every eval scorer.

    Parameters
    ----------
    name:
        Short scorer identifier (e.g. ``"tool_correctness"``).
    score:
        Quality on ``[0.0, 1.0]``. Each scorer defines its own
        rubric; see the module docstring of the producing scorer.
    passed:
        Whether the case passes this scorer's gate. By convention
        ``passed`` is ``score == 1.0`` but a scorer MAY publish a
        looser threshold (e.g. LLM-judge scorers in US-028).
    details:
        Free-form per-scorer payload — missing tools, ordering
        violations, ungrounded claims, etc.
    """

    name: str
    score: float
    passed: bool
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(
                f"score must be in [0.0, 1.0]; got {self.score!r}"
            )
        if not self.name:
            raise ValueError("name must be non-empty")
