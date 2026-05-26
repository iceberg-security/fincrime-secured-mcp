"""Tests for the tool-correctness + tool-ordering scorers (US-027)."""

from __future__ import annotations

from typing import Any

import pytest

from evals.datasets.schema import (
    EvalDataset,
    InputAlert,
    OrderingConstraint,
    RequiredFact,
    ToolCall,
    load_dataset,
)
from evals.scorers import ScorerResult, score_tool_correctness, score_tool_ordering
from evals.scorers.tool_correctness import (
    SCORER_NAME as TC_NAME,
)
from evals.scorers.tool_correctness import (
    extract_actual_pairs,
)
from evals.scorers.tool_ordering import (
    SCORER_NAME as TO_NAME,
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _row(
    server: str,
    tool: str,
    ts: str = "2026-01-01T00:00:00.000000+00:00",
    *,
    status: str = "ok",
    **extra: Any,
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "ts": ts,
        "server": server,
        "tool": tool,
        "status": status,
        "sub": "alice@example.com",
        "role": "analyst",
        "jti": f"jti-{server}-{tool}-{ts}",
        "trace_id": "trace-1",
        "args_preview": {},
        "result_hash": "",
        "deny_reason": None,
        "latency_ms": 1,
    }
    base.update(extra)
    return base


def _dataset(
    *,
    expected_tool_calls: list[dict[str, str]],
    ordering_constraints: list[dict[str, dict[str, str]]] | None = None,
    required_facts: list[dict[str, Any]] | None = None,
) -> EvalDataset:
    """Build a minimal-valid EvalDataset with the given tool surface."""
    if required_facts is None:
        first = expected_tool_calls[0]
        required_facts = [
            {
                "claim": "first call observed",
                "supporting_tool": {"server": first["server"], "tool": first["tool"]},
            }
        ]
    raw: dict[str, Any] = {
        "id": "tmp_case",
        "description": "test",
        "scenario": "clean",
        "input_alert": {
            "alert_id": "alert-1",
            "customer_id": "cust-1",
            "alert_type": "routine_review",
        },
        "expected_tool_calls": expected_tool_calls,
        "ordering_constraints": ordering_constraints or [],
        "expected_verdict": "low_risk",
        "required_facts": required_facts,
    }
    return load_dataset(raw)


# --------------------------------------------------------------------------- #
# ScorerResult invariants
# --------------------------------------------------------------------------- #


class TestScorerResult:
    def test_accepts_valid(self) -> None:
        r = ScorerResult(name="x", score=0.5, passed=False)
        assert r.score == 0.5
        assert r.details == {}

    def test_rejects_score_out_of_range_high(self) -> None:
        with pytest.raises(ValueError, match=r"score must be in"):
            ScorerResult(name="x", score=1.5, passed=True)

    def test_rejects_score_out_of_range_low(self) -> None:
        with pytest.raises(ValueError, match=r"score must be in"):
            ScorerResult(name="x", score=-0.1, passed=False)

    def test_rejects_empty_name(self) -> None:
        with pytest.raises(ValueError, match=r"name must be non-empty"):
            ScorerResult(name="", score=0.0, passed=False)

    def test_is_frozen(self) -> None:
        r = ScorerResult(name="x", score=1.0, passed=True)
        with pytest.raises((AttributeError, TypeError)):  # dataclass frozen
            r.score = 0.0  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# extract_actual_pairs
# --------------------------------------------------------------------------- #


class TestExtractActualPairs:
    def test_picks_ok_rows_only_by_default(self) -> None:
        rows = [
            _row("customer_data", "get_customer", status="ok"),
            _row("customer_data", "list_accounts", status="denied"),
            _row("transactions", "get_transactions", status="error"),
        ]
        pairs = extract_actual_pairs(rows)
        assert pairs == {("customer_data", "get_customer")}

    def test_only_ok_false_includes_failures(self) -> None:
        rows = [
            _row("customer_data", "get_customer", status="ok"),
            _row("transactions", "get_transactions", status="error"),
        ]
        pairs = extract_actual_pairs(rows, only_ok=False)
        assert pairs == {
            ("customer_data", "get_customer"),
            ("transactions", "get_transactions"),
        }

    def test_skips_rows_without_server_or_tool(self) -> None:
        rows: list[dict[str, Any]] = [
            {"ts": "t", "status": "ok"},
            {"ts": "t", "server": "customer_data", "status": "ok"},
            _row("customer_data", "get_customer"),
        ]
        pairs = extract_actual_pairs(rows)
        assert pairs == {("customer_data", "get_customer")}


# --------------------------------------------------------------------------- #
# tool_correctness scorer
# --------------------------------------------------------------------------- #


class TestToolCorrectness:
    def test_exact_match_scores_perfect(self) -> None:
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
                {"server": "customer_data", "tool": "list_accounts"},
            ]
        )
        rows = [
            _row("customer_data", "get_customer"),
            _row("customer_data", "list_accounts"),
        ]
        result = score_tool_correctness(ds, rows)
        assert result.name == TC_NAME
        assert result.score == pytest.approx(1.0)
        assert result.passed is True
        assert result.details["missing"] == []
        assert result.details["extra"] == []

    def test_missing_tool_reported(self) -> None:
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
                {"server": "customer_data", "tool": "list_accounts"},
            ]
        )
        rows = [_row("customer_data", "get_customer")]
        result = score_tool_correctness(ds, rows)
        assert result.passed is False
        assert result.details["missing"] == [("customer_data", "list_accounts")]
        assert result.details["extra"] == []
        # |∩|=1, |∪|=2 -> 0.5
        assert result.score == pytest.approx(0.5)

    def test_extra_tool_reported(self) -> None:
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
            ]
        )
        rows = [
            _row("customer_data", "get_customer"),
            _row("transactions", "get_transactions"),
        ]
        result = score_tool_correctness(ds, rows)
        assert result.passed is False
        assert result.details["missing"] == []
        assert result.details["extra"] == [("transactions", "get_transactions")]
        # |∩|=1, |∪|=2 -> 0.5
        assert result.score == pytest.approx(0.5)

    def test_both_missing_and_extra(self) -> None:
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
                {"server": "customer_data", "tool": "list_accounts"},
            ]
        )
        rows = [
            _row("customer_data", "get_customer"),
            _row("transactions", "get_transactions"),
        ]
        result = score_tool_correctness(ds, rows)
        assert result.passed is False
        assert result.details["missing"] == [("customer_data", "list_accounts")]
        assert result.details["extra"] == [("transactions", "get_transactions")]
        # |∩|=1, |∪|=3 -> 0.333
        assert result.score == pytest.approx(1 / 3)

    def test_denied_rows_do_not_count_as_actual(self) -> None:
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
            ]
        )
        rows = [_row("customer_data", "get_customer", status="denied")]
        result = score_tool_correctness(ds, rows)
        assert result.passed is False
        assert result.details["missing"] == [("customer_data", "get_customer")]

    def test_only_ok_false_lets_denied_rows_count(self) -> None:
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
            ]
        )
        rows = [_row("customer_data", "get_customer", status="denied")]
        result = score_tool_correctness(ds, rows, only_ok=False)
        assert result.passed is True

    def test_duplicates_in_audit_log_do_not_change_score(self) -> None:
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
            ]
        )
        rows = [
            _row("customer_data", "get_customer", ts="2026-01-01T00:00:00.000000+00:00"),
            _row("customer_data", "get_customer", ts="2026-01-01T00:00:01.000000+00:00"),
            _row("customer_data", "get_customer", ts="2026-01-01T00:00:02.000000+00:00"),
        ]
        result = score_tool_correctness(ds, rows)
        assert result.passed is True
        assert result.score == pytest.approx(1.0)

    def test_empty_audit_log_yields_zero(self) -> None:
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
            ]
        )
        result = score_tool_correctness(ds, [])
        assert result.passed is False
        assert result.score == pytest.approx(0.0)
        assert result.details["missing"] == [("customer_data", "get_customer")]


# --------------------------------------------------------------------------- #
# tool_ordering scorer
# --------------------------------------------------------------------------- #


class TestToolOrdering:
    def test_no_constraints_passes_trivially(self) -> None:
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
            ]
        )
        result = score_tool_ordering(ds, [])
        assert result.name == TO_NAME
        assert result.score == pytest.approx(1.0)
        assert result.passed is True
        assert result.details["total"] == 0

    def test_correct_order_passes(self) -> None:
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
                {"server": "transactions", "tool": "get_transactions"},
            ],
            ordering_constraints=[
                {
                    "before": {"server": "customer_data", "tool": "get_customer"},
                    "after": {"server": "transactions", "tool": "get_transactions"},
                }
            ],
        )
        rows = [
            _row("customer_data", "get_customer", ts="2026-01-01T00:00:00.000000+00:00"),
            _row("transactions", "get_transactions", ts="2026-01-01T00:00:01.000000+00:00"),
        ]
        result = score_tool_ordering(ds, rows)
        assert result.passed is True
        assert result.score == pytest.approx(1.0)
        assert len(result.details["satisfied"]) == 1
        assert result.details["violated"] == []
        assert result.details["unobserved"] == []

    def test_violated_order_fails(self) -> None:
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
                {"server": "transactions", "tool": "get_transactions"},
            ],
            ordering_constraints=[
                {
                    "before": {"server": "customer_data", "tool": "get_customer"},
                    "after": {"server": "transactions", "tool": "get_transactions"},
                }
            ],
        )
        rows = [
            _row("transactions", "get_transactions", ts="2026-01-01T00:00:00.000000+00:00"),
            _row("customer_data", "get_customer", ts="2026-01-01T00:00:01.000000+00:00"),
        ]
        result = score_tool_ordering(ds, rows)
        assert result.passed is False
        assert result.score == pytest.approx(0.0)
        assert len(result.details["violated"]) == 1
        violated = result.details["violated"][0]
        assert violated["before"] == ("customer_data", "get_customer")
        assert violated["after"] == ("transactions", "get_transactions")
        assert violated["reason"] == "before_at_or_after_after"

    def test_simultaneous_timestamps_count_as_violation(self) -> None:
        # before MUST appear earlier than after; equal timestamps don't satisfy.
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
                {"server": "transactions", "tool": "get_transactions"},
            ],
            ordering_constraints=[
                {
                    "before": {"server": "customer_data", "tool": "get_customer"},
                    "after": {"server": "transactions", "tool": "get_transactions"},
                }
            ],
        )
        ts = "2026-01-01T00:00:00.000000+00:00"
        rows = [
            _row("customer_data", "get_customer", ts=ts),
            _row("transactions", "get_transactions", ts=ts),
        ]
        result = score_tool_ordering(ds, rows)
        assert result.passed is False
        assert len(result.details["violated"]) == 1

    def test_uses_earliest_occurrence_of_before(self) -> None:
        # before appears twice; the earliest one should be used.
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
                {"server": "transactions", "tool": "get_transactions"},
            ],
            ordering_constraints=[
                {
                    "before": {"server": "customer_data", "tool": "get_customer"},
                    "after": {"server": "transactions", "tool": "get_transactions"},
                }
            ],
        )
        rows = [
            _row("customer_data", "get_customer", ts="2026-01-01T00:00:00.000000+00:00"),
            _row("transactions", "get_transactions", ts="2026-01-01T00:00:01.000000+00:00"),
            _row("customer_data", "get_customer", ts="2026-01-01T00:00:02.000000+00:00"),
        ]
        result = score_tool_ordering(ds, rows)
        assert result.passed is True
        sat = result.details["satisfied"][0]
        # earliest before is t=0; earliest after is t=1
        assert sat["before_ts"] == "2026-01-01T00:00:00.000000+00:00"
        assert sat["after_ts"] == "2026-01-01T00:00:01.000000+00:00"

    def test_unobserved_constraint_fails(self) -> None:
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
                {"server": "transactions", "tool": "get_transactions"},
            ],
            ordering_constraints=[
                {
                    "before": {"server": "customer_data", "tool": "get_customer"},
                    "after": {"server": "transactions", "tool": "get_transactions"},
                }
            ],
        )
        result = score_tool_ordering(ds, [])
        assert result.passed is False
        assert result.score == pytest.approx(0.0)
        assert len(result.details["unobserved"]) == 1
        assert result.details["unobserved"][0]["reason"] == "unobserved"

    def test_one_side_unobserved_fails(self) -> None:
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
                {"server": "transactions", "tool": "get_transactions"},
            ],
            ordering_constraints=[
                {
                    "before": {"server": "customer_data", "tool": "get_customer"},
                    "after": {"server": "transactions", "tool": "get_transactions"},
                }
            ],
        )
        rows = [_row("customer_data", "get_customer")]
        result = score_tool_ordering(ds, rows)
        assert result.passed is False
        assert len(result.details["unobserved"]) == 1
        assert result.details["unobserved"][0]["reason"] == "unobserved_one_side"

    def test_partial_satisfaction(self) -> None:
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
                {"server": "transactions", "tool": "get_transactions"},
                {"server": "transactions", "tool": "flag_velocity_anomalies"},
            ],
            ordering_constraints=[
                {
                    "before": {"server": "customer_data", "tool": "get_customer"},
                    "after": {"server": "transactions", "tool": "get_transactions"},
                },
                {
                    "before": {"server": "transactions", "tool": "get_transactions"},
                    "after": {"server": "transactions", "tool": "flag_velocity_anomalies"},
                },
            ],
        )
        # First constraint satisfied; second violated.
        rows = [
            _row("customer_data", "get_customer", ts="2026-01-01T00:00:00.000000+00:00"),
            _row(
                "transactions",
                "flag_velocity_anomalies",
                ts="2026-01-01T00:00:01.000000+00:00",
            ),
            _row("transactions", "get_transactions", ts="2026-01-01T00:00:02.000000+00:00"),
        ]
        result = score_tool_ordering(ds, rows)
        assert result.passed is False
        assert result.score == pytest.approx(0.5)
        assert len(result.details["satisfied"]) == 1
        assert len(result.details["violated"]) == 1

    def test_denied_rows_ignored_by_default(self) -> None:
        ds = _dataset(
            expected_tool_calls=[
                {"server": "customer_data", "tool": "get_customer"},
                {"server": "transactions", "tool": "get_transactions"},
            ],
            ordering_constraints=[
                {
                    "before": {"server": "customer_data", "tool": "get_customer"},
                    "after": {"server": "transactions", "tool": "get_transactions"},
                }
            ],
        )
        # Earliest get_customer is denied -> shouldn't anchor the
        # before; the OK row at t=2 is what counts.
        rows = [
            _row(
                "customer_data",
                "get_customer",
                ts="2026-01-01T00:00:00.000000+00:00",
                status="denied",
            ),
            _row(
                "transactions",
                "get_transactions",
                ts="2026-01-01T00:00:01.000000+00:00",
            ),
            _row(
                "customer_data",
                "get_customer",
                ts="2026-01-01T00:00:02.000000+00:00",
            ),
        ]
        result = score_tool_ordering(ds, rows)
        # Earliest OK before = t=2; earliest OK after = t=1 -> violated.
        assert result.passed is False
        assert len(result.details["violated"]) == 1

    def test_uses_shipped_dataset_ordering(self) -> None:
        """End-to-end against an actual shipped dataset (mule_account
        has 3 ordering constraints — wire them with a synthetic
        audit log and confirm the scorer reads the constraints out
        of the YAML correctly)."""
        from pathlib import Path

        from evals.datasets.schema import validate_dataset_file

        repo_root = Path(__file__).resolve().parents[1]
        ds = validate_dataset_file(repo_root / "evals" / "datasets" / "mule_account.yaml")
        # Build an audit log that satisfies every constraint in order.
        rows = [
            _row(call.server, call.tool, ts=f"2026-01-01T00:00:{idx:02d}.000000+00:00")
            for idx, call in enumerate(ds.expected_tool_calls)
        ]
        result = score_tool_ordering(ds, rows)
        assert result.passed is True
        assert result.details["total"] == len(ds.ordering_constraints)


# --------------------------------------------------------------------------- #
# Cross-scorer / contract smoke tests
# --------------------------------------------------------------------------- #


class TestScorerContracts:
    def test_correctness_scorer_name_is_pinned(self) -> None:
        from evals.scorers.tool_correctness import SCORER_NAME

        assert SCORER_NAME == "tool_correctness"

    def test_ordering_scorer_name_is_pinned(self) -> None:
        from evals.scorers.tool_ordering import SCORER_NAME

        assert SCORER_NAME == "tool_ordering"

    def test_scorers_returned_from_package_init(self) -> None:
        # Both scorers re-exported from evals.scorers for the runner.
        from evals.scorers import (
            ScorerResult as PkgResult,
        )
        from evals.scorers import (
            score_tool_correctness as pkg_correctness,
        )
        from evals.scorers import (
            score_tool_ordering as pkg_ordering,
        )

        assert pkg_correctness is score_tool_correctness
        assert pkg_ordering is score_tool_ordering
        assert PkgResult is ScorerResult

    def test_both_shipped_datasets_produce_results(self) -> None:
        """Smoke: every shipped dataset can be scored with empty audit
        rows without crashing (returns failed scores, not exceptions)."""
        from pathlib import Path

        from evals.datasets.schema import validate_dataset_dir

        repo_root = Path(__file__).resolve().parents[1]
        datasets = validate_dataset_dir(repo_root / "evals" / "datasets")
        assert len(datasets) >= 2
        for ds in datasets:
            tc_result = score_tool_correctness(ds, [])
            to_result = score_tool_ordering(ds, [])
            assert tc_result.name == "tool_correctness"
            assert to_result.name == "tool_ordering"
            # Empty audit log -> tool_correctness MUST fail (datasets
            # all have non-empty expected_tool_calls).
            assert tc_result.passed is False
            # Empty audit log -> ordering scorer passes only for
            # datasets that declared zero constraints.
            assert to_result.passed is (len(ds.ordering_constraints) == 0)


# --------------------------------------------------------------------------- #
# Direct ToolCall / OrderingConstraint / RequiredFact smoke tests
# (to keep imports used and explicit for future readers).
# --------------------------------------------------------------------------- #


def test_typed_helpers_can_construct_constraints() -> None:
    tc = ToolCall(server="customer_data", tool="get_customer")
    other = ToolCall(server="transactions", tool="get_transactions")
    oc = OrderingConstraint(before=tc, after=other)
    fact = RequiredFact(claim="x", supporting_tool=tc)
    alert = InputAlert(
        alert_id="a-1", customer_id="c-1", alert_type="routine_review"
    )
    assert oc.before.as_pair() == ("customer_data", "get_customer")
    assert fact.supporting_tool.as_pair() == ("customer_data", "get_customer")
    assert alert.alert_id == "a-1"
