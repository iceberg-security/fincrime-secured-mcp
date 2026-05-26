"""Tests for the grounding + reasoning LLM-judge scorers (US-028).

Every judge call in this file is mocked. No network. No
ANTHROPIC_API_KEY required to run the suite.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

import pytest

from evals.scorers import (
    AnthropicJudge,
    Judge,
    JudgeResponse,
    ScorerResult,
    score_grounding,
    score_reasoning,
)
from evals.scorers.grounding import GROUNDING_PROMPT
from evals.scorers.grounding import SCORER_NAME as GROUNDING_NAME
from evals.scorers.judge import DEFAULT_MODEL
from evals.scorers.reasoning import (
    DIMENSIONS,
    PASSING_OVERALL_SCORE,
    REASONING_PROMPT,
)
from evals.scorers.reasoning import SCORER_NAME as REASONING_NAME

# --------------------------------------------------------------------------- #
# Test helpers
# --------------------------------------------------------------------------- #


def _row(
    server: str,
    tool: str,
    *,
    status: str = "ok",
    ts: str = "2026-01-01T00:00:00.000000+00:00",
    args_preview: dict[str, Any] | None = None,
    result_hash: str = "deadbeef",
) -> dict[str, Any]:
    return {
        "ts": ts,
        "server": server,
        "tool": tool,
        "status": status,
        "sub": "alice@example.com",
        "role": "analyst",
        "jti": f"jti-{server}-{tool}-{ts}",
        "trace_id": "trace-1",
        "args_preview": args_preview or {},
        "result_hash": result_hash,
        "deny_reason": None,
        "latency_ms": 1,
    }


def _claim(
    claim: str,
    *,
    value: Any,
    server: str,
    tool: str,
    field: str = "value",
    subskill: str | None = None,
) -> dict[str, Any]:
    citation: dict[str, Any] = {"tool": tool, "field": field}
    if subskill is not None:
        citation["subskill"] = subskill
    # The scorer matches by tool name primarily; include the optional
    # server hint when callers want strict matching.
    citation["server"] = server
    return {"claim": claim, "value": value, "citation": citation}


def _report(
    *,
    evidence: list[dict[str, Any]],
    verdict: str = "elevated_risk",
    summary: str = "Test report",
    recommended_actions: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "alert_id": "alert-1",
        "customer_id": "cust-1",
        "alert_type": "routine_review",
        "summary": summary,
        "evidence": evidence,
        "verdict": verdict,
        "recommended_actions": recommended_actions or [],
        "evidence_gaps": [],
    }


class StubJudge:
    """Deterministic Judge implementation that returns canned JSON.

    Tracks every call so tests can pin both the system prompt
    (cache-hit surface) and the user prompt (per-claim payload).
    """

    def __init__(self, responses: list[str | dict[str, Any]]) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[str, str]] = []

    def __call__(self, *, system: str, user: str) -> JudgeResponse:
        self.calls.append((system, user))
        if not self._responses:
            raise AssertionError("StubJudge ran out of canned responses")
        nxt = self._responses.pop(0)
        text = nxt if isinstance(nxt, str) else json.dumps(nxt)
        return JudgeResponse(text=text)


class _RaisingJudge:
    """Judge that raises if called — used when the scorer must short-
    circuit (e.g. no matching audit rows means no judge call)."""

    def __call__(self, *, system: str, user: str) -> JudgeResponse:
        raise AssertionError("judge should not have been called")


# --------------------------------------------------------------------------- #
# Judge / Protocol contract
# --------------------------------------------------------------------------- #


class TestJudgeContract:
    def test_judge_protocol_is_satisfied_by_stub(self) -> None:
        stub = StubJudge([{"verdict": "grounded", "reason": "ok"}])
        # Protocol is runtime_checkable -> isinstance works.
        assert isinstance(stub, Judge)

    def test_judge_response_carries_text(self) -> None:
        resp = JudgeResponse(text="hi")
        assert resp.text == "hi"
        assert resp.raw is None

    def test_default_model_is_pinned(self) -> None:
        # PRD US-033 ADR pins Opus 4.7 as the default judge.
        assert DEFAULT_MODEL == "claude-opus-4-7"

    def test_anthropic_judge_uses_prompt_caching_on_system(self) -> None:
        """The AnthropicJudge MUST set cache_control on the system
        block — that's how the Anthropic API caches the rubric for the
        5-minute TTL window. The PRD AC explicitly requires it."""
        calls: list[dict[str, Any]] = []

        class _FakeMessages:
            def create(self, **kwargs: Any) -> Any:
                calls.append(kwargs)

                class _Resp:
                    content: list[Any] = []
                    model = kwargs.get("model")

                return _Resp()

        class _FakeClient:
            def __init__(self) -> None:
                self.messages = _FakeMessages()

        judge = AnthropicJudge(client=_FakeClient())
        judge(system="RULES", user="case")
        assert len(calls) == 1
        kwargs = calls[0]
        assert kwargs["model"] == DEFAULT_MODEL
        # Single system block with cache_control set ephemeral.
        assert kwargs["system"] == [
            {
                "type": "text",
                "text": "RULES",
                "cache_control": {"type": "ephemeral"},
            }
        ]
        assert kwargs["messages"] == [{"role": "user", "content": "case"}]

    def test_anthropic_judge_concatenates_text_blocks(self) -> None:
        """When the SDK returns multiple text blocks, the judge
        concatenates them. Defends against future SDK changes that
        split a single response across blocks."""

        class _Block:
            def __init__(self, text: str) -> None:
                self.text = text

        class _FakeMessages:
            def create(self, **kwargs: Any) -> Any:
                class _Resp:
                    content = [_Block("hello"), _Block(" world")]
                    model = kwargs["model"]

                return _Resp()

        class _FakeClient:
            def __init__(self) -> None:
                self.messages = _FakeMessages()

        judge = AnthropicJudge(client=_FakeClient())
        resp = judge(system="r", user="u")
        assert resp.text == "hello world"


# --------------------------------------------------------------------------- #
# Grounding scorer
# --------------------------------------------------------------------------- #


class TestGroundingScorer:
    def test_grounded_claim_accepted(self) -> None:
        """Every claim grounded -> passed=True, score=1.0."""
        evidence = [
            _claim(
                "customer flagged",
                value=True,
                server="customer_data",
                tool="get_customer",
            )
        ]
        report = _report(evidence=evidence)
        rows = [
            _row(
                "customer_data",
                "get_customer",
                args_preview={"customer_id": "cust-1"},
            )
        ]
        judge = StubJudge([{"verdict": "grounded", "reason": "args match"}])
        result = score_grounding(report, rows, judge=judge)
        assert isinstance(result, ScorerResult)
        assert result.name == GROUNDING_NAME
        assert result.passed is True
        assert result.score == pytest.approx(1.0)
        assert len(result.details["grounded"]) == 1
        assert result.details["partial"] == []
        assert result.details["ungrounded"] == []
        # The system prompt must be the cached rubric.
        assert judge.calls[0][0] == GROUNDING_PROMPT

    def test_ungrounded_claim_flagged(self) -> None:
        """A claim the judge rejects shows up in ``ungrounded`` and
        the scorer fails."""
        evidence = [
            _claim(
                "structuring pattern",
                value=True,
                server="transactions",
                tool="flag_velocity_anomalies",
            )
        ]
        report = _report(evidence=evidence)
        rows = [_row("transactions", "flag_velocity_anomalies")]
        judge = StubJudge(
            [{"verdict": "ungrounded", "reason": "args_preview doesn't match"}]
        )
        result = score_grounding(report, rows, judge=judge)
        assert result.passed is False
        assert result.score == pytest.approx(0.0)
        assert len(result.details["ungrounded"]) == 1
        rec = result.details["ungrounded"][0]
        assert rec["claim"] == "structuring pattern"
        assert rec["verdict"] == "ungrounded"

    def test_missing_audit_row_short_circuits_to_ungrounded(self) -> None:
        """No matching audit row -> no judge call; auto-ungrounded.
        Saves a round-trip + closes the loophole of 'the judge said
        grounded but no audit row exists'."""
        evidence = [
            _claim(
                "device change",
                value=True,
                server="customer_data",
                tool="get_device_history",
            )
        ]
        report = _report(evidence=evidence)
        rows = [_row("customer_data", "get_customer")]  # different tool
        judge = _RaisingJudge()
        result = score_grounding(report, rows, judge=judge)
        assert result.passed is False
        assert len(result.details["ungrounded"]) == 1
        rec = result.details["ungrounded"][0]
        assert rec["reason"] == "no_audit_row_matches_citation"

    def test_denied_audit_rows_do_not_count(self) -> None:
        """Only status='ok' rows can ground a claim. Denied rows mean
        the agent tried but never observed a result."""
        evidence = [
            _claim(
                "kyc record fetched",
                value="verified",
                server="kyc",
                tool="get_kyc_record",
            )
        ]
        report = _report(evidence=evidence)
        rows = [_row("kyc", "get_kyc_record", status="denied")]
        judge = _RaisingJudge()
        result = score_grounding(report, rows, judge=judge)
        assert result.passed is False
        rec = result.details["ungrounded"][0]
        assert rec["reason"] == "no_audit_row_matches_citation"

    def test_partial_claim_half_credit(self) -> None:
        """A 'partial' verdict counts as 0.5; passing requires every
        claim grounded (no partials, no ungrounded)."""
        evidence = [
            _claim(
                "high risk score",
                value=82,
                server="customer_data",
                tool="get_customer",
            ),
            _claim(
                "device list",
                value=[],
                server="customer_data",
                tool="get_device_history",
            ),
        ]
        report = _report(evidence=evidence)
        rows = [
            _row("customer_data", "get_customer"),
            _row("customer_data", "get_device_history"),
        ]
        judge = StubJudge(
            [
                {"verdict": "grounded", "reason": "score visible in args"},
                {"verdict": "partial", "reason": "tool called but value not in args"},
            ]
        )
        result = score_grounding(report, rows, judge=judge)
        # (1 grounded + 0.5 * 1 partial) / 2 = 0.75
        assert result.score == pytest.approx(0.75)
        assert result.passed is False  # partials don't pass
        assert len(result.details["grounded"]) == 1
        assert len(result.details["partial"]) == 1

    def test_empty_evidence_passes_trivially(self) -> None:
        """No claims -> nothing to ground. Scorer returns passed=True;
        the verifier (US-021) handles the case where empty evidence
        contradicts the verdict tier."""
        report = _report(evidence=[], verdict="insufficient_evidence")
        result = score_grounding(report, [], judge=_RaisingJudge())
        assert result.passed is True
        assert result.score == pytest.approx(1.0)
        assert result.details["total"] == 0

    def test_evidence_not_a_list_is_an_error(self) -> None:
        """Defends against malformed reports — caller gets a clear
        error, not an exception inside the scorer."""
        report = {"evidence": "not a list"}
        result = score_grounding(report, [], judge=_RaisingJudge())
        assert result.passed is False
        assert result.score == pytest.approx(0.0)
        assert "error" in result.details

    def test_judge_returns_malformed_json_fails_closed(self) -> None:
        """If the judge returns garbage, the scorer treats the claim
        as ungrounded (defense in depth — the rubric says reply with
        JSON, but the scorer doesn't trust the judge unconditionally)."""
        evidence = [
            _claim(
                "x",
                value=1,
                server="customer_data",
                tool="get_customer",
            )
        ]
        report = _report(evidence=evidence)
        rows = [_row("customer_data", "get_customer")]
        judge = StubJudge(["not json at all"])
        result = score_grounding(report, rows, judge=judge)
        assert result.passed is False
        rec = result.details["ungrounded"][0]
        assert "judge response not JSON" in rec["reason"]

    def test_judge_returns_invalid_verdict_fails_closed(self) -> None:
        evidence = [
            _claim(
                "x",
                value=1,
                server="customer_data",
                tool="get_customer",
            )
        ]
        report = _report(evidence=evidence)
        rows = [_row("customer_data", "get_customer")]
        judge = StubJudge([{"verdict": "maybe", "reason": "shrug"}])
        result = score_grounding(report, rows, judge=judge)
        assert result.passed is False
        rec = result.details["ungrounded"][0]
        assert "invalid verdict" in rec["reason"]

    def test_evidence_entry_not_an_object_flagged(self) -> None:
        report = {
            "alert_id": "a",
            "evidence": [{"good": "entry", "citation": None}, "not an object"],
        }
        rows: list[dict[str, Any]] = []
        judge = StubJudge([])  # no matching rows -> no judge call
        result = score_grounding(report, rows, judge=judge)
        assert result.passed is False
        # 2 entries, both ungrounded (no matching rows + malformed).
        assert len(result.details["ungrounded"]) == 2

    def test_server_mismatch_is_skipped_in_match(self) -> None:
        """When the citation specifies a server, only audit rows for
        that server can match — guards against the 'same tool name on
        a different server' (theoretical, since tools are unique
        across servers, but the scorer must defend against future
        drift)."""
        evidence = [
            _claim(
                "x",
                value=1,
                server="customer_data",
                tool="get_customer",
            )
        ]
        report = _report(evidence=evidence)
        # Tool name matches but server mismatches.
        rows = [
            {
                **_row("customer_data", "get_customer"),
                "server": "other_server",
            }
        ]
        result = score_grounding(report, rows, judge=_RaisingJudge())
        assert result.passed is False


# --------------------------------------------------------------------------- #
# Reasoning scorer
# --------------------------------------------------------------------------- #


def _dim(score: int, reason: str = "") -> dict[str, Any]:
    return {"score": score, "reason": reason}


def _all_dims(score: int) -> dict[str, Any]:
    return {dim: _dim(score) for dim in DIMENSIONS}


class TestReasoningScorer:
    def test_high_quality_reasoning_passes(self) -> None:
        """All 5s -> mean 5.0 -> normalized 1.0 -> passed=True."""
        report = _report(
            evidence=[
                _claim(
                    "sanctions hit",
                    value=True,
                    server="sanctions",
                    tool="screen_name",
                )
            ],
            verdict="high_risk",
        )
        rows = [_row("sanctions", "screen_name")]
        judge = StubJudge(
            [
                {
                    **_all_dims(5),
                    "overall_reason": "tight reasoning",
                }
            ]
        )
        result = score_reasoning(report, rows, judge=judge)
        assert result.name == REASONING_NAME
        assert result.passed is True
        assert result.score == pytest.approx(1.0)
        assert result.details["mean_score"] == pytest.approx(5.0)
        assert judge.calls[0][0] == REASONING_PROMPT

    def test_passing_threshold_is_exactly_four(self) -> None:
        """The PRD AC says 'high-quality reasoning scored >=4'. Mean
        4.0 passes; 3.999 doesn't. We pin the boundary with a 4-4-4-4
        run."""
        report = _report(evidence=[])
        report["evidence"] = []
        # evidence is a list (empty), reasoning scorer still queries judge
        # because it scores the chain, not the claims.
        rows: list[dict[str, Any]] = []
        judge = StubJudge(
            [{**_all_dims(4), "overall_reason": "solid"}]
        )
        result = score_reasoning(report, rows, judge=judge)
        assert result.details["mean_score"] == pytest.approx(4.0)
        assert result.passed is True
        # PASSING_OVERALL_SCORE constant is the contract.
        assert PASSING_OVERALL_SCORE == 4.0

    def test_weak_reasoning_fails(self) -> None:
        """All 2s -> mean 2.0 -> normalized (2-1)/4 = 0.25 -> passed=False.
        Pins the AC's 'weak reasoning <=2'."""
        report = _report(evidence=[])
        report["evidence"] = []
        rows: list[dict[str, Any]] = []
        judge = StubJudge(
            [{**_all_dims(2), "overall_reason": "multiple gaps"}]
        )
        result = score_reasoning(report, rows, judge=judge)
        assert result.passed is False
        assert result.score == pytest.approx(0.25)
        assert result.details["mean_score"] == pytest.approx(2.0)

    def test_mixed_scores_average_correctly(self) -> None:
        report = _report(evidence=[])
        report["evidence"] = []
        rows: list[dict[str, Any]] = []
        judge = StubJudge(
            [
                {
                    "relevance": _dim(5),
                    "soundness": _dim(3),
                    "completeness": _dim(4),
                    "calibration": _dim(4),
                    "overall_reason": "uneven",
                }
            ]
        )
        result = score_reasoning(report, rows, judge=judge)
        # mean = (5+3+4+4)/4 = 4.0 -> passing
        assert result.details["mean_score"] == pytest.approx(4.0)
        assert result.passed is True
        assert result.score == pytest.approx(0.75)
        per = result.details["per_dimension"]
        assert per["relevance"]["score"] == 5
        assert per["soundness"]["score"] == 3

    def test_judge_missing_dimension_fails(self) -> None:
        report = _report(evidence=[])
        report["evidence"] = []
        rows: list[dict[str, Any]] = []
        judge = StubJudge(
            [
                {
                    "relevance": _dim(5),
                    "soundness": _dim(5),
                    "completeness": _dim(5),
                    # calibration missing
                    "overall_reason": "incomplete reply",
                }
            ]
        )
        result = score_reasoning(report, rows, judge=judge)
        assert result.passed is False
        assert result.score == pytest.approx(0.0)
        assert result.details["error"] == "judge_response_parse_failed"
        assert "calibration" in result.details["reason"]

    def test_judge_out_of_range_score_fails(self) -> None:
        report = _report(evidence=[])
        report["evidence"] = []
        rows: list[dict[str, Any]] = []
        judge = StubJudge(
            [
                {
                    "relevance": _dim(7),
                    "soundness": _dim(4),
                    "completeness": _dim(4),
                    "calibration": _dim(4),
                    "overall_reason": "bad score",
                }
            ]
        )
        result = score_reasoning(report, rows, judge=judge)
        assert result.passed is False
        assert result.details["error"] == "judge_response_parse_failed"

    def test_evidence_not_a_list_short_circuits(self) -> None:
        report = {"evidence": "not a list"}
        rows: list[dict[str, Any]] = []
        result = score_reasoning(report, rows, judge=_RaisingJudge())
        assert result.passed is False
        assert result.score == pytest.approx(0.0)
        assert "not a list" in result.details["error"]

    def test_judge_returns_garbage_text_fails_closed(self) -> None:
        report = _report(evidence=[])
        report["evidence"] = []
        rows: list[dict[str, Any]] = []
        judge = StubJudge(["not json"])
        result = score_reasoning(report, rows, judge=judge)
        assert result.passed is False
        assert result.details["error"] == "judge_response_parse_failed"
        assert "raw_text" in result.details

    def test_only_ok_rows_passed_to_judge_by_default(self) -> None:
        """Denied rows shouldn't pollute the judge's view of the
        evidence the agent observed."""
        report = _report(evidence=[])
        report["evidence"] = []
        rows = [
            _row("customer_data", "get_customer", status="ok"),
            _row("transactions", "get_transactions", status="denied"),
        ]
        judge = StubJudge(
            [{**_all_dims(4), "overall_reason": "ok"}]
        )
        score_reasoning(report, rows, judge=judge)
        # Inspect the user prompt to confirm only the OK row reached
        # the judge.
        _, user = judge.calls[0]
        payload = json.loads(user)
        tools_seen = {r["tool"] for r in payload["audit_log"]}
        assert tools_seen == {"get_customer"}

    def test_only_ok_false_includes_denied_rows(self) -> None:
        report = _report(evidence=[])
        report["evidence"] = []
        rows = [
            _row("customer_data", "get_customer", status="ok"),
            _row("transactions", "get_transactions", status="denied"),
        ]
        judge = StubJudge(
            [{**_all_dims(4), "overall_reason": "ok"}]
        )
        score_reasoning(report, rows, judge=judge, only_ok=False)
        _, user = judge.calls[0]
        payload = json.loads(user)
        tools_seen = {r["tool"] for r in payload["audit_log"]}
        assert tools_seen == {"get_customer", "get_transactions"}


# --------------------------------------------------------------------------- #
# Cross-scorer contract
# --------------------------------------------------------------------------- #


class TestLLMScorerContracts:
    def test_grounding_scorer_name_pinned(self) -> None:
        assert GROUNDING_NAME == "grounding"

    def test_reasoning_scorer_name_pinned(self) -> None:
        assert REASONING_NAME == "reasoning"

    def test_dimensions_pinned(self) -> None:
        # PRD AC: relevance, soundness, completeness, calibration.
        assert DIMENSIONS == (
            "relevance",
            "soundness",
            "completeness",
            "calibration",
        )

    def test_package_init_reexports_llm_scorers(self) -> None:
        from evals.scorers import (
            score_grounding as pkg_grounding,
        )
        from evals.scorers import (
            score_reasoning as pkg_reasoning,
        )

        assert pkg_grounding is score_grounding
        assert pkg_reasoning is score_reasoning

    def test_package_init_reexports_judge_protocol(self) -> None:
        # The runner (US-030) needs `Judge` to type-annotate its
        # config; re-exporting from the package keeps import paths
        # short.
        from evals.scorers import AnthropicJudge as _A
        from evals.scorers import Judge as _J
        from evals.scorers import JudgeResponse as _R

        assert _J is Judge
        assert _R is JudgeResponse
        assert _A is AnthropicJudge

    def test_grounding_prompt_mentions_status_ok(self) -> None:
        # Pins the rubric's contract: only status='ok' rows count.
        assert "status=" in GROUNDING_PROMPT
        assert '"ok"' in GROUNDING_PROMPT

    def test_reasoning_prompt_lists_all_four_dimensions(self) -> None:
        for dim in DIMENSIONS:
            assert dim in REASONING_PROMPT

    def test_grounding_prompt_demands_strict_json(self) -> None:
        # Defense in depth: pin the wire shape so a future prompt edit
        # doesn't break the parser.
        assert "JSON object" in GROUNDING_PROMPT
        assert "markdown fences" in GROUNDING_PROMPT

    def test_reasoning_prompt_demands_strict_json(self) -> None:
        assert "JSON object" in REASONING_PROMPT
        assert "markdown fences" in REASONING_PROMPT


# --------------------------------------------------------------------------- #
# End-to-end smoke against a shipped dataset
# --------------------------------------------------------------------------- #


def _fake_judge_grounded(count: int) -> StubJudge:
    return StubJudge(
        [{"verdict": "grounded", "reason": f"row {i} matches"} for i in range(count)]
    )


class TestEndToEndAgainstShippedDataset:
    """Confirm the scorers can run against a shipped YAML's expected
    surface without crashing. Used as a smoke test only — the runner
    (US-030) will build the real audit log from a live harness run."""

    def test_grounding_passes_on_synthetic_perfect_run(self) -> None:
        from pathlib import Path

        from evals.datasets.schema import validate_dataset_file

        repo_root = Path(__file__).resolve().parents[1]
        ds = validate_dataset_file(
            repo_root / "evals" / "datasets" / "clean_customer.yaml"
        )
        # Build evidence list from required_facts; each fact maps
        # 1-1 to a supporting tool, which mirrors the draft-narrative
        # output shape.
        evidence = [
            _claim(
                fact.claim,
                value="seen",
                server=fact.supporting_tool.server,
                tool=fact.supporting_tool.tool,
            )
            for fact in ds.required_facts
        ]
        report = _report(evidence=evidence, verdict=ds.expected_verdict)
        rows = [
            _row(tc.server, tc.tool, ts=f"2026-01-01T00:00:{i:02d}.000000+00:00")
            for i, tc in enumerate(ds.expected_tool_calls)
        ]
        judge = _fake_judge_grounded(len(evidence))
        result = score_grounding(report, rows, judge=judge)
        assert result.passed is True
        assert result.score == pytest.approx(1.0)

    def test_reasoning_passes_on_synthetic_perfect_run(self) -> None:
        from pathlib import Path

        from evals.datasets.schema import validate_dataset_file

        repo_root = Path(__file__).resolve().parents[1]
        ds = validate_dataset_file(
            repo_root / "evals" / "datasets" / "mule_account.yaml"
        )
        evidence = [
            _claim(
                fact.claim,
                value="seen",
                server=fact.supporting_tool.server,
                tool=fact.supporting_tool.tool,
            )
            for fact in ds.required_facts
        ]
        report = _report(evidence=evidence, verdict=ds.expected_verdict)
        rows = [
            _row(tc.server, tc.tool, ts=f"2026-01-01T00:00:{i:02d}.000000+00:00")
            for i, tc in enumerate(ds.expected_tool_calls)
        ]
        judge = StubJudge(
            [{**_all_dims(5), "overall_reason": "excellent"}]
        )
        result = score_reasoning(report, rows, judge=judge)
        assert result.passed is True
        assert result.score == pytest.approx(1.0)


# --------------------------------------------------------------------------- #
# Misc: ensure unused imports don't drift
# --------------------------------------------------------------------------- #


def test_iterable_import_used() -> None:
    # `Iterable` is in the public type signature of the scorers; this
    # test exists so the import sticks around for type-checker
    # consumers reading the wire.
    def _accept(_rows: Iterable[dict[str, Any]]) -> None:
        pass

    _accept([_row("customer_data", "get_customer")])
