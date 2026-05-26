"""Tests for the eval runner + CI integration (US-030)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from evals.datasets.schema import validate_dataset_file
from evals.harness import FinalAnswer, ToolCall
from evals.run import (
    DEFAULT_SUB,
    DIMENSIONS,
    SMOKE_DATASETS,
    EvalRunConfig,
    EvalSuiteResult,
    OracleAgent,
    PerCaseResult,
    StubJudge,
    main,
    run_eval_suite,
)
from evals.scorers import ScorerResult
from evals.scorers.judge import JudgeResponse

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = REPO_ROOT / "evals" / "datasets"
CLEAN_DATASET = DATASET_DIR / "clean_customer.yaml"
MULE_DATASET = DATASET_DIR / "mule_account.yaml"


# --------------------------------------------------------------------------- #
# DIMENSIONS + SMOKE_DATASETS                                                 #
# --------------------------------------------------------------------------- #


def test_dimensions_match_us_030_ac() -> None:
    """PRD US-030 AC: scorecard reports tool-correctness, ordering,
    grounding, reasoning."""
    assert DIMENSIONS == (
        "tool_correctness",
        "tool_ordering",
        "grounding",
        "reasoning",
    )


def test_smoke_datasets_are_the_launch_blocker_set() -> None:
    """PRD US-030 AC: smoke runs clean_customer + mule_account only."""
    assert SMOKE_DATASETS == ("clean_customer", "mule_account")
    # Both files must exist; pinning the smoke set against datasets we
    # don't ship would be a silent CI break.
    for case_id in SMOKE_DATASETS:
        assert (DATASET_DIR / f"{case_id}.yaml").is_file()


# --------------------------------------------------------------------------- #
# OracleAgent                                                                 #
# --------------------------------------------------------------------------- #


def test_oracle_agent_emits_expected_calls_then_final() -> None:
    dataset = validate_dataset_file(CLEAN_DATASET)
    oracle = OracleAgent(dataset)
    seen_names: list[str] = []
    for _ in range(len(dataset.expected_tool_calls)):
        step = oracle(skill_md="x", alert={}, tools=[], tool_results=[])
        assert isinstance(step, ToolCall)
        seen_names.append(step.name)
    final = oracle(skill_md="x", alert={}, tools=[], tool_results=[])
    assert isinstance(final, FinalAnswer)
    assert final.report["verdict"] == dataset.expected_verdict
    expected_names = [
        f"{tc.server}__{tc.tool}" for tc in dataset.expected_tool_calls
    ]
    assert seen_names == expected_names


def test_oracle_agent_handles_sanctions_screen_name_args() -> None:
    """Sanctions tools take ``name``/``entity_name``/``hit_id``, not
    ``customer_id`` — the oracle MUST shape arguments per-tool."""
    dataset = validate_dataset_file(DATASET_DIR / "sanctions_hit.yaml")
    oracle = OracleAgent(dataset)
    for _ in range(len(dataset.expected_tool_calls)):
        step = oracle(skill_md="x", alert={}, tools=[], tool_results=[])
        assert isinstance(step, ToolCall)
        args = step.arguments["arguments"]
        name = step.name
        if name == "sanctions__screen_name":
            assert "name" in args and "customer_id" not in args
        if name == "sanctions__screen_entity":
            assert "entity_name" in args and "customer_id" not in args
        if name == "sanctions__get_watchlist_hit":
            assert "hit_id" in args
            assert args["hit_id"].startswith("hit_sanctions_hit_")


def test_oracle_agent_handles_kyc_get_document_id_shape() -> None:
    """The kyc.get_document tool requires a document_id matching the
    mock's deterministic naming (``doc_<customer_id>_id``)."""
    dataset = validate_dataset_file(DATASET_DIR / "synthetic_id.yaml")
    oracle = OracleAgent(dataset)
    seen_doc_args: dict[str, Any] | None = None
    for _ in range(len(dataset.expected_tool_calls)):
        step = oracle(skill_md="x", alert={}, tools=[], tool_results=[])
        assert isinstance(step, ToolCall)
        if step.name == "kyc__get_document":
            seen_doc_args = step.arguments["arguments"]
    assert seen_doc_args is not None
    assert seen_doc_args["document_id"] == (
        f"doc_{dataset.input_alert.customer_id}_id"
    )


def test_oracle_agent_does_not_call_case_actions() -> None:
    """The oracle ONLY scripts calls in ``expected_tool_calls``. Since
    no dataset ships case_actions in expected_tool_calls (write-path
    is out of scope for M2), the oracle never emits one."""
    for yaml_file in sorted(DATASET_DIR.glob("*.yaml")):
        dataset = validate_dataset_file(yaml_file)
        oracle = OracleAgent(dataset)
        for _ in range(len(dataset.expected_tool_calls)):
            step = oracle(skill_md="x", alert={}, tools=[], tool_results=[])
            assert isinstance(step, ToolCall)
            assert not step.name.startswith("case_actions__"), yaml_file


# --------------------------------------------------------------------------- #
# StubJudge                                                                   #
# --------------------------------------------------------------------------- #


def test_stub_judge_grounding_matches_ok_row() -> None:
    judge = StubJudge()
    resp = judge(
        system="ignored",
        user=json.dumps(
            {
                "claim": "x",
                "value": "y",
                "citation": {"server": "customer_data", "tool": "get_customer"},
                "matching_audit_rows": [
                    {"status": "ok", "server": "customer_data"}
                ],
            }
        ),
    )
    parsed = json.loads(resp.text)
    assert parsed["verdict"] == "grounded"


def test_stub_judge_grounding_flags_denied_row() -> None:
    judge = StubJudge()
    resp = judge(
        system="ignored",
        user=json.dumps(
            {
                "claim": "x",
                "value": "y",
                "citation": {"server": "customer_data", "tool": "get_customer"},
                "matching_audit_rows": [
                    {"status": "denied", "server": "customer_data"}
                ],
            }
        ),
    )
    parsed = json.loads(resp.text)
    assert parsed["verdict"] == "ungrounded"


def test_stub_judge_reasoning_scores_4_on_all_ok() -> None:
    judge = StubJudge()
    resp = judge(
        system="ignored",
        user=json.dumps(
            {
                "report": {"alert_id": "a-1", "evidence": []},
                "audit_log": [
                    {"status": "ok", "server": "customer_data"},
                    {"status": "ok", "server": "transactions"},
                ],
            }
        ),
    )
    parsed = json.loads(resp.text)
    for dim in ("relevance", "soundness", "completeness", "calibration"):
        assert parsed[dim]["score"] == 4
    assert "overall_reason" in parsed


def test_stub_judge_reasoning_scores_2_on_any_failure() -> None:
    judge = StubJudge()
    resp = judge(
        system="ignored",
        user=json.dumps(
            {
                "report": {"alert_id": "a-1", "evidence": []},
                "audit_log": [
                    {"status": "ok", "server": "customer_data"},
                    {"status": "denied", "server": "transactions"},
                ],
            }
        ),
    )
    parsed = json.loads(resp.text)
    for dim in ("relevance", "soundness", "completeness", "calibration"):
        assert parsed[dim]["score"] == 2


def test_stub_judge_reasoning_scores_3_on_empty_audit_log() -> None:
    judge = StubJudge()
    resp = judge(
        system="ignored",
        user=json.dumps({"report": {"alert_id": "a-1", "evidence": []}, "audit_log": []}),
    )
    parsed = json.loads(resp.text)
    for dim in ("relevance", "soundness", "completeness", "calibration"):
        assert parsed[dim]["score"] == 3


def test_stub_judge_returns_empty_on_garbage_user_prompt() -> None:
    judge = StubJudge()
    resp = judge(system="ignored", user="not json at all")
    assert isinstance(resp, JudgeResponse)
    assert resp.text == ""


# --------------------------------------------------------------------------- #
# PerCaseResult / EvalSuiteResult                                             #
# --------------------------------------------------------------------------- #


def test_per_case_result_passed_aggregates_scorers() -> None:
    case = PerCaseResult(
        dataset_id="x",
        scenario="clean",
        expected_verdict="low_risk",
        terminated="final_answer",
        steps_used=4,
        scorer_results={
            "tool_correctness": ScorerResult(
                name="tool_correctness", score=1.0, passed=True
            ),
            "tool_ordering": ScorerResult(
                name="tool_ordering", score=1.0, passed=True
            ),
            "grounding": ScorerResult(name="grounding", score=1.0, passed=True),
            "reasoning": ScorerResult(name="reasoning", score=1.0, passed=True),
        },
    )
    assert case.passed is True


def test_per_case_result_passed_false_on_any_failure() -> None:
    case = PerCaseResult(
        dataset_id="x",
        scenario="clean",
        expected_verdict="low_risk",
        terminated="final_answer",
        steps_used=4,
        scorer_results={
            "tool_correctness": ScorerResult(
                name="tool_correctness", score=0.5, passed=False
            ),
        },
    )
    assert case.passed is False


def test_per_case_result_passed_false_on_error() -> None:
    case = PerCaseResult(
        dataset_id="x",
        scenario="clean",
        expected_verdict="low_risk",
        terminated="error",
        steps_used=0,
        scorer_results={},
        error="kaboom",
    )
    assert case.passed is False


def test_eval_suite_result_passed_requires_cases_and_all_pass() -> None:
    empty = EvalSuiteResult(cases=[])
    assert empty.passed is False
    good = EvalSuiteResult(
        cases=[
            PerCaseResult(
                dataset_id="x",
                scenario="clean",
                expected_verdict="low_risk",
                terminated="final_answer",
                steps_used=4,
                scorer_results={
                    dim: ScorerResult(name=dim, score=1.0, passed=True)
                    for dim in DIMENSIONS
                },
            )
        ]
    )
    assert good.passed is True


def test_eval_suite_pass_rate_by_dimension_handles_empty() -> None:
    empty = EvalSuiteResult(cases=[])
    for dim, rate in empty.pass_rate_by_dimension().items():
        assert rate == 0.0
        assert dim in DIMENSIONS


def test_eval_suite_to_dict_has_stable_shape() -> None:
    suite = EvalSuiteResult(
        cases=[
            PerCaseResult(
                dataset_id="clean_customer",
                scenario="clean",
                expected_verdict="low_risk",
                terminated="final_answer",
                steps_used=4,
                scorer_results={
                    dim: ScorerResult(name=dim, score=1.0, passed=True)
                    for dim in DIMENSIONS
                },
            )
        ]
    )
    payload = suite.to_dict()
    assert "cases" in payload
    assert "aggregate" in payload
    assert payload["aggregate"]["total"] == 1
    assert payload["aggregate"]["passed"] == 1
    assert payload["aggregate"]["all_passed"] is True
    assert set(payload["aggregate"]["pass_rate_by_dimension"]) == set(DIMENSIONS)
    case = payload["cases"][0]
    assert case["dataset_id"] == "clean_customer"
    assert case["passed"] is True
    assert set(case["scorers"]) == set(DIMENSIONS)


# --------------------------------------------------------------------------- #
# run_eval_suite — load-bearing US-030 AC                                     #
# --------------------------------------------------------------------------- #


def test_run_eval_suite_smoke_passes_with_oracle_and_stub_judge() -> None:
    """**Load-bearing US-030 AC**: make evals-smoke must pass on the
    shipped datasets with the deterministic Oracle + StubJudge."""
    config = EvalRunConfig(smoke=True, quiet=True)
    result = run_eval_suite(config)
    assert len(result.cases) == 2
    case_ids = {c.dataset_id for c in result.cases}
    assert case_ids == set(SMOKE_DATASETS)
    assert result.passed is True
    for case in result.cases:
        assert case.terminated == "final_answer"
        for dim in DIMENSIONS:
            assert case.scorer_results[dim].passed is True, (
                case.dataset_id,
                dim,
                case.scorer_results[dim],
            )


def test_run_eval_suite_full_passes_with_oracle_and_stub_judge() -> None:
    """**Load-bearing US-030 AC**: make evals must pass on the full
    shipped six datasets with the deterministic Oracle + StubJudge."""
    config = EvalRunConfig(quiet=True)
    result = run_eval_suite(config)
    assert len(result.cases) == 6, [c.dataset_id for c in result.cases]
    assert result.passed is True, [
        (c.dataset_id, [(n, s.passed) for n, s in c.scorer_results.items()])
        for c in result.cases
        if not c.passed
    ]
    rates = result.pass_rate_by_dimension()
    for dim in DIMENSIONS:
        assert rates[dim] == 1.0, (dim, rates)


def test_run_eval_suite_explicit_dataset_filter() -> None:
    config = EvalRunConfig(dataset_ids=("clean_customer",), quiet=True)
    result = run_eval_suite(config)
    assert [c.dataset_id for c in result.cases] == ["clean_customer"]


def test_run_eval_suite_unknown_dataset_raises() -> None:
    from evals.datasets.schema import EvalSchemaError

    config = EvalRunConfig(dataset_ids=("not_a_real_case",), quiet=True)
    with pytest.raises(EvalSchemaError, match="not_a_real_case"):
        run_eval_suite(config)


def test_run_eval_suite_failing_agent_is_captured_per_case() -> None:
    """If an agent raises, the runner captures the error on the per-case
    row and continues — one bad case must not abort the suite."""

    def _boom(_dataset: Any) -> Any:
        def _agent(*, skill_md: Any, alert: Any, tools: Any, tool_results: Any) -> Any:
            raise RuntimeError("agent went boom")

        return _agent

    config = EvalRunConfig(smoke=True, quiet=True)
    result = run_eval_suite(config, agent_factory=_boom)
    # Both cases terminated with terminated="agent_error" — the runner
    # records the harness's terminated state, not an exception path.
    assert len(result.cases) == 2
    for case in result.cases:
        # The harness handles the agent error itself; the case still
        # produces scorer results, just with empty audit rows. The
        # tool_correctness scorer reports score=0 (nothing matched).
        assert case.scorer_results["tool_correctness"].passed is False


def test_run_eval_suite_with_stub_judge_smoke_yields_json() -> None:
    """The to_dict() shape is what the CI artifact ships."""
    config = EvalRunConfig(smoke=True, quiet=True)
    result = run_eval_suite(config)
    payload = result.to_dict()
    json_text = json.dumps(payload, default=str)
    # Round-trips cleanly.
    parsed = json.loads(json_text)
    assert parsed["aggregate"]["all_passed"] is True


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def test_main_returns_zero_on_smoke_pass(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(["--smoke", "--quiet"])
    assert exit_code == 0
    captured = capsys.readouterr()
    # --quiet suppresses per-case lines + footer
    assert captured.out == ""


def test_main_writes_output_json(tmp_path: Path) -> None:
    out = tmp_path / "scorecard.json"
    exit_code = main(["--smoke", "--quiet", "--output", str(out)])
    assert exit_code == 0
    assert out.exists()
    parsed = json.loads(out.read_text())
    assert parsed["aggregate"]["all_passed"] is True
    assert {c["dataset_id"] for c in parsed["cases"]} == set(SMOKE_DATASETS)


def test_main_reports_unknown_dataset(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["--datasets", "no_such_case"])
    assert exit_code == 1
    err = capsys.readouterr().err
    assert "no_such_case" in err


def test_main_subprocess_roundtrip_smoke(tmp_path: Path) -> None:
    """Pin the wire shape: running ``python -m evals.run --smoke``
    in a subprocess exits 0 and prints the scorecard."""
    out = tmp_path / "sub.json"
    proc = subprocess.run(
        [sys.executable, "-m", "evals.run", "--smoke", "--output", str(out), "--quiet"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    parsed = json.loads(out.read_text())
    assert parsed["aggregate"]["all_passed"] is True


# --------------------------------------------------------------------------- #
# Makefile + CI workflow wiring                                               #
# --------------------------------------------------------------------------- #


def test_makefile_wires_evals_and_evals_smoke() -> None:
    """``make evals`` and ``make evals-smoke`` must call the runner."""
    makefile = (REPO_ROOT / "Makefile").read_text()
    assert "evals: $(VENV)/bin/activate" in makefile
    assert "$(PY) -m evals.run" in makefile
    assert "evals-smoke: $(VENV)/bin/activate" in makefile
    assert "$(PY) -m evals.run --smoke" in makefile
    # Make sure the placeholder strings are GONE.
    assert "placeholder until US-030" not in makefile


def test_github_workflow_evals_yml_exists_and_runs_smoke() -> None:
    path = REPO_ROOT / ".github" / "workflows" / "evals.yml"
    assert path.is_file()
    text = path.read_text()
    assert "pull_request" in text
    assert "evals.run --smoke" in text or "evals-smoke" in text
    # PR runs MUST validate dataset schemas before running anything.
    assert "evals.validate" in text


def test_github_workflow_evals_nightly_yml_exists_and_runs_full() -> None:
    path = REPO_ROOT / ".github" / "workflows" / "evals-nightly.yml"
    assert path.is_file()
    text = path.read_text()
    assert "schedule:" in text
    assert "cron" in text
    assert "evals.run" in text
    # Nightly run is the FULL suite, not the smoke subset.
    # Either explicit full-suite OR just `evals.run` (no --smoke) qualifies.
    assert "--smoke" not in text or "full" in text.lower()


# --------------------------------------------------------------------------- #
# Defaults                                                                    #
# --------------------------------------------------------------------------- #


def test_default_sub_matches_load_fixtures_user() -> None:
    """The runner mints PASETOs for the same user load-fixtures uses
    so a shared dev environment produces an audit log indexed by one
    user."""
    assert DEFAULT_SUB == "alice@example.com"


def test_eval_run_config_defaults_are_safe() -> None:
    config = EvalRunConfig()
    assert config.smoke is False
    assert config.dataset_ids is None
    assert config.max_steps > 0
    assert config.sub == DEFAULT_SUB
    assert config.skill_path.is_file()
    assert config.dataset_dir.is_dir()
