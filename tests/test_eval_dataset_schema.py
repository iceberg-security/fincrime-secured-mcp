"""Tests for the eval-dataset schema + the two shipped YAMLs (US-025).

Two layers of coverage:

1. The Pydantic schema in ``evals/datasets/schema.py`` accepts the
   shapes the PRD says it must and rejects malformed ones.
2. The two YAML datasets we shipped under ``evals/datasets/`` parse,
   validate, and reference fixtures that exist in the seeded mock
   APIs (the latter via the ALLOWED_TOOLS table that mirrors every
   downstream MCP server's contract).

The Makefile target ``make validate-evals`` is also exercised
end-to-end via the ``evals.validate`` CLI.
"""

from __future__ import annotations

import io
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

import pytest
import yaml

from evals.datasets.schema import (
    ALLOWED_TOOLS,
    EvalDataset,
    EvalSchemaError,
    OrderingConstraint,
    RequiredFact,
    ToolCall,
    load_dataset,
    validate_dataset_dir,
    validate_dataset_file,
)
from evals.validate import main as validate_main

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASETS_DIR = REPO_ROOT / "evals" / "datasets"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _minimal_dataset() -> dict[str, Any]:
    """The smallest legal dataset payload, used as a template by the
    malformed-input tests."""
    return {
        "id": "tmp_case",
        "description": "throwaway",
        "scenario": "clean",
        "input_alert": {
            "alert_id": "alert-1",
            "customer_id": "cust-1",
            "alert_type": "routine_review",
        },
        "expected_tool_calls": [
            {"server": "customer_data", "tool": "get_customer"},
        ],
        "ordering_constraints": [],
        "expected_verdict": "low_risk",
        "required_facts": [
            {
                "claim": "profile fetched",
                "supporting_tool": {
                    "server": "customer_data",
                    "tool": "get_customer",
                },
            },
        ],
    }


# --------------------------------------------------------------------------- #
# Schema-level: positive
# --------------------------------------------------------------------------- #


def test_minimal_dataset_validates() -> None:
    ds = load_dataset(_minimal_dataset())
    assert isinstance(ds, EvalDataset)
    assert ds.id == "tmp_case"
    assert ds.expected_verdict == "low_risk"
    assert ds.expected_tool_calls[0].as_pair() == ("customer_data", "get_customer")


def test_allowed_tools_covers_every_mcp_server() -> None:
    """The static ALLOWED_TOOLS table is the bridge between the schema
    and the live mock stack. Every server the orchestrator declares
    MUST appear here, with exactly the tool list the plugin.json
    pins."""
    expected_servers = {
        "customer_data",
        "transactions",
        "kyc",
        "sanctions",
        "osint",
        "case_actions",
    }
    assert set(ALLOWED_TOOLS.keys()) == expected_servers
    # The orchestrator (US-010 / US-017 / US-018 / US-019) declares
    # exactly three tools per server; the case_actions server (US-016)
    # likewise has exactly three. Nail that down.
    for server, tools in ALLOWED_TOOLS.items():
        assert len(tools) == 3, (
            f"{server}: expected 3 tools, got {sorted(tools)}"
        )


def test_optional_input_alert_fields_are_accepted() -> None:
    raw = _minimal_dataset()
    raw["input_alert"]["opened_at"] = "2026-05-26T08:00:00Z"
    raw["input_alert"]["notes"] = "a note"
    raw["input_alert"]["severity"] = "high"
    ds = load_dataset(raw)
    assert ds.input_alert.notes == "a note"
    assert ds.input_alert.severity == "high"


def test_ordering_constraints_are_optional() -> None:
    raw = _minimal_dataset()
    raw["ordering_constraints"] = []
    ds = load_dataset(raw)
    assert ds.ordering_constraints == []


def test_ordering_constraint_with_valid_pair_validates() -> None:
    raw = _minimal_dataset()
    raw["expected_tool_calls"].append(
        {"server": "transactions", "tool": "get_transactions"}
    )
    raw["ordering_constraints"] = [
        {
            "before": {"server": "customer_data", "tool": "get_customer"},
            "after": {"server": "transactions", "tool": "get_transactions"},
        }
    ]
    ds = load_dataset(raw)
    assert len(ds.ordering_constraints) == 1
    assert ds.ordering_constraints[0].before.as_pair() == (
        "customer_data",
        "get_customer",
    )


def test_required_facts_pair_to_an_expected_tool_call() -> None:
    raw = _minimal_dataset()
    raw["expected_tool_calls"].append(
        {"server": "transactions", "tool": "get_transactions"}
    )
    raw["required_facts"].append(
        {
            "claim": "tx volume above mule threshold",
            "supporting_tool": {
                "server": "transactions",
                "tool": "get_transactions",
            },
        }
    )
    ds = load_dataset(raw)
    assert len(ds.required_facts) == 2


# --------------------------------------------------------------------------- #
# Schema-level: negative
# --------------------------------------------------------------------------- #


def test_unknown_server_rejected() -> None:
    raw = _minimal_dataset()
    raw["expected_tool_calls"] = [
        {"server": "totally_made_up", "tool": "get_customer"}
    ]
    with pytest.raises(EvalSchemaError, match="unknown MCP server"):
        load_dataset(raw)


def test_unknown_tool_on_known_server_rejected() -> None:
    raw = _minimal_dataset()
    raw["expected_tool_calls"] = [
        {"server": "customer_data", "tool": "send_email"}
    ]
    with pytest.raises(EvalSchemaError, match="unknown tool"):
        load_dataset(raw)


def test_unknown_scenario_rejected() -> None:
    raw = _minimal_dataset()
    raw["scenario"] = "nonsense"
    with pytest.raises(EvalSchemaError):
        load_dataset(raw)


def test_unknown_verdict_rejected() -> None:
    raw = _minimal_dataset()
    raw["expected_verdict"] = "definitely_a_bank_robber"
    with pytest.raises(EvalSchemaError):
        load_dataset(raw)


def test_empty_expected_tool_calls_rejected() -> None:
    raw = _minimal_dataset()
    raw["expected_tool_calls"] = []
    with pytest.raises(EvalSchemaError):
        load_dataset(raw)


def test_empty_required_facts_rejected() -> None:
    raw = _minimal_dataset()
    raw["required_facts"] = []
    with pytest.raises(EvalSchemaError):
        load_dataset(raw)


def test_id_must_be_kebab_or_snake_lowercase() -> None:
    raw = _minimal_dataset()
    raw["id"] = "Bad-ID-Has-Capitals"
    with pytest.raises(EvalSchemaError):
        load_dataset(raw)


def test_duplicate_expected_tool_calls_rejected() -> None:
    raw = _minimal_dataset()
    raw["expected_tool_calls"] = [
        {"server": "customer_data", "tool": "get_customer"},
        {"server": "customer_data", "tool": "get_customer"},
    ]
    with pytest.raises(EvalSchemaError, match="duplicate"):
        load_dataset(raw)


def test_ordering_constraint_references_unexpected_tool_rejected() -> None:
    raw = _minimal_dataset()
    raw["ordering_constraints"] = [
        {
            "before": {"server": "customer_data", "tool": "get_customer"},
            "after": {"server": "transactions", "tool": "get_transactions"},
        }
    ]
    # `after` is not in expected_tool_calls.
    with pytest.raises(EvalSchemaError, match="not in expected_tool_calls"):
        load_dataset(raw)


def test_required_fact_references_unexpected_tool_rejected() -> None:
    raw = _minimal_dataset()
    raw["required_facts"] = [
        {
            "claim": "X",
            "supporting_tool": {
                "server": "transactions",
                "tool": "get_transactions",
            },
        }
    ]
    with pytest.raises(EvalSchemaError, match="not in expected_tool_calls"):
        load_dataset(raw)


def test_trivial_ordering_constraint_rejected() -> None:
    raw = _minimal_dataset()
    raw["ordering_constraints"] = [
        {
            "before": {"server": "customer_data", "tool": "get_customer"},
            "after": {"server": "customer_data", "tool": "get_customer"},
        }
    ]
    with pytest.raises(EvalSchemaError, match="must differ"):
        load_dataset(raw)


def test_extra_field_rejected() -> None:
    raw = _minimal_dataset()
    raw["unsupported_field"] = "oops"
    with pytest.raises(EvalSchemaError):
        load_dataset(raw)


def test_extra_field_inside_input_alert_rejected() -> None:
    raw = _minimal_dataset()
    raw["input_alert"]["arbitrary"] = "not allowed"
    with pytest.raises(EvalSchemaError):
        load_dataset(raw)


# --------------------------------------------------------------------------- #
# File-level: real shipped YAMLs
# --------------------------------------------------------------------------- #


def test_clean_customer_yaml_validates() -> None:
    ds = validate_dataset_file(DATASETS_DIR / "clean_customer.yaml")
    assert ds.id == "clean_customer"
    assert ds.scenario == "clean"
    assert ds.expected_verdict == "low_risk"
    # The clean baseline must touch the customer_data surface only.
    servers = {tc.server for tc in ds.expected_tool_calls}
    assert servers == {"customer_data"}


def test_mule_account_yaml_validates() -> None:
    ds = validate_dataset_file(DATASETS_DIR / "mule_account.yaml")
    assert ds.id == "mule_account"
    assert ds.scenario == "mule"
    assert ds.expected_verdict == "high_risk"
    # The mule case must fan out to transactions + osint at minimum.
    servers = {tc.server for tc in ds.expected_tool_calls}
    assert {"customer_data", "transactions", "osint"}.issubset(servers)


def test_mule_account_has_ordering_constraints() -> None:
    """A high-risk fan-out case is the natural place to pin ordering
    rules; without them the tool-ordering scorer (US-027) has nothing
    to score."""
    ds = validate_dataset_file(DATASETS_DIR / "mule_account.yaml")
    assert len(ds.ordering_constraints) >= 1
    for oc in ds.ordering_constraints:
        assert isinstance(oc, OrderingConstraint)


def test_sanctions_hit_yaml_validates() -> None:
    ds = validate_dataset_file(DATASETS_DIR / "sanctions_hit.yaml")
    assert ds.id == "sanctions_hit"
    assert ds.scenario == "sanctions_hit"
    assert ds.expected_verdict == "high_risk"
    # The sanctions case MUST fan out through the sanctions surface +
    # the kyc cross-check; otherwise the screening-evidence chain is
    # incomplete.
    servers = {tc.server for tc in ds.expected_tool_calls}
    assert {"sanctions", "kyc", "customer_data"}.issubset(servers)
    # The sanctions surface specifically must include both screen_name
    # and get_watchlist_hit so the agent both finds AND inspects hits.
    sanctions_tools = {
        tc.tool for tc in ds.expected_tool_calls if tc.server == "sanctions"
    }
    assert {"screen_name", "get_watchlist_hit"}.issubset(sanctions_tools)


def test_account_takeover_yaml_validates() -> None:
    ds = validate_dataset_file(DATASETS_DIR / "account_takeover.yaml")
    assert ds.id == "account_takeover"
    assert ds.scenario == "ato"
    assert ds.expected_verdict == "high_risk"
    # ATO must touch device history + the transactions surface — the
    # whole typology is the device-change-then-spend correlation.
    pairs = {tc.as_pair() for tc in ds.expected_tool_calls}
    assert ("customer_data", "get_device_history") in pairs
    assert ("transactions", "get_transactions") in pairs
    # Device history must precede the transaction analysis.
    assert any(
        oc.before.as_pair() == ("customer_data", "get_device_history")
        and oc.after.as_pair() == ("transactions", "get_transactions")
        for oc in ds.ordering_constraints
    )


def test_structuring_yaml_validates() -> None:
    ds = validate_dataset_file(DATASETS_DIR / "structuring.yaml")
    assert ds.id == "structuring"
    assert ds.scenario == "structuring"
    assert ds.expected_verdict == "high_risk"
    # Structuring is fundamentally a transactions-velocity typology.
    pairs = {tc.as_pair() for tc in ds.expected_tool_calls}
    assert ("transactions", "flag_velocity_anomalies") in pairs
    assert ("transactions", "get_transactions") in pairs


def test_synthetic_id_yaml_validates() -> None:
    ds = validate_dataset_file(DATASETS_DIR / "synthetic_id.yaml")
    assert ds.id == "synthetic_id"
    assert ds.scenario == "synthetic_id"
    assert ds.expected_verdict == "high_risk"
    # Synthetic-id signal lives in the KYC surface (dob mismatch, thin
    # doc set, shell UBO) plus customer_data cross-check.
    pairs = {tc.as_pair() for tc in ds.expected_tool_calls}
    assert ("customer_data", "get_customer") in pairs
    assert ("kyc", "get_kyc_record") in pairs
    assert ("kyc", "get_ubo_tree") in pairs
    # The kyc cross-check must precede the document fetch — the
    # record carries the document_id list.
    assert any(
        oc.before.as_pair() == ("kyc", "get_kyc_record")
        and oc.after.as_pair() == ("kyc", "get_document")
        for oc in ds.ordering_constraints
    )


def test_all_six_personas_have_a_dataset() -> None:
    """US-026 acceptance: the full launch suite covers every persona
    the mocks bake into deterministic data. If a future PR drops a
    persona this test surfaces the gap immediately."""
    datasets = validate_dataset_dir(DATASETS_DIR)
    scenarios = {ds.scenario for ds in datasets}
    assert scenarios == {
        "clean",
        "mule",
        "sanctions_hit",
        "ato",
        "structuring",
        "synthetic_id",
    }


def test_each_required_fact_pairs_to_an_expected_tool_call() -> None:
    """Schema invariant — but verify it on every shipped YAML so a
    future regression in the cross-field validator is caught
    immediately."""
    for path in sorted(DATASETS_DIR.glob("*.yaml")):
        ds = validate_dataset_file(path)
        expected_pairs = {tc.as_pair() for tc in ds.expected_tool_calls}
        for fact in ds.required_facts:
            assert fact.supporting_tool.as_pair() in expected_pairs, (
                f"{path.name}: required_fact {fact.claim!r} points to "
                f"{fact.supporting_tool.as_pair()} which is not in "
                f"expected_tool_calls"
            )


def test_each_dataset_references_seeded_fixtures() -> None:
    """Every (server, tool) pair in every shipped dataset MUST be
    callable by the load-fixtures script's persona walk (US-024). The
    case_actions surface is excluded because it requires
    human_approval=true and is intentionally out of scope for read-path
    eval datasets — US-025 ships only read-only datasets."""
    for path in sorted(DATASETS_DIR.glob("*.yaml")):
        ds = validate_dataset_file(path)
        for tc in ds.expected_tool_calls:
            assert tc.server != "case_actions", (
                f"{path.name}: references write-path tool "
                f"{tc.as_pair()} — case_actions is out of scope for "
                f"M2 eval datasets per the load-fixtures contract"
            )
            assert tc.tool in ALLOWED_TOOLS[tc.server]


def test_validate_dataset_dir_returns_all_shipped_cases() -> None:
    datasets = validate_dataset_dir(DATASETS_DIR)
    ids = {ds.id for ds in datasets}
    assert {
        "clean_customer",
        "mule_account",
        "sanctions_hit",
        "account_takeover",
        "structuring",
        "synthetic_id",
    }.issubset(ids)


# --------------------------------------------------------------------------- #
# Loader edge cases
# --------------------------------------------------------------------------- #


def test_validate_dataset_file_missing_path_raises(tmp_path: Path) -> None:
    with pytest.raises(EvalSchemaError, match="cannot read"):
        validate_dataset_file(tmp_path / "does-not-exist.yaml")


def test_validate_dataset_file_invalid_yaml_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: :::\n  ::\n", encoding="utf-8")
    with pytest.raises(EvalSchemaError, match="invalid YAML"):
        validate_dataset_file(bad)


def test_validate_dataset_file_non_mapping_top_level(tmp_path: Path) -> None:
    bad = tmp_path / "list.yaml"
    bad.write_text("- just\n- a list\n", encoding="utf-8")
    with pytest.raises(EvalSchemaError, match="must be a mapping"):
        validate_dataset_file(bad)


def test_validate_dataset_dir_no_yamls(tmp_path: Path) -> None:
    with pytest.raises(EvalSchemaError, match="no \\*\\.yaml files"):
        validate_dataset_dir(tmp_path)


def test_validate_dataset_dir_not_a_dir(tmp_path: Path) -> None:
    f = tmp_path / "file.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(EvalSchemaError, match="not a directory"):
        validate_dataset_dir(f)


def test_validate_dataset_dir_stops_at_first_failure(tmp_path: Path) -> None:
    good = tmp_path / "good.yaml"
    good.write_text(yaml.safe_dump(_minimal_dataset()), encoding="utf-8")
    bad = tmp_path / "bad.yaml"
    bad_payload = _minimal_dataset()
    bad_payload["id"] = "Bad-ID"
    bad.write_text(yaml.safe_dump(bad_payload), encoding="utf-8")
    with pytest.raises(EvalSchemaError, match="bad.yaml"):
        validate_dataset_dir(tmp_path)


# --------------------------------------------------------------------------- #
# Makefile / CLI integration
# --------------------------------------------------------------------------- #


def test_validate_cli_returns_zero_for_shipped_datasets(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = validate_main(["--dir", str(DATASETS_DIR)])
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert "validate-evals: OK" in captured.out
    for case_id in (
        "clean_customer",
        "mule_account",
        "sanctions_hit",
        "account_takeover",
        "structuring",
        "synthetic_id",
    ):
        assert case_id in captured.out


def test_validate_cli_returns_nonzero_on_failure(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad_payload = _minimal_dataset()
    bad_payload["scenario"] = "bogus"
    bad.write_text(yaml.safe_dump(bad_payload), encoding="utf-8")
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = validate_main(["--dir", str(tmp_path)])
    assert rc == 1


def test_makefile_target_exists() -> None:
    """``make validate-evals`` must call our CLI. Pin the wiring at
    the file level so a future Makefile edit can't silently drop it."""
    text = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "validate-evals" in text
    assert "evals.validate" in text


def test_make_validate_evals_runs_against_shipped_datasets() -> None:
    """End-to-end smoke: run the CLI as a subprocess against the
    shipped datasets exactly the way ``make validate-evals`` would."""
    result = subprocess.run(
        [sys.executable, "-m", "evals.validate", "--dir", str(DATASETS_DIR)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "validate-evals: OK" in result.stdout


# --------------------------------------------------------------------------- #
# Sanity tools-level: round-tripping the (server, tool) constructors.
# --------------------------------------------------------------------------- #


def test_tool_call_construction_typed() -> None:
    tc = ToolCall(server="customer_data", tool="get_customer")
    assert tc.as_pair() == ("customer_data", "get_customer")


def test_required_fact_construction_typed() -> None:
    fact = RequiredFact(
        claim="x",
        supporting_tool=ToolCall(
            server="customer_data", tool="get_customer"
        ),
    )
    assert fact.claim == "x"
