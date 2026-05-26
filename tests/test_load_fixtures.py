"""Tests for scripts/load_fixtures.py (US-024).

These are structural tests: they verify that the script declares the six
scenario personas + the cross-server read loop, and that ``_build_arguments``
shapes the call args correctly for each persona. End-to-end testing of the
script against the live compose stack lives in the manual cold-start
benchmark — see README "Cold-start benchmark".
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "load_fixtures.py"


def _import_script() -> object:
    spec = importlib.util.spec_from_file_location("load_fixtures", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["load_fixtures"] = module
    spec.loader.exec_module(module)
    return module


def test_personas_cover_all_six_scenarios() -> None:
    mod = _import_script()
    personas = {p for p, _ in mod.PERSONAS}  # type: ignore[attr-defined]
    assert personas == {
        "clean",
        "mule",
        "sanctions_hit",
        "ato",
        "structuring",
        "synthetic_id",
    }


def test_read_calls_cover_every_read_only_server() -> None:
    mod = _import_script()
    servers = {server for server, _, _ in mod.READ_CALLS}  # type: ignore[attr-defined]
    # case_actions is intentionally excluded — write-path.
    assert servers == {"customer_data", "transactions", "kyc", "sanctions", "osint"}


def test_read_calls_excludes_case_actions() -> None:
    mod = _import_script()
    assert all(
        server != "case_actions" for server, _, _ in mod.READ_CALLS  # type: ignore[attr-defined]
    ), "load_fixtures must not call case_actions (write-path, needs human_approval)"


def test_build_arguments_substitutes_name_for_screen_tools() -> None:
    mod = _import_script()
    args = mod._build_arguments(  # type: ignore[attr-defined]
        {"_uses_name": True}, "cust-001", "sanctions_hit"
    )
    assert "name" in args
    assert "customer_id" not in args
    assert args["scenario"] == "sanctions_hit"


def test_build_arguments_substitutes_query_for_web_search() -> None:
    mod = _import_script()
    args = mod._build_arguments(  # type: ignore[attr-defined]
        {"_uses_name_as_query": True}, "cust-001", "clean"
    )
    assert "query" in args
    assert "customer_id" not in args


def test_build_arguments_substitutes_company_for_lookup_company() -> None:
    mod = _import_script()
    args = mod._build_arguments(  # type: ignore[attr-defined]
        {"_uses_company": True}, "cust-001", "mule"
    )
    assert "company_name" in args
    assert "customer_id" not in args


def test_build_arguments_default_keeps_customer_id() -> None:
    mod = _import_script()
    args = mod._build_arguments(  # type: ignore[attr-defined]
        {"limit": 50}, "cust-001", "ato"
    )
    assert args["customer_id"] == "cust-001"
    assert args["scenario"] == "ato"
    assert args["limit"] == 50
