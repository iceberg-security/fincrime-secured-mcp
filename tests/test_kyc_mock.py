"""Unit tests for mock_apis/kyc (US-013)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mock_apis.customer_data.main import _default_scenario_for as _cust_default
from mock_apis.kyc.main import (
    ALL_SCENARIOS,
    Scenario,
    _default_scenario_for,
    create_app,
)
from mock_apis.transactions.main import (
    _default_scenario_for as _tx_default,
)


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app())


# --------------------------------------------------------------------------- #
# Determinism                                                                 #
# --------------------------------------------------------------------------- #


def test_get_kyc_is_deterministic_for_same_id(client: TestClient) -> None:
    a = client.get("/customers/cust_42/kyc").json()
    b = client.get("/customers/cust_42/kyc").json()
    assert a == b


def test_list_documents_is_deterministic_for_same_id(client: TestClient) -> None:
    a = client.get("/customers/cust_42/documents").json()
    b = client.get("/customers/cust_42/documents").json()
    assert a == b


def test_get_ubo_is_deterministic_for_same_id(client: TestClient) -> None:
    a = client.get("/customers/cust_42/ubo").json()
    b = client.get("/customers/cust_42/ubo").json()
    assert a == b


def test_different_ids_yield_different_kyc(client: TestClient) -> None:
    a = client.get("/customers/cust_alpha/kyc").json()
    b = client.get("/customers/cust_beta/kyc").json()
    assert a["customer_id"] != b["customer_id"]
    # At least one field should differ — same scenario default is fine.
    assert (a["full_name"], a["dob"]) != (b["full_name"], b["dob"])


def test_same_id_same_scenario_is_deterministic(client: TestClient) -> None:
    a = client.get("/customers/cust_42/kyc", params={"scenario": "mule"}).json()
    b = client.get("/customers/cust_42/kyc", params={"scenario": "mule"}).json()
    assert a == b


# --------------------------------------------------------------------------- #
# Cross-mock consistency                                                      #
# --------------------------------------------------------------------------- #


def test_default_scenario_agrees_with_customer_data_mock() -> None:
    """The implicit ?scenario= default must match customer_data's choice."""
    for cust in ("cust_1", "cust_alpha", "cust_xyz", "cust_42"):
        assert _default_scenario_for(cust).value == _cust_default(cust).value


def test_default_scenario_agrees_with_transactions_mock() -> None:
    """Three mocks, one default-scenario salt. If this fails, the cross-mock
    contract has drifted."""
    for cust in ("cust_1", "cust_alpha", "cust_xyz", "cust_42"):
        assert _default_scenario_for(cust).value == _tx_default(cust).value


def test_synthetic_id_dob_mismatch_against_customer_data(client: TestClient) -> None:
    """The deliberate cross-mock inconsistency for synthetic_id.

    customer_data plants year+1 on its profile dob. kyc reports the unshifted
    dob. An investigator joining the two records sees the gap; this test pins
    that gap so a future "fix" doesn't accidentally normalize it out.
    """
    from fastapi.testclient import TestClient as CustClient

    from mock_apis.customer_data.main import create_app as create_cust_app

    cust_client = CustClient(create_cust_app())
    for cust in ("cust_synth_1", "cust_synth_2", "cust_42"):
        kyc = client.get(
            f"/customers/{cust}/kyc", params={"scenario": "synthetic_id"}
        ).json()
        prof = cust_client.get(
            f"/customers/{cust}", params={"scenario": "synthetic_id"}
        ).json()
        kyc_year = int(kyc["dob"].split("-")[0])
        prof_year = int(prof["dob"].split("-")[0])
        assert prof_year == kyc_year + 1, (
            f"customer_data profile dob should be one year after kyc dob for "
            f"synthetic_id (got prof={prof_year} kyc={kyc_year})"
        )
        # And the kyc record surfaces the mismatch explicitly.
        assert "ssn_dob_mismatch" in kyc["inconsistencies"]


def test_kyc_full_name_matches_customer_data_for_same_id(client: TestClient) -> None:
    """Same `customer_id` -> same person across mocks (name seeds are shared)."""
    from fastapi.testclient import TestClient as CustClient

    from mock_apis.customer_data.main import create_app as create_cust_app

    cust_client = CustClient(create_cust_app())
    for cust in ("cust_1", "cust_alpha", "cust_xyz"):
        kyc = client.get(f"/customers/{cust}/kyc", params={"scenario": "clean"}).json()
        prof = cust_client.get(f"/customers/{cust}", params={"scenario": "clean"}).json()
        assert kyc["full_name"] == prof["full_name"]


# --------------------------------------------------------------------------- #
# Scenarios                                                                   #
# --------------------------------------------------------------------------- #


def test_all_scenarios_are_supported(client: TestClient) -> None:
    for scen in ALL_SCENARIOS:
        resp = client.get(
            "/customers/cust_42/kyc", params={"scenario": scen.value}
        )
        assert resp.status_code == 200, f"scenario {scen.value} failed: {resp.text}"
        payload = resp.json()
        assert payload["scenario"] == scen.value


def test_sanctions_hit_sets_pep_and_sanctions_match(client: TestClient) -> None:
    rec = client.get(
        "/customers/cust_42/kyc", params={"scenario": "sanctions_hit"}
    ).json()
    assert rec["pep_flag"] is True
    assert rec["sanctions_match"] is True
    assert rec["kyc_status"] == "needs_review"
    assert "politically_exposed_person" in rec["inconsistencies"]
    assert "sanctions_screening_match" in rec["inconsistencies"]
    # And the issuer country comes from the high-risk set.
    assert rec["issuer_country"] in {"IR", "KP", "SY", "CU", "VE"}


def test_synthetic_id_surfaces_inconsistencies(client: TestClient) -> None:
    rec = client.get(
        "/customers/cust_42/kyc", params={"scenario": "synthetic_id"}
    ).json()
    assert rec["kyc_status"] == "needs_review"
    assert "ssn_dob_mismatch" in rec["inconsistencies"]
    assert "thin_credit_file" in rec["inconsistencies"]


def test_clean_scenario_is_verified_with_no_inconsistencies(
    client: TestClient,
) -> None:
    rec = client.get("/customers/cust_42/kyc", params={"scenario": "clean"}).json()
    assert rec["kyc_status"] == "verified"
    assert rec["inconsistencies"] == []
    assert rec["pep_flag"] is False
    assert rec["sanctions_match"] is False


def test_mule_scenario_has_recent_kyc_refresh(client: TestClient) -> None:
    rec = client.get("/customers/cust_42/kyc", params={"scenario": "mule"}).json()
    assert rec["verified_at_year"] == 2024
    assert "recent_kyc_refresh" in rec["inconsistencies"]


def test_ato_scenario_flags_device_change(client: TestClient) -> None:
    rec = client.get("/customers/cust_42/kyc", params={"scenario": "ato"}).json()
    assert "device_change_post_kyc" in rec["inconsistencies"]


def test_structuring_scenario_recommends_refresh(client: TestClient) -> None:
    rec = client.get(
        "/customers/cust_42/kyc", params={"scenario": "structuring"}
    ).json()
    assert "kyc_refresh_recommended" in rec["inconsistencies"]


def test_scenarios_produce_distinct_kyc_signatures(client: TestClient) -> None:
    """No two scenarios should collapse to the same kyc signature."""
    seen: set[tuple] = set()
    for scen in ALL_SCENARIOS:
        rec = client.get(
            "/customers/cust_42/kyc", params={"scenario": scen.value}
        ).json()
        sig = (
            rec["kyc_status"],
            rec["pep_flag"],
            rec["sanctions_match"],
            tuple(sorted(rec["inconsistencies"])),
        )
        assert sig not in seen, f"{scen.value} duplicates another scenario"
        seen.add(sig)


# --------------------------------------------------------------------------- #
# Documents                                                                   #
# --------------------------------------------------------------------------- #


def test_documents_list_for_clean_has_three(client: TestClient) -> None:
    docs = client.get(
        "/customers/cust_42/documents", params={"scenario": "clean"}
    ).json()["documents"]
    assert len(docs) == 3
    kinds = {d["document_id"].rsplit("_", 1)[-1] for d in docs}
    assert kinds == {"id", "address", "selfie"}


def test_documents_list_for_synthetic_id_is_thin(client: TestClient) -> None:
    docs = client.get(
        "/customers/cust_42/documents", params={"scenario": "synthetic_id"}
    ).json()["documents"]
    assert len(docs) == 1
    assert docs[0]["document_id"].endswith("_id")
    # synthetic_id near-expired contract
    assert docs[0]["expiry_year"] == 2025


def test_get_specific_document_by_id(client: TestClient) -> None:
    docs = client.get(
        "/customers/cust_42/documents", params={"scenario": "clean"}
    ).json()["documents"]
    target_id = docs[0]["document_id"]
    doc = client.get(
        f"/customers/cust_42/documents/{target_id}", params={"scenario": "clean"}
    ).json()
    assert doc == docs[0]


def test_get_unknown_document_returns_404(client: TestClient) -> None:
    resp = client.get(
        "/customers/cust_42/documents/doc_does_not_exist",
        params={"scenario": "clean"},
    )
    assert resp.status_code == 404


def test_sanctions_hit_id_doc_has_high_risk_issuer(client: TestClient) -> None:
    docs = client.get(
        "/customers/cust_42/documents", params={"scenario": "sanctions_hit"}
    ).json()["documents"]
    id_doc = next(d for d in docs if d["document_id"].endswith("_id"))
    assert id_doc["issuer_country"] in {"IR", "KP", "SY", "CU", "VE"}


# --------------------------------------------------------------------------- #
# UBO                                                                         #
# --------------------------------------------------------------------------- #


def test_default_ubo_is_trivial_self_owned(client: TestClient) -> None:
    ubo = client.get("/customers/cust_42/ubo", params={"scenario": "clean"}).json()
    assert ubo["entity_type"] == "natural_person"
    assert len(ubo["owners"]) == 1
    owner = ubo["owners"][0]
    assert owner["owner_type"] == "natural_person"
    assert owner["ownership_pct"] == 100
    assert owner["is_natural_person_at_top"] is True
    assert owner["layers"] == []
    assert ubo["flags"] == []


def test_synthetic_id_ubo_is_layered_shell(client: TestClient) -> None:
    ubo = client.get(
        "/customers/cust_42/ubo", params={"scenario": "synthetic_id"}
    ).json()
    owner = ubo["owners"][0]
    assert owner["is_natural_person_at_top"] is False
    assert len(owner["layers"]) >= 2
    # All layers should be entities, not natural persons.
    for layer in owner["layers"]:
        assert layer["owner_type"] == "entity"
    assert "no_natural_person_at_top" in ubo["flags"]
    assert "multi_layer_ownership" in ubo["flags"]


def test_sanctions_hit_ubo_has_pep_at_top(client: TestClient) -> None:
    ubo = client.get(
        "/customers/cust_42/ubo", params={"scenario": "sanctions_hit"}
    ).json()
    assert "pep_at_top" in ubo["flags"]
    owner = ubo["owners"][0]
    assert owner.get("pep_flag") is True
    assert owner["country"] in {"IR", "KP", "SY", "CU", "VE"}


# --------------------------------------------------------------------------- #
# Error handling                                                              #
# --------------------------------------------------------------------------- #


def test_unknown_scenario_returns_400(client: TestClient) -> None:
    resp = client.get(
        "/customers/cust_42/kyc", params={"scenario": "not_a_real_scenario"}
    )
    assert resp.status_code == 400
    assert "not_a_real_scenario" in resp.json()["detail"]


def test_default_scenario_is_deterministic_per_customer(client: TestClient) -> None:
    a = client.get("/customers/cust_42/kyc").json()
    b = client.get("/customers/cust_42/kyc").json()
    assert a["scenario"] == b["scenario"]
    assert a["scenario"] in {s.value for s in Scenario}


def test_consistency_across_kyc_endpoints_for_same_call(client: TestClient) -> None:
    """kyc, documents, ubo all agree on the scenario tag."""
    cust = "cust_xyz"
    scenario = "sanctions_hit"
    rec = client.get(f"/customers/{cust}/kyc", params={"scenario": scenario}).json()
    docs = client.get(
        f"/customers/{cust}/documents", params={"scenario": scenario}
    ).json()
    ubo = client.get(f"/customers/{cust}/ubo", params={"scenario": scenario}).json()
    assert rec["scenario"] == scenario
    assert docs["scenario"] == scenario
    assert ubo["scenario"] == scenario
    for d in docs["documents"]:
        assert d["customer_id"] == cust
        assert d["scenario"] == scenario


# --------------------------------------------------------------------------- #
# Health                                                                      #
# --------------------------------------------------------------------------- #


def test_healthz_reports_ok(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# --------------------------------------------------------------------------- #
# Zero external deps — sanity check                                           #
# --------------------------------------------------------------------------- #


def test_module_has_no_runtime_io_imports() -> None:
    """The mock module must not pull in sqlite/httpx/etc."""
    import importlib

    mod = importlib.import_module("mock_apis.kyc.main")
    source = mod.__loader__.get_source("mock_apis.kyc.main")  # type: ignore[union-attr]
    assert source is not None
    forbidden = ("import sqlite3", "import httpx", "import psycopg", "import requests")
    for needle in forbidden:
        assert needle not in source, f"unexpected runtime IO import: {needle}"
