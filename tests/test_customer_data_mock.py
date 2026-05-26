"""Unit tests for mock_apis/customer_data (US-008)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mock_apis.customer_data.main import ALL_SCENARIOS, Scenario, create_app


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app())


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #


def test_get_customer_is_deterministic_for_same_id(client: TestClient) -> None:
    """Same customer_id (no scenario override) -> identical payload across calls."""
    a = client.get("/customers/cust_42").json()
    b = client.get("/customers/cust_42").json()
    assert a == b


def test_list_accounts_is_deterministic_for_same_id(client: TestClient) -> None:
    a = client.get("/customers/cust_42/accounts").json()
    b = client.get("/customers/cust_42/accounts").json()
    assert a == b


def test_list_devices_is_deterministic_for_same_id(client: TestClient) -> None:
    a = client.get("/customers/cust_42/devices").json()
    b = client.get("/customers/cust_42/devices").json()
    assert a == b


def test_different_ids_yield_different_profiles(client: TestClient) -> None:
    a = client.get("/customers/cust_alpha").json()
    b = client.get("/customers/cust_beta").json()
    # Customer IDs differ, so at minimum the customer_id field differs;
    # but in practice the seed shifts other fields too.
    assert a["customer_id"] != b["customer_id"]
    differing_fields = {
        k for k in a if k != "customer_id" and a.get(k) != b.get(k)
    }
    assert differing_fields, "different IDs should yield differing payloads"


def test_same_id_same_scenario_is_deterministic(client: TestClient) -> None:
    """Pinning the scenario also gives stable output."""
    a = client.get("/customers/cust_42", params={"scenario": "mule"}).json()
    b = client.get("/customers/cust_42", params={"scenario": "mule"}).json()
    assert a == b


# --------------------------------------------------------------------------- #
# Scenarios return distinct shapes
# --------------------------------------------------------------------------- #


def test_all_scenarios_are_supported(client: TestClient) -> None:
    for scen in ALL_SCENARIOS:
        resp = client.get(
            "/customers/cust_42", params={"scenario": scen.value}
        )
        assert resp.status_code == 200, f"scenario {scen.value} failed: {resp.text}"
        payload = resp.json()
        assert payload["scenario"] == scen.value


def test_clean_vs_sanctions_hit_diverge_meaningfully(client: TestClient) -> None:
    clean = client.get(
        "/customers/cust_42", params={"scenario": "clean"}
    ).json()
    hit = client.get(
        "/customers/cust_42", params={"scenario": "sanctions_hit"}
    ).json()

    # Sanctions-hit should be flagged and high-risk.
    assert hit["pep"] is True
    assert hit["risk_score"] >= 80
    assert "sanctions_watchlist_possible" in hit["flags"]

    # Clean should be low-risk and not PEP.
    assert clean["pep"] is False
    assert clean["risk_score"] <= 25
    assert clean["flags"] == []


def test_mule_scenario_has_more_accounts_than_clean(client: TestClient) -> None:
    clean = client.get(
        "/customers/cust_mule_test/accounts", params={"scenario": "clean"}
    ).json()["accounts"]
    mule = client.get(
        "/customers/cust_mule_test/accounts", params={"scenario": "mule"}
    ).json()["accounts"]
    assert len(mule) >= len(clean)
    assert len(mule) >= 3  # mule scenario guarantees >=3 accounts


def test_mule_scenario_marks_recent_account_flag(client: TestClient) -> None:
    profile = client.get(
        "/customers/cust_42", params={"scenario": "mule"}
    ).json()
    assert "recent_account" in profile["flags"]


def test_ato_scenario_marks_suspicious_device(client: TestClient) -> None:
    devices = client.get(
        "/customers/cust_ato_test/devices", params={"scenario": "ato"}
    ).json()["devices"]
    # ATO scenario must surface at least one suspicious device.
    assert any(d["suspicious"] for d in devices)


def test_ato_scenario_has_more_devices_than_clean(client: TestClient) -> None:
    clean = client.get(
        "/customers/cust_ato_test/devices", params={"scenario": "clean"}
    ).json()["devices"]
    ato = client.get(
        "/customers/cust_ato_test/devices", params={"scenario": "ato"}
    ).json()["devices"]
    assert len(ato) >= 3
    assert len(ato) >= len(clean)


def test_structuring_scenario_carries_threshold_flag(client: TestClient) -> None:
    profile = client.get(
        "/customers/cust_42", params={"scenario": "structuring"}
    ).json()
    assert "repeated_sub_threshold_cash" in profile["flags"]


def test_synthetic_id_scenario_marks_kyc_needs_review(client: TestClient) -> None:
    profile = client.get(
        "/customers/cust_42", params={"scenario": "synthetic_id"}
    ).json()
    assert profile["kyc_status"] == "needs_review"
    assert "ssn_dob_mismatch" in profile["flags"]


def test_scenarios_produce_distinct_payloads_for_same_customer(
    client: TestClient,
) -> None:
    """Each scenario should give a meaningfully different shape for the same ID."""
    payloads: dict[str, dict] = {}
    for scen in ALL_SCENARIOS:
        payloads[scen.value] = client.get(
            "/customers/cust_42", params={"scenario": scen.value}
        ).json()

    # No two scenarios should produce the exact same payload.
    seen_signatures: set[tuple] = set()
    for scen_name, payload in payloads.items():
        sig = (
            payload["risk_score"],
            payload["kyc_status"],
            payload["pep"],
            tuple(sorted(payload["flags"])),
            payload["scenario"],
        )
        assert sig not in seen_signatures, f"{scen_name} duplicates another scenario"
        seen_signatures.add(sig)


# --------------------------------------------------------------------------- #
# Error handling
# --------------------------------------------------------------------------- #


def test_unknown_scenario_returns_400(client: TestClient) -> None:
    resp = client.get(
        "/customers/cust_42", params={"scenario": "not_a_real_scenario"}
    )
    assert resp.status_code == 400
    assert "not_a_real_scenario" in resp.json()["detail"]


def test_default_scenario_is_deterministic_per_customer(client: TestClient) -> None:
    """Omitting ?scenario picks a stable default keyed off the customer_id."""
    a = client.get("/customers/cust_42").json()
    b = client.get("/customers/cust_42").json()
    assert a["scenario"] == b["scenario"]
    # The chosen default must be one of the known scenarios.
    assert a["scenario"] in {s.value for s in Scenario}


def test_consistency_across_endpoints_for_same_call(client: TestClient) -> None:
    """Profile, accounts, and devices for the same scenario all agree on the scenario tag."""
    cust = "cust_xyz"
    scenario = "mule"
    profile = client.get(f"/customers/{cust}", params={"scenario": scenario}).json()
    accounts = client.get(
        f"/customers/{cust}/accounts", params={"scenario": scenario}
    ).json()
    devices = client.get(
        f"/customers/{cust}/devices", params={"scenario": scenario}
    ).json()
    assert profile["scenario"] == scenario
    assert accounts["scenario"] == scenario
    assert devices["scenario"] == scenario
    # The accounts list should reference the same customer_id as the profile.
    for acct in accounts["accounts"]:
        assert acct["customer_id"] == cust
    for dev in devices["devices"]:
        assert dev["customer_id"] == cust


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #


def test_healthz_reports_ok(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# --------------------------------------------------------------------------- #
# Zero external deps (no DB connection, no network) — sanity check.
# --------------------------------------------------------------------------- #


def test_module_has_no_runtime_io_imports() -> None:
    """Import-time check: the mock module must not pull in sqlite/httpx/etc.

    The mock is supposed to be pure in-memory generation. If a future change
    accidentally adds an external dep here, this test fails fast.
    """
    import importlib

    mod = importlib.import_module("mock_apis.customer_data.main")
    source = mod.__loader__.get_source("mock_apis.customer_data.main")  # type: ignore[union-attr]
    assert source is not None
    forbidden = ("import sqlite3", "import httpx", "import psycopg", "import requests")
    for needle in forbidden:
        assert needle not in source, f"unexpected runtime IO import: {needle}"
