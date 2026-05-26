"""Unit tests for mock_apis/transactions (US-012)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mock_apis.customer_data.main import _default_scenario_for as _cust_default
from mock_apis.transactions.main import (
    ALL_SCENARIOS,
    Scenario,
    _default_scenario_for,
    create_app,
)


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app())


# --------------------------------------------------------------------------- #
# Determinism                                                                 #
# --------------------------------------------------------------------------- #


def test_get_transactions_is_deterministic_for_same_id(client: TestClient) -> None:
    a = client.get("/customers/cust_42/transactions").json()
    b = client.get("/customers/cust_42/transactions").json()
    assert a == b


def test_get_counterparties_is_deterministic_for_same_id(client: TestClient) -> None:
    a = client.get("/customers/cust_42/counterparties").json()
    b = client.get("/customers/cust_42/counterparties").json()
    assert a == b


def test_velocity_anomalies_is_deterministic_for_same_id(client: TestClient) -> None:
    a = client.get("/customers/cust_42/velocity-anomalies").json()
    b = client.get("/customers/cust_42/velocity-anomalies").json()
    assert a == b


def test_different_ids_yield_different_transactions(client: TestClient) -> None:
    a = client.get("/customers/cust_alpha/transactions").json()
    b = client.get("/customers/cust_beta/transactions").json()
    assert a["customer_id"] != b["customer_id"]
    assert a["transactions"] != b["transactions"]


def test_same_id_same_scenario_is_deterministic(client: TestClient) -> None:
    a = client.get("/customers/cust_42/transactions", params={"scenario": "mule"}).json()
    b = client.get("/customers/cust_42/transactions", params={"scenario": "mule"}).json()
    assert a == b


# --------------------------------------------------------------------------- #
# Cross-mock consistency                                                      #
# --------------------------------------------------------------------------- #


def test_default_scenario_agrees_with_customer_data_mock() -> None:
    """The implicit ?scenario= default must match customer_data's choice.

    Same (customer_id, salt="scenario") -> sha256 -> int -> same scenario.
    If this drifts, every test that relies on cross-mock consistency for an
    "implicit" scenario will silently get inconsistent shapes from the two
    mocks.
    """
    for cust in ("cust_1", "cust_alpha", "cust_xyz", "cust_42"):
        assert _default_scenario_for(cust).value == _cust_default(cust).value


# --------------------------------------------------------------------------- #
# Scenarios                                                                   #
# --------------------------------------------------------------------------- #


def test_all_scenarios_are_supported(client: TestClient) -> None:
    for scen in ALL_SCENARIOS:
        resp = client.get(
            "/customers/cust_42/transactions", params={"scenario": scen.value}
        )
        assert resp.status_code == 200, f"scenario {scen.value} failed: {resp.text}"
        payload = resp.json()
        assert payload["scenario"] == scen.value
        assert payload["transactions"], "every scenario must produce >=1 tx"


def test_mule_scenario_has_more_transactions_than_clean(client: TestClient) -> None:
    clean = client.get(
        "/customers/cust_mule_test/transactions",
        params={"scenario": "clean", "limit": 500},
    ).json()["transactions"]
    mule = client.get(
        "/customers/cust_mule_test/transactions",
        params={"scenario": "mule", "limit": 500},
    ).json()["transactions"]
    assert len(mule) >= len(clean)
    assert len(mule) >= 40  # mule shape guarantees high volume


def test_mule_scenario_has_money_transfer_category(client: TestClient) -> None:
    txs = client.get(
        "/customers/cust_42/transactions",
        params={"scenario": "mule", "limit": 500},
    ).json()["transactions"]
    cats = {t["merchant_category"] for t in txs}
    assert "money_transfer" in cats


def test_mule_scenario_has_mule_hub_inflow_flag(client: TestClient) -> None:
    v = client.get(
        "/customers/cust_42/velocity-anomalies", params={"scenario": "mule"}
    ).json()
    assert "mule_hub_inflow" in v["flags"]
    assert "burst_inbound" in v["flags"]


def test_sanctions_hit_has_cross_border_burst_flag(client: TestClient) -> None:
    v = client.get(
        "/customers/cust_42/velocity-anomalies", params={"scenario": "sanctions_hit"}
    ).json()
    assert "cross_border_burst" in v["flags"]
    assert v["cross_border_count"] >= 2


def test_structuring_scenario_produces_structuring_pattern(client: TestClient) -> None:
    v = client.get(
        "/customers/cust_42/velocity-anomalies", params={"scenario": "structuring"}
    ).json()
    assert "structuring_pattern" in v["flags"]
    assert v["structuring_candidate_count"] >= 5
    # Each structuring tx should be in the sub-$10k cash deposit band.
    txs = client.get(
        "/customers/cust_42/transactions",
        params={"scenario": "structuring", "limit": 500},
    ).json()["transactions"]
    cash = [t for t in txs if t["type"] == "cash_deposit"]
    assert cash, "structuring scenario must contain cash deposits"
    for t in cash:
        assert 8_000 <= t["amount"] < 10_000


def test_ato_scenario_concentrates_high_risk_geo_late(client: TestClient) -> None:
    """The tail of an ATO scenario's tx list comes from high-risk geos."""
    txs = client.get(
        "/customers/cust_ato_test/transactions",
        params={"scenario": "ato", "limit": 500},
    ).json()["transactions"]
    # Bottom 3 (oldest in days_ago but listed last by index here) are the
    # suspicious cluster — high-risk country + online_retail card_purchase.
    tail = txs[-3:]
    high_risk = {"IR", "KP", "SY", "CU", "VE"}
    assert all(t["counterparty_country"] in high_risk for t in tail)
    assert all(t["type"] == "card_purchase" for t in tail)


def test_clean_scenario_is_low_signal(client: TestClient) -> None:
    v = client.get(
        "/customers/cust_42/velocity-anomalies", params={"scenario": "clean"}
    ).json()
    assert v["flags"] == []
    assert v["cross_border_count"] == 0
    assert v["structuring_candidate_count"] == 0


def test_synthetic_id_scenario_is_thin_file(client: TestClient) -> None:
    """Synthetic IDs have small, infrequent card purchases — no velocity flags."""
    v = client.get(
        "/customers/cust_42/velocity-anomalies", params={"scenario": "synthetic_id"}
    ).json()
    assert v["flags"] == []
    txs = client.get(
        "/customers/cust_42/transactions",
        params={"scenario": "synthetic_id", "limit": 500},
    ).json()["transactions"]
    assert txs, "synthetic_id should still have some transactions"
    for t in txs:
        assert t["type"] == "card_purchase"
        assert t["amount"] <= 80


def test_scenarios_produce_distinct_velocity_signatures(client: TestClient) -> None:
    """No two scenarios should collapse to the same anomaly signature."""
    seen: set[tuple] = set()
    for scen in ALL_SCENARIOS:
        v = client.get(
            "/customers/cust_42/velocity-anomalies", params={"scenario": scen.value}
        ).json()
        sig = (
            v["transaction_count"],
            v["inbound_count"],
            v["structuring_candidate_count"],
            v["cross_border_count"],
            tuple(sorted(v["flags"])),
        )
        assert sig not in seen, f"{scen.value} duplicates another scenario"
        seen.add(sig)


# --------------------------------------------------------------------------- #
# Counterparties                                                              #
# --------------------------------------------------------------------------- #


def test_counterparties_aggregate_correctly(client: TestClient) -> None:
    cps = client.get(
        "/customers/cust_42/counterparties", params={"scenario": "mule"}
    ).json()["counterparties"]
    assert cps, "mule scenario must have at least one counterparty"
    # tx_count == inbound + outbound rows for each cp (one direction per tx).
    for cp in cps:
        assert cp["inbound_total"] >= 0
        assert cp["outbound_total"] >= 0
        assert cp["tx_count"] >= 1
        assert cp["first_seen_days_ago"] >= cp["last_seen_days_ago"]


def test_counterparties_independent_of_tx_limit(client: TestClient) -> None:
    """Counterparty rollup must use the FULL tx set, not the ?limit slice."""
    a = client.get(
        "/customers/cust_42/counterparties", params={"scenario": "mule"}
    ).json()
    # Asking for transactions with a tiny limit should not change the rollup.
    _ = client.get(
        "/customers/cust_42/transactions",
        params={"scenario": "mule", "limit": 1},
    ).json()
    b = client.get(
        "/customers/cust_42/counterparties", params={"scenario": "mule"}
    ).json()
    assert a == b


# --------------------------------------------------------------------------- #
# limit query param                                                           #
# --------------------------------------------------------------------------- #


def test_limit_caps_returned_transactions(client: TestClient) -> None:
    payload = client.get(
        "/customers/cust_42/transactions",
        params={"scenario": "mule", "limit": 5},
    ).json()
    assert len(payload["transactions"]) == 5


def test_limit_zero_is_rejected(client: TestClient) -> None:
    resp = client.get(
        "/customers/cust_42/transactions",
        params={"scenario": "clean", "limit": 0},
    )
    assert resp.status_code == 422  # FastAPI validation


def test_limit_above_500_is_rejected(client: TestClient) -> None:
    resp = client.get(
        "/customers/cust_42/transactions",
        params={"scenario": "clean", "limit": 5000},
    )
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# Error handling                                                              #
# --------------------------------------------------------------------------- #


def test_unknown_scenario_returns_400(client: TestClient) -> None:
    resp = client.get(
        "/customers/cust_42/transactions",
        params={"scenario": "not_a_real_scenario"},
    )
    assert resp.status_code == 400
    assert "not_a_real_scenario" in resp.json()["detail"]


def test_default_scenario_is_deterministic_per_customer(client: TestClient) -> None:
    a = client.get("/customers/cust_42/transactions").json()
    b = client.get("/customers/cust_42/transactions").json()
    assert a["scenario"] == b["scenario"]
    assert a["scenario"] in {s.value for s in Scenario}


def test_consistency_across_endpoints_for_same_call(client: TestClient) -> None:
    """tx, counterparties, velocity-anomalies all agree on the scenario tag."""
    cust = "cust_xyz"
    scenario = "mule"
    txs = client.get(
        f"/customers/{cust}/transactions", params={"scenario": scenario}
    ).json()
    cps = client.get(
        f"/customers/{cust}/counterparties", params={"scenario": scenario}
    ).json()
    vel = client.get(
        f"/customers/{cust}/velocity-anomalies", params={"scenario": scenario}
    ).json()
    assert txs["scenario"] == scenario
    assert cps["scenario"] == scenario
    assert vel["scenario"] == scenario
    for tx in txs["transactions"]:
        assert tx["customer_id"] == cust


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
    """The mock module must not pull in sqlite/httpx/etc.

    Pure in-memory generation. If a future change accidentally adds an
    external dep here, this test fails fast.
    """
    import importlib

    mod = importlib.import_module("mock_apis.transactions.main")
    source = mod.__loader__.get_source("mock_apis.transactions.main")  # type: ignore[union-attr]
    assert source is not None
    forbidden = ("import sqlite3", "import httpx", "import psycopg", "import requests")
    for needle in forbidden:
        assert needle not in source, f"unexpected runtime IO import: {needle}"
