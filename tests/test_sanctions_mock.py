"""Unit tests for mock_apis/sanctions (US-014)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mock_apis.customer_data.main import create_app as create_cust_app
from mock_apis.kyc.main import create_app as create_kyc_app
from mock_apis.sanctions.main import (
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


def test_screen_name_is_deterministic_for_same_input(client: TestClient) -> None:
    a = client.get(
        "/screen/name", params={"name": "Alice Smith", "scenario": "sanctions_hit"}
    ).json()
    b = client.get(
        "/screen/name", params={"name": "Alice Smith", "scenario": "sanctions_hit"}
    ).json()
    assert a == b


def test_screen_entity_is_deterministic_for_same_input(client: TestClient) -> None:
    a = client.get(
        "/screen/entity",
        params={"entity_name": "Acme Holdings", "scenario": "sanctions_hit"},
    ).json()
    b = client.get(
        "/screen/entity",
        params={"entity_name": "Acme Holdings", "scenario": "sanctions_hit"},
    ).json()
    assert a == b


def test_get_hit_is_deterministic_for_same_id(client: TestClient) -> None:
    screen = client.get(
        "/screen/name",
        params={"name": "Alice Smith", "scenario": "sanctions_hit"},
    ).json()
    hit_id = screen["hits"][0]["hit_id"]
    a = client.get(f"/hits/{hit_id}").json()
    b = client.get(f"/hits/{hit_id}").json()
    assert a == b


def test_different_names_yield_different_hits(client: TestClient) -> None:
    a = client.get(
        "/screen/name", params={"name": "Alice Smith", "scenario": "sanctions_hit"}
    ).json()
    b = client.get(
        "/screen/name", params={"name": "Bob Jones", "scenario": "sanctions_hit"}
    ).json()
    assert a["hits"][0]["hit_id"] != b["hits"][0]["hit_id"]


# --------------------------------------------------------------------------- #
# Scenarios                                                                   #
# --------------------------------------------------------------------------- #


def test_all_scenarios_are_supported_for_screen_name(client: TestClient) -> None:
    for scen in ALL_SCENARIOS:
        resp = client.get(
            "/screen/name", params={"name": "Alice Smith", "scenario": scen.value}
        )
        assert resp.status_code == 200, f"scenario {scen.value} failed"
        payload = resp.json()
        assert payload["scenario"] == scen.value


def test_only_sanctions_hit_produces_real_matches(client: TestClient) -> None:
    """Every other scenario must screen clean (matched=false, no hits)."""
    for scen in ALL_SCENARIOS:
        if scen == Scenario.SANCTIONS_HIT:
            continue
        result = client.get(
            "/screen/name", params={"name": "Alice Smith", "scenario": scen.value}
        ).json()
        assert result["matched"] is False, f"scenario {scen.value} produced a hit"
        assert result["hits"] == [], f"scenario {scen.value} produced hits"


def test_sanctions_hit_produces_at_least_one_hit(client: TestClient) -> None:
    result = client.get(
        "/screen/name",
        params={"name": "Alice Smith", "scenario": "sanctions_hit"},
    ).json()
    assert result["matched"] is True
    assert len(result["hits"]) >= 1


def test_sanctions_hit_shape(client: TestClient) -> None:
    result = client.get(
        "/screen/name",
        params={"name": "Alice Smith", "scenario": "sanctions_hit"},
    ).json()
    hit = result["hits"][0]
    assert hit["queried_name"] == "Alice Smith"
    assert hit["listed_name"] == "Alice Smith"
    assert hit["entity_type"] == "natural_person"
    assert hit["program"] in {
        "OFAC_SDN",
        "EU_CONSOLIDATED",
        "UN_SANCTIONS",
        "UK_HMT",
    }
    assert hit["hit_type"] in {"sdn_match", "pep_match", "adverse_media"}
    assert 82 <= hit["match_score"] <= 99
    assert hit["country"] in {"IR", "KP", "SY", "CU", "VE", "RU"}
    assert hit["aliases"]
    assert isinstance(hit["addresses"], list)
    assert hit["addresses"][0]["country"] == hit["country"]


def test_screen_entity_sanctions_hit_sets_entity_type(client: TestClient) -> None:
    result = client.get(
        "/screen/entity",
        params={
            "entity_name": "Shell Holdings Ltd",
            "scenario": "sanctions_hit",
        },
    ).json()
    assert result["matched"] is True
    hit = result["hits"][0]
    assert hit["entity_type"] == "entity"


def test_clean_screen_has_empty_hits(client: TestClient) -> None:
    result = client.get(
        "/screen/name",
        params={"name": "Alice Smith", "scenario": "clean"},
    ).json()
    assert result["matched"] is False
    assert result["hits"] == []


# --------------------------------------------------------------------------- #
# Hit detail lookup                                                           #
# --------------------------------------------------------------------------- #


def test_get_hit_returns_full_record(client: TestClient) -> None:
    screen = client.get(
        "/screen/name",
        params={"name": "Alice Smith", "scenario": "sanctions_hit"},
    ).json()
    hit_id = screen["hits"][0]["hit_id"]
    detail = client.get(f"/hits/{hit_id}").json()
    # Same id, same hit shape — every screening field is reproducible from
    # the hit_id alone (the contract that lets investigators re-resolve hits).
    for field in (
        "hit_id",
        "program",
        "hit_type",
        "listed_on",
        "country",
        "match_score",
        "aliases",
        "addresses",
    ):
        assert field in detail
    assert detail["hit_id"] == hit_id


def test_get_unknown_hit_returns_404(client: TestClient) -> None:
    resp = client.get("/hits/hit_does_not_exist")
    assert resp.status_code == 404


def test_get_hit_with_non_sanctions_scenario_404(client: TestClient) -> None:
    """A well-formed hit_id whose scenario is not sanctions_hit is 404.

    The mock never emits such an id from /screen — only sanctions_hit
    produces hits. Anyone constructing one by hand is asking for trouble; the
    detail endpoint must refuse it.
    """
    resp = client.get("/hits/hit_clean_alice_smith_00")
    assert resp.status_code == 404


def test_get_hit_with_malformed_id_404(client: TestClient) -> None:
    resp = client.get("/hits/not_a_real_hit_id")
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Cross-mock consistency                                                      #
# --------------------------------------------------------------------------- #


def test_default_scenario_is_deterministic_per_name() -> None:
    for name in ("Alice Smith", "Bob Jones", "Carol Brown"):
        assert _default_scenario_for(name) == _default_scenario_for(name)


def test_sanctions_hit_screens_same_person_as_customer_data_and_kyc() -> None:
    """Cross-mock contract.

    A customer flagged in customer_data (``sanctions_watchlist_possible``)
    and in kyc (``sanctions_match=true``) MUST screen with a real hit on the
    sanctions mock when the caller passes the same full_name.
    """
    cust_client = TestClient(create_cust_app())
    kyc_client = TestClient(create_kyc_app())
    sanctions_client = TestClient(create_app())

    for customer_id in ("cust_42", "cust_alpha", "cust_xyz"):
        profile = cust_client.get(
            f"/customers/{customer_id}", params={"scenario": "sanctions_hit"}
        ).json()
        kyc = kyc_client.get(
            f"/customers/{customer_id}/kyc", params={"scenario": "sanctions_hit"}
        ).json()
        # Names match across the two upstream mocks by design.
        assert profile["full_name"] == kyc["full_name"], customer_id

        screen = sanctions_client.get(
            "/screen/name",
            params={
                "name": profile["full_name"],
                "scenario": "sanctions_hit",
            },
        ).json()
        assert screen["matched"] is True, (
            f"customer {customer_id} ({profile['full_name']}) should match "
            "in sanctions_hit but did not"
        )
        assert screen["hits"][0]["queried_name"] == profile["full_name"]


# --------------------------------------------------------------------------- #
# Error handling                                                              #
# --------------------------------------------------------------------------- #


def test_unknown_scenario_returns_400(client: TestClient) -> None:
    resp = client.get(
        "/screen/name",
        params={"name": "Alice Smith", "scenario": "not_a_real_scenario"},
    )
    assert resp.status_code == 400
    assert "not_a_real_scenario" in resp.json()["detail"]


def test_empty_name_returns_422(client: TestClient) -> None:
    resp = client.get("/screen/name", params={"name": ""})
    assert resp.status_code == 422


def test_missing_name_returns_422(client: TestClient) -> None:
    resp = client.get("/screen/name")
    assert resp.status_code == 422


def test_default_scenario_is_stable_per_name(client: TestClient) -> None:
    a = client.get("/screen/name", params={"name": "Alice Smith"}).json()
    b = client.get("/screen/name", params={"name": "Alice Smith"}).json()
    assert a["scenario"] == b["scenario"]
    assert a["scenario"] in {s.value for s in Scenario}


# --------------------------------------------------------------------------- #
# Distinct-scenario signatures                                                #
# --------------------------------------------------------------------------- #


def test_sanctions_hit_distinct_from_clean(client: TestClient) -> None:
    hit_result = client.get(
        "/screen/name",
        params={"name": "Alice Smith", "scenario": "sanctions_hit"},
    ).json()
    clean_result = client.get(
        "/screen/name", params={"name": "Alice Smith", "scenario": "clean"}
    ).json()
    assert hit_result["matched"] != clean_result["matched"]


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

    mod = importlib.import_module("mock_apis.sanctions.main")
    source = mod.__loader__.get_source("mock_apis.sanctions.main")  # type: ignore[union-attr]
    assert source is not None
    forbidden = ("import sqlite3", "import httpx", "import psycopg", "import requests")
    for needle in forbidden:
        assert needle not in source, f"unexpected runtime IO import: {needle}"
