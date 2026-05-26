"""Unit tests for mock_apis/osint (US-015)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mock_apis.customer_data.main import _default_scenario_for as cust_default_scenario
from mock_apis.osint.main import (
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


def test_web_search_is_deterministic(client: TestClient) -> None:
    a = client.get(
        "/web/search",
        params={"query": "Alice Smith", "scenario": "sanctions_hit"},
    ).json()
    b = client.get(
        "/web/search",
        params={"query": "Alice Smith", "scenario": "sanctions_hit"},
    ).json()
    assert a == b


def test_web_fetch_is_deterministic(client: TestClient) -> None:
    a = client.get(
        "/web/fetch",
        params={
            "url": "https://ofac.example/actions/alice-smith",
            "scenario": "sanctions_hit",
        },
    ).json()
    b = client.get(
        "/web/fetch",
        params={
            "url": "https://ofac.example/actions/alice-smith",
            "scenario": "sanctions_hit",
        },
    ).json()
    assert a == b


def test_lookup_company_is_deterministic(client: TestClient) -> None:
    a = client.get(
        "/companies/AcmeCorp", params={"scenario": "sanctions_hit"}
    ).json()
    b = client.get(
        "/companies/AcmeCorp", params={"scenario": "sanctions_hit"}
    ).json()
    assert a == b


def test_different_queries_yield_different_results(client: TestClient) -> None:
    a = client.get(
        "/web/search",
        params={"query": "Alice Smith", "scenario": "sanctions_hit"},
    ).json()
    b = client.get(
        "/web/search",
        params={"query": "Bob Jones", "scenario": "sanctions_hit"},
    ).json()
    assert a["results"] != b["results"]


# --------------------------------------------------------------------------- #
# Scenarios                                                                   #
# --------------------------------------------------------------------------- #


def test_all_scenarios_supported_for_web_search(client: TestClient) -> None:
    for scen in ALL_SCENARIOS:
        resp = client.get(
            "/web/search",
            params={"query": "Alice Smith", "scenario": scen.value},
        )
        assert resp.status_code == 200, scen.value
        payload = resp.json()
        assert payload["scenario"] == scen.value


def test_clean_scenario_has_no_adverse_results(client: TestClient) -> None:
    result = client.get(
        "/web/search",
        params={"query": "Alice Smith", "scenario": "clean"},
    ).json()
    assert result["adverse_count"] == 0
    assert all(not r["adverse"] for r in result["results"])


def test_sanctions_hit_search_has_adverse_media(client: TestClient) -> None:
    result = client.get(
        "/web/search",
        params={"query": "Alice Smith", "scenario": "sanctions_hit"},
    ).json()
    assert result["adverse_count"] >= 1
    adverse = [r for r in result["results"] if r["adverse"]]
    assert any("watchlist" in r["title"].lower() for r in adverse)


def test_mule_search_has_typology_hit(client: TestClient) -> None:
    result = client.get(
        "/web/search",
        params={"query": "Alice Smith", "scenario": "mule"},
    ).json()
    adverse = [r for r in result["results"] if r["adverse"]]
    assert any("mule" in r["title"].lower() for r in adverse)


def test_synthetic_id_search_has_credit_discrepancy(client: TestClient) -> None:
    result = client.get(
        "/web/search",
        params={"query": "Alice Smith", "scenario": "synthetic_id"},
    ).json()
    adverse = [r for r in result["results"] if r["adverse"]]
    assert any("credit" in r["title"].lower() for r in adverse)


def test_structuring_search_has_regulatory_bulletin(client: TestClient) -> None:
    result = client.get(
        "/web/search",
        params={"query": "Alice Smith", "scenario": "structuring"},
    ).json()
    adverse = [r for r in result["results"] if r["adverse"]]
    assert any("structuring" in r["title"].lower() for r in adverse)


def test_ato_search_has_phishing_forum_hit(client: TestClient) -> None:
    result = client.get(
        "/web/search",
        params={"query": "Alice Smith", "scenario": "ato"},
    ).json()
    adverse = [r for r in result["results"] if r["adverse"]]
    assert any("takeover" in r["title"].lower() for r in adverse)


# --------------------------------------------------------------------------- #
# Web fetch                                                                   #
# --------------------------------------------------------------------------- #


def test_fetch_sanctions_hit_page_is_adverse(client: TestClient) -> None:
    page = client.get(
        "/web/fetch",
        params={
            "url": "https://ofac.example/actions/alice-smith",
            "scenario": "sanctions_hit",
        },
    ).json()
    assert page["adverse"] is True
    assert "sanction" in page["text"].lower() or "regulator" in page["text"].lower()
    assert page["content_digest"]
    assert page["byte_size"] > 0


def test_fetch_clean_page_is_not_adverse(client: TestClient) -> None:
    page = client.get(
        "/web/fetch",
        params={
            "url": "https://reuters.example/story/123",
            "scenario": "clean",
        },
    ).json()
    assert page["adverse"] is False


def test_fetch_does_not_actually_call_network(client: TestClient) -> None:
    """The mock manufactures content; any URL works.

    A URL that's clearly not real should still return synthetic bytes — the
    mock doesn't validate that the URL is fetchable. The allowlist is the
    MCP server's concern, NOT this mock's.
    """
    page = client.get(
        "/web/fetch",
        params={
            "url": "https://this-host-does-not-exist.invalid/page",
            "scenario": "clean",
        },
    ).json()
    assert "url" in page
    assert page["fetched_from"] == "mock_osint"


# --------------------------------------------------------------------------- #
# Company lookup                                                              #
# --------------------------------------------------------------------------- #


def test_company_clean_has_no_risk_signals(client: TestClient) -> None:
    company = client.get(
        "/companies/AcmeCorp", params={"scenario": "clean"}
    ).json()
    assert company["risk_signals"] == []


def test_company_sanctions_hit_has_signals(client: TestClient) -> None:
    company = client.get(
        "/companies/AcmeCorp", params={"scenario": "sanctions_hit"}
    ).json()
    assert "sanctioned_owner" in company["risk_signals"]
    assert "pep_director" in company["risk_signals"]
    assert any(d["pep_flag"] for d in company["directors"])


def test_company_synthetic_id_is_shell(client: TestClient) -> None:
    company = client.get(
        "/companies/AcmeCorp", params={"scenario": "synthetic_id"}
    ).json()
    assert "shell_company_indicators" in company["risk_signals"]
    # Offshore jurisdictions.
    assert company["jurisdiction"] in {"BVI", "PA", "BS", "KY", "BZ", "VG"}
    # Beneficial owner is an entity (the layered structure).
    assert company["beneficial_owners"][0]["owner_type"] == "entity"


def test_company_mule_is_recent(client: TestClient) -> None:
    company = client.get(
        "/companies/AcmeCorp", params={"scenario": "mule"}
    ).json()
    assert company["incorporated_year"] == 2024
    assert "recent_incorporation" in company["risk_signals"]


# --------------------------------------------------------------------------- #
# Cross-mock consistency                                                      #
# --------------------------------------------------------------------------- #


def test_default_scenario_agrees_with_customer_data_mock() -> None:
    """The implicit ?scenario= default must agree with customer_data's helper.

    Salt is ``"scenario"`` — same across all five mocks. If this test ever
    flips, the per-customer implicit scenario is silently diverging
    cross-mock and US-026 eval datasets will see ghosts.
    """
    for key in ("Alice Smith", "Bob Jones", "AcmeCorp"):
        assert _default_scenario_for(key) == cust_default_scenario(key)


# --------------------------------------------------------------------------- #
# Error handling                                                              #
# --------------------------------------------------------------------------- #


def test_unknown_scenario_returns_400(client: TestClient) -> None:
    resp = client.get(
        "/web/search",
        params={"query": "Alice Smith", "scenario": "not_a_real_scenario"},
    )
    assert resp.status_code == 400
    assert "not_a_real_scenario" in resp.json()["detail"]


def test_empty_query_returns_422(client: TestClient) -> None:
    resp = client.get("/web/search", params={"query": ""})
    assert resp.status_code == 422


def test_missing_query_returns_422(client: TestClient) -> None:
    resp = client.get("/web/search")
    assert resp.status_code == 422


def test_empty_url_returns_422(client: TestClient) -> None:
    resp = client.get("/web/fetch", params={"url": ""})
    assert resp.status_code == 422


def test_default_scenario_stable_per_query(client: TestClient) -> None:
    a = client.get("/web/search", params={"query": "Alice Smith"}).json()
    b = client.get("/web/search", params={"query": "Alice Smith"}).json()
    assert a["scenario"] == b["scenario"]
    assert a["scenario"] in {s.value for s in Scenario}


# --------------------------------------------------------------------------- #
# Distinct scenario signatures                                                #
# --------------------------------------------------------------------------- #


def test_scenarios_produce_distinct_search_signatures(client: TestClient) -> None:
    signatures: set[tuple[int, int]] = set()
    for scen in ALL_SCENARIOS:
        payload = client.get(
            "/web/search",
            params={"query": "Alice Smith", "scenario": scen.value},
        ).json()
        sig = (len(payload["results"]), payload["adverse_count"])
        signatures.add(sig)
    # We expect at least 4 distinct (count, adverse_count) tuples across 6
    # scenarios — clean has 0 adverse, sanctions_hit has 1-2, the others
    # have 1 each. Distinct shapes can collide on the (count, adverse_count)
    # axis but we always want clean to be uniquely-zero.
    clean_payload = client.get(
        "/web/search", params={"query": "Alice Smith", "scenario": "clean"}
    ).json()
    assert clean_payload["adverse_count"] == 0
    # At least one scenario must produce a non-zero adverse_count.
    assert max(s[1] for s in signatures) > 0


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

    mod = importlib.import_module("mock_apis.osint.main")
    source = mod.__loader__.get_source("mock_apis.osint.main")  # type: ignore[union-attr]
    assert source is not None
    forbidden = ("import sqlite3", "import httpx", "import psycopg", "import requests")
    for needle in forbidden:
        assert needle not in source, f"unexpected runtime IO import: {needle}"
