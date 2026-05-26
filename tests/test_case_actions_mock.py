"""Tests for the case_actions mock API (mock_apis/case_actions/main.py).

Covers:
    * Determinism — same input -> same id, same content_hash.
    * Each write endpoint accepts a well-formed body and persists the record
      to the shared journal so the matching GET returns it.
    * Validation rejects malformed bodies.
    * Each app's journal is independent (no global state leak).
    * /healthz.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from mock_apis.case_actions.main import CaseStore, create_app

# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _client_and_store() -> tuple[TestClient, CaseStore]:
    store = CaseStore()
    return TestClient(create_app(store=store)), store


SAR_BODY: dict[str, Any] = {
    "customer_id": "cust_123",
    "narrative": "Mule typology suspected — see SAR-2025-0001.",
    "typology": "money_mule",
    "related_accounts": ["acct_cust_123_00", "acct_cust_123_01"],
}

FREEZE_BODY: dict[str, Any] = {
    "account_id": "acct_cust_123_00",
    "reason": "structuring deposits near CTR threshold",
    "requested_by": "bob@example.com",
}

ESCALATE_BODY: dict[str, Any] = {
    "case_id": "case_2025_0001",
    "summary": "Sanctions hit + mule pattern + adverse OSINT.",
    "severity": "high",
    "requested_by": "bob@example.com",
}


# --------------------------------------------------------------------------- #
# Healthz                                                                     #
# --------------------------------------------------------------------------- #


def test_healthz() -> None:
    client, _ = _client_and_store()
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# --------------------------------------------------------------------------- #
# SAR drafts                                                                  #
# --------------------------------------------------------------------------- #


def test_create_sar_draft_returns_record_and_persists() -> None:
    client, store = _client_and_store()
    resp = client.post("/sar-drafts", json=SAR_BODY)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["draft_id"].startswith("sar_")
    assert body["customer_id"] == SAR_BODY["customer_id"]
    assert body["narrative"] == SAR_BODY["narrative"]
    assert body["typology"] == SAR_BODY["typology"]
    assert body["related_accounts"] == SAR_BODY["related_accounts"]
    assert body["status"] == "draft"
    assert isinstance(body["content_hash"], str)
    assert len(body["content_hash"]) == 64  # sha256 hex

    # Persisted in journal.
    assert body["draft_id"] in store.sar_drafts
    assert store.sar_drafts[body["draft_id"]] == body


def test_create_sar_draft_is_deterministic() -> None:
    client1, _ = _client_and_store()
    client2, _ = _client_and_store()
    r1 = client1.post("/sar-drafts", json=SAR_BODY).json()
    r2 = client2.post("/sar-drafts", json=SAR_BODY).json()
    assert r1["draft_id"] == r2["draft_id"]
    assert r1["content_hash"] == r2["content_hash"]


def test_create_sar_draft_different_bodies_produce_different_ids() -> None:
    client, _ = _client_and_store()
    r1 = client.post("/sar-drafts", json=SAR_BODY).json()
    r2 = client.post(
        "/sar-drafts",
        json={**SAR_BODY, "typology": "structuring"},
    ).json()
    assert r1["draft_id"] != r2["draft_id"]


def test_get_sar_draft_round_trip() -> None:
    client, _ = _client_and_store()
    created = client.post("/sar-drafts", json=SAR_BODY).json()
    resp = client.get(f"/sar-drafts/{created['draft_id']}")
    assert resp.status_code == 200
    assert resp.json() == created


def test_get_sar_draft_unknown_returns_404() -> None:
    client, _ = _client_and_store()
    resp = client.get("/sar-drafts/sar_doesnotexist")
    assert resp.status_code == 404


def test_create_sar_draft_missing_field_is_422() -> None:
    client, _ = _client_and_store()
    resp = client.post(
        "/sar-drafts",
        json={"customer_id": "x", "typology": "y"},  # missing narrative
    )
    assert resp.status_code == 422


def test_create_sar_draft_empty_narrative_is_422() -> None:
    client, _ = _client_and_store()
    resp = client.post("/sar-drafts", json={**SAR_BODY, "narrative": ""})
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# Account freeze                                                              #
# --------------------------------------------------------------------------- #


def test_freeze_account_returns_record_and_persists() -> None:
    client, store = _client_and_store()
    resp = client.post("/accounts/freeze", json=FREEZE_BODY)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["freeze_id"].startswith("frz_")
    assert body["account_id"] == FREEZE_BODY["account_id"]
    assert body["status"] == "frozen"

    # Persisted in journal keyed by account_id.
    assert FREEZE_BODY["account_id"] in store.freezes
    assert store.freezes[FREEZE_BODY["account_id"]] == body


def test_freeze_account_is_deterministic() -> None:
    c1, _ = _client_and_store()
    c2, _ = _client_and_store()
    r1 = c1.post("/accounts/freeze", json=FREEZE_BODY).json()
    r2 = c2.post("/accounts/freeze", json=FREEZE_BODY).json()
    assert r1["freeze_id"] == r2["freeze_id"]
    assert r1["content_hash"] == r2["content_hash"]


def test_get_freeze_round_trip() -> None:
    client, _ = _client_and_store()
    created = client.post("/accounts/freeze", json=FREEZE_BODY).json()
    resp = client.get(f"/accounts/{FREEZE_BODY['account_id']}/freeze")
    assert resp.status_code == 200
    assert resp.json() == created


def test_get_freeze_unknown_returns_404() -> None:
    client, _ = _client_and_store()
    resp = client.get("/accounts/never_frozen/freeze")
    assert resp.status_code == 404


def test_freeze_account_missing_field_is_422() -> None:
    client, _ = _client_and_store()
    resp = client.post(
        "/accounts/freeze",
        json={"account_id": "x", "reason": "y"},  # missing requested_by
    )
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# Escalation                                                                  #
# --------------------------------------------------------------------------- #


def test_escalate_to_l3_returns_record_and_persists() -> None:
    client, store = _client_and_store()
    resp = client.post("/escalations", json=ESCALATE_BODY)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["escalation_id"].startswith("esc_")
    assert body["case_id"] == ESCALATE_BODY["case_id"]
    assert body["status"] == "escalated_l3"

    assert body["escalation_id"] in store.escalations
    assert store.escalations[body["escalation_id"]] == body


def test_escalate_to_l3_is_deterministic() -> None:
    c1, _ = _client_and_store()
    c2, _ = _client_and_store()
    r1 = c1.post("/escalations", json=ESCALATE_BODY).json()
    r2 = c2.post("/escalations", json=ESCALATE_BODY).json()
    assert r1["escalation_id"] == r2["escalation_id"]
    assert r1["content_hash"] == r2["content_hash"]


def test_get_escalation_round_trip() -> None:
    client, _ = _client_and_store()
    created = client.post("/escalations", json=ESCALATE_BODY).json()
    resp = client.get(f"/escalations/{created['escalation_id']}")
    assert resp.status_code == 200
    assert resp.json() == created


def test_get_escalation_unknown_returns_404() -> None:
    client, _ = _client_and_store()
    resp = client.get("/escalations/esc_doesnotexist")
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Per-app isolation                                                           #
# --------------------------------------------------------------------------- #


def test_separate_apps_have_independent_journals() -> None:
    client_a, store_a = _client_and_store()
    client_b, store_b = _client_and_store()

    a = client_a.post("/sar-drafts", json=SAR_BODY).json()
    # store_b is empty; the same draft_id should not be findable via client_b.
    resp = client_b.get(f"/sar-drafts/{a['draft_id']}")
    assert resp.status_code == 404
    assert store_b.sar_drafts == {}
    assert a["draft_id"] in store_a.sar_drafts


def test_shared_store_lets_two_apps_see_same_journal() -> None:
    store = CaseStore()
    app_a = create_app(store=store)
    app_b = create_app(store=store)
    client_a = TestClient(app_a)
    client_b = TestClient(app_b)

    created = client_a.post("/sar-drafts", json=SAR_BODY).json()
    resp = client_b.get(f"/sar-drafts/{created['draft_id']}")
    assert resp.status_code == 200
    assert resp.json() == created


# --------------------------------------------------------------------------- #
# Zero-runtime-IO import check                                                #
# --------------------------------------------------------------------------- #


def test_module_does_no_runtime_io() -> None:
    """Mock should not touch the network, the disk, or system clocks."""
    src = (
        __import__("mock_apis.case_actions.main", fromlist=["main"]).__file__
        or ""
    )
    text = open(src).read()
    forbidden = ["sqlite3", "httpx", "psycopg", "requests"]
    for word in forbidden:
        assert word not in text, f"case_actions mock should not import {word}"


# --------------------------------------------------------------------------- #
# content_hash sanity                                                         #
# --------------------------------------------------------------------------- #


def test_content_hash_is_stable_across_calls() -> None:
    """Same body -> same content_hash; different body -> different hash."""
    client, _ = _client_and_store()
    r1 = client.post("/sar-drafts", json=SAR_BODY).json()
    # Build a *new* app (fresh store) and re-post; the content_hash should
    # match because it's content-derived, not state-derived.
    client2, _ = _client_and_store()
    r2 = client2.post("/sar-drafts", json=SAR_BODY).json()
    assert r1["content_hash"] == r2["content_hash"]

    r3 = client.post(
        "/sar-drafts", json={**SAR_BODY, "narrative": "different"}
    ).json()
    assert r3["content_hash"] != r1["content_hash"]
