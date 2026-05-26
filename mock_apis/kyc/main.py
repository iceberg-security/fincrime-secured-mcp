"""KYC mock API — third concrete data path through the stack (US-013).

Stands in for an internal KYC / identity-verification system. Three endpoints:

    GET /customers/{customer_id}/kyc
        -> identity verification record (full_name, dob, ssn_last4,
           id_document_type, id_document_number, kyc_status, verified_at_year,
           inconsistencies: [...]).

    GET /customers/{customer_id}/documents/{document_id}
        -> document metadata (issuer_country, expiry_year, on_file,
           verification_method, ...).

    GET /customers/{customer_id}/ubo
        -> Ultimate Beneficial Owner tree: for natural persons it's a trivial
           self-owned node; for entities (synthetic_id scenario shapes a
           shell-company tree) it's a layered ownership graph.

All data is generated **deterministically** from the ``customer_id`` so the
same ID always returns the same record (no clock reads, no UUIDs, no unseeded
randomness). The ``?scenario=`` query param shifts shape into one of six
shared fraud personas — the same vocabulary as ``mock_apis.customer_data``:

    clean | mule | sanctions_hit | ato | structuring | synthetic_id

When ``scenario`` is omitted, the per-customer default is picked
deterministically from the seed (matching customer_data + transactions so all
three mocks agree on the implicit scenario for any given ``customer_id``).

Cross-mock consistency: the ``synthetic_id`` scenario surfaces the deliberate
dob-mismatch the customer_data mock plants (year+1 in the profile). This mock
reports the "true" dob and lists ``ssn_dob_mismatch`` in the
``inconsistencies`` field, so an investigator comparing the two records sees
the gap from both sides. Same idea drives ``sanctions_hit``: a
``politically_exposed_person`` flag mirrors customer_data's pep=true.

Zero external dependencies. Pure in-memory generation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Any

from fastapi import FastAPI, HTTPException, Query

from gateways.common.otel import instrument_fastapi

ScenarioParam = Annotated[
    str | None,
    Query(
        description=(
            "Optional scenario override. One of: clean, mule, "
            "sanctions_hit, ato, structuring, synthetic_id."
        )
    ),
]


# --------------------------------------------------------------------------- #
# Scenarios                                                                   #
# --------------------------------------------------------------------------- #


class Scenario(StrEnum):
    CLEAN = "clean"
    MULE = "mule"
    SANCTIONS_HIT = "sanctions_hit"
    ATO = "ato"
    STRUCTURING = "structuring"
    SYNTHETIC_ID = "synthetic_id"


ALL_SCENARIOS: tuple[Scenario, ...] = tuple(Scenario)


# --------------------------------------------------------------------------- #
# Deterministic seeded generation                                             #
# --------------------------------------------------------------------------- #


def _seed_from(customer_id: str, *salts: str) -> int:
    """Stable 64-bit integer seed derived from ``customer_id`` + optional salts.

    Mirrors ``mock_apis.customer_data.main._seed_from`` and
    ``mock_apis.transactions.main._seed_from`` so cross-mock seeded values stay
    aligned. Don't change the hash / encoding without coordinating every other
    mock — the per-customer implicit ``?scenario=`` default depends on it.
    """
    h = hashlib.sha256(customer_id.encode("utf-8"))
    for s in salts:
        h.update(b"|")
        h.update(s.encode("utf-8"))
    return int.from_bytes(h.digest()[:8], "big")


def _rng_choice(seed: int, options: list[str]) -> str:
    return options[seed % len(options)]


def _rng_int(seed: int, lo: int, hi: int) -> int:
    span = hi - lo + 1
    return lo + (seed % span)


# --------------------------------------------------------------------------- #
# Static lookup tables (mirror customer_data's name pool for cross-mock joins)
# --------------------------------------------------------------------------- #

_FIRST_NAMES = [
    "Alice", "Bob", "Carol", "David", "Eve", "Frank", "Grace", "Henry",
    "Ivy", "James", "Karen", "Liam", "Maya", "Noah", "Olivia", "Peter",
    "Quinn", "Rosa", "Sam", "Tara", "Uma", "Victor", "Wendy", "Xavier",
]
_LAST_NAMES = [
    "Smith", "Johnson", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson",
    "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee",
]
_COUNTRIES_LOW_RISK = ["US", "GB", "FR", "DE", "NL", "CA", "AU", "JP"]
_COUNTRIES_HIGH_RISK = ["IR", "KP", "SY", "CU", "VE"]
_ID_DOCUMENT_TYPES = ["passport", "drivers_license", "national_id"]
_VERIFICATION_METHODS = ["document_scan", "video_call", "in_person", "database_lookup"]


# --------------------------------------------------------------------------- #
# Context                                                                     #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _SeededContext:
    customer_id: str
    scenario: Scenario
    base_seed: int


def _default_scenario_for(customer_id: str) -> Scenario:
    # Salt matches customer_data + transactions so all three mocks agree.
    seed = _seed_from(customer_id, "scenario")
    return ALL_SCENARIOS[seed % len(ALL_SCENARIOS)]


def _resolve_scenario(customer_id: str, requested: str | None) -> Scenario:
    if requested is None:
        return _default_scenario_for(customer_id)
    try:
        return Scenario(requested)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                f"unknown scenario '{requested}'. "
                f"valid: {[s.value for s in ALL_SCENARIOS]}"
            ),
        ) from exc


def _context(customer_id: str, scenario_param: str | None) -> _SeededContext:
    scenario = _resolve_scenario(customer_id, scenario_param)
    return _SeededContext(
        customer_id=customer_id,
        scenario=scenario,
        base_seed=_seed_from(customer_id, scenario.value),
    )


# --------------------------------------------------------------------------- #
# KYC record                                                                  #
# --------------------------------------------------------------------------- #


def _kyc_record(ctx: _SeededContext) -> dict[str, Any]:
    # Name / dob derived from the same salts as customer_data so the two mocks
    # describe the same person for the same customer_id.
    first = _rng_choice(_seed_from(ctx.customer_id, "first"), _FIRST_NAMES)
    last = _rng_choice(_seed_from(ctx.customer_id, "last"), _LAST_NAMES)
    year = _rng_int(_seed_from(ctx.customer_id, "dob_year"), 1955, 2000)
    month = _rng_int(_seed_from(ctx.customer_id, "dob_month"), 1, 12)
    day = _rng_int(_seed_from(ctx.customer_id, "dob_day"), 1, 28)
    dob = f"{year:04d}-{month:02d}-{day:02d}"

    # ssn_last4 is just last 4 digits derived from a seed — never PII, but
    # plausibly shaped. Hash redaction in audit (US-006) will still scrub.
    ssn_last4 = f"{_rng_int(_seed_from(ctx.customer_id, 'ssn'), 0, 9999):04d}"

    id_doc_seed = _seed_from(ctx.customer_id, "id_doc")
    id_doc_type = _rng_choice(id_doc_seed, _ID_DOCUMENT_TYPES)
    id_doc_number = f"{ctx.customer_id[-6:].upper()}-{_rng_int(id_doc_seed, 100000, 999999)}"
    issuer_country = _rng_choice(
        _seed_from(ctx.customer_id, "issuer_country"), _COUNTRIES_LOW_RISK
    )
    verification_method = _rng_choice(
        _seed_from(ctx.customer_id, "verification"), _VERIFICATION_METHODS
    )
    verified_at_year = _rng_int(ctx.base_seed, 2018, 2024)

    # Defaults: clean, verified, no inconsistencies.
    kyc_status = "verified"
    inconsistencies: list[str] = []
    pep_flag = False
    sanctions_match = False
    entity_type = "natural_person"

    if ctx.scenario == Scenario.SANCTIONS_HIT:
        issuer_country = _rng_choice(
            _seed_from(ctx.customer_id, "issuer_sanctions"), _COUNTRIES_HIGH_RISK
        )
        pep_flag = True
        sanctions_match = True
        inconsistencies = ["politically_exposed_person", "sanctions_screening_match"]
        kyc_status = "needs_review"
    elif ctx.scenario == Scenario.SYNTHETIC_ID:
        # Synthetic ID: the customer_data profile carries year+1 on dob;
        # this mock reports the "true" dob and flags the gap. An investigator
        # comparing the two sources sees the inconsistency from both sides.
        kyc_status = "needs_review"
        inconsistencies = [
            "ssn_dob_mismatch",
            "thin_credit_file",
            "address_unverified",
        ]
        # synthetic_id verification often skipped or done lightly.
        verification_method = "database_lookup"
        # The ssn we report and the dob we report are CONSISTENT with each
        # other on this side; the inconsistency is with the customer_data
        # profile (which carries year+1 deliberately).
    elif ctx.scenario == Scenario.MULE:
        # Mule accounts: KYC passed but recently, often via lighter checks.
        verified_at_year = 2024
        inconsistencies = ["recent_kyc_refresh"]
    elif ctx.scenario == Scenario.ATO:
        # Account-takeover: KYC record itself is fine but recent
        # re-verification suspicion.
        inconsistencies = ["device_change_post_kyc"]
    elif ctx.scenario == Scenario.STRUCTURING:
        # Structuring: KYC is verified but the customer's cash behavior
        # warrants a refresh.
        inconsistencies = ["kyc_refresh_recommended"]

    return {
        "customer_id": ctx.customer_id,
        "full_name": f"{first} {last}",
        "dob": dob,
        "ssn_last4": ssn_last4,
        "id_document_type": id_doc_type,
        "id_document_number": id_doc_number,
        "issuer_country": issuer_country,
        "verification_method": verification_method,
        "verified_at_year": verified_at_year,
        "kyc_status": kyc_status,
        "pep_flag": pep_flag,
        "sanctions_match": sanctions_match,
        "entity_type": entity_type,
        "inconsistencies": inconsistencies,
        "scenario": ctx.scenario.value,
    }


# --------------------------------------------------------------------------- #
# Documents                                                                   #
# --------------------------------------------------------------------------- #


def _document_ids_for(ctx: _SeededContext) -> list[str]:
    """Stable document IDs the customer has on file under this scenario."""
    if ctx.scenario == Scenario.SYNTHETIC_ID:
        # Thin file: just the one ID doc, no proof of address.
        return [f"doc_{ctx.customer_id}_id"]
    if ctx.scenario == Scenario.SANCTIONS_HIT:
        return [
            f"doc_{ctx.customer_id}_id",
            f"doc_{ctx.customer_id}_address",
        ]
    # Default: ID + proof of address + selfie.
    return [
        f"doc_{ctx.customer_id}_id",
        f"doc_{ctx.customer_id}_address",
        f"doc_{ctx.customer_id}_selfie",
    ]


def _document(ctx: _SeededContext, document_id: str) -> dict[str, Any]:
    valid_ids = _document_ids_for(ctx)
    if document_id not in valid_ids:
        raise HTTPException(
            status_code=404,
            detail=(
                f"document '{document_id}' not on file for customer "
                f"'{ctx.customer_id}' (scenario={ctx.scenario.value})"
            ),
        )

    # Derive document attributes from a doc-specific seed so different docs
    # for the same customer have different attributes but each one is stable.
    seed = _seed_from(ctx.customer_id, ctx.scenario.value, document_id)
    if document_id.endswith("_id"):
        kind = _rng_choice(seed, _ID_DOCUMENT_TYPES)
    elif document_id.endswith("_address"):
        kind = "proof_of_address"
    elif document_id.endswith("_selfie"):
        kind = "selfie_with_id"
    else:
        kind = "other"

    issuer_country = _rng_choice(seed, _COUNTRIES_LOW_RISK)
    if ctx.scenario == Scenario.SANCTIONS_HIT and document_id.endswith("_id"):
        issuer_country = _rng_choice(seed, _COUNTRIES_HIGH_RISK)

    expiry_year = _rng_int(seed, 2025, 2034)
    if ctx.scenario == Scenario.SYNTHETIC_ID:
        # Slightly-off expiry — within a year of expiration, common synthetic
        # tell where the "real" person's expired doc is recycled.
        expiry_year = 2025

    verification_method = _rng_choice(seed, _VERIFICATION_METHODS)
    on_file = True
    return {
        "document_id": document_id,
        "customer_id": ctx.customer_id,
        "kind": kind,
        "issuer_country": issuer_country,
        "expiry_year": expiry_year,
        "verification_method": verification_method,
        "on_file": on_file,
        "scenario": ctx.scenario.value,
    }


def _list_documents(ctx: _SeededContext) -> list[dict[str, Any]]:
    return [_document(ctx, doc_id) for doc_id in _document_ids_for(ctx)]


# --------------------------------------------------------------------------- #
# UBO tree                                                                    #
# --------------------------------------------------------------------------- #


def _ubo_tree(ctx: _SeededContext) -> dict[str, Any]:
    """Ultimate Beneficial Owner graph.

    For natural persons (the default) the tree is trivial: self-owned, 100%.
    For ``synthetic_id`` we shape a shallow shell-company tree to surface the
    layered ownership pattern an investigator would expect to find.
    """
    if ctx.scenario == Scenario.SYNTHETIC_ID:
        # Shell-company structure: a holding entity owns the customer; the
        # holding's only listed UBO is another entity (no natural person at
        # the top — the red flag).
        return {
            "customer_id": ctx.customer_id,
            "scenario": ctx.scenario.value,
            "entity_type": "natural_person",
            "owners": [
                {
                    "owner_id": f"ubo_{ctx.customer_id}_self",
                    "owner_type": "natural_person",
                    "ownership_pct": 100,
                    "country": "US",
                    "is_natural_person_at_top": False,
                    "layers": [
                        {
                            "owner_id": f"ubo_{ctx.customer_id}_holdco",
                            "owner_type": "entity",
                            "country": "PA",
                            "ownership_pct": 100,
                            "is_natural_person_at_top": False,
                        },
                        {
                            "owner_id": f"ubo_{ctx.customer_id}_layer2",
                            "owner_type": "entity",
                            "country": "BS",
                            "ownership_pct": 100,
                            "is_natural_person_at_top": False,
                        },
                    ],
                }
            ],
            "flags": ["no_natural_person_at_top", "multi_layer_ownership"],
        }

    if ctx.scenario == Scenario.SANCTIONS_HIT:
        # PEP-owned: a natural person at the top, but one carrying a PEP
        # flag in their own right.
        return {
            "customer_id": ctx.customer_id,
            "scenario": ctx.scenario.value,
            "entity_type": "natural_person",
            "owners": [
                {
                    "owner_id": f"ubo_{ctx.customer_id}_self",
                    "owner_type": "natural_person",
                    "ownership_pct": 100,
                    "country": _rng_choice(
                        _seed_from(ctx.customer_id, "ubo_country"),
                        _COUNTRIES_HIGH_RISK,
                    ),
                    "is_natural_person_at_top": True,
                    "pep_flag": True,
                    "layers": [],
                }
            ],
            "flags": ["pep_at_top"],
        }

    # Default: trivial self-owned natural person.
    return {
        "customer_id": ctx.customer_id,
        "scenario": ctx.scenario.value,
        "entity_type": "natural_person",
        "owners": [
            {
                "owner_id": f"ubo_{ctx.customer_id}_self",
                "owner_type": "natural_person",
                "ownership_pct": 100,
                "country": _rng_choice(
                    _seed_from(ctx.customer_id, "ubo_country"), _COUNTRIES_LOW_RISK
                ),
                "is_natural_person_at_top": True,
                "layers": [],
            }
        ],
        "flags": [],
    }


# --------------------------------------------------------------------------- #
# FastAPI app                                                                 #
# --------------------------------------------------------------------------- #


def create_app() -> FastAPI:
    """Build the KYC FastAPI app.

    Stateless and pure — no startup hooks, no external deps. Each request
    regenerates from the seed, so identical inputs produce identical outputs.
    """
    app = FastAPI(
        title="kyc mock API",
        version="0.1.0",
        description=(
            "Mock KYC API exposing identity verification records, document "
            "metadata, and UBO (Ultimate Beneficial Owner) trees. "
            "Deterministic from customer_id; scenario-aware via "
            "?scenario=clean|mule|sanctions_hit|ato|structuring|synthetic_id. "
            "Cross-consistent with customer_data and transactions mocks."
        ),
    )
    instrument_fastapi(app, service_name="fraud-mock-kyc")

    @app.get("/customers/{customer_id}/kyc")
    def get_kyc(customer_id: str, scenario: ScenarioParam = None) -> dict[str, Any]:
        ctx = _context(customer_id, scenario)
        return _kyc_record(ctx)

    @app.get("/customers/{customer_id}/documents")
    def list_documents(
        customer_id: str, scenario: ScenarioParam = None
    ) -> dict[str, Any]:
        ctx = _context(customer_id, scenario)
        return {
            "customer_id": customer_id,
            "scenario": ctx.scenario.value,
            "documents": _list_documents(ctx),
        }

    @app.get("/customers/{customer_id}/documents/{document_id}")
    def get_document(
        customer_id: str, document_id: str, scenario: ScenarioParam = None
    ) -> dict[str, Any]:
        ctx = _context(customer_id, scenario)
        return _document(ctx, document_id)

    @app.get("/customers/{customer_id}/ubo")
    def get_ubo(customer_id: str, scenario: ScenarioParam = None) -> dict[str, Any]:
        ctx = _context(customer_id, scenario)
        return _ubo_tree(ctx)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


def build_default_app() -> FastAPI:
    """Construct the kyc app for ``uvicorn``-style launchers.

    No env vars consumed — the mock is stateless and reads no configuration.
    """
    return create_app()


__all__ = [
    "ALL_SCENARIOS",
    "Scenario",
    "build_default_app",
    "create_app",
]
