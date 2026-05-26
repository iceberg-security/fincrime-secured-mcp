"""Customer-data mock API — first concrete data path through the stack.

Stands in for an internal CRM / KYC-lite system. Three endpoints:

    GET /customers/{customer_id}            -> profile (name, dob, country, status, ...)
    GET /customers/{customer_id}/accounts   -> list of bank accounts
    GET /customers/{customer_id}/devices    -> known login devices

All data is generated **deterministically** from the ``customer_id`` (via a
hashed seed feeding ``random.Random``) so the same ID always returns the same
profile. The optional ``?scenario=`` query param shifts the generated data into
one of six fraud archetypes shared by the rest of the mock stack:

    clean | mule | sanctions_hit | ato | structuring | synthetic_id

When ``scenario`` is omitted, the per-customer default scenario is picked
deterministically from the seed (so callers that don't care about scenarios
still get plausible variety across IDs).

Zero external dependencies. Pure in-memory generation; no DB, no network.
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
# Scenarios
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
# Deterministic seeded generation
# --------------------------------------------------------------------------- #


def _seed_from(customer_id: str, *salts: str) -> int:
    """Stable 64-bit integer seed derived from ``customer_id`` + optional salts."""
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
# Static lookup tables (curated, not random — keeps generated data plausible)
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
_DEVICE_OS = ["iOS 17", "iOS 18", "Android 13", "Android 14", "Windows 11", "macOS 14"]
_DEVICE_TYPES = ["mobile", "mobile", "mobile", "desktop", "desktop", "tablet"]


# --------------------------------------------------------------------------- #
# Profile generation
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _SeededContext:
    customer_id: str
    scenario: Scenario
    base_seed: int


def _default_scenario_for(customer_id: str) -> Scenario:
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


def _profile(ctx: _SeededContext) -> dict[str, Any]:
    first = _rng_choice(_seed_from(ctx.customer_id, "first"), _FIRST_NAMES)
    last = _rng_choice(_seed_from(ctx.customer_id, "last"), _LAST_NAMES)
    year = _rng_int(_seed_from(ctx.customer_id, "dob_year"), 1955, 2000)
    month = _rng_int(_seed_from(ctx.customer_id, "dob_month"), 1, 12)
    day = _rng_int(_seed_from(ctx.customer_id, "dob_day"), 1, 28)
    dob = f"{year:04d}-{month:02d}-{day:02d}"

    # Scenario-specific overrides
    country = _rng_choice(_seed_from(ctx.customer_id, "country"), _COUNTRIES_LOW_RISK)
    risk_score = _rng_int(ctx.base_seed, 5, 25)  # default: low-risk
    status = "active"
    flags: list[str] = []
    pep = False
    kyc_status = "verified"

    if ctx.scenario == Scenario.SANCTIONS_HIT:
        country = _rng_choice(
            _seed_from(ctx.customer_id, "country_sanctions"), _COUNTRIES_HIGH_RISK
        )
        risk_score = _rng_int(ctx.base_seed, 80, 99)
        flags = ["sanctions_watchlist_possible"]
        pep = True
    elif ctx.scenario == Scenario.MULE:
        risk_score = _rng_int(ctx.base_seed, 55, 79)
        flags = ["recent_account", "multiple_inbound_counterparties"]
    elif ctx.scenario == Scenario.ATO:
        risk_score = _rng_int(ctx.base_seed, 60, 89)
        flags = ["device_change_recent", "geo_mismatch"]
    elif ctx.scenario == Scenario.STRUCTURING:
        risk_score = _rng_int(ctx.base_seed, 50, 74)
        flags = ["repeated_sub_threshold_cash"]
    elif ctx.scenario == Scenario.SYNTHETIC_ID:
        risk_score = _rng_int(ctx.base_seed, 65, 90)
        flags = ["ssn_dob_mismatch", "thin_credit_file"]
        kyc_status = "needs_review"
        # Synthetic IDs sometimes carry a slightly off DOB to mirror the
        # KYC inconsistency we surface from the kyc mock (US-013).
        dob = f"{year + 1:04d}-{month:02d}-{day:02d}"

    return {
        "customer_id": ctx.customer_id,
        "first_name": first,
        "last_name": last,
        "full_name": f"{first} {last}",
        "dob": dob,
        "country": country,
        "status": status,
        "kyc_status": kyc_status,
        "pep": pep,
        "risk_score": risk_score,
        "flags": flags,
        "scenario": ctx.scenario.value,
    }


def _accounts(ctx: _SeededContext) -> list[dict[str, Any]]:
    # Scenario shape: how many accounts and what kind.
    if ctx.scenario in {Scenario.CLEAN}:
        count = _rng_int(ctx.base_seed, 1, 2)
    elif ctx.scenario in {Scenario.MULE, Scenario.STRUCTURING}:
        count = _rng_int(ctx.base_seed, 3, 5)
    elif ctx.scenario == Scenario.SANCTIONS_HIT:
        count = _rng_int(ctx.base_seed, 1, 2)
    else:
        count = _rng_int(ctx.base_seed, 2, 3)

    accounts: list[dict[str, Any]] = []
    for i in range(count):
        seed = _seed_from(ctx.customer_id, ctx.scenario.value, f"acct{i}")
        kind = _rng_choice(seed, ["checking", "savings", "checking"])
        opened_year = _rng_int(seed, 2015, 2024)
        balance = _rng_int(seed, 100, 50_000)
        if ctx.scenario == Scenario.MULE and i == 0:
            # Mule accounts: recently opened, high inbound velocity.
            opened_year = 2024
            balance = _rng_int(seed, 100, 1_500)
        if ctx.scenario == Scenario.SANCTIONS_HIT:
            balance = _rng_int(seed, 5_000, 250_000)
        accounts.append(
            {
                "account_id": f"acct_{ctx.customer_id}_{i:02d}",
                "customer_id": ctx.customer_id,
                "type": kind,
                "currency": "USD",
                "opened_year": opened_year,
                "balance": balance,
                "status": "open",
            }
        )
    return accounts


def _devices(ctx: _SeededContext) -> list[dict[str, Any]]:
    if ctx.scenario == Scenario.ATO:
        count = _rng_int(ctx.base_seed, 3, 5)
    elif ctx.scenario == Scenario.CLEAN:
        count = _rng_int(ctx.base_seed, 1, 2)
    else:
        count = _rng_int(ctx.base_seed, 1, 3)

    devices: list[dict[str, Any]] = []
    for i in range(count):
        seed = _seed_from(ctx.customer_id, ctx.scenario.value, f"dev{i}")
        os_name = _rng_choice(seed, _DEVICE_OS)
        device_type = _rng_choice(seed, _DEVICE_TYPES)
        first_seen_year = _rng_int(seed, 2019, 2024)
        # ATO scenario: newest device added very recently, geo mismatch flag.
        suspicious = ctx.scenario == Scenario.ATO and i == count - 1
        devices.append(
            {
                "device_id": f"dev_{ctx.customer_id}_{i:02d}",
                "customer_id": ctx.customer_id,
                "os": os_name,
                "type": device_type,
                "first_seen_year": first_seen_year,
                "last_login_country": (
                    _rng_choice(seed, _COUNTRIES_LOW_RISK)
                    if not suspicious
                    else _rng_choice(seed, _COUNTRIES_HIGH_RISK)
                ),
                "suspicious": suspicious,
            }
        )
    return devices


# --------------------------------------------------------------------------- #
# FastAPI app
# --------------------------------------------------------------------------- #


def create_app() -> FastAPI:
    """Build the customer_data FastAPI app.

    Stateless and pure — no startup hooks, no external deps. Each request
    regenerates the response from the seed, so identical inputs are
    guaranteed to produce identical outputs.
    """
    app = FastAPI(
        title="customer_data mock API",
        version="0.1.0",
        description=(
            "Mock CRM-style API exposing customer profile, accounts, and "
            "devices. Deterministic from customer_id; scenario-aware via "
            "?scenario=clean|mule|sanctions_hit|ato|structuring|synthetic_id."
        ),
    )
    instrument_fastapi(app, service_name="fraud-mock-customer-data")

    @app.get("/customers/{customer_id}")
    def get_customer(customer_id: str, scenario: ScenarioParam = None) -> dict[str, Any]:
        ctx = _context(customer_id, scenario)
        return _profile(ctx)

    @app.get("/customers/{customer_id}/accounts")
    def list_accounts(customer_id: str, scenario: ScenarioParam = None) -> dict[str, Any]:
        ctx = _context(customer_id, scenario)
        return {
            "customer_id": customer_id,
            "scenario": ctx.scenario.value,
            "accounts": _accounts(ctx),
        }

    @app.get("/customers/{customer_id}/devices")
    def list_devices(customer_id: str, scenario: ScenarioParam = None) -> dict[str, Any]:
        ctx = _context(customer_id, scenario)
        return {
            "customer_id": customer_id,
            "scenario": ctx.scenario.value,
            "devices": _devices(ctx),
        }

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


def build_default_app() -> FastAPI:
    """Construct the customer_data app for ``uvicorn``-style launchers.

    No env vars consumed — the mock is stateless and reads no configuration.
    """
    return create_app()


__all__ = [
    "ALL_SCENARIOS",
    "Scenario",
    "build_default_app",
    "create_app",
]
