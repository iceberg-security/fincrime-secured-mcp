"""Transactions mock API — second concrete data path through the stack (US-012).

Stands in for an internal payments / ledger API. Three endpoints:

    GET /customers/{customer_id}/transactions
        -> list of transactions (amount, currency, ts, direction, ...).

    GET /customers/{customer_id}/counterparties
        -> aggregated counterparty summary (count, inbound/outbound totals,
           distinct countries).

    GET /customers/{customer_id}/velocity-anomalies
        -> derived flags for velocity-based fraud heuristics
           (burst_inbound, structuring_pattern, cross_border_burst, ...).

All data is generated **deterministically** from the ``customer_id`` so the
same ID always returns the same rows (no clock reads, no UUIDs, no unseeded
randomness). The ``?scenario=`` query param shifts shape into one of six
shared fraud personas — the same vocabulary as ``mock_apis.customer_data``:

    clean | mule | sanctions_hit | ato | structuring | synthetic_id

When ``scenario`` is omitted the per-customer default is picked
deterministically from the seed (matching customer_data so the two mocks
agree on the implicit scenario for any given ``customer_id``).

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

LimitParam = Annotated[
    int,
    Query(
        ge=1,
        le=500,
        description="Maximum number of transactions to return (default 50).",
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

    Mirrors ``mock_apis.customer_data.main._seed_from`` so callers that
    cross-reference (customer_id, scenario) bytes between mocks see consistent
    intermediate seeds. Don't change the hash / encoding without coordinating
    every other mock.
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
# Static lookup tables                                                        #
# --------------------------------------------------------------------------- #

_TX_TYPES = ["card_purchase", "transfer", "wire", "ach", "cash_deposit"]
_MERCHANT_CATEGORIES = [
    "grocery", "restaurant", "transport", "online_retail", "utilities",
    "subscription", "atm_withdrawal", "money_transfer",
]
_COUNTRIES_LOW_RISK = ["US", "GB", "FR", "DE", "NL", "CA", "AU", "JP"]
_COUNTRIES_HIGH_RISK = ["IR", "KP", "SY", "CU", "VE"]
_COUNTRIES_MULE_HUBS = ["NG", "RU", "TR", "MY", "HK"]


# --------------------------------------------------------------------------- #
# Context                                                                     #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _SeededContext:
    customer_id: str
    scenario: Scenario
    base_seed: int


def _default_scenario_for(customer_id: str) -> Scenario:
    # Salt matches customer_data so both mocks agree on the implicit scenario.
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
# Transaction generation                                                      #
# --------------------------------------------------------------------------- #


def _tx_count(ctx: _SeededContext) -> int:
    """How many transactions the customer has under this scenario."""
    if ctx.scenario == Scenario.CLEAN:
        return _rng_int(ctx.base_seed, 8, 16)
    if ctx.scenario == Scenario.MULE:
        return _rng_int(ctx.base_seed, 40, 60)
    if ctx.scenario == Scenario.STRUCTURING:
        return _rng_int(ctx.base_seed, 25, 40)
    if ctx.scenario == Scenario.SANCTIONS_HIT:
        return _rng_int(ctx.base_seed, 15, 25)
    if ctx.scenario == Scenario.ATO:
        return _rng_int(ctx.base_seed, 18, 30)
    # synthetic_id and any future fallback
    return _rng_int(ctx.base_seed, 10, 20)


def _transactions(ctx: _SeededContext, limit: int) -> list[dict[str, Any]]:
    total = _tx_count(ctx)
    # Cap the per-call response by ``limit`` but preserve total for counterparties.
    n = min(total, limit)

    txs: list[dict[str, Any]] = []
    for i in range(n):
        seed = _seed_from(ctx.customer_id, ctx.scenario.value, f"tx{i}")

        # Defaults: a normal, low-risk card purchase in the customer's region.
        amount = _rng_int(seed, 5, 500)
        currency = "USD"
        direction = _rng_choice(seed, ["debit", "debit", "debit", "credit"])
        tx_type = _rng_choice(seed, _TX_TYPES)
        merchant_category = _rng_choice(seed, _MERCHANT_CATEGORIES)
        counterparty_country = _rng_choice(seed, _COUNTRIES_LOW_RISK)

        # Scenario shaping — same indexing scheme, different ranges/labels.
        if ctx.scenario == Scenario.MULE:
            # High-velocity inbound from atypical hubs, then quick fan-out.
            if i % 3 == 0:
                direction = "credit"
                tx_type = "wire"
                amount = _rng_int(seed, 4_000, 9_500)
                counterparty_country = _rng_choice(seed, _COUNTRIES_MULE_HUBS)
                merchant_category = "money_transfer"
            else:
                direction = "debit"
                tx_type = "transfer"
                amount = _rng_int(seed, 1_500, 4_500)
                merchant_category = "money_transfer"
        elif ctx.scenario == Scenario.STRUCTURING:
            # Repeated sub-threshold cash deposits (US CTR threshold is $10k).
            direction = "credit"
            tx_type = "cash_deposit"
            amount = _rng_int(seed, 8_500, 9_900)
            merchant_category = "atm_withdrawal"
        elif ctx.scenario == Scenario.SANCTIONS_HIT:
            if i % 4 == 0:
                tx_type = "wire"
                counterparty_country = _rng_choice(seed, _COUNTRIES_HIGH_RISK)
                amount = _rng_int(seed, 2_000, 15_000)
                direction = _rng_choice(seed, ["debit", "credit"])
        elif ctx.scenario == Scenario.ATO:
            # Last few transactions are unusual: high-value online purchases
            # from a high-risk geo (matches the suspicious-device tail in the
            # customer_data mock).
            if i >= total - 3:
                tx_type = "card_purchase"
                merchant_category = "online_retail"
                amount = _rng_int(seed, 800, 3_500)
                counterparty_country = _rng_choice(seed, _COUNTRIES_HIGH_RISK)
                direction = "debit"
        elif ctx.scenario == Scenario.SYNTHETIC_ID:
            # Thin file: small, infrequent, all card_purchase.
            tx_type = "card_purchase"
            amount = _rng_int(seed, 5, 80)
            merchant_category = _rng_choice(seed, ["online_retail", "subscription"])

        # Stable, monotonically decreasing "days ago" — newest first.
        days_ago = i
        txs.append(
            {
                "tx_id": f"tx_{ctx.customer_id}_{i:04d}",
                "customer_id": ctx.customer_id,
                "amount": amount,
                "currency": currency,
                "direction": direction,
                "type": tx_type,
                "merchant_category": merchant_category,
                "counterparty_id": f"cp_{ctx.customer_id}_{i % 7:02d}",
                "counterparty_country": counterparty_country,
                "days_ago": days_ago,
                "status": "settled",
            }
        )
    return txs


# --------------------------------------------------------------------------- #
# Counterparty aggregation                                                    #
# --------------------------------------------------------------------------- #


def _counterparties(ctx: _SeededContext) -> list[dict[str, Any]]:
    """Aggregated view: one row per distinct counterparty.

    Derived from the full transaction set (NOT the ``?limit=`` slice) so the
    summary stays stable regardless of how many tx rows a caller requests.
    """
    txs = _transactions(ctx, limit=_tx_count(ctx))
    rollup: dict[str, dict[str, Any]] = {}
    for tx in txs:
        cp_id = tx["counterparty_id"]
        if cp_id not in rollup:
            rollup[cp_id] = {
                "counterparty_id": cp_id,
                "country": tx["counterparty_country"],
                "tx_count": 0,
                "inbound_total": 0,
                "outbound_total": 0,
                "first_seen_days_ago": tx["days_ago"],
                "last_seen_days_ago": tx["days_ago"],
            }
        row = rollup[cp_id]
        row["tx_count"] = int(row["tx_count"]) + 1
        if tx["direction"] == "credit":
            row["inbound_total"] = int(row["inbound_total"]) + int(tx["amount"])
        else:
            row["outbound_total"] = int(row["outbound_total"]) + int(tx["amount"])
        row["first_seen_days_ago"] = max(
            int(row["first_seen_days_ago"]), int(tx["days_ago"])
        )
        row["last_seen_days_ago"] = min(
            int(row["last_seen_days_ago"]), int(tx["days_ago"])
        )
    # Sort by counterparty_id so output is byte-stable across calls.
    return [rollup[k] for k in sorted(rollup.keys())]


# --------------------------------------------------------------------------- #
# Velocity-anomaly flags                                                      #
# --------------------------------------------------------------------------- #


def _velocity_anomalies(ctx: _SeededContext) -> dict[str, Any]:
    """Derived booleans for velocity-based fraud heuristics.

    Computed from the full transaction set so callers get a stable verdict
    regardless of the tx ``?limit=``.
    """
    txs = _transactions(ctx, limit=_tx_count(ctx))
    inbound_credits = [t for t in txs if t["direction"] == "credit"]
    structuring_candidates = [
        t for t in txs
        if t["type"] == "cash_deposit" and 8_000 <= int(t["amount"]) < 10_000
    ]
    cross_border = [
        t for t in txs if t["counterparty_country"] in _COUNTRIES_HIGH_RISK
    ]
    countries = sorted({t["counterparty_country"] for t in txs})

    flags: list[str] = []
    if len(inbound_credits) >= 8:
        flags.append("burst_inbound")
    if len(structuring_candidates) >= 5:
        flags.append("structuring_pattern")
    if len(cross_border) >= 2:
        flags.append("cross_border_burst")
    if any(
        t["counterparty_country"] in _COUNTRIES_MULE_HUBS for t in inbound_credits
    ):
        flags.append("mule_hub_inflow")

    return {
        "customer_id": ctx.customer_id,
        "scenario": ctx.scenario.value,
        "transaction_count": len(txs),
        "inbound_count": len(inbound_credits),
        "structuring_candidate_count": len(structuring_candidates),
        "cross_border_count": len(cross_border),
        "distinct_counterparty_countries": countries,
        "flags": flags,
    }


# --------------------------------------------------------------------------- #
# FastAPI app                                                                 #
# --------------------------------------------------------------------------- #


def create_app() -> FastAPI:
    """Build the transactions FastAPI app.

    Stateless and pure — no startup hooks, no external deps. Each request
    regenerates from the seed, so identical inputs produce identical outputs.
    """
    app = FastAPI(
        title="transactions mock API",
        version="0.1.0",
        description=(
            "Mock payments/ledger API exposing transactions, counterparty "
            "rollups, and velocity-anomaly flags. Deterministic from "
            "customer_id; scenario-aware via "
            "?scenario=clean|mule|sanctions_hit|ato|structuring|synthetic_id."
        ),
    )
    instrument_fastapi(app, service_name="fraud-mock-transactions")

    @app.get("/customers/{customer_id}/transactions")
    def get_transactions(
        customer_id: str,
        scenario: ScenarioParam = None,
        limit: LimitParam = 50,
    ) -> dict[str, Any]:
        ctx = _context(customer_id, scenario)
        return {
            "customer_id": customer_id,
            "scenario": ctx.scenario.value,
            "transactions": _transactions(ctx, limit=limit),
        }

    @app.get("/customers/{customer_id}/counterparties")
    def get_counterparties(
        customer_id: str, scenario: ScenarioParam = None
    ) -> dict[str, Any]:
        ctx = _context(customer_id, scenario)
        return {
            "customer_id": customer_id,
            "scenario": ctx.scenario.value,
            "counterparties": _counterparties(ctx),
        }

    @app.get("/customers/{customer_id}/velocity-anomalies")
    def flag_velocity_anomalies(
        customer_id: str, scenario: ScenarioParam = None
    ) -> dict[str, Any]:
        ctx = _context(customer_id, scenario)
        return _velocity_anomalies(ctx)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


def build_default_app() -> FastAPI:
    """Construct the transactions app for uvicorn-style launchers.

    No env vars consumed — the mock is stateless and reads no configuration.
    """
    return create_app()


__all__ = [
    "ALL_SCENARIOS",
    "Scenario",
    "build_default_app",
    "create_app",
]
