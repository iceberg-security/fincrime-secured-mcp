"""Sanctions mock API — OFAC-style watchlist screening (US-014).

Stands in for an internal sanctions / PEP / watchlist screening service. Three
endpoints:

    GET /screen/name?name=&scenario=
        -> screen a natural person's name against a synthetic OFAC-style
           watchlist. Returns ``{query, matched, hits: [...]}``.

    GET /screen/entity?entity_name=&scenario=
        -> screen an entity (corporation, trust, foundation) against the
           same watchlist. Returns ``{query, matched, hits: [...]}``.

    GET /hits/{hit_id}
        -> detailed record for a single watchlist hit (program, listed_on,
           aliases, addresses, …).

Determinism contract:

* Every output is derived from ``sha256(name|salt|...)``-based seeds via the
  same ``_seed_from`` helper used by ``mock_apis.customer_data``,
  ``mock_apis.transactions``, and ``mock_apis.kyc``. The hash function and salt
  encoding match those mocks so cross-mock joins keyed on a customer's name
  (which is shared across mocks via the ``first`` / ``last`` salts) work
  predictably.

* The ``?scenario=`` query param shifts shape into one of the six shared
  fraud personas:

    clean | mule | sanctions_hit | ato | structuring | synthetic_id

  ``sanctions_hit`` is the only scenario that produces a real watchlist
  match. All other scenarios return ``matched=false`` with an empty hits
  list. This is the deliberate cross-mock contract: a customer whose
  ``customer_data.get_customer(scenario=sanctions_hit)`` profile is flagged
  with ``sanctions_watchlist_possible`` and whose
  ``kyc.get_kyc_record(scenario=sanctions_hit)`` carries
  ``sanctions_match=true`` MUST screen with a real hit on this mock when the
  caller passes the same name + ``scenario=sanctions_hit``.

* ``GET /hits/{hit_id}`` is deterministic from the ``hit_id`` itself. The
  ``hit_id`` shape is ``hit_<scenario>_<name_slug>_<index>`` and the
  detail-fetch endpoint regenerates the hit purely from that id, so the
  detail call never needs to re-screen. Unknown hit ids return 404.

* When ``scenario`` is omitted on the screening endpoints, the per-name
  default is picked deterministically from ``sha256(name|"scenario")`` (the
  same salt the other mocks use against ``customer_id``). The cross-mock
  ``_default_scenario_for`` tests in the other mocks key off ``customer_id``;
  here we key off the raw name, since this mock is name-driven rather than
  customer-id-driven.

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

NameParam = Annotated[
    str,
    Query(
        min_length=1,
        max_length=200,
        description="Name to screen against the watchlist.",
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


def _seed_from(value: str, *salts: str) -> int:
    """Stable 64-bit integer seed.

    Mirrors ``mock_apis.customer_data.main._seed_from`` /
    ``mock_apis.transactions.main._seed_from`` /
    ``mock_apis.kyc.main._seed_from`` so cross-mock seeded values stay
    aligned. The salt encoding (UTF-8 bytes, pipe-separated) is the shared
    contract.
    """
    h = hashlib.sha256(value.encode("utf-8"))
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

_SANCTIONS_PROGRAMS = [
    "OFAC_SDN",
    "EU_CONSOLIDATED",
    "UN_SANCTIONS",
    "UK_HMT",
]
_HIT_TYPES = ["sdn_match", "pep_match", "adverse_media"]
_COUNTRIES_HIGH_RISK = ["IR", "KP", "SY", "CU", "VE", "RU"]
_LIST_YEARS = [2014, 2017, 2019, 2021, 2022, 2023]


# --------------------------------------------------------------------------- #
# Context                                                                     #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _ScreenContext:
    query: str
    scenario: Scenario
    base_seed: int


def _default_scenario_for(name: str) -> Scenario:
    seed = _seed_from(name, "scenario")
    return ALL_SCENARIOS[seed % len(ALL_SCENARIOS)]


def _resolve_scenario(name: str, requested: str | None) -> Scenario:
    if requested is None:
        return _default_scenario_for(name)
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


def _context(name: str, scenario_param: str | None) -> _ScreenContext:
    scenario = _resolve_scenario(name, scenario_param)
    return _ScreenContext(
        query=name,
        scenario=scenario,
        base_seed=_seed_from(name, scenario.value),
    )


# --------------------------------------------------------------------------- #
# Hit construction                                                            #
# --------------------------------------------------------------------------- #


def _name_slug(name: str) -> str:
    """URL-safe slug for embedding the queried name in a hit_id.

    Collapses everything that isn't alphanumeric into a single underscore and
    lowercases. Deterministic; reversible enough for the detail endpoint to
    regenerate the hit purely from the id.
    """
    out_chars: list[str] = []
    prev_underscore = False
    for ch in name.lower():
        if ch.isalnum():
            out_chars.append(ch)
            prev_underscore = False
        else:
            if not prev_underscore:
                out_chars.append("_")
                prev_underscore = True
    slug = "".join(out_chars).strip("_")
    return slug or "anon"


def _build_hit(
    *,
    scenario: Scenario,
    queried_name: str,
    index: int,
    entity_type: str,
) -> dict[str, Any]:
    """Construct one watchlist hit record.

    The hit_id is a function of (scenario, name slug, index) so the same
    inputs always produce the same id. Stored fields are derived from a
    hit-id-derived seed so the detail endpoint can regenerate them.
    """
    slug = _name_slug(queried_name)
    hit_id = f"hit_{scenario.value}_{slug}_{index:02d}"
    return _materialize_hit(hit_id=hit_id, queried_name=queried_name, entity_type=entity_type)


def _materialize_hit(
    *,
    hit_id: str,
    queried_name: str,
    entity_type: str,
) -> dict[str, Any]:
    """Regenerate a hit's fields from its id (used by both /screen and /hits)."""
    seed = _seed_from(hit_id, "hit")
    program = _rng_choice(seed, _SANCTIONS_PROGRAMS)
    hit_type = _rng_choice(_seed_from(hit_id, "type"), _HIT_TYPES)
    listed_on = _rng_choice(
        _seed_from(hit_id, "listed_on"), [str(y) for y in _LIST_YEARS]
    )
    country = _rng_choice(_seed_from(hit_id, "country"), _COUNTRIES_HIGH_RISK)
    # Match score: high but not always perfect — surfaces fuzzy-match shape.
    score = _rng_int(_seed_from(hit_id, "score"), 82, 99)
    # Aliases: a small deterministic list seeded off the hit id.
    alias_count = _rng_int(_seed_from(hit_id, "alias_count"), 1, 3)
    aliases: list[str] = []
    for i in range(alias_count):
        seed_i = _seed_from(hit_id, f"alias{i}")
        suffix = _rng_choice(
            seed_i, ["aka", "n.k.a.", "f.k.a.", "transliteration"]
        )
        aliases.append(f"{queried_name} ({suffix} variant {i + 1})")
    address = {
        "city": _rng_choice(
            _seed_from(hit_id, "city"),
            ["Tehran", "Pyongyang", "Damascus", "Havana", "Caracas", "Moscow"],
        ),
        "country": country,
    }
    return {
        "hit_id": hit_id,
        "queried_name": queried_name,
        "listed_name": queried_name,
        "entity_type": entity_type,
        "program": program,
        "hit_type": hit_type,
        "listed_on": int(listed_on),
        "country": country,
        "match_score": score,
        "aliases": aliases,
        "addresses": [address],
    }


def _screen(ctx: _ScreenContext, entity_type: str) -> dict[str, Any]:
    """Run screening against the synthetic watchlist.

    Only ``sanctions_hit`` produces matches; everything else screens clean.
    The number of hits is deterministic from (scenario, name) so callers can
    pin expectations in tests.
    """
    if ctx.scenario != Scenario.SANCTIONS_HIT:
        return {
            "query": ctx.query,
            "scenario": ctx.scenario.value,
            "matched": False,
            "hits": [],
        }

    hit_count = _rng_int(ctx.base_seed, 1, 2)
    hits = [
        _build_hit(
            scenario=ctx.scenario,
            queried_name=ctx.query,
            index=i,
            entity_type=entity_type,
        )
        for i in range(hit_count)
    ]
    return {
        "query": ctx.query,
        "scenario": ctx.scenario.value,
        "matched": True,
        "hits": hits,
    }


# --------------------------------------------------------------------------- #
# Hit detail lookup                                                           #
# --------------------------------------------------------------------------- #


def _parse_hit_id(hit_id: str) -> tuple[Scenario, str, int]:
    """Reverse a hit_id back into (scenario, name_slug, index).

    Raises HTTPException(404) if the id is malformed or references a scenario
    other than ``sanctions_hit`` (the only one that ever produces hits).

    The hit_id shape is ``hit_<scenario>_<name_slug>_<index>`` but every part
    may contain underscores (e.g. ``sanctions_hit``, ``alice_smith``), so we
    can't just split. Instead match the prefix against the known scenario
    enum values and parse from there.
    """
    if not hit_id.startswith("hit_"):
        raise HTTPException(
            status_code=404,
            detail=f"hit '{hit_id}' not found (malformed hit_id)",
        )
    rest = hit_id[len("hit_") :]

    matched_scenario: Scenario | None = None
    for scen in ALL_SCENARIOS:
        prefix = f"{scen.value}_"
        if rest.startswith(prefix):
            matched_scenario = scen
            rest = rest[len(prefix) :]
            break
    if matched_scenario is None:
        raise HTTPException(
            status_code=404,
            detail=f"hit '{hit_id}' not found (unknown scenario)",
        )
    if matched_scenario != Scenario.SANCTIONS_HIT:
        raise HTTPException(
            status_code=404,
            detail=(
                f"hit '{hit_id}' not found (scenario "
                f"'{matched_scenario.value}' produces no watchlist hits)"
            ),
        )

    if "_" not in rest:
        raise HTTPException(
            status_code=404, detail=f"hit '{hit_id}' not found (missing index)"
        )
    slug, _, idx_str = rest.rpartition("_")
    try:
        idx = int(idx_str)
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"hit '{hit_id}' not found (bad index)",
        ) from exc
    if not slug:
        raise HTTPException(
            status_code=404, detail=f"hit '{hit_id}' not found (empty slug)"
        )
    # Clamp index: the screening endpoints emit at most 2 hits today; allow
    # the full byte range here so the detail endpoint stays decoupled from
    # the screening count cap (a future change to that cap won't invalidate
    # already-issued hit_ids).
    if idx < 0 or idx > 99:
        raise HTTPException(
            status_code=404, detail=f"hit '{hit_id}' not found (index out of range)"
        )
    return matched_scenario, slug, idx


def _hit_detail(hit_id: str) -> dict[str, Any]:
    """Detail record for a watchlist hit.

    The hit_id is parsed back into (scenario, name_slug, index) and the hit
    is regenerated from a seed derived from the id. We don't have the
    original queried name (only its slug), so we report the slug back as
    ``queried_name`` — investigators get a stable record and the cross-mock
    test can pin the slug it expects.
    """
    _scenario, slug, _idx = _parse_hit_id(hit_id)
    # Without the original mixed-case name we report the slug; the
    # ``listed_name`` carries the same shape so downstream skills don't
    # special-case missing-case data.
    return _materialize_hit(
        hit_id=hit_id, queried_name=slug, entity_type="natural_person"
    )


# --------------------------------------------------------------------------- #
# FastAPI app                                                                 #
# --------------------------------------------------------------------------- #


def create_app() -> FastAPI:
    """Build the sanctions FastAPI app.

    Stateless and pure — no startup hooks, no external deps. Each request
    regenerates from the seed, so identical inputs produce identical outputs.
    """
    app = FastAPI(
        title="sanctions mock API",
        version="0.1.0",
        description=(
            "Mock OFAC-style watchlist screening API. Exposes name + entity "
            "screening plus per-hit detail lookup. Deterministic from the "
            "queried name; scenario-aware via "
            "?scenario=clean|mule|sanctions_hit|ato|structuring|synthetic_id. "
            "Only sanctions_hit produces real watchlist matches."
        ),
    )
    instrument_fastapi(app, service_name="fraud-mock-sanctions")

    @app.get("/screen/name")
    def screen_name(
        name: NameParam, scenario: ScenarioParam = None
    ) -> dict[str, Any]:
        ctx = _context(name, scenario)
        return _screen(ctx, entity_type="natural_person")

    @app.get("/screen/entity")
    def screen_entity(
        entity_name: NameParam, scenario: ScenarioParam = None
    ) -> dict[str, Any]:
        ctx = _context(entity_name, scenario)
        return _screen(ctx, entity_type="entity")

    @app.get("/hits/{hit_id}")
    def get_hit(hit_id: str) -> dict[str, Any]:
        return _hit_detail(hit_id)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


def build_default_app() -> FastAPI:
    """Construct the sanctions app for ``uvicorn``-style launchers.

    No env vars consumed — the mock is stateless and reads no configuration.
    """
    return create_app()


__all__ = [
    "ALL_SCENARIOS",
    "Scenario",
    "build_default_app",
    "create_app",
]
