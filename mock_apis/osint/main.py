"""OSINT mock API — public-context lookups (US-015).

Stands in for an internal OSINT aggregator (web search index, page fetcher,
company-records database). Three endpoints + ``/healthz``:

    GET /web/search?query=&scenario=
        -> synthetic search-result list. Returns ``{query, scenario, results: [
           {url, title, snippet, published_year, source, adverse}]}``.

    GET /web/fetch?url=&scenario=
        -> synthetic page content for an internal-style URL. Returns
           ``{url, scenario, title, text, language, captured_year}``. No real
           network call — the mock manufactures the page from the URL itself.

    GET /companies/{company_name}?scenario=
        -> synthetic company record:
           ``{company_name, scenario, jurisdiction, incorporated_year,
              status, directors: [...], beneficial_owners: [...],
              risk_signals: [...]}``.

Determinism contract:

* Every output is derived from ``sha256(value|salt|…)``-based seeds via the
  same ``_seed_from`` helper used by the four prior mocks. Salt encoding
  matches so a customer's name + scenario produces consistent signals across
  customer_data, kyc, sanctions, and now osint.

* The ``?scenario=`` query param shifts shape into one of the six shared
  fraud personas:

    clean | mule | sanctions_hit | ato | structuring | synthetic_id

  Scenario rules in this mock:

  - ``clean`` — generic news/blog hits, no adverse media, no risk signals on
    company records.
  - ``mule`` — one money-laundering-typology blog post; company records show
    a recent incorporation in a low-risk jurisdiction.
  - ``sanctions_hit`` — adverse media on the queried name (regulator
    actions, watchlist mentions), company records carry
    ``sanctioned_owner`` + ``pep_director`` signals.
  - ``ato`` — one phishing-takeover forum result; company records normal.
  - ``structuring`` — one regulatory-bulletin hit on cash-structuring.
  - ``synthetic_id`` — one credit-bureau-discrepancy hit; company records
    show ``shell_company_indicators`` + offshore jurisdiction.

* When ``?scenario=`` is omitted the implicit default is picked
  deterministically from ``sha256(value|"scenario")`` — same salt the other
  mocks use. Cross-mock joins land via the **value** itself (the name passed
  to ``web_search`` is typically the customer's ``full_name`` shared across
  customer_data and kyc).

Zero external dependencies. Pure in-memory generation; no real outbound HTTP
fetches happen here — the **OSINT MCP server** enforces the outbound
allowlist when ``fetch_page`` is called (see ``mcp_servers/osint``). This
mock simply manufactures the page content.
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

QueryParam = Annotated[
    str,
    Query(min_length=1, max_length=200, description="Search query string."),
]

UrlParam = Annotated[
    str,
    Query(min_length=1, max_length=500, description="Page URL to fetch."),
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

    Mirrors the four prior mocks' ``_seed_from`` so cross-mock joins stay
    aligned. The salt encoding (UTF-8 bytes, pipe-separated) is the shared
    contract — don't fork it.
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

_SOURCES_NEWS = ["bloomberg.example", "reuters.example", "ft.example", "wsj.example"]
_SOURCES_REGULATORY = ["ofac.example", "fincen.example", "fca.example", "sec.example"]
_SOURCES_BLOG = ["medium.example", "substack.example", "wordpress.example"]
_LANGUAGES = ["en", "en", "en", "fr", "de", "es"]
_JURISDICTIONS_LOW_RISK = ["US-DE", "US-NV", "GB", "FR", "DE", "NL", "CA"]
_JURISDICTIONS_OFFSHORE = ["BVI", "PA", "BS", "KY", "BZ", "VG"]


# --------------------------------------------------------------------------- #
# Context                                                                     #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _QueryContext:
    query: str
    scenario: Scenario
    base_seed: int


def _default_scenario_for(value: str) -> Scenario:
    seed = _seed_from(value, "scenario")
    return ALL_SCENARIOS[seed % len(ALL_SCENARIOS)]


def _resolve_scenario(value: str, requested: str | None) -> Scenario:
    if requested is None:
        return _default_scenario_for(value)
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


def _context(value: str, scenario_param: str | None) -> _QueryContext:
    scenario = _resolve_scenario(value, scenario_param)
    return _QueryContext(
        query=value,
        scenario=scenario,
        base_seed=_seed_from(value, scenario.value),
    )


# --------------------------------------------------------------------------- #
# Web search                                                                  #
# --------------------------------------------------------------------------- #


def _slug(value: str) -> str:
    """URL-safe lowercase slug. Mirrors the sanctions mock's ``_name_slug``."""
    out_chars: list[str] = []
    prev_underscore = False
    for ch in value.lower():
        if ch.isalnum():
            out_chars.append(ch)
            prev_underscore = False
        else:
            if not prev_underscore:
                out_chars.append("-")
                prev_underscore = True
    slug = "".join(out_chars).strip("-")
    return slug or "result"


def _search_baseline(ctx: _QueryContext, count: int) -> list[dict[str, Any]]:
    """Generic non-adverse hits, deterministic per (query, scenario)."""
    results: list[dict[str, Any]] = []
    for i in range(count):
        seed = _seed_from(ctx.query, ctx.scenario.value, f"baseline{i}")
        source = _rng_choice(seed, _SOURCES_NEWS + _SOURCES_BLOG)
        year = _rng_int(seed, 2015, 2024)
        slug = _slug(ctx.query)
        results.append(
            {
                "url": f"https://{source}/articles/{slug}-{i:02d}",
                "title": f"{ctx.query}: industry coverage ({year})",
                "snippet": (
                    f"Routine reporting on {ctx.query}. No adverse signals "
                    "detected in this excerpt."
                ),
                "published_year": year,
                "source": source,
                "adverse": False,
            }
        )
    return results


def _search(ctx: _QueryContext) -> dict[str, Any]:
    results: list[dict[str, Any]]
    if ctx.scenario == Scenario.CLEAN:
        results = _search_baseline(ctx, _rng_int(ctx.base_seed, 2, 4))
    elif ctx.scenario == Scenario.MULE:
        seed = _seed_from(ctx.query, "mule")
        adverse = {
            "url": (
                f"https://{_rng_choice(seed, _SOURCES_BLOG)}/typologies/"
                f"{_slug(ctx.query)}-money-mule"
            ),
            "title": (
                f"Suspected money-mule typology referencing {ctx.query}"
            ),
            "snippet": (
                "Forum post discusses transfers via newly-opened accounts "
                "tied to inbound wires from high-risk jurisdictions."
            ),
            "published_year": _rng_int(seed, 2022, 2024),
            "source": _rng_choice(seed, _SOURCES_BLOG),
            "adverse": True,
        }
        results = [adverse, *_search_baseline(ctx, _rng_int(ctx.base_seed, 1, 3))]
    elif ctx.scenario == Scenario.SANCTIONS_HIT:
        results = []
        for i in range(_rng_int(ctx.base_seed, 1, 2)):
            seed = _seed_from(ctx.query, "sanctions", f"adv{i}")
            results.append(
                {
                    "url": (
                        f"https://{_rng_choice(seed, _SOURCES_REGULATORY)}/"
                        f"actions/{_slug(ctx.query)}-{i:02d}"
                    ),
                    "title": (
                        f"Regulatory action involving {ctx.query} on watchlist"
                    ),
                    "snippet": (
                        f"Authorities announced enforcement action naming "
                        f"{ctx.query} in connection with sanctioned "
                        "jurisdictions and PEP exposure."
                    ),
                    "published_year": _rng_int(seed, 2020, 2024),
                    "source": _rng_choice(seed, _SOURCES_REGULATORY),
                    "adverse": True,
                }
            )
        results.extend(_search_baseline(ctx, _rng_int(ctx.base_seed, 1, 2)))
    elif ctx.scenario == Scenario.ATO:
        seed = _seed_from(ctx.query, "ato")
        results = [
            {
                "url": (
                    f"https://{_rng_choice(seed, _SOURCES_BLOG)}/forums/"
                    f"{_slug(ctx.query)}-account-takeover"
                ),
                "title": (
                    f"Account-takeover discussion referencing {ctx.query}"
                ),
                "snippet": (
                    "Forum thread describes credential phishing kits "
                    "targeting customers of the named institution."
                ),
                "published_year": _rng_int(seed, 2022, 2024),
                "source": _rng_choice(seed, _SOURCES_BLOG),
                "adverse": True,
            },
            *_search_baseline(ctx, _rng_int(ctx.base_seed, 1, 3)),
        ]
    elif ctx.scenario == Scenario.STRUCTURING:
        seed = _seed_from(ctx.query, "structuring")
        results = [
            {
                "url": (
                    f"https://{_rng_choice(seed, _SOURCES_REGULATORY)}/"
                    f"bulletins/{_slug(ctx.query)}-structuring"
                ),
                "title": (
                    "Regulatory bulletin: cash structuring patterns near "
                    "CTR threshold"
                ),
                "snippet": (
                    f"Bulletin discusses repeated sub-threshold cash "
                    f"deposits in accounts associated with {ctx.query}."
                ),
                "published_year": _rng_int(seed, 2021, 2024),
                "source": _rng_choice(seed, _SOURCES_REGULATORY),
                "adverse": True,
            },
            *_search_baseline(ctx, _rng_int(ctx.base_seed, 1, 3)),
        ]
    else:  # SYNTHETIC_ID
        seed = _seed_from(ctx.query, "synthetic_id")
        results = [
            {
                "url": (
                    f"https://{_rng_choice(seed, _SOURCES_NEWS)}/identity/"
                    f"{_slug(ctx.query)}-credit-discrepancies"
                ),
                "title": (
                    f"Credit-bureau discrepancies tied to identity {ctx.query}"
                ),
                "snippet": (
                    "Article notes thin credit file and SSN-vs-DOB "
                    f"mismatches reported under the identity {ctx.query}."
                ),
                "published_year": _rng_int(seed, 2022, 2024),
                "source": _rng_choice(seed, _SOURCES_NEWS),
                "adverse": True,
            },
            *_search_baseline(ctx, _rng_int(ctx.base_seed, 1, 3)),
        ]

    return {
        "query": ctx.query,
        "scenario": ctx.scenario.value,
        "results": results,
        "adverse_count": sum(1 for r in results if r["adverse"]),
    }


# --------------------------------------------------------------------------- #
# Page fetch (synthetic — no real network)                                    #
# --------------------------------------------------------------------------- #


def _fetch_page(url: str, scenario_param: str | None) -> dict[str, Any]:
    """Manufacture page content for ``url``.

    The osint mock NEVER touches the real internet. The MCP server gates
    outbound URLs through its allowlist; this mock simply produces synthetic
    page text deterministically from the URL itself. Whatever URL the caller
    passes (allowlisted or not, real or made-up), we generate page bytes.
    """
    ctx = _context(url, scenario_param)
    seed = ctx.base_seed
    language = _rng_choice(_seed_from(url, "lang"), _LANGUAGES)
    year = _rng_int(_seed_from(url, "year"), 2015, 2024)
    if ctx.scenario == Scenario.SANCTIONS_HIT:
        title = "Regulatory enforcement notice"
        text = (
            f"Authorities published an enforcement notice at {url} naming "
            "the listed parties in connection with sanctioned "
            "jurisdictions. The notice cites adverse-media reporting and "
            "lists watchlist references including OFAC SDN and EU "
            "consolidated entries."
        )
        adverse = True
    elif ctx.scenario == Scenario.MULE:
        title = "Money-mule typology coverage"
        text = (
            f"Coverage at {url} describes patterns consistent with "
            "money-mule activity: rapidly-opened accounts, repeated "
            "inbound wires from high-risk hubs, and outbound transfers to "
            "third parties shortly thereafter."
        )
        adverse = True
    elif ctx.scenario in {Scenario.ATO, Scenario.STRUCTURING, Scenario.SYNTHETIC_ID}:
        title = "Investigative report"
        text = (
            f"Report at {url} discusses patterns relevant to the "
            f"{ctx.scenario.value} fraud typology, including red flags and "
            "common indicators investigators look for."
        )
        adverse = True
    else:
        title = "Routine industry coverage"
        text = (
            f"The page at {url} contains routine industry coverage with "
            "no adverse signals detected."
        )
        adverse = False
    return {
        "url": url,
        "scenario": ctx.scenario.value,
        "title": title,
        "text": text,
        "language": language,
        "captured_year": year,
        "byte_size": len(text.encode("utf-8")),
        "adverse": adverse,
        # Tiny digest to let scorers verify they got the same page bytes back.
        "content_digest": hashlib.sha256(text.encode("utf-8")).hexdigest()[:16],
        # Echo a synthetic "fetched_from" so callers reading audits can tell
        # the page was generated by the mock and not a real fetch.
        "fetched_from": "mock_osint",
        "seed": seed % 100_000,
    }


# --------------------------------------------------------------------------- #
# Company lookup                                                              #
# --------------------------------------------------------------------------- #


def _company(name: str, scenario_param: str | None) -> dict[str, Any]:
    ctx = _context(name, scenario_param)
    base_seed = ctx.base_seed

    # Defaults: low-risk jurisdiction, natural-person director, no signals.
    jurisdiction = _rng_choice(
        _seed_from(name, "jurisdiction"), _JURISDICTIONS_LOW_RISK
    )
    incorporated_year = _rng_int(_seed_from(name, "incorporated"), 1995, 2024)
    status = "active"
    risk_signals: list[str] = []

    if ctx.scenario == Scenario.SANCTIONS_HIT:
        jurisdiction = _rng_choice(
            _seed_from(name, "jurisdiction_high"), _JURISDICTIONS_OFFSHORE
        )
        risk_signals = ["sanctioned_owner", "pep_director", "adverse_media"]
    elif ctx.scenario == Scenario.SYNTHETIC_ID:
        jurisdiction = _rng_choice(
            _seed_from(name, "jurisdiction_offshore"), _JURISDICTIONS_OFFSHORE
        )
        risk_signals = ["shell_company_indicators", "thin_records"]
    elif ctx.scenario == Scenario.MULE:
        incorporated_year = 2024
        risk_signals = ["recent_incorporation"]
    elif ctx.scenario == Scenario.STRUCTURING:
        risk_signals = ["repeated_cash_filings"]
    elif ctx.scenario == Scenario.ATO:
        risk_signals = ["recent_director_change"]
    # clean -> no signals

    directors: list[dict[str, Any]] = []
    director_count = _rng_int(base_seed, 1, 3)
    for i in range(director_count):
        seed_i = _seed_from(name, ctx.scenario.value, f"director{i}")
        directors.append(
            {
                "name": f"Director {i + 1} of {name}",
                "country": jurisdiction[:2] if len(jurisdiction) >= 2 else "US",
                "appointed_year": _rng_int(seed_i, incorporated_year, 2024),
                "pep_flag": (
                    ctx.scenario == Scenario.SANCTIONS_HIT and i == 0
                ),
            }
        )

    if ctx.scenario == Scenario.SYNTHETIC_ID:
        # Layered ownership echo of the kyc mock's UBO tree.
        beneficial_owners = [
            {
                "name": f"Holdco of {name}",
                "owner_type": "entity",
                "ownership_pct": 100,
                "country": "PA",
            }
        ]
    elif ctx.scenario == Scenario.SANCTIONS_HIT:
        beneficial_owners = [
            {
                "name": f"Owner of {name}",
                "owner_type": "natural_person",
                "ownership_pct": 100,
                "country": jurisdiction[:2] if len(jurisdiction) >= 2 else "IR",
                "pep_flag": True,
            }
        ]
    else:
        beneficial_owners = [
            {
                "name": f"Owner of {name}",
                "owner_type": "natural_person",
                "ownership_pct": 100,
                "country": (
                    jurisdiction[:2] if len(jurisdiction) >= 2 else "US"
                ),
            }
        ]

    return {
        "company_name": name,
        "scenario": ctx.scenario.value,
        "jurisdiction": jurisdiction,
        "incorporated_year": incorporated_year,
        "status": status,
        "directors": directors,
        "beneficial_owners": beneficial_owners,
        "risk_signals": risk_signals,
    }


# --------------------------------------------------------------------------- #
# FastAPI app                                                                 #
# --------------------------------------------------------------------------- #


def create_app() -> FastAPI:
    """Build the OSINT FastAPI app.

    Stateless and pure — no startup hooks, no external deps, no real network
    fetches. The MCP server (mcp_servers/osint) wraps this and adds the
    outbound-allowlist gate.
    """
    app = FastAPI(
        title="osint mock API",
        version="0.1.0",
        description=(
            "Mock OSINT aggregator. Synthesizes search results, page content, "
            "and company records deterministically from the query/url/name "
            "and an optional ?scenario= parameter."
        ),
    )
    instrument_fastapi(app, service_name="fraud-mock-osint")

    @app.get("/web/search")
    def web_search(query: QueryParam, scenario: ScenarioParam = None) -> dict[str, Any]:
        ctx = _context(query, scenario)
        return _search(ctx)

    @app.get("/web/fetch")
    def web_fetch(url: UrlParam, scenario: ScenarioParam = None) -> dict[str, Any]:
        return _fetch_page(url, scenario)

    @app.get("/companies/{company_name}")
    def lookup_company(
        company_name: str, scenario: ScenarioParam = None
    ) -> dict[str, Any]:
        if not company_name:
            raise HTTPException(status_code=400, detail="empty company_name")
        return _company(company_name, scenario)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


def build_default_app() -> FastAPI:
    """Construct the osint mock for ``uvicorn``-style launchers.

    No env vars consumed — the mock is stateless and reads no configuration.
    """
    return create_app()


__all__ = [
    "ALL_SCENARIOS",
    "Scenario",
    "build_default_app",
    "create_app",
]
