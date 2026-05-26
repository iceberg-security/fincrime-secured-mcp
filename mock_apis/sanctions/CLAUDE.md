# mock_apis/sanctions/

Mock OFAC-style watchlist screening API. Pure in-memory, zero external deps.
Fourth concrete downstream the gateway federates to
(US-007 → US-009 → US-012 → US-013 → **US-014**).

## Endpoints

| Method | Path                  | Returns                                                                                                                                     |
| ------ | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET`  | `/screen/name`        | `{query, scenario, matched, hits: [{hit_id, queried_name, listed_name, entity_type, program, hit_type, listed_on, country, match_score, aliases, addresses}]}` |
| `GET`  | `/screen/entity`      | Same shape as `/screen/name`; `entity_type="entity"`.                                                                                       |
| `GET`  | `/hits/{hit_id}`      | Single watchlist hit's detail record. Same fields as the screen result entries.                                                              |
| `GET`  | `/healthz`            | Liveness.                                                                                                                                  |

Both screening endpoints accept an optional `?scenario=` query param.
`/screen/name` takes `name` as a required query param; `/screen/entity` takes
`entity_name` (different param name on purpose so the MCP tool signatures
read naturally — `screen_name(name=...)` vs `screen_entity(entity_name=...)`).

## Scenarios

Same six personas as the other mocks: `clean | mule | sanctions_hit | ato |
structuring | synthetic_id`. The implicit default (no `?scenario=`) is picked
deterministically from `sha256(name|"scenario")` — same salt as the other
mocks but keyed off the queried `name` rather than a `customer_id`. This mock
is name-driven by design; the cross-mock contract is the *name* shared
across mocks (via the `first` / `last` salts in customer_data + kyc), not a
shared customer_id.

### Scenario shapes
- **clean / mule / ato / structuring / synthetic_id** — `matched=false`,
  empty `hits` list. The sanctions mock only matches in the `sanctions_hit`
  scenario; other persona signals belong to the other mocks.
- **sanctions_hit** — `matched=true`, 1-2 hits, each carrying
  `program ∈ {OFAC_SDN, EU_CONSOLIDATED, UN_SANCTIONS, UK_HMT}`,
  `hit_type ∈ {sdn_match, pep_match, adverse_media}`,
  `country ∈ _COUNTRIES_HIGH_RISK` (`{IR, KP, SY, CU, VE, RU}`),
  `match_score ∈ [82, 99]`, 1-3 aliases, one address.

## Cross-mock consistency

The single most load-bearing contract: a customer whose `customer_data`
profile carries `sanctions_watchlist_possible` + `pep=true` (scenario
`sanctions_hit`) AND whose `kyc` record carries `pep_flag=true` +
`sanctions_match=true` MUST screen with a real hit when this mock is called
with their `full_name` + `scenario=sanctions_hit`. The full_name is
identical across customer_data + kyc by virtue of the shared `first` /
`last` name seeds. Pinned by
`test_sanctions_hit_screens_same_person_as_customer_data_and_kyc`.

| Scenario        | customer_data signal                  | kyc signal                                   | sanctions signal                          |
| --------------- | ------------------------------------- | -------------------------------------------- | ----------------------------------------- |
| `clean`         | low risk_score, no flags              | verified, no inconsistencies                 | matched=false                             |
| `mule`          | `recent_account`, 3-5 accounts        | `recent_kyc_refresh`, verified               | matched=false                             |
| `structuring`   | `repeated_sub_threshold_cash`         | `kyc_refresh_recommended`                    | matched=false                             |
| `sanctions_hit` | `sanctions_watchlist_possible`, PEP   | `pep_flag=true`, `sanctions_match=true`      | **matched=true**, hits with high-risk country |
| `ato`           | `device_change_recent`, 3-5 devices   | `device_change_post_kyc`                     | matched=false                             |
| `synthetic_id`  | `kyc_status=needs_review`, thin file  | `ssn_dob_mismatch` inconsistency, shell UBO  | matched=false                             |

## Determinism contract

- Same `(name, scenario)` → identical payload bytes. No clock, no UUID.
- Seeds come from `sha256(value|salt|…)` via the inlined `_seed_from` helper.
  **The hash function and salt encoding must match customer_data +
  transactions + kyc.**
- `hit_id` is `hit_<scenario>_<name_slug>_<index>` where `name_slug` is a
  best-effort URL-safe collapse of the queried name (lowercased, non-alphanum
  → underscore). The detail endpoint regenerates the hit purely from the id,
  so an analyst can re-resolve a hit later without re-screening.

## hit_id parsing

`hit_id` parts may themselves contain underscores (e.g. `sanctions_hit`,
`alice_smith`), so the parser matches the scenario prefix against the known
enum values rather than splitting blindly. If you add a new scenario or
rename one, the parser auto-adapts via `ALL_SCENARIOS`.

## Adding a new scenario

1. Add it to the `Scenario` StrEnum here AND in customer_data + transactions
   + kyc — all mocks must know the same set, otherwise `_resolve_scenario`
   rejects.
2. Decide whether the new scenario should produce sanctions matches. If not,
   nothing else changes — `_screen` short-circuits everything except
   `SANCTIONS_HIT`. If it should, broaden the conditional in `_screen` and
   widen the `_parse_hit_id` allowed-scenario check.
3. Mirror the new scenario in the other mocks (US-015 / US-016).

## Pitfalls

- **Hit_id parsing is prefix-matching, not splitting.** `sanctions_hit` and
  `synthetic_id` are both two-word scenarios; the parser tries each
  `Scenario.value + "_"` against the remainder of the id. Don't replace it
  with `str.split("_")` without checking the `test_get_hit_*` cases.
- **`screen_name` and `screen_entity` use different param names** (`name`
  vs `entity_name`) on purpose — keeps the MCP tool signatures readable.
  FastAPI rejects calls that pass the wrong one with a 422.
- **No state.** `build_default_app()` reads no env vars — keep it that way.
- **Only sanctions_hit matches.** Don't sprinkle hits across other scenarios
  to "make the demo richer". The fence test
  `test_only_sanctions_hit_produces_real_matches` asserts every other
  scenario screens clean; that's the eval contract.
