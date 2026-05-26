# mock_apis/osint/

Mock OSINT aggregator (web search + page fetcher + company lookup). Pure
in-memory, zero external deps. Fifth concrete downstream the gateway
federates to (US-007 → US-009 → US-012 → US-013 → US-014 → **US-015**).

## Endpoints

| Method | Path                            | Returns                                                                                                                                          |
| ------ | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET`  | `/web/search?query=&scenario=`  | `{query, scenario, results: [{url, title, snippet, published_year, source, adverse}], adverse_count}`                                            |
| `GET`  | `/web/fetch?url=&scenario=`     | `{url, scenario, title, text, language, captured_year, byte_size, adverse, content_digest, fetched_from, seed}`                                  |
| `GET`  | `/companies/{company_name}?scenario=` | `{company_name, scenario, jurisdiction, incorporated_year, status, directors: [...], beneficial_owners: [...], risk_signals: [...]}`         |
| `GET`  | `/healthz`                      | Liveness.                                                                                                                                       |

`/web/search` takes `query` as a required query param (1..200 chars).
`/web/fetch` takes `url` as a required query param (1..500 chars).
`/companies/{name}` takes `name` as a path param.

**Important:** This mock NEVER touches the real internet. `/web/fetch`
manufactures synthetic page bytes deterministically from the URL. The MCP
server (`mcp_servers/osint`) is responsible for the **outbound allowlist**;
this mock is just a content generator behind it.

## Scenarios

Same six personas as the other mocks: `clean | mule | sanctions_hit | ato |
structuring | synthetic_id`. The implicit default (no `?scenario=`) is
picked deterministically from `sha256(value|"scenario")` — same salt as
customer_data/transactions/kyc/sanctions. Cross-mock joins land via the
**value** itself: typically the customer's `full_name` (shared across
customer_data + kyc + sanctions) is used as the `query` here.

### Scenario shapes
- **clean** — 2-4 generic news/blog hits, no adverse. Company records show
  no risk signals, low-risk jurisdiction.
- **mule** — one money-mule-typology forum post; rest are non-adverse.
  Company records show `recent_incorporation` (2024) in a low-risk
  jurisdiction.
- **sanctions_hit** — 1-2 regulator-action adverse hits + 1-2 baseline
  hits. Company records carry `sanctioned_owner` + `pep_director` +
  `adverse_media` signals, offshore jurisdiction, PEP-flagged owner +
  director.
- **ato** — one phishing-takeover forum hit; rest non-adverse. Company
  records show `recent_director_change`.
- **structuring** — one regulatory-bulletin hit on sub-CTR-threshold cash
  structuring. Company records show `repeated_cash_filings`.
- **synthetic_id** — one credit-bureau-discrepancy hit (thin file, SSN/DOB
  mismatch). Company records carry `shell_company_indicators` +
  `thin_records`, offshore jurisdiction (BVI/PA/BS/KY/BZ/VG), entity
  beneficial owner (layered).

## Determinism contract

- Same `(query/url/name, scenario)` → identical payload bytes. No clock,
  no UUID.
- Seeds come from `sha256(value|salt|…)` via the inlined `_seed_from`
  helper — fifth copy across the mocks. **The hash function and salt
  encoding must match the other four mocks.**
- `/web/fetch` is keyed off the **URL** as the seed value. Two different
  callers that fetch the same URL get the same bytes back.
- The `content_digest` field is a 16-char prefix of the sha256 of the
  manufactured page text — it lets the grounding scorer (US-028) pin "this
  was the page bytes the agent saw" without re-fetching.

## Cross-mock consistency

| Scenario        | customer_data signal                  | kyc signal                                   | sanctions signal              | osint signal                          |
| --------------- | ------------------------------------- | -------------------------------------------- | ----------------------------- | ------------------------------------- |
| `clean`         | low risk_score, no flags              | verified, no inconsistencies                 | matched=false                 | no adverse search, no risk signals    |
| `mule`          | `recent_account`                      | `recent_kyc_refresh`                         | matched=false                 | money-mule typology hit, recent incorp |
| `structuring`   | `repeated_sub_threshold_cash`         | `kyc_refresh_recommended`                    | matched=false                 | structuring bulletin hit              |
| `sanctions_hit` | `sanctions_watchlist_possible`, PEP   | `pep_flag=true`, `sanctions_match=true`      | matched=true, high-risk geo   | regulator-action adverse media + `sanctioned_owner` company signal |
| `ato`           | `device_change_recent`                | `device_change_post_kyc`                     | matched=false                 | phishing-forum hit                    |
| `synthetic_id`  | `kyc_status=needs_review`, year+1 dob | `ssn_dob_mismatch`, shell UBO                | matched=false                 | credit-discrepancy hit + shell company indicators |

## Pitfalls

- **No real network.** The mock never fetches `url` — it synthesizes bytes
  from the URL string. The allowlist gate is the **MCP server's**
  responsibility (mcp_servers/osint).
- **`Annotated[…, Query(…)]` aliases at module scope only** — same pydantic
  v2 forward-ref gotcha as every other mock.
- **`?scenario=` is optional everywhere.** When omitted, the per-value
  default is `_default_scenario_for(value)` and must agree with
  customer_data's helper. The fence test pins this against three
  customer_ids/names — drift breaks US-026 eval cross-mock chains.
- **`fetched_from="mock_osint"`** is included on every `/web/fetch` payload
  so a future scorer can sanity-check the response came from this mock and
  not a real fetch leaked through.

## Adding a new scenario

1. Add it to the `Scenario` StrEnum here AND in every other mock — they
   all share the vocabulary.
2. Add a branch in `_search`, `_fetch_page`, `_company` that shapes the
   data uniquely.
3. Mirror cross-mock signals (e.g. if the new scenario should produce
   adverse osint media, add a matching customer_data/kyc/sanctions
   signal).
