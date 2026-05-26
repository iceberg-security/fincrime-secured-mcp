# mock_apis/transactions/

Mock payments/ledger API. Pure in-memory, zero external deps. Second concrete
downstream the gateway federates to (US-007 → US-009 → **US-012**).

## Endpoints

| Method | Path                                            | Returns                                                                                                                                          |
| ------ | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET`  | `/customers/{customer_id}/transactions`         | `{customer_id, scenario, transactions: [{tx_id, amount, direction, type, merchant_category, counterparty_id, counterparty_country, days_ago, …}]}` |
| `GET`  | `/customers/{customer_id}/counterparties`       | `{customer_id, scenario, counterparties: [{counterparty_id, country, tx_count, inbound_total, outbound_total, first_seen_days_ago, last_seen_days_ago}]}` |
| `GET`  | `/customers/{customer_id}/velocity-anomalies`   | `{customer_id, scenario, transaction_count, inbound_count, structuring_candidate_count, cross_border_count, distinct_counterparty_countries, flags: [...]}` |
| `GET`  | `/healthz`                                      | Liveness.                                                                                                                                       |

All three data endpoints accept an optional `?scenario=` query param.
`/transactions` additionally accepts `?limit=1..500` (default 50).

## Scenarios

Same six personas as the other mocks: `clean | mule | sanctions_hit | ato |
structuring | synthetic_id`. The implicit default (no `?scenario=`) is picked
deterministically from `sha256(customer_id|"scenario")` — **the same salt**
the customer_data mock uses, so both mocks agree on a per-customer default.
This is enforced by `test_default_scenario_agrees_with_customer_data_mock`;
if you change either mock's default salt, that test fails.

### Scenario shapes
- **clean** — 8-16 txs, low amounts, low-risk geo, no flags.
- **mule** — 40-60 txs. Every 3rd row is a high-value (`$4k-$9.5k`) inbound
  `wire` from `_COUNTRIES_MULE_HUBS` (NG/RU/TR/MY/HK), the rest are
  outbound `transfer` rows. Surfaces `burst_inbound` + `mule_hub_inflow`.
- **structuring** — 25-40 cash deposits all in `$8.5k–$9.9k` (sub-CTR-threshold).
  Surfaces `structuring_pattern` (>=5 structuring candidates) + `burst_inbound`.
- **sanctions_hit** — 15-25 txs; every 4th is a wire to/from a
  high-risk country (IR/KP/SY/CU/VE). Surfaces `cross_border_burst`.
- **ato** — 18-30 txs; last 3 rows are high-value online_retail card_purchases
  from a high-risk geo (mirrors the suspicious-device tail in customer_data's
  ATO scenario). Surfaces `cross_border_burst`.
- **synthetic_id** — Thin file: 10-20 small card_purchase rows, no flags.

## Determinism contract

- Same `(customer_id, scenario)` → identical payload bytes. No clock, no UUID.
- Seeds come from `sha256(customer_id|salt|…)` via the inlined `_seed_from`
  helper. **The hash function and salt encoding must match customer_data**.
  If you change one, change the other in lockstep or cross-mock scenario
  defaults will drift.
- The counterparty rollup is derived from the **full** tx set (not the
  `?limit=` slice), so callers get a stable verdict regardless of paging.
  Same for `/velocity-anomalies` — the flags are computed off the full set.

## Cross-mock consistency

The transactions mock and the customer_data mock should describe the same
customer when given the same `(customer_id, scenario)`:

| Scenario        | customer_data signal                  | transactions signal                                  |
| --------------- | ------------------------------------- | ---------------------------------------------------- |
| `clean`         | low risk_score, no flags              | low tx count, no anomaly flags                       |
| `mule`          | `recent_account` flag, 3-5 accounts   | `burst_inbound` + `mule_hub_inflow`, 40-60 txs       |
| `structuring`   | `repeated_sub_threshold_cash` flag    | `structuring_pattern`, 25-40 cash deposits           |
| `sanctions_hit` | `sanctions_watchlist_possible`, PEP   | `cross_border_burst`, high-risk country wires       |
| `ato`           | `device_change_recent`, 3-5 devices   | suspicious tail of high-risk online_retail purchases |
| `synthetic_id`  | `kyc_status=needs_review`, thin file  | thin file: small card_purchases only                 |

## Adding a new scenario

1. Add it to the `Scenario` StrEnum (here AND in customer_data — both mocks
   must know the same set, otherwise `_resolve_scenario` rejects).
2. Add a branch in `_transactions` that shapes the rows uniquely. The
   `test_scenarios_produce_distinct_velocity_signatures` test asserts no two
   scenarios collapse to the same `(tx_count, inbound, structuring,
   cross_border, flags)` tuple.
3. Mirror the scenario in the other five mocks as they land (US-013..US-016).

## Pitfalls

- **`Annotated[…, Query(…)]` aliases at module scope only.** Pydantic v2's
  TypeAdapter can't resolve them inside `create_app()`. Same gotcha as
  customer_data — see `ScenarioParam` / `LimitParam` at module top.
- **The counterparty rollup must NOT depend on `?limit=`.** A test pins this
  invariant; if you optimize by reusing the windowed result, the rollup
  silently shrinks and downstream eval scorers (US-027) will produce
  unstable verdicts.
- **No state.** `build_default_app()` reads no env vars — keep it that way;
  this mock is stateless on purpose.
