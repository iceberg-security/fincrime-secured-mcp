# mock_apis/customer_data/

Mock CRM-style API. Pure in-memory, zero external deps. First downstream the gateway federates to (US-007 → US-009).

## Endpoints

| Method | Path                              | Returns                                                  |
| ------ | --------------------------------- | -------------------------------------------------------- |
| `GET`  | `/customers/{customer_id}`        | Profile (name, dob, country, kyc_status, pep, flags, …)  |
| `GET`  | `/customers/{customer_id}/accounts` | `{customer_id, scenario, accounts: [...]}`             |
| `GET`  | `/customers/{customer_id}/devices`  | `{customer_id, scenario, devices: [...]}`              |
| `GET`  | `/healthz`                        | Liveness.                                                |

All three data endpoints accept an optional `?scenario=` query param.

## Scenarios

`clean | mule | sanctions_hit | ato | structuring | synthetic_id` — the same six personas the rest of the mock stack and the eval datasets (US-025/US-026) share.

When omitted, the scenario is picked **deterministically from the customer_id**, so callers that don't care about scenarios still get plausible variety. Tests that rely on a specific shape MUST pin `?scenario=...` explicitly.

## Determinism contract

- Same `(customer_id, scenario)` → identical payload bytes. No clock, no UUID, no randomness that isn't seeded.
- Seeds are derived from `sha256(customer_id|salt|…)`. Don't introduce `random.random()` calls without a seeded `random.Random(_seed_from(…))`.
- The future `mcp_servers/customer_data/` (US-009) wraps this API — its contract tests will assume determinism.

## Adding a new scenario

1. Add it to the `Scenario` StrEnum.
2. Add a branch in `_profile`, `_accounts`, `_devices` that shapes the data uniquely (otherwise `test_scenarios_produce_distinct_payloads_for_same_customer` will fail — that test asserts no two scenarios collapse to the same signature).
3. Mirror the scenario in the other five mock APIs as they land (US-012–US-016). Cross-mock consistency for a given `customer_id+scenario` is the whole point of seeding.

## Pitfalls

- **Don't define `Annotated[…, Query(…)]` type aliases inside `create_app()`** — pydantic's TypeAdapter can't resolve the forward reference and request validation explodes with `PydanticUserError: not fully defined`. Module-scope only. (Burned on this once; ScenarioParam now sits at module top.)
- Synthetic ID intentionally returns a slightly off `dob` so the KYC mock (US-013) can surface a documented inconsistency. Don't "fix" it.
- No state. No startup hooks. `build_default_app()` reads no env vars — keep it that way; the only knob this mock should ever need is `?scenario=`.
