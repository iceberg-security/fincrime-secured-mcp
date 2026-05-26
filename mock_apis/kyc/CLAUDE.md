# mock_apis/kyc/

Mock KYC (Know Your Customer) API. Pure in-memory, zero external deps. Third
concrete downstream the gateway federates to (US-007 → US-009 → US-012 →
**US-013**).

## Endpoints

| Method | Path                                                  | Returns                                                                                                                                                  |
| ------ | ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET`  | `/customers/{customer_id}/kyc`                        | `{customer_id, full_name, dob, ssn_last4, id_document_type, id_document_number, issuer_country, verification_method, verified_at_year, kyc_status, pep_flag, sanctions_match, entity_type, inconsistencies: [...], scenario}` |
| `GET`  | `/customers/{customer_id}/documents`                  | `{customer_id, scenario, documents: [...]}`                                                                                                              |
| `GET`  | `/customers/{customer_id}/documents/{document_id}`    | `{document_id, customer_id, kind, issuer_country, expiry_year, verification_method, on_file, scenario}`                                                  |
| `GET`  | `/customers/{customer_id}/ubo`                        | `{customer_id, scenario, entity_type, owners: [{owner_id, owner_type, ownership_pct, country, is_natural_person_at_top, layers: [...]}], flags: [...]}` |
| `GET`  | `/healthz`                                            | Liveness.                                                                                                                                                |

All four data endpoints accept an optional `?scenario=` query param.

## Scenarios

Same six personas as the other mocks: `clean | mule | sanctions_hit | ato |
structuring | synthetic_id`. The implicit default (no `?scenario=`) is picked
deterministically from `sha256(customer_id|"scenario")` — **the same salt**
the other mocks use, so all three mocks agree on a per-customer default. This
is enforced by `test_default_scenario_agrees_with_customer_data_mock` (and a
similar one against transactions). If you change any mock's default salt,
all three fail.

### Scenario shapes
- **clean** — verified KYC, no inconsistencies, low-risk issuer country, full
  document set (id + address + selfie), trivial self-owned UBO.
- **mule** — verified KYC but with `recent_kyc_refresh` inconsistency
  (KYC re-run within 2024), full document set. UBO is trivial.
- **sanctions_hit** — `pep_flag=true`, `sanctions_match=true`,
  `kyc_status=needs_review`, issuer country in the high-risk set,
  inconsistencies = `[politically_exposed_person, sanctions_screening_match]`.
  UBO has `pep_at_top` flag.
- **ato** — KYC record itself is fine, but `device_change_post_kyc`
  inconsistency surfaces. Full document set.
- **structuring** — `kyc_refresh_recommended` inconsistency. Otherwise verified.
- **synthetic_id** — `kyc_status=needs_review`, inconsistencies =
  `[ssn_dob_mismatch, thin_credit_file, address_unverified]`. **Cross-mock
  contract**: this mock reports the "true" dob (derived from the same seeds
  as customer_data) while the customer_data mock plants `year+1` on its
  profile. Investigator comparing the two sees the gap. UBO is a layered
  shell-company tree with `no_natural_person_at_top` +
  `multi_layer_ownership` flags. Documents list is thin (just the ID), and
  the ID's `expiry_year` is 2025 (near-expired).

## Determinism contract

- Same `(customer_id, scenario)` → identical payload bytes. No clock, no UUID.
- Seeds come from `sha256(customer_id|salt|…)` via the inlined `_seed_from`
  helper. **The hash function and salt encoding must match customer_data +
  transactions**. The `dob` seeds (`dob_year`, `dob_month`, `dob_day`) and
  the name seeds (`first`, `last`) are deliberately reused from
  customer_data so the two mocks describe the same person for the same
  `customer_id`.
- The `synthetic_id` dob inconsistency is **load-bearing**: customer_data
  plants `year+1` deliberately and this mock reports the unshifted dob. The
  gap is the eval scenario's deliberate teaching moment. Don't normalize.

## Cross-mock consistency

| Scenario        | customer_data signal                      | kyc signal                                                       |
| --------------- | ----------------------------------------- | ---------------------------------------------------------------- |
| `clean`         | low risk_score, no flags                  | verified, no inconsistencies                                     |
| `mule`          | `recent_account`, 3-5 accounts            | `recent_kyc_refresh`, verified                                   |
| `structuring`   | `repeated_sub_threshold_cash`             | `kyc_refresh_recommended`                                        |
| `sanctions_hit` | `sanctions_watchlist_possible`, PEP       | `pep_flag=true`, `sanctions_match=true`, `pep_at_top` UBO flag   |
| `ato`           | `device_change_recent`, 3-5 devices       | `device_change_post_kyc`                                         |
| `synthetic_id`  | `kyc_status=needs_review`, dob = year+1   | `ssn_dob_mismatch` inconsistency, dob = year (true), shell UBO   |

## Adding a new scenario

1. Add it to the `Scenario` StrEnum (here AND in customer_data + transactions
   — all mocks must know the same set, otherwise `_resolve_scenario` rejects).
2. Add a branch in `_kyc_record`, `_document` (if shape changes), and
   `_ubo_tree` that shapes the data uniquely. The
   `test_scenarios_produce_distinct_kyc_signatures` test asserts no two
   scenarios collapse to the same signature.
3. Mirror the scenario in the other mocks as they land (US-014..US-016).

## Pitfalls

- **`Annotated[…, Query(…)]` aliases at module scope only.** Pydantic v2's
  TypeAdapter can't resolve them inside `create_app()`. Same gotcha as the
  other mocks — `ScenarioParam` lives at module top.
- **Document IDs are fixed per scenario** (`_document_ids_for`). Requesting
  a document_id outside that list returns 404. The MCP server's `get_document`
  tool surfaces this as `upstream_status=404`; don't smuggle it into a 500.
- **No state.** `build_default_app()` reads no env vars — keep it that way;
  this mock is stateless on purpose.
- The UBO tree is intentionally shallow for v1 (max one layer of nesting).
  Deeper structures will land with US-014 (sanctions) or US-027 (the
  reasoning scorer) if scoring needs them.
