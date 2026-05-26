"""Transactions mock API (US-012).

Mocks a transactions / payments-rail API: per-customer transaction history,
counterparty aggregation, and a velocity-anomaly detector. Deterministic
(seeded by customer_id) and scenario-aware. Cross-consistent with
``mock_apis.customer_data`` for the same ``(customer_id, scenario)``.
"""
