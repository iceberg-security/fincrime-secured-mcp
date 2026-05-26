"""KYC mock API (US-013).

Mocks a KYC (Know Your Customer) records system: per-customer identity
verification record, document metadata, and an Ultimate Beneficial Owner
(UBO) tree. Deterministic (seeded by customer_id) and scenario-aware.
Cross-consistent with ``mock_apis.customer_data`` for the same
``(customer_id, scenario)`` — synthetic_id deliberately surfaces a dob
mismatch against the customer_data profile.
"""
