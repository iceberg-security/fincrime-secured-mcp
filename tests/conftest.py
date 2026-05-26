"""Pytest-wide fixtures and environment setup.

Sets ``FRAUD_OTEL_NOOP=true`` by default so the OTel SDK records spans but
does not export them — keeping the test suite quiet without disabling the
SDK entirely (which would swap in a NoOpTracer and break the in-memory
exporter pattern in ``tests/test_otel.py``).
"""

from __future__ import annotations

import os

os.environ.setdefault("FRAUD_OTEL_NOOP", "true")
