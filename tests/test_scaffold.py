"""Smoke tests for the scaffold."""

from __future__ import annotations

import importlib


def test_packages_import() -> None:
    """Every top-level package should import cleanly."""
    for name in (
        "gateways",
        "gateways.common",
        "gateways.auth",
        "gateways.mcp",
        "mcp_servers",
        "mock_apis",
        "evals",
        "evals.scorers",
    ):
        importlib.import_module(name)
