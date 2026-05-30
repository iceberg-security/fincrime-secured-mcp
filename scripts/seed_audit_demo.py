"""Seed the audit DB with realistic, varied demo activity.

The default local stack runs a single analyst (alice) through one investigation,
which leaves the Grafana dashboard's "Tool calls per user" and "Denied requests
by role" panels with 0-1 rows — too sparse for the bar charts to render well.

This script writes additional synthetic audit rows through the gateway's own
``write_event`` API (correct schema + redaction + append-only semantics) so the
dashboard has multiple users, multiple roles, a spread across days, and a
handful of denied requests. Idempotency is NOT attempted — re-running adds more
rows (append-only by design). Intended for demos, not production.

Run inside the mcp-gateway container so it targets the live audit volume:

    docker compose exec -T mcp-gateway python3 scripts/seed_audit_demo.py
"""

from __future__ import annotations

import hashlib
import sys
from datetime import UTC, datetime, timedelta

# The gateway image has the package importable from /app.
sys.path.insert(0, "/app")
sys.path.insert(0, ".")

from gateways.common import audit  # noqa: E402
from gateways.common.audit import AuditEvent  # noqa: E402

# Analysts/reviewers we want to see in the "Tool calls per user" chart.
USERS = [
    ("alice@example.com", "analyst"),
    ("bob@example.com", "analyst"),
    ("carol@example.com", "reviewer"),
    ("dave@example.com", "analyst"),
    ("erin@example.com", "supervisor"),
]

# (server, tool) pairs drawn from the real tool surface.
TOOLS = [
    ("customer_data", "get_customer"),
    ("customer_data", "list_accounts"),
    ("customer_data", "get_device_history"),
    ("transactions", "get_transactions"),
    ("transactions", "get_counterparties"),
    ("transactions", "flag_velocity_anomalies"),
    ("osint", "web_search"),
    ("sanctions", "screen_name"),
    ("kyc", "get_kyc_record"),
]

# A few denied attempts so the "Denied requests by role" panel has stacked bars.
DENIALS = [
    ("dave@example.com", "analyst", "case_actions", "freeze_account", "tool_not_allowed"),
    ("dave@example.com", "analyst", "case_actions", "create_sar_draft", "human_approval_required"),
    ("bob@example.com", "analyst", "osint", "fetch_page", "domain_not_allowed"),
    ("carol@example.com", "reviewer", "case_actions", "freeze_account", "tool_not_allowed"),
    ("carol@example.com", "reviewer", "osint", "fetch_page", "domain_not_allowed"),
]


def _jti(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:32]


def _ts(days_ago: int, idx: int) -> str:
    # Spread rows across several days (for the volume chart) and within the day.
    base = datetime.now(tz=UTC) - timedelta(days=days_ago)
    base = base.replace(hour=9, minute=0, second=0, microsecond=0) + timedelta(minutes=idx * 3)
    return base.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


def main() -> None:
    backend = audit.get_backend()
    n = 0

    # Successful tool calls: every user exercises a varied slice of tools,
    # spread across the last 5 days so the volume chart has multiple buckets.
    for u_idx, (sub, role) in enumerate(USERS):
        # Give each user a different volume so the bar chart has visible spread.
        call_count = 6 + u_idx * 4
        for i in range(call_count):
            server, tool = TOOLS[(u_idx + i) % len(TOOLS)]
            days_ago = i % 5
            ev = AuditEvent(
                sub=sub,
                role=role,
                server=server,
                tool=tool,
                jti=_jti(f"{sub}:{tool}:{i}"),
                trace_id=hashlib.sha256(f"{sub}:{i}".encode()).hexdigest(),
                args_preview={"customer_id": f"cust-demo-{u_idx:02d}"},
                result_hash=hashlib.sha256(f"{sub}:{tool}:{i}:r".encode()).hexdigest(),
                status="ok",
                latency_ms=2 + (i % 9),
                ts=_ts(days_ago, i),
            )
            backend.write(ev)
            n += 1

    # Denied attempts.
    for d_idx, (sub, role, server, tool, reason) in enumerate(DENIALS):
        ev = AuditEvent(
            sub=sub,
            role=role,
            server=server,
            tool=tool,
            jti=_jti(f"deny:{sub}:{tool}:{d_idx}"),
            trace_id=hashlib.sha256(f"deny:{sub}:{d_idx}".encode()).hexdigest(),
            args_preview={"customer_id": f"cust-demo-{d_idx:02d}"},
            result_hash="",
            status="denied",
            deny_reason=reason,
            latency_ms=1,
            ts=_ts(d_idx % 5, d_idx),
        )
        backend.write(ev)
        n += 1

    backend.flush()
    print(f"seeded {n} audit rows across {len(USERS)} users ({len(DENIALS)} denied)")


if __name__ == "__main__":
    main()
