"""Seed the six scenario personas across the running mock stack (US-024).

The mock APIs are **stateless and deterministic** — every `(customer_id,
scenario)` pair already returns identical bytes on every call (see
`mock_apis/*/CLAUDE.md`). Nothing needs to be written into the mocks
themselves.

What this script does instead is **exercise the federated read path through
the live gateway for each of the six personas**:

    clean | mule | sanctions_hit | ato | structuring | synthetic_id

For each persona we mint a user PASETO via the mock OIDC + auth gateway,
call a representative tool on every downstream MCP server, and let the MCP
gateway record one audit row per call. The resulting audit DB makes the
Grafana panels (US-023) render non-empty out of the box.

Idempotent: re-running just appends more audit rows. The mock APIs cannot
drift because they hold no state.

Usage::

    make compose-up
    make load-fixtures            # uses default --gateway URLs (localhost)

    # Or hit a non-default stack:
    python scripts/load_fixtures.py --auth-gateway http://localhost:8080 \\
                                    --mcp-gateway  http://localhost:8000 \\
                                    --oidc         http://localhost:9000

The script exits non-zero if any persona fails to complete the full read
loop, so it doubles as an end-to-end smoke test for the M1 stack.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

DEFAULT_OIDC_URL = "http://localhost:9000"
DEFAULT_AUTH_URL = "http://localhost:8080"
DEFAULT_MCP_URL = "http://localhost:8000"

# Personas: one customer_id per scenario, both for human readability in the
# audit log and so each row is grouped tidily by sub + (server, tool).
PERSONAS: tuple[tuple[str, str], ...] = (
    ("clean", "cust-clean-01"),
    ("mule", "cust-mule-01"),
    ("sanctions_hit", "cust-sanctions-01"),
    ("ato", "cust-ato-01"),
    ("structuring", "cust-structuring-01"),
    ("synthetic_id", "cust-synthetic-01"),
)

# Read-only calls covering all five non-write MCP servers. case_actions is
# intentionally excluded — it requires human_approval=true on the PASETO and
# would write to the in-memory journal.
READ_CALLS: tuple[tuple[str, str, dict[str, object]], ...] = (
    ("customer_data", "get_customer", {}),
    ("customer_data", "list_accounts", {}),
    ("customer_data", "get_device_history", {}),
    ("transactions", "get_transactions", {"limit": 25}),
    ("transactions", "get_counterparties", {}),
    ("transactions", "flag_velocity_anomalies", {}),
    ("kyc", "get_kyc_record", {}),
    ("kyc", "get_ubo_tree", {}),
    ("sanctions", "screen_name", {"_uses_name": True}),
    ("osint", "web_search", {"_uses_name_as_query": True}),
    ("osint", "lookup_company", {"_uses_company": True}),
)

# Default analyst user — has access to every read-only server per
# config/rbac.yaml. Override with --email if you've changed the seed users.
DEFAULT_EMAIL = "alice@example.com"


@dataclass
class FixtureResult:
    scenario: str
    customer_id: str
    successes: int
    failures: list[str]


def _get_oidc_token(oidc_url: str, email: str, *, timeout: float) -> str:
    url = f"{oidc_url.rstrip('/')}/login?email={email}"
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    token = body.get("access_token")
    if not isinstance(token, str) or not token:
        raise RuntimeError(f"mock OIDC did not return an access_token: {body!r}")
    return token


def _mint_user_paseto(auth_url: str, oidc_token: str, *, timeout: float) -> str:
    req = urllib.request.Request(
        f"{auth_url.rstrip('/')}/token",
        method="POST",
        headers={"Authorization": f"Bearer {oidc_token}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    token = body.get("access_token")
    if not isinstance(token, str) or not token:
        raise RuntimeError(f"auth gateway did not return an access_token: {body!r}")
    return token


def _call_tool(
    mcp_url: str,
    paseto: str,
    server: str,
    tool: str,
    arguments: dict[str, object],
    *,
    timeout: float,
) -> tuple[int, dict[str, object]]:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        f"{mcp_url.rstrip('/')}/mcp/{server}",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {paseto}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            return resp.status, payload
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            payload = {"text": str(exc)}
        return exc.code, payload


def _name_for_persona(persona: str, customer_id: str) -> str:
    """Best-effort screen-name. The sanctions mock returns matches keyed by
    name + scenario, so passing a recognizable name keeps the audit row tidy.
    The mock will hash on the value; we just want determinism."""
    return f"Customer {customer_id}"


def _company_for_persona(persona: str, customer_id: str) -> str:
    return f"{customer_id}-counterparty"


def _build_arguments(
    template: dict[str, object],
    customer_id: str,
    persona: str,
) -> dict[str, object]:
    args: dict[str, object] = {"customer_id": customer_id, "scenario": persona}
    for key, value in template.items():
        if key.startswith("_"):
            continue
        args[key] = value
    if template.get("_uses_name"):
        args.pop("customer_id", None)
        args["name"] = _name_for_persona(persona, customer_id)
    if template.get("_uses_name_as_query"):
        args.pop("customer_id", None)
        args["query"] = _name_for_persona(persona, customer_id)
    if template.get("_uses_company"):
        args.pop("customer_id", None)
        args["company_name"] = _company_for_persona(persona, customer_id)
    return args


def _seed_persona(
    *,
    oidc_url: str,
    auth_url: str,
    mcp_url: str,
    email: str,
    persona: str,
    customer_id: str,
    timeout: float,
    verbose: bool,
) -> FixtureResult:
    failures: list[str] = []
    successes = 0
    for server, tool, template in READ_CALLS:
        # The gateway enforces jti-replay so each call needs its own fresh user
        # PASETO. Re-mint per call.
        try:
            oidc_token = _get_oidc_token(oidc_url, email, timeout=timeout)
            paseto = _mint_user_paseto(auth_url, oidc_token, timeout=timeout)
        except (urllib.error.URLError, RuntimeError) as exc:
            failures.append(f"auth: {server}.{tool}: {exc}")
            continue
        args = _build_arguments(template, customer_id, persona)
        try:
            status, payload = _call_tool(
                mcp_url, paseto, server, tool, args, timeout=timeout
            )
        except urllib.error.URLError as exc:
            failures.append(f"network: {server}.{tool}: {exc}")
            continue
        if status >= 400:
            failures.append(
                f"{server}.{tool} -> HTTP {status} {json.dumps(payload)[:120]}"
            )
            continue
        if "error" in payload:
            failures.append(f"{server}.{tool} -> RPC error {payload['error']}")
            continue
        successes += 1
        if verbose:
            print(f"  ok  {persona:<14} {server}.{tool}")
    return FixtureResult(
        scenario=persona,
        customer_id=customer_id,
        successes=successes,
        failures=failures,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oidc", default=DEFAULT_OIDC_URL, help="Mock OIDC base URL")
    parser.add_argument(
        "--auth-gateway", default=DEFAULT_AUTH_URL, help="Auth gateway base URL"
    )
    parser.add_argument(
        "--mcp-gateway", default=DEFAULT_MCP_URL, help="MCP gateway base URL"
    )
    parser.add_argument(
        "--email",
        default=DEFAULT_EMAIL,
        help=f"User to mint PASETOs for (default: {DEFAULT_EMAIL})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-HTTP-call timeout in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Print one line per tool call"
    )
    args = parser.parse_args(argv)

    started = time.perf_counter()
    print(
        f"Seeding {len(PERSONAS)} personas x {len(READ_CALLS)} read calls "
        f"against {args.mcp_gateway} (user={args.email})"
    )
    results: list[FixtureResult] = []
    for persona, customer_id in PERSONAS:
        result = _seed_persona(
            oidc_url=args.oidc,
            auth_url=args.auth_gateway,
            mcp_url=args.mcp_gateway,
            email=args.email,
            persona=persona,
            customer_id=customer_id,
            timeout=args.timeout,
            verbose=args.verbose,
        )
        results.append(result)
        status = "OK" if not result.failures else "PARTIAL"
        print(
            f"  [{status}] {persona:<14} customer_id={customer_id} "
            f"({result.successes}/{len(READ_CALLS)} ok)"
        )
        for failure in result.failures:
            print(f"     - {failure}")

    elapsed = time.perf_counter() - started
    total_calls = len(PERSONAS) * len(READ_CALLS)
    total_ok = sum(r.successes for r in results)
    total_fail = total_calls - total_ok
    print(
        f"\nSeed complete in {elapsed:.1f}s: "
        f"{total_ok}/{total_calls} calls OK, {total_fail} failed."
    )
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
