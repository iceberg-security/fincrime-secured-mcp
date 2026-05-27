"""Tail the fraud-copilot MCP gateway audit DB.

The SQLite audit DB lives on the ``audit_data`` named docker volume, mounted
inside the ``fraud-mcp-gateway`` container at ``/app/audit/audit.db``. This
script shells into the running container via ``docker compose exec`` and
prints the most recent ``audit_events`` rows, newest first.

Usage::

    python scripts/audit_tail.py            # last 20 rows
    python scripts/audit_tail.py -n 50      # last 50 rows
    make audit-tail N=50                    # equivalent via Make

Exits 1 if the gateway container is not running.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys

GATEWAY_SERVICE = "mcp-gateway"
INNER_SCRIPT = """
import sqlite3, sys
limit = int(sys.argv[1])
c = sqlite3.connect('/app/audit/audit.db')
rows = c.execute(
    'SELECT ts, sub, server, tool, status, latency_ms '
    'FROM audit_events ORDER BY ts DESC LIMIT ?',
    (limit,),
).fetchall()
for ts, sub, server, tool, status, latency_ms in rows:
    print(f'{ts}  {sub:<24}  {server:<14}  {tool:<28}  {status:<6}  {latency_ms}ms')
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-n",
        "--limit",
        type=int,
        default=20,
        help="number of most-recent rows to show (default: 20)",
    )
    args = parser.parse_args()

    if args.limit <= 0:
        parser.error("--limit must be a positive integer")

    if shutil.which("docker") is None:
        print("error: 'docker' not found on PATH", file=sys.stderr)
        return 1

    cmd = [
        "docker",
        "compose",
        "exec",
        "-T",
        GATEWAY_SERVICE,
        "python",
        "-c",
        INNER_SCRIPT,
        str(args.limit),
    ]
    result = subprocess.run(cmd)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
