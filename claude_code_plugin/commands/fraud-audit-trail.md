---
description: "Show the last N rows of the fraud-copilot audit DB (default 20)"
argument-hint: "[N]"
allowed-tools: ["Bash(make:*)", "Bash(docker:*)", "Bash(cd:*)"]
---

# Audit Trail

Show the user the most recent audit rows from the MCP gateway. This proves every model action was signed, RBAC-checked, and logged.

The Make target lives in the `fincrime-secured-mcp` repo. The command below `cd`s into the repo first (typically `~/Desktop/iceberg-workspace/fincrime-secured-mcp` — if the user's clone is elsewhere, adjust the path). The `N=$ARGUMENTS` form is safe even when `$ARGUMENTS` is empty — the Makefile falls back to 20 in that case.

Run exactly this one command:

```!
cd ~/Desktop/iceberg-workspace/fincrime-secured-mcp && make audit-tail N=$ARGUMENTS
```

If `cd` fails because the repo lives elsewhere, ask the user for the correct path.

If `docker compose exec` reports the gateway container is not running, tell the user to run `/fraud-stack-up` or `make compose-up` from the repo root and try again.
