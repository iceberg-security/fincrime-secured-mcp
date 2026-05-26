---
description: "Show the last N rows of the fraud-copilot audit DB (default 20)"
argument-hint: "[N]"
allowed-tools: ["Bash(docker exec fraud-mcp-gateway python:*)"]
---

# Audit Trail

Show the user the most recent audit rows from the MCP gateway. This proves every model action was signed, RBAC-checked, and logged.

```!
docker exec fraud-mcp-gateway python -c "
import sqlite3
c = sqlite3.connect('/app/audit/audit.db')
for row in c.execute('SELECT ts, sub, server, tool, status, latency_ms FROM audit_events ORDER BY ts DESC LIMIT ${ARGUMENTS:-20}'):
    print(f'{row[0]}  {row[1]:<24}  {row[2]:<14}  {row[3]:<28}  {row[4]:<6}  {row[5]}ms')
"
```

If the container is not running, tell the user to run `/fraud-stack-up` or `make compose-up` from the repo root and try again.
