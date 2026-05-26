---
description: "Bring up the fraud-copilot-oss docker stack (auth gateway, MCP gateway, 6 mock APIs + MCP servers, Grafana)"
argument-hint: ""
allowed-tools: ["Bash(make:*)", "Bash(docker:*)", "Bash(curl:*)", "Bash(jq:*)", "Bash(.venv/bin/python:*)"]
---

# Bring up fraud-copilot stack

Run the project's standard bring-up sequence and seed the demo personas. The user must be in the fraud-copilot-oss repo root.

```!
make compose-up && sleep 5 && make compose-ps
```

If host port 8000 is taken (DynamoDB Local, etc.), the MCP gateway is configured to use **host port 8100** instead. Verify with the `compose-ps` output.

Then seed fixtures:

```!
.venv/bin/python scripts/load_fixtures.py --mcp-gateway http://localhost:8100
```

Confirm the full path works:

```!
TOKEN=$(curl -s "http://localhost:9000/login?email=alice@example.com" | jq -r .access_token) && PASETO=$(curl -s -X POST http://localhost:8080/token -H "Authorization: Bearer $TOKEN" | jq -r .access_token) && curl -s -X POST http://localhost:8100/mcp/customer_data -H "Authorization: Bearer $PASETO" -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_customer","arguments":{"customer_id":"cust-mule-01"}}}' | jq .
```

If you see a JSON result with `customer_id: cust-mule-01`, the stack is ready. The user can now run `/fraud-investigate cust-mule-01`.
