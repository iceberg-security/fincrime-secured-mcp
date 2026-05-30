# fraud-copilot-oss

> **An open-source, agentic fraud-investigation copilot with the auth, RBAC, and
> audit plumbing that regulated industries actually need.**

**Showcase & integrator docs:** <https://iceberg-security.github.io/fincrime-secured-mcp/>

Most open-source MCP demos skip the load-bearing security layer. This one
ships it: a Claude Cowork plugin talks through an MCP gateway that mints
short-lived PASETO tokens, enforces declarative RBAC, audits every call,
and federates to six downstream MCP servers — each wrapping a mock data
source that an integrator swaps for their real backend.

Python everywhere. Apache 2.0. One `docker compose up` brings up the full
14+ service stack in under 30 seconds on an M-series MacBook.

---

## Architecture (30-second tour)

```
┌─────────────────────┐     OIDC bearer      ┌─────────────────────┐
│   Cowork Plugin     │ ───────────────────▶ │  Auth Gateway       │
│ (orchestrator +     │                      │  (PASETO mint)      │
│  subskills +        │                      └──────────┬──────────┘
│  verify-output)     │                                 │ user PASETO (5 min)
└──────────┬──────────┘                                 ▼
           │  user PASETO + JSON-RPC      ┌─────────────────────────┐
           └─────────────────────────────▶│  MCP Gateway            │
                                          │  - PASETO verify        │
                                          │  - replay cache (jti)   │
                                          │  - RBAC enforce         │
                                          │  - re-sign service token│
                                          │  - audit emit           │
                                          └──────────┬──────────────┘
                                                     │ service PASETO (60s, separate keypair)
                                                     ▼
                              ┌──────────────────────────────────────────────┐
                              │   6 downstream MCP servers (FastMCP)         │
                              │   customer_data, transactions, kyc,          │
                              │   sanctions, osint, case_actions             │
                              └──────────┬───────────────────────────────────┘
                                         │ HTTP (loopback / cluster-local)
                                         ▼
                              ┌──────────────────────────────────────────────┐
                              │   6 mock APIs (FastAPI, in-memory)           │
                              │   ─ replaced by integrator's real backends   │
                              └──────────────────────────────────────────────┘
```

Audit rows land in SQLite (default) or ClickHouse (opt-in). OpenTelemetry
spans correlate every hop via the PASETO `trace_id` claim. The
[threat model](docs/threat-model.md) walks the trust boundaries; the
[ADR index](docs/adr/README.md) explains every load-bearing choice.

The full architecture and design rationale lives in the
[threat model](docs/threat-model.md) and the [ADR index](docs/adr/README.md).

---

## Quickstart

Five minutes to a running investigation against the mock stack:

```bash
make install        # create virtualenv and install dependencies
make gen-keys       # one-off: generate Ed25519 PASETO keypairs under config/keys/
make compose-up     # build the shared image and start every service
make compose-ps     # all services should be 'healthy' within ~30 seconds
make load-fixtures  # seed the six scenario personas across the mock stack
```

Smoke test the full `mock-oidc → auth-gateway → mcp-gateway → customer_data`
path:

```bash
TOKEN=$(curl -s "http://localhost:9000/login?email=alice@example.com" | jq -r .access_token)
PASETO=$(curl -s -X POST http://localhost:8080/token \
             -H "Authorization: Bearer $TOKEN" | jq -r .access_token)
curl -s -X POST http://localhost:8000/mcp/customer_data \
     -H "Authorization: Bearer $PASETO" \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
          "params":{"name":"get_customer",
                     "arguments":{"customer_id":"cust-0001"}}}'
```

Tear down with `make compose-down`. The audit DB lives in a named volume
(`audit_data`) so it survives restarts.

Local dev (no Docker) is just as fast:

```bash
make lint           # ruff
make typecheck      # mypy
make test           # pytest (>=600 cases, runs in <30s on a laptop)
make evals-smoke    # deterministic eval suite — no API key required
```

---

## What's included

The layers that ship in this repo:

| Layer | What ships | Where it lives |
| --- | --- | --- |
| **Auth gateway** | FastAPI service that validates an OIDC bearer and mints 5-min user PASETO v4.public tokens; publishes its verify key at `/.well-known/paseto-key` | [`gateways/auth/`](gateways/auth/) |
| **MCP gateway** | Streamable-HTTP MCP gateway: PASETO verify, jti replay cache (LRU 10 000), RBAC enforce, re-sign service-to-service PASETO (separate keypair, 60s TTL), forward, audit emit. ≤500 LOC of core. | [`gateways/mcp/`](gateways/mcp/) |
| **Shared gateway helpers** | PASETO mint/verify, RBAC YAML loader with role inheritance + hot reload, audit (SQLite default, ClickHouse via `AUDIT_BACKEND=clickhouse`), OpenTelemetry tracing helpers | [`gateways/common/`](gateways/common/) |
| **6 downstream MCP servers** | One FastMCP server per domain: `customer_data`, `transactions`, `kyc`, `sanctions`, `osint`, `case_actions`. Each validates the service PASETO; `case_actions` additionally requires `human_approval=true` on the claim | [`mcp_servers/`](mcp_servers/) |
| **6 mock APIs** | Pure in-memory FastAPI mocks, deterministic per `customer_id`, six scenario personas (`clean`, `mule`, `sanctions_hit`, `ato`, `structuring`, `synthetic_id`) returning cross-server-consistent shapes | [`mock_apis/`](mock_apis/) |
| **Mock OIDC IdP** | Dev-only OIDC IdP with `/login?email=…` shortcut. **Do not use in production.** | [`mock_apis/mock_oidc/`](mock_apis/mock_oidc/) |
| **Cowork plugin** | XML-structured `SKILL.md` files: an orchestrator (≤100 lines, routes only), five investigation subskills (`gather-customer-profile`, `analyze-transactions`, `check-osint`, `screen-sanctions`, `draft-narrative`), and the `verify-output` meta-skill (annotate-not-block in v1) | [`plugin/`](plugin/) |
| **Eval suite** | Declarative YAML datasets (one per persona) + four scorers (tool correctness, tool ordering, grounding via LLM judge, reasoning via LLM judge) + headless harness + `evals/run.py` + GitHub Actions CI | [`evals/`](evals/) |
| **Grafana dashboard** | Provisioned dashboard with panels for per-user tool-call counts, p50/p95 latency by tool, denied requests by role (stacked), audit volume per day. Works against SQLite and ClickHouse. | [`config/grafana/`](config/grafana/) |
| **Docs** | Threat model, "Add your data source in 1 hour" tutorial, agent testing guide, ADRs for every load-bearing decision, launch post draft | [`docs/`](docs/) |
| **Reference config** | Declarative RBAC with inheritance + groups | [`config/rbac.yaml`](config/rbac.yaml) |

For the design rationale behind each row see the
[ADR index](docs/adr/README.md). For the security posture see the
[threat model](docs/threat-model.md). For integrators wiring their own
backends see [`docs/adding-a-data-source.md`](docs/adding-a-data-source.md).

---

## Service ports

| Service              | Port |
| -------------------- | ---- |
| MCP Gateway          | 8000 |
| customer_data mock   | 8001 |
| customer_data MCP    | 8002 |
| transactions mock    | 8003 |
| transactions MCP     | 8004 |
| kyc mock             | 8005 |
| kyc MCP              | 8006 |
| sanctions mock       | 8007 |
| sanctions MCP        | 8008 |
| osint mock           | 8009 |
| osint MCP            | 8010 |
| case_actions mock    | 8011 |
| case_actions MCP     | 8012 |
| Auth Gateway         | 8080 |
| Mock OIDC IdP        | 9000 |
| Grafana              | 3000 |

---

## Cold-start benchmark

On an M-series MacBook the full 14+ service stack reaches a healthy state
within roughly 22 seconds of `docker compose up -d` (after the shared
image is built once). The dominant cost is Grafana installing the SQLite
and ClickHouse datasource plugins on first boot; subsequent runs are
faster because `grafana_data` is persisted.

Reproduce the benchmark:

```bash
make gen-keys
docker compose build                 # warm the shared image once
docker compose down -v               # tear down + drop volumes for a true cold start
time bash -c 'docker compose up -d && \
              until [ "$(docker compose ps --format json | \
                        jq -s "all(.[]; .Health == \"healthy\")")" = "true" ]; do \
                  sleep 1; \
              done'
```

The acceptance gate is `<30 sec` cold-start to fully-healthy. A single
failed health check shifts the next attempt by 2 seconds (the healthcheck
interval), so a small amount of variance per run is expected.

---

## Repository layout

```
gateways/         # auth + MCP gateways and shared helpers (PASETO, RBAC, audit, OTel)
mcp_servers/      # FastMCP servers wrapping the six mock APIs
mock_apis/        # FastAPI mocks (customer_data, transactions, kyc, sanctions, osint, case_actions, mock_oidc)
plugin/           # Cowork plugin: orchestrator + subskills + verify-output meta-skill
config/           # rbac.yaml, Grafana dashboards + provisioning, generated PASETO keypairs
evals/            # datasets (YAML), scorers, headless harness, runner
docs/             # threat model, tutorial, agent testing, launch post, ADRs
tests/            # pytest suite (>=600 cases)
tasks/            # the PRD itself
scripts/          # gen_dev_keys.py, load_fixtures.py
```

---

## Plug in your own data source

The [`docs/adding-a-data-source.md`](docs/adding-a-data-source.md) tutorial
walks through wiring a new backend in under an hour: define the MCP tool
schema, write the FastMCP server using the shared
`mcp_servers/_common.create_jsonrpc_app` factory, declare it in
`config/servers.yaml` and `config/rbac.yaml`, and reference it from a
subskill `SKILL.md`. Every step has a copy-paste verification command.

---

## Project status

- M0 (bones, end-to-end hello-world): **shipped**
- M1 (full 14-service stack + Grafana): **shipped**
- M2 (eval suite + scorers + CI): **shipped**
- M3 (docs + launch artifacts): **shipped**

See the [launch post](docs/launch-post.md) for the full story.

---

## Launch post

A draft of the launch blog post lives at
[`docs/launch-post.md`](docs/launch-post.md). It frames the project for a
mixed audience of compliance officers, detection engineers, and platform
engineers.

---

## License

Apache 2.0. See [`LICENSE`](LICENSE) (TBD) for the full text.
