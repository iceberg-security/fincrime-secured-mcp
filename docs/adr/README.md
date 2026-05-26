# Architecture Decision Records

This directory captures the load-bearing design decisions for the
fraud-investigator stack. Each ADR follows the standard four-section
template — **Context**, **Decision**, **Consequences**, **Alternatives** —
and is immutable once accepted: superseding decisions land as new
ADRs that link back to the originals.

| ADR | Title | One-line summary |
| --- | --- | --- |
| [0001](0001-headless-cowork-harness.md) | Headless Cowork harness | Custom Python harness in `evals/harness/` drives the orchestrator skill; the Cowork CLI is not a runtime dependency of the eval gate. |
| [0002](0002-paseto-over-jwt.md) | PASETO v4.public over JWT | Service-to-service auth uses PASETO v4.public — no algorithm-confusion surface, typed claims, two distinct Ed25519 keypairs. |
| [0003](0003-yaml-rbac.md) | YAML over Terraform for RBAC | RBAC lives in `config/rbac.yaml`, parsed by `gateways/common/rbac.py`, hot-reloaded via mtime, reviewable per PR. |
| [0004](0004-sqlite-default-audit.md) | SQLite default for the audit store | `gateways/common/audit.py` defaults to a single SQLite file; ClickHouse is opt-in via `AUDIT_BACKEND=clickhouse` + the `clickhouse` extra. |
| [0005](0005-fastmcp-framework.md) | FastMCP for downstream MCP servers | FastMCP is used as a tool registry only; transport, PASETO verify, JSON-RPC framing, and upstream calls live in `mcp_servers/_common.create_jsonrpc_app`. |
| [0006](0006-annotate-not-block-verifier.md) | Annotate-not-block verifier (v1) | The verify-output meta-skill annotates reports with `unsupported_claim` / `verdict_disagreement` / etc. — it never blocks at v1. |
| [0007](0007-opus-default-model.md) | Claude Opus 4.7 as the default model | `evals/harness/AnthropicAgent` and `evals/scorers/AnthropicJudge` default to `claude-opus-4-7`; CI uses deterministic `OracleAgent` + `StubJudge`. |

## How to add an ADR

1. Pick the next four-digit number (`NNNN-kebab-case-slug.md`).
2. Copy the section structure from any existing ADR (Status / Date /
   Story / Context / Decision / Consequences / Alternatives / Cross-
   links).
3. Add a row to the index above with a one-line summary.
4. Cross-link from the most relevant place(s):
   [`docs/threat-model.md`](../threat-model.md),
   [`docs/agent-testing.md`](../agent-testing.md),
   [`docs/adding-a-data-source.md`](../adding-a-data-source.md), or the
   PRD user story that motivated the decision.

Tests in `tests/test_adr_index.py` walk this directory and pin
structural invariants (each ADR has the four required sections, the
README indexes every ADR, every cross-link target resolves). If you
add an ADR and the test fails, the test is right — fix the file.
