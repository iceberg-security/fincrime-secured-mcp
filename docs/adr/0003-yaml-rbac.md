# ADR 0003 — YAML over Terraform for RBAC configuration

- **Status**: Accepted
- **Date**: 2026-05-26
- **Story**: US-033 (decision originally implemented in US-003)

## Context

The fraud-investigator's authorization model is a flat role-based
mapping: an email or group identifier resolves to a set of allowed
MCP servers and per-server tools (with `"*"` wildcards). The resolved
shape is embedded verbatim into the user PASETO claim
`allowed_tools: dict[str, list[str]]` and enforced by the MCP gateway
on every call.

The configuration carrier needs to:

- Sit in the repo and be reviewable via PR. Compliance reviewers and
  fraud-team leads should be able to read the file diff and
  understand "Alice gained access to `case_actions.freeze_account`"
  without learning a new tool.
- Support inheritance — `l3_admin` inherits from `analyst` which
  inherits from `base_reader`. We need to merge rather than override.
- Hot reload. Operators tweak RBAC during incidents (e.g., revoke a
  compromised account); restarting the auth gateway means a
  multi-second outage of the investigator surface.
- Be diffable. A `git diff` on the file must show added/removed
  permissions, not opaque hash changes.

The two serious options were YAML (with a Python loader inside
`gateways/common/rbac.py`) and Terraform (with a provider talking to
either an IAM service or an in-repo state file).

Terraform's draw was infrastructure-as-code consistency — the same
toolchain that provisions the database also provisions the access
list. Several teams we surveyed use Terraform for IAM today.

We rejected Terraform on four grounds:

- **Wrong granularity.** Terraform is designed for slowly-changing
  infrastructure. RBAC for an investigator stack changes at the
  cadence of compliance reviews and incidents — daily during launch,
  weekly steady-state. Running `terraform apply` against a state file
  every time analyst Alice gets a tool unlock is a poor fit for the
  workflow.
- **Pulled in a heavyweight dependency.** A Terraform-only RBAC pulls
  the `terraform` binary into CI, the provider plugin, and either an
  external state store or a local state file we have to commit. The
  in-repo YAML loader is 350 lines of Python and reads a file.
- **Hot reload is awkward.** Terraform's loop is "edit, plan, apply."
  There is no native equivalent of "rewrite the file and the running
  service notices within 5 seconds." We would have to build the file
  watcher anyway.
- **PR readability suffers.** YAML diffs are the file. Terraform
  diffs are HCL plus the state plan. Compliance reviewers cannot
  rubber-stamp a 50-line plan output the way they can a 10-line YAML
  diff.

## Decision

**RBAC lives in `config/rbac.yaml` and is parsed by
`gateways/common/rbac.py`.**

Schema (US-003 acceptance):

```yaml
roles:
  base_reader:
    allowed_servers: [customer_data]
    allowed_tools:
      customer_data: ["*"]
  analyst:
    inherits: [base_reader]
    allowed_servers: [transactions, kyc, sanctions, osint]
    allowed_tools:
      transactions: ["*"]
      kyc: ["*"]
      sanctions: ["*"]
      osint: ["*"]
  l3_admin:
    inherits: [analyst]
    allowed_servers: [case_actions]
    allowed_tools:
      case_actions: ["*"]

users:
  alice@example.com: [analyst]
  l3-oncall@example.com: [l3_admin]

groups:
  fraud-analysts: [analyst]
  fraud-l3: [l3_admin]
```

Loader contract:

- `RBACLoader(path)` reads and parses on init.
- `resolve_user(email, groups=None) -> ResolvedUser` returns the
  merged snapshot: `email`, `roles`, `allowed_servers` (sorted,
  deduped), `allowed_tools: dict[str, list[str]]`.
- Inheritance is recursive with cycle detection (DFS).
- Wildcards: per-server `"*"` stored as `{"server": ["*"]}`;
  top-level `"*"` as `{"*": ["*"]}`. The MCP gateway checks both
  shapes.
- Hot reload via mtime check on every `resolve_user()` call. On
  macOS's 1-second mtime resolution, tests `os.utime(path, (t+1, t+1))`
  to force a reload window.
- Module-level helper `resolve_user(...)` uses a process-wide
  singleton keyed off `RBAC_CONFIG_PATH`. Tests reset it via
  `reset_default_loader()` in an autouse fixture.

## Consequences

**Positive:**

- A 30-line `config/rbac.yaml` diff is the authoritative compliance
  record of an access change. PR review is the audit log for who
  granted whom what.
- Hot reload works without any extra tooling. The file watcher is one
  `os.path.getmtime()` call per `resolve_user()`.
- The YAML schema is the wire format for the loader's tests — every
  invariant (inheritance, wildcards, cycles, hot reload) is pinned in
  `tests/test_rbac.py`.
- Adding a new role to a contributor stack is one PR. Adding a new
  user is one PR. No infrastructure deployment.

**Negative:**

- The config file is a single point of write. A compromised commit
  could grant `l3_admin` to an attacker. Mitigations live outside
  this ADR: branch protection, code owners on `config/rbac.yaml`,
  signed commits — see
  [`docs/threat-model.md`](../threat-model.md) §7 (operator
  responsibilities).
- The loader is in-process. Federated deployment (one auth gateway
  per region) requires every replica to read the same file. We treat
  this as an operator concern; the file fits comfortably in a
  ConfigMap, an S3 sync, or a git pull.
- YAML's permissive parsing (no schema enforcement out of the box)
  means typos can pass silently. The loader counters this by raising
  on every unknown role reference and unknown user, and the test
  suite covers cycles, missing files, and conflicting inheritance.

**Risk acceptance:**

- A future federated RBAC source (e.g., reading roles from Okta
  groups) would replace the loader's backend without changing its
  public API. `RBACLoader` is one file; the rest of the codebase
  imports the `resolve_user` function and the `ResolvedUser`
  dataclass. Migration is a contained change.

## Alternatives considered

- **Terraform + a provider talking to a state file.** Rejected — see
  Context. The mismatch between Terraform's cadence and RBAC's
  change rate was the deciding factor.
- **OPA / Rego.** Rejected — gives us a more expressive policy
  language but the runtime is heavier than this project needs. A 350-
  line Python loader covers the entire spec; Rego would add
  conceptual surface area for no functional gain at v1. OPA remains a
  reasonable replacement when the policy language outgrows YAML.
- **Casbin.** Rejected — same reason as Rego, less language
  expressiveness, and a less-active Python community than at
  decision time.
- **A database table with an admin UI.** Rejected — adds a write-path
  service, breaks the "everything in dev is in-process" property,
  and the audit story (who edited the row?) is worse than `git
  log config/rbac.yaml`.

## Cross-links

- [US-003 prd.json entry](../../prd.json) — loader acceptance
  criteria, role inheritance, hot reload.
- `gateways/common/rbac.py` — `RBACLoader`, `ResolvedUser`,
  `resolve_user()`.
- `config/rbac.yaml` — the shipped example with `base_reader`,
  `analyst`, `l3_admin`.
- [`docs/threat-model.md`](../threat-model.md) §7 — operator
  responsibilities (branch protection, code owners on rbac.yaml).
- [`docs/adding-a-data-source.md`](../adding-a-data-source.md) §4 —
  worked example of adding a new server's tools to an existing role.
