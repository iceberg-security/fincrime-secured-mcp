# ADR 0002 — PASETO v4.public over JWT for service-to-service auth

- **Status**: Accepted
- **Date**: 2026-05-26
- **Story**: US-033 (decision originally implemented in US-002 / US-004 / US-007)

## Context

The fraud-investigator stack has two distinct token-bearing hops:

1. **User → Auth Gateway → MCP Gateway.** The auth gateway accepts an
   OIDC bearer token from the IdP (real or mock), resolves the user
   through `config/rbac.yaml`, and mints a short-lived service token
   the plugin presents to the MCP gateway.
2. **MCP Gateway → downstream MCP server.** The MCP gateway re-mints a
   second short-lived token, scoped per call, carrying the user's
   resolved RBAC snapshot plus the `human_approval` claim, the
   `trace_id`, and a fresh `jti`.

JWT is the obvious incumbent. It is universally understood, every
language has a library, and the OIDC token coming into the auth
gateway is already a JWT — keeping the same format for the downstream
hops would mean one library, one parser, one mental model.

We did not pick JWT. The reasons accumulated over the security review
that fed into PRD §6 (Auth) and §7 (Threats):

- **JWT's algorithm field is the historic footgun.** `alg: none`,
  `alg: HS256` against an RSA public key as a HMAC secret, and similar
  confusion attacks are old and well-documented (Auth0 2015, RFC 8725
  BCP §3.1). Every JWT library since has shipped mitigations, but the
  surface keeps reappearing — most recently in 2024 across several
  JavaScript libraries that accepted `kid` header injection. The
  service-to-service hop runs inside a security-critical product;
  defaults that fail closed beat defaults that need configuring.
- **JWT's serialization is permissive.** Base64URL with no length
  bounds, duplicate JSON keys, unicode normalization quirks, comments
  in some parsers — none of these are exploits in themselves, but
  every one is an exception the parser has to handle correctly. PASETO
  v4's binary footer + fixed-key cryptography removes the entire
  category.
- **Service-to-service tokens never need the `alg` flexibility JWT
  provides.** We control both ends of the wire. There is no third
  party for whom we need to negotiate signing algorithms. JWT's
  algorithm agility is a benefit at the OIDC boundary (third-party
  IdPs) and a liability everywhere else.
- **PASETO's typing pins down a single cryptographic intent per
  token version.** v4.public uses Ed25519 — period. There is no
  algorithm-selection logic in the verifier. The library exposes
  `verify(token, public_key)` and that is the entire contract.
- **The pyseto Python library was production-quality.** PASETO is a
  young spec (2018) and ecosystem maturity was the legitimate risk; we
  did due diligence on the maintainer activity, audit history, and
  test coverage of pyseto before committing.

The downstream cost of choosing PASETO is real: contributors who
arrive knowing JWT have to learn a new format, and the audit log
records mention version numbers and footers that don't map to any
familiar standard.

## Decision

**Adopt PASETO v4.public for both service-to-service token hops.**

OIDC at the IdP boundary remains JWT (we don't control the IdP).
Inside our trust boundary, every token is a PASETO v4.public:

- **Library**: `pyseto>=1.7` (the only mature Python implementation).
- **Helpers**: `gateways/common/paseto.py::mint(claims, ttl_seconds)`
  and `verify(token)`. `mint()` populates `jti` and `exp` on the
  encoded payload, never mutating the in-memory `Claims` dataclass.
  `verify()` raises typed exceptions (`ExpiredTokenError`,
  `InvalidTokenError`, `MalformedTokenError`) that the gateways map
  to `401` / `403`.
- **Keypairs**: Ed25519 PEM files. Paths via
  `PASETO_PRIVATE_KEY_PATH` and `PASETO_PUBLIC_KEY_PATH` (env
  vars). Two distinct keypairs are mandatory: one for
  auth-gateway → MCP gateway (user-token hop), one for
  MCP gateway → downstream MCP servers (service hop). Mixing them
  would let a compromised downstream server forge user-scoped
  tokens. The fixture in `scripts/gen_dev_keys.py` generates both
  pairs idempotently.
- **TTLs**: 5 minutes on user tokens, 60 seconds on service tokens.
  The shorter service-token TTL bounds the replay window per call.
- **Claims**: typed `Claims` dataclass (`sub`, `roles`,
  `allowed_servers`, `allowed_tools`, `exp`, `jti`, `trace_id`,
  `human_approval`). Anything outside the dataclass is dropped at
  verify time.
- **Public-key publication**: the auth gateway exposes the user-token
  verification key at `GET /.well-known/paseto-key`. The MCP gateway
  reads it once on startup and caches it.

## Consequences

**Positive:**

- The algorithm-confusion attack family is structurally impossible.
  v4.public verifies under Ed25519 — there is no `alg` field to
  manipulate, no `kid` field to inject, no parser branch to confuse.
- The MCP gateway's verify path is one library call. The full per-hop
  pipeline (verify → replay-cache → RBAC → mint → forward → audit)
  fits in `gateways/mcp/main.py` under 500 LOC (US-007 budget).
- Service tokens carry a fresh `jti` per call. The in-memory LRU at
  `gateways/mcp/replay_cache.py` evicts on TTL, capped at 10000
  entries. Replay → `401 token_replay` deny.
- Tests are hermetic: every test that needs a keypair generates one
  in-process via
  `cryptography.hazmat.primitives.asymmetric.ed25519`. No fixture
  files in `tests/`.

**Negative:**

- The pyseto dependency has a smaller community than PyJWT. We track
  upstream advisories manually; nothing has surfaced in the project's
  lifetime so far.
- New contributors meet PASETO for the first time. We document the
  format in this ADR and link it from
  [`docs/threat-model.md`](../threat-model.md) §4.2 (token replay)
  and §5 (cross-boundary controls).
- Tooling familiar from JWT debugging (jwt.io decoders, browser
  extensions) does not work on PASETO. The Grafana dashboard does not
  decode tokens at all — only the `jti`, `sub`, `server`, `tool`, and
  `status` columns from the audit table are inspected.

**Risk acceptance:**

- A future PASETO v5 spec or a major pyseto API break would require
  migration work. The `gateways/common/paseto.py` wrapper isolates
  the dependency surface — every other module imports from there.
  Migration would touch one file plus its tests.

## Alternatives considered

- **JWT with a strict allowlist (`EdDSA` only) and a hand-rolled
  verifier.** Rejected — possible in theory, but every JWT library we
  surveyed exposed the broader algorithm surface in some
  configuration path, and we did not want to fight the library on
  every dependency bump. The "use JWT safely" checklist is also long
  and easy to regress.
- **OAuth 2.0 Mutual TLS (mTLS) for service-to-service auth.**
  Rejected — mTLS gives us cryptographic peer auth but no in-band
  claims. We would still need a token format to carry `roles`,
  `allowed_tools`, `trace_id`, etc. mTLS at the infra layer remains a
  reasonable production hardening (operator responsibility, see
  [`docs/threat-model.md`](../threat-model.md) §7) and is orthogonal
  to this decision.
- **Macaroons.** Rejected — third-party caveats are a great fit for
  delegated capability but the operational tooling is thin in Python.
  Per-call PASETO mints already give us the scoped-down,
  short-lived-token property without introducing macaroon-specific
  concepts to the audit log.
- **Opaque session tokens + a redis-backed claims store.** Rejected —
  adds a stateful dependency to the hot path and breaks the
  "everything is in-memory in dev" property we promise contributors
  in [`docs/adding-a-data-source.md`](../adding-a-data-source.md).

## Cross-links

- [US-002 prd.json entry](../../prd.json) — `mint` / `verify`
  helpers + their typed errors.
- [US-004 prd.json entry](../../prd.json) — Auth Gateway minting.
- [US-007 prd.json entry](../../prd.json) — MCP Gateway re-mint +
  replay cache.
- `gateways/common/paseto.py` — implementation.
- `gateways/mcp/replay_cache.py` — LRU + TTL replay defense.
- [`docs/threat-model.md`](../threat-model.md) §4.2 — token replay.
