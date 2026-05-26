# gateways/auth/

The **Authorization Gateway**. Exchanges an OIDC bearer token for a short-lived PASETO that downstream services trust.

## Modules

- `oidc.py` — `OIDCValidator` wraps PyJWT + the configured IdP's JWKS endpoint. Enforces signature, `aud`, `exp`, and (optionally) `iss`. Raises `OIDCExpiredTokenError` / `OIDCInvalidTokenError`.
- `main.py` — FastAPI app factory `create_app(...)`. The factory takes the OIDC validator, RBAC loader, and PEM paths as keyword args so tests inject fakes. `build_default_app()` is the env-var-driven production entry point.

## Endpoints

| Method | Path                          | Purpose                                                                                   |
| ------ | ----------------------------- | ----------------------------------------------------------------------------------------- |
| `POST` | `/token`                      | `Authorization: Bearer <oidc>` → `{access_token, token_type, expires_in}` PASETO response |
| `GET`  | `/.well-known/paseto-key`     | Public Ed25519 PEM; MCP gateway fetches this to verify inbound tokens (US-007).           |
| `GET`  | `/healthz`                    | Cheap liveness probe.                                                                     |

PASETO TTL is **300 seconds** by default (PRD §6.3). Override via `create_app(token_ttl_seconds=...)`.

## Env vars

- `OIDC_JWKS_URL` — IdP JWKS endpoint.
- `OIDC_AUDIENCE` — Expected `aud` claim.
- `OIDC_ISSUER` — Optional; enforced when set.
- `PASETO_PRIVATE_KEY_PATH` — Ed25519 signing key (used by `mint`).
- `PASETO_PUBLIC_KEY_PATH` — Verification key (served at `/.well-known/paseto-key`).
- `RBAC_CONFIG_PATH` — Defaults to `config/rbac.yaml`.

## Conventions

- **Do not** add request-body parameters to `/token` — the OIDC token rides in the `Authorization` header so the route stays GET-shaped semantically. Adding a body would also re-introduce 422 traps.
- The factory uses closures, not `Depends(...)`, to wire collaborators. This keeps FastAPI from misinterpreting injected handles as request fields and avoids the `ruff B008` warning. If you need per-request scoping later, switch to `Depends`.
- `OIDCInvalidTokenError` → HTTP 401 (auth failure). `UnknownUserError` from RBAC → HTTP 403 (authenticated but unauthorized). Keep this 401/403 split — the MCP gateway mirrors it for tool authorization.
- The minted PASETO embeds the **flattened** RBAC snapshot at mint time. Downstream services do not re-resolve RBAC; they enforce against what's in the token. This is why `Claims.allowed_tools` matches `ResolvedUser.allowed_tools` shape (`dict[str, list[str]]`).

## Pitfalls

- `OIDCValidator.__init__` constructs a `PyJWKClient` which lazily hits the network on first verify, not in the constructor. Tests must either monkeypatch `_jwks_client.get_signing_key_from_jwt` or subclass `OIDCValidator` and bypass `super().__init__()` (see `_FakeOIDCValidator` in `tests/test_auth_gateway.py`).
- PyJWT's `decode()` raises `ExpiredSignatureError` for expiry only when `exp` is present **and** numeric. We pass `options={"require": ["exp", "aud"]}` to make missing claims a hard error rather than a silent pass.
- The OIDC `groups` claim must be a JSON array. We reject scalar `groups` claims at validation time so the RBAC loader's `groups: list[str]` contract holds.
- Allowed JWS algorithms are `RS256`, `ES256`, `EdDSA`. If your IdP uses `HS256` (symmetric), DO NOT add it here — symmetric algs on a public JWKS endpoint are a footgun.
