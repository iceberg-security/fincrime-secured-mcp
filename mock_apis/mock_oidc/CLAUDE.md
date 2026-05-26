# mock_apis/mock_oidc/

**DEV ONLY — DO NOT USE IN PRODUCTION.**

Mock OpenID Connect identity provider. Stands in for Okta/Auth0 so contributors can run the stack without registering an external IdP.

## What it provides

| Method | Path                                  | Purpose                                                                       |
| ------ | ------------------------------------- | ----------------------------------------------------------------------------- |
| `GET`  | `/.well-known/openid-configuration`   | OIDC discovery doc. The auth gateway reads this to locate `/jwks`.            |
| `GET`  | `/jwks`                               | Public RSA JWKS. RS256, single key, `kid=mock-oidc-key-1`.                    |
| `GET`  | `/login?email=<addr>`                 | Dev shortcut — issues a signed token for any `users:` email in `rbac.yaml`.   |
| `POST` | `/token`                              | OAuth-style endpoint accepting `grant_type=password` + `username`.            |
| `GET`  | `/healthz`                            | Liveness.                                                                     |

## Conventions

- The signing key is generated **in memory** at startup. It never persists; restarting the mock invalidates all outstanding tokens. This is intentional — production code paths must use a real IdP with proper key rotation.
- The user directory is snapshotted from `RBACLoader._config` at app-creation time. Adding a new user/group to `config/rbac.yaml` only takes effect after a process restart for the mock IdP (the auth gateway hot-reloads independently via mtime).
- The `groups` claim emitted for each user is the union of rbac groups whose `roles:` list overlaps that user's `roles:` list. So `alice@example.com` (`roles: [analyst]`) automatically advertises `fraud-analysts` (which also has `roles: [analyst]`).
- Audience defaults to `fraud-copilot`; issuer defaults to `http://mock-oidc`. Override per-app via `create_app(audience=..., issuer=...)` or via `MOCK_OIDC_AUDIENCE` / `MOCK_OIDC_ISSUER` env vars in `build_default_app()`. The auth gateway must be configured with the **same** values.

## Pitfalls

- **Never** point a real environment at this. There is no password check, no consent, no key rotation, no rate limiting.
- The mock reads `RBACLoader._config` directly (private). If you change the shape of the rbac config dataclass, update `_build_directory` too — the failure mode is silent (empty directory, all `/login` calls 404).
- The auth gateway's `PyJWKClient` caches keys; if you bounce the mock IdP in a long-lived dev session, also bounce the auth gateway so it re-fetches the new JWKS.
- For containerised setups (US-011/US-024), publish `/healthz` for healthchecks and set the auth gateway's `OIDC_JWKS_URL=http://mock-oidc:<port>/jwks`.

## Testing this module

`tests/test_mock_oidc.py` exercises both standalone behavior (discovery, JWKS, `/login`, `/token`) and end-to-end integration with the auth gateway. The end-to-end path uses `_JWKSBackedOIDCValidator` — an `OIDCValidator` subclass that resolves signing keys from a pre-fetched JWK dict — so the test runs without sockets while still exercising real RS256 signature verification.
