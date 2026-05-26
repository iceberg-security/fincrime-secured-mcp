"""Mock OIDC identity provider — DEV ONLY, DO NOT USE IN PRODUCTION.

Replaces Okta/Auth0 for local development of the auth gateway. Signs OIDC
tokens with an in-memory RS256 keypair and exposes the JWKS so the auth
gateway can verify them.

Endpoints:
    GET /.well-known/openid-configuration
        OIDC discovery document. The auth gateway uses this to locate /jwks.

    GET /jwks
        Public RSA keys for token verification.

    POST /token
        OAuth-style token endpoint. Accepts ``grant_type=password`` plus a
        ``username`` (email) field and returns an OIDC id_token + access_token.
        This is the spec-shaped path — most dev callers will use /login.

    GET /login?email=<addr>
        Developer shortcut. Returns a signed OIDC token for any email known
        to ``config/rbac.yaml`` (directly under ``users:`` or reachable
        through ``groups:``). No password required.

The user database is read from the same ``config/rbac.yaml`` the auth gateway
consumes, so any user/group defined there is automatically loginable. The
``groups`` claim is populated from the rbac groups whose role assignments
overlap with the user's roles.

DO NOT USE IN PRODUCTION. There is no password check, no consent screen, no
key rotation, no rate limiting — this exists solely to let contributors run
the stack without registering an external IdP.
"""

from __future__ import annotations

import base64
import os
import time
import uuid
from dataclasses import dataclass
from typing import Annotated, Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    generate_private_key,
)
from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from gateways.common.otel import instrument_fastapi
from gateways.common.rbac import RBACLoader, UnknownUserError

_DEFAULT_AUDIENCE = "fraud-copilot"
_DEFAULT_ISSUER = "http://mock-oidc"
_DEFAULT_TOKEN_TTL = 300  # 5 minutes; matches the auth gateway's PASETO TTL
_KID = "mock-oidc-key-1"


# --------------------------------------------------------------------------- #
# Keypair (in-memory, generated at startup)
# --------------------------------------------------------------------------- #


def _generate_rsa_keypair() -> RSAPrivateKey:
    return generate_private_key(public_exponent=65537, key_size=2048)


def _b64url_uint(value: int) -> str:
    byte_len = (value.bit_length() + 7) // 8 or 1
    return (
        base64.urlsafe_b64encode(value.to_bytes(byte_len, "big"))
        .rstrip(b"=")
        .decode("ascii")
    )


def _public_jwk(key: RSAPrivateKey, *, kid: str) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }


def _private_pem(key: RSAPrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


# --------------------------------------------------------------------------- #
# RBAC-backed user directory
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _DirectoryEntry:
    email: str
    sub: str
    groups: list[str]


def _build_directory(rbac: RBACLoader) -> dict[str, _DirectoryEntry]:
    """Snapshot the rbac config into an email -> directory entry map.

    Both directly-listed users and group members are surfaced. The ``groups``
    claim for each user is the set of rbac groups whose role list overlaps
    the user's own role list (so an analyst-via-group shortcut still gets
    the ``fraud-analysts`` group claim that the auth gateway will hand to
    the RBAC resolver).
    """
    # Reach into the loader's parsed config — it is intentionally private
    # but stable; we don't expose this to external callers, just to the
    # other modules inside this repo.
    config = rbac._config  # noqa: SLF001 - co-located private access
    assert config is not None, "RBACLoader must be initialized before snapshotting"

    user_roles: dict[str, set[str]] = {
        email: set(roles) for email, roles in config.users.items()
    }
    group_roles: dict[str, set[str]] = {
        gname: set(roles) for gname, roles in config.groups.items()
    }

    out: dict[str, _DirectoryEntry] = {}
    for email, roles in user_roles.items():
        groups = sorted(
            gname for gname, groles in group_roles.items() if roles & groles
        )
        out[email] = _DirectoryEntry(email=email, sub=email, groups=groups)
    return out


# --------------------------------------------------------------------------- #
# Token minting
# --------------------------------------------------------------------------- #


def _mint_oidc_token(
    *,
    key: RSAPrivateKey,
    kid: str,
    entry: _DirectoryEntry,
    audience: str,
    issuer: str,
    ttl_seconds: int,
    extra_groups: list[str] | None = None,
) -> tuple[str, int]:
    """Mint an RS256-signed OIDC JWT for ``entry``.

    Returns ``(token, expires_in)``.
    """
    now = int(time.time())
    exp = now + ttl_seconds
    merged_groups = sorted({*entry.groups, *(extra_groups or [])})
    payload: dict[str, Any] = {
        "sub": entry.sub,
        "email": entry.email,
        "groups": merged_groups,
        "aud": audience,
        "iss": issuer,
        "iat": now,
        "exp": exp,
        "jti": uuid.uuid4().hex,
    }
    pem = _private_pem(key)
    token = jwt.encode(payload, pem, algorithm="RS256", headers={"kid": kid})
    return token, ttl_seconds


# --------------------------------------------------------------------------- #
# FastAPI app
# --------------------------------------------------------------------------- #


def create_app(
    *,
    rbac_loader: RBACLoader | None = None,
    audience: str = _DEFAULT_AUDIENCE,
    issuer: str = _DEFAULT_ISSUER,
    token_ttl_seconds: int = _DEFAULT_TOKEN_TTL,
    rsa_key: RSAPrivateKey | None = None,
    kid: str = _KID,
) -> FastAPI:
    """Build the mock OIDC FastAPI app.

    DEV ONLY. The injected ``rbac_loader`` is required; in production code
    paths the loader is built from ``RBAC_CONFIG_PATH``. Tests pass a
    purpose-built loader pointed at a tmp_path YAML.
    """
    if rbac_loader is None:
        raise ValueError("rbac_loader is required (mock OIDC mirrors the rbac directory)")

    key = rsa_key or _generate_rsa_keypair()
    jwk = _public_jwk(key, kid=kid)
    directory = _build_directory(rbac_loader)

    app = FastAPI(
        title="Mock OIDC IdP (DEV ONLY)",
        version="0.1.0",
        description=(
            "Mock OpenID Connect identity provider used for local development "
            "of the fraud-copilot stack. DO NOT USE IN PRODUCTION."
        ),
    )
    instrument_fastapi(app, service_name="fraud-mock-oidc")

    def _lookup(email: str) -> _DirectoryEntry:
        entry = directory.get(email)
        if entry is None:
            # Re-snapshot in case the rbac.yaml was edited since startup
            # (the RBAC loader hot-reloads on mtime change inside its own
            # resolve_user path; we just re-query here for the same effect).
            try:
                resolved = rbac_loader.resolve_user(email)
            except UnknownUserError as exc:
                raise HTTPException(
                    status_code=404, detail=f"unknown email: {email}"
                ) from exc
            entry = _DirectoryEntry(
                email=resolved.email, sub=resolved.email, groups=[]
            )
        return entry

    @app.get("/.well-known/openid-configuration")
    def openid_configuration(request: Request) -> dict[str, Any]:
        base = str(request.base_url).rstrip("/")
        return {
            "issuer": issuer,
            "jwks_uri": f"{base}/jwks",
            "token_endpoint": f"{base}/token",
            "authorization_endpoint": f"{base}/login",
            "id_token_signing_alg_values_supported": ["RS256"],
            "response_types_supported": ["id_token", "token"],
            "subject_types_supported": ["public"],
            "scopes_supported": ["openid", "email", "profile", "groups"],
        }

    @app.get("/jwks")
    def jwks() -> dict[str, list[dict[str, str]]]:
        return {"keys": [jwk]}

    @app.get("/login")
    def login(
        email: Annotated[str, Query(description="Email of a user in config/rbac.yaml")],
    ) -> JSONResponse:
        entry = _lookup(email)
        token, expires_in = _mint_oidc_token(
            key=key,
            kid=kid,
            entry=entry,
            audience=audience,
            issuer=issuer,
            ttl_seconds=token_ttl_seconds,
        )
        return JSONResponse(
            {
                "id_token": token,
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": expires_in,
                "scope": "openid email groups",
            }
        )

    @app.post("/token")
    def token_endpoint(
        username: Annotated[str | None, Form()] = None,
        grant_type: Annotated[str | None, Form()] = None,
    ) -> JSONResponse:
        if grant_type and grant_type not in {"password", "client_credentials"}:
            raise HTTPException(status_code=400, detail=f"unsupported grant_type: {grant_type}")
        if not username:
            raise HTTPException(status_code=400, detail="missing 'username' form field")
        entry = _lookup(username)
        token, expires_in = _mint_oidc_token(
            key=key,
            kid=kid,
            entry=entry,
            audience=audience,
            issuer=issuer,
            ttl_seconds=token_ttl_seconds,
        )
        return JSONResponse(
            {
                "id_token": token,
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": expires_in,
            }
        )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


def build_default_app() -> FastAPI:
    """Construct the mock OIDC app from env vars (production-style entry).

    Reads ``RBAC_CONFIG_PATH`` (default ``config/rbac.yaml``),
    ``MOCK_OIDC_AUDIENCE`` (default ``fraud-copilot``), and
    ``MOCK_OIDC_ISSUER`` (default ``http://mock-oidc``). Generates a fresh
    RSA keypair on every startup — that key never persists, so restarting
    the mock invalidates outstanding tokens (acceptable for dev).
    """
    rbac_path = os.environ.get("RBAC_CONFIG_PATH", "config/rbac.yaml")
    loader = RBACLoader(rbac_path)
    return create_app(
        rbac_loader=loader,
        audience=os.environ.get("MOCK_OIDC_AUDIENCE", _DEFAULT_AUDIENCE),
        issuer=os.environ.get("MOCK_OIDC_ISSUER", _DEFAULT_ISSUER),
    )


__all__ = ["create_app", "build_default_app"]
