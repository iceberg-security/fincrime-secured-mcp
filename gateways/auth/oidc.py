"""OIDC bearer-token validation for the auth gateway.

Fetches the configured IdP's JWKS over HTTP, caches the keys, and verifies
incoming OIDC tokens against ``OIDC_JWKS_URL`` / ``OIDC_AUDIENCE`` /
``OIDC_ISSUER`` env vars (or explicit constructor args).

Validation enforces signature, ``aud``, ``iss``, and ``exp`` (PyJWT handles
``exp`` with leeway=0). The decoded payload is returned as a dict so callers
can pluck ``email`` and ``groups`` claims off it.

The validator is deliberately a small class with sync ``validate()`` — JWKS
fetching is the only network call and runs at startup (or on key rotation),
not on every token validation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient


class OIDCError(Exception):
    """Base class for OIDC validation errors."""


class OIDCConfigError(OIDCError):
    """Raised when the validator is misconfigured (missing URL/audience)."""


class OIDCInvalidTokenError(OIDCError):
    """Raised when token signature/issuer/audience does not check out."""


class OIDCExpiredTokenError(OIDCError):
    """Raised when the token signature is valid but ``exp`` is in the past."""


@dataclass(slots=True)
class OIDCClaims:
    """Subset of OIDC claims the auth gateway cares about."""

    sub: str
    email: str
    groups: list[str]
    raw: dict[str, Any]


class OIDCValidator:
    """Validates OIDC bearer tokens against a JWKS endpoint.

    Args:
        jwks_url: HTTPS URL exposing the IdP's JWKS document. Defaults to the
            ``OIDC_JWKS_URL`` env var.
        audience: Expected ``aud`` claim. Defaults to ``OIDC_AUDIENCE`` env var.
        issuer: Optional expected ``iss`` claim. Defaults to ``OIDC_ISSUER``
            env var. If both are unset, ``iss`` is not enforced.
        http_client: Optional pre-built httpx client (used by tests to point
            at a local mock IdP without DNS).
    """

    def __init__(
        self,
        *,
        jwks_url: str | None = None,
        audience: str | None = None,
        issuer: str | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._jwks_url = jwks_url or os.environ.get("OIDC_JWKS_URL", "")
        self._audience = audience or os.environ.get("OIDC_AUDIENCE", "")
        self._issuer = issuer or os.environ.get("OIDC_ISSUER", "") or None
        if not self._jwks_url:
            raise OIDCConfigError(
                "OIDC_JWKS_URL not configured (set env var or pass jwks_url=)."
            )
        if not self._audience:
            raise OIDCConfigError(
                "OIDC_AUDIENCE not configured (set env var or pass audience=)."
            )
        self._jwks_client = PyJWKClient(self._jwks_url)
        self._http_client = http_client

    def validate(self, token: str) -> OIDCClaims:
        """Verify ``token`` and return the parsed claims.

        Raises:
            OIDCInvalidTokenError: signature mismatch, wrong audience/issuer,
                malformed token.
            OIDCExpiredTokenError: signature valid, ``exp`` in the past.
        """
        if not token or not isinstance(token, str):
            raise OIDCInvalidTokenError("empty or non-string token")
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
        except jwt.exceptions.PyJWKClientError as exc:
            raise OIDCInvalidTokenError(f"jwks lookup failed: {exc}") from exc
        except jwt.exceptions.DecodeError as exc:
            raise OIDCInvalidTokenError(f"malformed token: {exc}") from exc

        options: dict[str, Any] = {"require": ["exp", "aud"]}
        decode_kwargs: dict[str, Any] = {
            "audience": self._audience,
            "options": options,
        }
        if self._issuer:
            decode_kwargs["issuer"] = self._issuer

        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256", "EdDSA"],
                **decode_kwargs,
            )
        except jwt.ExpiredSignatureError as exc:
            raise OIDCExpiredTokenError(str(exc)) from exc
        except (jwt.InvalidTokenError, jwt.DecodeError) as exc:
            raise OIDCInvalidTokenError(str(exc)) from exc

        sub = str(payload.get("sub") or "")
        email = str(payload.get("email") or sub)
        groups_raw = payload.get("groups") or []
        if not isinstance(groups_raw, list):
            raise OIDCInvalidTokenError("'groups' claim must be a list")
        groups = [str(g) for g in groups_raw]

        if not email:
            raise OIDCInvalidTokenError("token missing 'sub' / 'email' claim")

        return OIDCClaims(sub=sub, email=email, groups=groups, raw=payload)
