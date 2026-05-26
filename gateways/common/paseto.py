"""PASETO v4.public mint and verify helpers.

Used by the auth gateway (to mint user tokens) and the MCP gateway (to verify
incoming tokens and re-sign service-to-service tokens). The signing keypair is
Ed25519, loaded from PEM files whose paths are configured via env vars:

- ``PASETO_PRIVATE_KEY_PATH``: PEM-encoded Ed25519 private key (for ``mint``).
- ``PASETO_PUBLIC_KEY_PATH``:  PEM-encoded Ed25519 public  key (for ``verify``).

Both env vars can be overridden per call by passing ``private_key_path`` /
``public_key_path`` directly — used by tests and by service-to-service flows
that maintain a separate keypair.
"""

from __future__ import annotations

import os
import secrets
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import pyseto
from pyseto import Key
from pyseto.exceptions import PysetoError as _PysetoError
from pyseto.exceptions import VerifyError as _PysetoVerifyError

__all__ = [
    "Claims",
    "PasetoError",
    "InvalidTokenError",
    "ExpiredTokenError",
    "MalformedTokenError",
    "mint",
    "verify",
    "load_private_key",
    "load_public_key",
]


# --------------------------------------------------------------------------- #
# Exceptions                                                                  #
# --------------------------------------------------------------------------- #


class PasetoError(Exception):
    """Base class for PASETO mint/verify errors raised by this module."""


class InvalidTokenError(PasetoError):
    """Signature does not validate against the configured public key."""


class ExpiredTokenError(PasetoError):
    """Token signature validates but the ``exp`` claim is in the past."""


class MalformedTokenError(PasetoError):
    """Token cannot be parsed (truncated, wrong header, bad base64)."""


# --------------------------------------------------------------------------- #
# Claims model                                                                #
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class Claims:
    """Typed claims carried inside the PASETO token.

    ``exp`` and ``jti`` are populated automatically inside :func:`mint` if the
    caller leaves them empty. Callers normally only set the identity / RBAC
    fields and the ``trace_id``.

    ``allowed_tools`` mirrors :class:`gateways.common.rbac.ResolvedUser` —
    mapping ``server_name -> [tool, ...]``. The literal ``["*"]`` value means
    "all tools" for that server; a key of ``"*"`` with value ``["*"]`` means
    "all tools on all servers". The MCP gateway enforces both shapes.
    """

    sub: str
    roles: list[str] = field(default_factory=list)
    allowed_servers: list[str] = field(default_factory=list)
    allowed_tools: dict[str, list[str]] = field(default_factory=dict)
    exp: str = ""
    jti: str = ""
    trace_id: str = ""
    human_approval: bool = False

    def to_payload(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> Claims:
        raw_tools = payload.get("allowed_tools") or {}
        if isinstance(raw_tools, dict):
            tools: dict[str, list[str]] = {
                str(k): list(v or []) for k, v in raw_tools.items()
            }
        else:
            tools = {}
        return cls(
            sub=str(payload.get("sub", "")),
            roles=list(payload.get("roles", []) or []),
            allowed_servers=list(payload.get("allowed_servers", []) or []),
            allowed_tools=tools,
            exp=str(payload.get("exp", "")),
            jti=str(payload.get("jti", "")),
            trace_id=str(payload.get("trace_id", "")),
            human_approval=bool(payload.get("human_approval", False)),
        )


# --------------------------------------------------------------------------- #
# Key loading                                                                 #
# --------------------------------------------------------------------------- #


def _read_pem(path: str | os.PathLike[str]) -> bytes:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"PASETO key file not found: {p}")
    return p.read_bytes()


@lru_cache(maxsize=8)
def _load_private_key_cached(path: str) -> Any:
    return Key.new(version=4, purpose="public", key=_read_pem(path))


@lru_cache(maxsize=8)
def _load_public_key_cached(path: str) -> Any:
    return Key.new(version=4, purpose="public", key=_read_pem(path))


def load_private_key(path: str | os.PathLike[str] | None = None) -> Any:
    resolved = str(path) if path is not None else os.environ.get("PASETO_PRIVATE_KEY_PATH", "")
    if not resolved:
        raise PasetoError(
            "PASETO private key path not configured "
            "(set PASETO_PRIVATE_KEY_PATH or pass private_key_path=)."
        )
    return _load_private_key_cached(resolved)


def load_public_key(path: str | os.PathLike[str] | None = None) -> Any:
    resolved = str(path) if path is not None else os.environ.get("PASETO_PUBLIC_KEY_PATH", "")
    if not resolved:
        raise PasetoError(
            "PASETO public key path not configured "
            "(set PASETO_PUBLIC_KEY_PATH or pass public_key_path=)."
        )
    return _load_public_key_cached(resolved)


# --------------------------------------------------------------------------- #
# Mint / verify                                                               #
# --------------------------------------------------------------------------- #


def mint(
    claims: Claims | dict[str, Any],
    ttl_seconds: int,
    *,
    private_key_path: str | os.PathLike[str] | None = None,
) -> str:
    """Sign ``claims`` into a PASETO v4.public token valid for ``ttl_seconds``.

    The ``exp`` and ``jti`` claims are auto-filled if missing. ``exp`` is set
    in ISO-8601 UTC (matching pyseto's registered-claim format) so that
    :func:`verify` can detect expiration.
    """
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be > 0")

    if isinstance(claims, Claims):
        payload = claims.to_payload()
    else:
        payload = dict(claims)
        payload.setdefault("sub", "")
        payload.setdefault("roles", [])
        payload.setdefault("allowed_servers", [])
        payload.setdefault("allowed_tools", {})
        payload.setdefault("trace_id", "")
        payload.setdefault("human_approval", False)

    if not payload.get("jti"):
        payload["jti"] = uuid.uuid4().hex

    expires_at = datetime.now(tz=UTC) + timedelta(seconds=ttl_seconds)
    payload["exp"] = expires_at.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    key = load_private_key(private_key_path)

    try:
        token = pyseto.encode(key, payload)
    except _PysetoError as exc:  # pragma: no cover - defensive
        raise PasetoError(f"failed to mint PASETO token: {exc}") from exc

    return token.decode("utf-8")


def verify(
    token: str,
    *,
    public_key_path: str | os.PathLike[str] | None = None,
) -> Claims:
    """Verify ``token`` against the configured public key and return claims.

    Raises:
        ExpiredTokenError:   signature OK, ``exp`` in the past.
        InvalidTokenError:   signature mismatch (tampered or wrong-key token).
        MalformedTokenError: token cannot be parsed at all.
    """
    if not token or not isinstance(token, str):
        raise MalformedTokenError("empty or non-string token")

    if not token.startswith("v4.public."):
        raise MalformedTokenError("not a v4.public PASETO token")

    key = load_public_key(public_key_path)

    import json

    try:
        parsed = pyseto.decode(key, token, deserializer=json)
    except _PysetoVerifyError as exc:
        msg = str(exc)
        if "expired" in msg.lower():
            raise ExpiredTokenError(msg) from exc
        raise InvalidTokenError(msg) from exc
    except _PysetoError as exc:
        raise InvalidTokenError(str(exc)) from exc
    except ValueError as exc:
        raise MalformedTokenError(str(exc)) from exc

    payload = parsed.payload
    if not isinstance(payload, dict):
        raise MalformedTokenError("payload is not a JSON object")

    return Claims.from_payload(payload)


# --------------------------------------------------------------------------- #
# Helpers for tests / dev                                                     #
# --------------------------------------------------------------------------- #


def _new_trace_id() -> str:
    """Generate a fresh trace id (used by callers that don't yet have one)."""
    return secrets.token_hex(16)
