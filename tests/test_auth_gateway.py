"""Unit tests for gateways/auth (auth gateway FastAPI service)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from fastapi.testclient import TestClient

from gateways.auth.main import create_app
from gateways.auth.oidc import (
    OIDCClaims,
    OIDCExpiredTokenError,
    OIDCInvalidTokenError,
    OIDCValidator,
)
from gateways.common import paseto as paseto_mod
from gateways.common.paseto import verify as paseto_verify
from gateways.common.rbac import RBACLoader

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clear_paseto_key_cache() -> None:
    paseto_mod._load_private_key_cached.cache_clear()
    paseto_mod._load_public_key_cached.cache_clear()


@pytest.fixture()
def paseto_keypair(tmp_path: Path) -> tuple[Path, Path]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = tmp_path / "paseto_private.pem"
    pub_path = tmp_path / "paseto_public.pem"
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    return priv_path, pub_path


@pytest.fixture()
def rbac_loader(tmp_path: Path) -> RBACLoader:
    yaml_path = tmp_path / "rbac.yaml"
    yaml_path.write_text(
        """
roles:
  base_reader:
    allowed_servers: [customer_data]
    allowed_tools:
      customer_data: [get_customer, list_accounts]
  analyst:
    inherits: [base_reader]
    allowed_servers: [transactions]
    allowed_tools:
      transactions: [get_transactions]
users:
  alice@example.com:
    roles: [analyst]
  readonly@example.com:
    roles: [base_reader]
groups:
  fraud-analysts:
    roles: [analyst]
""",
        encoding="utf-8",
    )
    return RBACLoader(yaml_path)


class _FakeOIDCValidator(OIDCValidator):  # type: ignore[misc]
    """OIDCValidator subclass that bypasses JWKS lookup for unit tests.

    The real validator hits the network during ``__init__`` to load the JWKS
    cache; we sidestep that by overriding ``__init__`` and ``validate``.
    """

    def __init__(self, *, accepted_tokens: dict[str, OIDCClaims]) -> None:
        # Skip super().__init__ entirely — no network.
        self._accepted = accepted_tokens

    def validate(self, token: str) -> OIDCClaims:  # type: ignore[override]
        if not token:
            raise OIDCInvalidTokenError("empty token")
        if token == "__expired__":
            raise OIDCExpiredTokenError("token expired")
        if token not in self._accepted:
            raise OIDCInvalidTokenError("unknown token")
        return self._accepted[token]


def _client(
    *,
    rbac: RBACLoader,
    paseto_keys: tuple[Path, Path],
    accepted: dict[str, OIDCClaims],
) -> TestClient:
    priv, pub = paseto_keys
    app = create_app(
        oidc_validator=_FakeOIDCValidator(accepted_tokens=accepted),
        rbac_loader=rbac,
        public_key_path=pub,
        private_key_path=priv,
    )
    return TestClient(app)


# --------------------------------------------------------------------------- #
# /token tests
# --------------------------------------------------------------------------- #


def test_post_token_valid_mint(
    rbac_loader: RBACLoader, paseto_keypair: tuple[Path, Path]
) -> None:
    accepted = {
        "good-token": OIDCClaims(
            sub="alice@example.com",
            email="alice@example.com",
            groups=[],
            raw={"sub": "alice@example.com", "email": "alice@example.com"},
        )
    }
    client = _client(rbac=rbac_loader, paseto_keys=paseto_keypair, accepted=accepted)

    resp = client.post("/token", headers={"Authorization": "Bearer good-token"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 300
    assert body["access_token"].startswith("v4.public.")

    # Decode the minted PASETO and check the embedded RBAC snapshot.
    decoded = paseto_verify(body["access_token"], public_key_path=paseto_keypair[1])
    assert decoded.sub == "alice@example.com"
    assert decoded.roles == ["analyst"]
    assert set(decoded.allowed_servers) == {"customer_data", "transactions"}
    # Inheritance flattened: analyst -> base_reader brings customer_data tools in.
    assert "customer_data" in decoded.allowed_tools
    assert "transactions" in decoded.allowed_tools
    assert set(decoded.allowed_tools["customer_data"]) == {"get_customer", "list_accounts"}
    assert decoded.allowed_tools["transactions"] == ["get_transactions"]
    assert decoded.jti
    assert decoded.trace_id


def test_post_token_role_inheritance_applied(
    rbac_loader: RBACLoader, paseto_keypair: tuple[Path, Path]
) -> None:
    """readonly@example.com -> base_reader only; analyst-specific tools absent."""
    accepted = {
        "ro-token": OIDCClaims(
            sub="readonly@example.com",
            email="readonly@example.com",
            groups=[],
            raw={"email": "readonly@example.com"},
        )
    }
    client = _client(rbac=rbac_loader, paseto_keys=paseto_keypair, accepted=accepted)
    resp = client.post("/token", headers={"Authorization": "Bearer ro-token"})
    assert resp.status_code == 200
    decoded = paseto_verify(resp.json()["access_token"], public_key_path=paseto_keypair[1])
    assert decoded.roles == ["base_reader"]
    assert decoded.allowed_servers == ["customer_data"]
    assert "transactions" not in decoded.allowed_tools


def test_post_token_group_mapped_role(
    rbac_loader: RBACLoader, paseto_keypair: tuple[Path, Path]
) -> None:
    """User unknown but group matches -> analyst role."""
    accepted = {
        "grp-token": OIDCClaims(
            sub="newcomer@example.com",
            email="newcomer@example.com",
            groups=["fraud-analysts"],
            raw={"email": "newcomer@example.com", "groups": ["fraud-analysts"]},
        )
    }
    client = _client(rbac=rbac_loader, paseto_keys=paseto_keypair, accepted=accepted)
    resp = client.post("/token", headers={"Authorization": "Bearer grp-token"})
    assert resp.status_code == 200
    decoded = paseto_verify(resp.json()["access_token"], public_key_path=paseto_keypair[1])
    assert decoded.roles == ["analyst"]


def test_post_token_expired_oidc_rejected(
    rbac_loader: RBACLoader, paseto_keypair: tuple[Path, Path]
) -> None:
    client = _client(rbac=rbac_loader, paseto_keys=paseto_keypair, accepted={})
    resp = client.post("/token", headers={"Authorization": "Bearer __expired__"})
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()


def test_post_token_invalid_oidc_rejected(
    rbac_loader: RBACLoader, paseto_keypair: tuple[Path, Path]
) -> None:
    client = _client(rbac=rbac_loader, paseto_keys=paseto_keypair, accepted={})
    resp = client.post("/token", headers={"Authorization": "Bearer garbage"})
    assert resp.status_code == 401
    assert "invalid" in resp.json()["detail"].lower()


def test_post_token_unknown_user_rejected(
    rbac_loader: RBACLoader, paseto_keypair: tuple[Path, Path]
) -> None:
    """OIDC token is valid but email/groups don't resolve to any role -> 403."""
    accepted = {
        "no-role-token": OIDCClaims(
            sub="stranger@example.com",
            email="stranger@example.com",
            groups=[],
            raw={"email": "stranger@example.com"},
        )
    }
    client = _client(rbac=rbac_loader, paseto_keys=paseto_keypair, accepted=accepted)
    resp = client.post("/token", headers={"Authorization": "Bearer no-role-token"})
    assert resp.status_code == 403
    assert "stranger@example.com" in resp.json()["detail"]


def test_post_token_missing_authorization_header(
    rbac_loader: RBACLoader, paseto_keypair: tuple[Path, Path]
) -> None:
    client = _client(rbac=rbac_loader, paseto_keys=paseto_keypair, accepted={})
    resp = client.post("/token")
    assert resp.status_code == 401


def test_post_token_malformed_authorization_header(
    rbac_loader: RBACLoader, paseto_keypair: tuple[Path, Path]
) -> None:
    client = _client(rbac=rbac_loader, paseto_keys=paseto_keypair, accepted={})
    resp = client.post("/token", headers={"Authorization": "Basic xxx"})
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# /.well-known/paseto-key tests
# --------------------------------------------------------------------------- #


def test_well_known_paseto_key_returns_pem(
    rbac_loader: RBACLoader, paseto_keypair: tuple[Path, Path]
) -> None:
    client = _client(rbac=rbac_loader, paseto_keys=paseto_keypair, accepted={})
    resp = client.get("/.well-known/paseto-key")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-pem-file")
    body = resp.text
    assert "BEGIN PUBLIC KEY" in body
    assert "END PUBLIC KEY" in body


def test_well_known_paseto_key_missing_file_returns_500(
    rbac_loader: RBACLoader, tmp_path: Path
) -> None:
    bogus = tmp_path / "does_not_exist.pem"
    priv = tmp_path / "priv.pem"
    priv.write_bytes(b"unused")
    app = create_app(
        oidc_validator=_FakeOIDCValidator(accepted_tokens={}),
        rbac_loader=rbac_loader,
        public_key_path=bogus,
        private_key_path=priv,
    )
    client = TestClient(app)
    resp = client.get("/.well-known/paseto-key")
    assert resp.status_code == 500


def test_healthz(rbac_loader: RBACLoader, paseto_keypair: tuple[Path, Path]) -> None:
    client = _client(rbac=rbac_loader, paseto_keys=paseto_keypair, accepted={})
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# --------------------------------------------------------------------------- #
# OIDCValidator unit tests (signature-level — uses a synthetic RSA JWKS).
# --------------------------------------------------------------------------- #


def _rsa_keypair_jwk() -> tuple[str, dict[str, str]]:
    """Generate an RSA keypair and return the PEM + a JWK dict."""
    import base64

    key = generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    numbers = key.public_key().public_numbers()

    def _b64(n: int) -> str:
        byte_len = (n.bit_length() + 7) // 8
        return (
            base64.urlsafe_b64encode(n.to_bytes(byte_len, "big")).rstrip(b"=").decode()
        )

    jwk = {
        "kty": "RSA",
        "kid": "test-key-1",
        "use": "sig",
        "alg": "RS256",
        "n": _b64(numbers.n),
        "e": _b64(numbers.e),
    }
    return priv_pem, jwk


def test_oidc_validator_accepts_well_formed_token(monkeypatch: pytest.MonkeyPatch) -> None:
    priv_pem, jwk = _rsa_keypair_jwk()
    payload = {
        "sub": "alice@example.com",
        "email": "alice@example.com",
        "groups": ["fraud-analysts"],
        "aud": "fraud-copilot",
        "iss": "https://example.com",
        "exp": int((datetime.now(tz=UTC) + timedelta(minutes=5)).timestamp()),
    }
    token = jwt.encode(payload, priv_pem, algorithm="RS256", headers={"kid": jwk["kid"]})

    validator = OIDCValidator(
        jwks_url="https://example.com/.well-known/jwks.json",
        audience="fraud-copilot",
        issuer="https://example.com",
    )
    # Patch the inner PyJWKClient to return our test signing key.
    from jwt import PyJWK

    monkeypatch.setattr(
        validator._jwks_client,
        "get_signing_key_from_jwt",
        lambda _t: PyJWK(jwk),
    )

    claims = validator.validate(token)
    assert claims.email == "alice@example.com"
    assert claims.groups == ["fraud-analysts"]


def test_oidc_validator_rejects_expired_token(monkeypatch: pytest.MonkeyPatch) -> None:
    priv_pem, jwk = _rsa_keypair_jwk()
    payload = {
        "sub": "alice@example.com",
        "email": "alice@example.com",
        "aud": "fraud-copilot",
        "iss": "https://example.com",
        "exp": int((datetime.now(tz=UTC) - timedelta(seconds=5)).timestamp()),
    }
    token = jwt.encode(payload, priv_pem, algorithm="RS256", headers={"kid": jwk["kid"]})

    validator = OIDCValidator(
        jwks_url="https://example.com/.well-known/jwks.json",
        audience="fraud-copilot",
        issuer="https://example.com",
    )
    from jwt import PyJWK

    monkeypatch.setattr(
        validator._jwks_client,
        "get_signing_key_from_jwt",
        lambda _t: PyJWK(jwk),
    )

    with pytest.raises(OIDCExpiredTokenError):
        validator.validate(token)


def test_oidc_validator_rejects_wrong_audience(monkeypatch: pytest.MonkeyPatch) -> None:
    priv_pem, jwk = _rsa_keypair_jwk()
    payload = {
        "sub": "alice@example.com",
        "email": "alice@example.com",
        "aud": "some-other-audience",
        "iss": "https://example.com",
        "exp": int((datetime.now(tz=UTC) + timedelta(minutes=5)).timestamp()),
    }
    token = jwt.encode(payload, priv_pem, algorithm="RS256", headers={"kid": jwk["kid"]})

    validator = OIDCValidator(
        jwks_url="https://example.com/.well-known/jwks.json",
        audience="fraud-copilot",
        issuer="https://example.com",
    )
    from jwt import PyJWK

    monkeypatch.setattr(
        validator._jwks_client,
        "get_signing_key_from_jwt",
        lambda _t: PyJWK(jwk),
    )

    with pytest.raises(OIDCInvalidTokenError):
        validator.validate(token)
