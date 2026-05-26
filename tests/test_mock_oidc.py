"""Unit tests for mock_apis/mock_oidc (DEV-ONLY mock IdP)."""

from __future__ import annotations

from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from jwt import PyJWK

from gateways.auth.main import create_app as create_auth_app
from gateways.auth.oidc import OIDCInvalidTokenError, OIDCValidator
from gateways.common import paseto as paseto_mod
from gateways.common.rbac import RBACLoader
from mock_apis.mock_oidc.main import create_app as create_mock_oidc_app


@pytest.fixture(autouse=True)
def _clear_paseto_key_cache() -> None:
    paseto_mod._load_private_key_cached.cache_clear()
    paseto_mod._load_public_key_cached.cache_clear()


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


@pytest.fixture()
def paseto_keypair(tmp_path: Path) -> tuple[Path, Path]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_path = tmp_path / "paseto_private.pem"
    pub_path = tmp_path / "paseto_public.pem"
    priv_path.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    pub_path.write_bytes(
        pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv_path, pub_path


def _mock_oidc_client(rbac: RBACLoader) -> TestClient:
    app = create_mock_oidc_app(rbac_loader=rbac)
    return TestClient(app)


# --------------------------------------------------------------------------- #
# Discovery / JWKS
# --------------------------------------------------------------------------- #


def test_openid_configuration_lists_required_endpoints(rbac_loader: RBACLoader) -> None:
    client = _mock_oidc_client(rbac_loader)
    resp = client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    body = resp.json()
    assert body["issuer"] == "http://mock-oidc"
    assert body["jwks_uri"].endswith("/jwks")
    assert body["token_endpoint"].endswith("/token")
    assert "RS256" in body["id_token_signing_alg_values_supported"]


def test_jwks_returns_public_keys(rbac_loader: RBACLoader) -> None:
    client = _mock_oidc_client(rbac_loader)
    resp = client.get("/jwks")
    assert resp.status_code == 200
    body = resp.json()
    assert "keys" in body
    assert len(body["keys"]) == 1
    jwk = body["keys"][0]
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["kid"]
    assert jwk["n"]
    assert jwk["e"]


# --------------------------------------------------------------------------- #
# /login
# --------------------------------------------------------------------------- #


def test_login_returns_signed_token_for_known_email(rbac_loader: RBACLoader) -> None:
    client = _mock_oidc_client(rbac_loader)
    resp = client.get("/login", params={"email": "alice@example.com"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 300
    token = body["id_token"]
    assert token

    # Decode locally (no verification) to confirm claim shape.
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload["email"] == "alice@example.com"
    assert payload["sub"] == "alice@example.com"
    assert payload["aud"] == "fraud-copilot"
    assert payload["iss"] == "http://mock-oidc"


def test_login_unknown_email_returns_404(rbac_loader: RBACLoader) -> None:
    client = _mock_oidc_client(rbac_loader)
    resp = client.get("/login", params={"email": "stranger@example.com"})
    assert resp.status_code == 404


def test_login_token_signature_verifies_against_jwks(rbac_loader: RBACLoader) -> None:
    """The token /login returns must be verifiable using the JWKS we publish."""
    client = _mock_oidc_client(rbac_loader)
    jwks = client.get("/jwks").json()
    jwk = PyJWK(jwks["keys"][0])

    token = client.get("/login", params={"email": "alice@example.com"}).json()["id_token"]
    payload = jwt.decode(
        token,
        jwk.key,
        algorithms=["RS256"],
        audience="fraud-copilot",
        issuer="http://mock-oidc",
    )
    assert payload["email"] == "alice@example.com"


def test_login_for_user_with_group_membership_includes_group_claim(
    tmp_path: Path,
) -> None:
    """A user whose role overlaps a group's role set should advertise that group."""
    yaml_path = tmp_path / "rbac.yaml"
    yaml_path.write_text(
        """
roles:
  analyst:
    allowed_servers: [transactions]
    allowed_tools:
      transactions: [get_transactions]
users:
  alice@example.com:
    roles: [analyst]
groups:
  fraud-analysts:
    roles: [analyst]
""",
        encoding="utf-8",
    )
    loader = RBACLoader(yaml_path)
    client = TestClient(create_mock_oidc_app(rbac_loader=loader))
    token = client.get("/login", params={"email": "alice@example.com"}).json()["id_token"]
    payload = jwt.decode(token, options={"verify_signature": False})
    assert "fraud-analysts" in payload["groups"]


# --------------------------------------------------------------------------- #
# /token (OAuth-style)
# --------------------------------------------------------------------------- #


def test_token_endpoint_password_grant(rbac_loader: RBACLoader) -> None:
    client = _mock_oidc_client(rbac_loader)
    resp = client.post(
        "/token",
        data={"username": "readonly@example.com", "grant_type": "password"},
    )
    assert resp.status_code == 200
    body = resp.json()
    payload = jwt.decode(body["id_token"], options={"verify_signature": False})
    assert payload["email"] == "readonly@example.com"


def test_token_endpoint_missing_username_400(rbac_loader: RBACLoader) -> None:
    client = _mock_oidc_client(rbac_loader)
    resp = client.post("/token", data={"grant_type": "password"})
    assert resp.status_code == 400


# --------------------------------------------------------------------------- #
# End-to-end: mock OIDC -> auth gateway accepts the token.
# --------------------------------------------------------------------------- #


class _JWKSBackedOIDCValidator(OIDCValidator):
    """Validator that resolves signing keys from a JWK dict pre-fetched from
    the mock IdP — bypasses the network call PyJWKClient would otherwise make.
    """

    def __init__(self, *, jwks: dict[str, object], audience: str, issuer: str) -> None:
        # Skip super().__init__ — we don't need a PyJWKClient because we
        # already have the JWKS in hand. Pretend we have a placeholder URL
        # so the parent class invariants (non-empty _jwks_url/_audience) hold.
        self._jwks_url = "http://mock-oidc/jwks"
        self._audience = audience
        self._issuer = issuer
        self._http_client = None
        keys_raw = jwks.get("keys", [])
        if not isinstance(keys_raw, list) or not keys_raw:
            raise OIDCInvalidTokenError("jwks empty")
        first = keys_raw[0]
        if not isinstance(first, dict):
            raise OIDCInvalidTokenError("malformed jwks entry")
        self._signing_key = PyJWK(first)

    def _get_signing_key(self, _token: str) -> PyJWK:  # pragma: no cover - small shim
        return self._signing_key

    def validate(self, token: str):  # type: ignore[override]
        # Reuse the parent class logic but inject our pre-loaded key.
        from typing import Any as _Any

        import jwt as _jwt

        from gateways.auth.oidc import OIDCClaims, OIDCExpiredTokenError

        options: dict[str, _Any] = {"require": ["exp", "aud"]}
        decode_kwargs: dict[str, _Any] = {
            "audience": self._audience,
            "options": options,
            "issuer": self._issuer,
        }
        try:
            payload: dict[str, _Any] = _jwt.decode(
                token,
                self._signing_key.key,
                algorithms=["RS256", "ES256", "EdDSA"],
                **decode_kwargs,
            )
        except _jwt.ExpiredSignatureError as exc:
            raise OIDCExpiredTokenError(str(exc)) from exc
        except (_jwt.InvalidTokenError, _jwt.DecodeError) as exc:
            raise OIDCInvalidTokenError(str(exc)) from exc

        sub = str(payload.get("sub") or "")
        email = str(payload.get("email") or sub)
        groups_raw = payload.get("groups") or []
        if not isinstance(groups_raw, list):
            raise OIDCInvalidTokenError("'groups' claim must be a list")
        return OIDCClaims(
            sub=sub,
            email=email,
            groups=[str(g) for g in groups_raw],
            raw=payload,
        )


def test_auth_gateway_accepts_mock_oidc_token(
    rbac_loader: RBACLoader, paseto_keypair: tuple[Path, Path]
) -> None:
    """The canonical acceptance test from US-005: /login -> auth gateway /token."""
    mock_client = _mock_oidc_client(rbac_loader)
    jwks = mock_client.get("/jwks").json()
    oidc_token = mock_client.get(
        "/login", params={"email": "alice@example.com"}
    ).json()["id_token"]

    priv, pub = paseto_keypair
    auth_app = create_auth_app(
        oidc_validator=_JWKSBackedOIDCValidator(
            jwks=jwks,
            audience="fraud-copilot",
            issuer="http://mock-oidc",
        ),
        rbac_loader=rbac_loader,
        public_key_path=pub,
        private_key_path=priv,
    )
    auth_client = TestClient(auth_app)
    resp = auth_client.post(
        "/token", headers={"Authorization": f"Bearer {oidc_token}"}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["access_token"].startswith("v4.public.")
    assert body["expires_in"] == 300


def test_auth_gateway_rejects_mock_oidc_token_with_wrong_audience(
    rbac_loader: RBACLoader, paseto_keypair: tuple[Path, Path]
) -> None:
    mock_app = create_mock_oidc_app(rbac_loader=rbac_loader, audience="some-other-aud")
    mock_client = TestClient(mock_app)
    jwks = mock_client.get("/jwks").json()
    oidc_token = mock_client.get(
        "/login", params={"email": "alice@example.com"}
    ).json()["id_token"]

    priv, pub = paseto_keypair
    auth_app = create_auth_app(
        oidc_validator=_JWKSBackedOIDCValidator(
            jwks=jwks,
            audience="fraud-copilot",  # the real audience the gateway expects
            issuer="http://mock-oidc",
        ),
        rbac_loader=rbac_loader,
        public_key_path=pub,
        private_key_path=priv,
    )
    auth_client = TestClient(auth_app)
    resp = auth_client.post(
        "/token", headers={"Authorization": f"Bearer {oidc_token}"}
    )
    assert resp.status_code == 401


def test_healthz(rbac_loader: RBACLoader) -> None:
    client = _mock_oidc_client(rbac_loader)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
