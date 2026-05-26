"""Unit tests for gateways/common/paseto.py."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateways.common import paseto as paseto_mod
from gateways.common.paseto import (
    Claims,
    ExpiredTokenError,
    InvalidTokenError,
    MalformedTokenError,
    mint,
    verify,
)


def _write_keypair(tmp_path: Path, name: str = "k") -> tuple[Path, Path]:
    """Generate an Ed25519 keypair and write PEM files into ``tmp_path``."""
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

    priv_path = tmp_path / f"{name}_private.pem"
    pub_path = tmp_path / f"{name}_public.pem"
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    return priv_path, pub_path


@pytest.fixture(autouse=True)
def _clear_key_cache() -> None:
    """Reset cached keys between tests so each tmp_path keypair is fresh."""
    paseto_mod._load_private_key_cached.cache_clear()
    paseto_mod._load_public_key_cached.cache_clear()


def test_mint_then_verify_roundtrip(tmp_path: Path) -> None:
    priv, pub = _write_keypair(tmp_path)

    claims = Claims(
        sub="alice@example.com",
        roles=["analyst"],
        allowed_servers=["customer_data", "transactions"],
        allowed_tools={
            "customer_data": ["get_customer"],
            "transactions": ["get_transactions"],
        },
        trace_id="trace-abc",
    )

    token = mint(claims, ttl_seconds=300, private_key_path=priv)
    assert token.startswith("v4.public.")

    decoded = verify(token, public_key_path=pub)
    assert decoded.sub == "alice@example.com"
    assert decoded.roles == ["analyst"]
    assert decoded.allowed_servers == ["customer_data", "transactions"]
    assert decoded.allowed_tools == {
        "customer_data": ["get_customer"],
        "transactions": ["get_transactions"],
    }
    assert decoded.trace_id == "trace-abc"
    # mint auto-fills jti and exp
    assert decoded.jti
    assert decoded.exp


def test_mint_auto_assigns_unique_jti(tmp_path: Path) -> None:
    priv, pub = _write_keypair(tmp_path)
    claims = Claims(sub="alice@example.com")

    t1 = verify(mint(claims, ttl_seconds=60, private_key_path=priv), public_key_path=pub)
    t2 = verify(mint(claims, ttl_seconds=60, private_key_path=priv), public_key_path=pub)
    assert t1.jti and t2.jti and t1.jti != t2.jti


def test_expired_token_rejected(tmp_path: Path) -> None:
    """A real-time expiry: mint with TTL=1s, sleep 2s, verify must reject."""
    priv, pub = _write_keypair(tmp_path)
    token = mint(Claims(sub="alice@example.com"), ttl_seconds=1, private_key_path=priv)
    time.sleep(2)
    with pytest.raises(ExpiredTokenError):
        verify(token, public_key_path=pub)


def test_tampered_token_rejected(tmp_path: Path) -> None:
    priv, pub = _write_keypair(tmp_path)
    token = mint(Claims(sub="alice@example.com"), ttl_seconds=300, private_key_path=priv)

    # Flip a character in the payload section. token format is v4.public.<payload>.<optional footer>
    head, version, payload = token.split(".", 2)
    # Swap two characters near the middle of the payload section to invalidate the signature.
    mid = len(payload) // 2
    swapped = payload[:mid] + ("A" if payload[mid] != "A" else "B") + payload[mid + 1 :]
    tampered = f"{head}.{version}.{swapped}"

    with pytest.raises(InvalidTokenError):
        verify(tampered, public_key_path=pub)


def test_wrong_key_rejected(tmp_path: Path) -> None:
    priv_a, _pub_a = _write_keypair(tmp_path, name="a")
    _priv_b, pub_b = _write_keypair(tmp_path, name="b")

    token = mint(Claims(sub="alice@example.com"), ttl_seconds=300, private_key_path=priv_a)
    with pytest.raises(InvalidTokenError):
        verify(token, public_key_path=pub_b)


def test_malformed_token_rejected(tmp_path: Path) -> None:
    _priv, pub = _write_keypair(tmp_path)
    with pytest.raises(MalformedTokenError):
        verify("", public_key_path=pub)
    with pytest.raises(MalformedTokenError):
        verify("not-a-paseto-token", public_key_path=pub)
    with pytest.raises(MalformedTokenError):
        verify("v2.local.abcdef", public_key_path=pub)


def test_env_var_fallback_for_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    priv, pub = _write_keypair(tmp_path)
    monkeypatch.setenv("PASETO_PRIVATE_KEY_PATH", str(priv))
    monkeypatch.setenv("PASETO_PUBLIC_KEY_PATH", str(pub))

    token = mint(Claims(sub="alice@example.com"), ttl_seconds=60)
    decoded = verify(token)
    assert decoded.sub == "alice@example.com"


def test_dict_claims_accepted(tmp_path: Path) -> None:
    priv, pub = _write_keypair(tmp_path)
    token = mint(
        {"sub": "alice@example.com", "roles": ["analyst"]},
        ttl_seconds=60,
        private_key_path=priv,
    )
    decoded = verify(token, public_key_path=pub)
    assert decoded.sub == "alice@example.com"
    assert decoded.roles == ["analyst"]


def test_ttl_must_be_positive(tmp_path: Path) -> None:
    priv, _pub = _write_keypair(tmp_path)
    with pytest.raises(ValueError):
        mint(Claims(sub="alice@example.com"), ttl_seconds=0, private_key_path=priv)
