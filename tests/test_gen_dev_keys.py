"""Smoke tests for scripts/gen_dev_keys.py (US-011).

Ensures the keypair generator is callable, idempotent, and emits PEMs that
PASETO's ``mint``/``verify`` can actually consume — so the docker stack
that mounts ``config/keys/`` boots with usable keys.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import gen_dev_keys  # noqa: E402

from gateways.common import paseto as paseto_mod  # noqa: E402
from gateways.common.paseto import Claims, mint, verify  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_paseto_key_cache() -> Iterator[None]:
    paseto_mod._load_private_key_cached.cache_clear()
    paseto_mod._load_public_key_cached.cache_clear()
    yield
    paseto_mod._load_private_key_cached.cache_clear()
    paseto_mod._load_public_key_cached.cache_clear()


def test_generates_two_keypairs(tmp_path: Path) -> None:
    rc = gen_dev_keys.main(["--out-dir", str(tmp_path)])
    assert rc == 0
    for name in ("auth_paseto", "service_paseto"):
        assert (tmp_path / f"{name}_private.pem").exists()
        assert (tmp_path / f"{name}_public.pem").exists()


def test_is_idempotent_without_force(tmp_path: Path) -> None:
    gen_dev_keys.main(["--out-dir", str(tmp_path)])
    priv = tmp_path / "auth_paseto_private.pem"
    pub = tmp_path / "auth_paseto_public.pem"
    priv_bytes_before = priv.read_bytes()
    pub_bytes_before = pub.read_bytes()
    gen_dev_keys.main(["--out-dir", str(tmp_path)])
    assert priv.read_bytes() == priv_bytes_before
    assert pub.read_bytes() == pub_bytes_before


def test_force_regenerates(tmp_path: Path) -> None:
    gen_dev_keys.main(["--out-dir", str(tmp_path)])
    priv = tmp_path / "auth_paseto_private.pem"
    before = priv.read_bytes()
    gen_dev_keys.main(["--out-dir", str(tmp_path), "--force"])
    after = priv.read_bytes()
    assert before != after, "--force should regenerate keys"


def test_generated_keys_work_with_paseto_helpers(tmp_path: Path) -> None:
    """End-to-end: keys produced by the generator must round-trip through mint+verify."""
    gen_dev_keys.main(["--out-dir", str(tmp_path)])
    priv = tmp_path / "auth_paseto_private.pem"
    pub = tmp_path / "auth_paseto_public.pem"
    claims = Claims(
        sub="alice@example.com",
        roles=["analyst"],
        allowed_servers=["customer_data"],
        allowed_tools={"customer_data": ["get_customer"]},
        trace_id="trace-xyz",
    )
    token = mint(claims, ttl_seconds=60, private_key_path=str(priv))
    decoded = verify(token, public_key_path=str(pub))
    assert decoded.sub == "alice@example.com"
    assert decoded.roles == ["analyst"]
