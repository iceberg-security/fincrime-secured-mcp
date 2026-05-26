"""Generate Ed25519 keypairs for the M0 dev stack.

Produces two keypairs under ``config/keys/`` (gitignored):

* ``auth_paseto_*.pem`` — user PASETOs minted by the auth gateway, verified
  by the MCP gateway. Public PEM is also served at the auth gateway's
  ``/.well-known/paseto-key`` for ad-hoc verification.
* ``service_paseto_*.pem`` — service-to-service PASETOs minted by the MCP
  gateway, verified by each downstream MCP server (US-009+).

Idempotent: skips existing files unless ``--force`` is passed. The dev keys
are NOT for production — they are intentionally checked-in-friendly via the
``.gitignore`` rule on ``keys/`` so a fresh clone regenerates them.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_DEFAULT_DIR = Path("config/keys")
_KEYS = ("auth_paseto", "service_paseto")


def _write_keypair(name: str, out_dir: Path, *, force: bool) -> tuple[Path, Path]:
    priv_path = out_dir / f"{name}_private.pem"
    pub_path = out_dir / f"{name}_public.pem"
    if priv_path.exists() and pub_path.exists() and not force:
        return priv_path, pub_path
    sk = Ed25519PrivateKey.generate()
    priv_pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = sk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    priv_path.chmod(0o600)
    pub_path.chmod(0o644)
    return priv_path, pub_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=_DEFAULT_DIR,
        help=f"Output directory (default: {_DEFAULT_DIR})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Regenerate keys even if they already exist",
    )
    args = parser.parse_args(argv)

    for name in _KEYS:
        priv, pub = _write_keypair(name, args.out_dir, force=args.force)
        print(f"  {name}: {priv}  {pub}")
    print(f"Wrote {len(_KEYS)} keypair(s) to {args.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
