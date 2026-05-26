"""`make register-plugin` entry point.

Validates the plugin bundle (plugin.json + every SKILL.md) and, when a
Cowork CLI is on PATH, hands off to it for the actual install. Without the
CLI, the script still emits the registration manifest to stdout and writes
a stable copy under `<state_dir>/fraud-investigator.manifest.json` so an
operator can drop it into a Cowork install manually.

Run with:
    python -m plugin.register             # validate + register
    python -m plugin.register --dry-run   # validate only
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from plugin.loader import (
    PluginManifest,
    PluginValidationError,
    SkillFrontmatter,
    validate_plugin,
)

DEFAULT_PLUGIN_DIR = Path(__file__).resolve().parent
COWORK_BIN_ENV = "COWORK_BIN"
STATE_DIR_ENV = "FRAUD_COPILOT_STATE_DIR"


def _state_dir() -> Path:
    override = os.environ.get(STATE_DIR_ENV)
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base / "fraud-copilot-oss"


def _print_manifest_summary(
    manifest: PluginManifest, skills: dict[str, SkillFrontmatter]
) -> None:
    print(f"plugin: {manifest.name} v{manifest.version}")
    print(f"  entry: {manifest.entry_point}")
    print(f"  skills ({len(skills)}):")
    for sid, sk in skills.items():
        print(f"    - {sid:<30} {sk.line_count:>4} lines  ({sk.path.name})")
    print(f"  mcp servers ({len(manifest.mcp_servers)}):")
    for s in manifest.mcp_servers:
        print(f"    - {s.name:<20} tools: {', '.join(s.tools)}")


def _write_state_manifest(manifest: PluginManifest, plugin_dir: Path) -> Path:
    state = _state_dir()
    state.mkdir(parents=True, exist_ok=True)
    out = state / f"{manifest.name}.manifest.json"
    payload = dict(manifest.raw)
    payload["__resolved_plugin_dir"] = str(plugin_dir)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return out


def _maybe_install_via_cowork(plugin_dir: Path) -> tuple[bool, str]:
    """Best-effort handoff to a Cowork CLI if one is on PATH.

    Returns (attempted, message). Never raises — failure here is non-fatal
    so a fresh contributor without the Cowork CLI installed can still call
    `make register-plugin` to validate the bundle.
    """
    cowork_bin = os.environ.get(COWORK_BIN_ENV) or shutil.which("cowork")
    if not cowork_bin:
        return False, "cowork CLI not found on PATH; skipping install handoff"
    try:
        result = subprocess.run(  # noqa: S603 — bin path validated above
            [cowork_bin, "plugins", "install", str(plugin_dir)],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except OSError as e:
        return True, f"cowork install failed to start: {e}"
    if result.returncode != 0:
        return True, (
            f"cowork install exited with {result.returncode}: "
            f"{(result.stderr or result.stdout).strip()}"
        )
    return True, f"cowork install succeeded: {result.stdout.strip() or 'ok'}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plugin-dir",
        type=Path,
        default=DEFAULT_PLUGIN_DIR,
        help="Path to the plugin/ directory (defaults to the one shipping with this repo).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the bundle but do not write the state manifest or call cowork.",
    )
    args = parser.parse_args(argv)

    try:
        manifest, skills = validate_plugin(args.plugin_dir)
    except PluginValidationError as e:
        print(f"plugin validation failed: {e}", file=sys.stderr)
        return 1

    _print_manifest_summary(manifest, skills)
    if args.dry_run:
        print("dry-run: skipping install.")
        return 0

    out = _write_state_manifest(manifest, args.plugin_dir)
    print(f"wrote registration manifest -> {out}")

    attempted, message = _maybe_install_via_cowork(args.plugin_dir)
    if attempted:
        print(message)
    else:
        print(f"note: {message}. Set {COWORK_BIN_ENV} or install the cowork CLI.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
