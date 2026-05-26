"""Tests pinning the contents of ``docs/adr/`` (US-033).

The ADR set is the load-bearing record of why each design choice was
made. These tests act as a structural fence — they make sure every
PRD-required ADR exists, follows the four-section template, is indexed
in ``docs/adr/README.md``, and that cross-links inside each ADR
resolve on disk. The assertions intentionally do not lint prose so
authors can iterate on wording without breaking CI.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ADR_DIR = REPO_ROOT / "docs" / "adr"
ADR_INDEX_PATH = ADR_DIR / "README.md"

# PRD US-033 AC: ADRs cover PASETO over JWT, YAML over Terraform for RBAC,
# SQLite default audit, FastMCP framework, annotate-not-block verifier,
# Opus 4.7 as default model. ADR 0001 (headless Cowork harness) shipped
# with US-029 and is the seed; US-033 adds the six below.
REQUIRED_ADR_FILENAMES: tuple[str, ...] = (
    "0001-headless-cowork-harness.md",
    "0002-paseto-over-jwt.md",
    "0003-yaml-rbac.md",
    "0004-sqlite-default-audit.md",
    "0005-fastmcp-framework.md",
    "0006-annotate-not-block-verifier.md",
    "0007-opus-default-model.md",
)

REQUIRED_SECTIONS: tuple[str, ...] = (
    "## Context",
    "## Decision",
    "## Consequences",
    # "Alternatives considered" is the canonical wording from ADR 0001;
    # accept either form so future ADRs aren't pinned to the exact title.
)


def _all_adr_files() -> list[Path]:
    return sorted(
        p for p in ADR_DIR.glob("*.md") if p.name != "README.md"
    )


# --------------------------------------------------------------------------- #
# AC: docs/adr/ contains one ADR per decision following the standard template #
# --------------------------------------------------------------------------- #


def test_adr_directory_exists() -> None:
    assert ADR_DIR.is_dir(), f"docs/adr/ must exist at {ADR_DIR}"


@pytest.mark.parametrize("filename", REQUIRED_ADR_FILENAMES)
def test_required_adr_exists(filename: str) -> None:
    path = ADR_DIR / filename
    assert path.is_file(), (
        f"PRD US-033 requires an ADR at {path}. Each major decision listed "
        "in the AC must have a dedicated ADR."
    )


@pytest.mark.parametrize("filename", REQUIRED_ADR_FILENAMES)
def test_adr_has_required_sections(filename: str) -> None:
    text = (ADR_DIR / filename).read_text(encoding="utf-8")
    for section in REQUIRED_SECTIONS:
        assert section in text, (
            f"ADR {filename} must include the section '{section}' "
            "(standard template: Context / Decision / Consequences / Alternatives)."
        )


@pytest.mark.parametrize("filename", REQUIRED_ADR_FILENAMES)
def test_adr_has_alternatives_section(filename: str) -> None:
    text = (ADR_DIR / filename).read_text(encoding="utf-8")
    # Accept either "## Alternatives" or "## Alternatives considered" so
    # authors can choose phrasing.
    assert "## Alternatives" in text, (
        f"ADR {filename} must include an Alternatives section "
        "(standard ADR template)."
    )


@pytest.mark.parametrize("filename", REQUIRED_ADR_FILENAMES)
def test_adr_has_status_line(filename: str) -> None:
    text = (ADR_DIR / filename).read_text(encoding="utf-8")
    lowered = text.lower()
    assert "**status**" in lowered, (
        f"ADR {filename} must declare a Status (Accepted / Proposed / Superseded)."
    )


# --------------------------------------------------------------------------- #
# AC: ADRs cover the six PRD-mandated topics                                   #
# --------------------------------------------------------------------------- #

PRD_TOPIC_MARKERS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "PASETO over JWT",
        "0002-paseto-over-jwt.md",
        ("paseto", "jwt", "ed25519"),
    ),
    (
        "YAML over Terraform for RBAC",
        "0003-yaml-rbac.md",
        ("yaml", "terraform", "rbac"),
    ),
    (
        "SQLite default audit",
        "0004-sqlite-default-audit.md",
        ("sqlite", "clickhouse", "audit"),
    ),
    (
        "FastMCP framework",
        "0005-fastmcp-framework.md",
        ("fastmcp", "mcp_servers/_common", "tool"),
    ),
    (
        "Annotate-not-block verifier",
        "0006-annotate-not-block-verifier.md",
        ("annotate", "block", "verifier", "verify-output"),
    ),
    (
        "Opus 4.7 as default model",
        "0007-opus-default-model.md",
        ("claude-opus-4-7", "default_model", "anthropic"),
    ),
)


@pytest.mark.parametrize("topic,filename,markers", PRD_TOPIC_MARKERS)
def test_prd_topic_covered(topic: str, filename: str, markers: tuple[str, ...]) -> None:
    text = (ADR_DIR / filename).read_text(encoding="utf-8").lower()
    for marker in markers:
        assert marker.lower() in text, (
            f"ADR for '{topic}' ({filename}) must reference '{marker}' "
            "(grounds the decision in the codebase)."
        )


# --------------------------------------------------------------------------- #
# AC: docs/adr/README.md indexes all ADRs with one-line summaries              #
# --------------------------------------------------------------------------- #


def test_adr_readme_exists() -> None:
    assert ADR_INDEX_PATH.is_file(), (
        f"docs/adr/README.md is the US-033 index and must exist at {ADR_INDEX_PATH}"
    )


@pytest.mark.parametrize("filename", REQUIRED_ADR_FILENAMES)
def test_readme_indexes_every_adr(filename: str) -> None:
    text = ADR_INDEX_PATH.read_text(encoding="utf-8")
    assert filename in text, (
        f"docs/adr/README.md must index {filename} so reviewers can navigate."
    )


def test_readme_index_has_summary_table() -> None:
    text = ADR_INDEX_PATH.read_text(encoding="utf-8")
    # A markdown table with at least one one-line-summary column.
    assert "| ADR" in text or "| ADR |" in text, (
        "README index should ship the ADRs as a one-row-per-ADR table."
    )


def test_readme_links_resolve_on_disk() -> None:
    text = ADR_INDEX_PATH.read_text(encoding="utf-8")
    for match in re.finditer(r"\(([0-9]{4}-[A-Za-z0-9_\-]+\.md)\)", text):
        target = ADR_DIR / match.group(1)
        assert target.exists(), (
            f"Broken ADR link in docs/adr/README.md: {target}"
        )


# --------------------------------------------------------------------------- #
# Cross-link sanity: every adr/*.md link inside an ADR resolves on disk        #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("filename", REQUIRED_ADR_FILENAMES)
def test_cross_links_within_adr_resolve(filename: str) -> None:
    text = (ADR_DIR / filename).read_text(encoding="utf-8")
    # Match relative links to sibling ADRs (no path prefix) or to other docs
    # via "../" prefix; both must resolve.
    for match in re.finditer(
        r"\(([0-9]{4}-[A-Za-z0-9_\-]+\.md)\)", text
    ):
        target = ADR_DIR / match.group(1)
        assert target.exists(), (
            f"Broken sibling-ADR link in {filename}: {target}"
        )
    for match in re.finditer(
        r"\(\.\./([A-Za-z0-9_\-/]+\.md)\)", text
    ):
        target = (ADR_DIR / ".." / match.group(1)).resolve()
        assert target.exists(), (
            f"Broken docs/ cross-link in {filename}: {target}"
        )


# --------------------------------------------------------------------------- #
# Structural sanity                                                            #
# --------------------------------------------------------------------------- #


def test_us_033_is_referenced_in_at_least_one_adr() -> None:
    # The new ADRs landed under US-033; at least one ADR must self-identify so
    # future readers can trace the decision provenance.
    hits = 0
    for path in _all_adr_files():
        if "US-033" in path.read_text(encoding="utf-8"):
            hits += 1
    assert hits >= 1, (
        "At least one ADR must reference US-033 so the new ADRs are traceable."
    )


def test_no_unexpected_adr_files() -> None:
    # If new ADR files land, they must be added to REQUIRED_ADR_FILENAMES OR
    # explicitly intended (e.g., a future US adds 0008). This guard nudges
    # authors to update the test list rather than orphaning ADRs.
    on_disk = {p.name for p in _all_adr_files()}
    declared = set(REQUIRED_ADR_FILENAMES)
    extras = on_disk - declared
    assert not extras, (
        f"ADRs on disk not declared in REQUIRED_ADR_FILENAMES: {sorted(extras)}. "
        "Add them to the list so the structural fence covers them."
    )
