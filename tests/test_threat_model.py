"""Tests pinning the contents of ``docs/threat-model.md`` (US-031).

The threat model is the security reviewer's entry point into the project.
These tests act as a structural fence — they make sure that every AC
required by the PRD continues to be covered, even as the document is
revised. The assertions check for the presence of specific phrases /
sections; they intentionally do not lint prose so authors can iterate on
wording without breaking CI.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
THREAT_MODEL_PATH = REPO_ROOT / "docs" / "threat-model.md"


@pytest.fixture(scope="module")
def threat_model_text() -> str:
    assert THREAT_MODEL_PATH.exists(), (
        "docs/threat-model.md is the load-bearing US-031 artifact and must "
        f"exist at {THREAT_MODEL_PATH}"
    )
    return THREAT_MODEL_PATH.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# AC: docs/threat-model.md covers all trust boundaries from PRD §7            #
# --------------------------------------------------------------------------- #


def test_file_exists() -> None:
    assert THREAT_MODEL_PATH.is_file()


def test_has_trust_boundaries_section(threat_model_text: str) -> None:
    lowered = threat_model_text.lower()
    assert "trust boundar" in lowered, "must call out trust boundaries explicitly"


@pytest.mark.parametrize(
    "boundary_id",
    [
        "TB-1",  # Analyst ↔ plugin
        "TB-2",  # Plugin ↔ Auth Gateway
        "TB-3",  # Plugin ↔ MCP Gateway
        "TB-4",  # MCP Gateway ↔ MCP servers
        "TB-5",  # MCP server ↔ upstream API
        "TB-6",  # Audit pipeline ↔ readers
        "TB-7",  # Repo ↔ deployed skill
    ],
)
def test_enumerates_each_trust_boundary(
    threat_model_text: str, boundary_id: str
) -> None:
    assert boundary_id in threat_model_text, (
        f"Trust boundary {boundary_id} must be enumerated (PRD §7)"
    )


def test_mentions_every_architectural_hop(threat_model_text: str) -> None:
    lowered = threat_model_text.lower()
    for hop in (
        "auth gateway",
        "mcp gateway",
        "mcp server",
        "mock api",
        "audit",
        "cowork",
    ):
        assert hop in lowered, f"every architectural hop must be named (missing: {hop})"


# --------------------------------------------------------------------------- #
# AC: Documents mitigations for the five named threats                        #
# --------------------------------------------------------------------------- #

REQUIRED_THREAT_TOPICS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("prompt injection in tool results", ("prompt injection", "untrusted")),
    ("token replay", ("token replay", "jti", "replay cache")),
    ("skill spoofing", ("skill spoofing", "commit hash", "verbatim")),
    ("audit tampering", ("audit tampering", "append-only", "no public delete")),
    (
        "data exfil via OSINT",
        ("data exfiltration", "osint_allowlist", "domain_not_allowed"),
    ),
)


@pytest.mark.parametrize("label,markers", REQUIRED_THREAT_TOPICS)
def test_required_threat_topic_covered(
    threat_model_text: str, label: str, markers: tuple[str, ...]
) -> None:
    lowered = threat_model_text.lower()
    for marker in markers:
        assert marker.lower() in lowered, (
            f"Threat topic '{label}' must reference '{marker}' (mitigation discussion)"
        )


def test_residual_risks_section_present(threat_model_text: str) -> None:
    lowered = threat_model_text.lower()
    # Every named threat must explicitly call out a residual risk; the document
    # also carries a top-level summary section.
    assert lowered.count("residual risk") >= 5, (
        "every named threat should call out its residual risk; "
        "plus a summary residual-risks section"
    )


def test_operator_responsibilities_section_present(threat_model_text: str) -> None:
    lowered = threat_model_text.lower()
    assert "operator responsibilit" in lowered, (
        "PRD AC requires a 'lists residual risks and operator responsibilities' section"
    )


# --------------------------------------------------------------------------- #
# AC: Cross-links to relevant ADRs                                            #
# --------------------------------------------------------------------------- #


def test_cross_links_to_existing_adrs(threat_model_text: str) -> None:
    # ADR 0001 is the only ADR in the tree as of US-031 (US-029 shipped it).
    # The threat model must link to it; future ADRs land via US-033.
    assert "adr/0001-headless-cowork-harness.md" in threat_model_text, (
        "threat model must cross-link to docs/adr/0001-headless-cowork-harness.md"
    )


def test_adr_link_targets_exist() -> None:
    # Sanity check that every adr/*.md link in the threat model resolves on disk.
    text = THREAT_MODEL_PATH.read_text(encoding="utf-8")
    import re

    for match in re.finditer(r"adr/([0-9a-zA-Z_\-]+\.md)", text):
        target = REPO_ROOT / "docs" / "adr" / match.group(1)
        assert target.exists(), f"Broken ADR cross-link in threat model: {target}"


# --------------------------------------------------------------------------- #
# Structural sanity                                                            #
# --------------------------------------------------------------------------- #


def test_document_has_a_change_log(threat_model_text: str) -> None:
    lowered = threat_model_text.lower()
    assert "change log" in lowered or "changelog" in lowered, (
        "include a change log so future iterations record document evolution"
    )


def test_us_031_is_referenced(threat_model_text: str) -> None:
    assert "US-031" in threat_model_text, (
        "the threat model is the US-031 artifact and should self-identify"
    )


def test_pii_attribute_boundary_called_out(threat_model_text: str) -> None:
    lowered = threat_model_text.lower()
    # OTel PII boundary is a cross-cutting control with its own §
    assert "user.email" in lowered and "user.sub" in lowered, (
        "the OTel PII boundary (no user.email / user.sub in spans) is a "
        "cross-cutting control and must be documented"
    )


def test_two_distinct_keypairs_called_out(threat_model_text: str) -> None:
    lowered = threat_model_text.lower()
    assert "two distinct" in lowered or "separate keypair" in lowered, (
        "the user-token vs service-token keypair separation is a load-bearing "
        "cross-boundary control"
    )


def test_human_approval_gate_called_out(threat_model_text: str) -> None:
    lowered = threat_model_text.lower()
    assert "human_approval" in lowered, (
        "the case_actions human_approval gate is the only write-path control "
        "and must be documented"
    )
