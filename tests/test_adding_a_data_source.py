"""Tests pinning the contents of ``docs/adding-a-data-source.md`` (US-032).

The tutorial is the detection engineer's entry point into the project.
These tests act as a structural fence — they make sure every AC required
by the PRD continues to be covered, even as the document is revised.
The assertions check for presence of specific phrases / sections; they
intentionally do not lint prose so authors can iterate on wording
without breaking CI.

Mirrors the test pattern shipped with US-031 (``tests/test_threat_model.py``)
— the same "docs-with-test-fence" pattern documented in
``scripts/ralph/progress.txt`` (Codebase Patterns).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TUTORIAL_PATH = REPO_ROOT / "docs" / "adding-a-data-source.md"


@pytest.fixture(scope="module")
def tutorial_text() -> str:
    assert TUTORIAL_PATH.exists(), (
        "docs/adding-a-data-source.md is the load-bearing US-032 artifact "
        f"and must exist at {TUTORIAL_PATH}"
    )
    return TUTORIAL_PATH.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# AC: file exists                                                              #
# --------------------------------------------------------------------------- #


def test_file_exists() -> None:
    assert TUTORIAL_PATH.is_file()


def test_us_032_is_referenced(tutorial_text: str) -> None:
    assert "US-032" in tutorial_text, (
        "the tutorial is the US-032 artifact and should self-identify"
    )


# --------------------------------------------------------------------------- #
# AC: walks through defining MCP tools, FastMCP server, config/servers.yaml,   #
# config/rbac.yaml, declaring usage in a SKILL.md                              #
# --------------------------------------------------------------------------- #

# The PRD AC enumerates the five wiring steps. Each becomes one test via
# parametrize so authors see which step regressed at a glance. ``markers``
# are case-insensitive substrings that MUST all appear; one of them is
# the canonical filename / module path so the test fails loudly if a
# rename drifts the doc.
REQUIRED_WIRING_STEPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "defining MCP tools",
        ("fastmcp", "tools/list", "tools/call", "@mcp.tool"),
    ),
    (
        "writing a FastMCP server",
        ("mcp_servers/", "_common.py", "create_jsonrpc_app", "build_default_app"),
    ),
    (
        "updating config/servers.yaml (gateway URL map / compose)",
        # No config/servers.yaml file exists in the repo — the canonical
        # server registry is the gateway URL map + docker-compose.yml.
        # The doc must call this out explicitly so contributors don't go
        # looking for a missing file.
        ("config/servers.yaml", "mcp_gateway_downstream_urls", "docker-compose"),
    ),
    (
        "updating config/rbac.yaml",
        ("config/rbac.yaml", "allowed_servers", "allowed_tools", "hot reload"),
    ),
    (
        "declaring usage in a SKILL.md",
        ("skill.md", "plugin.json", "plugin/loader.py", "<tools>"),
    ),
)


@pytest.mark.parametrize("label,markers", REQUIRED_WIRING_STEPS)
def test_required_wiring_step_covered(
    tutorial_text: str, label: str, markers: tuple[str, ...]
) -> None:
    lowered = tutorial_text.lower()
    for marker in markers:
        assert marker.lower() in lowered, (
            f"Wiring step '{label}' must reference '{marker}' "
            f"(verifier discipline for AC §32)"
        )


# --------------------------------------------------------------------------- #
# AC: worked example uses a fictional 'neobank' API                            #
# --------------------------------------------------------------------------- #


def test_worked_example_uses_neobank(tutorial_text: str) -> None:
    lowered = tutorial_text.lower()
    # "neobank" must appear in the mock path, the MCP server path, and
    # the SKILL.md path — proves the example is end-to-end, not just a
    # name-drop.
    assert lowered.count("neobank") >= 5, (
        "the worked example must thread the 'neobank' name through every "
        "step (mock path, MCP server, SKILL.md, RBAC entry, dataset)"
    )
    for path_fragment in (
        "mock_apis/neobank",
        "mcp_servers/neobank",
        "check-neobank-credit",
    ):
        assert path_fragment in tutorial_text, (
            f"worked example must include the '{path_fragment}' path so "
            "contributors can copy verbatim"
        )


# --------------------------------------------------------------------------- #
# AC: each step has a verification command (e.g. curl ... returns 200)         #
# --------------------------------------------------------------------------- #


def test_has_verification_commands(tutorial_text: str) -> None:
    # The tutorial structure pins one "Verify:" prompt per step. The five
    # wiring steps + the prereqs step + the smoke step = at least 6
    # verifier sections. We assert >= 6 occurrences of "Verify" (case
    # sensitive — the doc uses "**Verify**" as a section marker).
    occurrences = tutorial_text.count("**Verify")
    assert occurrences >= 6, (
        f"each step needs a verification command (found only {occurrences} "
        "'**Verify' markers — PRD AC §32 requires one per step)"
    )


def test_verification_includes_http_200_check(tutorial_text: str) -> None:
    # At least one verifier must demonstrate the "curl ... returns 200"
    # shape the PRD calls out by example.
    assert "200" in tutorial_text and "curl" in tutorial_text.lower(), (
        "PRD AC §32 example is 'curl ... returns 200' — at least one "
        "verifier must demonstrate that exact shape"
    )


def test_verification_exercises_federated_path(tutorial_text: str) -> None:
    # The doc must show the gateway-mediated call, not just the raw mock,
    # otherwise contributors miss the RBAC + audit hop.
    lowered = tutorial_text.lower()
    assert "localhost:8000/mcp/" in lowered, (
        "at least one verifier must call through the MCP gateway "
        "(localhost:8000/mcp/<server>) so the RBAC + audit hop is exercised"
    )


# --------------------------------------------------------------------------- #
# AC: manually followed end-to-end in <1 hour (documented in PR)               #
# --------------------------------------------------------------------------- #


def test_time_budget_documented(tutorial_text: str) -> None:
    lowered = tutorial_text.lower()
    # The doc must declare an explicit time budget that totals under 60 min.
    assert "time budget" in lowered or "1 hour" in lowered or "55 min" in lowered, (
        "PRD AC §32 requires the <1 hour completion time to be documented "
        "in the tutorial itself"
    )


def test_steps_have_individual_durations(tutorial_text: str) -> None:
    # At least four "<n> min" annotations on step headings — the doc has
    # 7 steps and each should call out its share of the hour.
    minute_markers = re.findall(r"\d+\s*min", tutorial_text.lower())
    assert len(minute_markers) >= 5, (
        f"steps must individually declare their time share (found "
        f"{len(minute_markers)} minute annotations)"
    )


# --------------------------------------------------------------------------- #
# Cross-links: docs should reference the existing ADRs + sibling docs          #
# --------------------------------------------------------------------------- #


def test_cross_links_to_existing_adrs(tutorial_text: str) -> None:
    # ADR 0001 is the only ADR in the tree at US-032 time; the tutorial
    # should reference it so the contributor lands on the architectural
    # context before diving in.
    assert "adr/0001-headless-cowork-harness.md" in tutorial_text, (
        "tutorial must cross-link to docs/adr/0001-headless-cowork-harness.md"
    )


def test_cross_links_to_sibling_docs(tutorial_text: str) -> None:
    # The agent-testing + threat-model docs are the contributor's next
    # natural reads after this tutorial.
    for sibling in ("agent-testing.md", "threat-model.md"):
        assert sibling in tutorial_text, (
            f"tutorial should cross-link to docs/{sibling}"
        )


def test_adr_link_targets_exist() -> None:
    # Sanity-check every adr/*.md link resolves on disk.
    text = TUTORIAL_PATH.read_text(encoding="utf-8")
    found = False
    for match in re.finditer(r"adr/([0-9a-zA-Z_\-]+\.md)", text):
        found = True
        target = REPO_ROOT / "docs" / "adr" / match.group(1)
        assert target.exists(), f"Broken ADR cross-link in tutorial: {target}"
    assert found, "tutorial should reference at least one ADR by file path"


def test_sibling_doc_link_targets_exist() -> None:
    # Every docs/<file>.md link in the tutorial must resolve on disk.
    text = TUTORIAL_PATH.read_text(encoding="utf-8")
    # Match relative .md links that don't go up a directory and aren't ADRs
    # (those are covered above) — pattern is the doc filename inside
    # parentheses, possibly prefixed with ./ but not ../.
    for match in re.finditer(r"\(((?!\.\.|adr/)[a-z0-9\-_]+\.md)\)", text):
        target = REPO_ROOT / "docs" / match.group(1)
        assert target.exists(), f"Broken sibling-doc cross-link: {target}"


# --------------------------------------------------------------------------- #
# Structural sanity                                                            #
# --------------------------------------------------------------------------- #


def test_document_has_a_change_log(tutorial_text: str) -> None:
    lowered = tutorial_text.lower()
    assert "change log" in lowered or "changelog" in lowered, (
        "include a change log so future iterations record document evolution "
        "(US-031 set the precedent)"
    )


def test_mentions_six_personas(tutorial_text: str) -> None:
    # The eval datasets + mocks share a fixed six-persona enum
    # (clean/mule/sanctions_hit/ato/structuring/synthetic_id). The
    # tutorial must reference at least four so contributors know to make
    # their data source scenario-aware.
    lowered = tutorial_text.lower()
    personas = ("clean", "mule", "sanctions_hit", "ato", "structuring", "synthetic_id")
    hits = [p for p in personas if p in lowered]
    assert len(hits) >= 4, (
        f"tutorial must reference the persona enum so contributors make "
        f"their data source scenario-aware (found only {hits})"
    )


def test_calls_out_paseto_replay_pitfall(tutorial_text: str) -> None:
    # The PASETO jti-replay gotcha catches every new contributor exactly
    # once. The tutorial's pitfalls section must call it out by name.
    lowered = tutorial_text.lower()
    assert "jti" in lowered, (
        "the PASETO jti-replay pitfall must be documented in the tutorial "
        "(catches every new contributor exactly once)"
    )


def test_calls_out_read_only_constraint(tutorial_text: str) -> None:
    # Read-only is a load-bearing constraint — the tutorial keeps the
    # human_approval flow off the critical path.
    lowered = tutorial_text.lower()
    assert "read-only" in lowered, (
        "tutorial must emphasize read-only data sources (the human_approval "
        "flow is reserved for case_actions)"
    )


def test_references_optional_eval_step(tutorial_text: str) -> None:
    # Step 6 (eval dataset) is optional but recommended — it's the only
    # way the new server gets CI coverage. The tutorial must mention it.
    lowered = tutorial_text.lower()
    assert "evals/datasets" in lowered or "make validate-evals" in lowered, (
        "tutorial must show how to add an eval dataset for the new server "
        "(the only way it gets CI coverage)"
    )
