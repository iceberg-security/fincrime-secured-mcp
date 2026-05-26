"""Tests pinning ``README.md`` and ``docs/launch-post.md`` (US-034).

US-034 is the launch story: the README is the public face of the project
and the launch blog post is the announcement artifact. These tests act
as a structural fence — they pin the PRD AC bullets so the documents
stay aligned with the spec as future iterations revise the wording.

The assertions check for the presence of specific phrases / sections;
they intentionally do not lint prose so authors can iterate on wording
without breaking CI.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
README_PATH = REPO_ROOT / "README.md"
LAUNCH_POST_PATH = REPO_ROOT / "docs" / "launch-post.md"


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def readme_text() -> str:
    assert README_PATH.exists(), (
        f"README.md is the US-034 artifact and must exist at {README_PATH}"
    )
    return README_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def launch_post_text() -> str:
    assert LAUNCH_POST_PATH.exists(), (
        "docs/launch-post.md is the US-034 launch artifact and must exist "
        f"at {LAUNCH_POST_PATH}"
    )
    return LAUNCH_POST_PATH.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# AC: README hero — one-sentence value prop                                   #
# --------------------------------------------------------------------------- #


def test_readme_exists() -> None:
    assert README_PATH.is_file()


def test_readme_has_hero_value_prop(readme_text: str) -> None:
    # The hero should be a single load-bearing sentence, set off as a
    # blockquote so readers skimming the file can find it instantly.
    lines = readme_text.splitlines()
    blockquote_lines = [line for line in lines[:20] if line.startswith("> ")]
    assert blockquote_lines, (
        "README hero section must contain a blockquote value prop within "
        "the first 20 lines"
    )
    hero = " ".join(line[2:].strip() for line in blockquote_lines)
    lowered = hero.lower()
    # The value prop must name the load-bearing concepts.
    for marker in ("fraud", "auth", "rbac", "audit"):
        assert marker in lowered, (
            f"hero value prop must mention '{marker}' (got: {hero!r})"
        )


# --------------------------------------------------------------------------- #
# AC: README hero — architecture diagram referenced from PRD §5               #
# --------------------------------------------------------------------------- #


def test_readme_references_architecture(readme_text: str) -> None:
    lowered = readme_text.lower()
    assert "architecture" in lowered, (
        "README must have an Architecture section (PRD AC)"
    )
    # The PRD lives at tasks/prd-fraud-investigator-plugin.md; the README
    # must point to it for the canonical diagram.
    assert "tasks/prd-fraud-investigator-plugin.md" in readme_text, (
        "README must cross-link to the PRD where the canonical architecture "
        "diagram lives (PRD §5)"
    )


def test_readme_architecture_diagram_present(readme_text: str) -> None:
    # An ASCII architecture diagram is acceptable; the standard one mentions
    # the load-bearing hops. The hero diagram must name every major hop.
    lowered = readme_text.lower()
    for hop in (
        "cowork plugin",
        "auth gateway",
        "mcp gateway",
        "mcp server",
        "mock api",
    ):
        assert hop in lowered, (
            f"architecture diagram must name '{hop}' (PRD §5 hop list)"
        )


# --------------------------------------------------------------------------- #
# AC: README quickstart commands                                              #
# --------------------------------------------------------------------------- #


REQUIRED_QUICKSTART_COMMANDS: tuple[str, ...] = (
    "make install",
    "make compose-up",
    "make load-fixtures",
)


@pytest.mark.parametrize("command", REQUIRED_QUICKSTART_COMMANDS)
def test_readme_quickstart_lists_command(readme_text: str, command: str) -> None:
    assert command in readme_text, (
        f"README quickstart must list '{command}' verbatim (PRD AC)"
    )


def test_readme_has_quickstart_section(readme_text: str) -> None:
    lowered = readme_text.lower()
    assert "## quickstart" in lowered, (
        "README must carry a 'Quickstart' section (PRD AC)"
    )


# --------------------------------------------------------------------------- #
# AC: 'What's included' table mirroring PRD §6                                #
# --------------------------------------------------------------------------- #


def test_readme_has_whats_included_section(readme_text: str) -> None:
    lowered = readme_text.lower()
    assert "## what's included" in lowered or "## whats included" in lowered, (
        "README must include a 'What's included' section mirroring PRD §6"
    )


WHATS_INCLUDED_ROWS: tuple[str, ...] = (
    "auth gateway",
    "mcp gateway",
    "mcp server",
    "mock api",
    "cowork",
    "eval",
    "grafana",
    "docs",
)


@pytest.mark.parametrize("row_topic", WHATS_INCLUDED_ROWS)
def test_whats_included_table_covers_topic(
    readme_text: str, row_topic: str
) -> None:
    lowered = readme_text.lower()
    # The 'What's included' table must reference every PRD §6 layer.
    assert row_topic in lowered, (
        f"'What's included' table must reference '{row_topic}' (PRD §6 layer)"
    )


def test_whats_included_table_is_a_markdown_table(readme_text: str) -> None:
    # Find the 'What's included' section and assert it contains a markdown
    # table (header row with pipes + separator with dashes).
    pattern = re.compile(
        r"## what's included(.*?)(?:\n## |\Z)",
        re.IGNORECASE | re.DOTALL,
    )
    match = pattern.search(readme_text)
    assert match, "expected a 'What's included' section"
    body = match.group(1)
    assert "|" in body, "'What's included' section must contain a markdown table"
    assert re.search(r"\|\s*-+\s*\|", body), (
        "'What's included' section must contain a table separator row"
    )


# --------------------------------------------------------------------------- #
# AC: Demo GIF or video link embedded                                          #
# --------------------------------------------------------------------------- #


def test_readme_embeds_demo_asset(readme_text: str) -> None:
    # Markdown image embed targeting docs/assets/.
    pattern = re.compile(r"!\[[^\]]*\]\(docs/assets/[^)]+\)")
    assert pattern.search(readme_text), (
        "README must embed a demo GIF/video from docs/assets/ (PRD AC)"
    )


def test_demo_assets_directory_exists() -> None:
    assets_dir = REPO_ROOT / "docs" / "assets"
    assert assets_dir.is_dir(), (
        "docs/assets/ must exist as the home for the demo asset"
    )


# --------------------------------------------------------------------------- #
# Cross-link sanity: every doc/* link in the README resolves on disk           #
# --------------------------------------------------------------------------- #


def test_readme_doc_links_resolve(readme_text: str) -> None:
    # Walk every relative markdown link the README declares and assert the
    # target exists. We constrain the regex to in-repo paths so we do not
    # try to resolve `http://localhost:9000/...` smoke-test URLs.
    pattern = re.compile(r"\]\((?!https?:|#)([^)]+)\)")
    for match in pattern.finditer(readme_text):
        raw = match.group(1).split("#", 1)[0]  # strip in-page anchor
        if not raw:
            continue
        target = (REPO_ROOT / raw).resolve()
        # docs/assets/demo.gif is intentionally not committed — see
        # docs/assets/README.md. Skip just that one path.
        if target.name == "demo.gif":
            continue
        # The LICENSE file is referenced as TBD and may not exist yet.
        if target.name == "LICENSE" and not target.exists():
            continue
        assert target.exists(), f"Broken README link: {raw} -> {target}"


# --------------------------------------------------------------------------- #
# AC: docs/launch-post.md drafts the launch blog post                          #
# --------------------------------------------------------------------------- #


def test_launch_post_exists() -> None:
    assert LAUNCH_POST_PATH.is_file()


def test_launch_post_has_title(launch_post_text: str) -> None:
    first_line = launch_post_text.splitlines()[0].strip()
    assert first_line.startswith("# "), (
        "launch post must start with an h1 title line"
    )
    lowered = first_line.lower()
    assert "fraud" in lowered or "copilot" in lowered, (
        "launch post title should name the project"
    )


LAUNCH_POST_REQUIRED_SECTIONS: tuple[str, ...] = (
    "tl;dr",
    "why we built this",
    "what's in the box",
    "how to contribute",
    "change log",
)


@pytest.mark.parametrize("section_marker", LAUNCH_POST_REQUIRED_SECTIONS)
def test_launch_post_has_required_section(
    launch_post_text: str, section_marker: str
) -> None:
    lowered = launch_post_text.lower()
    assert section_marker in lowered, (
        f"launch post must carry a '{section_marker}' section"
    )


LAUNCH_POST_REQUIRED_TOPICS: tuple[str, ...] = (
    "paseto",
    "rbac",
    "audit",
    "mcp",
    "cowork",
    "grafana",
    "human_approval",
)


@pytest.mark.parametrize("topic", LAUNCH_POST_REQUIRED_TOPICS)
def test_launch_post_covers_required_topic(
    launch_post_text: str, topic: str
) -> None:
    lowered = launch_post_text.lower()
    assert topic in lowered, (
        f"launch post must reference '{topic}' (load-bearing project concept)"
    )


def test_launch_post_references_us_034(launch_post_text: str) -> None:
    assert "US-034" in launch_post_text, (
        "launch post is the US-034 artifact and should self-identify"
    )


def test_launch_post_cross_links_resolve(launch_post_text: str) -> None:
    pattern = re.compile(r"\]\((?!https?:|#)([^)]+)\)")
    base = LAUNCH_POST_PATH.parent
    for match in pattern.finditer(launch_post_text):
        raw = match.group(1).split("#", 1)[0]
        if not raw:
            continue
        target = (base / raw).resolve()
        if target.name == "demo.gif":
            continue
        assert target.exists(), f"Broken launch post link: {raw} -> {target}"


def test_launch_post_links_to_threat_model(launch_post_text: str) -> None:
    # The threat model is the security reviewer's entry point and must be
    # cross-linked from the launch post.
    assert "threat-model.md" in launch_post_text, (
        "launch post must link to docs/threat-model.md"
    )


def test_launch_post_links_to_adrs(launch_post_text: str) -> None:
    # ADR links anchor the design decisions; the post should reference at
    # least one specific ADR by file path.
    assert re.search(r"adr/\d{4}-[a-z0-9-]+\.md", launch_post_text), (
        "launch post must reference at least one specific ADR by path"
    )


# --------------------------------------------------------------------------- #
# AC: Markdown linter passes                                                  #
# --------------------------------------------------------------------------- #


def test_readme_has_no_unclosed_code_fences(readme_text: str) -> None:
    # Light-weight markdown sanity: every ``` opens must close.
    assert readme_text.count("```") % 2 == 0, (
        "README has an unclosed code fence — would break markdown rendering"
    )


def test_launch_post_has_no_unclosed_code_fences(launch_post_text: str) -> None:
    assert launch_post_text.count("```") % 2 == 0, (
        "launch post has an unclosed code fence — would break markdown rendering"
    )
