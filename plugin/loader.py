"""Plugin manifest + SKILL.md loader for the fraud-investigator Cowork plugin.

Responsibilities:
  - Parse `plugin/plugin.json` into typed dataclasses.
  - Parse each SKILL.md: extract the declared MCP servers/tools block AND
    the XML-structured sections (<goal>, <inputs>, <tools>, <steps>,
    <output_format>, <constraints>).
  - Enforce per-PRD §6 invariants:
      * orchestrator SKILL.md <= 100 lines
      * every other SKILL.md <= 200 lines
      * every SKILL.md contains all six required XML sections
      * the tool surface declared in plugin.json matches the tools declared
        in the orchestrator's dependency block

This module is import-light and stdlib-only so `make register-plugin` works
in a fresh venv before any third-party deps are pulled.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- #
# Constants                                                                   #
# --------------------------------------------------------------------------- #

# PRD §6 limits.
ORCHESTRATOR_MAX_LINES = 100
SUBSKILL_MAX_LINES = 200

# Every SKILL.md MUST contain these XML sections (PRD §6 / FR-34).
REQUIRED_SKILL_SECTIONS: tuple[str, ...] = (
    "goal",
    "inputs",
    "tools",
    "steps",
    "output_format",
    "constraints",
)


class PluginValidationError(ValueError):
    """Raised when the plugin bundle violates a structural invariant."""


# --------------------------------------------------------------------------- #
# Dataclasses                                                                 #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SkillEntry:
    """One skill entry from plugin.json's `skills` array."""

    id: str
    path: str
    kind: str  # "orchestrator" | "subskill" | "meta"


@dataclass(frozen=True)
class MCPServerSpec:
    """One downstream MCP server declared in plugin.json."""

    name: str
    transport: str
    url_env: str
    tools: tuple[str, ...]


@dataclass(frozen=True)
class PluginManifest:
    """Typed view of plugin.json."""

    name: str
    version: str
    description: str
    entry_point: str
    skills: tuple[SkillEntry, ...]
    mcp_servers: tuple[MCPServerSpec, ...]
    raw: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class SkillFrontmatter:
    """Parsed SKILL.md content. Stays stdlib-only so it's cheap to load."""

    path: Path
    title: str
    line_count: int
    declared_servers: dict[str, tuple[str, ...]]  # server -> tools
    sections: dict[str, str]  # XML tag name -> inner text (stripped)


# --------------------------------------------------------------------------- #
# plugin.json                                                                 #
# --------------------------------------------------------------------------- #


def load_manifest(plugin_dir: Path) -> PluginManifest:
    """Read plugin.json from `plugin_dir` and return a typed manifest."""
    manifest_path = plugin_dir / "plugin.json"
    if not manifest_path.is_file():
        raise PluginValidationError(f"plugin.json not found at {manifest_path}")
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    try:
        skills = tuple(
            SkillEntry(id=s["id"], path=s["path"], kind=s["kind"])
            for s in raw["skills"]
        )
        mcp_servers = tuple(
            MCPServerSpec(
                name=s["name"],
                transport=s["transport"],
                url_env=s["urlEnv"],
                tools=tuple(s["tools"]),
            )
            for s in raw.get("mcpServers", [])
        )
        return PluginManifest(
            name=raw["name"],
            version=raw["version"],
            description=raw["description"],
            entry_point=raw["entryPoint"],
            skills=skills,
            mcp_servers=mcp_servers,
            raw=raw,
        )
    except KeyError as e:
        raise PluginValidationError(f"plugin.json missing required key: {e}") from e


# --------------------------------------------------------------------------- #
# SKILL.md parsing                                                            #
# --------------------------------------------------------------------------- #

# <goal>…</goal> etc. Cross-line, DOTALL.
_SECTION_RE = re.compile(r"<(?P<tag>[a-z_]+)>(?P<body>.*?)</(?P=tag)>", re.DOTALL)

# The MCP-server declaration block lives inside an HTML comment at the top of
# every SKILL.md. We accept loose YAML-ish indentation; the parser is
# intentionally narrow — keep the format stable.
_DEPS_BLOCK_RE = re.compile(
    r"mcp_servers:\s*\n(?P<body>(?:[ \t]+[^\n]*\n)+)",
    re.MULTILINE,
)


def _parse_declared_servers(text: str) -> dict[str, tuple[str, ...]]:
    """Extract the mcp_servers/tools block from a SKILL.md header comment.

    Accepted shapes (both equivalent, both used in our skills):

        mcp_servers:
          customer_data:
            tools: [get_customer, list_accounts]

        mcp_servers:
          customer_data:
            tools:
              - get_customer
              - list_accounts

    Returns `{}` when no block is present (legal for skills that consume
    only prior subskill outputs, e.g. draft-narrative in US-020).
    """
    m = _DEPS_BLOCK_RE.search(text)
    if not m:
        return {}
    body = m.group("body")
    out: dict[str, list[str]] = {}
    current_server: str | None = None
    inline_tools_re = re.compile(r"tools:\s*\[(?P<inner>[^\]]*)\]")
    bullet_re = re.compile(r"-\s+(?P<tool>[A-Za-z_][A-Za-z0-9_]*)")
    server_re = re.compile(r"^[ \t]{2}(?P<name>[A-Za-z_][A-Za-z0-9_]*):\s*$")
    for line in body.splitlines():
        if not line.strip():
            continue
        sm = server_re.match(line)
        if sm:
            current_server = sm.group("name")
            out.setdefault(current_server, [])
            continue
        if current_server is None:
            continue
        im = inline_tools_re.search(line)
        if im:
            tools = [t.strip() for t in im.group("inner").split(",") if t.strip()]
            out[current_server].extend(tools)
            continue
        bm = bullet_re.search(line)
        if bm:
            out[current_server].append(bm.group("tool"))
    return {server: tuple(tools) for server, tools in out.items()}


def parse_skill(path: Path) -> SkillFrontmatter:
    """Load a SKILL.md and return parsed sections + declared dependencies."""
    if not path.is_file():
        raise PluginValidationError(f"SKILL.md not found: {path}")
    text = path.read_text(encoding="utf-8")
    sections = {
        m.group("tag"): m.group("body").strip()
        for m in _SECTION_RE.finditer(text)
    }
    # Title is the first `# Heading` line, falling back to the parent dir name.
    title = path.parent.name
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("# "):
            title = line[2:].strip()
            break
    return SkillFrontmatter(
        path=path,
        title=title,
        line_count=len(text.splitlines()),
        declared_servers=_parse_declared_servers(text),
        sections=sections,
    )


# --------------------------------------------------------------------------- #
# Validation                                                                  #
# --------------------------------------------------------------------------- #


def _enforce_skill_invariants(skill: SkillFrontmatter, *, is_orchestrator: bool) -> None:
    limit = ORCHESTRATOR_MAX_LINES if is_orchestrator else SUBSKILL_MAX_LINES
    if skill.line_count > limit:
        kind = "orchestrator" if is_orchestrator else "subskill"
        raise PluginValidationError(
            f"{skill.path}: {kind} SKILL.md is {skill.line_count} lines "
            f"(max {limit})"
        )
    missing = [tag for tag in REQUIRED_SKILL_SECTIONS if tag not in skill.sections]
    if missing:
        raise PluginValidationError(
            f"{skill.path}: SKILL.md missing required XML sections: "
            f"{', '.join(missing)}"
        )


def validate_plugin(plugin_dir: Path) -> tuple[PluginManifest, dict[str, SkillFrontmatter]]:
    """Validate the whole plugin bundle and return (manifest, parsed skills).

    Raises PluginValidationError on the first violation. Designed to be the
    single source of truth for `make register-plugin` AND the contract test
    in `tests/test_plugin_bundle.py`.
    """
    manifest = load_manifest(plugin_dir)

    skills: dict[str, SkillFrontmatter] = {}
    orchestrator_seen = False
    for entry in manifest.skills:
        skill_path = plugin_dir / entry.path
        skill = parse_skill(skill_path)
        is_orch = entry.kind == "orchestrator"
        if is_orch:
            if orchestrator_seen:
                raise PluginValidationError(
                    "more than one orchestrator declared in plugin.json"
                )
            orchestrator_seen = True
        _enforce_skill_invariants(skill, is_orchestrator=is_orch)
        skills[entry.id] = skill

    if not orchestrator_seen:
        raise PluginValidationError(
            "plugin.json declares no orchestrator skill (kind: 'orchestrator')"
        )

    # Cross-check: every MCP server declared at the manifest level must be
    # referenced by at least one skill's dependency block. Reverse direction
    # is also enforced: a skill that names an MCP server must be declared in
    # the manifest so RBAC/audit configuration stays in sync.
    manifest_servers = {s.name: set(s.tools) for s in manifest.mcp_servers}
    skill_servers: dict[str, set[str]] = {}
    for skill in skills.values():
        for server, tools in skill.declared_servers.items():
            skill_servers.setdefault(server, set()).update(tools)

    unused_manifest = set(manifest_servers) - set(skill_servers)
    if unused_manifest:
        raise PluginValidationError(
            f"MCP servers declared in plugin.json but unused by any skill: "
            f"{sorted(unused_manifest)}"
        )
    undeclared_in_manifest = set(skill_servers) - set(manifest_servers)
    if undeclared_in_manifest:
        raise PluginValidationError(
            f"MCP servers referenced by SKILL.md but missing from plugin.json: "
            f"{sorted(undeclared_in_manifest)}"
        )
    for server, used_tools in skill_servers.items():
        manifest_tools = manifest_servers[server]
        unknown = used_tools - manifest_tools
        if unknown:
            raise PluginValidationError(
                f"SKILL.md uses tools not declared in plugin.json for "
                f"server {server!r}: {sorted(unknown)}"
            )

    return manifest, skills
