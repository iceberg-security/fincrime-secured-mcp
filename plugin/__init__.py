"""Claude Cowork plugin for the fraud-investigator copilot.

Skill files (SKILL.md) are repo-resident and signed by commit hash in the
audit log; they are NOT model-generated. `plugin.json` is the registration
manifest consumed by Cowork. The `register` submodule validates the bundle
and is the entry point for `make register-plugin`.
"""

from plugin.loader import (
    PluginManifest,
    PluginValidationError,
    SkillEntry,
    SkillFrontmatter,
    load_manifest,
    parse_skill,
    validate_plugin,
)

__all__ = [
    "PluginManifest",
    "PluginValidationError",
    "SkillEntry",
    "SkillFrontmatter",
    "load_manifest",
    "parse_skill",
    "validate_plugin",
]
