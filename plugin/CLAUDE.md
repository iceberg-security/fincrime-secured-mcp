# plugin/

Claude Cowork plugin: orchestrator skill + subskills + (later) verifier
meta-skill. Skill files are **repo-resident** and audited by commit hash —
they are never model-generated. `plugin.json` is the registration manifest.

## Files

| File                              | Purpose                                                                                       |
| --------------------------------- | --------------------------------------------------------------------------------------------- |
| `plugin.json`                     | Cowork registration manifest (name, version, skills, MCP servers, tools).                     |
| `skills/orchestrator/SKILL.md`    | Top-level router. ≤100 lines. Delegates to subskills only — never calls MCP tools directly.   |
| `skills/<name>/SKILL.md`          | One subskill per directory. ≤200 lines. Declares its MCP servers/tools in the top comment.    |
| `loader.py`                       | Stdlib-only parser for `plugin.json` + every SKILL.md. Source of truth for validation.        |
| `register.py`                     | `python -m plugin.register` entry point used by `make register-plugin`.                       |

## SKILL.md contract (PRD §6, FR-34..FR-38)

1. Every SKILL.md MUST contain all six XML sections in order:
   `<goal>`, `<inputs>`, `<tools>`, `<steps>`, `<output_format>`,
   `<constraints>`.
2. Every SKILL.md MUST declare its MCP-server dependencies in an HTML
   comment at the top:

   ```html
   <!--
   mcp_servers:
     <server_name>:
       tools: [tool_a, tool_b]
   -->
   ```

   The bullet-list shape is equally valid:

   ```yaml
   mcp_servers:
     <server_name>:
       tools:
         - tool_a
         - tool_b
   ```

   Both are parsed by `loader._parse_declared_servers`. The orchestrator's
   block declares the union of every server/tool the routed subskills can
   reach — this is the static dependency surface.
3. Line caps: orchestrator ≤100 lines, subskills ≤200 lines. Enforced by
   `loader._enforce_skill_invariants` AND by
   `tests/test_plugin_bundle.py`.
4. The orchestrator MUST NOT call MCP tools directly. It only invokes
   subskills. The line cap is the disciplinary mechanism.
5. Every tool a SKILL.md names MUST be declared in `plugin.json`'s
   `mcpServers[].tools`. Cross-checked by `loader.validate_plugin`.

## `make register-plugin`

Validates the bundle and (if `cowork` is on PATH) hands off to the CLI for
the actual install. Without the CLI, the script still writes a
registration manifest to `${XDG_STATE_HOME:-~/.local/state}/fraud-copilot-oss/`
that an operator can drop into a Cowork install manually. Set
`COWORK_BIN=/path/to/cowork` to override.

The validation step is the gold: if a SKILL.md drifts from `plugin.json`,
or a SKILL.md is missing a required XML section, `make register-plugin`
fails BEFORE any install happens. The same invariants are checked by the
CI test in `tests/test_plugin_bundle.py`, so contributors see the same
failure locally and in CI.

## Adding a new subskill

1. Create `skills/<name>/SKILL.md` following the XML skeleton.
2. Add the tools it needs to `plugin.json` under the right MCP server
   entry. If the server isn't already there, add it (and update
   `config/rbac.yaml` so the role can reach it).
3. Add a `{ id: "<name>", path: "skills/<name>/SKILL.md", kind: "subskill" }`
   entry to `plugin.json`'s `skills` array.
4. If the subskill is invoked by the orchestrator, list it in
   `skills/orchestrator/SKILL.md`'s `<steps>` routing table.
5. **Extend the orchestrator's `mcp_servers:` dependency comment** to
   include any new server/tools the subskill reaches. The orchestrator's
   declared surface MUST equal the union of every subskill's surface —
   `test_orchestrator_dependency_block_matches_subskill_union` is the
   drift detector. Easiest step to forget.
6. Run `make register-plugin --dry-run` (or `pytest tests/test_plugin_bundle.py`)
   to confirm the bundle still validates.

## Why `plugin/` is excluded from `pyproject.toml`'s `packages.find`

`plugin/` ships SKILL.md content, not library code that should land in a
wheel. We keep `loader.py` + `register.py` inside the directory so they
live next to the manifest they validate, and they're invoked via
`python -m plugin.register` (which adds the repo root to `sys.path`)
rather than as an installed entry point. If we ever ship a wheel of the
runtime gateways, the plugin should still be packaged as a separate
artifact (e.g. a tarball of the directory).
