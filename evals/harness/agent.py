"""Agent abstraction for the headless harness (US-029).

The harness drives an :class:`Agent` through a tool-use loop. Production
runs use the Anthropic-backed :class:`AnthropicAgent`; tests inject a
deterministic :class:`StubAgent` that returns a scripted sequence of
steps. Both satisfy the :class:`Agent` Protocol so the runner code is
identical.

The Protocol shape mirrors the :class:`evals.scorers.judge.Judge`
Protocol introduced in US-028: one pattern, two seams (judging /
agent-driving).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from evals.datasets.schema import ALLOWED_TOOLS

if TYPE_CHECKING:  # pragma: no cover - optional SDK import
    from anthropic import Anthropic

__all__ = [
    "Agent",
    "AgentStep",
    "AnthropicAgent",
    "DEFAULT_FINAL_ANSWER_TOOL",
    "FinalAnswer",
    "StubAgent",
    "ToolCall",
    "derive_tool_definitions",
]

#: Synthetic tool the agent calls to terminate the loop with a final report.
#: Not exposed to the MCP gateway — the harness intercepts it in the runner.
DEFAULT_FINAL_ANSWER_TOOL = "final_answer"

# Mirror of evals.scorers.judge.DEFAULT_MODEL so the harness defaults to
# the same Opus 4.7 variant the LLM-judge scorers use. US-033 ADR.
DEFAULT_MODEL = "claude-opus-4-7"


# --------------------------------------------------------------------------- #
# AgentStep variants
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ToolCall:
    """The agent wants to invoke an MCP tool.

    ``id`` is the call id (the Anthropic tool-use ``id``); the harness
    echoes it back in the corresponding ``tool_result`` block so the
    agent can correlate the response.
    """

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True, slots=True)
class FinalAnswer:
    """The agent has finished and is returning the report."""

    report: dict[str, Any]


# Union shape so the runner can pattern-match without isinstance ladders
# at the call site. Python 3.11+ supports ``match`` on dataclass shapes
# directly.
AgentStep = ToolCall | FinalAnswer


# --------------------------------------------------------------------------- #
# Agent Protocol
# --------------------------------------------------------------------------- #


@runtime_checkable
class Agent(Protocol):
    """Anything callable with the per-step harness signature.

    Each call corresponds to one round of the agent loop: the harness
    passes the orchestrator skill (the system prompt), the input alert,
    the available tool definitions, and the history of tool results
    observed so far. The agent returns either a :class:`ToolCall` or a
    :class:`FinalAnswer`.

    Stateless by contract — implementations MUST treat each invocation
    as a fresh round and re-derive their state from ``tool_results``.
    Stateful implementations (the Anthropic-backed agent's prompt
    caching, for example) hold their state on the instance, not on the
    Protocol.
    """

    def __call__(
        self,
        *,
        skill_md: str,
        alert: Mapping[str, Any],
        tools: Sequence[Mapping[str, Any]],
        tool_results: Sequence[Mapping[str, Any]],
    ) -> AgentStep: ...


# --------------------------------------------------------------------------- #
# Helpers: derive tool definitions from a dataset
# --------------------------------------------------------------------------- #


def derive_tool_definitions(
    expected_tool_calls: Sequence[Mapping[str, str]],
    *,
    include_final_answer: bool = True,
) -> list[dict[str, Any]]:
    """Build agent tool definitions for the harness.

    The shape mirrors Anthropic's tool-use schema
    (``name`` / ``description`` / ``input_schema``) and is what the
    :class:`AnthropicAgent` forwards verbatim to the API. The
    :class:`StubAgent` ignores the definitions but the runner asserts
    every emitted :class:`ToolCall` references one of them.

    The agent is given ONE tool per ``(server, tool)`` pair in
    ``expected_tool_calls`` — exactly the surface the dataset author
    sanctioned. The runner's safety net (not the agent's prompt) is
    what keeps the agent from issuing calls outside this surface.

    ``include_final_answer`` (default True) appends the synthetic
    :data:`DEFAULT_FINAL_ANSWER_TOOL` definition so the agent can
    signal completion.
    """
    seen: set[tuple[str, str]] = set()
    definitions: list[dict[str, Any]] = []
    for entry in expected_tool_calls:
        server = entry.get("server")
        tool = entry.get("tool")
        if not isinstance(server, str) or not isinstance(tool, str):
            continue
        if server not in ALLOWED_TOOLS or tool not in ALLOWED_TOOLS[server]:
            continue
        pair = (server, tool)
        if pair in seen:
            continue
        seen.add(pair)
        definitions.append(
            {
                "name": f"{server}__{tool}",
                "description": (
                    f"Call the {server} MCP server's {tool} tool through "
                    f"the gateway. Arguments are forwarded verbatim as the "
                    f"JSON-RPC tools/call arguments."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "arguments": {
                            "type": "object",
                            "description": (
                                "Arguments object the MCP tool will receive."
                            ),
                            "additionalProperties": True,
                        }
                    },
                    "required": ["arguments"],
                    "additionalProperties": False,
                },
                # Sidecar metadata the runner uses to route the call to
                # the right MCP server. Not part of the Anthropic schema,
                # but Anthropic's API ignores unknown top-level keys on
                # tool definitions, so this is safe to ship as-is.
                "_meta": {"server": server, "tool": tool},
            }
        )
    if include_final_answer:
        definitions.append(
            {
                "name": DEFAULT_FINAL_ANSWER_TOOL,
                "description": (
                    "Emit the final draft-narrative report and terminate "
                    "the investigation. Call this exactly once, when all "
                    "evidence has been gathered."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "report": {
                            "type": "object",
                            "description": (
                                "Draft-narrative output. MUST match the "
                                "shape declared in plugin/skills/"
                                "draft-narrative/SKILL.md."
                            ),
                            "additionalProperties": True,
                        }
                    },
                    "required": ["report"],
                    "additionalProperties": False,
                },
                "_meta": {"final_answer": True},
            }
        )
    return definitions


def _strip_meta(tools: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Drop the harness-internal ``_meta`` sidecar before handing the
    tool list to the Anthropic SDK."""
    out: list[dict[str, Any]] = []
    for entry in tools:
        clean = {k: v for k, v in entry.items() if not k.startswith("_")}
        out.append(clean)
    return out


# --------------------------------------------------------------------------- #
# StubAgent — deterministic test fake
# --------------------------------------------------------------------------- #


@dataclass
class StubAgent:
    """Deterministic agent that returns a scripted sequence of steps.

    Used by ``tests/test_harness.py`` to drive the runner without
    hitting the network. The instance is single-use: each call pops the
    next scripted step. Calling past the end raises ``IndexError`` so
    test bugs surface loudly.
    """

    steps: list[AgentStep] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)

    def __call__(
        self,
        *,
        skill_md: str,
        alert: Mapping[str, Any],
        tools: Sequence[Mapping[str, Any]],
        tool_results: Sequence[Mapping[str, Any]],
    ) -> AgentStep:
        # Record what we were called with so tests can pin the runner
        # passes through the right surface area each step.
        self.calls.append(
            {
                "skill_md_len": len(skill_md),
                "alert": dict(alert),
                "tool_names": [t.get("name") for t in tools],
                "tool_results_count": len(tool_results),
            }
        )
        if not self.steps:
            raise IndexError(
                "StubAgent invoked past the end of its scripted steps"
            )
        return self.steps.pop(0)


# --------------------------------------------------------------------------- #
# AnthropicAgent — production implementation
# --------------------------------------------------------------------------- #


class AnthropicAgent:
    """Anthropic Messages API-backed :class:`Agent` implementation.

    Each ``__call__`` issues one Messages request with the full message
    history reconstructed from ``tool_results``. The orchestrator's
    SKILL.md is pinned in the ``system`` channel with
    ``cache_control={"type": "ephemeral"}`` so the static rubric is
    cached for the 5-minute Anthropic TTL — every step in one dataset
    run hits the cache. This mirrors the :class:`AnthropicJudge`
    pattern from US-028.

    The SDK import is lazy at constructor time so the harness module
    keeps importing on machines without ``anthropic`` installed (tests
    inject :class:`StubAgent`).
    """

    def __init__(
        self,
        *,
        client: Anthropic | None = None,
        model: str = DEFAULT_MODEL,
        max_tokens: int = 4096,
    ) -> None:
        if client is None:
            try:
                from anthropic import Anthropic as _Anthropic
            except ImportError as exc:  # pragma: no cover - import-time
                raise RuntimeError(
                    "anthropic SDK not installed; add `anthropic` to your "
                    "deps or inject a StubAgent / your own Agent fake."
                ) from exc
            client = _Anthropic()
        self._client = client
        self._model = model
        self._max_tokens = max_tokens

    def __call__(
        self,
        *,
        skill_md: str,
        alert: Mapping[str, Any],
        tools: Sequence[Mapping[str, Any]],
        tool_results: Sequence[Mapping[str, Any]],
    ) -> AgentStep:
        messages = self._reconstruct_messages(alert=alert, tool_results=tool_results)
        response = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=[
                {
                    "type": "text",
                    "text": skill_md,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            tools=_strip_meta(tools),
            messages=messages,
        )
        return _parse_response(response)

    @staticmethod
    def _reconstruct_messages(
        *,
        alert: Mapping[str, Any],
        tool_results: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        """Rebuild the Anthropic message list from the harness state.

        The harness keeps an authoritative ``tool_results`` list keyed by
        the tool-use id. We replay it as alternating assistant
        (``tool_use``) / user (``tool_result``) message pairs so the
        Anthropic API sees a well-formed history regardless of how many
        steps have run.
        """
        # Opening user turn carries the alert payload + a short cue.
        messages: list[dict[str, Any]] = [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Investigate this fraud alert per the orchestrator "
                            "skill. Use the available tools to gather evidence, "
                            "then call the final_answer tool with the report.\n\n"
                            f"Alert:\n{json.dumps(dict(alert), indent=2)}"
                        ),
                    }
                ],
            }
        ]
        for entry in tool_results:
            tool_use_id = entry.get("tool_use_id")
            tool_name = entry.get("tool_name")
            arguments = entry.get("arguments", {})
            result = entry.get("result")
            messages.append(
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": tool_use_id,
                            "name": tool_name,
                            "input": {"arguments": arguments},
                        }
                    ],
                }
            )
            messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": json.dumps(result, default=str),
                            "is_error": bool(entry.get("is_error", False)),
                        }
                    ],
                }
            )
        return messages


def _parse_response(response: Any) -> AgentStep:
    """Parse one Anthropic Messages response into an :class:`AgentStep`.

    The response always carries a ``content`` list; we prefer the first
    ``tool_use`` block. If none is present, we treat the response as a
    final answer with the raw text in ``report.text`` so the harness
    can still terminate gracefully on agents that emit prose instead
    of the expected tool call.
    """
    content = getattr(response, "content", []) or []
    for block in content:
        block_type = getattr(block, "type", None)
        if block_type == "tool_use":
            name = getattr(block, "name", "") or ""
            block_id = getattr(block, "id", "") or ""
            raw_input = getattr(block, "input", {}) or {}
            if not isinstance(raw_input, Mapping):
                raw_input = {}
            arguments = raw_input.get("arguments", {})
            if not isinstance(arguments, Mapping):
                arguments = {}
            if name == DEFAULT_FINAL_ANSWER_TOOL:
                report = raw_input.get("report", {})
                if not isinstance(report, Mapping):
                    report = {"raw": report}
                return FinalAnswer(report=dict(report))
            return ToolCall(
                id=str(block_id),
                name=str(name),
                arguments=dict(arguments),
            )
    text_parts: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            text_parts.append(text)
    return FinalAnswer(report={"text": "".join(text_parts)})
