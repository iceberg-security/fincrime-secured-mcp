"""Headless harness for driving the fraud-investigator plugin (US-029).

The harness reads the orchestrator SKILL.md as a system prompt, binds the
MCP-server tools as agent tool definitions, and runs an agent loop that
issues tool calls through the MCP gateway. The resulting audit-log slice
+ the final report feed the US-027 / US-028 scorers without coupling the
eval gate to the Cowork product surface.

See :doc:`docs/adr/0001-headless-cowork-harness.md` for the decision and
``docs/agent-testing.md`` for a worked example.
"""

from evals.harness.agent import (
    DEFAULT_FINAL_ANSWER_TOOL,
    Agent,
    AgentStep,
    AnthropicAgent,
    FinalAnswer,
    StubAgent,
    ToolCall,
    derive_tool_definitions,
)
from evals.harness.runner import (
    DEFAULT_MAX_STEPS,
    HarnessResult,
    PasetoFactory,
    ToolInvocation,
    run_dataset,
)

__all__ = [
    "Agent",
    "AgentStep",
    "AnthropicAgent",
    "DEFAULT_FINAL_ANSWER_TOOL",
    "DEFAULT_MAX_STEPS",
    "FinalAnswer",
    "HarnessResult",
    "PasetoFactory",
    "StubAgent",
    "ToolCall",
    "ToolInvocation",
    "derive_tool_definitions",
    "run_dataset",
]
