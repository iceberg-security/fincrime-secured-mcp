"""Eval-dataset schema + loader (US-025).

Declarative case files live under ``evals/datasets/*.yaml``. Each file
describes a fraud-investigation scenario the harness will run against
the live mock stack; the scorers in US-027/US-028 key off the same
fields this schema pins.

Schema (Pydantic v2):

    id:                  short kebab-case identifier (filename stem).
    description:         one-paragraph human summary.
    scenario:            one of the six personas baked into the mocks
                         (clean | mule | sanctions_hit | ato |
                         structuring | synthetic_id).
    input_alert:         the alert payload the orchestrator receives.
    expected_tool_calls: set of {server, tool} pairs the agent MUST
                         invoke (extras count as 'extra' in the
                         tool-correctness scorer; misses count as
                         'missing').
    ordering_constraints: list of {before, after} pairs naming tools
                         that MUST appear in that order in the audit
                         log (e.g. screen-sanctions before
                         create-sar-draft).
    expected_verdict:    one of the four draft-narrative verdicts.
    required_facts:      list of {claim, supporting_tool} pairs. The
                         grounding scorer (US-028) treats every claim
                         in the agent's report as ungrounded unless
                         its supporting tool produced an audit row.

The schema is intentionally **declarative-only** — a dataset is a
config file, not Python. Validation is via :func:`load_dataset` /
:func:`validate_dataset_file`. Both raise :class:`EvalSchemaError`
with a precise error message on the first failure.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

# --------------------------------------------------------------------------- #
# Canonical enums — kept in sync with mock_apis.<*>.main.Scenario and
# plugin/skills/draft-narrative/SKILL.md.
# --------------------------------------------------------------------------- #

Scenario = Literal[
    "clean",
    "mule",
    "sanctions_hit",
    "ato",
    "structuring",
    "synthetic_id",
]

Verdict = Literal[
    "high_risk",
    "elevated_risk",
    "low_risk",
    "insufficient_evidence",
]

# The (server, tool) pairs the agent is allowed to call. Anything outside
# this set in `expected_tool_calls` is a typo; the schema rejects it.
ALLOWED_TOOLS: dict[str, frozenset[str]] = {
    "customer_data": frozenset(
        {"get_customer", "list_accounts", "get_device_history"}
    ),
    "transactions": frozenset(
        {"get_transactions", "get_counterparties", "flag_velocity_anomalies"}
    ),
    "kyc": frozenset({"get_kyc_record", "get_document", "get_ubo_tree"}),
    "sanctions": frozenset(
        {"screen_name", "screen_entity", "get_watchlist_hit"}
    ),
    "osint": frozenset({"web_search", "fetch_page", "lookup_company"}),
    "case_actions": frozenset(
        {"create_sar_draft", "freeze_account", "escalate_to_l3"}
    ),
}


class EvalSchemaError(ValueError):
    """Raised when a dataset YAML fails to validate."""


# --------------------------------------------------------------------------- #
# Pydantic models
# --------------------------------------------------------------------------- #


class ToolCall(BaseModel):
    """A (server, tool) reference. Used in expected_tool_calls + as the
    `before`/`after` payload in ordering_constraints + as the
    `supporting_tool` of a required fact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    server: str = Field(..., min_length=1)
    tool: str = Field(..., min_length=1)

    @model_validator(mode="after")
    def _check_tool_is_allowed(self) -> ToolCall:
        allowed = ALLOWED_TOOLS.get(self.server)
        if allowed is None:
            raise ValueError(
                f"unknown MCP server: {self.server!r}; "
                f"valid: {sorted(ALLOWED_TOOLS.keys())}"
            )
        if self.tool not in allowed:
            raise ValueError(
                f"unknown tool {self.tool!r} on server {self.server!r}; "
                f"valid: {sorted(allowed)}"
            )
        return self

    def as_pair(self) -> tuple[str, str]:
        return (self.server, self.tool)


class OrderingConstraint(BaseModel):
    """`before` MUST appear in the audit log earlier than `after`. Both
    sides reference (server, tool) pairs the scorer can spot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    before: ToolCall
    after: ToolCall

    @model_validator(mode="after")
    def _reject_trivial(self) -> OrderingConstraint:
        if self.before == self.after:
            raise ValueError(
                f"ordering_constraints[before] and [after] must differ; "
                f"got both = {self.before.as_pair()}"
            )
        return self


class RequiredFact(BaseModel):
    """A factual claim the agent's report MUST surface, plus the tool
    call that should ground it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claim: str = Field(..., min_length=1)
    supporting_tool: ToolCall


class InputAlert(BaseModel):
    """The alert the orchestrator receives. Mirrors the
    plugin/skills/orchestrator/SKILL.md <inputs> shape."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(..., min_length=1)
    customer_id: str = Field(..., min_length=1)
    alert_type: str = Field(..., min_length=1)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    opened_at: str | None = None
    notes: str | None = None


class EvalDataset(BaseModel):
    """One declarative eval case."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., pattern=r"^[a-z][a-z0-9_]*$")
    description: str = Field(..., min_length=1)
    scenario: Scenario
    input_alert: InputAlert
    expected_tool_calls: list[ToolCall] = Field(..., min_length=1)
    ordering_constraints: list[OrderingConstraint] = Field(default_factory=list)
    expected_verdict: Verdict
    required_facts: list[RequiredFact] = Field(..., min_length=1)

    @model_validator(mode="after")
    def _cross_field_checks(self) -> EvalDataset:
        expected_pairs = {tc.as_pair() for tc in self.expected_tool_calls}
        if len(expected_pairs) != len(self.expected_tool_calls):
            raise ValueError(
                "expected_tool_calls contains duplicate (server, tool) pairs"
            )

        for idx, oc in enumerate(self.ordering_constraints):
            if oc.before.as_pair() not in expected_pairs:
                raise ValueError(
                    f"ordering_constraints[{idx}].before "
                    f"{oc.before.as_pair()} is not in expected_tool_calls"
                )
            if oc.after.as_pair() not in expected_pairs:
                raise ValueError(
                    f"ordering_constraints[{idx}].after "
                    f"{oc.after.as_pair()} is not in expected_tool_calls"
                )

        for idx, fact in enumerate(self.required_facts):
            if fact.supporting_tool.as_pair() not in expected_pairs:
                raise ValueError(
                    f"required_facts[{idx}].supporting_tool "
                    f"{fact.supporting_tool.as_pair()} is not in "
                    f"expected_tool_calls"
                )
        return self


# --------------------------------------------------------------------------- #
# Loader / validator
# --------------------------------------------------------------------------- #


def load_dataset(raw: dict[str, Any]) -> EvalDataset:
    """Validate ``raw`` (an already-parsed YAML dict) against the schema."""
    try:
        return EvalDataset.model_validate(raw)
    except ValidationError as exc:
        raise EvalSchemaError(str(exc)) from exc


def validate_dataset_file(path: str | Path) -> EvalDataset:
    """Parse ``path`` as YAML and validate it. Raises
    :class:`EvalSchemaError` with a leading path hint on failure."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise EvalSchemaError(f"{p}: cannot read ({exc})") from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise EvalSchemaError(f"{p}: invalid YAML ({exc})") from exc
    if not isinstance(raw, dict):
        raise EvalSchemaError(
            f"{p}: top-level YAML node must be a mapping, got {type(raw).__name__}"
        )
    try:
        return load_dataset(raw)
    except EvalSchemaError as exc:
        raise EvalSchemaError(f"{p}: {exc}") from exc


def validate_dataset_dir(root: str | Path) -> list[EvalDataset]:
    """Validate every ``*.yaml`` under ``root``. Returns the parsed
    datasets in filename order. Raises on the first failure with the
    offending path mentioned."""
    root_path = Path(root)
    if not root_path.is_dir():
        raise EvalSchemaError(f"{root_path}: not a directory")
    yaml_files = sorted(root_path.glob("*.yaml"))
    if not yaml_files:
        raise EvalSchemaError(f"{root_path}: no *.yaml files found")
    return [validate_dataset_file(p) for p in yaml_files]


__all__ = [
    "ALLOWED_TOOLS",
    "EvalDataset",
    "EvalSchemaError",
    "InputAlert",
    "OrderingConstraint",
    "RequiredFact",
    "Scenario",
    "ToolCall",
    "Verdict",
    "load_dataset",
    "validate_dataset_dir",
    "validate_dataset_file",
]
