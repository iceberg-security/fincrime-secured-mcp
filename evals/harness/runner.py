"""Runner: drive the orchestrator skill against the mock stack (US-029).

The runner takes one :class:`evals.datasets.schema.EvalDataset`, an
:class:`Agent`, an HTTP client pointed at the MCP gateway, and a minted
user PASETO. It loops the agent until either a :class:`FinalAnswer` is
returned or ``max_steps`` is exhausted. Each :class:`ToolCall` becomes
an HTTP JSON-RPC ``tools/call`` against the gateway; the gateway audits
the call and forwards it to the right MCP server.

Output is a :class:`HarnessResult` carrying:

- ``trace_id``    — the user PASETO's trace_id, also the audit-log key.
- ``invocations`` — every tool call observed (success/denied/error).
- ``audit_rows``  — the audit-log slice for this run, filtered by
                    ``trace_id``. Consumable by US-027 / US-028 scorers.
- ``report``      — the final draft-narrative artifact (or ``None`` if
                    the agent never produced one).
- ``terminated``  — terminal state: ``"final_answer"`` / ``"max_steps"``
                    / ``"agent_error"``.

The runner is deliberately small (~150 LOC excluding docstrings) so it
stays inside the harness LOC budget the eval gate (US-030) implies.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from evals.datasets.schema import EvalDataset
from evals.harness.agent import (
    DEFAULT_FINAL_ANSWER_TOOL,
    Agent,
    FinalAnswer,
    ToolCall,
    derive_tool_definitions,
)
from gateways.common import audit as audit_mod

#: ``PasetoFactory`` is anything callable that returns a fresh user
#: PASETO. The MCP gateway tracks ``jti`` and rejects reuse within the
#: token TTL, so every tool call needs a new token. Callers wire this
#: to either (a) the auth-gateway flow (mock OIDC -> /token) or (b) a
#: direct ``mint(...)`` call in tests.
PasetoFactory = Callable[[], str]

__all__ = [
    "DEFAULT_MAX_STEPS",
    "HarnessResult",
    "PasetoFactory",
    "ToolInvocation",
    "run_dataset",
]

DEFAULT_MAX_STEPS = 16


@dataclass(frozen=True, slots=True)
class ToolInvocation:
    """One tool call the agent issued, plus what came back.

    ``status`` mirrors the audit-log column shape:
    ``ok`` / ``denied`` / ``error`` / ``unknown_tool``. ``unknown_tool``
    is the harness-side reject for agent calls that don't match any of
    the derived tool definitions; ``denied`` covers gateway RBAC
    rejections.
    """

    step: int
    tool_use_id: str
    tool_name: str
    server: str | None
    tool: str | None
    arguments: dict[str, Any]
    status: str
    http_status: int | None
    result: Any
    deny_reason: str | None = None


@dataclass(frozen=True, slots=True)
class HarnessResult:
    """Output of one dataset run."""

    dataset_id: str
    trace_id: str
    invocations: list[ToolInvocation]
    audit_rows: list[dict[str, Any]]
    report: dict[str, Any] | None
    terminated: str
    steps_used: int
    agent_calls: list[dict[str, Any]] = field(default_factory=list)


def _load_skill_md(skill_path: Path) -> str:
    """Read the orchestrator SKILL.md verbatim.

    The skill content is the system prompt. We refuse to substitute or
    template it — the file is audited by commit hash per the PRD's
    skill-spoofing threat model.
    """
    return skill_path.read_text(encoding="utf-8")


def _split_tool_name(name: str) -> tuple[str | None, str | None]:
    """Recover ``(server, tool)`` from the agent-facing ``server__tool``
    name. Returns ``(None, None)`` on a malformed name."""
    if "__" not in name:
        return None, None
    server, _, tool = name.partition("__")
    if not server or not tool:
        return None, None
    return server, tool


def _build_user_alert(dataset: EvalDataset) -> dict[str, Any]:
    """Project the dataset's ``input_alert`` into the shape the
    orchestrator's ``<inputs>`` block expects, plus the persona scenario
    so the mocks stay deterministic.
    """
    alert = dataset.input_alert.model_dump()
    # The scenario isn't part of the alert payload in production, but the
    # orchestrator's `<inputs>` block carries an optional `scenario`
    # override for deterministic eval runs. Push it through.
    alert["_scenario"] = dataset.scenario
    return alert


def _post_tool_call(
    *,
    http_client: httpx.Client,
    gateway_url: str,
    paseto: str,
    server: str,
    tool: str,
    arguments: Mapping[str, Any],
    rpc_id: int,
) -> tuple[int, dict[str, Any]]:
    """Issue one MCP gateway ``tools/call``. Returns the HTTP status
    and the parsed JSON body. Network errors raise.

    Per-call timeout is configured on the ``httpx.Client`` itself at
    construction time; we don't pass ``timeout=`` to ``.post`` so the
    TestClient (which doesn't accept that kwarg) works the same way as
    a production ``httpx.Client``.
    """
    body = {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": dict(arguments)},
    }
    url = f"{gateway_url.rstrip('/')}/mcp/{server}"
    resp = http_client.post(
        url,
        json=body,
        headers={
            "Authorization": f"Bearer {paseto}",
            "Content-Type": "application/json",
        },
    )
    try:
        payload = resp.json()
    except (json.JSONDecodeError, ValueError):
        payload = {"text": resp.text}
    return resp.status_code, payload


def _classify_response(http_status: int, payload: Mapping[str, Any]) -> tuple[
    str, str | None
]:
    """Map an HTTP/JSON-RPC response to ``(status, deny_reason)``.

    The MCP gateway pins ``deny_reason`` inside ``error.data`` on every
    RBAC/PASETO failure. 4xx with a deny_reason is ``denied``; other
    errors are ``error``; ``result`` present is ``ok``.
    """
    if 200 <= http_status < 300 and "result" in payload:
        return "ok", None
    error = payload.get("error") if isinstance(payload, Mapping) else None
    if isinstance(error, Mapping):
        data = error.get("data")
        if isinstance(data, Mapping):
            deny = data.get("deny_reason")
            if isinstance(deny, str):
                return "denied", deny
    return "error", None


def run_dataset(  # noqa: C901 - the loop is intentionally explicit
    dataset: EvalDataset,
    *,
    skill_path: Path,
    agent: Agent,
    http_client: httpx.Client,
    gateway_url: str,
    paseto_factory: PasetoFactory,
    trace_id: str,
    sub: str,
    max_steps: int = DEFAULT_MAX_STEPS,
    audit_backend: audit_mod.AuditBackend | None = None,
) -> HarnessResult:
    """Drive ``dataset`` through the orchestrator skill and return a
    :class:`HarnessResult`.

    Parameters
    ----------
    dataset:
        The case to run. ``expected_tool_calls`` determines the tool
        surface the agent sees; ``input_alert`` is the user message.
    skill_path:
        Path to the orchestrator SKILL.md. The harness reads it
        verbatim — never template it.
    agent:
        Any :class:`evals.harness.agent.Agent`. Production runs use
        :class:`AnthropicAgent`; tests use :class:`StubAgent`.
    http_client:
        ``httpx.Client`` whose transport routes ``f"{gateway_url}/mcp/.."``
        to the MCP gateway. Tests inject an ASGI-transport-backed client.
    gateway_url:
        Base URL of the MCP gateway, e.g. ``http://localhost:8000``.
    paseto_factory:
        Zero-arg callable that returns a fresh user PASETO. The MCP
        gateway tracks ``jti`` and rejects reuse, so the harness mints
        a new token per tool call. Production callers wire this to the
        mock OIDC -> auth gateway flow; tests typically wrap a closure
        over ``mint(...)``.
    trace_id:
        The trace_id baked into every PASETO produced by
        ``paseto_factory``. We pass it explicitly so the runner can
        filter the audit log without re-parsing each token.
    sub:
        The PASETO's ``sub`` claim (typically the user email). Used as
        a secondary audit-log filter so cross-run trace_id collisions
        (vanishingly unlikely; defense in depth) still produce hermetic
        results.
    max_steps:
        Cap on the agent loop. The harness terminates with
        ``terminated="max_steps"`` once exceeded.
    audit_backend:
        Optional explicit backend to read the audit slice from. Defaults
        to ``gateways.common.audit.get_backend()`` (the same process-wide
        singleton the gateway writes to in-process tests).
    """
    if max_steps <= 0:
        raise ValueError("max_steps must be positive")

    skill_md = _load_skill_md(skill_path)
    tools = derive_tool_definitions(
        [
            {"server": tc.server, "tool": tc.tool}
            for tc in dataset.expected_tool_calls
        ]
    )
    tool_by_name = {t["name"]: t for t in tools}
    alert = _build_user_alert(dataset)

    invocations: list[ToolInvocation] = []
    tool_history: list[dict[str, Any]] = []
    report: dict[str, Any] | None = None
    terminated = "max_steps"
    steps_used = 0
    rpc_id = 0
    agent_calls_log: list[dict[str, Any]] = []

    for step_idx in range(1, max_steps + 1):
        steps_used = step_idx
        try:
            step = agent(
                skill_md=skill_md,
                alert=alert,
                tools=tools,
                tool_results=tool_history,
            )
        except Exception as exc:  # noqa: BLE001 - surface any agent fault
            terminated = "agent_error"
            agent_calls_log.append({"step": step_idx, "error": str(exc)})
            break

        if isinstance(step, FinalAnswer):
            report = dict(step.report)
            terminated = "final_answer"
            break

        if not isinstance(step, ToolCall):  # pragma: no cover - defensive
            terminated = "agent_error"
            break

        tool_def = tool_by_name.get(step.name)
        tool_use_id = step.id or f"call_{uuid.uuid4().hex[:12]}"
        if tool_def is None:
            invocations.append(
                ToolInvocation(
                    step=step_idx,
                    tool_use_id=tool_use_id,
                    tool_name=step.name,
                    server=None,
                    tool=None,
                    arguments=dict(step.arguments),
                    status="unknown_tool",
                    http_status=None,
                    result={
                        "error": "unknown_tool",
                        "available": sorted(tool_by_name.keys()),
                    },
                    deny_reason=None,
                )
            )
            tool_history.append(
                {
                    "tool_use_id": tool_use_id,
                    "tool_name": step.name,
                    "arguments": dict(step.arguments),
                    "result": {"error": "unknown_tool"},
                    "is_error": True,
                }
            )
            continue

        meta = tool_def.get("_meta", {})
        if meta.get("final_answer"):
            # The final_answer tool is the synthetic terminator. If the
            # agent calls it via ToolCall rather than FinalAnswer the
            # harness still honors it.
            raw_report = step.arguments.get("report", step.arguments)
            if isinstance(raw_report, Mapping):
                report = dict(raw_report)
            else:
                report = {"raw": raw_report}
            terminated = "final_answer"
            break

        server = meta.get("server")
        tool = meta.get("tool")
        if not isinstance(server, str) or not isinstance(tool, str):
            # Should never happen — derive_tool_definitions populates
            # both. Treat as unknown_tool defensively.
            invocations.append(
                ToolInvocation(
                    step=step_idx,
                    tool_use_id=tool_use_id,
                    tool_name=step.name,
                    server=None,
                    tool=None,
                    arguments=dict(step.arguments),
                    status="unknown_tool",
                    http_status=None,
                    result={"error": "tool_definition_missing_meta"},
                    deny_reason=None,
                )
            )
            continue

        # Tool definitions declare the input shape as
        # ``{"arguments": <obj>}`` so the Anthropic tool-use schema can
        # carry an arbitrary args object inside one well-typed field.
        # Unwrap that envelope before posting to the MCP gateway, which
        # expects flat arguments (e.g. ``{"customer_id": ...}``).
        outbound_args = step.arguments.get("arguments", step.arguments)
        if not isinstance(outbound_args, Mapping):
            outbound_args = {}
        rpc_id += 1
        # Mint a fresh user PASETO per tool call. The MCP gateway
        # tracks ``jti`` to prevent replay; reusing a token across
        # calls yields a token_replay deny on the second call.
        try:
            paseto = paseto_factory()
        except Exception as exc:  # noqa: BLE001 - surface as a per-call error
            invocations.append(
                ToolInvocation(
                    step=step_idx,
                    tool_use_id=tool_use_id,
                    tool_name=step.name,
                    server=server,
                    tool=tool,
                    arguments=dict(step.arguments),
                    status="error",
                    http_status=None,
                    result={"error": "paseto_mint_failed", "detail": str(exc)},
                    deny_reason=None,
                )
            )
            tool_history.append(
                {
                    "tool_use_id": tool_use_id,
                    "tool_name": step.name,
                    "arguments": dict(step.arguments),
                    "result": {"error": "paseto_mint_failed"},
                    "is_error": True,
                }
            )
            continue
        try:
            http_status, payload = _post_tool_call(
                http_client=http_client,
                gateway_url=gateway_url,
                paseto=paseto,
                server=server,
                tool=tool,
                arguments=outbound_args,
                rpc_id=rpc_id,
            )
        except httpx.HTTPError as exc:
            invocations.append(
                ToolInvocation(
                    step=step_idx,
                    tool_use_id=tool_use_id,
                    tool_name=step.name,
                    server=server,
                    tool=tool,
                    arguments=dict(step.arguments),
                    status="error",
                    http_status=None,
                    result={"error": "network", "detail": str(exc)},
                    deny_reason=None,
                )
            )
            tool_history.append(
                {
                    "tool_use_id": tool_use_id,
                    "tool_name": step.name,
                    "arguments": dict(step.arguments),
                    "result": {"error": "network", "detail": str(exc)},
                    "is_error": True,
                }
            )
            continue

        status, deny_reason = _classify_response(http_status, payload)
        invocations.append(
            ToolInvocation(
                step=step_idx,
                tool_use_id=tool_use_id,
                tool_name=step.name,
                server=server,
                tool=tool,
                arguments=dict(step.arguments),
                status=status,
                http_status=http_status,
                result=payload.get("result") if status == "ok" else payload,
                deny_reason=deny_reason,
            )
        )
        tool_history.append(
            {
                "tool_use_id": tool_use_id,
                "tool_name": step.name,
                "arguments": dict(step.arguments),
                "result": payload.get("result") if status == "ok" else payload,
                "is_error": status != "ok",
            }
        )

    audit_rows = _collect_audit_rows(
        backend=audit_backend, trace_id=trace_id, sub=sub
    )

    return HarnessResult(
        dataset_id=dataset.id,
        trace_id=trace_id,
        invocations=invocations,
        audit_rows=audit_rows,
        report=report,
        terminated=terminated,
        steps_used=steps_used,
        agent_calls=agent_calls_log,
    )


def _collect_audit_rows(
    *,
    backend: audit_mod.AuditBackend | None,
    trace_id: str,
    sub: str,
) -> list[dict[str, Any]]:
    """Pull the audit slice for this run.

    Filters on ``sub`` (the audit module's first-class filter) then
    keeps only rows whose ``trace_id`` matches. The audit module
    doesn't currently expose a ``trace_id`` query filter — the runner
    handles it client-side rather than expanding the audit API
    surface.
    """
    if backend is None:
        try:
            backend = audit_mod.get_backend()
        except Exception:  # noqa: BLE001
            return []
    # Some backends buffer writes; if it exposes flush(), call it.
    flush = getattr(backend, "flush", None)
    if callable(flush):
        try:
            flush()
        except Exception:  # noqa: BLE001 - audit IO must never raise here
            pass
    try:
        rows = backend.query(sub=sub)
    except Exception:  # noqa: BLE001
        return []
    return [row for row in rows if row.get("trace_id") == trace_id]


# The implicit DEFAULT_FINAL_ANSWER_TOOL re-export keeps callers' import
# graphs tidy — runner.py is the single import point for the harness
# loop. AGENT-FRIENDLY: the tool name shows up here too for ctrl-F.
_FINAL_ANSWER_TOOL = DEFAULT_FINAL_ANSWER_TOOL
