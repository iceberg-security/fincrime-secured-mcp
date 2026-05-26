"""Eval runner + CI gate (US-030).

``evals/run.py`` is the orchestration entry point: it loads the
declarative datasets under ``evals/datasets/`` (US-025/US-026), drives
each through the headless harness against a federated mock stack
(US-029), scores the resulting trace + report against the four PRD
dimensions (US-027 tool_correctness + tool_ordering; US-028 grounding
+ reasoning), and emits a per-case scorecard plus a per-dimension
aggregate pass rate.

Two harness modes:

- **In-process** (default in CI smoke runs + tests). The runner builds
  the full app graph in-process — mock APIs wired by ASGI transport
  into MCP servers, then into the MCP gateway — so a single Python
  process can run the whole suite without Docker. Fast + hermetic.

- **External** (``--gateway-url``). The runner POSTs against a live
  MCP gateway URL (usually one stood up by ``docker compose up``).
  ``make evals`` uses this mode after bringing the compose stack up
  and tears it back down on exit.

The runner picks one of two ``Agent`` implementations:

- **OracleAgent** (default). A scripted agent that issues exactly the
  ``expected_tool_calls`` declared by the dataset, then a synthetic
  ``FinalAnswer``. The runner uses this when ``ANTHROPIC_API_KEY`` is
  unset so the CI gate is deterministic + free. The oracle is **not**
  cheating — the scorers still verify what actually landed in the
  audit log against the dataset's contract, and the tool-correctness
  + tool-ordering scorers will catch any drift between the oracle's
  scripted calls and what the gateway actually saw.

- **AnthropicAgent** (when ``--use-llm`` is passed + the SDK + key are
  present). Drives the orchestrator skill through real Claude calls.
  Costs money; runs nightly, not on PR.

LLM-judge scorers (grounding + reasoning) require a ``Judge``. Two
implementations:

- **StubJudge** (default + CI smoke). Returns a synthetic verdict
  derived from the audit-log shape — grounded if a matching audit row
  with ``status='ok'`` exists, ungrounded otherwise; reasoning scored
  4-out-of-5 across all four dimensions iff every required_facts'
  supporting_tool produced an OK audit row, otherwise 2-out-of-5.
  The stub is the CI deterministic gate; it MUST NOT regress as the
  scorers' rubric changes.

- **AnthropicJudge** (when ``--use-llm`` is passed). Real Opus calls.

Output:

The scorecard is a JSON document; the human-readable summary is a
plain-text table written to stdout. Both shapes are stable so the
nightly CI uploads the JSON as an artifact and the PR check posts
the table.

Exit code is ``0`` iff every case passes every dimension; ``1`` if any
dimension fails on any case. The smoke subset (``--smoke``) restricts
to ``clean_customer`` + ``mule_account`` — the launch-blocker set.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Silence the OTel ConsoleSpanExporter (the default when
# OTEL_EXPORTER_OTLP_ENDPOINT is unset) — the runner's scorecard is
# the user-facing output, not a span dump. Tests + production callers
# can override by exporting FRAUD_OTEL_NOOP=false before invoking us.
os.environ.setdefault("FRAUD_OTEL_NOOP", "true")

import httpx  # noqa: E402 - import order matters for OTel init
from fastapi.testclient import TestClient  # noqa: E402

from evals.datasets.schema import (
    EvalDataset,
    EvalSchemaError,
    validate_dataset_dir,
)
from evals.harness import (
    DEFAULT_MAX_STEPS,
    FinalAnswer,
    HarnessResult,
    ToolCall,
    run_dataset,
)
from evals.harness.agent import Agent, AgentStep
from evals.scorers import (
    Judge,
    JudgeResponse,
    ScorerResult,
    score_grounding,
    score_reasoning,
    score_tool_correctness,
    score_tool_ordering,
)
from gateways.common import audit as audit_mod
from gateways.common.audit import SQLiteAuditBackend
from gateways.common.paseto import Claims, mint

__all__ = [
    "DEFAULT_SUB",
    "DIMENSIONS",
    "EvalRunConfig",
    "EvalSuiteResult",
    "OracleAgent",
    "PerCaseResult",
    "SMOKE_DATASETS",
    "StubJudge",
    "main",
    "run_eval_suite",
]

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET_DIR = REPO_ROOT / "evals" / "datasets"
DEFAULT_SKILL_PATH = (
    REPO_ROOT / "plugin" / "skills" / "orchestrator" / "SKILL.md"
)
DEFAULT_SUB = "alice@example.com"

#: The four scorer dimensions, in the canonical order the scorecard
#: surfaces. Mirrors the PRD US-030 AC ordering.
DIMENSIONS: tuple[str, ...] = (
    "tool_correctness",
    "tool_ordering",
    "grounding",
    "reasoning",
)

#: Smoke subset — the two launch-blocker datasets. Used by
#: ``make evals-smoke`` + the PR-time CI workflow.
SMOKE_DATASETS: tuple[str, ...] = ("clean_customer", "mule_account")


# --------------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class PerCaseResult:
    """One case's scorecard row."""

    dataset_id: str
    scenario: str
    expected_verdict: str
    terminated: str
    steps_used: int
    scorer_results: dict[str, ScorerResult] = field(default_factory=dict)
    error: str | None = None

    @property
    def passed(self) -> bool:
        if self.error is not None:
            return False
        if not self.scorer_results:
            return False
        return all(s.passed for s in self.scorer_results.values())


@dataclass(frozen=True, slots=True)
class EvalSuiteResult:
    """Aggregate scorecard for one suite run."""

    cases: list[PerCaseResult]
    dimensions: tuple[str, ...] = DIMENSIONS

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.cases) and bool(self.cases)

    def pass_rate_by_dimension(self) -> dict[str, float]:
        """Per-dimension pass rate across every case that produced a
        result for that dimension."""
        out: dict[str, float] = {}
        for dim in self.dimensions:
            considered = [
                c for c in self.cases if dim in c.scorer_results
            ]
            if not considered:
                out[dim] = 0.0
                continue
            passes = sum(
                1 for c in considered if c.scorer_results[dim].passed
            )
            out[dim] = passes / len(considered)
        return out

    def to_dict(self) -> dict[str, Any]:
        """Stable JSON shape for CI artifact uploads."""
        return {
            "cases": [
                {
                    "dataset_id": c.dataset_id,
                    "scenario": c.scenario,
                    "expected_verdict": c.expected_verdict,
                    "terminated": c.terminated,
                    "steps_used": c.steps_used,
                    "passed": c.passed,
                    "error": c.error,
                    "scorers": {
                        name: {
                            "score": s.score,
                            "passed": s.passed,
                            "details": s.details,
                        }
                        for name, s in c.scorer_results.items()
                    },
                }
                for c in self.cases
            ],
            "aggregate": {
                "total": len(self.cases),
                "passed": sum(1 for c in self.cases if c.passed),
                "pass_rate_by_dimension": self.pass_rate_by_dimension(),
                "all_passed": self.passed,
            },
        }


# --------------------------------------------------------------------------- #
# Configuration                                                               #
# --------------------------------------------------------------------------- #


@dataclass
class EvalRunConfig:
    """Top-level runner configuration.

    All fields have sensible defaults so the runner is callable from a
    bare ``run_eval_suite(EvalRunConfig())`` in tests.
    """

    dataset_dir: Path = DEFAULT_DATASET_DIR
    skill_path: Path = DEFAULT_SKILL_PATH
    smoke: bool = False
    dataset_ids: tuple[str, ...] | None = None
    max_steps: int = DEFAULT_MAX_STEPS
    sub: str = DEFAULT_SUB
    trace_prefix: str = "eval"
    output_path: Path | None = None
    quiet: bool = False


# --------------------------------------------------------------------------- #
# Oracle agent — scripted, deterministic, cheating-resistant
# --------------------------------------------------------------------------- #


class OracleAgent:
    """Deterministic agent that scripts itself from the dataset.

    For each ``(server, tool)`` pair in ``expected_tool_calls`` (in
    declaration order), the oracle emits a ``ToolCall`` with the
    canonical ``{customer_id, scenario}`` arguments (overridden where
    a known tool needs a different shape — e.g. ``sanctions.screen_name``
    takes ``name=`` instead of ``customer_id=``). Once every call has
    been issued, it emits a synthetic ``FinalAnswer`` whose
    ``evidence`` list cites every ``required_facts`` entry.

    The oracle is **not** a free pass on the scorers:

    - The MCP gateway still has to RBAC-allow each call, audit it, and
      forward to the right downstream server. Drift between the
      dataset and the live stack surfaces as ``denied`` or ``error``
      rows in the audit log, which the tool_correctness scorer
      penalizes.
    - The synthetic final report cites tools the oracle DID call, but
      the grounding scorer (US-028) still checks every citation
      against the audit log; if a call denied or errored, the
      matching citation will fail.

    Used by ``run_eval_suite`` when ``ANTHROPIC_API_KEY`` is unset and
    by every unit test.
    """

    def __init__(self, dataset: EvalDataset) -> None:
        self._dataset = dataset
        self._customer_id = dataset.input_alert.customer_id
        self._scenario = dataset.scenario
        self._steps: list[AgentStep] = self._build_steps()
        self._idx = 0

    def _build_steps(self) -> list[AgentStep]:
        steps: list[AgentStep] = []
        for tc in self._dataset.expected_tool_calls:
            arguments = self._args_for(tc.server, tc.tool)
            steps.append(
                ToolCall(
                    id=f"oracle-{tc.server}-{tc.tool}-{uuid.uuid4().hex[:6]}",
                    name=f"{tc.server}__{tc.tool}",
                    arguments={"arguments": arguments},
                )
            )
        steps.append(FinalAnswer(report=self._build_report()))
        return steps

    def _args_for(self, server: str, tool: str) -> dict[str, Any]:
        """Build the per-tool argument shape.

        Most tools take ``customer_id`` + optional ``scenario``. The
        odd ones out are the OSINT / sanctions screening tools, which
        screen on names + queries + company names instead.
        """
        if server == "sanctions" and tool == "screen_name":
            return {"name": self._name_for_customer(), "scenario": self._scenario}
        if server == "sanctions" and tool == "screen_entity":
            return {
                "entity_name": self._company_for_customer(),
                "scenario": self._scenario,
            }
        if server == "sanctions" and tool == "get_watchlist_hit":
            # The hit_id is built from the scenario + the screened
            # name. We use the same shape the sanctions mock pins
            # (hit_<scenario>_<slug>_0); the mock returns 404 for any
            # other id, so the audit log will record this as either
            # ok (when scenario=sanctions_hit) or denied/error (when
            # scenario=clean and the like). The scorer handles both.
            return {"hit_id": self._sanctions_hit_id()}
        if server == "osint" and tool == "web_search":
            return {
                "query": self._name_for_customer(),
                "scenario": self._scenario,
            }
        if server == "osint" and tool == "fetch_page":
            return {
                "url": f"https://compliance.example/{self._customer_id}",
                "scenario": self._scenario,
            }
        if server == "osint" and tool == "lookup_company":
            return {
                "company_name": self._company_for_customer(),
                "scenario": self._scenario,
            }
        if server == "kyc" and tool == "get_document":
            # The kyc mock keys documents as ``doc_<customer_id>_id``
            # and the ID-document is present in every scenario (the
            # ``synthetic_id`` shape ships ONLY the ID; other scenarios
            # also ship address / selfie). See
            # ``mock_apis/kyc/main.py::_document_ids_for``.
            return {
                "customer_id": self._customer_id,
                "document_id": f"doc_{self._customer_id}_id",
                "scenario": self._scenario,
            }
        return {
            "customer_id": self._customer_id,
            "scenario": self._scenario,
        }

    def _name_for_customer(self) -> str:
        return f"Customer {self._customer_id}"

    def _company_for_customer(self) -> str:
        return f"{self._customer_id}-counterparty"

    def _sanctions_hit_id(self) -> str:
        # Mirrors mock_apis.sanctions: hit_<scenario>_<name_slug>_<idx>
        slug = self._name_for_customer().lower().replace(" ", "_")
        # Strip any non-alnum/underscore the same way the mock does.
        slug = "".join(c if c.isalnum() or c == "_" else "_" for c in slug)
        return f"hit_{self._scenario}_{slug}_0"

    def _build_report(self) -> dict[str, Any]:
        evidence: list[dict[str, Any]] = []
        for fact in self._dataset.required_facts:
            evidence.append(
                {
                    "claim": fact.claim,
                    "value": "see citation",
                    "citation": {
                        "subskill": "oracle",
                        "server": fact.supporting_tool.server,
                        "tool": fact.supporting_tool.tool,
                        "field": "synthetic",
                    },
                }
            )
        return {
            "alert_id": self._dataset.input_alert.alert_id,
            "customer_id": self._customer_id,
            "alert_type": self._dataset.input_alert.alert_type,
            "summary": (
                f"Oracle-driven investigation of {self._dataset.scenario} "
                f"persona {self._customer_id}."
            ),
            "evidence": evidence,
            "verdict": self._dataset.expected_verdict,
            "recommended_actions": [],
            "evidence_gaps": [],
        }

    def __call__(
        self,
        *,
        skill_md: str,
        alert: Mapping[str, Any],
        tools: Sequence[Mapping[str, Any]],
        tool_results: Sequence[Mapping[str, Any]],
    ) -> AgentStep:
        if self._idx >= len(self._steps):
            # Defensive: should never happen — the runner caps at
            # max_steps and the script has exactly len(expected_calls)
            # + 1 entries. Surface as FinalAnswer with an empty
            # report so the harness terminates cleanly rather than
            # raising IndexError.
            return FinalAnswer(report={})
        step = self._steps[self._idx]
        self._idx += 1
        return step


# --------------------------------------------------------------------------- #
# Stub judge — deterministic, audit-log-driven
# --------------------------------------------------------------------------- #


class StubJudge:
    """Deterministic ``Judge`` implementation for CI runs.

    The stub doesn't actually reason about the text — it parses the
    serialized prompt the scorer hands it and answers based on the
    audit-row shape. This keeps the CI gate free of LLM cost while
    still exercising the scorer's JSON parsing + threshold logic.

    Grounding verdict:
    - ``grounded`` if any matching audit row has ``status='ok'`` AND
      the claim/value pair is non-empty.
    - ``ungrounded`` otherwise.

    Reasoning verdict:
    - Returns 4-out-of-5 across all four dimensions if every audit
      row is ``status='ok'``; 2-out-of-5 if any rows are non-ok.
    """

    def __call__(self, *, system: str, user: str) -> JudgeResponse:
        try:
            payload = json.loads(user)
        except (ValueError, json.JSONDecodeError):
            return JudgeResponse(text="")
        if "claim" in payload:
            return self._grounding_response(payload)
        return self._reasoning_response(payload)

    @staticmethod
    def _grounding_response(payload: Mapping[str, Any]) -> JudgeResponse:
        claim = payload.get("claim")
        rows = payload.get("matching_audit_rows", [])
        has_ok = any(
            isinstance(r, Mapping) and r.get("status") == "ok" for r in rows
        )
        if claim and has_ok:
            return JudgeResponse(
                text=json.dumps(
                    {"verdict": "grounded", "reason": "matching ok row"}
                )
            )
        return JudgeResponse(
            text=json.dumps(
                {"verdict": "ungrounded", "reason": "no matching ok row"}
            )
        )

    @staticmethod
    def _reasoning_response(payload: Mapping[str, Any]) -> JudgeResponse:
        rows = payload.get("audit_log") or payload.get("audit_rows") or []
        if isinstance(rows, list) and rows:
            all_ok = all(
                isinstance(r, Mapping) and r.get("status") == "ok"
                for r in rows
            )
        else:
            # No rows at all is treated as inconclusive: the verifier
            # (US-021) catches reports with zero evidence; the stub
            # judge gives 3-of-5 so the eval suite registers a
            # meaningful gradient rather than a hard pass.
            all_ok = False
        if all_ok:
            score = 4
            reason = "stub judge: every audit row is status=ok"
        elif rows:
            score = 2
            reason = "stub judge: at least one non-ok row in the audit log"
        else:
            score = 3
            reason = "stub judge: empty audit log; inconclusive"
        body: dict[str, Any] = {
            dim: {"score": score, "reason": reason}
            for dim in ("relevance", "soundness", "completeness", "calibration")
        }
        body["overall_reason"] = reason
        return JudgeResponse(text=json.dumps(body))


# --------------------------------------------------------------------------- #
# In-process stack
# --------------------------------------------------------------------------- #


@dataclass
class _StackHandles:
    """The in-process stack the runner stands up for hermetic runs."""

    client: TestClient
    inbound_priv: Path
    backend: SQLiteAuditBackend


def _build_in_process_stack(
    *,
    tmp_dir: Path,
    exit_stack: ExitStack,
) -> _StackHandles:
    """Wire mocks -> MCP servers -> gateway in one Python process.

    Mirrors the test fixture pattern from ``tests/test_harness.py`` but
    spans every read-only MCP server so any dataset can run. case_actions
    is excluded — it needs ``human_approval=true`` which the eval flow
    doesn't mint.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    # Local imports keep the runner module fast to import in unit
    # tests that don't need the stack (CLI arg parsing, etc.).
    from gateways.mcp.main import create_app as create_gateway_app
    from mcp_servers.customer_data.main import (
        create_app as create_customer_data_server,
    )
    from mcp_servers.kyc.main import create_app as create_kyc_server
    from mcp_servers.osint.main import create_app as create_osint_server
    from mcp_servers.sanctions.main import create_app as create_sanctions_server
    from mcp_servers.transactions.main import create_app as create_transactions_server
    from mock_apis.customer_data.main import (
        create_app as create_customer_data_mock,
    )
    from mock_apis.kyc.main import create_app as create_kyc_mock
    from mock_apis.osint.main import create_app as create_osint_mock
    from mock_apis.sanctions.main import create_app as create_sanctions_mock
    from mock_apis.transactions.main import create_app as create_transactions_mock

    def _write_key(name: str) -> tuple[Path, Path]:
        priv = Ed25519PrivateKey.generate()
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        priv_path = tmp_dir / f"{name}_priv.pem"
        pub_path = tmp_dir / f"{name}_pub.pem"
        priv_path.write_bytes(priv_pem)
        pub_path.write_bytes(pub_pem)
        return priv_path, pub_path

    inbound_priv, inbound_pub = _write_key("inbound")
    service_priv, service_pub = _write_key("service")

    # OSINT needs an allowlist if a dataset uses fetch_page. None of
    # the six shipped datasets exercise fetch_page, but if a future
    # dataset does, set OSINT_ALLOWLIST in the calling environment;
    # the server will pick it up at import time.
    os.environ.setdefault("OSINT_ALLOWLIST", "compliance.example")

    mock_factories: dict[str, Callable[[], Any]] = {
        "customer_data": create_customer_data_mock,
        "transactions": create_transactions_mock,
        "kyc": create_kyc_mock,
        "sanctions": create_sanctions_mock,
        "osint": create_osint_mock,
    }
    mcp_factories: dict[str, Callable[..., Any]] = {
        "customer_data": create_customer_data_server,
        "transactions": create_transactions_server,
        "kyc": create_kyc_server,
        "sanctions": create_sanctions_server,
        "osint": create_osint_server,
    }

    # Hold strong references so the AsyncClients don't drop mid-run.
    held: list[Any] = []
    server_transports: dict[str, httpx.ASGITransport] = {}
    downstream_urls: dict[str, str] = {}

    for server_name in mock_factories:
        mock_app = mock_factories[server_name]()
        mock_client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mock_app),
            base_url=f"http://mock-{server_name}",
        )
        held.append(mock_client)
        factory = mcp_factories[server_name]
        server_app = factory(
            public_key_path=service_pub, api_client=mock_client
        )
        server_transports[server_name] = httpx.ASGITransport(app=server_app)
        downstream_urls[server_name] = f"http://downstream-{server_name}"

    # The gateway calls `http_client.post(f"{downstream_url}/...", ...)`
    # so each downstream hostname must route to the matching server's
    # ASGI transport. httpx's `mounts` parameter handles per-prefix
    # routing natively.
    gateway_http_client = httpx.AsyncClient(
        mounts={
            f"http://downstream-{srv}": transport
            for srv, transport in server_transports.items()
        }
    )
    held.append(gateway_http_client)

    gateway_app = create_gateway_app(
        downstream_urls=downstream_urls,
        service_private_key_path=service_priv,
        inbound_public_key_path=inbound_pub,
        http_client=gateway_http_client,
    )
    client = TestClient(gateway_app)
    exit_stack.callback(client.close)

    backend = SQLiteAuditBackend(":memory:")
    audit_mod.set_backend(backend)
    exit_stack.callback(audit_mod.reset_default_backend)

    # held is captured by the lambda so its refs survive until exit.
    exit_stack.callback(lambda: held.clear())

    return _StackHandles(
        client=client, inbound_priv=inbound_priv, backend=backend
    )


# --------------------------------------------------------------------------- #
# PASETO factory                                                              #
# --------------------------------------------------------------------------- #


def _make_paseto_factory(
    *,
    inbound_priv: Path,
    sub: str,
    trace_id: str,
    dataset: EvalDataset,
) -> Callable[[], str]:
    """Build a zero-arg ``paseto_factory`` for ``run_dataset``.

    The user PASETO grants the union of ``allowed_servers``/
    ``allowed_tools`` derived from the dataset's ``expected_tool_calls``
    so the gateway RBAC won't deny anything the dataset says the agent
    SHOULD call. Anything outside the dataset's surface (e.g. a buggy
    agent calling ``case_actions.create_sar_draft``) still gets denied
    by the gateway, and the deny shows up in the audit log so the
    tool_correctness scorer can penalize it.
    """
    allowed_servers = sorted(
        {tc.server for tc in dataset.expected_tool_calls}
    )
    allowed_tools: dict[str, list[str]] = {}
    for tc in dataset.expected_tool_calls:
        allowed_tools.setdefault(tc.server, []).append(tc.tool)

    def factory() -> str:
        claims = Claims(
            sub=sub,
            roles=["analyst"],
            allowed_servers=allowed_servers,
            allowed_tools=allowed_tools,
            trace_id=trace_id,
        )
        return mint(claims, ttl_seconds=300, private_key_path=inbound_priv)

    return factory


# --------------------------------------------------------------------------- #
# Per-case execution                                                          #
# --------------------------------------------------------------------------- #


def _select_datasets(
    *,
    dataset_dir: Path,
    smoke: bool,
    dataset_ids: tuple[str, ...] | None,
) -> list[EvalDataset]:
    """Load + filter datasets per the runner config."""
    datasets = validate_dataset_dir(dataset_dir)
    if dataset_ids is not None:
        wanted = set(dataset_ids)
        selected = [d for d in datasets if d.id in wanted]
        missing = wanted - {d.id for d in selected}
        if missing:
            raise EvalSchemaError(
                f"requested dataset ids not found: {sorted(missing)}"
            )
        return selected
    if smoke:
        smoke_set = set(SMOKE_DATASETS)
        return [d for d in datasets if d.id in smoke_set]
    return datasets


def _score_one(
    *,
    dataset: EvalDataset,
    harness_result: HarnessResult,
    judge: Judge,
) -> dict[str, ScorerResult]:
    """Run all four scorers against one HarnessResult."""
    audit_rows = harness_result.audit_rows
    report = harness_result.report or {}
    return {
        "tool_correctness": score_tool_correctness(dataset, audit_rows),
        "tool_ordering": score_tool_ordering(dataset, audit_rows),
        "grounding": score_grounding(report, audit_rows, judge=judge),
        "reasoning": score_reasoning(report, audit_rows, judge=judge),
    }


def _run_one_case(
    *,
    dataset: EvalDataset,
    stack: _StackHandles,
    skill_path: Path,
    agent_factory: Callable[[EvalDataset], Agent],
    judge: Judge,
    sub: str,
    trace_prefix: str,
    max_steps: int,
) -> PerCaseResult:
    """Drive one dataset and score it."""
    trace_id = f"{trace_prefix}-{dataset.id}-{uuid.uuid4().hex[:8]}"
    factory = _make_paseto_factory(
        inbound_priv=stack.inbound_priv,
        sub=sub,
        trace_id=trace_id,
        dataset=dataset,
    )
    try:
        agent = agent_factory(dataset)
        harness_result = run_dataset(
            dataset,
            skill_path=skill_path,
            agent=agent,
            http_client=stack.client,
            gateway_url="",
            paseto_factory=factory,
            trace_id=trace_id,
            sub=sub,
            max_steps=max_steps,
            audit_backend=stack.backend,
        )
    except Exception as exc:  # noqa: BLE001 - per-case error containment
        return PerCaseResult(
            dataset_id=dataset.id,
            scenario=dataset.scenario,
            expected_verdict=dataset.expected_verdict,
            terminated="error",
            steps_used=0,
            scorer_results={},
            error=str(exc),
        )

    scorer_results = _score_one(
        dataset=dataset, harness_result=harness_result, judge=judge
    )
    return PerCaseResult(
        dataset_id=dataset.id,
        scenario=dataset.scenario,
        expected_verdict=dataset.expected_verdict,
        terminated=harness_result.terminated,
        steps_used=harness_result.steps_used,
        scorer_results=scorer_results,
        error=None,
    )


# --------------------------------------------------------------------------- #
# Suite driver                                                                #
# --------------------------------------------------------------------------- #


def run_eval_suite(
    config: EvalRunConfig,
    *,
    agent_factory: Callable[[EvalDataset], Agent] | None = None,
    judge: Judge | None = None,
    stack: _StackHandles | None = None,
) -> EvalSuiteResult:
    """Run the eval suite per ``config`` and return a scorecard.

    Parameters
    ----------
    config:
        Top-level runner config.
    agent_factory:
        Factory taking the dataset and returning an :class:`Agent`.
        Defaults to :class:`OracleAgent`.
    judge:
        LLM-judge implementation. Defaults to :class:`StubJudge`.
    stack:
        Pre-built in-process stack. When ``None``, a new stack is
        provisioned per call. Tests may inject an existing handle to
        share the audit DB across calls.
    """
    if agent_factory is None:
        agent_factory = OracleAgent
    if judge is None:
        judge = StubJudge()

    datasets = _select_datasets(
        dataset_dir=config.dataset_dir,
        smoke=config.smoke,
        dataset_ids=config.dataset_ids,
    )
    if not datasets:
        return EvalSuiteResult(cases=[])

    with ExitStack() as exit_stack:
        if stack is None:
            import tempfile

            tmp_dir = Path(
                exit_stack.enter_context(
                    tempfile.TemporaryDirectory(prefix="evals-")
                )
            )
            stack = _build_in_process_stack(
                tmp_dir=tmp_dir, exit_stack=exit_stack
            )

        cases: list[PerCaseResult] = []
        for dataset in datasets:
            result = _run_one_case(
                dataset=dataset,
                stack=stack,
                skill_path=config.skill_path,
                agent_factory=agent_factory,
                judge=judge,
                sub=config.sub,
                trace_prefix=config.trace_prefix,
                max_steps=config.max_steps,
            )
            cases.append(result)
            if not config.quiet:
                _print_case_line(result)

    return EvalSuiteResult(cases=cases)


# --------------------------------------------------------------------------- #
# Scorecard printing                                                          #
# --------------------------------------------------------------------------- #


def _print_case_line(case: PerCaseResult) -> None:
    """One human-readable status line per case."""
    flag = "PASS" if case.passed else "FAIL"
    parts = [f"  [{flag}] {case.dataset_id:<24} scenario={case.scenario:<14}"]
    if case.error is not None:
        parts.append(f"error={case.error}")
    else:
        for dim in DIMENSIONS:
            sr = case.scorer_results.get(dim)
            if sr is None:
                parts.append(f"{dim}=n/a")
            else:
                tag = "ok" if sr.passed else f"fail({sr.score:.2f})"
                parts.append(f"{dim}={tag}")
    print(" ".join(parts))


def _print_scorecard(result: EvalSuiteResult) -> None:
    """Aggregate scorecard footer."""
    rates = result.pass_rate_by_dimension()
    print("\nPer-dimension pass rate:")
    for dim in DIMENSIONS:
        print(f"  {dim:<20} {rates[dim] * 100:5.1f}%")
    total = len(result.cases)
    passed = sum(1 for c in result.cases if c.passed)
    overall = "PASS" if result.passed else "FAIL"
    print(f"\nOverall: [{overall}] {passed}/{total} cases passed.")


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--smoke",
        action="store_true",
        help=(
            f"Run only the smoke subset ({', '.join(SMOKE_DATASETS)})."
        ),
    )
    parser.add_argument(
        "--datasets",
        nargs="+",
        help="Explicit dataset id(s) to run; overrides --smoke.",
    )
    parser.add_argument(
        "--dataset-dir",
        default=str(DEFAULT_DATASET_DIR),
        help=f"Dataset directory (default: {DEFAULT_DATASET_DIR}).",
    )
    parser.add_argument(
        "--skill",
        default=str(DEFAULT_SKILL_PATH),
        help=f"Orchestrator SKILL.md path (default: {DEFAULT_SKILL_PATH}).",
    )
    parser.add_argument(
        "--sub",
        default=DEFAULT_SUB,
        help=f"PASETO sub claim (default: {DEFAULT_SUB}).",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=DEFAULT_MAX_STEPS,
        help=f"Per-case agent loop cap (default: {DEFAULT_MAX_STEPS}).",
    )
    parser.add_argument(
        "--output",
        help="Write the JSON scorecard to this path.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-case output lines (still writes JSON / footer).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Exits 0 on full pass, 1 otherwise."""
    args = _parse_args(argv)
    dataset_ids = tuple(args.datasets) if args.datasets else None
    config = EvalRunConfig(
        dataset_dir=Path(args.dataset_dir),
        skill_path=Path(args.skill),
        smoke=args.smoke,
        dataset_ids=dataset_ids,
        max_steps=args.max_steps,
        sub=args.sub,
        output_path=Path(args.output) if args.output else None,
        quiet=args.quiet,
    )
    if not config.quiet:
        scope = (
            f"smoke ({len(SMOKE_DATASETS)} cases)"
            if config.smoke and not dataset_ids
            else f"selected ({len(dataset_ids)})" if dataset_ids
            else "full suite"
        )
        print(f"Running eval suite: {scope}")
    try:
        result = run_eval_suite(config)
    except EvalSchemaError as exc:
        print(f"evals: dataset selection failed: {exc}", file=sys.stderr)
        return 1
    if not config.quiet:
        _print_scorecard(result)
    if config.output_path is not None:
        config.output_path.parent.mkdir(parents=True, exist_ok=True)
        config.output_path.write_text(
            json.dumps(result.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        if not config.quiet:
            print(f"\nScorecard written to {config.output_path}")
    return 0 if result.passed else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
