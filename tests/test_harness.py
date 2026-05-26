"""Smoke + unit tests for the headless harness (US-029)."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from evals.datasets.schema import validate_dataset_file
from evals.harness import (
    DEFAULT_FINAL_ANSWER_TOOL,
    DEFAULT_MAX_STEPS,
    FinalAnswer,
    HarnessResult,
    StubAgent,
    ToolCall,
    ToolInvocation,
    derive_tool_definitions,
    run_dataset,
)
from evals.scorers import score_tool_correctness, score_tool_ordering
from gateways.common import audit as audit_mod
from gateways.common import paseto as paseto_mod
from gateways.common.audit import SQLiteAuditBackend
from gateways.common.paseto import Claims, mint
from gateways.mcp.main import create_app as create_gateway_app
from mcp_servers.customer_data.main import (
    SERVER_NAME as CUSTOMER_DATA_SERVER,
)
from mcp_servers.customer_data.main import (
    create_app as create_customer_data_server_app,
)
from mock_apis.customer_data.main import create_app as create_customer_data_mock_app

REPO_ROOT = Path(__file__).resolve().parent.parent
ORCHESTRATOR_SKILL = REPO_ROOT / "plugin" / "skills" / "orchestrator" / "SKILL.md"
CLEAN_DATASET = REPO_ROOT / "evals" / "datasets" / "clean_customer.yaml"


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clear_paseto_key_cache() -> Iterator[None]:
    paseto_mod._load_private_key_cached.cache_clear()
    paseto_mod._load_public_key_cached.cache_clear()
    yield
    paseto_mod._load_private_key_cached.cache_clear()
    paseto_mod._load_public_key_cached.cache_clear()


def _write_keypair(tmp_path: Path, name: str) -> tuple[Path, Path]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = tmp_path / f"{name}_priv.pem"
    pub_path = tmp_path / f"{name}_pub.pem"
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    return priv_path, pub_path


@pytest.fixture()
def inbound_keys(tmp_path: Path) -> tuple[Path, Path]:
    return _write_keypair(tmp_path, "inbound")


@pytest.fixture()
def service_keys(tmp_path: Path) -> tuple[Path, Path]:
    return _write_keypair(tmp_path, "service")


@pytest.fixture()
def memory_audit_backend() -> Iterator[SQLiteAuditBackend]:
    backend = SQLiteAuditBackend(":memory:")
    audit_mod.set_backend(backend)
    yield backend
    audit_mod.reset_default_backend()


@pytest.fixture()
def gateway_client(
    inbound_keys: tuple[Path, Path], service_keys: tuple[Path, Path]
) -> Iterator[TestClient]:
    """In-process MCP gateway + customer_data server + customer_data mock.

    This is the same wiring the existing
    ``test_customer_data_mcp_server.py`` end-to-end test uses, condensed
    into a single fixture so the smoke test reads cleanly.
    """
    _, inbound_pub = inbound_keys
    service_priv, service_pub = service_keys

    mock_app = create_customer_data_mock_app()
    mock_transport = httpx.ASGITransport(app=mock_app)
    mock_client = httpx.AsyncClient(transport=mock_transport, base_url="http://mock")

    server_app = create_customer_data_server_app(
        public_key_path=service_pub, api_client=mock_client
    )
    server_transport = httpx.ASGITransport(app=server_app)
    gateway_http_client = httpx.AsyncClient(
        transport=server_transport, base_url="http://downstream"
    )

    gateway_app = create_gateway_app(
        downstream_url="http://downstream",
        service_private_key_path=service_priv,
        inbound_public_key_path=inbound_pub,
        http_client=gateway_http_client,
    )
    client = TestClient(gateway_app)
    yield client
    client.close()


def _mint_user_token(
    *,
    inbound_priv: Path,
    sub: str = "alice@example.com",
    trace_id: str = "trace-harness-001",
) -> str:
    claims = Claims(
        sub=sub,
        roles=["analyst"],
        allowed_servers=[CUSTOMER_DATA_SERVER],
        allowed_tools={
            CUSTOMER_DATA_SERVER: [
                "get_customer",
                "list_accounts",
                "get_device_history",
            ]
        },
        trace_id=trace_id,
    )
    return mint(claims, ttl_seconds=300, private_key_path=inbound_priv)


def _factory(
    *, inbound_priv: Path, trace_id: str, sub: str = "alice@example.com"
) -> Callable[[], str]:
    return lambda: _mint_user_token(
        inbound_priv=inbound_priv, sub=sub, trace_id=trace_id
    )


# --------------------------------------------------------------------------- #
# Tool-definition derivation                                                  #
# --------------------------------------------------------------------------- #


def test_derive_tool_definitions_includes_final_answer() -> None:
    tools = derive_tool_definitions(
        [{"server": "customer_data", "tool": "get_customer"}]
    )
    names = [t["name"] for t in tools]
    assert names == ["customer_data__get_customer", DEFAULT_FINAL_ANSWER_TOOL]
    # Sidecar meta carries the (server, tool) the runner needs.
    assert tools[0]["_meta"] == {"server": "customer_data", "tool": "get_customer"}
    assert tools[1]["_meta"] == {"final_answer": True}


def test_derive_tool_definitions_can_omit_final_answer() -> None:
    tools = derive_tool_definitions(
        [{"server": "customer_data", "tool": "get_customer"}],
        include_final_answer=False,
    )
    assert all(t["name"] != DEFAULT_FINAL_ANSWER_TOOL for t in tools)


def test_derive_tool_definitions_dedupes_repeated_pairs() -> None:
    tools = derive_tool_definitions(
        [
            {"server": "customer_data", "tool": "get_customer"},
            {"server": "customer_data", "tool": "get_customer"},
            {"server": "customer_data", "tool": "list_accounts"},
        ]
    )
    names = [t["name"] for t in tools if t["name"] != DEFAULT_FINAL_ANSWER_TOOL]
    assert names == ["customer_data__get_customer", "customer_data__list_accounts"]


def test_derive_tool_definitions_rejects_unknown_server() -> None:
    tools = derive_tool_definitions(
        [{"server": "bogus", "tool": "anything"}],
        include_final_answer=False,
    )
    assert tools == []


def test_derive_tool_definitions_rejects_unknown_tool_on_known_server() -> None:
    tools = derive_tool_definitions(
        [{"server": "customer_data", "tool": "freeze_account"}],
        include_final_answer=False,
    )
    assert tools == []


def test_derive_tool_definitions_input_schema_shape() -> None:
    tools = derive_tool_definitions(
        [{"server": "customer_data", "tool": "get_customer"}],
        include_final_answer=True,
    )
    schema = tools[0]["input_schema"]
    assert schema["type"] == "object"
    assert "arguments" in schema["properties"]
    assert schema["required"] == ["arguments"]
    assert schema["additionalProperties"] is False
    fa = tools[1]["input_schema"]
    assert "report" in fa["properties"]
    assert fa["required"] == ["report"]


# --------------------------------------------------------------------------- #
# StubAgent contract                                                          #
# --------------------------------------------------------------------------- #


def test_stub_agent_returns_scripted_steps_in_order() -> None:
    stub = StubAgent(
        steps=[
            ToolCall(id="t1", name="customer_data__get_customer", arguments={}),
            FinalAnswer(report={"verdict": "low_risk"}),
        ]
    )
    first = stub(skill_md="x", alert={}, tools=[], tool_results=[])
    assert isinstance(first, ToolCall)
    assert first.name == "customer_data__get_customer"
    second = stub(skill_md="x", alert={}, tools=[], tool_results=[])
    assert isinstance(second, FinalAnswer)
    assert second.report == {"verdict": "low_risk"}


def test_stub_agent_records_what_it_was_called_with() -> None:
    stub = StubAgent(steps=[FinalAnswer(report={})])
    stub(
        skill_md="SOME SKILL CONTENT",
        alert={"alert_id": "a-1"},
        tools=[{"name": "customer_data__get_customer"}],
        tool_results=[],
    )
    assert stub.calls == [
        {
            "skill_md_len": len("SOME SKILL CONTENT"),
            "alert": {"alert_id": "a-1"},
            "tool_names": ["customer_data__get_customer"],
            "tool_results_count": 0,
        }
    ]


def test_stub_agent_raises_when_run_past_end() -> None:
    stub = StubAgent(steps=[])
    with pytest.raises(IndexError):
        stub(skill_md="x", alert={}, tools=[], tool_results=[])


# --------------------------------------------------------------------------- #
# Runner: smoke test against clean_customer.yaml                              #
# --------------------------------------------------------------------------- #


def test_harness_drives_clean_customer_smoke(
    inbound_keys: tuple[Path, Path],
    gateway_client: TestClient,
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    """**Load-bearing US-029 AC**: harness drives the orchestrator
    against the mock stack and yields a trace consumable by the
    scorers."""
    inbound_priv, _ = inbound_keys
    trace_id = "trace-clean-smoke"
    factory = _factory(inbound_priv=inbound_priv, trace_id=trace_id)

    dataset = validate_dataset_file(CLEAN_DATASET)

    final_report = {
        "alert_id": dataset.input_alert.alert_id,
        "customer_id": dataset.input_alert.customer_id,
        "verdict": "low_risk",
        "summary": "Routine review; no adverse signals observed.",
        "evidence": [
            {
                "claim": "customer profile retrieved with kyc_status=verified",
                "value": "verified",
                "citation": {
                    "subskill": "gather-customer-profile",
                    "server": "customer_data",
                    "tool": "get_customer",
                    "field": "kyc_status",
                },
            }
        ],
        "recommended_actions": [],
        "evidence_gaps": [],
    }

    stub = StubAgent(
        steps=[
            ToolCall(
                id="t1",
                name="customer_data__get_customer",
                arguments={
                    "arguments": {
                        "customer_id": dataset.input_alert.customer_id,
                        "scenario": dataset.scenario,
                    }
                },
            ),
            ToolCall(
                id="t2",
                name="customer_data__list_accounts",
                arguments={
                    "arguments": {
                        "customer_id": dataset.input_alert.customer_id,
                        "scenario": dataset.scenario,
                    }
                },
            ),
            ToolCall(
                id="t3",
                name="customer_data__get_device_history",
                arguments={
                    "arguments": {
                        "customer_id": dataset.input_alert.customer_id,
                        "scenario": dataset.scenario,
                    }
                },
            ),
            FinalAnswer(report=final_report),
        ]
    )

    result = run_dataset(
        dataset,
        skill_path=ORCHESTRATOR_SKILL,
        agent=stub,
        http_client=gateway_client,
        gateway_url="",  # TestClient ignores base; just use the path.
        paseto_factory=factory,
        trace_id=trace_id,
        sub="alice@example.com",
    )

    # The harness loop terminated cleanly with a final report.
    assert result.terminated == "final_answer"
    assert result.report is not None
    assert result.report["verdict"] == dataset.expected_verdict == "low_risk"
    assert result.steps_used == 4  # 3 tool calls + 1 final answer

    # Every invocation is status=ok and matches expected_tool_calls.
    assert len(result.invocations) == 3
    pairs = {(inv.server, inv.tool) for inv in result.invocations}
    expected_pairs = {tc.as_pair() for tc in dataset.expected_tool_calls}
    assert pairs == expected_pairs
    for inv in result.invocations:
        assert inv.status == "ok", inv
        assert inv.http_status == 200
        assert inv.deny_reason is None

    # Audit slice filtered by trace_id pulls back exactly those rows.
    assert len(result.audit_rows) == 3
    for row in result.audit_rows:
        assert row["status"] == "ok"
        assert row["trace_id"] == trace_id
        assert row["server"] == "customer_data"

    # Trace is consumable by the US-027 scorers.
    correctness = score_tool_correctness(dataset, result.audit_rows)
    assert correctness.passed is True
    assert correctness.score == 1.0
    ordering = score_tool_ordering(dataset, result.audit_rows)
    # clean_customer has no ordering constraints — a zero-constraint
    # dataset scores 1.0 and passes trivially.
    assert ordering.passed is True
    assert ordering.score == 1.0


# --------------------------------------------------------------------------- #
# Runner: unit-level behaviors                                                #
# --------------------------------------------------------------------------- #


def test_runner_terminates_on_max_steps(
    inbound_keys: tuple[Path, Path],
    gateway_client: TestClient,
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, _ = inbound_keys
    trace_id = "trace-max-steps"
    factory = _factory(inbound_priv=inbound_priv, trace_id=trace_id)
    dataset = validate_dataset_file(CLEAN_DATASET)

    # Script the agent to keep issuing the same valid call forever; we
    # cap at max_steps=2 and verify the harness gives up cleanly.
    steps: list[Any] = [
        ToolCall(
            id=f"t{i}",
            name="customer_data__get_customer",
            arguments={
                "arguments": {
                    "customer_id": dataset.input_alert.customer_id,
                    "scenario": dataset.scenario,
                }
            },
        )
        for i in range(10)
    ]
    stub = StubAgent(steps=steps)

    result = run_dataset(
        dataset,
        skill_path=ORCHESTRATOR_SKILL,
        agent=stub,
        http_client=gateway_client,
        gateway_url="",
        paseto_factory=factory,
        trace_id=trace_id,
        sub="alice@example.com",
        max_steps=2,
    )

    assert result.terminated == "max_steps"
    assert result.report is None
    assert result.steps_used == 2
    assert len(result.invocations) == 2


def test_runner_records_unknown_tool_without_calling_gateway(
    inbound_keys: tuple[Path, Path],
    gateway_client: TestClient,
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, _ = inbound_keys
    trace_id = "trace-unknown-tool"
    factory = _factory(inbound_priv=inbound_priv, trace_id=trace_id)
    dataset = validate_dataset_file(CLEAN_DATASET)

    stub = StubAgent(
        steps=[
            ToolCall(id="t1", name="not_a_real_tool", arguments={}),
            FinalAnswer(report={"verdict": "low_risk"}),
        ]
    )

    result = run_dataset(
        dataset,
        skill_path=ORCHESTRATOR_SKILL,
        agent=stub,
        http_client=gateway_client,
        gateway_url="",
        paseto_factory=factory,
        trace_id=trace_id,
        sub="alice@example.com",
    )

    assert result.terminated == "final_answer"
    assert len(result.invocations) == 1
    inv = result.invocations[0]
    assert inv.status == "unknown_tool"
    assert inv.server is None
    assert inv.tool is None
    assert inv.http_status is None
    # The gateway was never called — no audit row landed.
    assert result.audit_rows == []


def test_runner_propagates_agent_error(
    inbound_keys: tuple[Path, Path],
    gateway_client: TestClient,
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, _ = inbound_keys
    trace_id = "trace-agent-error"
    factory = _factory(inbound_priv=inbound_priv, trace_id=trace_id)
    dataset = validate_dataset_file(CLEAN_DATASET)

    def _boom(
        *,
        skill_md: str,
        alert: Any,
        tools: Any,
        tool_results: Any,
    ) -> Any:
        raise RuntimeError("agent went boom")

    result = run_dataset(
        dataset,
        skill_path=ORCHESTRATOR_SKILL,
        agent=_boom,
        http_client=gateway_client,
        gateway_url="",
        paseto_factory=factory,
        trace_id=trace_id,
        sub="alice@example.com",
    )

    assert result.terminated == "agent_error"
    assert result.report is None
    assert result.invocations == []
    assert result.agent_calls == [{"step": 1, "error": "agent went boom"}]


def test_runner_rejects_max_steps_zero(
    inbound_keys: tuple[Path, Path],
    gateway_client: TestClient,
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    inbound_priv, _ = inbound_keys
    trace_id = "trace-rej"
    factory = _factory(inbound_priv=inbound_priv, trace_id=trace_id)
    dataset = validate_dataset_file(CLEAN_DATASET)

    with pytest.raises(ValueError, match="max_steps must be positive"):
        run_dataset(
            dataset,
            skill_path=ORCHESTRATOR_SKILL,
            agent=StubAgent(steps=[]),
            http_client=gateway_client,
            gateway_url="",
            paseto_factory=factory,
            trace_id=trace_id,
            sub="alice@example.com",
            max_steps=0,
        )


def test_runner_audit_slice_filters_by_trace_id(
    inbound_keys: tuple[Path, Path],
    gateway_client: TestClient,
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    """Two consecutive runs land in the same audit DB; each
    HarnessResult MUST contain only its own rows."""
    inbound_priv, _ = inbound_keys
    dataset = validate_dataset_file(CLEAN_DATASET)
    final = FinalAnswer(report={"verdict": "low_risk"})

    def _one_call_run(trace_id: str) -> HarnessResult:
        factory = _factory(inbound_priv=inbound_priv, trace_id=trace_id)
        stub = StubAgent(
            steps=[
                ToolCall(
                    id="t1",
                    name="customer_data__get_customer",
                    arguments={
                        "arguments": {
                            "customer_id": dataset.input_alert.customer_id,
                            "scenario": dataset.scenario,
                        }
                    },
                ),
                final,
            ]
        )
        return run_dataset(
            dataset,
            skill_path=ORCHESTRATOR_SKILL,
            agent=stub,
            http_client=gateway_client,
            gateway_url="",
            paseto_factory=factory,
            trace_id=trace_id,
            sub="alice@example.com",
        )

    r1 = _one_call_run("trace-iso-1")
    r2 = _one_call_run("trace-iso-2")

    assert {row["trace_id"] for row in r1.audit_rows} == {"trace-iso-1"}
    assert {row["trace_id"] for row in r2.audit_rows} == {"trace-iso-2"}
    # Two distinct rows in the global audit log, one per run.
    memory_audit_backend.flush()
    all_rows = memory_audit_backend.query(sub="alice@example.com")
    trace_ids = {row["trace_id"] for row in all_rows}
    assert trace_ids == {"trace-iso-1", "trace-iso-2"}


# --------------------------------------------------------------------------- #
# Defaults + contracts                                                        #
# --------------------------------------------------------------------------- #


def test_default_max_steps_matches_constant() -> None:
    assert DEFAULT_MAX_STEPS == 16
    assert DEFAULT_MAX_STEPS > 0


def test_tool_invocation_is_frozen() -> None:
    inv = ToolInvocation(
        step=1,
        tool_use_id="t1",
        tool_name="customer_data__get_customer",
        server="customer_data",
        tool="get_customer",
        arguments={},
        status="ok",
        http_status=200,
        result=None,
    )
    # Frozen dataclasses raise FrozenInstanceError (which is a
    # dataclasses.FrozenInstanceError, subclass of AttributeError).
    from dataclasses import FrozenInstanceError

    with pytest.raises(FrozenInstanceError):
        inv.step = 2  # type: ignore[misc]


def test_harness_result_dataclass_has_expected_fields() -> None:
    result = HarnessResult(
        dataset_id="x",
        trace_id="t",
        invocations=[],
        audit_rows=[],
        report=None,
        terminated="final_answer",
        steps_used=0,
    )
    # Fields that the eval runner (US-030) will key off.
    assert result.dataset_id == "x"
    assert result.trace_id == "t"
    assert result.invocations == []
    assert result.audit_rows == []
    assert result.report is None
    assert result.terminated == "final_answer"
    assert result.steps_used == 0
    assert result.agent_calls == []


def test_agent_protocol_satisfied_by_callable() -> None:
    from evals.harness.agent import Agent

    def _shaped(
        *,
        skill_md: str,
        alert: Any,
        tools: Any,
        tool_results: Any,
    ) -> FinalAnswer:
        return FinalAnswer(report={})

    # Protocol is runtime_checkable; a stub callable with the right
    # keywords is a valid Agent.
    assert isinstance(_shaped, Agent)
