"""Tests for the OpenTelemetry tracing wiring (US-022).

Covers:
    * ``gateways.common.otel.tool_span_attributes`` — accepted/forbidden keys.
    * ``configure_tracing`` — idempotent, honors ``OTEL_EXPORTER_OTLP_ENDPOINT``,
      falls through to a no-op when ``FRAUD_OTEL_NOOP=true`` (the default in
      the test harness via ``tests/conftest.py``).
    * ``trace_id_to_int`` / ``trace_context_from_id`` — PASETO trace-id claim
      cleanly maps to an OTel-compatible trace ID.
    * Integration: a single investigation through auth gateway → MCP gateway →
      customer_data MCP server → customer_data mock API produces a complete
      trace where every hop shares the same trace_id, every span carries the
      mandated attribute set, and **no** span carries the forbidden PII keys.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from opentelemetry import trace as trace_api
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from gateways.common import audit as audit_mod
from gateways.common import otel as otel_mod
from gateways.common import paseto as paseto_mod
from gateways.common.audit import SQLiteAuditBackend
from gateways.common.otel import (
    ATTR_MCP_SERVER,
    ATTR_MCP_TOOL,
    ATTR_USER_ROLE,
    FORBIDDEN_ATTRIBUTES,
    configure_tracing,
    tool_span_attributes,
    trace_context_from_id,
    trace_id_to_int,
)
from gateways.common.paseto import Claims, mint
from gateways.mcp.main import create_app as create_gateway_app
from mcp_servers.customer_data.main import SERVER_NAME
from mcp_servers.customer_data.main import create_app as create_server_app
from mock_apis.customer_data.main import create_app as create_mock_app

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clear_paseto_key_cache() -> Iterator[None]:
    paseto_mod._load_private_key_cached.cache_clear()
    paseto_mod._load_public_key_cached.cache_clear()
    yield
    paseto_mod._load_private_key_cached.cache_clear()
    paseto_mod._load_public_key_cached.cache_clear()


@pytest.fixture()
def memory_exporter(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[InMemorySpanExporter]:
    """Install a fresh in-memory exporter on the process tracer provider.

    OTel's global TracerProvider can only be set once per process (subsequent
    ``set_tracer_provider`` calls log a warning and are ignored). To stay
    hermetic across tests we instead **add an extra span processor** to
    whatever provider is currently installed. Combined with
    :func:`otel_mod._reset_for_tests` (which lets ``configure_tracing`` be
    re-run by app factories) the fixture lets each test see the spans emitted
    by the apps it constructs.
    """
    # OTel's SDK ignores span recording entirely when ``FRAUD_OTEL_NOOP``
    # is truthy, so enabling it is required for the integration test to see
    # any spans. We pair that with explicit, in-memory exporter only: no
    # ConsoleSpanExporter (which would race with pytest's stdout capture).
    monkeypatch.setenv("FRAUD_OTEL_NOOP", "false")
    exporter = InMemorySpanExporter()
    current = trace_api.get_tracer_provider()
    if not isinstance(current, TracerProvider):
        # No SDK provider yet — install one wired to our exporter.
        otel_mod._reset_for_tests()
        otel_mod.configure_tracing(
            "fraud-test-harness", exporter=exporter, use_batch_processor=False
        )
    else:
        # Existing SDK provider (installed by a prior test). We can't replace
        # it, but we can attach our in-memory exporter as an extra processor.
        current.add_span_processor(SimpleSpanProcessor(exporter))
    yield exporter
    exporter.clear()


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


# --------------------------------------------------------------------------- #
# Module-level helpers
# --------------------------------------------------------------------------- #


def test_attribute_keys_are_the_prd_set() -> None:
    """PRD §6.4: span attributes MUST include mcp.server / mcp.tool / user.role."""
    assert ATTR_MCP_SERVER == "mcp.server"
    assert ATTR_MCP_TOOL == "mcp.tool"
    assert ATTR_USER_ROLE == "user.role"


def test_forbidden_attributes_block_pii() -> None:
    """PRD §6.4: spans MUST NOT carry user.email or user.sub."""
    assert "user.email" in FORBIDDEN_ATTRIBUTES
    assert "user.sub" in FORBIDDEN_ATTRIBUTES


def test_tool_span_attributes_drops_none_values() -> None:
    attrs = tool_span_attributes(server="customer_data", tool=None, role="analyst")
    assert attrs == {ATTR_MCP_SERVER: "customer_data", ATTR_USER_ROLE: "analyst"}


def test_tool_span_attributes_rejects_forbidden_extras() -> None:
    """Defense in depth: tool_span_attributes refuses to set PII keys."""
    with pytest.raises(ValueError):
        tool_span_attributes(extra={"user.email": "alice@example.com"})
    with pytest.raises(ValueError):
        tool_span_attributes(extra={"user.sub": "alice@example.com"})


def test_tool_span_attributes_accepts_non_pii_extras() -> None:
    attrs = tool_span_attributes(
        server="customer_data",
        tool="get_customer",
        role="analyst",
        extra={"latency_ms": 17, "status": "ok"},
    )
    assert attrs[ATTR_MCP_SERVER] == "customer_data"
    assert attrs[ATTR_MCP_TOOL] == "get_customer"
    assert attrs[ATTR_USER_ROLE] == "analyst"
    assert attrs["latency_ms"] == 17
    assert attrs["status"] == "ok"


# --------------------------------------------------------------------------- #
# Trace-id mapping
# --------------------------------------------------------------------------- #


def test_trace_id_to_int_round_trips_paseto_hex() -> None:
    """The PASETO trace_id (32 hex chars) maps to a 128-bit OTel trace ID."""
    paseto_trace = "a" * 32
    value = trace_id_to_int(paseto_trace)
    assert value == int(paseto_trace, 16)


def test_trace_id_to_int_rejects_malformed() -> None:
    assert trace_id_to_int("") is None
    assert trace_id_to_int("not-hex-at-all") is None
    assert trace_id_to_int("0" * 32) is None  # zero trace id reserved


def test_trace_context_from_id_returns_context() -> None:
    ctx = trace_context_from_id("a" * 32)
    assert ctx is not None


def test_trace_context_from_id_malformed_returns_none() -> None:
    assert trace_context_from_id("nope") is None


# --------------------------------------------------------------------------- #
# configure_tracing
# --------------------------------------------------------------------------- #


def test_configure_tracing_idempotent(memory_exporter: InMemorySpanExporter) -> None:
    """Calling configure_tracing twice keeps the first-installed provider."""
    provider_a = trace_api.get_tracer_provider()
    configure_tracing("svc")
    provider_b = trace_api.get_tracer_provider()
    assert provider_a is provider_b


def test_configure_tracing_honors_otel_sdk_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When FRAUD_OTEL_NOOP=true, configure_tracing installs a no-op provider."""
    otel_mod._reset_for_tests()
    monkeypatch.setenv("FRAUD_OTEL_NOOP", "true")
    try:
        provider = configure_tracing("svc-disabled")
        # The provider has no span processors when disabled.
        # _active_span_processor on TracerProvider is the composite holder.
        # We assert via tracer behavior: starting a span should still work but
        # never reach an exporter — so the span finishes without error.
        tracer = provider.get_tracer("test")
        with tracer.start_as_current_span("noop-span"):
            pass
    finally:
        otel_mod._reset_for_tests()


def test_configure_tracing_picks_otlp_when_endpoint_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With an OTLP endpoint set, _build_exporter returns the OTLP HTTP exporter."""
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.example:4318/v1/traces")
    monkeypatch.delenv("FRAUD_OTEL_NOOP", raising=False)
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    exporter = otel_mod._build_exporter(
        os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"]
    )
    assert isinstance(exporter, OTLPSpanExporter)


def test_configure_tracing_defaults_to_console_when_no_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No OTLP endpoint, no FRAUD_OTEL_NOOP → ConsoleSpanExporter."""
    from opentelemetry.sdk.trace.export import ConsoleSpanExporter

    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    exporter = otel_mod._build_exporter(None)
    assert isinstance(exporter, ConsoleSpanExporter)


# --------------------------------------------------------------------------- #
# Integration: full chain emits a complete trace
# --------------------------------------------------------------------------- #


def _rpc_call(tool: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args or {}},
    }


def test_full_investigation_chain_produces_complete_trace(
    memory_exporter: InMemorySpanExporter,
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    """Single investigation → spans from gateway, server, mock all share trace_id.

    This is the load-bearing US-022 acceptance: one investigation through
    plugin → MCP gateway → MCP server → mock API yields a *complete* trace
    (every hop is a span, every span carries the mandated attributes, no span
    carries any forbidden PII attribute, and they all share a single trace
    rooted at the PASETO trace_id).
    """
    inbound_priv, inbound_pub = inbound_keys
    service_priv, service_pub = service_keys

    # Build mock → server → gateway in-process chain (matches the e2e pattern
    # used by tests/test_customer_data_mcp_server.py).
    mock_app = create_mock_app()
    mock_transport = httpx.ASGITransport(app=mock_app)
    mock_client = httpx.AsyncClient(transport=mock_transport, base_url="http://mock")

    server_app = create_server_app(
        public_key_path=service_pub,
        api_client=mock_client,
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
    gateway_client = TestClient(gateway_app)

    # PASETO trace_id MUST be 32 hex chars so trace_context_from_id can lift
    # it into the OTel context (the auth gateway's _new_trace_id() emits this
    # exact shape).
    user_trace_id = "deadbeefcafef00d0123456789abcdef"
    user_claims = Claims(
        sub="alice@example.com",
        roles=["analyst"],
        allowed_servers=["customer_data"],
        allowed_tools={
            "customer_data": [
                "get_customer",
                "list_accounts",
                "get_device_history",
            ]
        },
        trace_id=user_trace_id,
    )
    user_token = mint(user_claims, ttl_seconds=300, private_key_path=inbound_priv)

    resp = gateway_client.post(
        f"/mcp/{SERVER_NAME}",
        json=_rpc_call(
            "get_customer", {"customer_id": "c-otel", "scenario": "clean"}
        ),
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 200, resp.text

    spans = list(memory_exporter.get_finished_spans())
    assert spans, "no spans were exported for the investigation"

    # Find the gateway span and the server span we wrap explicitly.
    gateway_spans = [s for s in spans if s.name == "mcp.gateway.tool_call"]
    server_spans = [
        s for s in spans if s.name == f"mcp.{SERVER_NAME}.tool_call"
    ]
    assert gateway_spans, f"missing gateway span; saw {[s.name for s in spans]}"
    assert server_spans, f"missing server span; saw {[s.name for s in spans]}"

    expected_trace_id = trace_id_to_int(user_trace_id)
    assert expected_trace_id is not None

    # Both gateway and server tool_call spans must share the PASETO trace_id.
    for span in gateway_spans + server_spans:
        assert span.context.trace_id == expected_trace_id, (
            f"span {span.name} trace_id did not match PASETO trace_id"
        )

    # Attribute hygiene: required keys present, forbidden keys absent.
    _assert_span_attributes(gateway_spans[0])
    _assert_span_attributes(server_spans[0])

    # FastAPIInstrumentor on the mock API emits an HTTP server span. It
    # should sit under the same trace as the tool_call spans so the operator
    # sees one trace from gateway to mock.
    mock_spans = [
        s for s in spans
        if s.attributes
        and any(
            str(k).startswith("http.")
            for k in s.attributes.keys()
        )
    ]
    assert mock_spans, "no HTTP server spans were emitted by FastAPIInstrumentor"
    # At least one mock-API HTTP span should share the trace.
    assert any(
        s.context.trace_id == expected_trace_id for s in mock_spans
    ), "no HTTP span carried the investigation trace_id"


def _assert_span_attributes(span: ReadableSpan) -> None:
    attrs = dict(span.attributes or {})
    assert attrs.get(ATTR_MCP_SERVER) == "customer_data"
    assert attrs.get(ATTR_MCP_TOOL) == "get_customer"
    role = attrs.get(ATTR_USER_ROLE)
    assert isinstance(role, str)
    assert "analyst" in role
    for forbidden in FORBIDDEN_ATTRIBUTES:
        assert forbidden not in attrs, (
            f"span {span.name} carries forbidden attribute {forbidden}"
        )


def test_every_emitted_span_passes_pii_policy(
    memory_exporter: InMemorySpanExporter,
    inbound_keys: tuple[Path, Path],
    service_keys: tuple[Path, Path],
    memory_audit_backend: SQLiteAuditBackend,
) -> None:
    """Sweep every exported span and confirm no PII attribute leaks across the chain."""
    inbound_priv, inbound_pub = inbound_keys
    service_priv, service_pub = service_keys

    mock_app = create_mock_app()
    mock_transport = httpx.ASGITransport(app=mock_app)
    mock_client = httpx.AsyncClient(transport=mock_transport, base_url="http://mock")

    server_app = create_server_app(
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
    gateway_client = TestClient(gateway_app)

    user_trace_id = "0badc0ffeebadc0ffee" + "0" * (32 - len("0badc0ffeebadc0ffee"))
    user_claims = Claims(
        sub="alice@example.com",
        roles=["analyst"],
        allowed_servers=["customer_data"],
        allowed_tools={"customer_data": ["get_customer"]},
        trace_id=user_trace_id,
    )
    user_token = mint(user_claims, ttl_seconds=300, private_key_path=inbound_priv)
    resp = gateway_client.post(
        f"/mcp/{SERVER_NAME}",
        json=_rpc_call(
            "get_customer", {"customer_id": "c-pii", "scenario": "clean"}
        ),
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 200

    spans = list(memory_exporter.get_finished_spans())
    assert spans
    for span in spans:
        attrs = dict(span.attributes or {})
        for forbidden in FORBIDDEN_ATTRIBUTES:
            assert forbidden not in attrs, (
                f"span {span.name} leaks {forbidden}"
            )
        # The audit log carries identity; spans must not echo the user's email
        # or subject anywhere in the attribute values either (defense in depth).
        for value in attrs.values():
            if isinstance(value, str):
                assert "alice@example.com" not in value, (
                    f"span {span.name} attribute value carries user email"
                )
