"""OpenTelemetry tracing helpers for every hop in the fraud-copilot stack.

US-022 wires spans across the chain plugin -> auth gateway -> MCP gateway ->
downstream MCP servers -> mock APIs. The exporter is configurable via
``OTEL_EXPORTER_OTLP_ENDPOINT``; the default in dev is a stdout
``ConsoleSpanExporter`` so contributors can see spans without standing up an
OTel collector.

This module is the single owner of the global ``TracerProvider`` for the
process. It is intentionally idempotent: calling :func:`configure_tracing`
twice is a no-op (the existing provider is reused), so each FastAPI
app-factory can call it without worrying about ordering.

Span-attribute policy (PRD §6.4):

* MUST include: ``mcp.server``, ``mcp.tool``, ``user.role``.
* MUST NOT include: ``user.email``, ``user.sub`` (PII boundary — the audit
  log is the system of record for identity; spans must be safe to ship to a
  shared OTel collector).
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from opentelemetry import trace as trace_api
from opentelemetry.context import attach, detach
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
    SpanExporter,
)
from opentelemetry.trace import (
    NonRecordingSpan,
    SpanContext,
    TraceFlags,
    set_span_in_context,
)

if TYPE_CHECKING:
    from fastapi import FastAPI

__all__ = [
    "ATTR_MCP_SERVER",
    "ATTR_MCP_TOOL",
    "ATTR_USER_ROLE",
    "FORBIDDEN_ATTRIBUTES",
    "configure_tracing",
    "get_tracer",
    "instrument_fastapi",
    "tool_span_attributes",
    "trace_id_to_int",
    "trace_context_from_id",
]

_LOG = logging.getLogger(__name__)

# Stable span-attribute keys (PRD §6.4). Don't rename without updating
# config/grafana/dashboards/* in US-023 — these are the join keys for the
# operator dashboards.
ATTR_MCP_SERVER = "mcp.server"
ATTR_MCP_TOOL = "mcp.tool"
ATTR_USER_ROLE = "user.role"

# Attribute keys that MUST NOT appear on any emitted span. Enforced by the
# tests in tests/test_otel.py and re-checked at attribute-application time
# in :func:`tool_span_attributes`.
FORBIDDEN_ATTRIBUTES: frozenset[str] = frozenset({"user.email", "user.sub"})


_provider_lock = threading.Lock()
_provider_configured = False


def _build_exporter(endpoint: str | None) -> SpanExporter:
    """Pick an exporter based on ``OTEL_EXPORTER_OTLP_ENDPOINT``.

    Default (no endpoint configured): :class:`ConsoleSpanExporter` so dev
    contributors get spans on stdout without running a collector.

    Endpoint configured: HTTP OTLP exporter (the gRPC variant requires a
    different protobuf path and adds a heavier transport dep — HTTP is the
    safer default and matches the ``opentelemetry-exporter-otlp`` extras we
    pin in pyproject.toml).
    """
    if not endpoint:
        return ConsoleSpanExporter()
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
    except ImportError:  # pragma: no cover - exporter package missing
        _LOG.warning(
            "OTLP HTTP exporter unavailable; falling back to ConsoleSpanExporter"
        )
        return ConsoleSpanExporter()
    return OTLPSpanExporter(endpoint=endpoint)


def _sdk_disabled() -> bool:
    """Return whether tracing exports should be suppressed.

    Honored env var: ``FRAUD_OTEL_NOOP`` (truthy disables). When disabled,
    :func:`configure_tracing` installs a bare :class:`TracerProvider` with
    **no span processors** so spans are recorded (the SDK still creates
    real ``Span`` objects, which is important for tests that monkey-patch
    in their own processor) but never exported anywhere.

    We intentionally do NOT key off ``OTEL_SDK_DISABLED`` — that standard
    OTel env var swaps in a ``NoOpTracer`` and any subsequent attempt to
    attach a processor is silently ignored, which breaks the in-memory
    exporter pattern the OTel tests rely on. Suppressing exports without
    disabling span recording is the right shape for "I want quiet logs
    during tests but I want tests to be able to opt into recording."
    """
    return os.environ.get("FRAUD_OTEL_NOOP", "").lower() in {"true", "1", "yes"}


def configure_tracing(
    service_name: str,
    *,
    exporter: SpanExporter | None = None,
    use_batch_processor: bool | None = None,
) -> TracerProvider:
    """Install a global :class:`TracerProvider` for the current process.

    Idempotent: subsequent calls return the already-installed provider so each
    FastAPI app factory in the stack can call this freely. The first caller's
    ``service_name`` wins (subsequent service names are recorded on per-span
    ``service.name`` resource attributes when needed).

    Args:
        service_name: Logical name for the running service (e.g.
            ``"fraud-auth-gateway"``). Lands in the ``service.name`` resource
            attribute.
        exporter: Optional explicit exporter. Tests pass a recording exporter
            to assert on emitted spans; production leaves this ``None`` and
            lets the ``OTEL_EXPORTER_OTLP_ENDPOINT`` env var pick.
        use_batch_processor: If ``True`` use :class:`BatchSpanProcessor`,
            otherwise :class:`SimpleSpanProcessor` (synchronous, easier for
            tests). Default: ``True`` when ``exporter`` is ``None``, ``False``
            when an explicit exporter is passed (so tests see spans
            immediately).
    """
    global _provider_configured

    with _provider_lock:
        existing = trace_api.get_tracer_provider()
        if isinstance(existing, TracerProvider):
            # OTel's global TracerProvider can only be set once per process —
            # a second ``set_tracer_provider`` is silently ignored with a
            # warning. If something already installed an SDK provider, reuse
            # it rather than try (and fail) to replace it.
            _provider_configured = True
            return existing

        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)

        if exporter is None and _sdk_disabled():
            # No-op provider: keep tracers callable but don't export.
            trace_api.set_tracer_provider(provider)
            _provider_configured = True
            return provider

        if exporter is None:
            endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
            exporter = _build_exporter(endpoint or None)
            if use_batch_processor is None:
                use_batch_processor = True
        elif use_batch_processor is None:
            use_batch_processor = False

        processor: BatchSpanProcessor | SimpleSpanProcessor
        if use_batch_processor:
            processor = BatchSpanProcessor(exporter)
        else:
            processor = SimpleSpanProcessor(exporter)
        provider.add_span_processor(processor)
        trace_api.set_tracer_provider(provider)
        _provider_configured = True
        return provider


def _reset_for_tests() -> None:
    """Forget the configured-provider sentinel.

    Tests that swap exporters need to start from a clean slate; production
    code must never call this.
    """
    global _provider_configured
    with _provider_lock:
        _provider_configured = False


def get_tracer(name: str) -> trace_api.Tracer:
    """Shortcut for ``trace_api.get_tracer(name)``."""
    return trace_api.get_tracer(name)


def tool_span_attributes(
    *,
    server: str | None = None,
    tool: str | None = None,
    role: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the standard span-attribute dict for a tool / endpoint span.

    Drops keys with ``None`` values so spans only carry what's known. Raises
    ``ValueError`` if a caller passes any of the forbidden PII keys via
    ``extra`` — defense in depth on top of the linter / test sweep.
    """
    attrs: dict[str, Any] = {}
    if server is not None:
        attrs[ATTR_MCP_SERVER] = server
    if tool is not None:
        attrs[ATTR_MCP_TOOL] = tool
    if role is not None:
        attrs[ATTR_USER_ROLE] = role
    if extra:
        forbidden = FORBIDDEN_ATTRIBUTES.intersection(extra)
        if forbidden:
            raise ValueError(
                f"span attribute(s) {sorted(forbidden)} are not allowed on "
                "OTel spans (PII boundary — PRD §6.4)"
            )
        attrs.update(extra)
    return attrs


def trace_id_to_int(trace_id: str) -> int | None:
    """Map the PASETO ``trace_id`` claim to an OTel-compatible 128-bit integer.

    The PASETO claim is a 32-char hex string (16 random bytes, see
    :func:`gateways.common.paseto._new_trace_id`). OTel trace IDs are 16-byte
    integers. Anything else returns ``None`` (caller falls back to a fresh
    trace ID for the span).
    """
    if not trace_id or not isinstance(trace_id, str):
        return None
    cleaned = trace_id.replace("-", "")
    if len(cleaned) != 32:
        return None
    try:
        value = int(cleaned, 16)
    except ValueError:
        return None
    if value == 0:
        return None
    return value


def trace_context_from_id(trace_id: str) -> Any:
    """Build an OTel ``Context`` rooted at the PASETO trace_id.

    Returns the OTel ``Context`` object on success (suitable for
    ``tracer.start_as_current_span(..., context=ctx)``) or ``None`` if the
    PASETO trace_id is malformed. Spans started under this context will share
    the trace ID so plugin -> gateway -> server -> mock chain into one trace.
    """
    int_trace_id = trace_id_to_int(trace_id)
    if int_trace_id is None:
        return None
    span_ctx = SpanContext(
        trace_id=int_trace_id,
        span_id=int.from_bytes(os.urandom(8), "big") or 1,
        is_remote=True,
        trace_flags=TraceFlags(TraceFlags.SAMPLED),
    )
    return set_span_in_context(NonRecordingSpan(span_ctx))


@contextmanager
def _maybe_attach_context(ctx: Any) -> Iterator[None]:
    """Attach ``ctx`` if non-None; no-op if it's ``None``."""
    if ctx is None:
        yield
        return
    token = attach(ctx)
    try:
        yield
    finally:
        detach(token)


def instrument_fastapi(
    app: FastAPI,
    *,
    service_name: str,
) -> None:
    """Apply :class:`FastAPIInstrumentor` to ``app`` and ensure tracing is configured.

    Calling this on every FastAPI app in the stack means every HTTP hop
    automatically emits a server span. Span-attribute hygiene is enforced by
    the request hook below which strips any forbidden keys before export
    (defense in depth — the instrumentor itself doesn't set
    ``user.email``/``user.sub`` by default but a future upgrade could).
    """
    configure_tracing(service_name)
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    except ImportError:  # pragma: no cover
        _LOG.warning("opentelemetry-instrumentation-fastapi missing; skipping")
        return

    instrumentor = FastAPIInstrumentor()
    # Only instrument once per app — the instrumentor is idempotent per-app
    # but logs a warning on double-instrumentation; suppress that.
    if getattr(app, "_otel_instrumented", False):
        return
    instrumentor.instrument_app(app)
    app._otel_instrumented = True  # type: ignore[attr-defined]
