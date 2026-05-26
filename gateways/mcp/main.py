"""MCP Gateway — verifies PASETO, enforces RBAC, audits, forwards to downstream.

Speaks the MCP "streamable HTTP" transport: a single endpoint that accepts
JSON-RPC 2.0 requests (``tools/list`` and ``tools/call``) and returns JSON-RPC
responses. The gateway:

1. Verifies the inbound PASETO using the auth gateway's verification key
   (US-002 / US-004). Expired or invalid tokens → HTTP 401.
2. Rejects replayed ``jti`` values via an in-memory LRU
   (capacity ≥ 10000).
3. Enforces ``allowed_servers`` / ``allowed_tools`` from the embedded RBAC
   snapshot. Disallowed calls return HTTP 403 with a structured
   ``deny_reason`` body.
4. Re-signs a fresh service-to-service PASETO (60-sec TTL, separate keypair)
   and forwards the JSON-RPC payload to the configured downstream MCP server
   over HTTP.
5. Emits one audit event per call (status ``"ok"``, ``"denied"``, or
   ``"error"``).

The implementation is intentionally a single small file plus
``replay_cache.py`` — well under the 500-LOC budget mandated by US-007.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

import httpx
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from gateways.common import audit
from gateways.common.audit import AuditEvent
from gateways.common.otel import (
    get_tracer,
    instrument_fastapi,
    tool_span_attributes,
    trace_context_from_id,
)
from gateways.common.paseto import (
    Claims,
    ExpiredTokenError,
    InvalidTokenError,
    MalformedTokenError,
    _new_trace_id,
    mint,
    verify,
)
from gateways.mcp.replay_cache import ReplayCache

__all__ = [
    "create_app",
    "build_default_app",
    "DenyReason",
    "DEFAULT_SERVICE_TTL_SECONDS",
]

_LOG = logging.getLogger(__name__)

DEFAULT_SERVICE_TTL_SECONDS = 60  # PRD: 60s service-to-service PASETO TTL
DEFAULT_REPLAY_CAPACITY = 10_000  # PRD: in-memory LRU >=10000
WILDCARD = "*"

# JSON-RPC error codes (subset we use).
_JSONRPC_PARSE_ERROR = -32700
_JSONRPC_INVALID_REQUEST = -32600
_JSONRPC_METHOD_NOT_FOUND = -32601
_JSONRPC_INVALID_PARAMS = -32602
_JSONRPC_INTERNAL_ERROR = -32603


class DenyReason:
    """Stable string codes for the ``deny_reason`` field.

    These values land in the Grafana dashboard (US-023) and the audit log;
    keep them stable across versions.
    """

    TOKEN_MISSING = "token_missing"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_INVALID = "token_invalid"
    TOKEN_REPLAY = "token_replay"
    SERVER_NOT_ALLOWED = "server_not_allowed"
    TOOL_NOT_ALLOWED = "tool_not_allowed"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"
    DOWNSTREAM_ERROR = "downstream_error"


@dataclass(frozen=True)
class _Allowed:
    """Result of an RBAC check."""

    allowed: bool
    deny_reason: str | None = None


def _resolve_downstream(
    server: str, url_map: Mapping[str, str], fallback: str | None
) -> str | None:
    """Pick the downstream base URL for ``server``.

    The per-server map wins when the entry exists; otherwise ``fallback`` is
    used. Returning ``None`` means the gateway is misconfigured for this
    server and the caller should surface a structured error rather than
    crashing.
    """
    if server in url_map:
        return url_map[server]
    return fallback


def _check_tool_allowed(claims: Claims, server: str, tool: str) -> _Allowed:
    """Return whether ``claims`` permits calling ``server.tool``."""
    top = claims.allowed_tools.get(WILDCARD)
    if top is not None and WILDCARD in top:
        return _Allowed(True)
    if server not in claims.allowed_servers and WILDCARD not in claims.allowed_servers:
        return _Allowed(False, DenyReason.SERVER_NOT_ALLOWED)
    per_server = claims.allowed_tools.get(server)
    if per_server is None:
        return _Allowed(False, DenyReason.TOOL_NOT_ALLOWED)
    if WILDCARD in per_server or tool in per_server:
        return _Allowed(True)
    return _Allowed(False, DenyReason.TOOL_NOT_ALLOWED)


def _result_hash(result: Any) -> str:
    try:
        encoded = json.dumps(result, sort_keys=True, default=str).encode("utf-8")
    except (TypeError, ValueError):
        encoded = str(result).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _parse_exp_to_epoch(exp: str) -> float:
    """Parse the ISO-8601 ``exp`` claim into epoch seconds; fallback to now+TTL."""
    try:
        from datetime import datetime

        dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        return dt.timestamp()
    except (ValueError, AttributeError):
        return time.time() + DEFAULT_SERVICE_TTL_SECONDS


def _jsonrpc_error(
    rpc_id: Any, code: int, message: str, *, data: Any = None
) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": rpc_id, "error": err}


def _deny_body(rpc_id: Any, deny_reason: str, detail: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {
            "code": _JSONRPC_INVALID_REQUEST,
            "message": detail,
            "data": {"deny_reason": deny_reason},
        },
    }


def create_app(
    *,
    downstream_url: str | None = None,
    downstream_urls: Mapping[str, str] | None = None,
    service_private_key_path: Path | str,
    inbound_public_key_path: Path | str,
    http_client: httpx.AsyncClient | None = None,
    replay_cache: ReplayCache | None = None,
    service_ttl_seconds: int = DEFAULT_SERVICE_TTL_SECONDS,
    request_timeout_seconds: float = 10.0,
) -> FastAPI:
    """Build the MCP gateway FastAPI app.

    Args:
        downstream_url: Single-host base URL of a downstream MCP server. The
            gateway POSTs JSON-RPC payloads to ``f"{downstream_url}/{server}"``.
            Used when every MCP server is reachable on the same base URL
            (one-server stacks; reverse-proxied stacks).
        downstream_urls: Per-server URL map (``{"customer_data": "http://...:8002"}``).
            When set, the gateway picks the entry for the requested server and
            POSTs to ``f"{url}/{server}"``. The 14-service compose (US-024)
            uses this shape because each MCP server has its own hostname.
            ``downstream_url`` and ``downstream_urls`` may both be supplied —
            the map wins when the key exists, otherwise the single URL is the
            fallback.
        service_private_key_path: Ed25519 PEM used to mint the re-signed
            service-to-service PASETO. **Separate** from the auth gateway's
            keypair.
        inbound_public_key_path: Ed25519 PEM used to verify inbound user
            PASETOs (fetched from the auth gateway's
            ``/.well-known/paseto-key``).
        http_client: Optional pre-built ``httpx.AsyncClient`` — tests inject a
            transport-mounted client; production lets the factory build one.
        replay_cache: Optional pre-built replay cache. Defaults to a fresh
            ``ReplayCache(capacity=10_000)``.
        service_ttl_seconds: TTL for the minted service-to-service PASETO.
        request_timeout_seconds: Timeout for the downstream HTTP call.
    """
    if downstream_url is None and not downstream_urls:
        raise ValueError(
            "create_app requires downstream_url or downstream_urls (or both)"
        )
    url_map: dict[str, str] = dict(downstream_urls or {})
    fallback_url = downstream_url
    cache = replay_cache or ReplayCache(capacity=DEFAULT_REPLAY_CAPACITY)
    owns_http_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=request_timeout_seconds)

    @asynccontextmanager
    async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if owns_http_client:
                await client.aclose()

    app = FastAPI(title="Fraud Copilot MCP Gateway", version="0.1.0", lifespan=_lifespan)
    instrument_fastapi(app, service_name="fraud-mcp-gateway")
    tracer = get_tracer(__name__)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/mcp/{server}")
    async def mcp_call(
        server: str,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> JSONResponse:
        body_bytes = await request.body()
        try:
            payload = json.loads(body_bytes) if body_bytes else {}
        except json.JSONDecodeError as exc:
            return JSONResponse(
                _jsonrpc_error(None, _JSONRPC_PARSE_ERROR, f"invalid json: {exc}"),
                status_code=400,
            )
        if not isinstance(payload, dict):
            return JSONResponse(
                _jsonrpc_error(None, _JSONRPC_INVALID_REQUEST, "payload not an object"),
                status_code=400,
            )
        rpc_id = payload.get("id")
        method = payload.get("method", "")
        params = payload.get("params") or {}

        # 1. PASETO verify.
        if not authorization or not authorization.lower().startswith("bearer "):
            return JSONResponse(
                _deny_body(rpc_id, DenyReason.TOKEN_MISSING, "missing bearer token"),
                status_code=401,
            )
        token = authorization.split(" ", 1)[1].strip()
        try:
            claims = verify(token, public_key_path=inbound_public_key_path)
        except ExpiredTokenError as exc:
            return JSONResponse(
                _deny_body(rpc_id, DenyReason.TOKEN_EXPIRED, str(exc)),
                status_code=401,
            )
        except (InvalidTokenError, MalformedTokenError) as exc:
            return JSONResponse(
                _deny_body(rpc_id, DenyReason.TOKEN_INVALID, str(exc)),
                status_code=401,
            )

        # 2. Replay prevention.
        exp_ts = _parse_exp_to_epoch(claims.exp)
        if cache.seen(claims.jti, exp_ts):
            return JSONResponse(
                _deny_body(rpc_id, DenyReason.TOKEN_REPLAY, "jti already seen"),
                status_code=401,
            )

        # 3. tools/list bypasses tool-level RBAC but still requires server access.
        if method == "tools/list":
            if (
                server not in claims.allowed_servers
                and WILDCARD not in claims.allowed_servers
                and claims.allowed_tools.get(WILDCARD) != [WILDCARD]
            ):
                _emit_audit(
                    claims=claims,
                    server=server,
                    tool="<list>",
                    args={},
                    status="denied",
                    deny_reason=DenyReason.SERVER_NOT_ALLOWED,
                    latency_ms=0,
                    result_hash="",
                )
                return JSONResponse(
                    _deny_body(
                        rpc_id,
                        DenyReason.SERVER_NOT_ALLOWED,
                        f"server '{server}' not allowed",
                    ),
                    status_code=403,
                )
            target = _resolve_downstream(server, url_map, fallback_url)
            if target is None:
                _emit_audit(
                    claims=claims,
                    server=server,
                    tool="<list>",
                    args={},
                    status="denied",
                    deny_reason=DenyReason.SERVER_NOT_ALLOWED,
                    latency_ms=0,
                    result_hash="",
                )
                return JSONResponse(
                    _deny_body(
                        rpc_id,
                        DenyReason.SERVER_NOT_ALLOWED,
                        f"no downstream configured for server '{server}'",
                    ),
                    status_code=404,
                )
            ctx = trace_context_from_id(claims.trace_id)
            with tracer.start_as_current_span(
                "mcp.gateway.tools_list",
                context=ctx,
                attributes=tool_span_attributes(
                    server=server,
                    tool="<list>",
                    role=",".join(claims.roles) or "none",
                ),
            ):
                return await _forward(
                    client=client,
                    downstream_url=target,
                    server=server,
                    tool="<list>",
                    args={},
                    payload=payload,
                    claims=claims,
                    service_private_key_path=service_private_key_path,
                    service_ttl_seconds=service_ttl_seconds,
                )

        if method != "tools/call":
            return JSONResponse(
                _jsonrpc_error(rpc_id, _JSONRPC_METHOD_NOT_FOUND, f"unsupported method: {method}"),
                status_code=400,
            )

        # 4. RBAC tool enforcement.
        if not isinstance(params, Mapping):
            return JSONResponse(
                _jsonrpc_error(rpc_id, _JSONRPC_INVALID_PARAMS, "params must be an object"),
                status_code=400,
            )
        tool = str(params.get("name") or "")
        args = params.get("arguments") or {}
        if not tool:
            return JSONResponse(
                _jsonrpc_error(rpc_id, _JSONRPC_INVALID_PARAMS, "missing tool name"),
                status_code=400,
            )

        check = _check_tool_allowed(claims, server, tool)
        if not check.allowed:
            assert check.deny_reason is not None
            _emit_audit(
                claims=claims,
                server=server,
                tool=tool,
                args=args if isinstance(args, dict) else {"_": args},
                status="denied",
                deny_reason=check.deny_reason,
                latency_ms=0,
                result_hash="",
            )
            return JSONResponse(
                _deny_body(
                    rpc_id,
                    check.deny_reason,
                    f"call to {server}.{tool} not permitted",
                ),
                status_code=403,
            )

        # 5. Forward to downstream.
        target = _resolve_downstream(server, url_map, fallback_url)
        if target is None:
            _emit_audit(
                claims=claims,
                server=server,
                tool=tool,
                args=args if isinstance(args, dict) else {"_": args},
                status="error",
                deny_reason=DenyReason.DOWNSTREAM_ERROR,
                latency_ms=0,
                result_hash="",
            )
            return JSONResponse(
                _jsonrpc_error(
                    rpc_id,
                    _JSONRPC_INTERNAL_ERROR,
                    f"no downstream configured for server '{server}'",
                    data={"deny_reason": DenyReason.DOWNSTREAM_ERROR},
                ),
                status_code=502,
            )
        ctx = trace_context_from_id(claims.trace_id)
        with tracer.start_as_current_span(
            "mcp.gateway.tool_call",
            context=ctx,
            attributes=tool_span_attributes(
                server=server,
                tool=tool,
                role=",".join(claims.roles) or "none",
            ),
        ):
            return await _forward(
                client=client,
                downstream_url=target,
                server=server,
                tool=tool,
                args=args if isinstance(args, dict) else {"_": args},
                payload=payload,
                claims=claims,
                service_private_key_path=service_private_key_path,
                service_ttl_seconds=service_ttl_seconds,
            )

    return app


async def _forward(
    *,
    client: httpx.AsyncClient,
    downstream_url: str,
    server: str,
    tool: str,
    args: dict[str, Any],
    payload: dict[str, Any],
    claims: Claims,
    service_private_key_path: Path | str,
    service_ttl_seconds: int,
) -> JSONResponse:
    """Mint a service token, forward the JSON-RPC payload, audit the outcome."""
    service_claims = Claims(
        sub=claims.sub,
        roles=list(claims.roles),
        allowed_servers=list(claims.allowed_servers),
        allowed_tools=dict(claims.allowed_tools),
        trace_id=claims.trace_id or _new_trace_id(),
        jti=uuid.uuid4().hex,
        human_approval=claims.human_approval,
    )
    service_token = mint(
        service_claims,
        ttl_seconds=service_ttl_seconds,
        private_key_path=service_private_key_path,
    )
    headers = {
        "authorization": f"Bearer {service_token}",
        "content-type": "application/json",
        "x-trace-id": claims.trace_id,
    }
    url = f"{downstream_url.rstrip('/')}/{server}"
    rpc_id = payload.get("id")
    started = time.perf_counter()
    try:
        resp = await client.post(url, json=payload, headers=headers)
    except httpx.HTTPError as exc:
        latency_ms = int((time.perf_counter() - started) * 1000)
        _emit_audit(
            claims=claims,
            server=server,
            tool=tool,
            args=args,
            status="error",
            deny_reason=DenyReason.DOWNSTREAM_ERROR,
            latency_ms=latency_ms,
            result_hash="",
        )
        return JSONResponse(
            _jsonrpc_error(
                rpc_id,
                _JSONRPC_INTERNAL_ERROR,
                f"downstream unreachable: {exc}",
                data={"deny_reason": DenyReason.DOWNSTREAM_ERROR},
            ),
            status_code=502,
        )

    latency_ms = int((time.perf_counter() - started) * 1000)
    status_code = resp.status_code
    try:
        body: Any = resp.json()
    except (ValueError, json.JSONDecodeError):
        body = {"text": resp.text}

    if status_code >= 500:
        _emit_audit(
            claims=claims,
            server=server,
            tool=tool,
            args=args,
            status="error",
            deny_reason=DenyReason.DOWNSTREAM_ERROR,
            latency_ms=latency_ms,
            result_hash=_result_hash(body),
        )
        return JSONResponse(
            _jsonrpc_error(
                rpc_id,
                _JSONRPC_INTERNAL_ERROR,
                f"downstream error {status_code}",
                data={"deny_reason": DenyReason.DOWNSTREAM_ERROR, "body": body},
            ),
            status_code=502,
        )

    if status_code >= 400:
        _emit_audit(
            claims=claims,
            server=server,
            tool=tool,
            args=args,
            status="error",
            deny_reason=DenyReason.DOWNSTREAM_ERROR,
            latency_ms=latency_ms,
            result_hash=_result_hash(body),
        )
        return JSONResponse(body, status_code=status_code)

    _emit_audit(
        claims=claims,
        server=server,
        tool=tool,
        args=args,
        status="ok",
        deny_reason=None,
        latency_ms=latency_ms,
        result_hash=_result_hash(body),
    )
    return JSONResponse(body, status_code=status_code)


def _emit_audit(
    *,
    claims: Claims,
    server: str,
    tool: str,
    args: dict[str, Any],
    status: str,
    deny_reason: str | None,
    latency_ms: int,
    result_hash: str,
) -> None:
    """Best-effort audit emission — never propagate audit failures to the caller."""
    try:
        audit.write_event(
            AuditEvent(
                sub=claims.sub,
                role=",".join(claims.roles),
                server=server,
                tool=tool,
                jti=claims.jti,
                trace_id=claims.trace_id,
                args_preview=args if isinstance(args, dict) else {"_": args},
                result_hash=result_hash,
                status=status,
                deny_reason=deny_reason,
                latency_ms=latency_ms,
            )
        )
    except Exception:  # pragma: no cover - defensive
        _LOG.exception("audit emission failed; continuing")


def build_default_app() -> FastAPI:
    """Construct the gateway from env vars (production entry point).

    Env vars:
        ``MCP_GATEWAY_DOWNSTREAM_URL``      — single base URL of a downstream
            MCP server. Backward-compat for the M0 stack which fronted only
            ``customer_data``. Used as the fallback when a server has no
            entry in ``MCP_GATEWAY_DOWNSTREAM_URLS``.
        ``MCP_GATEWAY_DOWNSTREAM_URLS``     — JSON-encoded ``{server: url}``
            map for the federated 14-service stack (US-024). Each MCP server
            has its own hostname; the gateway selects the entry matching the
            requested ``/{server}`` path. At least one of
            ``MCP_GATEWAY_DOWNSTREAM_URL`` or ``MCP_GATEWAY_DOWNSTREAM_URLS``
            must be set.
        ``MCP_GATEWAY_SERVICE_PRIVATE_KEY`` — PEM path for service-to-service mint.
        ``MCP_GATEWAY_INBOUND_PUBLIC_KEY``  — PEM path to verify inbound PASETOs.
    """
    downstream = os.environ.get("MCP_GATEWAY_DOWNSTREAM_URL", "")
    downstream_urls_raw = os.environ.get("MCP_GATEWAY_DOWNSTREAM_URLS", "")
    service_priv = os.environ.get("MCP_GATEWAY_SERVICE_PRIVATE_KEY", "")
    inbound_pub = os.environ.get("MCP_GATEWAY_INBOUND_PUBLIC_KEY", "")
    url_map: dict[str, str] = {}
    if downstream_urls_raw:
        try:
            parsed = json.loads(downstream_urls_raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"MCP_GATEWAY_DOWNSTREAM_URLS is not valid JSON: {exc}"
            ) from exc
        if not isinstance(parsed, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in parsed.items()
        ):
            raise RuntimeError(
                "MCP_GATEWAY_DOWNSTREAM_URLS must decode to a {str: str} map"
            )
        url_map = parsed
    if not (downstream or url_map) or not service_priv or not inbound_pub:
        raise RuntimeError(
            "MCP gateway env vars not configured "
            "(need at least one of MCP_GATEWAY_DOWNSTREAM_URL / "
            "MCP_GATEWAY_DOWNSTREAM_URLS, plus MCP_GATEWAY_SERVICE_PRIVATE_KEY "
            "and MCP_GATEWAY_INBOUND_PUBLIC_KEY)"
        )
    return create_app(
        downstream_url=downstream or None,
        downstream_urls=url_map or None,
        service_private_key_path=Path(service_priv),
        inbound_public_key_path=Path(inbound_pub),
    )
