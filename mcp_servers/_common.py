"""Shared JSON-RPC + service-PASETO pipeline for downstream MCP servers.

Lifted out of the four duplicated `mcp_servers/<name>/main.py` files
(`customer_data`, `transactions`, `kyc`, `sanctions`) when US-015 added a
fifth downstream (`osint`). The duplication crossed the consolidation
threshold during US-013; US-015 does the lift before adding the fifth copy,
which is also the right moment because US-016 (`case_actions`) needs an
extra middleware seam (the ``human_approval=true`` claim check) — adding
that to one shared factory beats wiring it into five separate copies.

The shared surface:

* :class:`JsonRpc` — error codes + helpers (``error()``, ``result()``).
* :func:`verify_service_paseto_header` — service PASETO bearer check.
* :func:`list_tools_response` — MCP wire shape for ``tools/list``.
* :func:`tool_result_to_mcp` — coerce ``FastMCP.ToolResult`` -> wire shape.
* :func:`create_jsonrpc_app` — higher-order factory that wires the whole
  pipeline (PASETO verify -> JSON-RPC dispatch -> upstream HTTP call ->
  tool-result coercion -> error mapping). Accepts an optional
  ``extra_validate`` callable so US-016 can drop in the human-approval
  check without duplicating the pipeline.

Each downstream server's ``main.py`` is now a thin shell: declare
constants, define ``build_mcp(api_client)`` for the tool registry, and call
``create_jsonrpc_app(...)``. See ``mcp_servers/customer_data/main.py`` for
the canonical thin shell.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

import httpx
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from fastmcp import FastMCP

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
    verify,
)

__all__ = [
    "JsonRpc",
    "ToolDispatchError",
    "create_jsonrpc_app",
    "list_tools_response",
    "tool_result_to_mcp",
    "verify_service_paseto_header",
]


class ToolDispatchError(Exception):
    """Tool intentionally rejected the call (e.g. allowlist deny).

    Raised by a tool's coroutine to short-circuit the dispatch with a
    structured JSON-RPC error rather than a generic 500. The shared
    pipeline catches this and emits
    ``{"jsonrpc":"2.0","id":...,"error":{"code":-32600,"message":<message>,"data":<data>}}``
    with the requested HTTP status code.

    Use cases:
    * Outbound URL not in allowlist (osint server, US-015).
    * Caller-provided params fail a tool-internal validation that wants a
      caller-facing 4xx rather than a 5xx.
    """

    def __init__(
        self, message: str, *, status_code: int = 400, data: Any = None
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.data = data

_LOG = logging.getLogger(__name__)


class JsonRpc:
    """JSON-RPC 2.0 error codes + response helpers.

    Codes match the subset used across every downstream server.
    """

    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603

    @staticmethod
    def error(
        rpc_id: Any, code: int, message: str, *, data: Any = None
    ) -> dict[str, Any]:
        err: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": "2.0", "id": rpc_id, "error": err}

    @staticmethod
    def result(rpc_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def verify_service_paseto_header(
    authorization: str | None, public_key_path: Path | str
) -> Claims | JSONResponse:
    """Validate the bearer PASETO carried in ``Authorization``.

    Returns the verified :class:`Claims` on success, or a 401
    :class:`JSONResponse` describing the failure. The caller is responsible
    for returning the response unchanged when this function returns one.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        return JSONResponse(
            JsonRpc.error(None, JsonRpc.INVALID_REQUEST, "missing bearer token"),
            status_code=401,
        )
    token = authorization.split(" ", 1)[1].strip()
    try:
        return verify(token, public_key_path=public_key_path)
    except ExpiredTokenError as exc:
        return JSONResponse(
            JsonRpc.error(None, JsonRpc.INVALID_REQUEST, f"token expired: {exc}"),
            status_code=401,
        )
    except (InvalidTokenError, MalformedTokenError) as exc:
        return JSONResponse(
            JsonRpc.error(None, JsonRpc.INVALID_REQUEST, f"invalid token: {exc}"),
            status_code=401,
        )


async def list_tools_response(mcp: FastMCP) -> dict[str, Any]:
    """Return ``{"tools": [...]}`` shaped per the MCP spec (subset)."""
    tools = await mcp.list_tools(run_middleware=False)
    out: list[dict[str, Any]] = []
    for tool in tools:
        out.append(
            {
                "name": tool.name,
                "description": tool.description or "",
                "inputSchema": tool.parameters,
            }
        )
    return {"tools": out}


def tool_result_to_mcp(tool_result: Any) -> dict[str, Any]:
    """Coerce a FastMCP ``ToolResult`` into the MCP wire shape (text + struct)."""
    content_models = getattr(tool_result, "content", None) or []
    content: list[dict[str, Any]] = []
    for item in content_models:
        if hasattr(item, "model_dump"):
            dumped = item.model_dump(exclude_none=True)
        elif isinstance(item, dict):
            dumped = item
        else:
            dumped = {"type": "text", "text": str(item)}
        content.append(dumped)
    structured = getattr(tool_result, "structured_content", None)
    payload: dict[str, Any] = {"content": content}
    if structured is not None:
        payload["structuredContent"] = structured
    return payload


# Optional middleware-style hook executed after PASETO verify but before
# tool dispatch. Returning ``None`` means "allow"; returning a JSONResponse
# short-circuits the pipeline. US-016 (case_actions) will pass an
# implementation that returns a 403 deny_reason when ``human_approval`` is
# missing from the claims.
ExtraValidate = Callable[[Claims], JSONResponse | None]

# Factory that builds the upstream ``httpx.AsyncClient`` for the server's
# downstream calls. Tests inject an ASGI-transport-backed client; the
# default factory creates a fresh AsyncClient bound to ``api_base_url``.
ApiClientFactory = Callable[[str, float], httpx.AsyncClient]


def _default_api_client_factory(
    base_url: str, request_timeout_seconds: float
) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=base_url, timeout=request_timeout_seconds)


def create_jsonrpc_app(
    *,
    server_name: str,
    title: str,
    description: str,
    mcp_factory: Callable[[httpx.AsyncClient], FastMCP],
    public_key_path: Path | str,
    api_base_url: str,
    api_client: httpx.AsyncClient | None = None,
    api_client_factory: ApiClientFactory = _default_api_client_factory,
    request_timeout_seconds: float = 10.0,
    extra_validate: ExtraValidate | None = None,
    on_request: Callable[[Request, Claims], Awaitable[None]] | None = None,
) -> FastAPI:
    """Build a downstream MCP server FastAPI app.

    Exposes ``POST /<server_name>`` (JSON-RPC 2.0) and ``GET /healthz``.
    The pipeline:

    1. Parse the JSON body (400 on parse error / non-object).
    2. Verify the service PASETO bearer (401 on any failure).
    3. Run ``extra_validate(claims)`` if provided (e.g. human-approval check
       in US-016) — return its response unchanged on deny.
    4. Dispatch ``tools/list`` to :func:`list_tools_response`.
    5. Dispatch ``tools/call``: look up the tool in the FastMCP registry,
       call ``tool.run(arguments)``, coerce the result to the MCP wire
       shape. Upstream 4xx/5xx surface via ``error.data.upstream_status`` /
       ``upstream_body``; HTTP 502 is used for 5xx and the original status
       for 4xx.
    """
    owns_client = api_client is None
    client = api_client or api_client_factory(api_base_url, request_timeout_seconds)
    mcp = mcp_factory(client)

    @asynccontextmanager
    async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if owns_client:
                await client.aclose()

    app = FastAPI(
        title=title,
        version="0.1.0",
        description=description,
        lifespan=_lifespan,
    )
    instrument_fastapi(app, service_name=f"fraud-mcp-{server_name}")
    tracer = get_tracer(f"mcp_servers.{server_name}")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post(f"/{server_name}")
    async def mcp_endpoint(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> JSONResponse:
        body_bytes = await request.body()
        try:
            payload = json.loads(body_bytes) if body_bytes else {}
        except json.JSONDecodeError as exc:
            return JSONResponse(
                JsonRpc.error(None, JsonRpc.PARSE_ERROR, f"invalid json: {exc}"),
                status_code=400,
            )
        if not isinstance(payload, dict):
            return JSONResponse(
                JsonRpc.error(None, JsonRpc.INVALID_REQUEST, "payload not an object"),
                status_code=400,
            )
        rpc_id = payload.get("id")

        # 1. Service PASETO validation.
        claims_or_resp = verify_service_paseto_header(authorization, public_key_path)
        if isinstance(claims_or_resp, JSONResponse):
            return claims_or_resp
        claims = claims_or_resp

        # 2. Optional caller-supplied claim check (e.g. human_approval in US-016).
        if extra_validate is not None:
            deny = extra_validate(claims)
            if deny is not None:
                return deny

        # Optional pre-dispatch hook (e.g. attach claims to logging context).
        if on_request is not None:
            await on_request(request, claims)

        method = payload.get("method", "")
        params = payload.get("params") or {}

        if method == "tools/list":
            ctx = trace_context_from_id(claims.trace_id)
            with tracer.start_as_current_span(
                f"mcp.{server_name}.tools_list",
                context=ctx,
                attributes=tool_span_attributes(
                    server=server_name,
                    tool="<list>",
                    role=",".join(claims.roles) or "none",
                ),
            ):
                return JSONResponse(
                    JsonRpc.result(rpc_id, await list_tools_response(mcp))
                )

        if method != "tools/call":
            return JSONResponse(
                JsonRpc.error(
                    rpc_id, JsonRpc.METHOD_NOT_FOUND, f"unsupported method: {method}"
                ),
                status_code=400,
            )

        if not isinstance(params, dict):
            return JSONResponse(
                JsonRpc.error(rpc_id, JsonRpc.INVALID_PARAMS, "params must be an object"),
                status_code=400,
            )
        tool_name = str(params.get("name") or "")
        arguments = params.get("arguments") or {}
        if not tool_name:
            return JSONResponse(
                JsonRpc.error(rpc_id, JsonRpc.INVALID_PARAMS, "missing tool name"),
                status_code=400,
            )
        if not isinstance(arguments, dict):
            return JSONResponse(
                JsonRpc.error(
                    rpc_id, JsonRpc.INVALID_PARAMS, "arguments must be an object"
                ),
                status_code=400,
            )

        tool = await mcp.get_tool(tool_name)
        if tool is None:
            return JSONResponse(
                JsonRpc.error(
                    rpc_id,
                    JsonRpc.METHOD_NOT_FOUND,
                    f"unknown tool: {tool_name}",
                ),
                status_code=404,
            )

        ctx = trace_context_from_id(claims.trace_id)
        span_cm = tracer.start_as_current_span(
            f"mcp.{server_name}.tool_call",
            context=ctx,
            attributes=tool_span_attributes(
                server=server_name,
                tool=tool_name,
                role=",".join(claims.roles) or "none",
            ),
        )
        try:
            with span_cm:
                tool_result = await tool.run(arguments)
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            try:
                body: Any = exc.response.json()
            except (ValueError, json.JSONDecodeError):
                body = {"text": exc.response.text}
            return JSONResponse(
                JsonRpc.error(
                    rpc_id,
                    JsonRpc.INTERNAL_ERROR,
                    f"upstream {status}: {exc}",
                    data={"upstream_status": status, "upstream_body": body},
                ),
                status_code=502 if status >= 500 else status,
            )
        except httpx.HTTPError as exc:
            return JSONResponse(
                JsonRpc.error(
                    rpc_id,
                    JsonRpc.INTERNAL_ERROR,
                    f"upstream unreachable: {exc}",
                ),
                status_code=502,
            )
        except ToolDispatchError as exc:
            # Tool intentionally rejected the call (e.g. allowlist deny).
            # Surface as a JSON-RPC error with the tool's status + payload
            # so the caller sees deny_reason instead of a generic 500.
            return JSONResponse(
                JsonRpc.error(
                    rpc_id,
                    JsonRpc.INVALID_REQUEST,
                    exc.message,
                    data=exc.data,
                ),
                status_code=exc.status_code,
            )
        except Exception as exc:  # pragma: no cover - defensive
            _LOG.exception("tool execution failed")
            return JSONResponse(
                JsonRpc.error(
                    rpc_id, JsonRpc.INTERNAL_ERROR, f"tool error: {exc}"
                ),
                status_code=500,
            )

        return JSONResponse(JsonRpc.result(rpc_id, tool_result_to_mcp(tool_result)))

    return app


def env_required(name: str) -> str:
    """Read a required environment variable or raise a friendly error."""
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} not configured")
    return value
