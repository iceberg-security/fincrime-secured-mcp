"""Authorization Gateway — FastAPI service.

Endpoints:
    POST /token
        Body: ignored. Authorization: Bearer <oidc_token>
        -> 200 {"access_token": "v4.public.<paseto>", "token_type": "Bearer",
                "expires_in": <ttl_seconds>}

    GET /.well-known/paseto-key
        -> 200 application/x-pem-file with the Ed25519 PASETO verification
           public key. The MCP gateway fetches this to verify inbound tokens.

    GET /healthz
        -> 200 {"status": "ok"}

The OIDC validator and RBAC loader are pluggable on the app factory so tests
can inject fakes. In production they are constructed from env vars on startup.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse

from gateways.auth.oidc import (
    OIDCClaims,
    OIDCExpiredTokenError,
    OIDCInvalidTokenError,
    OIDCValidator,
)
from gateways.common import paseto as paseto_mod
from gateways.common.otel import (
    get_tracer,
    instrument_fastapi,
    tool_span_attributes,
    trace_context_from_id,
)
from gateways.common.paseto import Claims, _new_trace_id, mint
from gateways.common.rbac import (
    RBACError,
    RBACLoader,
    ResolvedUser,
    UnknownUserError,
)

_DEFAULT_TTL_SECONDS = 300  # PRD: 5-minute PASETO TTL


def _resolve_public_key_path() -> Path:
    raw = os.environ.get("PASETO_PUBLIC_KEY_PATH", "")
    if not raw:
        raise RuntimeError("PASETO_PUBLIC_KEY_PATH not configured")
    return Path(raw)


def create_app(
    *,
    oidc_validator: OIDCValidator | None = None,
    rbac_loader: RBACLoader | None = None,
    public_key_path: Path | None = None,
    private_key_path: Path | None = None,
    token_ttl_seconds: int = _DEFAULT_TTL_SECONDS,
) -> FastAPI:
    """Build the auth gateway FastAPI app.

    All collaborators are injectable to keep the unit tests hermetic.
    """
    app = FastAPI(title="Fraud Copilot Auth Gateway", version="0.1.0")
    instrument_fastapi(app, service_name="fraud-auth-gateway")
    _tracer = get_tracer(__name__)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/.well-known/paseto-key", response_class=PlainTextResponse)
    def get_paseto_key() -> PlainTextResponse:
        path = public_key_path or _resolve_public_key_path()
        if not path.is_file():
            raise HTTPException(
                status_code=500, detail=f"paseto public key not found at {path}"
            )
        return PlainTextResponse(
            path.read_text(encoding="utf-8"),
            media_type="application/x-pem-file",
        )

    @app.post("/token")
    def post_token(
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, object]:
        if oidc_validator is None or rbac_loader is None:
            raise HTTPException(status_code=500, detail="auth gateway not configured")
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(
                status_code=401,
                detail="missing or malformed Authorization header (expected 'Bearer <oidc_token>')",
            )
        oidc_token = authorization.split(" ", 1)[1].strip()

        try:
            oidc_claims: OIDCClaims = oidc_validator.validate(oidc_token)
        except OIDCExpiredTokenError as exc:
            raise HTTPException(status_code=401, detail=f"oidc token expired: {exc}") from exc
        except OIDCInvalidTokenError as exc:
            raise HTTPException(status_code=401, detail=f"invalid oidc token: {exc}") from exc

        try:
            user: ResolvedUser = rbac_loader.resolve_user(
                oidc_claims.email, groups=oidc_claims.groups
            )
        except UnknownUserError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except RBACError as exc:
            raise HTTPException(status_code=500, detail=f"rbac error: {exc}") from exc

        trace_id = _new_trace_id()
        claims = Claims(
            sub=user.email,
            roles=user.roles,
            allowed_servers=user.allowed_servers,
            allowed_tools=user.allowed_tools,
            trace_id=trace_id,
        )
        ctx = trace_context_from_id(trace_id)
        with _tracer.start_as_current_span(
            "auth.mint_token",
            context=ctx,
            attributes=tool_span_attributes(role=",".join(user.roles) or "none"),
        ):
            token = mint(
                claims,
                ttl_seconds=token_ttl_seconds,
                private_key_path=private_key_path,
            )
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": token_ttl_seconds,
        }

    return app


def build_default_app() -> FastAPI:
    """Construct the app from env vars (production entry point).

    Used by ``uvicorn gateways.auth.main:app`` style launchers.
    """
    validator = OIDCValidator()
    rbac_path = os.environ.get("RBAC_CONFIG_PATH", "config/rbac.yaml")
    loader = RBACLoader(rbac_path)
    return create_app(oidc_validator=validator, rbac_loader=loader)


# Re-export so PASETO key cache is reachable from tests via auth.main as well.
__all__ = ["create_app", "build_default_app", "paseto_mod"]
