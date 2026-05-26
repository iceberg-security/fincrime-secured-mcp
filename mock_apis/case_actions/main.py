"""case_actions mock API — write-path actions on an investigation case (US-016).

Stands in for an internal case-management / compliance-action service. Three
endpoints + ``/healthz``:

    POST /sar-drafts        -> create a SAR (Suspicious Activity Report) draft
    POST /accounts/freeze   -> freeze an account
    POST /escalations       -> escalate a case to an L3 reviewer

Plus read endpoints so tests and the verifier meta-skill (US-021) can query
back what was recorded:

    GET  /sar-drafts/{draft_id}
    GET  /accounts/{account_id}/freeze
    GET  /escalations/{escalation_id}

Determinism contract:

* Each ``POST`` carries a deterministic body. The resulting record id is
  derived from ``sha256(body|salt)`` so the same inputs always yield the
  same id. **There is no clock-based id, no UUID** — this matters for the
  eval scorers (US-027/US-028) so test runs are reproducible.

* The mock holds state in-memory **per app instance**. Each
  ``create_app()`` call returns a fresh app with an empty store; tests
  that need isolation should build their own app. ``build_default_app()``
  is a thin wrapper used by uvicorn / docker-compose.

Unlike the five read-only mocks in this stack, case_actions is the only
write-path service. Every action is logged to a per-app journal so the
verify-output meta-skill (US-021) can cross-reference the audit log.

The **human-approval gate** is enforced one layer up at the MCP server
(``mcp_servers/case_actions``) by checking the ``human_approval=true``
PASETO claim. The mock itself accepts any well-formed body — the gate is
the *server's* job, so the mock stays focused on data shape.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from gateways.common.otel import instrument_fastapi

__all__ = [
    "CaseStore",
    "build_default_app",
    "create_app",
]


# --------------------------------------------------------------------------- #
# In-memory journal                                                           #
# --------------------------------------------------------------------------- #


@dataclass
class CaseStore:
    """Per-app, append-only journal of recorded actions.

    Exposed for tests that want to inspect the store directly without going
    through the HTTP layer. The MCP server never holds a reference — every
    interaction is via the HTTP API.
    """

    sar_drafts: dict[str, dict[str, Any]] = field(default_factory=dict)
    freezes: dict[str, dict[str, Any]] = field(default_factory=dict)
    escalations: dict[str, dict[str, Any]] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Deterministic id helper                                                     #
# --------------------------------------------------------------------------- #


def _deterministic_id(prefix: str, *parts: str) -> str:
    """Stable id derived from ``sha256(parts|prefix)``.

    Same inputs always produce the same id. The first 12 hex chars are
    enough to keep ids readable; the full sha256 still lives in
    ``content_hash`` on the record.
    """
    h = hashlib.sha256(prefix.encode("utf-8"))
    for p in parts:
        h.update(b"|")
        h.update(p.encode("utf-8"))
    return f"{prefix}_{h.hexdigest()[:12]}"


def _content_hash(payload: dict[str, Any]) -> str:
    """Stable sha256 of a payload — used by the grounding scorer."""
    import json

    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


# --------------------------------------------------------------------------- #
# Request models                                                              #
# --------------------------------------------------------------------------- #


class SarDraftRequest(BaseModel):
    customer_id: str = Field(min_length=1, max_length=200)
    narrative: str = Field(min_length=1, max_length=10_000)
    typology: str = Field(min_length=1, max_length=200)
    related_accounts: list[str] = Field(default_factory=list, max_length=50)


class FreezeAccountRequest(BaseModel):
    account_id: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=2_000)
    requested_by: str = Field(min_length=1, max_length=200)


class EscalateRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1, max_length=4_000)
    severity: str = Field(min_length=1, max_length=50)
    requested_by: str = Field(min_length=1, max_length=200)


# --------------------------------------------------------------------------- #
# FastAPI app                                                                 #
# --------------------------------------------------------------------------- #


def create_app(store: CaseStore | None = None) -> FastAPI:
    """Build the case_actions FastAPI app.

    Args:
        store: Optional pre-built ``CaseStore``. When ``None``, a fresh
            empty store is created. Tests typically pass their own store so
            they can inspect it directly.
    """
    journal = store if store is not None else CaseStore()

    app = FastAPI(
        title="case_actions mock API",
        version="0.1.0",
        description=(
            "Mock case-management / compliance-action write-path API. "
            "Records SAR drafts, account freezes, and L3 escalations. The "
            "human-approval gate lives at the MCP server layer "
            "(mcp_servers/case_actions); this mock accepts well-formed "
            "bodies and journals them deterministically."
        ),
    )
    instrument_fastapi(app, service_name="fraud-mock-case-actions")

    # ---- Writes ------------------------------------------------------ #

    @app.post("/sar-drafts")
    def create_sar_draft(body: SarDraftRequest) -> dict[str, Any]:
        draft_id = _deterministic_id(
            "sar",
            body.customer_id,
            body.typology,
            body.narrative,
            ",".join(sorted(body.related_accounts)),
        )
        payload: dict[str, Any] = {
            "draft_id": draft_id,
            "customer_id": body.customer_id,
            "narrative": body.narrative,
            "typology": body.typology,
            "related_accounts": list(body.related_accounts),
            "status": "draft",
        }
        payload["content_hash"] = _content_hash(payload)
        journal.sar_drafts[draft_id] = payload
        return payload

    @app.post("/accounts/freeze")
    def freeze_account(body: FreezeAccountRequest) -> dict[str, Any]:
        freeze_id = _deterministic_id(
            "frz", body.account_id, body.reason, body.requested_by
        )
        payload: dict[str, Any] = {
            "freeze_id": freeze_id,
            "account_id": body.account_id,
            "reason": body.reason,
            "requested_by": body.requested_by,
            "status": "frozen",
        }
        payload["content_hash"] = _content_hash(payload)
        journal.freezes[body.account_id] = payload
        return payload

    @app.post("/escalations")
    def escalate_to_l3(body: EscalateRequest) -> dict[str, Any]:
        escalation_id = _deterministic_id(
            "esc",
            body.case_id,
            body.severity,
            body.summary,
            body.requested_by,
        )
        payload: dict[str, Any] = {
            "escalation_id": escalation_id,
            "case_id": body.case_id,
            "summary": body.summary,
            "severity": body.severity,
            "requested_by": body.requested_by,
            "status": "escalated_l3",
        }
        payload["content_hash"] = _content_hash(payload)
        journal.escalations[escalation_id] = payload
        return payload

    # ---- Reads (verifier / tests) ------------------------------------ #

    @app.get("/sar-drafts/{draft_id}")
    def get_sar_draft(draft_id: str) -> dict[str, Any]:
        if draft_id not in journal.sar_drafts:
            raise HTTPException(
                status_code=404, detail=f"sar draft '{draft_id}' not found"
            )
        return journal.sar_drafts[draft_id]

    @app.get("/accounts/{account_id}/freeze")
    def get_freeze(account_id: str) -> dict[str, Any]:
        if account_id not in journal.freezes:
            raise HTTPException(
                status_code=404,
                detail=f"freeze for account '{account_id}' not found",
            )
        return journal.freezes[account_id]

    @app.get("/escalations/{escalation_id}")
    def get_escalation(escalation_id: str) -> dict[str, Any]:
        if escalation_id not in journal.escalations:
            raise HTTPException(
                status_code=404,
                detail=f"escalation '{escalation_id}' not found",
            )
        return journal.escalations[escalation_id]

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


def build_default_app() -> FastAPI:
    """Construct the mock for ``uvicorn`` / docker-compose launchers.

    No env vars consumed — the mock is process-local and reads no
    configuration. A new empty journal is created on app build.
    """
    return create_app()
