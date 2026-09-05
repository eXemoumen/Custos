"""Prompts endpoint: Human-in-the-Loop approval requests."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from custos.schema import Decision
from custos.server.gateway_manager import GatewayManager

router = APIRouter(prefix="/api/v1/prompts", tags=["Prompts"])


class PromptResponseRequest(BaseModel):
    choice: str = Field(..., description="Decision choice: allow, allow_once, allow_and_persist, deny, quarantine")
    approver: str = Field(default="admin_ui", description="Identifier of the human approver")


def get_gw_manager() -> GatewayManager:
    from custos.server.app import get_gateway_manager
    return get_gateway_manager()


@router.get("")
async def list_pending_prompts(
    gw: GatewayManager = Depends(get_gw_manager),
) -> list[dict[str, Any]]:
    """List all pending tool invocations currently held for human approval."""
    return gw.approval_manager.list_pending()


@router.post("/{request_id}/respond")
async def respond_to_prompt(
    request_id: str,
    body: PromptResponseRequest,
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    """Submit a human decision to allow or deny a held tool invocation."""
    try:
        choice_enum = Decision(body.choice)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid decision choice: {body.choice}")

    resolved = gw.approval_manager.resolve_prompt(
        request_id=request_id,
        choice=choice_enum,
        approver=body.approver,
    )
    if not resolved:
        raise HTTPException(status_code=404, detail=f"Prompt {request_id} not found or already resolved")

    return {"status": "resolved", "request_id": request_id, "choice": body.choice}
