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


class BatchPromptResponseRequest(BaseModel):
    resolutions: list[dict[str, Any]] = Field(..., description="List of {request_id, choice, approver}")


@router.get("")
async def list_pending_prompts(
    gw: GatewayManager = Depends(get_gw_manager),
) -> list[dict[str, Any]]:
    """List all pending tool invocations currently held for human approval."""
    return gw.approval_manager.list_pending()


@router.get("/{request_id}")
async def get_prompt(
    request_id: str,
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    """Inspect the arguments, risk score, and options for a specific pending prompt."""
    prompt = gw.approval_manager.get_prompt(request_id)
    if not prompt:
        raise HTTPException(status_code=404, detail=f"Prompt {request_id} not found or expired")
    return prompt


@router.post("/{request_id}/respond")
@router.post("/{request_id}/resolve")
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


@router.post("/{request_id}/cancel")
async def cancel_prompt(
    request_id: str,
    reason: str = "cancelled_by_operator",
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    """Dismiss a held tool invocation, automatically resolving it with DENY."""
    cancelled = gw.approval_manager.cancel_prompt(request_id, reason=reason)
    if not cancelled:
        raise HTTPException(status_code=404, detail=f"Prompt {request_id} not found or already resolved")
    return {"status": "cancelled", "request_id": request_id, "resolution": "deny"}


@router.post("/batch-respond")
async def batch_respond(
    body: BatchPromptResponseRequest,
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    """Submit approvals or rejections for multiple held invocations at once."""
    results = gw.approval_manager.batch_resolve_prompts(body.resolutions)
    return {"results": results, "total": len(results)}
