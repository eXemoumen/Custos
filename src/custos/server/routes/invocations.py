"""Invocations endpoint: evaluates tool calls through Custos Gateway."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from custos.server.gateway_manager import GatewayManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/invocations", tags=["Invocations"])


class DecideRequest(BaseModel):
    tool: str = Field(..., description="Tool name, e.g. fs.read, shell.exec, db.query")
    args: dict[str, Any] = Field(default_factory=dict, description="Arguments passed to the tool")
    user_id: str = Field(default="default_user", description="Caller user or agent identity")
    goal_id: str | None = Field(default=None, description="Active goal or conversation scope")
    task_id: str | None = Field(default=None, description="Active task identifier")
    risk_tier: int = Field(default=2, ge=1, le=5, description="Declared or default risk tier (1-5)")
    extra: dict[str, Any] | None = Field(default=None, description="Optional metadata")


class DecideResponse(BaseModel):
    decision: str
    allowed: bool
    risk: float | None = None
    reasoning: str | None = None
    audit_event: dict[str, Any]


def get_gw_manager() -> GatewayManager:
    from custos.server.app import get_gateway_manager
    return get_gateway_manager()


@router.post("/decide", response_model=DecideResponse)
async def decide_invocation(
    req: DecideRequest,
    gw: GatewayManager = Depends(get_gw_manager),
) -> DecideResponse:
    """Evaluate an agent tool invocation against the active policy, Knowledge Base, and approval pipeline."""
    try:
        result = await asyncio.to_thread(
            gw.decide,
            tool=req.tool,
            args=req.args,
            user_id=req.user_id,
            goal_id=req.goal_id,
            task_id=req.task_id,
            risk_tier=req.risk_tier,
            extra=req.extra,
        )
        audit_dict = result.audit.to_dict()
        return DecideResponse(
            decision=result.decision.value,
            allowed=result.decision.is_allow,
            risk=result.audit.risk_score,
            reasoning=result.audit.reasoning or result.audit.policy_match,
            audit_event=audit_dict,
        )
    except Exception as err:
        logger.exception("Error evaluating tool invocation: %s", err)
        raise HTTPException(status_code=500, detail="Failed to evaluate tool invocation") from err
