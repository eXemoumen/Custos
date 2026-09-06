"""Invocations endpoint: evaluates tool calls through Custos Gateway."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from custos.schema import Decision
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
    timeout_seconds: float | None = Field(default=None, ge=0.5, le=300.0, description="Optional prompt wait timeout")
    async_mode: bool = Field(default=False, description="Whether to return immediately if human approval is required")


class DecideResponse(BaseModel):
    decision: str
    allowed: bool
    risk: float | None = None
    reasoning: str | None = None
    audit_event: dict[str, Any]
    request_id: str | None = Field(default=None, description="Request ID if awaiting human approval")
    pending_approval: bool | None = Field(default=None, description="Whether invocation is awaiting human approval")


class DecideBatchRequest(BaseModel):
    invocations: list[DecideRequest] = Field(..., min_length=1, max_length=50)


class DecideBatchResponse(BaseModel):
    total: int
    results: list[DecideResponse]


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
            timeout_seconds=req.timeout_seconds,
            async_mode=req.async_mode,
        )
        audit_dict = result.audit.to_dict()
        is_pending = result.decision == Decision.PROMPT and req.async_mode
        req_id = getattr(result, "request_id", None) or (
            result.audit.invocation.request_id if hasattr(result.audit, "invocation") else None
        )
        return DecideResponse(
            decision=result.decision.value,
            allowed=result.decision.is_allow,
            risk=result.audit.risk_score,
            reasoning=result.audit.reasoning or result.audit.policy_match,
            audit_event=audit_dict,
            request_id=req_id if is_pending else None,
            pending_approval=is_pending,
        )
    except Exception as err:
        logger.exception("Error evaluating tool invocation: %s", err)
        raise HTTPException(status_code=500, detail="Failed to evaluate tool invocation") from err


@router.post("/decide-batch", response_model=DecideBatchResponse)
async def decide_batch(
    req: DecideBatchRequest,
    gw: GatewayManager = Depends(get_gw_manager),
) -> DecideBatchResponse:
    """Evaluate a batch of tool invocations through the Custos gateway pipeline."""
    responses: list[DecideResponse] = []
    for inv_req in req.invocations:
        try:
            result = await asyncio.to_thread(
                gw.decide,
                tool=inv_req.tool,
                args=inv_req.args,
                user_id=inv_req.user_id,
                goal_id=inv_req.goal_id,
                task_id=inv_req.task_id,
                risk_tier=inv_req.risk_tier,
                extra=inv_req.extra,
                timeout_seconds=inv_req.timeout_seconds,
                async_mode=inv_req.async_mode,
            )
            audit_dict = result.audit.to_dict()
            is_pending = result.decision == Decision.PROMPT and inv_req.async_mode
            req_id = getattr(result, "request_id", None) or (
                result.audit.invocation.request_id if hasattr(result.audit, "invocation") else None
            )
            responses.append(DecideResponse(
                decision=result.decision.value,
                allowed=result.decision.is_allow,
                risk=result.audit.risk_score,
                reasoning=result.audit.reasoning or result.audit.policy_match,
                audit_event=audit_dict,
                request_id=req_id if is_pending else None,
                pending_approval=is_pending,
            ))
        except Exception as err:
            logger.exception("Error evaluating batch item: %s", err)
            raise HTTPException(status_code=500, detail=f"Failed to evaluate tool '{inv_req.tool}': {err}") from err

    return DecideBatchResponse(total=len(responses), results=responses)
