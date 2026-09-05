"""Policies endpoint: inspect active policy rules and test matching."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from custos.schema import Invocation, SubjectContext, ToolDescriptor
from custos.server.gateway_manager import GatewayManager

router = APIRouter(prefix="/api/v1/policies", tags=["Policies"])


def get_gw_manager() -> GatewayManager:
    from custos.server.app import get_gateway_manager
    return get_gateway_manager()


class PolicyMatchTestRequest(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    user_id: str = "test_user"
    risk_tier: int = 2


@router.get("")
async def get_active_policy(gw: GatewayManager = Depends(get_gw_manager)) -> dict[str, Any]:
    """Retrieve the currently compiled active rules and policy metadata."""
    rules_list = []
    for r in gw._policy._rules_ro:
        rules_list.append({
            "action": r.action,
            "overlay_id": r.overlay_id,
            "match": dict(r.spec.match) if hasattr(r.spec, "match") else {},
            "description": getattr(r.spec, "description", None),
        })

    return {
        "default": gw._policy._default,
        "total_rules": len(rules_list),
        "rules": rules_list,
    }


@router.post("/test-match")
async def test_policy_match(
    body: PolicyMatchTestRequest,
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    """Dry-run test an invocation against active policy rules to inspect which rule fires."""
    inv = Invocation(
        tool=body.tool,
        args=body.args,
        context=SubjectContext(user_id=body.user_id),
        descriptor=ToolDescriptor(name=body.tool, risk_tier=body.risk_tier),
    )
    outcome = gw._policy.evaluate(inv)
    matched = gw._policy.matched_rule(inv)

    return {
        "outcome": outcome.value,
        "matched_rule": {
            "action": matched.action,
            "overlay_id": matched.overlay_id,
            "match": dict(matched.spec.match) if hasattr(matched.spec, "match") else {},
            "description": getattr(matched.spec, "description", None),
        } if matched else None,
    }
