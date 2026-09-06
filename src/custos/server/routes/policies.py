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


class PolicyValidateRequest(BaseModel):
    policy: dict[str, Any] | None = None
    yaml_content: str | None = None


@router.post("/validate")
async def validate_policy(body: PolicyValidateRequest) -> dict[str, Any]:
    """Validate a candidate policy structure or YAML string without applying it."""
    from custos.policy import Policy
    import yaml

    data = body.policy
    if data is None and body.yaml_content is not None:
        try:
            parsed = yaml.safe_load(body.yaml_content)
            if not isinstance(parsed, dict):
                return {"valid": False, "error": "YAML content must evaluate to a dictionary"}
            data = parsed
        except Exception as e:
            return {"valid": False, "error": f"YAML syntax error: {e}"}

    if data is None:
        return {"valid": False, "error": "Must provide either 'policy' dictionary or 'yaml_content'"}

    try:
        candidate = Policy.from_dict(data)
        return {
            "valid": True,
            "rule_count": len(candidate._rules_ro),
            "default": candidate._default,
            "message": f"Policy definition is valid ({len(candidate._rules_ro)} rules parsed).",
        }
    except Exception as err:
        return {"valid": False, "error": f"Invalid policy definition: {err}"}


@router.post("/reload")
async def reload_policy(gw: GatewayManager = Depends(get_gw_manager)) -> dict[str, Any]:
    """Force reload the base policy from disk and recompile the Knowledge Base overlay."""
    gw.recompile_and_reload()
    return {
        "status": "success",
        "message": "Policy reloaded successfully from source and Knowledge Base.",
        "default": gw._policy._default,
        "total_rules": len(gw._policy._rules_ro),
    }


@router.get("/overlays")
async def list_overlays(gw: GatewayManager = Depends(get_gw_manager)) -> dict[str, Any]:
    """List loaded policy overlays and their rule counts in evaluation priority order."""
    overlay_counts: dict[str, int] = {}
    for r in gw._policy._rules_ro:
        oid = r.overlay_id or "base_policy"
        overlay_counts[oid] = overlay_counts.get(oid, 0) + 1

    return {
        "total_overlays": len(overlay_counts),
        "overlays": [{"id": k, "rule_count": v} for k, v in overlay_counts.items()],
    }

