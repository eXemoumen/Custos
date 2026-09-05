"""Knowledge Base routes: manage assets, natural language rules, and threat patterns."""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from custos.knowledge.schema import (
    AssetType,
    GuardrailAction,
    GuardrailCategory,
    GuardrailRule,
    SensitiveAsset,
    Severity,
    ThreatPattern,
)
from custos.schema import Invocation, SubjectContext, ToolDescriptor
from custos.server.gateway_manager import GatewayManager

router = APIRouter(prefix="/api/v1/knowledge", tags=["Knowledge Base"])


def get_gw_manager() -> GatewayManager:
    from custos.server.app import get_gateway_manager
    return get_gateway_manager()


# --- Assets ---

class AssetCreate(BaseModel):
    name: str
    asset_type: AssetType = AssetType.FILE_PATH
    pattern: str
    action: GuardrailAction = GuardrailAction.DENY
    severity: Severity = Severity.HIGH
    description: str = ""
    enabled: bool = True


class AssetUpdate(BaseModel):
    name: str | None = None
    asset_type: str | None = None
    pattern: str | None = None
    action: str | None = None
    severity: str | None = None
    description: str | None = None
    enabled: bool | None = None


@router.get("/assets")
async def list_assets(gw: GatewayManager = Depends(get_gw_manager)) -> list[dict[str, Any]]:
    return [a.to_dict() for a in gw.kb_store.list_assets()]


@router.post("/assets")
async def create_asset(body: AssetCreate, gw: GatewayManager = Depends(get_gw_manager)) -> dict[str, Any]:
    asset = SensitiveAsset(
        name=body.name,
        asset_type=body.asset_type,
        pattern=body.pattern,
        action=body.action,
        severity=body.severity,
        description=body.description,
        enabled=body.enabled,
    )
    added = gw.kb_store.add_asset(asset)
    gw.recompile_and_reload()
    return added.to_dict()


@router.put("/assets/{asset_id}")
async def update_asset(
    asset_id: str,
    body: AssetUpdate,
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    updated = gw.kb_store.update_asset(asset_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Asset not found")
    gw.recompile_and_reload()
    return updated.to_dict()


@router.delete("/assets/{asset_id}")
async def delete_asset(asset_id: str, gw: GatewayManager = Depends(get_gw_manager)) -> dict[str, Any]:
    deleted = gw.kb_store.delete_asset(asset_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Asset not found")
    gw.recompile_and_reload()
    return {"status": "deleted", "id": asset_id}


# --- Rules ---

class RuleCreate(BaseModel):
    name: str
    natural_language_rule: str
    category: GuardrailCategory = GuardrailCategory.GENERAL
    action: GuardrailAction = GuardrailAction.PROMPT
    severity: Severity = Severity.HIGH
    target_tools: list[str] = Field(default_factory=lambda: ["*"])
    keywords: list[str] = Field(default_factory=list)
    enabled: bool = True


class RuleUpdate(BaseModel):
    name: str | None = None
    natural_language_rule: str | None = None
    category: str | None = None
    action: str | None = None
    severity: str | None = None
    target_tools: list[str] | None = None
    keywords: list[str] | None = None
    enabled: bool | None = None


@router.get("/rules")
async def list_rules(gw: GatewayManager = Depends(get_gw_manager)) -> list[dict[str, Any]]:
    return [r.to_dict() for r in gw.kb_store.list_rules()]


@router.post("/rules")
async def create_rule(body: RuleCreate, gw: GatewayManager = Depends(get_gw_manager)) -> dict[str, Any]:
    rule = GuardrailRule(
        name=body.name,
        natural_language_rule=body.natural_language_rule,
        category=body.category,
        action=body.action,
        severity=body.severity,
        target_tools=body.target_tools,
        keywords=body.keywords,
        enabled=body.enabled,
    )
    added = gw.kb_store.add_rule(rule)
    gw.recompile_and_reload()
    return added.to_dict()


@router.put("/rules/{rule_id}")
async def update_rule(
    rule_id: str,
    body: RuleUpdate,
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    updated = gw.kb_store.update_rule(rule_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Rule not found")
    gw.recompile_and_reload()
    return updated.to_dict()


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str, gw: GatewayManager = Depends(get_gw_manager)) -> dict[str, Any]:
    deleted = gw.kb_store.delete_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Rule not found")
    gw.recompile_and_reload()
    return {"status": "deleted", "id": rule_id}


# --- Threats ---

class ThreatCreate(BaseModel):
    name: str
    pattern: str
    is_regex: bool = True
    severity: Severity = Severity.CRITICAL
    description: str = ""
    action: GuardrailAction = GuardrailAction.QUARANTINE
    enabled: bool = True


@router.get("/threats")
async def list_threats(gw: GatewayManager = Depends(get_gw_manager)) -> list[dict[str, Any]]:
    return [t.to_dict() for t in gw.kb_store.list_threats()]


@router.post("/threats")
async def create_threat(body: ThreatCreate, gw: GatewayManager = Depends(get_gw_manager)) -> dict[str, Any]:
    pattern = body.pattern.strip()
    if not pattern:
        raise HTTPException(status_code=400, detail="Pattern cannot be empty")
    if len(pattern) > 1000:
        raise HTTPException(status_code=400, detail="Threat pattern exceeds maximum allowed length of 1000 characters")
    if body.is_regex:
        try:
            re.compile(pattern)
        except re.error as err:
            raise HTTPException(status_code=400, detail=f"Invalid regular expression: {err}") from err

    threat = ThreatPattern(
        name=body.name,
        pattern=body.pattern,
        is_regex=body.is_regex,
        severity=body.severity,
        description=body.description,
        action=body.action,
        enabled=body.enabled,
    )
    added = gw.kb_store.add_threat(threat)
    return added.to_dict()


@router.delete("/threats/{threat_id}")
async def delete_threat(threat_id: str, gw: GatewayManager = Depends(get_gw_manager)) -> dict[str, Any]:
    deleted = gw.kb_store.delete_threat(threat_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Threat pattern not found")
    return {"status": "deleted", "id": threat_id}


# --- Recompile & Test ---

class TestGuardrailRequest(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    user_message: str | None = None


@router.post("/compile")
async def recompile_knowledge_base(gw: GatewayManager = Depends(get_gw_manager)) -> dict[str, Any]:
    """Recompiles the Knowledge Base into policy overlays and applies them immediately."""
    gw.recompile_and_reload()
    return {"status": "success", "message": "Knowledge Base recompiled and policy reloaded."}


@router.post("/test")
async def test_guardrail(
    body: TestGuardrailRequest,
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    """Test a sample tool call against the Knowledge Base without executing it."""
    inv = Invocation(
        tool=body.tool,
        args=body.args,
        context=SubjectContext(user_id="test_runner"),
        descriptor=ToolDescriptor(name=body.tool, risk_tier=2),
    )
    result = gw.kb_assistant.intent_checker.evaluate(inv, user_message=body.user_message)
    return {
        "allowed": result.allowed,
        "action": result.action.value if result.action else None,
        "risk_score": result.risk_score,
        "reasoning": result.reasoning,
        "violated_rule": result.violated_rule.to_dict() if result.violated_rule else None,
        "violated_asset": result.violated_asset.to_dict() if result.violated_asset else None,
        "violated_threat": result.violated_threat.to_dict() if result.violated_threat else None,
    }
