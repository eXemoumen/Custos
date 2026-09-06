"""Agents endpoint: inspect and manage autonomous agent identity and quarantine status."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from custos.server.gateway_manager import GatewayManager

router = APIRouter(prefix="/api/v1/agents", tags=["Agents"])


def get_gw_manager() -> GatewayManager:
    from custos.server.app import get_gateway_manager
    return get_gateway_manager()


class AgentCreate(BaseModel):
    id: str = Field(..., min_length=1, max_length=128, description="Unique agent identifier")
    name: str | None = Field(default=None, description="Human-friendly agent name")
    framework: str = Field(default="Autonomous / Ingress", description="Framework or runtime")
    policy_profile: str = Field(default="compiled-abac-strict", description="Active policy profile")
    description: str = Field(default="", description="Optional description of agent role")


class AgentUpdate(BaseModel):
    name: str | None = None
    framework: str | None = None
    policy_profile: str | None = None
    description: str | None = None


@router.get("")
async def list_agents(gw: GatewayManager = Depends(get_gw_manager)) -> list[dict[str, Any]]:
    """List all registered and observed agents with real-time status."""
    return gw.list_agents()


@router.post("", status_code=201)
async def register_agent(
    body: AgentCreate,
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    """Register a new autonomous agent in the gateway registry."""
    agent_id = body.id.strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="Agent ID cannot be empty")
    return gw.register_agent(
        agent_id=agent_id,
        name=body.name,
        framework=body.framework,
        policy_profile=body.policy_profile,
        description=body.description,
    )


@router.get("/{agent_id}")
async def get_agent(
    agent_id: str,
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    """Get detailed telemetry and containment status for a specific agent."""
    agent = gw.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return agent


@router.put("/{agent_id}")
async def update_agent(
    agent_id: str,
    body: AgentUpdate,
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    """Update an agent's display name, framework, policy profile, or description."""
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    updated = gw.update_agent(agent_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return updated


@router.delete("/{agent_id}")
async def delete_agent(
    agent_id: str,
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    """Deregister an agent and remove from quarantine containment."""
    success = gw.delete_agent(agent_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return {"status": "deleted", "agent_id": agent_id, "success": True}


@router.post("/{agent_id}/quarantine")
async def quarantine_agent(
    agent_id: str,
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    """Quarantine an agent, instantly blocking all subsequent tool calls."""
    success = gw.quarantine_agent(agent_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return {"status": "quarantined", "agent_id": agent_id, "success": success}


@router.post("/{agent_id}/release")
async def release_agent(
    agent_id: str,
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    """Release an agent from quarantine."""
    success = gw.release_agent(agent_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return {"status": "active", "agent_id": agent_id, "success": success}

