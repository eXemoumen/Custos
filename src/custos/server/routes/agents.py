"""Agents endpoint: inspect and manage autonomous agent identity and quarantine status."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from custos.server.gateway_manager import GatewayManager

router = APIRouter(prefix="/api/v1/agents", tags=["Agents"])


def get_gw_manager() -> GatewayManager:
    from custos.server.app import get_gateway_manager
    return get_gateway_manager()


@router.get("")
async def list_agents(gw: GatewayManager = Depends(get_gw_manager)) -> list[dict[str, Any]]:
    """List all registered and observed agents with real-time status."""
    return gw.list_agents()


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
