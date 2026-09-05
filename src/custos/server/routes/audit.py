"""Audit routes: fetch logs and verify tamper-evident hash chain."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from custos.server.gateway_manager import GatewayManager

router = APIRouter(prefix="/api/v1/audit", tags=["Audit"])


def get_gw_manager() -> GatewayManager:
    from custos.server.app import get_gateway_manager
    return get_gateway_manager()


@router.get("")
async def get_audit_events(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    decision: str | None = None,
    tool: str | None = None,
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    """Retrieve paginated audit log events with optional filtering."""
    all_events = gw.get_audit_events(limit=None, offset=0)

    filtered = all_events
    if decision:
        filtered = [e for e in filtered if e.get("decision") == decision]
    if tool:
        filtered = [e for e in filtered if tool in e.get("tool", "")]

    paged = filtered[offset : offset + limit]
    return {
        "total": len(filtered),
        "limit": limit,
        "offset": offset,
        "events": paged,
    }


@router.post("/verify")
async def verify_audit_log(gw: GatewayManager = Depends(get_gw_manager)) -> dict[str, Any]:
    """Cryptographically verify the integrity of the hash-chained audit log."""
    return gw.verify_audit()
