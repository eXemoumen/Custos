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
    user_id: str | None = None,
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    """Retrieve paginated audit log events with optional filtering by decision, tool, and agent/user."""
    all_events = gw.get_audit_events(limit=None, offset=0, user_id=user_id)

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


@router.get("/stats")
async def get_audit_stats(gw: GatewayManager = Depends(get_gw_manager)) -> dict[str, Any]:
    """Calculate aggregated decision distributions and high-risk tool counts from the audit ledger."""
    all_events = gw.get_audit_events(limit=None, offset=0)
    decision_counts: dict[str, int] = {}
    tool_counts: dict[str, int] = {}
    high_risk_count = 0

    for ev in all_events:
        d = ev.get("decision", "unknown")
        decision_counts[d] = decision_counts.get(d, 0) + 1
        t = ev.get("tool", "unknown")
        tool_counts[t] = tool_counts.get(t, 0) + 1
        risk = ev.get("risk_score") or ev.get("risk") or 0.0
        if isinstance(risk, (int, float)) and risk >= 0.7:
            high_risk_count += 1

    return {
        "total_events": len(all_events),
        "decision_counts": decision_counts,
        "top_tools": sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)[:10],
        "high_risk_events_count": high_risk_count,
    }


@router.post("/verify")
async def verify_audit_log(gw: GatewayManager = Depends(get_gw_manager)) -> dict[str, Any]:
    """Cryptographically verify the integrity of the hash-chained audit log."""
    return gw.verify_audit()
