"""Health and status endpoint for Custos Server."""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends

from custos import __version__
from custos.server.gateway_manager import GatewayManager

router = APIRouter(prefix="/api/v1/health", tags=["Health"])


def get_gw_manager() -> GatewayManager:
    from custos.server.app import get_gateway_manager
    return get_gateway_manager()


_START_TIME = time.time()


@router.get("")
async def get_health_status(gw: GatewayManager = Depends(get_gw_manager)) -> dict[str, Any]:
    """Retrieve runtime health and diagnostic metrics."""
    pending_prompts = gw.approval_manager.list_pending()
    metrics = gw.get_metrics()
    return {
        "status": "healthy",
        "version": __version__,
        "uptime_seconds": round(time.time() - _START_TIME, 1),
        "gateway": {
            "active_rules": len(gw._policy._rules_ro),
            "pending_prompts": len(pending_prompts),
            "kb_assets": len(gw.kb_store.list_assets()),
            "kb_rules": len(gw.kb_store.list_rules()),
            "kb_threats": len(gw.kb_store.list_threats()),
        },
        "metrics": metrics,
    }
