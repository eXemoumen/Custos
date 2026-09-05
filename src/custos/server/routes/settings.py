"""Settings endpoint: inspect and update gateway runtime settings."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from custos.server.gateway_manager import GatewayManager

router = APIRouter(prefix="/api/v1/settings", tags=["Settings"])


def get_gw_manager() -> GatewayManager:
    from custos.server.app import get_gateway_manager
    return get_gateway_manager()


class SettingsUpdate(BaseModel):
    default_action: str | None = None
    ollama_url: str | None = None
    ollama_model: str | None = None
    hmac_key: str | None = None


@router.get("")
async def get_settings(gw: GatewayManager = Depends(get_gw_manager)) -> dict[str, Any]:
    """Return current server settings with masked HMAC key."""
    has_key = bool(gw.config.hmac_key)
    return {
        "default_action": gw._policy._default,
        "ollama_url": gw.config.ollama_url or "http://localhost:11434",
        "ollama_model": gw.config.ollama_model or "llama3.2",
        "hmac_key_configured": has_key,
        "hmac_key_masked": "••••••••" if has_key else "",
    }


@router.put("")
async def update_settings(
    body: SettingsUpdate,
    gw: GatewayManager = Depends(get_gw_manager),
) -> dict[str, Any]:
    """Persist updated gateway settings."""
    with gw._lock:
        if body.default_action is not None:
            action = body.default_action.lower().strip()
            if action not in ("deny", "prompt", "allow"):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid default action. Must be 'deny', 'prompt', or 'allow'",
                )
            gw._policy._default = action
        if body.ollama_url is not None:
            gw.config.ollama_url = body.ollama_url
            if hasattr(gw.kb_assistant, "intent_checker"):
                gw.kb_assistant.intent_checker.ollama_url = body.ollama_url
        if body.ollama_model is not None:
            gw.config.ollama_model = body.ollama_model
            if hasattr(gw.kb_assistant, "intent_checker"):
                gw.kb_assistant.intent_checker.ollama_model = body.ollama_model
        if body.hmac_key is not None and body.hmac_key.strip():
            gw.config.hmac_key = body.hmac_key.strip()
            if hasattr(gw.audit_sink, "_signing_key"):
                gw.audit_sink._signing_key = body.hmac_key.strip().encode("utf-8")

    return {"status": "success", "message": "Settings updated successfully"}
