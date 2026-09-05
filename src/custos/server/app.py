"""FastAPI application for Custos Control Plane server."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from custos.server.config import ServerConfig
from custos.server.gateway_manager import GatewayManager
from custos.server.routes import agents, audit, health, invocations, knowledge, policies, prompts

logger = logging.getLogger(__name__)

_GW_MANAGER: GatewayManager | None = None


def get_gateway_manager() -> GatewayManager:
    global _GW_MANAGER
    if _GW_MANAGER is None:
        _GW_MANAGER = GatewayManager()
    return _GW_MANAGER


def create_app(config: ServerConfig | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    global _GW_MANAGER
    cfg = config or ServerConfig.from_env()
    _GW_MANAGER = GatewayManager(cfg)

    app = FastAPI(
        title="Custos Control Plane",
        description="Autonomous AI Agent Security & Governance Platform",
        version="1.1.1",
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API routers
    app.include_router(invocations.router)
    app.include_router(prompts.router)
    app.include_router(knowledge.router)
    app.include_router(policies.router)
    app.include_router(audit.router)
    app.include_router(health.router)
    app.include_router(agents.router)

    # WebSocket for real-time approvals
    @app.websocket("/ws/approvals")
    async def websocket_approvals(websocket: WebSocket) -> None:
        gw = get_gateway_manager()
        await gw.approval_manager.connect(websocket)
        try:
            while True:
                # Keep connection alive and accept client response messages
                data = await websocket.receive_json()
                if data.get("type") == "respond":
                    req_id = data.get("request_id")
                    choice = data.get("choice")
                    approver = data.get("approver", "ws_user")
                    if req_id and choice:
                        gw.approval_manager.resolve_prompt(req_id, choice, approver)
        except WebSocketDisconnect:
            gw.approval_manager.disconnect(websocket)
        except Exception as err:
            logger.debug("WebSocket error: %s", err)
            gw.approval_manager.disconnect(websocket)

    # UI serving
    ui_html_path = Path(__file__).parent / "ui" / "index.html"

    @app.get("/", response_class=HTMLResponse)
    async def serve_ui() -> HTMLResponse:
        if ui_html_path.exists():
            return HTMLResponse(content=ui_html_path.read_text(encoding="utf-8"))
        return HTMLResponse(content="<h1>Custos Control Plane</h1><p>UI asset not found.</p>")

    return app


# Default app instance
app = create_app()
