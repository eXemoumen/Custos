"""FastAPI application for Custos Control Plane server."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Security, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

from custos.schema import Decision
from custos.server.config import ServerConfig
from custos.server.gateway_manager import GatewayManager
from custos.server.routes import agents, audit, health, invocations, knowledge, policies, prompts, settings

logger = logging.getLogger(__name__)

_GW_MANAGER: GatewayManager | None = None
security_scheme = HTTPBearer(auto_error=False)


def get_auth_dependency(cfg: ServerConfig):
    """Dependency enforcing Bearer token authentication when auth_token is configured."""
    async def require_auth(
        credentials: HTTPAuthorizationCredentials | None = Security(security_scheme),
    ) -> None:
        if not cfg.auth_token:
            return
        if not credentials or credentials.scheme.lower() != "bearer" or credentials.credentials != cfg.auth_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    return require_auth


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

    auth_dep = Depends(get_auth_dependency(cfg))

    # Mount API routers
    app.include_router(invocations.router, dependencies=[auth_dep])
    app.include_router(prompts.router, dependencies=[auth_dep])
    app.include_router(knowledge.router, dependencies=[auth_dep])
    app.include_router(policies.router, dependencies=[auth_dep])
    app.include_router(audit.router, dependencies=[auth_dep])
    app.include_router(agents.router, dependencies=[auth_dep])
    app.include_router(settings.router, dependencies=[auth_dep])
    app.include_router(health.router)

    # WebSocket for real-time approvals
    @app.websocket("/ws/approvals")
    async def websocket_approvals(websocket: WebSocket, token: str | None = None) -> None:
        gw = get_gateway_manager()
        if gw.config.auth_token:
            auth_header = websocket.headers.get("authorization", "")
            header_token = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""
            client_token = token or header_token or websocket.query_params.get("token")
            if client_token != gw.config.auth_token:
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return

        await gw.approval_manager.connect(websocket)
        try:
            while True:
                try:
                    data = await websocket.receive_json()
                except WebSocketDisconnect:
                    raise
                except Exception as e:
                    logger.debug("Malformed WebSocket message: %s", e)
                    continue

                if not isinstance(data, dict):
                    continue

                msg_type = data.get("type")
                if msg_type == "ping":
                    import time
                    await websocket.send_json({"type": "pong", "ts": time.time()})
                    continue

                if msg_type == "respond":
                    req_id = data.get("request_id")
                    choice_raw = data.get("choice")
                    approver = data.get("approver", "ws_user")
                    if not req_id or not choice_raw:
                        continue

                    try:
                        choice = Decision(choice_raw)
                    except ValueError:
                        logger.warning("Invalid decision choice received over WebSocket: %r", choice_raw)
                        continue

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
