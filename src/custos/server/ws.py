"""Real-time WebSocket dispatcher and Human-in-the-Loop approval manager for Custos Server."""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import threading
import time
from typing import Any
import uuid

from fastapi import WebSocket

from custos.responders.base import PromptRequest, PromptResponse, Responder, ResponderAsync
from custos.schema import Decision

logger = logging.getLogger(__name__)

async_mode_ctx: contextvars.ContextVar[bool] = contextvars.ContextVar("server_approval_async_mode", default=False)


class ServerApprovalManager:
    """Manages active WebSockets and pending Human-in-the-Loop prompts."""

    def __init__(self, default_timeout_seconds: float = 60.0) -> None:
        self.default_timeout_seconds = default_timeout_seconds
        self._active_sockets: set[WebSocket] = set()
        self._lock = threading.Lock()
        # request_id -> (PromptRequest, threading.Event, holder dict for result, created_at)
        self._pending: dict[str, tuple[PromptRequest, threading.Event, dict[str, Any], float]] = {}

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        with self._lock:
            self._active_sockets.add(websocket)
        logger.info("WebSocket client connected. Total clients: %d", len(self._active_sockets))

        # Send current pending prompts to new client
        pending_list = self.list_pending()
        await websocket.send_text(json.dumps({
            "type": "initial_state",
            "pending_prompts": pending_list,
        }))

    def disconnect(self, websocket: WebSocket) -> None:
        with self._lock:
            self._active_sockets.discard(websocket)
        logger.info("WebSocket client disconnected. Total clients: %d", len(self._active_sockets))

    def list_pending(self) -> list[dict[str, Any]]:
        with self._lock:
            now_ms = int(time.time() * 1000)
            # Prune expired prompts
            expired = [
                req_id for req_id, (req, _, _, _) in self._pending.items()
                if req.deadline_unix_ms and now_ms > req.deadline_unix_ms
            ]
            for req_id in expired:
                self._pending.pop(req_id, None)

            prompts = []
            for req_id, (req, _, _, created_at) in self._pending.items():
                prompts.append({
                    "request_id": req_id,
                    "tool": req.tool,
                    "args": dict(req.args_redacted),
                    "risk": req.risk,
                    "reasoning": req.reasoning,
                    "options": [opt.value for opt in req.options],
                    "created_at": created_at,
                    "deadline_ms": req.deadline_unix_ms,
                })
            return prompts

    def broadcast_sync(self, message: dict[str, Any]) -> None:
        """Broadcasts a message to all active WebSocket clients safely across threads."""
        text = json.dumps(message)
        with self._lock:
            sockets = list(self._active_sockets)

        for ws in sockets:
            try:
                # Use call_soon_threadsafe if an event loop is running
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.run_coroutine_threadsafe(ws.send_text(text), loop)
            except Exception as err:
                logger.debug("Failed to send to WebSocket: %s", err)

    def get_prompt(self, request_id: str) -> dict[str, Any] | None:
        """Retrieve details of a single pending prompt."""
        with self._lock:
            entry = self._pending.get(request_id)
            if entry is None:
                return None
            req, _, _, created_at = entry
            return {
                "request_id": request_id,
                "tool": req.tool,
                "args": dict(req.args_redacted),
                "risk": req.risk,
                "reasoning": req.reasoning,
                "options": [opt.value for opt in req.options],
                "created_at": created_at,
                "deadline_ms": req.deadline_unix_ms,
            }

    def cancel_prompt(self, request_id: str, reason: str = "cancelled_by_operator") -> bool:
        """Cancel a pending prompt, automatically resolving it with DENY."""
        return self.resolve_prompt(request_id, Decision.DENY, approver=reason)

    def batch_resolve_prompts(
        self,
        resolutions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Resolve multiple pending prompts in a single batch operation."""
        results = []
        for item in resolutions:
            req_id = item.get("request_id")
            choice = item.get("choice")
            approver = item.get("approver", "batch_admin")
            if not req_id or not choice:
                results.append({"request_id": req_id, "success": False, "error": "Missing request_id or choice"})
                continue
            try:
                dec = Decision(choice)
                success = self.resolve_prompt(req_id, dec, approver=approver)
                results.append({"request_id": req_id, "success": success, "choice": dec.value})
            except Exception as e:
                results.append({"request_id": req_id, "success": False, "error": str(e)})
        return results

    def broadcast_agent_status(self, agent_id: str, status: str) -> None:
        """Broadcast real-time agent containment/status transition to all connected WebSockets."""
        self.broadcast_sync({
            "type": "agent_status_changed",
            "agent_id": agent_id,
            "status": status,
            "ts": time.time(),
        })

    def resolve_prompt(
        self,
        request_id: str,
        choice: str | Decision,
        approver: str = "web_user",
    ) -> bool:
        """Resolves a pending prompt and unblocks the waiting gateway thread."""
        with self._lock:
            entry = self._pending.pop(request_id, None)
            if entry is None:
                return False

            req, event, result_holder, _ = entry
            decision_enum = Decision(choice) if isinstance(choice, str) else choice
            result_holder["response"] = PromptResponse(
                choice=decision_enum,
                approver=approver,
            )
            event.set()

        self.broadcast_sync({
            "type": "prompt_resolved",
            "request_id": request_id,
            "choice": decision_enum.value,
            "approver": approver,
        })
        return True

    def submit_async(self, req: PromptRequest) -> tuple[PromptResponse, str]:
        """Registers a prompt request non-blockingly and broadcasts to connected clients."""
        req_id = req.request_id or f"prompt-{uuid.uuid4()}"
        event = threading.Event()
        result_holder: dict[str, Any] = {}

        timeout = self.default_timeout_seconds
        if req.deadline_unix_ms:
            now_ms = int(time.time() * 1000)
            timeout = max(1.0, (req.deadline_unix_ms - now_ms) / 1000.0)

        with self._lock:
            self._pending[req_id] = (req, event, result_holder, time.time())

        # Notify UI clients
        self.broadcast_sync({
            "type": "prompt_requested",
            "data": {
                "request_id": req_id,
                "tool": req.tool,
                "args": dict(req.args_redacted),
                "risk": req.risk,
                "reasoning": req.reasoning,
                "options": [opt.value for opt in req.options],
                "timeout_seconds": timeout,
            },
        })
        logger.info("Prompt %s registered in async mode (non-blocking)", req_id)
        return PromptResponse(choice=Decision.PROMPT, approver="pending"), req_id

    def submit_and_wait(self, req: PromptRequest) -> PromptResponse:
        """Submits a prompt request and blocks until a user responds or timeout expires."""
        if async_mode_ctx.get():
            resp, _ = self.submit_async(req)
            return resp

        req_id = req.request_id or f"prompt-{uuid.uuid4()}"
        event = threading.Event()
        result_holder: dict[str, Any] = {}

        timeout = self.default_timeout_seconds
        if req.deadline_unix_ms:
            now_ms = int(time.time() * 1000)
            timeout = max(1.0, (req.deadline_unix_ms - now_ms) / 1000.0)

        with self._lock:
            self._pending[req_id] = (req, event, result_holder, time.time())

        # Notify UI clients
        self.broadcast_sync({
            "type": "prompt_requested",
            "data": {
                "request_id": req_id,
                "tool": req.tool,
                "args": dict(req.args_redacted),
                "risk": req.risk,
                "reasoning": req.reasoning,
                "options": [opt.value for opt in req.options],
                "timeout_seconds": timeout,
            },
        })

        # Block until human responds or timeout
        signaled = event.wait(timeout=timeout)

        with self._lock:
            self._pending.pop(req_id, None)

        if not signaled or "response" not in result_holder:
            logger.warning("Prompt %s timed out after %.1fs -> DENY", req_id, timeout)
            self.broadcast_sync({
                "type": "prompt_timed_out",
                "request_id": req_id,
            })
            return PromptResponse(choice=Decision.DENY, approver="system_timeout")

        return result_holder["response"]


class ServerResponder(Responder, ResponderAsync):
    """Responder that routes prompt requests to the ServerApprovalManager."""

    name = "server-web"

    def __init__(self, manager: ServerApprovalManager) -> None:
        self.manager = manager

    def prompt(self, req: PromptRequest) -> PromptResponse:
        return self.manager.submit_and_wait(req)

    async def prompt_async(self, req: PromptRequest) -> PromptResponse:
        return await asyncio.to_thread(self.manager.submit_and_wait, req)
