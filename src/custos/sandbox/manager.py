"""BubbleManager for managing per-session execution bubbles."""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

from custos.sandbox.bubble import AgentBubble
from custos.sandbox.schema import BubbleConfig, BubbleStatus, Changeset

__all__ = ["BubbleManager"]

logger = logging.getLogger("custos.sandbox")


class BubbleManager:
    """Registry and lifecycle coordinator for active AgentBubbles."""

    def __init__(self, default_config: BubbleConfig | None = None) -> None:
        self.default_config = default_config
        self._lock = threading.RLock()
        self._bubbles: dict[str, AgentBubble] = {}

    def get_or_create(
        self,
        session_id: str,
        config: BubbleConfig | None = None,
    ) -> AgentBubble:
        """Retrieve existing bubble or initialize a new one for session_id."""
        with self._lock:
            bubble = self._bubbles.get(session_id)
            if bubble is not None:
                if bubble.status == BubbleStatus.UNINITIALIZED:
                    bubble.start()
                return bubble

            cfg = config or self.default_config
            if cfg is None:
                raise ValueError(
                    f"Cannot create AgentBubble for session {session_id!r}: no BubbleConfig provided."
                )

            bubble = AgentBubble(session_id=session_id, config=cfg)
            bubble.start()
            self._bubbles[session_id] = bubble
            return bubble

    def get_bubble(self, session_id: str) -> AgentBubble | None:
        """Look up an active bubble by session ID."""
        with self._lock:
            return self._bubbles.get(session_id)

    def commit(self, session_id: str) -> Changeset | None:
        """Commit staged changes for a session's bubble."""
        with self._lock:
            bubble = self._bubbles.get(session_id)
            if bubble is not None:
                res = bubble.commit()
                self._bubbles.pop(session_id, None)
                return res
            return None

    def rollback(self, session_id: str) -> bool:
        """Roll back and destroy a session's bubble."""
        with self._lock:
            bubble = self._bubbles.get(session_id)
            if bubble is not None:
                bubble.rollback()
                self._bubbles.pop(session_id, None)
                return True
            return False

    def rollback_all(self) -> int:
        """Emergency cleanup: rollback all active bubbles."""
        with self._lock:
            rolled_back = 0
            for sid, bubble in list(self._bubbles.items()):
                try:
                    bubble.rollback()
                    self._bubbles.pop(sid, None)
                    rolled_back += 1
                except Exception as exc:
                    logger.warning("Failed to rollback bubble for session %r: %s", sid, exc)
            return rolled_back
