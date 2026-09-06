"""Session store implementations for Custos Agent Security Runtime.

Provides:
- SessionStore (sync Protocol) and SessionStoreAsync (async Protocol)
- InMemorySessionStore: thread-safe, TTL-evicted in-memory store
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from custos.session.schema import AgentSession

if TYPE_CHECKING:
    from custos.schema import SubjectContext

__all__ = ["SessionStore", "SessionStoreAsync", "InMemorySessionStore"]


@runtime_checkable
class SessionStore(Protocol):
    """Protocol for synchronous session storage."""

    def get_or_create(
        self, session_id: str, subject: SubjectContext | None = None
    ) -> AgentSession:
        """Retrieve existing session or create and register a new one."""
        ...

    def get(self, session_id: str) -> AgentSession | None:
        """Retrieve an existing session if present and unexpired."""
        ...

    def put(self, session: AgentSession) -> None:
        """Store or update an active session."""
        ...

    def delete(self, session_id: str) -> bool:
        """Remove a session from storage."""
        ...

    def clear(self) -> None:
        """Invalidate all stored sessions."""
        ...


@runtime_checkable
class SessionStoreAsync(Protocol):
    """Protocol for asynchronous session storage."""

    async def get_or_create(
        self, session_id: str, subject: SubjectContext | None = None
    ) -> AgentSession:
        ...

    async def get(self, session_id: str) -> AgentSession | None:
        ...

    async def put(self, session: AgentSession) -> None:
        ...

    async def delete(self, session_id: str) -> bool:
        ...

    async def clear(self) -> None:
        ...


class InMemorySessionStore:
    """Thread-safe in-memory session store with TTL and LRU eviction.

    Attributes:
        max_sessions: maximum active sessions retained before LRU pruning.
        ttl_ms: session lifetime in milliseconds (default 1 hour).
    """

    def __init__(self, *, max_sessions: int = 10_000, ttl_ms: int = 3_600_000) -> None:
        self.max_sessions = max_sessions
        self.ttl_ms = ttl_ms
        self._lock = threading.RLock()
        self._sessions: OrderedDict[str, AgentSession] = OrderedDict()

    def get_or_create(
        self, session_id: str, subject: SubjectContext | None = None
    ) -> AgentSession:
        with self._lock:
            self._prune_expired()
            session = self._sessions.get(session_id)
            if session is not None:
                # Security check: Prevent session hijacking across distinct user principals!
                if subject is not None and session.subject is not None:
                    if session.subject.user_id != subject.user_id:
                        raise PermissionError(
                            f"Session hijacking detected: session {session_id!r} is owned by "
                            f"{session.subject.user_id!r}, cannot be accessed by {subject.user_id!r}"
                        )
                # Move to end for LRU
                self._sessions.move_to_end(session_id)
                session.last_active_ms = int(time.time() * 1000)
                if subject is not None and session.subject is None:
                    session.subject = subject
                return session

            # Create new
            session = AgentSession(session_id=session_id, subject=subject)
            self._sessions[session_id] = session
            if len(self._sessions) > self.max_sessions:
                # Evict oldest
                self._sessions.popitem(last=False)
            return session

    def get(self, session_id: str) -> AgentSession | None:
        with self._lock:
            self._prune_expired()
            session = self._sessions.get(session_id)
            if session is not None:
                self._sessions.move_to_end(session_id)
                session.last_active_ms = int(time.time() * 1000)
            return session

    def put(self, session: AgentSession) -> None:
        with self._lock:
            self._prune_expired()
            self._sessions[session.session_id] = session
            self._sessions.move_to_end(session.session_id)
            if len(self._sessions) > self.max_sessions:
                self._sessions.popitem(last=False)

    def delete(self, session_id: str) -> bool:
        with self._lock:
            return bool(self._sessions.pop(session_id, None))

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()

    def _prune_expired(self) -> None:
        """Evict sessions that have exceeded ttl_ms since last activity."""
        now = int(time.time() * 1000)
        expired_keys = [
            sid
            for sid, sess in self._sessions.items()
            if (now - sess.last_active_ms) > self.ttl_ms
        ]
        for sid in expired_keys:
            self._sessions.pop(sid, None)
