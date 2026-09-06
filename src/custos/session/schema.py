"""Session and Taint schemas for Custos Agent Security Runtime.

Defines:
- TaintLevel: strictly monotonic security lattice (TRUSTED -> TAINTED_MALICIOUS).
- TaintSourceRecord: provenance record for ingested input sources.
- SessionInvocationRecord: lightweight trajectory entry for behavioral auditing.
- AgentSession: stateful container tracking identity, monotonic taint, active capability leases, and execution history.
"""

from __future__ import annotations

import fnmatch
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from custos.lease.schema import CapabilityLease
    from custos.schema import Decision, Invocation, SubjectContext

__all__ = [
    "TaintLevel",
    "TaintSourceRecord",
    "SessionInvocationRecord",
    "AgentSession",
]


class TaintLevel(IntEnum):
    """Monotonic security lattice representing data trustworthiness.

    Lattice order (lower number = higher trust, higher number = higher risk):
      0. TRUSTED: System prompt, verified operator instruction, sealed internal assets.
      1. CONTROLLED: Internal authenticated databases/APIs, vetted enterprise stores.
      2. SEMI_TRUSTED: Standard tool outputs, outputs from verified subagents.
      3. UNTRUSTED: Web search, public URLs, inbound emails, untrusted files, MCP tools.
      4. TAINTED_MALICIOUS: Attributed prompt injection, malicious payloads, hostile input.
    """

    TRUSTED = 0
    CONTROLLED = 1
    SEMI_TRUSTED = 2
    UNTRUSTED = 3
    TAINTED_MALICIOUS = 4

    @classmethod
    def from_value(cls, val: Any) -> TaintLevel:
        """Coerce int, string name, or TaintLevel into a canonical TaintLevel."""
        if isinstance(val, TaintLevel):
            return val
        if isinstance(val, int):
            return cls(val)
        if isinstance(val, str):
            val_clean = val.strip().upper()
            try:
                return cls[val_clean]
            except KeyError:
                # Support integer string representations e.g. "3"
                if val_clean.isdigit():
                    return cls(int(val_clean))
                raise ValueError(f"Unknown TaintLevel name: {val!r}")
        raise TypeError(f"Cannot coerce {type(val).__name__} to TaintLevel")


@dataclass(frozen=True)
class TaintSourceRecord:
    """Provenance entry recording an untrusted input source ingested by an agent."""

    source_id: str
    source_type: str
    taint_level: TaintLevel
    ts_unix_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    content_hash: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_type": self.source_type,
            "taint_level": self.taint_level.name,
            "ts_unix_ms": self.ts_unix_ms,
            "content_hash": self.content_hash,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class SessionInvocationRecord:
    """Lightweight historical record of an invocation executed within a session."""

    tool: str
    decision: str
    risk_score: float
    ts_unix_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    taint_level: TaintLevel = TaintLevel.TRUSTED
    lease_id: str | None = None
    policy_match: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "decision": self.decision,
            "risk_score": self.risk_score,
            "ts_unix_ms": self.ts_unix_ms,
            "taint_level": self.taint_level.name,
            "lease_id": self.lease_id,
            "policy_match": self.policy_match,
        }


@dataclass
class AgentSession:
    """Stateful execution container for an autonomous agent process.

    Maintains:
    - Process identity and delegation scope
    - Monotonic taint level and full data provenance chain
    - Active capability leases
    - Rolling execution trajectory (ring-buffer)
    - Dynamic trust score and quarantine status
    """

    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    subject: SubjectContext | None = None
    taint_level: TaintLevel = TaintLevel.TRUSTED
    taint_sources: list[TaintSourceRecord] = field(default_factory=list)
    active_leases: dict[str, CapabilityLease] = field(default_factory=dict)
    history: list[SessionInvocationRecord] = field(default_factory=list)
    trust_score: float = 1.0
    is_quarantined: bool = False
    quarantine_reason: str = ""
    created_at_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    last_active_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    max_history_entries: int = 200
    metadata: dict[str, Any] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    def ingest_source(
        self,
        source_id: str,
        source_type: str,
        taint: TaintLevel | int | str,
        *,
        content_hash: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> bool:
        """Ingest an untrusted source into the session.

        Updates the session taint monotonically:
            session.taint_level = max(session.taint_level, source.taint_level)

        Returns True if session taint escalated, False otherwise.
        """
        with self._lock:
            now = int(time.time() * 1000)
            self.last_active_ms = now
            source_taint = TaintLevel.from_value(taint)

            record = TaintSourceRecord(
                source_id=source_id,
                source_type=source_type,
                taint_level=source_taint,
                ts_unix_ms=now,
                content_hash=content_hash,
                metadata=metadata or {},
            )
            self.taint_sources.append(record)

            escalated = source_taint > self.taint_level
            if escalated:
                self.taint_level = source_taint
                self._invalidate_tainted_leases()

            return escalated

    def _invalidate_tainted_leases(self) -> None:
        """Invalidate active capability leases whose max_taint_level is exceeded."""
        for lease in list(self.active_leases.values()):
            if lease.max_taint_level < self.taint_level:
                lease.revoke(reason=f"session taint escalated to {self.taint_level.name}")

    def add_lease(self, lease: CapabilityLease) -> None:
        """Register a new capability lease on this session."""
        with self._lock:
            self.active_leases[lease.lease_id] = lease

    def get_valid_lease(
        self,
        tool: str,
        now_ms: int | None = None,
        args: Mapping[str, Any] | None = None,
    ) -> CapabilityLease | None:
        """Find an active, unexpired, unexhausted lease covering `tool` and matching `args`."""
        with self._lock:
            if now_ms is None:
                now_ms = int(time.time() * 1000)

            for lease in list(self.active_leases.values()):
                if lease.is_valid(now_ms=now_ms, current_taint=self.taint_level, args=args):
                    if fnmatch.fnmatchcase(tool, lease.tool_pattern):
                        return lease
            return None

    def consume_lease(
        self,
        tool: str,
        now_ms: int | None = None,
        args: Mapping[str, Any] | None = None,
    ) -> CapabilityLease | None:
        """Atomically consume one use of a valid capability lease for `tool`."""
        with self._lock:
            lease = self.get_valid_lease(tool, now_ms=now_ms, args=args)
            if lease is not None and lease.consume(now_ms=now_ms, current_taint=self.taint_level, args=args):
                return lease
            return None

    def record_invocation(
        self,
        tool: str,
        decision: Decision | str,
        risk_score: float = 0.0,
        *,
        lease_id: str | None = None,
        policy_match: str | None = None,
    ) -> None:
        """Record an execution step into the session history ring buffer."""
        with self._lock:
            now = int(time.time() * 1000)
            self.last_active_ms = now
            decision_val = decision.value if hasattr(decision, "value") else str(decision)

            entry = SessionInvocationRecord(
                tool=tool,
                decision=decision_val,
                risk_score=risk_score,
                ts_unix_ms=now,
                taint_level=self.taint_level,
                lease_id=lease_id,
                policy_match=policy_match,
            )
            self.history.append(entry)
            if len(self.history) > self.max_history_entries:
                self.history.pop(0)

    def quarantine(self, reason: str) -> None:
        """Soft-quarantine this session. Preserves state for forensic inspection."""
        with self._lock:
            self.is_quarantined = True
            self.quarantine_reason = reason
            self.taint_level = TaintLevel.TAINTED_MALICIOUS
            self._invalidate_tainted_leases()

    def to_dict(self) -> dict[str, Any]:
        """Serialize session state for forensic audit or inspection."""
        with self._lock:
            return {
                "session_id": self.session_id,
                "subject": self.subject.to_dict() if self.subject and hasattr(self.subject, "to_dict") else None,
                "taint_level": self.taint_level.name,
                "taint_sources": [s.to_dict() for s in self.taint_sources],
                "active_leases": [l.to_dict() for l in self.active_leases.values()],
                "history_count": len(self.history),
                "trust_score": self.trust_score,
                "is_quarantined": self.is_quarantined,
                "quarantine_reason": self.quarantine_reason,
                "created_at_ms": self.created_at_ms,
                "last_active_ms": self.last_active_ms,
            }
