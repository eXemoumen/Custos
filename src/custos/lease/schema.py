"""Capability Lease schema for Custos Agent Security Runtime.

A CapabilityLease represents temporary, bounded, consumable execution authority.
Rather than granting standing permissions, Custos issues leases that constrain:
- Execution count (max_invocations)
- Validity time window (monotonic timestamp expiry)
- Maximum allowed session taint level (auto-revocation upon taint escalation)
- Target tool pattern (fnmatch pattern)
"""

from __future__ import annotations

import fnmatch
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from custos.session.schema import TaintLevel

__all__ = ["LeaseStatus", "CapabilityLease"]


class LeaseStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    EXHAUSTED = "exhausted"
    REVOKED = "revoked"
    TAINT_INVALIDATED = "taint_invalidated"


@dataclass
class CapabilityLease:
    """A bounded capability lease granting temporary execution authority."""

    tool_pattern: str
    session_id: str
    lease_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    granted_at_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    expires_at_ms: int = field(default_factory=lambda: int(time.time() * 1000) + 60_000)  # default 60s
    max_invocations: int = 1
    invocations_used: int = 0
    max_taint_level: TaintLevel = TaintLevel.CONTROLLED
    allowed_args_predicates: Mapping[str, Any] = field(default_factory=dict)
    revoked: bool = False
    revoked_reason: str = ""
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    def matches_args(self, args: Mapping[str, Any] | None) -> bool:
        """Evaluate whether the given invocation args satisfy allowed_args_predicates."""
        if not self.allowed_args_predicates:
            return True
        if args is None:
            return False
        for param, expected in self.allowed_args_predicates.items():
            if param not in args:
                return False
            actual = args[param]
            if isinstance(expected, str) and isinstance(actual, str):
                if not fnmatch.fnmatchcase(actual, expected):
                    return False
            elif actual != expected:
                return False
        return True

    def status(
        self,
        now_ms: int | None = None,
        current_taint: TaintLevel | None = None,
    ) -> LeaseStatus:
        """Evaluate the current operational status of the lease."""
        with self._lock:
            if self.revoked:
                return LeaseStatus.REVOKED

            if current_taint is not None and current_taint > self.max_taint_level:
                return LeaseStatus.TAINT_INVALIDATED

            if now_ms is None:
                now_ms = int(time.time() * 1000)

            if now_ms > self.expires_at_ms:
                return LeaseStatus.EXPIRED

            if self.invocations_used >= self.max_invocations:
                return LeaseStatus.EXHAUSTED

            return LeaseStatus.ACTIVE

    def is_valid(
        self,
        now_ms: int | None = None,
        current_taint: TaintLevel | None = None,
        args: Mapping[str, Any] | None = None,
    ) -> bool:
        """True if the lease is currently active and can be used."""
        with self._lock:
            if self.status(now_ms=now_ms, current_taint=current_taint) != LeaseStatus.ACTIVE:
                return False
            if args is not None and not self.matches_args(args):
                return False
            return True

    def consume(
        self,
        now_ms: int | None = None,
        current_taint: TaintLevel | None = None,
        args: Mapping[str, Any] | None = None,
    ) -> bool:
        """Atomically validate and consume one execution invocation under this lease.

        Thread-safe: guarantees invocations_used never exceeds max_invocations under concurrency.
        """
        with self._lock:
            now = now_ms if now_ms is not None else int(time.time() * 1000)
            if not self.is_valid(now_ms=now, current_taint=current_taint, args=args):
                return False
            self.invocations_used += 1
            return True

    def revoke(self, reason: str = "operator_revocation") -> None:
        """Immediately revoke this capability lease."""
        with self._lock:
            self.revoked = True
            self.revoked_reason = reason

    def to_dict(self) -> dict[str, Any]:
        return {
            "lease_id": self.lease_id,
            "session_id": self.session_id,
            "tool_pattern": self.tool_pattern,
            "status": self.status().value,
            "max_invocations": self.max_invocations,
            "invocations_used": self.invocations_used,
            "granted_at_ms": self.granted_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "max_taint_level": self.max_taint_level.name,
            "revoked": self.revoked,
            "revoked_reason": self.revoked_reason,
        }
