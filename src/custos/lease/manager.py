"""Capability lease manager for issuing, validating, and revoking leases."""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any

from custos.lease.schema import CapabilityLease
from custos.session.schema import AgentSession, TaintLevel

__all__ = ["LeaseManager"]


class LeaseManager:
    """Manages creation and lifecycle of capability leases attached to agent sessions."""

    @staticmethod
    def issue_lease(
        session: AgentSession,
        tool_pattern: str,
        *,
        ttl_seconds: float = 60.0,
        max_invocations: int = 1,
        max_taint_level: TaintLevel = TaintLevel.CONTROLLED,
        allowed_args_predicates: Mapping[str, Any] | None = None,
    ) -> CapabilityLease:
        """Issue a new capability lease and register it to the session."""
        now_ms = int(time.time() * 1000)
        expires_at_ms = now_ms + int(ttl_seconds * 1000)

        lease = CapabilityLease(
            tool_pattern=tool_pattern,
            session_id=session.session_id,
            granted_at_ms=now_ms,
            expires_at_ms=expires_at_ms,
            max_invocations=max_invocations,
            max_taint_level=max_taint_level,
            allowed_args_predicates=allowed_args_predicates or {},
        )
        session.add_lease(lease)
        return lease

    @staticmethod
    def revoke_all(session: AgentSession, reason: str = "session_reset") -> int:
        """Revoke all active leases in a session. Returns count of revoked leases."""
        count = 0
        for lease in session.active_leases.values():
            if not lease.revoked:
                lease.revoke(reason=reason)
                count += 1
        return count
