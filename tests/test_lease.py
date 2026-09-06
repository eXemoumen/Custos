"""Tests for Capability Leasing (Custos Agent Security Runtime)."""

import time
import pytest

from custos.lease import CapabilityLease, LeaseManager, LeaseStatus
from custos.session import AgentSession, TaintLevel


def test_capability_lease_consumption():
    session = AgentSession(session_id="sess_lease")
    lease = LeaseManager.issue_lease(
        session,
        "git.push",
        ttl_seconds=10.0,
        max_invocations=2,
        max_taint_level=TaintLevel.CONTROLLED,
    )

    assert lease.status() == LeaseStatus.ACTIVE
    assert lease.is_valid() is True

    # Check lookup in session
    found = session.get_valid_lease("git.push")
    assert found is lease
    assert session.get_valid_lease("fs.delete") is None

    # First consumption
    consumed = session.consume_lease("git.push")
    assert consumed is lease
    assert lease.invocations_used == 1
    assert lease.is_valid() is True

    # Second consumption
    consumed = session.consume_lease("git.push")
    assert consumed is lease
    assert lease.invocations_used == 2
    assert lease.status() == LeaseStatus.EXHAUSTED
    assert lease.is_valid() is False

    # Third consumption fails
    consumed = session.consume_lease("git.push")
    assert consumed is None


def test_capability_lease_expiration():
    session = AgentSession(session_id="sess_exp")
    lease = LeaseManager.issue_lease(
        session,
        "deploy.*",
        ttl_seconds=0.1,  # 100ms
        max_invocations=5,
    )
    assert lease.is_valid() is True

    time.sleep(0.15)
    assert lease.status() == LeaseStatus.EXPIRED
    assert lease.is_valid() is False
    assert session.get_valid_lease("deploy.staging") is None


def test_capability_lease_taint_invalidation():
    session = AgentSession(session_id="sess_taint_lease")
    lease = LeaseManager.issue_lease(
        session,
        "payments.transfer",
        max_taint_level=TaintLevel.CONTROLLED,
    )
    assert lease.is_valid(current_taint=session.taint_level) is True

    # Ingest controlled source -> lease stays valid
    session.ingest_source("internal_db", "db_table", TaintLevel.CONTROLLED)
    assert lease.is_valid(current_taint=session.taint_level) is True

    # Ingest untrusted source (e.g. web search) -> lease is automatically revoked/invalidated!
    session.ingest_source("external_web", "web", TaintLevel.UNTRUSTED)
    assert session.taint_level == TaintLevel.UNTRUSTED
    assert lease.revoked is True
    assert "taint escalated" in lease.revoked_reason
    assert lease.is_valid() is False
    assert session.get_valid_lease("payments.transfer") is None


def test_lease_manager_revoke_all():
    session = AgentSession(session_id="sess_revoke_all")
    l1 = LeaseManager.issue_lease(session, "fs.*")
    l2 = LeaseManager.issue_lease(session, "net.*")

    assert l1.is_valid() is True
    assert l2.is_valid() is True

    revoked_count = LeaseManager.revoke_all(session, reason="security_lockdown")
    assert revoked_count == 2
    assert l1.is_valid() is False
    assert l2.is_valid() is False
    assert l1.revoked_reason == "security_lockdown"
