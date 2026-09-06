import asyncio
import functools
import time
from pathlib import Path
from typing import Any
import pytest

from custos.async_gateway import AsyncGateway
from custos.gateway import Gateway
from custos.lease import LeaseManager
from custos.policy import Policy, PolicyRuleSpec, Rule
from custos.sandbox.manager import BubbleManager
from custos.sandbox.schema import BubbleConfig, BubbleStatus, EgressMode, IsolationLevel
from custos.schema import (
    ContextSnapshot,
    Decision,
    InputSource,
    Invocation,
    SubjectContext,
    TaintLevel,
)
from custos.session import InMemorySessionStore


def _async_test(coro_fn):
    @functools.wraps(coro_fn)
    def runner(*args: Any, **kwargs: Any) -> None:
        return asyncio.run(coro_fn(*args, **kwargs))

    return runner


def test_gateway_bubble_binding_and_audit(tmp_path: Path):
    """Gateway automatically binds an AgentBubble to the session and includes bubble_id in audit events."""
    policy = Policy(default="allow")
    bubble_mgr = BubbleManager(
        default_config=BubbleConfig(
            workspace_root=tmp_path,
            isolation_level=IsolationLevel.LOCAL,
        )
    )
    store = InMemorySessionStore()
    gw = Gateway(policy=policy, session_store=store, bubble_manager=bubble_mgr)

    ctx = SubjectContext(user_id="alice", session_id="sess_bubble_audit")
    inv = Invocation(tool="file.write", args={"path": "notes.txt", "content": "hello"}, context=ctx)

    res = gw.decide(inv)
    assert res.decision == Decision.ALLOW
    assert res.audit.bubble_id is not None
    assert res.audit.session_id == "sess_bubble_audit"

    # Verify session has the attached bubble
    session = store.get("sess_bubble_audit")
    assert session is not None
    assert session.bubble is not None
    assert session.bubble.bubble_id == res.audit.bubble_id
    assert session.bubble.status == BubbleStatus.ACTIVE

    bubble_mgr.rollback_all()


def test_gateway_taint_escalation_triggers_egress_degradation(tmp_path: Path):
    """Ingesting an UNTRUSTED source into the session must monotonically degrade bubble egress."""
    policy = Policy(default="allow")
    bubble_mgr = BubbleManager(
        default_config=BubbleConfig(
            workspace_root=tmp_path,
            isolation_level=IsolationLevel.LOCAL,
            allowed_egress_domains=("api.github.com",),
        )
    )
    store = InMemorySessionStore()
    gw = Gateway(policy=policy, session_store=store, bubble_manager=bubble_mgr)

    ctx = SubjectContext(user_id="bob", session_id="sess_taint_egress")
    inv1 = Invocation(tool="web.search", args={"q": "rust docs"}, context=ctx)
    res1 = gw.decide(inv1)
    assert res1.decision == Decision.ALLOW

    session = store.get("sess_taint_egress")
    assert session is not None
    assert session.bubble.egress.mode == EgressMode.ALLOWLISTED

    # Egress check on allowlisted domain
    allowed, _ = session.bubble.egress.check_request(method="POST", url="https://api.github.com/repos")
    assert allowed

    # Now ingest untrusted web scrape snapshot
    snapshot = ContextSnapshot(
        ts_unix_ms=int(time.time() * 1000),
        sources=(
            InputSource(
                source_id="web:untrusted_blog",
                source_type="web",
                content="untrusted content",
                taint_level=TaintLevel.UNTRUSTED,
            ),
        ),
    )
    inv2 = Invocation(tool="code.parse", args={"file": "test.py"}, context=ctx)
    gw.decide(inv2, snapshot=snapshot)

    # Session taint escalated -> bubble egress degraded to READ_ONLY
    assert session.taint_level == TaintLevel.UNTRUSTED
    assert session.bubble.egress.mode == EgressMode.READ_ONLY

    # In READ_ONLY mode, GET is permitted, POST/PUT/DELETE is blocked!
    allowed_get, _ = session.bubble.egress.check_request(method="GET", url="https://api.github.com/repos")
    assert allowed_get

    blocked_post, reason = session.bubble.egress.check_request(method="POST", url="https://api.github.com/repos")
    assert not blocked_post
    assert "drops payload under READ_ONLY egress mode" in reason

    bubble_mgr.rollback_all()


def test_gateway_quarantine_wipes_bubble(tmp_path: Path):
    """When a session is quarantined, the bubble's staged worktree is automatically purged."""
    # Policy with an inspector rule that triggers quarantine
    policy = Policy(default="allow")
    bubble_mgr = BubbleManager(
        default_config=BubbleConfig(
            workspace_root=tmp_path,
            isolation_level=IsolationLevel.LOCAL,
        )
    )
    store = InMemorySessionStore()
    gw = Gateway(policy=policy, session_store=store, bubble_manager=bubble_mgr)

    ctx = SubjectContext(user_id="charlie", session_id="sess_quarantine_wipe")
    inv = Invocation(tool="file.write", args={"path": "evil.sh"}, context=ctx)
    gw.decide(inv)

    session = store.get("sess_quarantine_wipe")
    bubble = session.bubble
    assert bubble.status == BubbleStatus.ACTIVE

    # Write a staged file into the bubble worktree
    staged_file = bubble.resolve_path("malicious.sh")
    staged_file.write_text("rm -rf /", encoding="utf-8")
    assert staged_file.exists()

    # Base workspace is untouched
    assert not (tmp_path / "malicious.sh").exists()

    # Trigger quarantine on session
    session.quarantine("Prompt injection detected")

    # The bubble should have executed rollback and set status to QUARANTINED
    assert bubble.status == BubbleStatus.QUARANTINED
    assert not bubble.worktree_path.exists()
    assert not (tmp_path / "malicious.sh").exists()

    # Subsequent gateway calls are blocked under quarantine
    res_subsequent = gw.decide(inv)
    assert res_subsequent.decision == Decision.QUARANTINE
    assert res_subsequent.audit.bubble_id == bubble.bubble_id

    bubble_mgr.rollback_all()


@_async_test
async def test_async_gateway_bubble_integration(tmp_path: Path):
    """AsyncGateway correctly binds bubble and handles quarantine rollback."""
    policy = Policy(default="allow")
    bubble_mgr = BubbleManager(
        default_config=BubbleConfig(
            workspace_root=tmp_path,
            isolation_level=IsolationLevel.LOCAL,
        )
    )
    store = InMemorySessionStore()
    async_gw = AsyncGateway(policy=policy, session_store=store, bubble_manager=bubble_mgr)

    ctx = SubjectContext(user_id="dana", session_id="sess_async_bubble")
    inv = Invocation(tool="bash.exec", args={"cmd": "ls"}, context=ctx)

    res = await async_gw.decide(inv)
    assert res.decision == Decision.ALLOW
    assert res.audit.bubble_id is not None

    session = store.get("sess_async_bubble")
    assert session is not None
    assert session.bubble is not None
    assert session.bubble.bubble_id == res.audit.bubble_id

    # Quarantine session in async gateway
    session.quarantine("Async violation detected")
    assert session.bubble.status == BubbleStatus.QUARANTINED
    assert not session.bubble.worktree_path.exists()

    res_quarantined = await async_gw.decide(inv)
    assert res_quarantined.decision == Decision.QUARANTINE
    assert res_quarantined.audit.bubble_id == session.bubble.bubble_id

    bubble_mgr.rollback_all()


def test_lease_taint_invalidation_with_bubble(tmp_path: Path):
    """Invariant 6: capability leases are invalidated on taint escalation in the bubble."""
    policy = Policy(
        rules=[
            Rule(
                PolicyRuleSpec(
                    match={"tool": "git.push", "requires_lease": True},
                    action="allow",
                )
            )
        ],
        default="deny",
    )
    bubble_mgr = BubbleManager(
        default_config=BubbleConfig(
            workspace_root=tmp_path,
            isolation_level=IsolationLevel.LOCAL,
        )
    )
    store = InMemorySessionStore()
    gw = Gateway(policy=policy, session_store=store, bubble_manager=bubble_mgr)

    ctx = SubjectContext(user_id="eve", session_id="sess_lease_invalidation")
    session = store.get_or_create("sess_lease_invalidation", ctx)

    # Issue lease
    lease = LeaseManager.issue_lease(
        session,
        tool_pattern="git.push",
        ttl_seconds=60.0,
        max_invocations=5,
        allowed_args_predicates={"branch": "main"},
    )

    inv = Invocation(tool="git.push", args={"branch": "main"}, context=ctx)
    res1 = gw.decide(inv)
    assert res1.decision == Decision.ALLOW
    assert res1.audit.lease_id == lease.lease_id

    # Simulate untrusted data ingestion
    session.ingest_source(
        source_id="untrusted_payload",
        source_type="file",
        taint=TaintLevel.UNTRUSTED,
    )

    # Lease is now revoked due to taint escalation!
    assert lease.revoked is True
    assert "taint escalated" in lease.revoked_reason

    res2 = gw.decide(inv)
    assert res2.decision == Decision.DENY
    assert res2.audit.lease_id is None

    bubble_mgr.rollback_all()
