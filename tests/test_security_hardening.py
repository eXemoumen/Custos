"""Comprehensive security hardening tests for Custos 2.0 Agent Security Runtime.

Tests:
1. Concurrency safety: atomic lease consumption under high multithreaded contention.
2. Capability lease argument predicate enforcement.
3. Cross-principal session hijacking prevention.
4. Delegation chain taint and quarantine inheritance.
5. Assistant rule persistence H3 narrowness enforcement (cannot drop taint or lease requirements).
6. Fail-closed quarantine behavior in SDK and integration wrappers without memory_wipe.
"""

import concurrent.futures
import threading
from typing import Any
import pytest

from custos.exceptions import PermissionDenied
from custos.gateway import Gateway, _persist_assistant_rule_impl
from custos.lease import CapabilityLease, LeaseManager, LeaseStatus
from custos.policy import Policy, PolicyRuleSpec, Rule
from custos.schema import (
    ContextSnapshot,
    Decision,
    InputSource,
    Invocation,
    SubjectContext,
    TaintLevel,
    ToolDescriptor,
)
from custos.sdk import wrap_callables
from custos.session import AgentSession, InMemorySessionStore


def test_concurrent_lease_consumption_race_condition():
    """Ensure a capability lease with max_invocations=1 can ONLY be consumed once under 20 concurrent threads."""
    session = AgentSession(session_id="race_test_session")
    lease = LeaseManager.issue_lease(
        session,
        tool_pattern="db.drop_table",
        max_invocations=1,
        ttl_seconds=60.0,
    )

    consumed_count = 0
    lock = threading.Lock()

    def worker():
        nonlocal consumed_count
        res = session.consume_lease("db.drop_table")
        if res is not None:
            with lock:
                consumed_count += 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(worker) for _ in range(20)]
        concurrent.futures.wait(futures)

    assert consumed_count == 1
    assert lease.invocations_used == 1
    assert lease.status() == LeaseStatus.EXHAUSTED


def test_lease_argument_predicate_enforcement():
    """Ensure lease allowed_args_predicates strictly enforce argument constraints."""
    session = AgentSession(session_id="pred_test_session")
    lease = LeaseManager.issue_lease(
        session,
        tool_pattern="fs.write",
        max_invocations=5,
        allowed_args_predicates={"path": "/safe/dir/*", "mode": "w"},
    )

    # Mismatched path
    res_bad_path = session.consume_lease("fs.write", args={"path": "/etc/shadow", "mode": "w"})
    assert res_bad_path is None

    # Mismatched mode
    res_bad_mode = session.consume_lease("fs.write", args={"path": "/safe/dir/output.txt", "mode": "r"})
    assert res_bad_mode is None

    # Matching args -> successfully consumed
    res_good = session.consume_lease("fs.write", args={"path": "/safe/dir/output.txt", "mode": "w"})
    assert res_good is lease
    assert lease.invocations_used == 1


def test_cross_principal_session_hijacking_rejected():
    """Ensure InMemorySessionStore prevents session hijacking across distinct user principals."""
    store = InMemorySessionStore()
    alice_ctx = SubjectContext(user_id="alice", session_id="shared_sess_key")
    sess = store.get_or_create("shared_sess_key", alice_ctx)
    assert sess.subject.user_id == "alice"

    # Attacker bob attempts to access alice's session
    bob_ctx = SubjectContext(user_id="bob", session_id="shared_sess_key")
    with pytest.raises(PermissionError) as exc_info:
        store.get_or_create("shared_sess_key", bob_ctx)
    assert "hijacking detected" in str(exc_info.value).lower()


def test_delegation_chain_taint_and_quarantine_inheritance():
    """Ensure child subagent inherits higher taint and quarantine state from delegator parent."""
    store = InMemorySessionStore()
    policy = Policy(
        rules=[
            Rule(
                PolicyRuleSpec(
                    match={"tool": "cloud.deploy", "requires_clean_taint": True},
                    action="allow",
                )
            ),
            Rule(PolicyRuleSpec(match={"tool": "public.read"}, action="allow")),
        ],
        default="deny",
    )
    gw = Gateway(policy=policy, session_store=store)

    # 1. Parent agent gets tainted
    parent_ctx = SubjectContext(user_id="alice", session_id="parent_agent_01")
    parent_sess = store.get_or_create("parent_agent_01", parent_ctx)
    parent_sess.ingest_source("untrusted_web", "web", TaintLevel.UNTRUSTED)
    assert parent_sess.taint_level == TaintLevel.UNTRUSTED

    # 2. Child agent invoked with delegation_chain containing parent_agent_01
    child_ctx = SubjectContext(
        user_id="alice",
        session_id="child_worker_01",
        delegation_chain=("parent_agent_01",),
    )
    inv_child = Invocation(tool="cloud.deploy", args={}, context=child_ctx)

    # Child should be denied because it inherited parent's UNTRUSTED taint!
    res = gw.decide(inv_child)
    assert res.decision == Decision.DENY
    child_sess = store.get("child_worker_01")
    assert child_sess is not None
    assert child_sess.taint_level == TaintLevel.UNTRUSTED

    # 3. If parent is quarantined, child is immediately quarantined
    parent_sess.quarantine("Compromised credentials detected")
    child2_ctx = SubjectContext(
        user_id="alice",
        session_id="child_worker_02",
        delegation_chain=("parent_agent_01",),
    )
    inv_child2 = Invocation(tool="public.read", args={}, context=child2_ctx)
    res2 = gw.decide(inv_child2)
    assert res2.decision == Decision.QUARANTINE
    assert "inherited quarantine" in res2.audit.reasoning


def test_assistant_cannot_drop_taint_or_lease_requirements_on_persist():
    """H3 invariant: assistant allow_and_persist cannot strip requires_clean_taint or requires_lease."""
    policy = Policy(
        rules=[
            Rule(
                PolicyRuleSpec(
                    match={"tool": "db.query", "requires_clean_taint": True, "requires_lease": True},
                    action="prompt",
                )
            )
        ],
        default="deny",
    )
    initial_rule_count = len(policy.rules)

    # Assistant attempts to persist an allow rule without requires_clean_taint or requires_lease
    inv = Invocation(tool="db.query", args={"table": "users"}, context=SubjectContext(user_id="dev"))
    untrusted_suggested_rule = {
        "action": "allow",
        "match": {"tool": "db.query"},  # Missing requires_clean_taint and requires_lease!
    }

    _persist_assistant_rule_impl(policy, untrusted_suggested_rule, inv)

    # Rule must have been rejected by H3 narrowness check
    assert len(policy.rules) == initial_rule_count


def test_sdk_fails_closed_on_quarantine_without_memory_wipe():
    """Ensure SDK wrap_callables unconditionally blocks quarantined decisions even if memory_wipe is None."""
    rules = [Rule(PolicyRuleSpec(match={"tool": "dangerous_action"}, action="allow"))]
    policy = Policy(rules=rules, default="deny")
    store = InMemorySessionStore()
    gw = Gateway(policy=policy, session_store=store)

    # Pre-quarantine session
    ctx = SubjectContext(user_id="hacker", session_id="hacked_session")
    sess = store.get_or_create("hacked_session", ctx)
    sess.quarantine("Exfiltration attempt")

    def dangerous_action(x: int) -> int:
        return x * 2

    # Wrap callable without memory_wipe
    wrapped = wrap_callables(gw, [dangerous_action])
    gated_fn = wrapped[0]

    # Must raise PermissionDenied and NEVER run dangerous_action
    with pytest.raises(PermissionDenied) as exc_info:
        gated_fn(10, custos_context=ctx)
    assert "quarantine" in str(exc_info.value).lower()
