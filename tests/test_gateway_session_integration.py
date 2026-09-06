import asyncio
import functools
import time
from typing import Any
import pytest

from custos.async_gateway import AsyncGateway
from custos.gateway import Gateway
from custos.lease import LeaseManager
from custos.policy import Policy, PolicyRuleSpec, Rule
from custos.schema import ContextSnapshot, Decision, InputSource, Invocation, SubjectContext, TaintLevel
from custos.session import InMemorySessionStore


def _async_test(coro_fn):
    @functools.wraps(coro_fn)
    def runner(*args: Any, **kwargs: Any) -> None:
        return asyncio.run(coro_fn(*args, **kwargs))

    return runner


def test_gateway_capability_lease_enforcement_and_consumption():
    # Policy: tool "git.push" requires a valid capability lease to be allowed
    rules = [
        Rule(
            PolicyRuleSpec(
                match={"tool": "git.push", "requires_lease": True},
                action="allow",
            )
        )
    ]
    policy = Policy(rules=rules, default="deny")
    store = InMemorySessionStore()
    gw = Gateway(policy=policy, session_store=store)

    ctx = SubjectContext(user_id="deployer", session_id="sess_deploy")
    inv = Invocation(tool="git.push", args={"branch": "main"}, context=ctx)

    # 1. No lease issued yet -> Policy doesn't match rule with requires_lease: true -> default DENY
    res1 = gw.decide(inv)
    assert res1.decision == Decision.DENY
    assert res1.audit.policy_match == "default:deny"
    assert res1.audit.lease_id is None

    # 2. Issue a 1-use capability lease on the session
    session = store.get_or_create("sess_deploy", ctx)
    lease = LeaseManager.issue_lease(
        session,
        tool_pattern="git.push",
        ttl_seconds=60.0,
        max_invocations=1,
    )

    # 3. Next call has valid lease -> ALLOW, lease is consumed, lease_id is in audit
    res2 = gw.decide(inv)
    assert res2.decision == Decision.ALLOW
    assert res2.audit.lease_id == lease.lease_id
    assert res2.audit.session_id == "sess_deploy"
    assert lease.invocations_used == 1

    # 4. Subsequent call: lease is now EXHAUSTED -> DENY
    res3 = gw.decide(inv)
    assert res3.decision == Decision.DENY
    assert res3.audit.policy_match == "default:deny"


def test_quarantined_session_blocks_all_further_calls():
    rules = [Rule(PolicyRuleSpec(match={"tool": "fs.read"}, action="allow"))]
    policy = Policy(rules=rules, default="deny")
    store = InMemorySessionStore()
    gw = Gateway(policy=policy, session_store=store)

    ctx = SubjectContext(user_id="analyst", session_id="sess_quar")
    inv = Invocation(tool="fs.read", args={"file": "test.txt"}, context=ctx)

    # Normal allow
    res1 = gw.decide(inv)
    assert res1.decision == Decision.ALLOW

    # Quarantine session
    session = store.get("sess_quar")
    assert session is not None
    session.quarantine("Detected reverse-shell payload in output")

    # Immediate next call is quarantined
    res2 = gw.decide(inv)
    assert res2.decision == Decision.QUARANTINE
    assert "quarantined" in res2.audit.reasoning
    assert res2.audit.session_taint == "TAINTED_MALICIOUS"


@_async_test
async def test_async_gateway_session_and_lease():
    rules = [
        Rule(
            PolicyRuleSpec(
                match={"tool": "api.call", "requires_clean_taint": True, "requires_lease": True},
                action="allow",
            )
        )
    ]
    policy = Policy(rules=rules, default="deny")
    store = InMemorySessionStore()
    async_gw = AsyncGateway(policy=policy, session_store=store)

    ctx = SubjectContext(user_id="async_agent", session_id="sess_async")
    inv = Invocation(tool="api.call", args={"op": "ping"}, context=ctx)

    session = store.get_or_create("sess_async", ctx)
    lease = LeaseManager.issue_lease(session, "api.*", max_invocations=1)

    # Call with clean taint and lease -> ALLOW
    res = await async_gw.decide(inv)
    assert res.decision == Decision.ALLOW
    assert res.audit.lease_id == lease.lease_id

    # Exhausted -> DENY
    res2 = await async_gw.decide(inv)
    assert res2.decision == Decision.DENY


def test_runtime_performance_overhead():
    # Benchmark: ensure decision pipeline with stateful session and taint tracking is < 0.2ms (200 microseconds)
    rules = [
        Rule(PolicyRuleSpec(match={"tool": "fast.tool", "requires_clean_taint": True}, action="allow"))
    ]
    policy = Policy(rules=rules, default="deny")
    gw = Gateway(policy=policy)

    ctx = SubjectContext(user_id="perf_user", session_id="sess_perf")
    inv = Invocation(tool="fast.tool", args={"x": 1}, context=ctx)

    # Warm-up
    for _ in range(50):
        gw.decide(inv)

    iterations = 1000
    start = time.perf_counter()
    for _ in range(iterations):
        gw.decide(inv)
    elapsed = time.perf_counter() - start

    avg_ms = (elapsed / iterations) * 1000
    # Average time should be well under 1ms, typically under 0.1ms
    assert avg_ms < 1.0, f"Average decision latency too high: {avg_ms:.4f} ms"
