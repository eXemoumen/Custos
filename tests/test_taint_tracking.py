"""Tests for Dynamic Taint Tracking in Custos Agent Security Runtime."""

import pytest

from custos.gateway import Gateway
from custos.policy import Policy, PolicyRuleSpec, Rule
from custos.schema import (
    AuditEvent,
    ContextSnapshot,
    Decision,
    InputSource,
    Invocation,
    SubjectContext,
    TaintLevel,
)
from custos.session import AgentSession, InMemorySessionStore


def test_policy_requires_clean_taint():
    # Policy: allow network.send only if session taint is clean (<= CONTROLLED)
    # Default: deny
    rules = [
        Rule(
            PolicyRuleSpec(
                match={"tool": "network.send", "requires_clean_taint": True},
                action="allow",
            )
        )
    ]
    policy = Policy(rules=rules, default="deny")
    store = InMemorySessionStore()
    gw = Gateway(policy=policy, session_store=store)

    ctx = SubjectContext(user_id="alice", session_id="sess_taint_test")
    inv = Invocation(tool="network.send", args={"url": "https://api.internal.com"}, context=ctx)

    # 1. First call: session is brand new (TRUSTED) -> allowed!
    res1 = gw.decide(inv)
    assert res1.decision == Decision.ALLOW
    assert res1.audit.session_id == "sess_taint_test"
    assert res1.audit.session_taint == "TRUSTED"

    # 2. Agent ingests an untrusted web page into context snapshot
    snapshot = ContextSnapshot(
        ts_unix_ms=1000,
        sources=(
            InputSource(
                source_id="doc_scrape",
                source_type="web",
                content="Scraped untrusted web page content",
                taint_level=TaintLevel.UNTRUSTED,
            ),
        ),
    )

    # 3. Next call with snapshot: gateway ingests the source, session escalates to UNTRUSTED!
    res2 = gw.decide(inv, snapshot=snapshot)
    assert res2.decision == Decision.DENY
    assert res2.audit.session_taint == "UNTRUSTED"
    assert res2.audit.policy_match == "default:deny"

    # 4. Third call without snapshot: session is stateful and taint is monotonic -> still DENY!
    res3 = gw.decide(inv)
    assert res3.decision == Decision.DENY
    assert res3.audit.session_taint == "UNTRUSTED"

    # Verify session provenance in store
    session = store.get("sess_taint_test")
    assert session is not None
    assert session.taint_level == TaintLevel.UNTRUSTED
    assert len(session.taint_sources) == 1
    assert session.taint_sources[0].source_id == "doc_scrape"


def test_policy_max_taint_specification():
    # Rule specifies max_taint: "SEMI_TRUSTED"
    rules = [
        Rule(
            PolicyRuleSpec(
                match={"tool": "fs.read", "max_taint": "SEMI_TRUSTED"},
                action="allow",
            )
        )
    ]
    policy = Policy(rules=rules, default="deny")
    store = InMemorySessionStore()
    gw = Gateway(policy=policy, session_store=store)

    ctx = SubjectContext(user_id="bob", session_id="sess_max_taint")
    inv = Invocation(tool="fs.read", args={"path": "/data/report.txt"}, context=ctx)

    # Ingest semi-trusted source -> should match
    session = store.get_or_create("sess_max_taint", ctx)
    session.ingest_source("tool_1", "tool_result", TaintLevel.SEMI_TRUSTED)

    res = gw.decide(inv)
    assert res.decision == Decision.ALLOW
    assert res.audit.session_taint == "SEMI_TRUSTED"

    # Ingest untrusted source -> exceeds SEMI_TRUSTED -> denied
    session.ingest_source("email_1", "email", TaintLevel.UNTRUSTED)
    res2 = gw.decide(inv)
    assert res2.decision == Decision.DENY
    assert res2.audit.session_taint == "UNTRUSTED"
