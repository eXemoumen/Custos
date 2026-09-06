"""Custos 2.0 Agent Security Runtime - Local Interactive Demo.

Run with:
    python examples/demo_runtime.py

This script demonstrates:
1. Stateful Agent Session initialization.
2. Capability Lease issuance and bounded single-use consumption.
3. Dynamic Taint Ingestion (agent reads untrusted web input -> taint escalates to UNTRUSTED).
4. Automated policy enforcement: sensitive actions blocked when tainted.
5. Soft-quarantine trigger and forensic session inspection.
"""

from custos.gateway import Gateway
from custos.lease import LeaseManager
from custos.policy import Policy, PolicyRuleSpec, Rule
from custos.schema import ContextSnapshot, Decision, InputSource, Invocation, SubjectContext, TaintLevel
from custos.session import InMemorySessionStore


def main():
    print("=" * 70)
    print(" CUSTOS 2.0 AGENT SECURITY RUNTIME - LIVE DEMO")
    print("=" * 70)

    # 1. Define Policy with Custos 2.0 Primitives
    rules = [
        # web.search: allowed always
        Rule(PolicyRuleSpec(match={"tool": "web.search"}, action="allow")),
        # git.push: requires a valid Capability Lease AND clean taint
        Rule(
            PolicyRuleSpec(
                match={
                    "tool": "git.push",
                    "requires_lease": True,
                    "requires_clean_taint": True,
                },
                action="allow",
            )
        ),
        # fs.read: allowed always
        Rule(PolicyRuleSpec(match={"tool": "fs.read"}, action="allow")),
    ]
    policy = Policy(rules=rules, default="deny")
    session_store = InMemorySessionStore()
    gateway = Gateway(policy=policy, session_store=session_store)

    user_ctx = SubjectContext(user_id="alice", session_id="agent_session_demo_01")

    # --------------------------------------------------------------------------
    # Step 1: Attempt sensitive action before any lease is issued
    # --------------------------------------------------------------------------
    print("\n[Step 1] Agent attempts 'git.push' without a capability lease...")
    inv1 = Invocation(tool="git.push", args={"branch": "main"}, context=user_ctx)
    res1 = gateway.decide(inv1)
    print(f"  -> Decision: {res1.decision.value.upper()} (Policy Match: {res1.audit.policy_match})")
    assert res1.decision == Decision.DENY, "Expected DENY without lease"

    # --------------------------------------------------------------------------
    # Step 2: Issue a 1-use Capability Lease to the session
    # --------------------------------------------------------------------------
    print("\n[Step 2] Operator grants a 1-use Capability Lease for 'git.push'...")
    session = session_store.get_or_create("agent_session_demo_01", user_ctx)
    lease = LeaseManager.issue_lease(
        session,
        tool_pattern="git.push",
        max_invocations=1,
        ttl_seconds=30.0,
        max_taint_level=TaintLevel.CONTROLLED,
    )
    print(f"  -> Lease issued: id={lease.lease_id[:8]}... max_uses={lease.max_invocations} status={lease.status().value}")

    # --------------------------------------------------------------------------
    # Step 3: Agent executes 'git.push' with valid lease
    # --------------------------------------------------------------------------
    print("\n[Step 3] Agent retries 'git.push' with the active lease...")
    res2 = gateway.decide(inv1)
    print(f"  -> Decision: {res2.decision.value.upper()} (Used Lease ID: {res2.audit.lease_id[:8]}...)")
    assert res2.decision == Decision.ALLOW, "Expected ALLOW with active lease"

    # --------------------------------------------------------------------------
    # Step 4: Agent tries 'git.push' again (Lease is now EXHAUSTED)
    # --------------------------------------------------------------------------
    print("\n[Step 4] Agent attempts a second 'git.push' with the exhausted lease...")
    res3 = gateway.decide(inv1)
    print(f"  -> Decision: {res3.decision.value.upper()} (Reasoning: {res3.audit.reasoning})")
    assert res3.decision == Decision.DENY, "Expected DENY after lease exhaustion"

    # --------------------------------------------------------------------------
    # Step 5: Ingest Untrusted External Web Input (Dynamic Taint Escalation)
    # --------------------------------------------------------------------------
    print("\n[Step 5] Agent reads an untrusted external web page via 'web.search'...")
    import time

    untrusted_snapshot = ContextSnapshot(
        ts_unix_ms=int(time.time() * 1000),
        sources=(
            InputSource(
                source_id="web_doc_99",
                source_type="web_scrape",
                content="<untrusted html with potential prompt injection>",
                taint_level=TaintLevel.UNTRUSTED,
            ),
        ),
    )
    inv_search = Invocation(tool="web.search", args={"q": "latest updates"}, context=user_ctx)
    gateway.decide(inv_search, snapshot=untrusted_snapshot)
    print(f"  -> Current Session Taint Level: {session.taint_level.name}")
    assert session.taint_level == TaintLevel.UNTRUSTED

    # --------------------------------------------------------------------------
    # Step 6: Grant a new lease, but taint prevents execution
    # --------------------------------------------------------------------------
    print("\n[Step 6] Granting a new lease to push code, but agent is UNTRUSTED...")
    new_lease = LeaseManager.issue_lease(session, "git.push", max_invocations=1)
    res4 = gateway.decide(inv1)
    print(f"  -> Decision: {res4.decision.value.upper()} (requires clean taint, but session is {session.taint_level.name})")
    assert res4.decision == Decision.DENY

    # --------------------------------------------------------------------------
    # Step 7: Quarantine trigger and Forensic State
    # --------------------------------------------------------------------------
    print("\n[Step 7] Security monitor detects jailbreak in output -> Session QUARANTINE...")
    session.quarantine("Detected prompt injection override payload in agent memory")
    res5 = gateway.decide(Invocation(tool="fs.read", args={"file": "notes.txt"}, context=user_ctx))
    print(f"  -> Any further tool call Decision: {res5.decision.value.upper()} ({res5.audit.reasoning})")
    assert res5.decision == Decision.QUARANTINE

    # --------------------------------------------------------------------------
    # Step 8: Forensic Session Snapshot
    # --------------------------------------------------------------------------
    print("\n[Step 8] Forensic Session Inspection:")
    state = session.to_dict()
    print(f"  - Session ID:       {state['session_id']}")
    print(f"  - Quarantined:      {state['is_quarantined']} (Reason: {state['quarantine_reason']})")
    print(f"  - Final Taint:      {state['taint_level']}")
    print(f"  - Taint Sources:    {len(state['taint_sources'])} source(s) recorded")
    print(f"  - Total Invocations:{state['history_count']} in ring buffer")

    print("\n" + "=" * 70)
    print("[OK] DEMO COMPLETED SUCCESSFULLY - ALL SECURITY INVARIANTS VERIFIED!")
    print("=" * 70)


if __name__ == "__main__":
    main()
