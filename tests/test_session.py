"""Tests for Session State & Taint Lattice (Custos Agent Security Runtime)."""

import threading
import time
import pytest

from custos.schema import Decision, SubjectContext
from custos.session import (
    AgentSession,
    InMemorySessionStore,
    SessionInvocationRecord,
    TaintLevel,
    TaintSourceRecord,
)


def test_taint_lattice_ordering():
    assert TaintLevel.TRUSTED < TaintLevel.CONTROLLED
    assert TaintLevel.CONTROLLED < TaintLevel.SEMI_TRUSTED
    assert TaintLevel.SEMI_TRUSTED < TaintLevel.UNTRUSTED
    assert TaintLevel.UNTRUSTED < TaintLevel.TAINTED_MALICIOUS

    # Coercion tests
    assert TaintLevel.from_value("trusted") == TaintLevel.TRUSTED
    assert TaintLevel.from_value("UNTRUSTED") == TaintLevel.UNTRUSTED
    assert TaintLevel.from_value(3) == TaintLevel.UNTRUSTED
    assert TaintLevel.from_value(TaintLevel.CONTROLLED) == TaintLevel.CONTROLLED


def test_session_source_ingestion_monotonicity():
    session = AgentSession(session_id="test_sess_1")
    assert session.taint_level == TaintLevel.TRUSTED

    # Ingest controlled source -> escalates to CONTROLLED
    escalated = session.ingest_source("db_1", "db_table", TaintLevel.CONTROLLED)
    assert escalated is True
    assert session.taint_level == TaintLevel.CONTROLLED

    # Ingest trusted source -> does NOT decay (remains CONTROLLED)
    escalated = session.ingest_source("sys_1", "operator", TaintLevel.TRUSTED)
    assert escalated is False
    assert session.taint_level == TaintLevel.CONTROLLED

    # Ingest untrusted source -> escalates to UNTRUSTED
    escalated = session.ingest_source("web_1", "web_search", TaintLevel.UNTRUSTED, content_hash="abc12345")
    assert escalated is True
    assert session.taint_level == TaintLevel.UNTRUSTED

    # Check provenance records
    assert len(session.taint_sources) == 3
    assert session.taint_sources[-1].source_id == "web_1"
    assert session.taint_sources[-1].content_hash == "abc12345"


def test_session_history_ring_buffer():
    session = AgentSession(session_id="test_hist", max_history_entries=3)

    session.record_invocation("tool.a", Decision.ALLOW, 0.1)
    session.record_invocation("tool.b", Decision.PROMPT, 0.5)
    session.record_invocation("tool.c", Decision.ALLOW, 0.2)
    assert len(session.history) == 3
    assert session.history[0].tool == "tool.a"

    # 4th entry pushes out tool.a
    session.record_invocation("tool.d", Decision.DENY, 0.9)
    assert len(session.history) == 3
    assert session.history[0].tool == "tool.b"
    assert session.history[-1].tool == "tool.d"


def test_session_quarantine_preserves_state():
    session = AgentSession(session_id="test_quarantine")
    session.record_invocation("tool.a", Decision.ALLOW)
    assert session.is_quarantined is False

    session.quarantine("Attributed indirect prompt injection")
    assert session.is_quarantined is True
    assert session.quarantine_reason == "Attributed indirect prompt injection"
    assert session.taint_level == TaintLevel.TAINTED_MALICIOUS
    # History preserved
    assert len(session.history) == 1


def test_in_memory_session_store():
    store = InMemorySessionStore(max_sessions=2, ttl_ms=500)
    ctx1 = SubjectContext(user_id="user_1")
    s1 = store.get_or_create("sess_1", ctx1)
    assert s1.session_id == "sess_1"
    assert s1.subject == ctx1

    # Retrieval
    s1_ret = store.get("sess_1")
    assert s1_ret is s1

    # Exceed max_sessions -> LRU eviction
    s2 = store.get_or_create("sess_2")
    s3 = store.get_or_create("sess_3")
    assert store.get("sess_1") is None  # sess_1 was evicted
    assert store.get("sess_2") is not None
    assert store.get("sess_3") is not None

    # TTL eviction
    time.sleep(0.55)
    assert store.get("sess_2") is None


def test_session_store_thread_safety():
    store = InMemorySessionStore(max_sessions=100)

    def worker(worker_id: int):
        for i in range(50):
            sid = f"worker_{worker_id}_sess_{i % 5}"
            sess = store.get_or_create(sid)
            sess.ingest_source(f"src_{i}", "tool", TaintLevel.SEMI_TRUSTED)
            sess.record_invocation(f"tool_{i}", Decision.ALLOW)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Verify no corruption or crashes
    sess = store.get("worker_0_sess_0")
    assert sess is not None
    assert sess.taint_level >= TaintLevel.SEMI_TRUSTED
