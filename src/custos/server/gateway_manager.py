"""Gateway lifecycle and session orchestrator for Custos Server."""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

from custos.audit import FileAuditSink, HashChainedAuditSink
from custos.gateway import Gateway
from custos.knowledge.assistant import KnowledgeBaseAssistant
from custos.knowledge.compiler import KnowledgeBaseCompiler
from custos.knowledge.store import KnowledgeBaseStore
from custos.policy import Policy
from custos.schema import (
    AuditEvent,
    DecideResult,
    Decision,
    Invocation,
    SubjectContext,
    ToolDescriptor,
)
from custos.server.config import ServerConfig
from custos.server.ws import ServerApprovalManager, ServerResponder

logger = logging.getLogger(__name__)


class GatewayManager:
    """Manages the active Custos Gateway, Knowledge Base, and Responders for the server."""

    def __init__(self, config: ServerConfig | None = None) -> None:
        self.config = config or ServerConfig.from_env()
        self._lock = threading.RLock()

        # Initialize Approval & Responder subsystem
        self.approval_manager = ServerApprovalManager()
        self.responder = ServerResponder(self.approval_manager)

        # Initialize Knowledge Base
        self.kb_store = KnowledgeBaseStore(self.config.kb_path)
        self.kb_assistant = KnowledgeBaseAssistant(
            self.kb_store,
            ollama_url=self.config.ollama_url,
            ollama_model=self.config.ollama_model,
        )

        # Initialize Cryptographic Hash-Chained Audit Sink
        self.config.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        signing_key = self.config.hmac_key.encode("utf-8") if self.config.hmac_key else None
        self.audit_sink = HashChainedAuditSink(str(self.config.audit_log_path), signing_key=signing_key)

        # Build initial Policy
        self._policy = self._build_policy()

        # Agent tracking & quarantine registry
        self._agents: dict[str, dict[str, Any]] = {}
        self._quarantined_agents: set[str] = set()

        # Instantiate the Gateway
        self.gateway = Gateway(
            policy=self._policy,
            assistant=self.kb_assistant,
            responder=self.responder,
            audit_sink=self.audit_sink,
        )
        logger.info("Initialized Custos GatewayManager successfully.")

    def _build_policy(self) -> Policy:
        """Construct a Policy incorporating base rules and compiled Knowledge Base overlays."""
        base_policy_dict: dict[str, Any] = {
            "version": 1,
            "default": "deny",
            "overlays": [],
        }

        # If operator provided a policy file, load it
        if self.config.policy_path and self.config.policy_path.exists():
            try:
                import yaml
                loaded = yaml.safe_load(self.config.policy_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    base_policy_dict = loaded
            except Exception as e:
                logger.error("Error loading policy file %s: %s", self.config.policy_path, e)

        # Ensure overlays list exists
        if "overlays" not in base_policy_dict or not isinstance(base_policy_dict["overlays"], list):
            base_policy_dict["overlays"] = []

        # Compile and inject Knowledge Base overlay as highest-priority (first) overlay
        kb_overlay = KnowledgeBaseCompiler.compile_store_to_overlay(self.kb_store)
        # Prepend KB overlay
        base_policy_dict["overlays"].insert(0, kb_overlay)

        return Policy.from_dict(base_policy_dict)

    def recompile_and_reload(self) -> None:
        """Recompiles the Knowledge Base overlay and reloads the active gateway policy."""
        with self._lock:
            new_policy = self._build_policy()
            self._policy = new_policy
            self.gateway.policy = new_policy
            logger.info("Recompiled Knowledge Base and reloaded Gateway policy.")

    def decide(
        self,
        tool: str,
        args: dict[str, Any],
        user_id: str = "default_user",
        goal_id: str | None = None,
        task_id: str | None = None,
        risk_tier: int = 2,
        extra: dict[str, Any] | None = None,
    ) -> DecideResult:
        """Evaluate a tool invocation through the full Custos decision pipeline."""
        with self._lock:
            # Check quarantine status
            if user_id in self._quarantined_agents:
                audit = AuditEvent(
                    tool=tool,
                    decision=Decision.QUARANTINE,
                    risk_score=1.0,
                    reasoning=f"Agent '{user_id}' is currently quarantined due to prior security violations.",
                    policy_rule_id="gateway_agent_quarantine",
                )
                self.audit_sink.emit(audit)
                self._record_agent_activity(user_id, tool)
                return DecideResult(decision=Decision.QUARANTINE, audit=audit)

            context = SubjectContext(
                user_id=user_id,
                goal_id=goal_id,
                task_id=task_id,
                extra=extra or {},
            )
            descriptor = ToolDescriptor(
                name=tool,
                risk_tier=risk_tier,
            )
            inv = Invocation(
                tool=tool,
                args=args,
                context=context,
                descriptor=descriptor,
            )
            result = self.gateway.decide(inv)

            # Auto-quarantine agent if decision was quarantine
            if result.decision == Decision.QUARANTINE:
                self._quarantined_agents.add(user_id)

            self._record_agent_activity(user_id, tool)
            return result

    def _record_agent_activity(self, agent_id: str, tool: str) -> None:
        """Record live agent telemetry."""
        now = time.time()
        if agent_id not in self._agents:
            self._agents[agent_id] = {
                "id": agent_id,
                "name": agent_id.replace("_", " ").title(),
                "framework": "Autonomous / Ingress",
                "status": "quarantined" if agent_id in self._quarantined_agents else "active",
                "policy_profile": "compiled-abac-strict",
                "calls": 1,
                "last_seen_ts": now,
                "last_tool": tool,
            }
        else:
            rec = self._agents[agent_id]
            rec["calls"] += 1
            rec["last_seen_ts"] = now
            rec["last_tool"] = tool
            rec["status"] = "quarantined" if agent_id in self._quarantined_agents else "active"

    def list_agents(self) -> list[dict[str, Any]]:
        """Return list of observed and registered agents."""
        with self._lock:
            # Sync status
            for a_id, data in self._agents.items():
                data["status"] = "quarantined" if a_id in self._quarantined_agents else "active"
            return list(self._agents.values())

    def quarantine_agent(self, agent_id: str) -> bool:
        """Place an agent in quarantine."""
        with self._lock:
            self._quarantined_agents.add(agent_id)
            if agent_id in self._agents:
                self._agents[agent_id]["status"] = "quarantined"
            return True

    def release_agent(self, agent_id: str) -> bool:
        """Release an agent from quarantine."""
        with self._lock:
            self._quarantined_agents.discard(agent_id)
            if agent_id in self._agents:
                self._agents[agent_id]["status"] = "active"
            return True

    def get_audit_events(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Read recent audit log events from the audit sink."""
        path = self.config.audit_log_path
        if not path.exists():
            return []

        events: list[dict[str, Any]] = []
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            # Flatten event envelope if hash-chained
                            if "event" in data and isinstance(data["event"], dict):
                                ev = data["event"]
                                ev["hash"] = data.get("prev_hash")
                                ev["sig"] = data.get("sig")
                                events.append(ev)
                            else:
                                events.append(data)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.error("Failed to read audit log: %s", e)
            return []

        # Reverse so newest are first
        events.reverse()
        return events[offset : offset + limit]

    def get_metrics(self) -> dict[str, Any]:
        """Compute real cumulative statistics from audit log."""
        events = self.get_audit_events(limit=1000)
        total_calls = len(events)
        total_allowed = sum(1 for e in events if e.get("decision") in ("allow", "allow_once", "allow_and_persist"))
        total_blocked = sum(1 for e in events if e.get("decision") in ("deny", "quarantine"))
        total_prompted = sum(1 for e in events if e.get("decision") == "prompt")

        return {
            "total_calls": total_calls,
            "total_allowed": total_allowed,
            "total_blocked": total_blocked,
            "total_prompted": total_prompted,
            "active_agents_count": len(self._agents),
            "quarantined_agents_count": len(self._quarantined_agents),
        }

    def verify_audit(self) -> dict[str, Any]:
        """Verify the cryptographic hash-chain of the audit log."""
        from custos.audit import verify_chain

        path = self.config.audit_log_path
        if not path.exists():
            return {"verified": True, "event_count": 0, "message": "Log file is empty"}

        try:
            signing_key = self.config.hmac_key.encode("utf-8") if self.config.hmac_key else None
            report = verify_chain(path, hmac_key=signing_key)
            is_valid = getattr(report, "is_ok", getattr(report, "ok", False))
            return {
                "verified": is_valid,
                "event_count": report.line_count,
                "errors": [f"Line {e.line_no}: {e.kind} - {e.detail}" for e in report.errors],
                "message": f"Verified {report.line_count} blocks with SHA-256 HMAC. Status: {'Valid (Cryptographically Intact)' if is_valid else 'Integrity compromised'}"
            }
        except Exception as e:
            return {"verified": False, "event_count": 0, "error": str(e)}
