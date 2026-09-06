"""Gateway lifecycle and session orchestrator for Custos Server."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any
import uuid

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
from custos.server.ws import ServerApprovalManager, ServerResponder, async_mode_ctx

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

        # Agent tracking & quarantine registry with persistence
        self._agents_file = self.config.kb_path.parent / "agents.json"
        self._agents: dict[str, dict[str, Any]] = {}
        self._quarantined_agents: set[str] = set()
        self._load_agents()

        # Cumulative metrics counters
        self._metric_counters: dict[str, int] = {
            "total_calls": 0,
            "total_allowed": 0,
            "total_blocked": 0,
            "total_prompted": 0,
        }
        self._init_metrics_from_log()

        # Instantiate the Gateway
        self.gateway = Gateway(
            policy=self._policy,
            assistant=self.kb_assistant,
            responder=self.responder,
            audit_sink=self.audit_sink,
        )
        logger.info("Initialized Custos GatewayManager successfully.")

    def _init_metrics_from_log(self) -> None:
        """Populate initial cumulative metrics from existing audit log on disk."""
        path = self.config.audit_log_path
        if not path.exists():
            return
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line_clean = line.strip()
                    if not line_clean:
                        continue
                    try:
                        data = json.loads(line_clean)
                        ev = data.get("event") if isinstance(data.get("event"), dict) else data
                        dec = str(ev.get("decision", "")).lower()
                        self._metric_counters["total_calls"] += 1
                        if dec in ("allow", "allow_once", "allow_and_persist"):
                            self._metric_counters["total_allowed"] += 1
                        elif dec in ("deny", "quarantine"):
                            self._metric_counters["total_blocked"] += 1
                        elif dec == "prompt":
                            self._metric_counters["total_prompted"] += 1
                    except Exception:
                        continue
        except Exception as e:
            logger.error("Failed to read historical audit log for metrics: %s", e)

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

    def _load_agents(self) -> None:
        """Load registered agents and quarantine state from disk."""
        if not self._agents_file.exists():
            return
        try:
            raw = self._agents_file.read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, dict):
                agents_data = data.get("agents", {})
                if isinstance(agents_data, dict):
                    self._agents = agents_data
                elif isinstance(agents_data, list):
                    self._agents = {a["id"]: a for a in agents_data if isinstance(a, dict) and "id" in a}
                quarantined = data.get("quarantined", [])
                if isinstance(quarantined, list):
                    self._quarantined_agents = set(quarantined)
            logger.info("Loaded %d agents from %s", len(self._agents), self._agents_file)
        except Exception as e:
            logger.warning("Could not load agents file %s: %s", self._agents_file, e)

    def _save_agents(self) -> None:
        """Persist registered agents and quarantine state to disk."""
        try:
            self._agents_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "version": 1,
                "agents": self._agents,
                "quarantined": list(self._quarantined_agents),
            }
            self._agents_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning("Could not save agents file %s: %s", self._agents_file, e)

    def decide(
        self,
        tool: str,
        args: dict[str, Any],
        user_id: str = "default_user",
        goal_id: str | None = None,
        task_id: str | None = None,
        risk_tier: int = 2,
        extra: dict[str, Any] | None = None,
        timeout_seconds: float | None = None,
        async_mode: bool = False,
    ) -> DecideResult:
        """Evaluate a tool invocation through the full Custos decision pipeline."""
        with self._lock:
            is_quarantined = user_id in self._quarantined_agents

        if is_quarantined:
            audit = AuditEvent(
                tool=tool,
                decision=Decision.QUARANTINE,
                risk_score=1.0,
                reasoning=f"Agent '{user_id}' is currently quarantined due to prior security violations.",
                policy_rule_id="gateway_agent_quarantine",
            )
            self.audit_sink.emit(audit)
            with self._lock:
                self._record_agent_activity(user_id, tool)
                self._record_decision_metric(Decision.QUARANTINE)
            return DecideResult(decision=Decision.QUARANTINE, audit=audit)

        extra_dict = dict(extra or {})
        if timeout_seconds:
            extra_dict["timeout_seconds"] = timeout_seconds

        invocation_req_id = extra_dict.get("request_id") or f"prompt-{uuid.uuid4()}"

        context = SubjectContext(
            user_id=user_id,
            goal_id=goal_id,
            task_id=task_id,
            extra=extra_dict,
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
            request_id=invocation_req_id,
        )

        orig_timeout = self.approval_manager.default_timeout_seconds
        if timeout_seconds and timeout_seconds > 0:
            self.approval_manager.default_timeout_seconds = timeout_seconds

        token = async_mode_ctx.set(async_mode)
        try:
            result = self.gateway.decide(inv)
        finally:
            async_mode_ctx.reset(token)
            if timeout_seconds and timeout_seconds > 0:
                self.approval_manager.default_timeout_seconds = orig_timeout

        with self._lock:
            # Auto-quarantine agent if decision was quarantine
            if result.decision == Decision.QUARANTINE:
                self._quarantined_agents.add(user_id)
                self._save_agents()
                self.approval_manager.broadcast_agent_status(user_id, "quarantined")

            self._record_agent_activity(user_id, tool)
            self._record_decision_metric(result.decision)

        return result

    def _record_decision_metric(self, decision: Decision | str) -> None:
        """Increment cumulative in-memory metrics counters."""
        dec_str = decision.value if isinstance(decision, Decision) else str(decision).lower()
        self._metric_counters["total_calls"] += 1
        if dec_str in ("allow", "allow_once", "allow_and_persist"):
            self._metric_counters["total_allowed"] += 1
        elif dec_str in ("deny", "quarantine"):
            self._metric_counters["total_blocked"] += 1
        elif dec_str == "prompt":
            self._metric_counters["total_prompted"] += 1

    def _record_agent_activity(self, agent_id: str, tool: str) -> None:
        """Record live agent telemetry."""
        now = time.time()
        is_new = agent_id not in self._agents
        if is_new:
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

        if is_new:
            self._save_agents()

    def list_agents(self) -> list[dict[str, Any]]:
        """Return list of observed and registered agents."""
        with self._lock:
            # Sync status
            for a_id, data in self._agents.items():
                data["status"] = "quarantined" if a_id in self._quarantined_agents else "active"
            return list(self._agents.values())

    def register_agent(
        self,
        agent_id: str,
        name: str | None = None,
        framework: str = "Autonomous / Ingress",
        policy_profile: str = "compiled-abac-strict",
        description: str = "",
    ) -> dict[str, Any]:
        """Register a new autonomous agent or update an existing registration."""
        with self._lock:
            now = time.time()
            clean_id = agent_id.strip()
            display_name = name.strip() if name and name.strip() else clean_id.replace("_", " ").title()
            existing = self._agents.get(clean_id)
            record = {
                "id": clean_id,
                "name": display_name,
                "framework": framework,
                "status": "quarantined" if clean_id in self._quarantined_agents else (existing.get("status", "active") if existing else "active"),
                "policy_profile": policy_profile,
                "description": description,
                "calls": existing.get("calls", 0) if existing else 0,
                "last_seen_ts": existing.get("last_seen_ts", now) if existing else now,
                "last_tool": existing.get("last_tool", None) if existing else None,
            }
            self._agents[clean_id] = record
            self._save_agents()
            self.approval_manager.broadcast_agent_status(clean_id, record["status"])
            return dict(record)

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        """Retrieve details of a single registered agent."""
        with self._lock:
            data = self._agents.get(agent_id)
            if data is None:
                return None
            data["status"] = "quarantined" if agent_id in self._quarantined_agents else "active"
            return dict(data)

    def update_agent(self, agent_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        """Update an agent's configuration, profile, or framework."""
        with self._lock:
            if agent_id not in self._agents:
                return None
            rec = self._agents[agent_id]
            for field in ("name", "framework", "policy_profile", "description"):
                if field in updates and updates[field] is not None:
                    rec[field] = updates[field]
            rec["status"] = "quarantined" if agent_id in self._quarantined_agents else "active"
            self._save_agents()
            self.approval_manager.broadcast_agent_status(agent_id, rec["status"])
            return dict(rec)

    def delete_agent(self, agent_id: str) -> bool:
        """Deregister an agent and remove from quarantine state."""
        with self._lock:
            if agent_id not in self._agents:
                return False
            del self._agents[agent_id]
            self._quarantined_agents.discard(agent_id)
            self._save_agents()
            self.approval_manager.broadcast_agent_status(agent_id, "deleted")
            return True

    def quarantine_agent(self, agent_id: str) -> bool:
        """Place an agent in quarantine."""
        with self._lock:
            if agent_id not in self._agents:
                return False
            self._quarantined_agents.add(agent_id)
            self._agents[agent_id]["status"] = "quarantined"
            self._save_agents()
            self.approval_manager.broadcast_agent_status(agent_id, "quarantined")
            return True

    def release_agent(self, agent_id: str) -> bool:
        """Release an agent from quarantine."""
        with self._lock:
            if agent_id not in self._agents:
                return False
            self._quarantined_agents.discard(agent_id)
            self._agents[agent_id]["status"] = "active"
            self._save_agents()
            self.approval_manager.broadcast_agent_status(agent_id, "active")
            return True

    def get_audit_events(
        self,
        limit: int | None = 50,
        offset: int = 0,
        user_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Read recent audit log events from the audit sink with optional user/agent filter."""
        path = self.config.audit_log_path
        if not path.exists():
            return []

        events: list[dict[str, Any]] = []
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line_clean = line.strip()
                    if line_clean:
                        try:
                            data = json.loads(line_clean)
                            line_hash = hashlib.sha256(line_clean.encode("utf-8")).hexdigest()
                            # Flatten event envelope if hash-chained
                            if "event" in data and isinstance(data["event"], dict):
                                ev = dict(data["event"])
                                ev["hash"] = line_hash
                                ev["prev_hash"] = data.get("prev_hash")
                                ev["sig"] = data.get("sig")
                            else:
                                ev = dict(data)
                                ev["hash"] = line_hash

                            # Promote nested fields to top level for API and UI convenience
                            subj = ev.get("subject") if isinstance(ev.get("subject"), dict) else {}
                            if "user_id" not in ev and "user_id" in subj:
                                ev["user_id"] = subj["user_id"]
                            if "agent_id" not in ev:
                                ev["agent_id"] = ev.get("user_id") or ev.get("assistant")
                            if "tool" not in ev and isinstance(ev.get("invocation"), dict):
                                ev["tool"] = ev["invocation"].get("tool")

                            events.append(ev)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.error("Failed to read audit log: %s", e)
            return []

        # Reverse so newest are first
        events.reverse()
        if user_id:
            events = [
                e for e in events
                if e.get("user_id") == user_id
                or e.get("agent_id") == user_id
                or (isinstance(e.get("subject"), dict) and e["subject"].get("user_id") == user_id)
            ]
        if limit is None:
            return events[offset:]
        return events[offset : offset + limit]

    def get_metrics(self) -> dict[str, Any]:
        """Compute real cumulative statistics without full log parsing per request."""
        with self._lock:
            return {
                "total_calls": self._metric_counters["total_calls"],
                "total_allowed": self._metric_counters["total_allowed"],
                "total_blocked": self._metric_counters["total_blocked"],
                "total_prompted": self._metric_counters["total_prompted"],
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
