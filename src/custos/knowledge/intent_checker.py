"""Evaluates agent tool invocations against natural language guardrail rules and threat signatures.

Supports:
- Zero-latency heuristic matching (regex, keywords, tool patterns)
- Local LLM evaluation (e.g., local Ollama on localhost:11434 or custom endpoint)
- Threat pattern scanning (IPI triggers, jailbreak phrases)
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from custos.knowledge.schema import (
    GuardrailAction,
    GuardrailEvaluationResult,
    GuardrailRule,
    SensitiveAsset,
    ThreatPattern,
)
from custos.knowledge.store import KnowledgeBaseStore
from custos.schema import Invocation

logger = logging.getLogger(__name__)


class IntentChecker:
    """Evaluates invocations against the Knowledge Base."""

    def __init__(
        self,
        store: KnowledgeBaseStore,
        *,
        ollama_url: str | None = None,
        ollama_model: str = "llama3.2",
        timeout_seconds: float = 3.0,
    ) -> None:
        self.store = store
        self.ollama_url = ollama_url
        self.ollama_model = ollama_model
        self.timeout_seconds = timeout_seconds

    def evaluate(
        self,
        inv: Invocation,
        user_message: str | None = None,
    ) -> GuardrailEvaluationResult:
        """Run multi-layer evaluation on an invocation."""
        # 1. Threat Signature Scan (Highest Priority -> Quarantine)
        threat_result = self._scan_threats(inv, user_message)
        if threat_result is not None:
            return threat_result

        # 2. Heuristic Asset & Rule Matching
        heuristic_result = self._evaluate_heuristics(inv)
        if heuristic_result is not None and not heuristic_result.allowed:
            return heuristic_result

        # 3. Semantic LLM Guardrail Check (if Ollama/LLM configured)
        if self.ollama_url:
            llm_result = self._evaluate_llm(inv, user_message)
            if llm_result is not None:
                return llm_result

        # Default: Safe / Pass
        return GuardrailEvaluationResult(
            allowed=True,
            action=None,
            risk_score=0.0,
            reasoning="Passed all Knowledge Base guardrails.",
        )

    def _scan_threats(
        self,
        inv: Invocation,
        user_message: str | None,
    ) -> GuardrailEvaluationResult | None:
        """Scan invocation arguments and user messages for known threat signatures."""
        search_corpus = [
            inv.tool,
            json.dumps(inv.args, default=str),
        ]
        if user_message:
            search_corpus.append(user_message)

        corpus_text = " \n ".join(search_corpus)

        for threat in self.store.list_threats(enabled_only=True):
            matched = False
            if threat.is_regex:
                try:
                    if re.search(threat.pattern, corpus_text, re.IGNORECASE):
                        matched = True
                except re.error as err:
                    logger.warning("Invalid threat regex %r: %s", threat.pattern, err)
            else:
                if threat.pattern.lower() in corpus_text.lower():
                    matched = True

            if matched:
                return GuardrailEvaluationResult(
                    allowed=False,
                    action=threat.action,
                    violated_threat=threat,
                    risk_score=1.0,
                    reasoning=f"Threat signature matched: {threat.name} ({threat.description})",
                )
        return None

    def _evaluate_heuristics(self, inv: Invocation) -> GuardrailEvaluationResult | None:
        """Check direct keyword and tool targets defined on rules."""
        args_text = json.dumps(inv.args, default=str).lower()

        for rule in self.store.list_rules(enabled_only=True):
            # Check tool match
            tool_matched = False
            for target in rule.target_tools:
                if target == "*" or target == inv.tool or (target.endswith("*") and inv.tool.startswith(target[:-1])):
                    tool_matched = True
                    break

            if not tool_matched:
                continue

            # Check keyword match
            for kw in rule.keywords:
                if kw.lower() in args_text:
                    risk_val = 0.9 if rule.action == GuardrailAction.DENY else 0.7
                    return GuardrailEvaluationResult(
                        allowed=False,
                        action=rule.action,
                        violated_rule=rule,
                        risk_score=risk_val,
                        reasoning=f"Guardrail triggered: {rule.name} (Keyword '{kw}' in args)",
                    )
        return None

    def _evaluate_llm(
        self,
        inv: Invocation,
        user_message: str | None,
    ) -> GuardrailEvaluationResult | None:
        """Query local Ollama to evaluate plain-English guardrails."""
        rules = self.store.list_rules(enabled_only=True)
        if not rules:
            return None

        rules_prompt = "\n".join(
            f"- [{r.id}] ({r.name}): {r.natural_language_rule} (Action if violated: {r.action.value})"
            for r in rules
        )

        system_prompt = (
            "You are an AI safety and permission guardrail officer. "
            "Evaluate whether the following tool call violates any organizational safety rules.\n"
            "Rules:\n"
            f"{rules_prompt}\n\n"
            "Return ONLY valid JSON with format:\n"
            '{"violates": true|false, "rule_id": "id or empty", "risk": 0.0-1.0, "reasoning": "brief explanation"}'
        )

        user_content = (
            f"Tool: {inv.tool}\n"
            f"Arguments: {json.dumps(inv.args, default=str)}\n"
            f"User context: {user_message or 'None'}"
        )

        payload = {
            "model": self.ollama_model,
            "system": system_prompt,
            "prompt": user_content,
            "stream": False,
            "format": "json",
        }

        try:
            url = f"{self.ollama_url.rstrip('/')}/api/generate"
            req = Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=self.timeout_seconds) as resp:
                result_data = json.loads(resp.read().decode("utf-8"))
                llm_output = json.loads(result_data.get("response", "{}"))

                if llm_output.get("violates"):
                    rule_id = llm_output.get("rule_id")
                    violated_rule = self.store.get_rule(rule_id) if rule_id else None
                    action = violated_rule.action if violated_rule else GuardrailAction.PROMPT
                    return GuardrailEvaluationResult(
                        allowed=False,
                        action=action,
                        violated_rule=violated_rule,
                        risk_score=float(llm_output.get("risk", 0.8)),
                        reasoning=llm_output.get("reasoning", "Violates organizational guardrail rule."),
                    )
        except (URLError, TimeoutError, json.JSONDecodeError, Exception) as err:
            logger.debug("Ollama guardrail check skipped: %s", err)
            return None

        return None
