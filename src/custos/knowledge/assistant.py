"""Knowledge Base Assistant (A13).

Plugs directly into the Custos decision pipeline to evaluate invocations
against the Knowledge Base rules, sensitive assets, and threat signatures.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from custos.assistants.base import AssistantBase, AssistantBaseAsync
from custos.knowledge.intent_checker import IntentChecker
from custos.knowledge.schema import GuardrailAction
from custos.knowledge.store import KnowledgeBaseStore
from custos.schema import AssistantOutput, Decision, Invocation, SubjectContext

logger = logging.getLogger(__name__)


class KnowledgeBaseAssistant(AssistantBase, AssistantBaseAsync):
    """Evaluates invocations against the Knowledge Base guardrail rules and assets."""

    name = "knowledge-base"
    exfiltrates_args = False  # By default, local heuristic evaluation; does not exfiltrate to remote cloud

    def __init__(
        self,
        store: KnowledgeBaseStore | None = None,
        *,
        ollama_url: str | None = None,
        ollama_model: str = "llama3.2",
    ) -> None:
        self.store = store or KnowledgeBaseStore()
        self.intent_checker = IntentChecker(
            self.store,
            ollama_url=ollama_url,
            ollama_model=ollama_model,
        )
        self._user_messages: dict[str, str] = {}
        self._msg_lock = threading.Lock()

    def observe_user_message(self, message: str, user_id: str = "default_user") -> None:
        """Pre-tool hook to capture user prompt context for a subject."""
        with self._msg_lock:
            if len(self._user_messages) >= 200:
                # Keep bounded
                self._user_messages.pop(next(iter(self._user_messages)))
            self._user_messages[user_id] = message

    def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        """Evaluate invocation against Knowledge Base rules."""
        # Prefer subject-scoped extra context, fallback to bounded user map
        user_id = (ctx.user_id if ctx else None) or (inv.context.user_id if inv.context else "default_user")
        user_message: str | None = None
        if ctx and ctx.extra and "user_message" in ctx.extra:
            user_message = str(ctx.extra["user_message"])
        elif inv.context and inv.context.extra and "user_message" in inv.context.extra:
            user_message = str(inv.context.extra["user_message"])
        else:
            with self._msg_lock:
                user_message = self._user_messages.get(user_id)

        result = self.intent_checker.evaluate(inv, user_message=user_message)

        if not result.allowed:
            if result.action == GuardrailAction.QUARANTINE:
                return AssistantOutput(
                    decision=Decision.QUARANTINE,
                    risk=1.0,
                    reasoning=result.reasoning,
                )
            if result.action == GuardrailAction.DENY:
                return AssistantOutput(
                    decision=Decision.DENY,
                    risk=1.0,
                    reasoning=result.reasoning,
                )
            # Default fallback for violations: PROMPT
            return AssistantOutput(
                decision=Decision.PROMPT,
                risk=result.risk_score,
                reasoning=result.reasoning,
            )

        # Passed guardrails -> default allow
        return AssistantOutput(
            decision=Decision.ALLOW,
            risk=result.risk_score,
            reasoning=result.reasoning,
        )

    async def decide_async(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        """Async variant of decide: offloads synchronous execution to a worker thread."""
        return await asyncio.to_thread(self.decide, inv, ctx)

