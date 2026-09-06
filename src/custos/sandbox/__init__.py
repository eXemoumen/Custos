"""Custos Sandbox Bubble Engine.

Provides isolated execution bubbles per AgentSession with transactional
git worktree staging, fail-closed confinement probing, and egress enforcement.
"""

from __future__ import annotations

from custos.sandbox.bubble import AgentBubble
from custos.sandbox.exceptions import (
    BubbleError,
    BubbleExecutionError,
    IsolationUnavailableError,
)
from custos.sandbox.manager import BubbleManager
from custos.sandbox.probe import SandboxCapabilities, probe_environment
from custos.sandbox.schema import (
    BubbleConfig,
    BubbleStatus,
    Changeset,
    EgressMode,
    ExecutionResult,
    IsolationLevel,
)
from custos.sandbox.worktree import GitWorktreeManager

__all__ = [
    "AgentBubble",
    "BubbleManager",
    "GitWorktreeManager",
    "IsolationLevel",
    "EgressMode",
    "BubbleStatus",
    "Changeset",
    "BubbleConfig",
    "ExecutionResult",
    "SandboxCapabilities",
    "probe_environment",
    "BubbleError",
    "IsolationUnavailableError",
    "BubbleExecutionError",
]
