"""Schema definitions for Custos Sandbox Bubble Engine."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

__all__ = [
    "IsolationLevel",
    "EgressMode",
    "BubbleStatus",
    "Changeset",
    "BubbleConfig",
    "ExecutionResult",
]


class IsolationLevel(str, Enum):
    """Execution isolation level provided by the sandbox bubble."""

    LOCAL = "local"
    """Transactional workspace staging via Git worktree.
    Subprocesses run with cwd=worktree, but are NOT isolated from host files/network.
    """

    CONFINED = "confined"
    """OS-level user namespace confinement (e.g. via bubblewrap on Linux).
    Masks host root filesystem as read-only, bounds read-write to the worktree only.
    Fails closed if unsupported.
    """

    CONTAINER = "container"
    """Docker / Podman container boundary isolation."""


class EgressMode(str, Enum):
    """Network egress enforcement mode tied to session taint."""

    ALLOWLISTED = "allowlisted"
    """Permits outbound calls only to configured allowlist domains (CLEAN session)."""

    READ_ONLY = "read_only"
    """Payload-dropping mode (GET/HEAD only). Blocks POST/PUT/DELETE exfiltration.
    Triggered when session taint reaches UNTRUSTED.
    """

    REVOKED = "revoked"
    """Complete network air-gap. All sockets and DNS traffic dropped."""


class BubbleStatus(str, Enum):
    """Lifecycle state of an AgentBubble."""

    UNINITIALIZED = "uninitialized"
    ACTIVE = "active"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"
    QUARANTINED = "quarantined"
    FAILED = "failed"


@dataclass(frozen=True)
class Changeset:
    """Structured diff of filesystem mutations staged in the bubble."""

    modified_files: tuple[str, ...] = ()
    added_files: tuple[str, ...] = ()
    deleted_files: tuple[str, ...] = ()
    diff_text: str = ""

    @property
    def is_empty(self) -> bool:
        return not (self.modified_files or self.added_files or self.deleted_files)

    @property
    def has_changes(self) -> bool:
        return not self.is_empty

    @property
    def total_changes(self) -> int:
        return len(self.modified_files) + len(self.added_files) + len(self.deleted_files)

    def to_dict(self) -> dict[str, Any]:
        return {
            "modified_files": list(self.modified_files),
            "added_files": list(self.added_files),
            "deleted_files": list(self.deleted_files),
            "diff_text": self.diff_text,
            "total_changes": self.total_changes,
        }


@dataclass
class BubbleConfig:
    """Configuration for an AgentBubble."""

    workspace_root: Path | str
    isolation_level: IsolationLevel = IsolationLevel.LOCAL
    allowed_egress_domains: Sequence[str] = field(default_factory=tuple)
    allow_all_egress: bool = False
    auto_rollback_on_quarantine: bool = True
    execution_timeout_seconds: float = 60.0
    bubble_storage_dir: Path | str | None = None

    def __post_init__(self) -> None:
        self.workspace_root = Path(self.workspace_root).resolve()
        if self.bubble_storage_dir is not None:
            self.bubble_storage_dir = Path(self.bubble_storage_dir).resolve()


@dataclass(frozen=True)
class ExecutionResult:
    """Result of a command executed inside an AgentBubble."""

    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: float
    worktree_path: str
