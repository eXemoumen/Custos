"""AgentBubble execution enclave implementation."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from custos.sandbox.egress import EgressController
from custos.sandbox.exceptions import (
    BubbleError,
    BubbleExecutionError,
    IsolationUnavailableError,
)
from custos.sandbox.probe import probe_environment
from custos.sandbox.schema import (
    BubbleConfig,
    BubbleStatus,
    Changeset,
    EgressMode,
    ExecutionResult,
    IsolationLevel,
)
from custos.sandbox.worktree import GitWorktreeManager
from custos.session.schema import TaintLevel

__all__ = ["AgentBubble"]

logger = logging.getLogger("custos.sandbox")


class AgentBubble:
    """An isolated execution bubble bound to an AgentSession."""

    def __init__(
        self,
        session_id: str,
        config: BubbleConfig,
        bubble_id: str | None = None,
    ) -> None:
        self.session_id = session_id
        self.config = config
        self.bubble_id = bubble_id or f"bubble_{uuid.uuid4().hex[:12]}"
        self.status = BubbleStatus.UNINITIALIZED
        self._lock = threading.RLock()
        self._active_processes: set[subprocess.Popen[Any]] = set()
        self.worktree = GitWorktreeManager(
            workspace_root=config.workspace_root,
            session_id=session_id,
            storage_dir=config.bubble_storage_dir,
        )
        self.egress = EgressController(
            allowed_domains=config.allowed_egress_domains,
            initial_mode=EgressMode.ALLOWLISTED,
            allow_all_domains=config.allow_all_egress,
        )

    @property
    def worktree_path(self) -> Path:
        return self.worktree.worktree_path

    def start(self) -> Path:
        """Initialize the execution bubble."""
        with self._lock:
            if self.status in (
                BubbleStatus.COMMITTED,
                BubbleStatus.ROLLED_BACK,
                BubbleStatus.QUARANTINED,
                BubbleStatus.FAILED,
            ):
                raise BubbleError(
                    f"Cannot start bubble in terminal status {self.status.value!r}. "
                    "Create a new AgentBubble for a new execution lifecycle."
                )

            if self.status == BubbleStatus.ACTIVE and self.worktree_path.exists():
                return self.worktree_path

            # Fail-closed isolation validation
            if self.config.isolation_level == IsolationLevel.CONFINED:
                caps = probe_environment()
                if not caps.can_confine:
                    self.status = BubbleStatus.FAILED
                    raise IsolationUnavailableError(
                        "Kernel unprivileged user namespaces / bwrap is unavailable or blocked in this environment"
                    )

            self.worktree.setup()
            self.status = BubbleStatus.ACTIVE
            return self.worktree_path

    def resolve_path(self, path: Path | str) -> Path:
        """Resolve a path inside the isolated worktree."""
        if self.status != BubbleStatus.ACTIVE:
            self.start()
        return self.worktree.resolve_path(path)

    def notify_taint_escalation(self, taint: TaintLevel) -> EgressMode:
        """Inform bubble of session taint change to dynamically restrict egress."""
        return self.egress.update_from_taint(taint)

    def run_command(
        self,
        cmd: Sequence[str] | str,
        *,
        timeout: float | None = None,
        env: Mapping[str, str] | None = None,
        check: bool = False,
    ) -> ExecutionResult:
        """Execute a shell command inside the bubble."""
        if self.status in (
            BubbleStatus.COMMITTED,
            BubbleStatus.ROLLED_BACK,
            BubbleStatus.QUARANTINED,
            BubbleStatus.FAILED,
        ):
            cmd_tuple = (cmd,) if isinstance(cmd, str) else tuple(cmd)
            raise BubbleExecutionError(
                cmd_tuple,
                -1,
                f"Execution blocked: bubble is in terminal status {self.status.value!r}.",
            )

        if self.status != BubbleStatus.ACTIVE:
            self.start()

        timeout_sec = timeout if timeout is not None else self.config.execution_timeout_seconds
        cmd_list = [cmd] if isinstance(cmd, str) else list(cmd)

        # Sanitize environment: strip sensitive host environment variables and dynamic loader overrides
        exec_env = dict(os.environ)
        if env:
            exec_env.update(env)
        _LOADER_VARS = (
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "LD_ORIGIN_PATH",
            "LD_DEBUG",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH",
        )
        for var in _LOADER_VARS:
            exec_env.pop(var, None)

        _STRIP_PREFIXES = (
            "AWS_",
            "AZURE_",
            "GOOGLE_",
            "GEMINI_",
            "GITHUB_",
            "GITLAB_",
            "OPENAI_",
            "ANTHROPIC_",
            "CUSTOS_",
            "SSH_",
            "KUBE",
            "SLACK_",
            "DISCORD_",
        )
        _STRIP_SUBSTRINGS = ("TOKEN", "SECRET", "KEY", "PASSWORD", "AUTH")
        for key in list(exec_env.keys()):
            key_upper = key.upper()
            if any(key.startswith(prefix) for prefix in _STRIP_PREFIXES) or any(
                sub in key_upper for sub in _STRIP_SUBSTRINGS
            ):
                exec_env.pop(key, None)

        start_time = time.perf_counter()

        if self.config.isolation_level == IsolationLevel.CONFINED:
            # Wrap with Linux bubblewrap using minimal safe root ro-binds
            bwrap_path = shutil.which("bwrap") or "bwrap"
            safe_system_paths = [
                "/usr",
                "/bin",
                "/sbin",
                "/lib",
                "/lib64",
                "/etc/alternatives",
                "/etc/ssl",
                "/etc/pki",
                "/etc/resolv.conf",
                "/etc/hosts",
                "/etc/ld.so.cache",
                "/etc/ld.so.conf",
                "/etc/ld.so.conf.d",
            ]
            wrapped_cmd = [bwrap_path]
            bound_paths = [p for p in safe_system_paths if Path(p).exists()]
            if not bound_paths:
                bound_paths = ["/usr", "/bin", "/lib"]
            for p in bound_paths:
                wrapped_cmd.extend(["--ro-bind", p, p])

            wrapped_cmd.extend([
                "--bind", str(self.worktree_path), str(self.worktree_path),
                "--dev", "/dev",
                "--proc", "/proc",
                "--tmpfs", "/tmp",
                "--unshare-all",
                "--die-with-parent",
                "--chdir", str(self.worktree_path),
                "--",
            ])
            if isinstance(cmd, str):
                wrapped_cmd.extend(["sh", "-c", cmd])
            else:
                wrapped_cmd.extend(cmd_list)

            target_cmd = wrapped_cmd
            target_cwd = None
        else:
            # LocalBubble: unconfined shell warning
            logger.warning(
                "[CUSTOS SECURITY ALERT] Session %r is running shell command %r under LocalBubble. "
                "Subprocesses are NOT isolated from the host filesystem or network.",
                self.session_id,
                cmd,
            )
            target_cmd = cmd
            target_cwd = str(self.worktree_path)

        proc: subprocess.Popen[str] | None = None
        try:
            proc = subprocess.Popen(
                target_cmd,
                cwd=target_cwd,
                env=exec_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=isinstance(target_cmd, str),
            )
            with self._lock:
                self._active_processes.add(proc)

            stdout, stderr = proc.communicate(timeout=timeout_sec)
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            result = ExecutionResult(
                command=tuple(cmd_list),
                returncode=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_ms=elapsed_ms,
                worktree_path=str(self.worktree_path),
            )
            if check and proc.returncode != 0:
                raise BubbleExecutionError(cmd_list, proc.returncode, stderr)
            return result
        except subprocess.TimeoutExpired as exc:
            if proc is not None:
                proc.kill()
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            raise BubbleExecutionError(cmd_list, -1, f"Execution timed out after {timeout_sec}s") from exc
        finally:
            if proc is not None:
                with self._lock:
                    self._active_processes.discard(proc)

    def get_changeset(self) -> Changeset:
        """Inspect staged changes."""
        return self.worktree.get_changeset()

    def commit(self) -> Changeset:
        """Commit staged changes to the real host workspace and destroy the worktree."""
        with self._lock:
            if self.status != BubbleStatus.ACTIVE:
                return Changeset()

            changeset = self.worktree.commit()
            self.status = BubbleStatus.COMMITTED
            return changeset

    def rollback(self) -> None:
        """Discard all staged changes. Host workspace remains 100% byte-for-byte untouched."""
        with self._lock:
            if self.status in (BubbleStatus.ROLLED_BACK, BubbleStatus.QUARANTINED):
                return

            self.worktree.rollback()
            self.status = BubbleStatus.ROLLED_BACK

    def quarantine(self, reason: str) -> None:
        """Quarantine this bubble. Drops network egress, kills active processes, and purges staged files."""
        with self._lock:
            self.egress.update_from_taint(TaintLevel.TAINTED_MALICIOUS)

            # Terminate any active commands at the OS boundary
            for proc in list(self._active_processes):
                try:
                    proc.kill()
                except Exception:
                    pass
            self._active_processes.clear()

            try:
                self.worktree.rollback()
                self.status = BubbleStatus.QUARANTINED
            except Exception as exc:
                self.status = BubbleStatus.FAILED
                logger.error("Failed to rollback worktree during quarantine for session %s: %s", self.session_id, exc)
                raise
            logger.info("Bubble %s quarantined for session %s: %s", self.bubble_id, self.session_id, reason)
