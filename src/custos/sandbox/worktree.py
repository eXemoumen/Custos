"""Git Worktree manager for Custos Sandbox Bubble.

Provides single-root transactional staging for agent file tools and subprocesses.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

from custos.sandbox.exceptions import BubbleError
from custos.sandbox.schema import Changeset

EXCLUDED_DIRS: frozenset[str] = frozenset({".git", ".custos", "__pycache__", "node_modules", ".venv", "venv"})

__all__ = ["GitWorktreeManager", "EXCLUDED_DIRS"]


class GitWorktreeManager:
    """Manages an ephemeral Git worktree or fallback staging directory for an AgentSession."""

    def __init__(
        self,
        workspace_root: Path | str,
        session_id: str,
        storage_dir: Path | str | None = None,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.session_id = session_id

        if storage_dir is not None:
            self.storage_root = Path(storage_dir).resolve()
        else:
            self.storage_root = self.workspace_root / ".custos" / "worktrees"

        # Unique worktree directory for this session
        clean_sid = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in session_id)
        self.worktree_path = self.storage_root / clean_sid
        self.is_git = (self.workspace_root / ".git").exists() and shutil.which("git") is not None
        self._initialized = False

    def setup(self) -> Path:
        """Create the ephemeral worktree or staging directory."""
        if self._initialized and self.worktree_path.exists():
            return self.worktree_path

        self.storage_root.mkdir(parents=True, exist_ok=True)

        if self.worktree_path.exists():
            self._cleanup_path(self.worktree_path)

        if self.is_git:
            try:
                # Add detached worktree from HEAD
                res = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(self.workspace_root),
                        "worktree",
                        "add",
                        "--detach",
                        str(self.worktree_path),
                        "HEAD",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if res.returncode != 0:
                    # Fallback to copy if git worktree fails (e.g. bare repo or unborn HEAD)
                    self._setup_copy_fallback()
                else:
                    self._initialized = True
            except Exception:
                self._setup_copy_fallback()
        else:
            self._setup_copy_fallback()

        self._initialized = True
        return self.worktree_path

    def _setup_copy_fallback(self) -> None:
        """Fallback staging mode: copy workspace files ignoring excluded directories."""
        def _ignore(directory: str, contents: list[str]) -> set[str]:
            return {c for c in contents if c in EXCLUDED_DIRS}

        shutil.copytree(
            self.workspace_root,
            self.worktree_path,
            ignore=_ignore,
            dirs_exist_ok=True,
        )
        self.is_git = False

    def resolve_path(self, target_path: Path | str) -> Path:
        """Resolve a path strictly inside the ephemeral worktree.

        Prevents path traversal attacks (e.g. '../..').
        """
        if not self._initialized:
            self.setup()

        p = Path(target_path)
        # Block direct access to internal metadata directories
        for part in p.parts:
            if part in (".git", ".custos"):
                raise PermissionError(
                    f"Access denied: access to internal metadata path {str(target_path)!r} is blocked."
                )

        if p.is_absolute():
            # If path points to real workspace_root, translate to worktree_path
            try:
                rel = p.resolve().relative_to(self.workspace_root)
                resolved = (self.worktree_path / rel).resolve()
            except ValueError:
                # Absolute path outside workspace_root -> check if already in worktree_path
                try:
                    p.resolve().relative_to(self.worktree_path)
                    resolved = p.resolve()
                except ValueError:
                    raise PermissionError(
                        f"Access denied: path {str(target_path)!r} is outside the sandbox workspace."
                    )
        else:
            # Relative path -> resolve inside worktree_path
            resolved = (self.worktree_path / p).resolve()
            try:
                resolved.relative_to(self.worktree_path)
            except ValueError:
                raise PermissionError(
                    f"Access denied: path traversal detected for {str(target_path)!r}."
                )

        return resolved

    def get_changeset(self) -> Changeset:
        """Inspect and return the structured changeset between the worktree and base workspace."""
        if not self._initialized or not self.worktree_path.exists():
            return Changeset()

        if self.is_git:
            return self._get_git_changeset()
        else:
            return self._get_copy_changeset()

    def _get_git_changeset(self) -> Changeset:
        # 1. Status porcelain with -uall to explicitly enumerate untracked files inside new folders
        res_status = subprocess.run(
            ["git", "-C", str(self.worktree_path), "status", "--porcelain", "-uall"],
            capture_output=True,
            text=True,
            check=False,
        )
        modified: list[str] = []
        added: list[str] = []
        deleted: list[str] = []

        for line in res_status.stdout.splitlines():
            if len(line) < 4:
                continue
            status = line[:2].strip()
            path = line[3:].strip()
            if status in ("M", "MM"):
                modified.append(path)
            elif status in ("A", "??"):
                added.append(path)
            elif status in ("D",):
                deleted.append(path)
            else:
                modified.append(path)

        # 2. Diff text
        res_diff = subprocess.run(
            ["git", "-C", str(self.worktree_path), "diff", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        diff_text = res_diff.stdout

        # Also capture untracked files in diff preview
        for add_p in added:
            add_file = self.worktree_path / add_p
            if add_file.is_file():
                try:
                    content = add_file.read_text(encoding="utf-8", errors="replace")
                    diff_text += f"\n--- /dev/null\n+++ b/{add_p}\n@@ -0,0 +1 @@\n+{content[:500]}"
                except Exception:
                    pass

        return Changeset(
            modified_files=tuple(modified),
            added_files=tuple(added),
            deleted_files=tuple(deleted),
            diff_text=diff_text,
        )

    def _get_copy_changeset(self) -> Changeset:
        """Compare files between worktree_path and workspace_root."""
        modified: list[str] = []
        added: list[str] = []
        deleted: list[str] = []

        # Find added & modified
        for root, dirnames, files in os.walk(self.worktree_path):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
            for f in files:
                rel = Path(root, f).relative_to(self.worktree_path)
                orig = self.workspace_root / rel
                if not orig.exists():
                    added.append(str(rel))
                else:
                    wt_stat = Path(root, f).stat()
                    orig_stat = orig.stat()
                    if wt_stat.st_mtime != orig_stat.st_mtime or wt_stat.st_size != orig_stat.st_size:
                        modified.append(str(rel))
                    else:
                        try:
                            if Path(root, f).read_bytes() != orig.read_bytes():
                                modified.append(str(rel))
                        except Exception:
                            pass

        # Find deleted
        for root, dirnames, files in os.walk(self.workspace_root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
            for f in files:
                rel = Path(root, f).relative_to(self.workspace_root)
                wt = self.worktree_path / rel
                if not wt.exists():
                    deleted.append(str(rel))

        return Changeset(
            modified_files=tuple(modified),
            added_files=tuple(added),
            deleted_files=tuple(deleted),
            diff_text=f"Changeset: {len(modified)} modified, {len(added)} added, {len(deleted)} deleted.",
        )

    def commit(self) -> Changeset:
        """Apply staged changes back to the real workspace and prune the worktree."""
        changeset = self.get_changeset()
        if not self._initialized or not self.worktree_path.exists():
            return changeset

        def _ignore_symlinks(directory: str, contents: list[str]) -> set[str]:
            return {c for c in contents if os.path.islink(os.path.join(directory, c))}

        # Apply file copies to base workspace
        for add_p in changeset.added_files:
            src = self.worktree_path / add_p
            dst = (self.workspace_root / add_p).resolve()
            try:
                dst.relative_to(self.workspace_root)
            except ValueError:
                continue
            if dst == self.workspace_root:
                continue
            try:
                src.resolve().relative_to(self.worktree_path)
            except ValueError:
                continue
            if os.path.islink(src) or src.is_symlink():
                continue
            if os.path.islink(dst) or dst.is_symlink():
                dst.unlink()

            if src.is_dir():
                shutil.copytree(src, dst, dirs_exist_ok=True, ignore=_ignore_symlinks)
            elif src.is_file():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)

        for mod_p in changeset.modified_files:
            src = self.worktree_path / mod_p
            dst = (self.workspace_root / mod_p).resolve()
            try:
                dst.relative_to(self.workspace_root)
            except ValueError:
                continue
            if dst == self.workspace_root:
                continue
            try:
                src.resolve().relative_to(self.worktree_path)
            except ValueError:
                continue
            if os.path.islink(src) or src.is_symlink():
                continue
            if os.path.islink(dst) or dst.is_symlink():
                dst.unlink()

            if src.is_file():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)

        for del_p in changeset.deleted_files:
            dst = (self.workspace_root / del_p).resolve()
            try:
                dst.relative_to(self.workspace_root)
            except ValueError:
                continue
            if dst == self.workspace_root:
                continue
            if os.path.islink(dst) or dst.is_symlink():
                dst.unlink()
            elif dst.is_file():
                dst.unlink()
            elif dst.is_dir():
                shutil.rmtree(dst, ignore_errors=True)

        self.rollback()
        return changeset

    def rollback(self) -> None:
        """Discard all staged changes. Host workspace remains 100% byte-for-byte untouched."""
        if not self.worktree_path.exists():
            self._initialized = False
            return

        if self.is_git:
            try:
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(self.workspace_root),
                        "worktree",
                        "remove",
                        "--force",
                        str(self.worktree_path),
                    ],
                    capture_output=True,
                    check=False,
                )
            except Exception:
                pass

        if self.worktree_path.exists():
            self._cleanup_path(self.worktree_path)

        self._initialized = False

    def _cleanup_path(self, path: Path) -> None:
        """Force delete directory even with read-only files on Windows."""
        def _on_error(func: Any, p: str, excinfo: Any) -> None:
            try:
                os.chmod(p, 0o777)
                func(p)
            except Exception:
                pass

        shutil.rmtree(path, onerror=_on_error)
