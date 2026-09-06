from pathlib import Path
import subprocess
import pytest

from custos.sandbox.worktree import GitWorktreeManager


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Create a temporary git repository with an initial commit."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    subprocess.run(["git", "init", "-b", "main"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Custos Test"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@custos.dev"], cwd=str(repo_dir), check=True, capture_output=True)

    # Initial file and commit
    readme = repo_dir / "README.md"
    readme.write_text("# Test Repo\nInitial content\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=str(repo_dir), check=True, capture_output=True)

    return repo_dir


def test_worktree_setup_and_path_resolution(git_repo: Path):
    mgr = GitWorktreeManager(workspace_root=git_repo, session_id="bubble-test-1")
    try:
        worktree_path = mgr.setup()
        assert worktree_path.exists()
        assert (worktree_path / "README.md").exists()
        assert (worktree_path / "README.md").read_text(encoding="utf-8") == "# Test Repo\nInitial content\n"

        # Resolve valid relative path
        resolved = mgr.resolve_path("src/app.py")
        assert resolved == (worktree_path / "src" / "app.py").resolve()

        # Path traversal out of worktree should be blocked
        with pytest.raises(PermissionError, match="path traversal detected"):
            mgr.resolve_path("../../outside.txt")

        # Absolute path outside worktree should be blocked
        with pytest.raises(PermissionError, match="outside the sandbox workspace"):
            mgr.resolve_path(str(git_repo.parent / "escape.txt"))

        # Internal metadata directories (.git, .custos) must be blocked from direct tool access
        with pytest.raises(PermissionError, match="access to internal metadata path"):
            mgr.resolve_path(".git/hooks/pre-commit")

        with pytest.raises(PermissionError, match="access to internal metadata path"):
            mgr.resolve_path(".custos/worktrees/config")

    finally:
        mgr.rollback()


def test_worktree_changeset_and_rollback(git_repo: Path):
    mgr = GitWorktreeManager(workspace_root=git_repo, session_id="bubble-test-rollback")
    try:
        worktree_path = mgr.setup()

        # Add a new file
        new_file = worktree_path / "payload.py"
        new_file.write_text("print('pwned?')\n", encoding="utf-8")

        # Modify README
        readme = worktree_path / "README.md"
        readme.write_text("# Test Repo\nModified in sandbox\n", encoding="utf-8")

        # Inspect changeset
        changeset = mgr.get_changeset()
        assert "payload.py" in changeset.added_files
        assert "README.md" in changeset.modified_files
        assert changeset.has_changes

        # Base repository should still be pristine!
        base_readme = git_repo / "README.md"
        assert base_readme.read_text(encoding="utf-8") == "# Test Repo\nInitial content\n"
        assert not (git_repo / "payload.py").exists()

        # Atomic rollback
        mgr.rollback()

        # Worktree path should no longer exist
        assert not worktree_path.exists()

        # Base repository remains completely untouched
        assert base_readme.read_text(encoding="utf-8") == "# Test Repo\nInitial content\n"
        assert not (git_repo / "payload.py").exists()

    finally:
        mgr.rollback()


def test_worktree_commit(git_repo: Path):
    mgr = GitWorktreeManager(workspace_root=git_repo, session_id="bubble-test-commit")
    try:
        worktree_path = mgr.setup()

        # Create changes: single file and nested directory file
        staged_file = worktree_path / "feature.txt"
        staged_file.write_text("Staged feature content\n", encoding="utf-8")

        nested_dir = worktree_path / "pkg" / "nested"
        nested_dir.mkdir(parents=True)
        nested_file = nested_dir / "module.py"
        nested_file.write_text("def run(): pass\n", encoding="utf-8")

        changeset = mgr.get_changeset()
        assert "feature.txt" in changeset.added_files
        # With -uall, git status explicitly tracks module.py inside new directory
        assert any("module.py" in f for f in changeset.added_files)

        # Commit to base workspace
        committed = mgr.commit()
        assert "feature.txt" in committed.added_files

        # Verify base repo received both the root file and the nested directory file
        base_feature = git_repo / "feature.txt"
        assert base_feature.exists()
        assert base_feature.read_text(encoding="utf-8") == "Staged feature content\n"

        base_nested = git_repo / "pkg" / "nested" / "module.py"
        assert base_nested.exists()
        assert base_nested.read_text(encoding="utf-8") == "def run(): pass\n"

        # Ephemeral worktree should have been rolled back / pruned after commit
        assert not worktree_path.exists()

    finally:
        mgr.rollback()


def test_non_git_workspace_fallback(tmp_path: Path):
    """Test fallback staging when workspace is not a git repo."""
    workspace = tmp_path / "plain_folder"
    workspace.mkdir()
    (workspace / "doc.txt").write_text("Hello plain world\n", encoding="utf-8")

    mgr = GitWorktreeManager(workspace_root=workspace, session_id="bubble-test-nongit")
    try:
        wt = mgr.setup()
        assert wt.exists()
        assert (wt / "doc.txt").read_text(encoding="utf-8") == "Hello plain world\n"
        assert not mgr.is_git

        # Modify file
        (wt / "doc.txt").write_text("Modified plain world\n", encoding="utf-8")
        changeset = mgr.get_changeset()
        assert "doc.txt" in changeset.modified_files

        # Commit back to workspace
        mgr.commit()
        assert (workspace / "doc.txt").read_text(encoding="utf-8") == "Modified plain world\n"
        assert not wt.exists()

    finally:
        mgr.rollback()


def test_copy_fallback_excluded_dirs_not_deleted(tmp_path: Path):
    """Ensure excluded directories like node_modules and .venv are never marked as deleted."""
    workspace = tmp_path / "app_project"
    workspace.mkdir()
    (workspace / "index.js").write_text("console.log('hi');", encoding="utf-8")
    
    nm = workspace / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("module.exports = {};", encoding="utf-8")

    venv = workspace / ".venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "activate").write_text("# venv", encoding="utf-8")

    mgr = GitWorktreeManager(workspace_root=workspace, session_id="test-excluded-dirs")
    try:
        wt = mgr.setup()
        assert not (wt / "node_modules").exists()
        assert not (wt / ".venv").exists()

        # Modify app file
        (wt / "index.js").write_text("console.log('bye');", encoding="utf-8")

        changeset = mgr.get_changeset()
        assert "index.js" in changeset.modified_files
        # Critical assertion: node_modules and .venv files must NOT be in deleted_files!
        assert len(changeset.deleted_files) == 0

        mgr.commit()
        # Verify node_modules and .venv still exist untouched in host workspace
        assert (workspace / "node_modules" / "pkg" / "index.js").exists()
        assert (workspace / ".venv" / "bin" / "activate").exists()
        assert (workspace / "index.js").read_text(encoding="utf-8") == "console.log('bye');"
    finally:
        mgr.rollback()


def test_copy_fallback_same_size_same_mtime_modified(tmp_path: Path):
    """Ensure same-size modifications with identical mtimes are detected via content hash/bytes."""
    import os
    workspace = tmp_path / "app_project2"
    workspace.mkdir()
    f = workspace / "config.txt"
    f.write_text("alpha", encoding="utf-8")  # 5 bytes

    mgr = GitWorktreeManager(workspace_root=workspace, session_id="test-same-size")
    try:
        wt = mgr.setup()
        wt_f = wt / "config.txt"
        assert wt_f.exists()

        # Write same byte length but different content
        wt_f.write_text("bravo", encoding="utf-8")  # 5 bytes
        # Force mtime to be identical to original
        orig_stat = f.stat()
        os.utime(wt_f, (orig_stat.st_atime, orig_stat.st_mtime))

        changeset = mgr.get_changeset()
        assert "config.txt" in changeset.modified_files

        mgr.commit()
        assert f.read_text(encoding="utf-8") == "bravo"
    finally:
        mgr.rollback()


