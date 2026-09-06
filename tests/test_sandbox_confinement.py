import logging
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from custos.sandbox.bubble import AgentBubble
from custos.sandbox.exceptions import IsolationUnavailableError
from custos.sandbox.probe import SandboxCapabilities, probe_environment
from custos.sandbox.schema import (
    BubbleConfig,
    BubbleStatus,
    IsolationLevel,
)
from custos.session.schema import TaintLevel


def test_probe_environment_real():
    """Verify probe_environment returns a valid capabilities object on the current host."""
    caps = probe_environment()
    assert isinstance(caps, SandboxCapabilities)
    assert isinstance(caps.git_available, bool)
    assert isinstance(caps.bwrap_available, bool)
    assert isinstance(caps.docker_available, bool)
    assert isinstance(caps.in_container, bool)


def test_fail_closed_when_confinement_unavailable(tmp_path: Path):
    """If CONFINED isolation is requested but can_confine is False, bubble must fail closed."""
    config = BubbleConfig(
        workspace_root=tmp_path,
        isolation_level=IsolationLevel.CONFINED,
    )
    bubble = AgentBubble(session_id="sess_fail_closed", config=config)

    # Mock probe_environment to return cannot confine
    fake_caps = SandboxCapabilities(
        git_available=True,
        bwrap_available=False,
        docker_available=False,
        userns_supported=False,
        in_container=False,
    )
    with patch("custos.sandbox.bubble.probe_environment", return_value=fake_caps):
        with pytest.raises(IsolationUnavailableError, match="Kernel unprivileged user namespaces"):
            bubble.start()

        # Invariant: bubble must NOT silently fallback to LOCAL!
        assert bubble.status == BubbleStatus.FAILED
        assert not bubble.worktree_path.exists()


def test_local_bubble_warning_and_execution(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    """LocalBubble must log a prominent security warning on subprocess execution."""
    config = BubbleConfig(
        workspace_root=tmp_path,
        isolation_level=IsolationLevel.LOCAL,
    )
    bubble = AgentBubble(session_id="sess_local", config=config)
    bubble.start()
    assert bubble.status == BubbleStatus.ACTIVE

    with caplog.at_level(logging.WARNING, logger="custos.sandbox"):
        # Run a simple benign command (python -c "print('hello_sandbox')")
        result = bubble.run_command(["python", "-c", "print('hello_sandbox')"])
        assert result.returncode == 0
        assert "hello_sandbox" in result.stdout

        # Verify prominent security warning was emitted
        assert any(
            "[CUSTOS SECURITY ALERT]" in record.message and "Subprocesses are NOT isolated" in record.message
            for record in caplog.records
        )

    bubble.rollback()
    assert bubble.status == BubbleStatus.ROLLED_BACK


def test_env_sanitization_strips_secrets(tmp_path: Path):
    """Subprocess execution must strip sensitive environment variables."""
    config = BubbleConfig(
        workspace_root=tmp_path,
        isolation_level=IsolationLevel.LOCAL,
    )
    bubble = AgentBubble(session_id="sess_env_strip", config=config)
    bubble.start()

    with patch.dict(
        os.environ,
        {
            "AWS_SECRET_ACCESS_KEY": "fake_aws_key",
            "OPENAI_API_KEY": "fake_openai_key",
            "CUSTOS_SECRET_KEY": "fake_custos_secret",
            "SAFE_VAR": "safe_value",
        },
    ):
        # Execute script checking environment variables
        code = (
            "import os, sys\n"
            "assert 'AWS_SECRET_ACCESS_KEY' not in os.environ\n"
            "assert 'OPENAI_API_KEY' not in os.environ\n"
            "assert 'CUSTOS_SECRET_KEY' not in os.environ\n"
            "assert os.environ.get('SAFE_VAR') == 'safe_value'\n"
            "print('ENV_OK')\n"
        )
        res = bubble.run_command(["python", "-c", code])
        assert res.returncode == 0
        assert "ENV_OK" in res.stdout

    bubble.rollback()


def test_confined_bubble_command_wrapping(tmp_path: Path):
    """When can_confine is True, commands are wrapped with bwrap and isolation arguments."""
    config = BubbleConfig(
        workspace_root=tmp_path,
        isolation_level=IsolationLevel.CONFINED,
    )
    bubble = AgentBubble(session_id="sess_confined_wrap", config=config)

    fake_caps = SandboxCapabilities(
        git_available=True,
        bwrap_available=True,
        docker_available=False,
        userns_supported=True,
        in_container=False,
    )
    with patch("custos.sandbox.bubble.probe_environment", return_value=fake_caps), \
         patch("custos.sandbox.bubble.shutil.which", return_value="/usr/bin/bwrap"), \
         patch("custos.sandbox.bubble.subprocess.Popen") as mock_popen:

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = ("confined output\n", "")
        mock_popen.return_value = mock_proc

        bubble.start()
        assert bubble.status == BubbleStatus.ACTIVE

        bubble.run_command(["ls", "-la"])

        # Check wrapped command passed to subprocess.Popen
        mock_popen.assert_called_once()
        cmd_called = mock_popen.call_args[0][0]
        assert cmd_called[0] == "/usr/bin/bwrap"
        assert "--ro-bind" in cmd_called
        assert "--unshare-all" in cmd_called
        assert "--die-with-parent" in cmd_called
        assert str(bubble.worktree_path) in cmd_called
        assert "ls" in cmd_called
        assert "-la" in cmd_called

    bubble.rollback()


def test_bubble_lifecycle_quarantine(tmp_path: Path):
    """Test quarantine drops egress and rolls back worktree."""
    config = BubbleConfig(
        workspace_root=tmp_path,
        isolation_level=IsolationLevel.LOCAL,
    )
    bubble = AgentBubble(session_id="sess_quarantine", config=config)
    bubble.start()

    # Stage a file
    (bubble.worktree_path / "threat.sh").write_text("rm -rf /", encoding="utf-8")
    assert (bubble.worktree_path / "threat.sh").exists()

    # Trigger quarantine
    bubble.quarantine("Detected reverse shell payload")

    assert bubble.status == BubbleStatus.QUARANTINED
    # Egress should be REVOKED
    assert bubble.egress.mode.value == "revoked"
    # Staged worktree should be rolled back / wiped
    assert not bubble.worktree_path.exists()
