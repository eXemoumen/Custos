"""Environment capability probe for Custos Sandbox Engine.

Determines available isolation primitives (git, bwrap/userns, docker, container detection).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

__all__ = ["SandboxCapabilities", "probe_environment"]


@dataclass(frozen=True)
class SandboxCapabilities:
    """Detected sandbox capabilities in the current host environment."""

    git_available: bool
    userns_supported: bool
    bwrap_available: bool
    docker_available: bool
    in_container: bool

    @property
    def can_confine(self) -> bool:
        """True if hard OS-level confinement is achievable without Docker."""
        return self.userns_supported and self.bwrap_available

    def to_dict(self) -> dict[str, bool]:
        return {
            "git_available": self.git_available,
            "userns_supported": self.userns_supported,
            "bwrap_available": self.bwrap_available,
            "docker_available": self.docker_available,
            "in_container": self.in_container,
            "can_confine": self.can_confine,
        }


def probe_environment() -> SandboxCapabilities:
    """Probe current OS environment for sandbox capabilities."""
    git_avail = shutil.which("git") is not None
    bwrap_path = shutil.which("bwrap")
    bwrap_avail = bwrap_path is not None

    userns_supported = False
    if sys.platform.startswith("linux") and bwrap_avail:
        # Test whether bwrap can actually create an unprivileged user namespace
        try:
            res = subprocess.run(
                [bwrap_path, "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-all", "true"],
                capture_output=True,
                timeout=2,
            )
            userns_supported = (res.returncode == 0)
        except Exception:
            userns_supported = False
    else:
        # macOS and Windows do not have unprivileged Linux user namespaces
        userns_supported = False

    # Check for docker availability
    docker_path = shutil.which("docker")
    docker_avail = False
    if docker_path is not None:
        try:
            res = subprocess.run(
                [docker_path, "info"],
                capture_output=True,
                timeout=2,
            )
            docker_avail = (res.returncode == 0)
        except Exception:
            docker_avail = False

    # Check if running inside an existing container (CI runner, docker, k8s)
    in_container = (
        Path("/.dockerenv").exists()
        or bool(os.environ.get("KUBERNETES_SERVICE_HOST"))
        or bool(os.environ.get("GITHUB_ACTIONS"))
        or bool(os.environ.get("CI"))
    )
    if not in_container and sys.platform.startswith("linux"):
        try:
            cgroup_path = Path("/proc/1/cgroup")
            if cgroup_path.exists():
                text = cgroup_path.read_text(encoding="utf-8", errors="ignore")
                if "docker" in text or "containerd" in text or "kubepods" in text:
                    in_container = True
        except Exception:
            pass

    return SandboxCapabilities(
        git_available=git_avail,
        userns_supported=userns_supported,
        bwrap_available=bwrap_avail,
        docker_available=docker_avail,
        in_container=in_container,
    )
