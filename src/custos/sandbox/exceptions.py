"""Exceptions for Custos Sandbox Bubble Engine."""

from __future__ import annotations

__all__ = [
    "BubbleError",
    "IsolationUnavailableError",
    "BubbleExecutionError",
]


class BubbleError(Exception):
    """Base exception for all Custos sandbox bubble errors."""


class IsolationUnavailableError(BubbleError):
    """Raised when an requested isolation level (e.g. CONFINED) is unavailable.

    Fails closed: Custos never silently degrades from confined to unconfined.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(
            f"Requested sandbox isolation level is unavailable in this environment: {reason}. "
            f"Failing closed to prevent unconfined execution."
        )


class BubbleExecutionError(BubbleError):
    """Raised when command execution inside a bubble fails or times out."""

    def __init__(self, cmd: list[str] | str, returncode: int | None, stderr: str = "") -> None:
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(
            f"Sandbox execution failed for {cmd!r} with code {returncode}: {stderr.strip()}"
        )
