"""Egress controller for Custos Sandbox Bubble.

Enforces egress-mode ladder monotonically tied to dynamic session taint.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Sequence
from urllib.parse import urlparse

from custos.sandbox.schema import EgressMode
from custos.session.schema import TaintLevel

__all__ = ["EgressController"]


class EgressController:
    """Controls network egress permissions for an AgentBubble."""

    def __init__(
        self,
        allowed_domains: Sequence[str] = (),
        initial_mode: EgressMode = EgressMode.ALLOWLISTED,
        allow_all_domains: bool = False,
    ) -> None:
        self.allowed_domains = tuple(allowed_domains)
        self.allow_all_domains = allow_all_domains
        self._mode = initial_mode

    @property
    def mode(self) -> EgressMode:
        return self._mode

    def update_from_taint(self, taint: TaintLevel) -> EgressMode:
        """Monotonically update egress mode based on session taint (Invariant 3).

        Egress permissions only degrade during an autonomous session:
            ALLOWLISTED -> READ_ONLY -> REVOKED
        """
        if taint >= TaintLevel.TAINTED_MALICIOUS:
            self._mode = EgressMode.REVOKED
        elif taint >= TaintLevel.UNTRUSTED:
            if self._mode != EgressMode.REVOKED:
                self._mode = EgressMode.READ_ONLY

        return self._mode

    def check_request(self, method: str, url: str) -> tuple[bool, str]:
        """Verify whether an outbound HTTP request is permitted under current egress mode."""
        method_upper = method.upper()

        if self._mode == EgressMode.REVOKED:
            return False, "Egress blocked: network access is fully revoked."

        if self._mode == EgressMode.READ_ONLY and method_upper not in ("GET", "HEAD"):
            return (
                False,
                f"Egress blocked: method {method_upper!r} drops payload under READ_ONLY egress mode.",
            )

        parsed = urlparse(url)
        host = parsed.hostname or url

        if not self.allow_all_domains:
            if not self.allowed_domains:
                return (
                    False,
                    "Egress blocked: allowed_domains is empty and unrestricted egress is disabled.",
                )
            matched = any(
                fnmatch.fnmatchcase(host.lower(), d.lower()) or host.lower() == d.lower()
                for d in self.allowed_domains
            )
            if not matched:
                return (
                    False,
                    f"Egress blocked: destination host {host!r} is not in allowed domains.",
                )

        return True, "Allowed"
