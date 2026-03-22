"""Policy engine combining taint tracking, LSH matching, and rules.

Decision logic:
  tainted + non-allowlisted → DENY
  tainted + allowlisted + LSH match → DENY
  tainted + allowlisted + anomaly → DENY
  tainted + allowlisted + clean → ALLOW
  clean → ALLOW
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import Enum

from .anomaly import AnomalyDetector
from .lsh import LSHEngine
from .taint import TaintLabel, TaintTracker


class Decision(Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason: str


DEFAULT_ALLOWED_HOSTS = frozenset({
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "rubygems.org",
    "crates.io",
    "api.github.com",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "docs.python.org",
    "developer.mozilla.org",
})

# Pre-compiled patterns for exec checks
_DESTRUCTIVE_PATTERNS = [
    re.compile(r"\brm\s+-rf\s+/"),
    re.compile(r"\brm\s+-rf\s+\.(?:\s|$)"),
    re.compile(r"\brm\s+-rf\s+\*"),
    re.compile(r"\bmkfs\b"),
    re.compile(r"\bdd\s+.*of=/dev/"),
    re.compile(r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;"),  # fork bomb
]

_NETWORK_CMD_PATTERN = re.compile(r"\b(?:curl|wget|nc|ncat|ssh|scp|rsync)\b")

_SYSTEM_PATHS = ["/etc/", "/usr/", "/bin/", "/sbin/", "/var/", "/boot/", "/proc/", "/sys/"]

_CRITICAL_FILES = frozenset({
    ".git", ".env", "package.json", "pyproject.toml", "Cargo.toml", "go.mod",
})


class PolicyEngine:
    """Evaluates requests against taint state, LSH index, and anomaly detectors."""

    def __init__(
        self,
        taint_tracker: TaintTracker,
        lsh_engine: LSHEngine,
        anomaly_detector: AnomalyDetector,
        allowed_hosts: frozenset[str] | None = None,
    ) -> None:
        self.taint = taint_tracker
        self.lsh = lsh_engine
        self.anomaly = anomaly_detector
        self.allowed_hosts = allowed_hosts or DEFAULT_ALLOWED_HOSTS
        self.decisions: list[PolicyResult] = []

    def _record(self, decision: Decision, reason: str) -> PolicyResult:
        result = PolicyResult(decision, reason)
        self.decisions.append(result)
        return result

    def check_network(self, pid: int, host: str, body: str = "") -> PolicyResult:
        """Check if a network request from pid to host should be allowed."""
        taint_label = self.taint.get_process_taint(pid)

        if taint_label == TaintLabel.NONE:
            return self._record(Decision.ALLOW, "process not tainted")

        if host not in self.allowed_hosts:
            return self._record(
                Decision.DENY,
                f"tainted process ({taint_label}) sending to non-allowlisted host {host}",
            )

        if body:
            matched, score, lsh_reason = self.lsh.check(body)
            if matched:
                return self._record(Decision.DENY, f"LSH content match: {lsh_reason}")

            blocked, anomaly_reason = self.anomaly.check(host, body)
            if blocked:
                return self._record(Decision.DENY, f"anomaly: {anomaly_reason}")

        return self._record(Decision.ALLOW, "tainted but clean content to allowlisted host")

    def check_file_write(self, pid: int, path: str, project_root: str) -> PolicyResult:
        """Check if a file write should be allowed."""
        abs_path = os.path.abspath(path)
        abs_root = os.path.abspath(project_root)

        if not abs_path.startswith(abs_root):
            return self._record(Decision.DENY, f"write outside project: {path}")

        if any(abs_path.startswith(sp) for sp in _SYSTEM_PATHS):
            return self._record(Decision.DENY, f"write to system path: {path}")

        return self._record(Decision.ALLOW, "write within project")

    def check_file_delete(self, pid: int, path: str, project_root: str) -> PolicyResult:
        """Check if a file deletion should be allowed."""
        abs_path = os.path.abspath(path)
        abs_root = os.path.abspath(project_root)

        if not abs_path.startswith(abs_root):
            return self._record(Decision.DENY, f"delete outside project: {path}")

        basename = os.path.basename(path)
        if basename in _CRITICAL_FILES:
            return self._record(Decision.DENY, f"delete of critical project file: {basename}")

        return self._record(Decision.ALLOW, "delete within project")

    def check_exec(self, pid: int, command: str) -> PolicyResult:
        """Check if a command execution should be allowed."""
        for pattern in _DESTRUCTIVE_PATTERNS:
            if pattern.search(command):
                return self._record(Decision.DENY, f"destructive command: {command[:80]}")

        taint_label = self.taint.get_process_taint(pid)
        if taint_label != TaintLabel.NONE:
            if _NETWORK_CMD_PATTERN.search(command):
                return self._record(
                    Decision.DENY,
                    f"network command from tainted process: {command[:80]}",
                )

        return self._record(Decision.ALLOW, "command allowed")
