"""Policy engine combining taint tracking, LSH matching, and rules.

Decision logic:
  tainted + non-allowlisted → DENY
  tainted + allowlisted + LSH match → DENY
  tainted + allowlisted + anomaly → DENY
  tainted + allowlisted + clean → ALLOW
  clean → ALLOW
"""

from __future__ import annotations

from dataclasses import dataclass, field
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
})


class PolicyEngine:
    """Evaluates network requests against taint state, LSH index, and anomaly detectors."""

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

    def check_network(self, pid: int, host: str, body: str = "") -> PolicyResult:
        """Check if a network request from pid to host should be allowed."""
        taint_label = self.taint.get_process_taint(pid)

        # Clean process: allow
        if taint_label == TaintLabel.NONE:
            result = PolicyResult(Decision.ALLOW, "process not tainted")
            self.decisions.append(result)
            return result

        # Tainted + non-allowlisted: deny
        if host not in self.allowed_hosts:
            result = PolicyResult(
                Decision.DENY,
                f"tainted process ({taint_label}) sending to non-allowlisted host {host}",
            )
            self.decisions.append(result)
            return result

        # Tainted + allowlisted: check content
        if body:
            matched, score, lsh_reason = self.lsh.check(body)
            if matched:
                result = PolicyResult(
                    Decision.DENY,
                    f"LSH content match: {lsh_reason}",
                )
                self.decisions.append(result)
                return result

            blocked, anomaly_reason = self.anomaly.check(host, body)
            if blocked:
                result = PolicyResult(Decision.DENY, f"anomaly: {anomaly_reason}")
                self.decisions.append(result)
                return result

        result = PolicyResult(Decision.ALLOW, "tainted but clean content to allowlisted host")
        self.decisions.append(result)
        return result

    def check_file_write(self, pid: int, path: str, project_root: str) -> PolicyResult:
        """Check if a file write should be allowed."""
        import os

        abs_path = os.path.abspath(path)
        abs_root = os.path.abspath(project_root)

        if not abs_path.startswith(abs_root):
            result = PolicyResult(Decision.DENY, f"write outside project: {path}")
            self.decisions.append(result)
            return result

        system_paths = ["/etc/", "/usr/", "/bin/", "/sbin/"]
        if any(abs_path.startswith(sp) for sp in system_paths):
            result = PolicyResult(Decision.DENY, f"write to system path: {path}")
            self.decisions.append(result)
            return result

        result = PolicyResult(Decision.ALLOW, "write within project")
        self.decisions.append(result)
        return result

    def check_exec(self, pid: int, command: str) -> PolicyResult:
        """Check if a command execution should be allowed."""
        import re

        destructive = [
            re.compile(r"\brm\s+-rf\s+/"),
            re.compile(r"\brm\s+-rf\s+\.(?:\s|$)"),
            re.compile(r"\bmkfs\b"),
            re.compile(r":\(\)\s*\{"),  # fork bomb
        ]
        for pattern in destructive:
            if pattern.search(command):
                result = PolicyResult(Decision.DENY, f"destructive command: {command[:80]}")
                self.decisions.append(result)
                return result

        taint_label = self.taint.get_process_taint(pid)
        if taint_label != TaintLabel.NONE:
            network_cmds = re.compile(r"\b(?:curl|wget|nc|ncat|ssh|scp)\b")
            if network_cmds.search(command):
                result = PolicyResult(
                    Decision.DENY,
                    f"network command from tainted process: {command[:80]}",
                )
                self.decisions.append(result)
                return result

        result = PolicyResult(Decision.ALLOW, "command allowed")
        self.decisions.append(result)
        return result
