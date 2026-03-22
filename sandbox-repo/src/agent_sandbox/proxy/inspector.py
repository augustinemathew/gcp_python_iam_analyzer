"""HTTPS proxy inspector for content and anomaly detection.

Designed as a mitmproxy addon that inspects every request body against
the scan manifest. Uses LSH content matching and anomaly detection to
block exfiltration of sensitive data.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from agent_sandbox.sandbox import AnomalyDetector, LSHEngine

logger = logging.getLogger(__name__)


class ProxyInspector:
    """Inspects HTTP(S) requests for sensitive content.

    Loads a manifest at startup and checks every outbound request
    body against indexed sensitive values. Operates three layers:

    1. Taint-based host filtering (non-allowlisted hosts blocked if tainted)
    2. LSH content matching (catches encoded/embedded secrets)
    3. Anomaly detection (catches chunked/char-by-char exfiltration)
    """

    def __init__(
        self,
        manifest_path: str | None = None,
        allowed_hosts: set[str] | None = None,
    ) -> None:
        self.lsh = LSHEngine()
        self.anomaly = AnomalyDetector()
        self.tainted = False
        self.allowed_hosts = allowed_hosts or {
            "registry.npmjs.org",
            "pypi.org",
            "files.pythonhosted.org",
            "api.github.com",
            "github.com",
        }
        self.blocked_requests: list[dict[str, str]] = []
        self.allowed_requests: list[dict[str, str]] = []
        self.sensitive_values: list[str] = []

        if manifest_path:
            self._load_manifest(manifest_path)

    def _load_manifest(self, path: str) -> None:
        """Load a scan manifest and index sensitive values."""
        try:
            with open(path) as f:
                data = json.load(f)

            for value in data.get("sensitive_values", []):
                self.sensitive_values.append(value)
                self.lsh.index_value(value)

            # Auto-taint if there are sensitive values
            if self.sensitive_values:
                self.tainted = True

            logger.info(
                "Loaded manifest: %d sensitive values", len(self.sensitive_values)
            )
        except (OSError, json.JSONDecodeError) as e:
            logger.error("Failed to load manifest: %s", e)

    def index_value(self, value: str) -> None:
        """Index a sensitive value for content matching."""
        self.sensitive_values.append(value)
        self.lsh.index_value(value)

    def mark_tainted(self) -> None:
        """Mark the process as tainted."""
        self.tainted = True

    def check_request(self, host: str, body: str) -> tuple[bool, str]:
        """Check if a request should be allowed.

        Returns (allowed, reason).
        """
        # Not tainted — allow everything
        if not self.tainted:
            self.allowed_requests.append({"host": host, "reason": "not tainted"})
            return True, "ok"

        # Tainted + non-allowlisted = deny
        if host not in self.allowed_hosts:
            reason = f"tainted + non-allowlisted host: {host}"
            self.blocked_requests.append({"host": host, "reason": reason})
            return False, reason

        # Tainted + allowlisted = check content
        if body:
            # LSH check
            found, lsh_reason = self.lsh.check(body)
            if found:
                self.blocked_requests.append({"host": host, "reason": lsh_reason})
                return False, lsh_reason

            # Anomaly check
            blocked, anomaly_reason = self.anomaly.check(host, body)
            if blocked:
                self.blocked_requests.append({"host": host, "reason": anomaly_reason})
                return False, anomaly_reason

        self.allowed_requests.append({"host": host, "reason": "clean"})
        return True, "ok"

    def get_stats(self) -> dict[str, int]:
        """Get inspector statistics."""
        return {
            "total_checked": len(self.blocked_requests) + len(self.allowed_requests),
            "blocked": len(self.blocked_requests),
            "allowed": len(self.allowed_requests),
            "indexed_values": len(self.sensitive_values),
            "tainted": int(self.tainted),
        }
