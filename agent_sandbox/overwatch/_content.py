"""Content inspector: detects leaked secrets in request bodies.

Composes LSH (encoded/transformed secret detection) with AnomalyDetector
(rate/shape/accumulator) into a single check for HTTP and MCP request bodies.
"""

from __future__ import annotations

from agent_sandbox.overwatch._anomaly import AnomalyDetector
from agent_sandbox.overwatch._lsh import LSHEngine
from agent_sandbox.overwatch._types import ContentAlert


class ContentInspector:
    """Inspects HTTP/MCP request bodies for leaked secrets.

    Uses LSH to detect secrets even after base64/hex/URL encoding,
    and AnomalyDetector to catch chunked or drip exfiltration.
    """

    def __init__(
        self,
        lsh: LSHEngine | None = None,
        anomaly: AnomalyDetector | None = None,
    ) -> None:
        self._lsh = lsh or LSHEngine()
        self._anomaly = anomaly or AnomalyDetector()

    @property
    def lsh(self) -> LSHEngine:
        return self._lsh

    def index_secret(self, value: str) -> None:
        """Index a secret for content matching."""
        self._lsh.index(value)

    def inspect(self, host: str, body: str) -> ContentAlert | None:
        """Inspect a request body for leaked secrets.

        Returns a ContentAlert if the body matches a known secret or
        triggers anomaly detection. Returns None if clean.
        """
        if not body:
            return None

        # Check LSH for secret content.
        lsh_matched, lsh_score, lsh_reason = self._lsh.check(body)
        if lsh_matched:
            return ContentAlert(
                lsh_score=lsh_score,
                matched_pattern=lsh_reason,
                body_prefix=body[:512],
                host=host,
            )

        # Check anomaly patterns (rate, shape, accumulator).
        anomaly_blocked, anomaly_reason = self._anomaly.check(host, body)
        if anomaly_blocked:
            return ContentAlert(
                lsh_score=0.0,
                matched_pattern=anomaly_reason,
                body_prefix=body[:512],
                host=host,
            )

        return None
