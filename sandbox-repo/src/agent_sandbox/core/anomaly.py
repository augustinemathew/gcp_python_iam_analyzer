"""Anomaly detection: rate, shape, and accumulator detectors.

Three detectors catching different evasion strategies:
- Rate: too many requests per minute to the same host
- Shape: extract skeleton of each request, count repetitions
- Accumulator: track total bytes from small requests
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class AnomalyDetector:
    """Detects anomalous network behavior patterns."""

    rate_limit: int = 30
    shape_limit: int = 4
    accum_limit: int = 500

    request_count: dict[str, int] = field(default_factory=dict)
    shapes: dict[str, int] = field(default_factory=dict)
    small_bytes: dict[str, int] = field(default_factory=dict)
    small_count: dict[str, int] = field(default_factory=dict)

    def check(self, host: str, body: str) -> tuple[bool, str]:
        """Check a request for anomalous patterns.

        Returns (blocked, reason).
        """
        # Rate detector
        self.request_count[host] = self.request_count.get(host, 0) + 1
        if self.request_count[host] > self.rate_limit:
            return True, f"rate limit ({self.request_count[host]} requests to {host})"

        # Shape detector: normalize to skeleton
        shape = re.sub(r"\b\d+\b", "<N>", body)
        shape = re.sub(r"\b[a-zA-Z0-9/:.@_-]{1,8}\b", "<W>", shape)
        self.shapes[shape] = self.shapes.get(shape, 0) + 1
        if self.shapes[shape] >= self.shape_limit:
            return True, f"repeated pattern ({self.shapes[shape]}x)"

        # Accumulator: track total bytes from small requests
        if len(body) < 300:
            self.small_bytes[host] = self.small_bytes.get(host, 0) + len(body)
            self.small_count[host] = self.small_count.get(host, 0) + 1
            if (
                self.small_bytes[host] > self.accum_limit
                and self.small_count[host] > 5
            ):
                return True, (
                    f"accumulated small requests "
                    f"({self.small_count[host]} reqs, "
                    f"{self.small_bytes[host]} bytes to {host})"
                )

        return False, ""

    def reset(self) -> None:
        """Reset all detectors."""
        self.request_count.clear()
        self.shapes.clear()
        self.small_bytes.clear()
        self.small_count.clear()
