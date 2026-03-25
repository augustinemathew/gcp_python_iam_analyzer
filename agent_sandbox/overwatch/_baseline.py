"""L1 statistical baseline with EMA counters."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from agent_sandbox.overwatch._types import OpType, OperationFeatures


@dataclass
class FeatureCounter:
    """EMA-smoothed counter for a single feature value."""

    count: int = 0
    ema_rate: float = 0.0
    last_seen: float = 0.0


@dataclass
class Baseline:
    """Statistical baseline of normal agent behavior.

    Tracks distributions of operation features using EMA for natural decay.
    Constant memory, O(1) update and query.
    """

    # Per-feature counters.
    op_type_counts: dict[OpType, FeatureCounter] = field(default_factory=dict)
    host_counts: dict[str, FeatureCounter] = field(default_factory=dict)
    file_ext_counts: dict[str, FeatureCounter] = field(default_factory=dict)
    dir_prefix_counts: dict[str, FeatureCounter] = field(default_factory=dict)
    mcp_tool_counts: dict[str, FeatureCounter] = field(default_factory=dict)
    http_method_counts: dict[str, FeatureCounter] = field(default_factory=dict)

    # Op-type bigram tracker (prev_type -> current_type -> count).
    bigrams: dict[tuple[OpType, OpType], int] = field(default_factory=dict)

    # Ring buffer for recent operations (for L2 context).
    recent: deque[OperationFeatures] = field(
        default_factory=lambda: deque(maxlen=20)
    )

    # Global counters.
    total_ops: int = 0
    window_start: float = field(default_factory=time.monotonic)
    _last_op_type: OpType | None = field(default=None, repr=False)

    # Breadth tracking: unique resources in a 60s window.
    _breadth_hosts: set[str] = field(default_factory=set, repr=False)
    _breadth_files: set[str] = field(default_factory=set, repr=False)
    _breadth_tools: set[str] = field(default_factory=set, repr=False)
    _breadth_window_start: float = field(default_factory=time.monotonic, repr=False)

    # Burst tracking: timestamps of recent ops.
    _burst_times: deque[float] = field(
        default_factory=lambda: deque(maxlen=20), repr=False
    )

    # Configuration.
    ema_alpha: float = 0.1
    warmup_ops: int = 20

    @property
    def is_warm(self) -> bool:
        """True if we have enough data for reliable scoring."""
        return self.total_ops >= self.warmup_ops

    def observe(self, features: OperationFeatures) -> None:
        """Update baseline with a new observation."""
        now = time.monotonic()
        self.total_ops += 1
        self.recent.append(features)
        self._burst_times.append(now)

        # Update per-feature counters.
        self._update_counter(self.op_type_counts, features.op_type, now)
        if features.host_domain:
            self._update_counter(self.host_counts, features.host_domain, now)
            self._track_breadth_host(features.host_domain, now)
        if features.file_extension:
            self._update_counter(self.file_ext_counts, features.file_extension, now)
        if features.directory_prefix:
            self._update_counter(self.dir_prefix_counts, features.directory_prefix, now)
            self._track_breadth_file(features.directory_prefix, now)
        if features.mcp_tool:
            self._update_counter(self.mcp_tool_counts, features.mcp_tool, now)
            self._track_breadth_tool(features.mcp_tool, now)
        if features.http_method:
            self._update_counter(self.http_method_counts, features.http_method, now)

        # Update bigrams.
        if self._last_op_type is not None:
            key = (self._last_op_type, features.op_type)
            self.bigrams[key] = self.bigrams.get(key, 0) + 1
        self._last_op_type = features.op_type

    def _update_counter(
        self,
        counters: dict,
        key: object,
        now: float,
    ) -> None:
        """Update EMA counter for a feature value."""
        if key not in counters:
            counters[key] = FeatureCounter()
        c = counters[key]
        c.count += 1
        elapsed = max(now - c.last_seen, 0.001) if c.last_seen > 0 else 1.0
        instant_rate = 1.0 / elapsed
        c.ema_rate = self.ema_alpha * instant_rate + (1 - self.ema_alpha) * c.ema_rate
        c.last_seen = now

    def _track_breadth_host(self, host: str, now: float) -> None:
        self._maybe_reset_breadth(now)
        self._breadth_hosts.add(host)

    def _track_breadth_file(self, prefix: str, now: float) -> None:
        self._maybe_reset_breadth(now)
        self._breadth_files.add(prefix)

    def _track_breadth_tool(self, tool: str, now: float) -> None:
        self._maybe_reset_breadth(now)
        self._breadth_tools.add(tool)

    def _maybe_reset_breadth(self, now: float) -> None:
        if now - self._breadth_window_start > 60.0:
            self._breadth_hosts.clear()
            self._breadth_files.clear()
            self._breadth_tools.clear()
            self._breadth_window_start = now

    def get_breadth(self) -> int:
        """Total unique resources in the current 60s window."""
        return len(self._breadth_hosts) + len(self._breadth_files) + len(self._breadth_tools)

    def get_burst_count(self, window_ms: float = 100.0) -> int:
        """Count ops in the last `window_ms` milliseconds."""
        if not self._burst_times:
            return 0
        now = self._burst_times[-1]
        threshold = now - (window_ms / 1000.0)
        return sum(1 for t in self._burst_times if t >= threshold)

    def query(self, features: OperationFeatures) -> dict[str, FeatureCounter | None]:
        """Return current counters for the given features."""
        return {
            "op_type": self.op_type_counts.get(features.op_type),
            "host": self.host_counts.get(features.host_domain) if features.host_domain else None,
            "file_ext": self.file_ext_counts.get(features.file_extension) if features.file_extension else None,
            "dir_prefix": self.dir_prefix_counts.get(features.directory_prefix) if features.directory_prefix else None,
            "mcp_tool": self.mcp_tool_counts.get(features.mcp_tool) if features.mcp_tool else None,
            "http_method": self.http_method_counts.get(features.http_method) if features.http_method else None,
        }

    def snapshot(self) -> dict:
        """Serialize baseline for persistence."""

        def _counter_dict(counters: dict) -> dict:
            return {
                str(k): {"count": v.count, "ema_rate": v.ema_rate}
                for k, v in counters.items()
            }

        return {
            "total_ops": self.total_ops,
            "op_type_counts": _counter_dict(self.op_type_counts),
            "host_counts": _counter_dict(self.host_counts),
            "file_ext_counts": _counter_dict(self.file_ext_counts),
            "dir_prefix_counts": _counter_dict(self.dir_prefix_counts),
            "mcp_tool_counts": _counter_dict(self.mcp_tool_counts),
            "http_method_counts": _counter_dict(self.http_method_counts),
        }

    def restore(self, data: dict) -> None:
        """Restore baseline from a snapshot."""

        def _restore_counters(raw: dict) -> dict:
            result = {}
            for k, v in raw.items():
                result[k] = FeatureCounter(
                    count=v["count"],
                    ema_rate=v["ema_rate"],
                )
            return result

        self.total_ops = data.get("total_ops", 0)
        self.host_counts = _restore_counters(data.get("host_counts", {}))
        self.file_ext_counts = _restore_counters(data.get("file_ext_counts", {}))
        self.dir_prefix_counts = _restore_counters(data.get("dir_prefix_counts", {}))
        self.mcp_tool_counts = _restore_counters(data.get("mcp_tool_counts", {}))
        self.http_method_counts = _restore_counters(data.get("http_method_counts", {}))
        # op_type_counts use OpType enum keys — restore from string names.
        raw_op = data.get("op_type_counts", {})
        for k, v in raw_op.items():
            try:
                op = OpType[k] if isinstance(k, str) else k
                self.op_type_counts[op] = FeatureCounter(
                    count=v["count"], ema_rate=v["ema_rate"]
                )
            except KeyError:
                pass
