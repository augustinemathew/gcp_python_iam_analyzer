"""Data types for the Overwatch adaptive anomaly detection system."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto


class OpType(Enum):
    """Operation domains Overwatch monitors."""

    FILE_READ = auto()
    FILE_WRITE = auto()
    FILE_EXECUTE = auto()
    NETWORK = auto()
    HTTP = auto()
    MCP = auto()
    PROCESS = auto()


class VerdictAction(Enum):
    """Policy decision from L1, L2, or user."""

    ALLOW = "allow"
    BLOCK = "block"
    DEFER = "defer"


@dataclass(frozen=True)
class Operation:
    """A single observed operation from the agent."""

    op_type: OpType
    timestamp: float = field(default_factory=time.monotonic)
    # File ops
    path: str | None = None
    mode: str | None = None
    # Network ops
    host: str | None = None
    port: int | None = None
    # HTTP ops
    method: str | None = None
    http_path: str | None = None
    # MCP ops
    tool: str | None = None
    resource: str | None = None
    args: dict[str, object] | None = None
    # Process ops
    pid: int | None = None
    command: str | None = None
    # Seccheck metadata
    request_id: int | None = None
    container_id: str | None = None
    process_name: str | None = None


@dataclass(frozen=True)
class OperationFeatures:
    """Extracted comparable features from an Operation."""

    op_type: OpType
    # File features
    file_extension: str | None = None
    directory_depth: int | None = None
    directory_prefix: str | None = None
    # Network features
    host_domain: str | None = None
    port_class: str | None = None
    # HTTP features
    http_method: str | None = None
    http_path_prefix: str | None = None
    # MCP features
    mcp_tool: str | None = None
    mcp_arg_keys: tuple[str, ...] | None = None


@dataclass(frozen=True)
class DeviationSignal:
    """A single deviation signal from L1."""

    name: str
    score: float  # 0.0 (normal) to 1.0 (extreme anomaly)
    detail: str


@dataclass(frozen=True)
class L1Result:
    """Result of L1 statistical check."""

    operation: Operation
    features: OperationFeatures
    signals: list[DeviationSignal]
    composite_score: float
    escalate: bool


@dataclass(frozen=True)
class L2Verdict:
    """Result of L2 LLM analysis."""

    action: VerdictAction
    confidence: float
    reasoning: str
    latency_ms: float


@dataclass(frozen=True)
class UserDecision:
    """A user's verdict when L2 defers."""

    action: VerdictAction
    explanation: str
    extracted_features: list[str]
    timestamp: float = field(default_factory=time.time)


@dataclass(frozen=True)
class ContentAlert:
    """Alert from content inspection of a request body."""

    lsh_score: float
    matched_pattern: str
    body_prefix: str
    host: str


@dataclass(frozen=True)
class TaintContext:
    """Taint state for the current operation, passed to scorer."""

    pid_tainted: bool
    taint_sources: list[str]  # file paths that caused taint
    content_alert: ContentAlert | None = None


@dataclass(frozen=True)
class MemoryRecord:
    """A remembered decision for cross-session persistence."""

    operation_features: OperationFeatures
    action: VerdictAction
    source: str  # "l2" or "user"
    explanation: str
    extracted_patterns: list[str]
    created_at: float
    session_id: str
