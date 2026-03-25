"""Feature extraction from operations and user explanations."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from agent_sandbox.overwatch._types import OpType, Operation, OperationFeatures


def extract_features(op: Operation) -> OperationFeatures:
    """Extract comparable features from an operation. Pure function, O(1)."""
    if op.op_type in (OpType.FILE_READ, OpType.FILE_WRITE, OpType.FILE_EXECUTE):
        return _extract_file_features(op)
    if op.op_type == OpType.NETWORK:
        return _extract_network_features(op)
    if op.op_type == OpType.HTTP:
        return _extract_http_features(op)
    if op.op_type == OpType.MCP:
        return _extract_mcp_features(op)
    if op.op_type == OpType.PROCESS:
        return OperationFeatures(op_type=op.op_type)
    return OperationFeatures(op_type=op.op_type)


def _extract_file_features(op: Operation) -> OperationFeatures:
    """Extract file path features."""
    path = PurePosixPath(op.path) if op.path else PurePosixPath("/")
    parts = path.parts
    prefix = str(PurePosixPath(*parts[:4])) if len(parts) >= 4 else str(path.parent)
    return OperationFeatures(
        op_type=op.op_type,
        file_extension=path.suffix or None,
        directory_depth=len(parts) - 1,
        directory_prefix=prefix,
    )


def _extract_network_features(op: Operation) -> OperationFeatures:
    """Extract network host/port features."""
    domain = _host_domain(op.host) if op.host else None
    port_class = _classify_port(op.port)
    return OperationFeatures(
        op_type=op.op_type,
        host_domain=domain,
        port_class=port_class,
    )


def _extract_http_features(op: Operation) -> OperationFeatures:
    """Extract HTTP method/path features."""
    domain = _host_domain(op.host) if op.host else None
    path_prefix = _path_prefix(op.http_path) if op.http_path else None
    return OperationFeatures(
        op_type=op.op_type,
        host_domain=domain,
        http_method=op.method,
        http_path_prefix=path_prefix,
    )


def _extract_mcp_features(op: Operation) -> OperationFeatures:
    """Extract MCP tool/args features."""
    arg_keys = None
    if op.args:
        arg_keys = tuple(sorted(op.args.keys()))
    return OperationFeatures(
        op_type=op.op_type,
        mcp_tool=op.tool,
        mcp_arg_keys=arg_keys,
    )


def _host_domain(host: str) -> str:
    """Extract the registerable domain (last 2 parts) from a hostname."""
    parts = host.rsplit(".", 2)
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _classify_port(port: int | None) -> str:
    """Classify a port into a category."""
    if port is None:
        return "unknown"
    if port == 80:
        return "http"
    if port == 443:
        return "https"
    if port == 53:
        return "dns"
    return "other"


def _path_prefix(path: str) -> str:
    """Extract the first 2 segments of an HTTP path."""
    segments = [s for s in path.split("/") if s]
    prefix_parts = segments[:2]
    return "/" + "/".join(prefix_parts) if prefix_parts else "/"


# Patterns for extracting features from user explanations.
_FILE_EXT_PATTERN = re.compile(
    r"(?:\.(?:py|js|ts|json|yaml|yml|toml|md|txt|csv|xml|html|css|go|rs|rb|sh))"
    r"|(?:\*\.(\w+))"
    r"|(?:(\w+)\s+files)",
    re.IGNORECASE,
)
_DIR_PATTERN = re.compile(r"(?:in\s+|under\s+|from\s+)([/\w.-]+)", re.IGNORECASE)
_HOST_PATTERN = re.compile(
    r"(?:to\s+|from\s+|host\s+)([\w.-]+\.(?:com|org|net|io|dev))", re.IGNORECASE
)
_TOOL_PATTERN = re.compile(r"(?:tool\s+|mcp\s+)(\w+)", re.IGNORECASE)

# Map of common words to file extensions.
_EXT_MAP = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "json": ".json",
    "yaml": ".yaml",
    "markdown": ".md",
    "text": ".txt",
    "go": ".go",
    "rust": ".rs",
    "ruby": ".rb",
    "shell": ".sh",
    "bash": ".sh",
}


def extract_explanation_features(
    explanation: str, op: Operation
) -> list[str]:
    """Extract generalizable patterns from a user's natural language explanation.

    Returns pattern strings like "file_extension:.py", "directory_prefix:/workspace".
    """
    patterns: list[str] = []

    # Extract file extension mentions.
    for m in _FILE_EXT_PATTERN.finditer(explanation):
        ext = m.group(0) if m.group(0).startswith(".") else None
        word = m.group(2)
        if ext:
            patterns.append(f"file_extension:{ext}")
        elif word and word.lower() in _EXT_MAP:
            patterns.append(f"file_extension:{_EXT_MAP[word.lower()]}")

    # Extract directory mentions.
    for m in _DIR_PATTERN.finditer(explanation):
        patterns.append(f"directory_prefix:{m.group(1)}")

    # Extract host mentions.
    for m in _HOST_PATTERN.finditer(explanation):
        patterns.append(f"host_domain:{_host_domain(m.group(1))}")

    # Extract tool mentions.
    for m in _TOOL_PATTERN.finditer(explanation):
        patterns.append(f"mcp_tool:{m.group(1)}")

    # If no patterns found, derive from the operation itself.
    if not patterns and op.path:
        feat = extract_features(op)
        if feat.file_extension:
            patterns.append(f"file_extension:{feat.file_extension}")
        if feat.directory_prefix:
            patterns.append(f"directory_prefix:{feat.directory_prefix}")

    return patterns
