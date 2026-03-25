"""Cross-session persistent memory for Overwatch decisions."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from agent_sandbox.overwatch._types import (
    MemoryRecord,
    OpType,
    OperationFeatures,
    VerdictAction,
)


_DEFAULT_PATH = os.path.expanduser("~/.agent_sandbox/overwatch_memory.json")


class MemoryStore:
    """Persists user and L2 decisions across sessions.

    Storage format: JSON with version field for future migration.
    Similarity search: O(n) scan with weighted feature matching.
    """

    def __init__(self, path: str | None = None) -> None:
        self._path = path or _DEFAULT_PATH
        self._records: list[MemoryRecord] = []
        self._baseline_snapshot: dict | None = None

    def load(self) -> None:
        """Load records from disk. No-op if file doesn't exist."""
        if not os.path.exists(self._path):
            return
        with open(self._path) as f:
            data = json.load(f)
        if data.get("version") != 1:
            return
        self._baseline_snapshot = data.get("baseline_snapshot")
        for raw in data.get("records", []):
            self._records.append(_deserialize_record(raw))

    def save(self, baseline_snapshot: dict | None = None) -> None:
        """Save records and baseline snapshot to disk."""
        if baseline_snapshot is not None:
            self._baseline_snapshot = baseline_snapshot
        data = {
            "version": 1,
            "records": [_serialize_record(r) for r in self._records],
            "baseline_snapshot": self._baseline_snapshot,
        }
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w") as f:
            json.dump(data, f, indent=2)

    @property
    def baseline_snapshot(self) -> dict | None:
        return self._baseline_snapshot

    @property
    def records(self) -> list[MemoryRecord]:
        return list(self._records)

    def add(self, record: MemoryRecord) -> None:
        """Add a decision to memory."""
        self._records.append(record)

    def find_similar(
        self, features: OperationFeatures, limit: int = 5
    ) -> list[MemoryRecord]:
        """Find memory records with similar features. O(n) scan."""
        scored = []
        for record in self._records:
            score = _similarity_score(features, record.operation_features)
            if score > 0:
                scored.append((score, record))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [r for _, r in scored[:limit]]

    def find_blocks(self, features: OperationFeatures) -> list[MemoryRecord]:
        """Find BLOCK records matching these features."""
        return [
            r
            for r in self._records
            if r.action == VerdictAction.BLOCK
            and _similarity_score(features, r.operation_features) >= 3
        ]

    def get_blocked_features(self) -> list[OperationFeatures]:
        """Return features of all blocked operations."""
        return [
            r.operation_features
            for r in self._records
            if r.action == VerdictAction.BLOCK
        ]


def _similarity_score(a: OperationFeatures, b: OperationFeatures) -> int:
    """Weighted feature similarity. Higher = more similar."""
    score = 0
    if a.op_type == b.op_type:
        score += 2
    if a.host_domain and a.host_domain == b.host_domain:
        score += 2
    if a.mcp_tool and a.mcp_tool == b.mcp_tool:
        score += 3
    if a.file_extension and a.file_extension == b.file_extension:
        score += 1
    if a.directory_prefix and a.directory_prefix == b.directory_prefix:
        score += 2
    if a.http_method and a.http_method == b.http_method:
        score += 1
    if a.http_path_prefix and a.http_path_prefix == b.http_path_prefix:
        score += 2
    return score


def _serialize_record(r: MemoryRecord) -> dict:
    """Serialize a MemoryRecord to a JSON-compatible dict."""
    return {
        "features": _serialize_features(r.operation_features),
        "action": r.action.value,
        "source": r.source,
        "explanation": r.explanation,
        "patterns": r.extracted_patterns,
        "created_at": r.created_at,
        "session_id": r.session_id,
    }


def _deserialize_record(raw: dict) -> MemoryRecord:
    """Deserialize a MemoryRecord from a JSON dict."""
    return MemoryRecord(
        operation_features=_deserialize_features(raw["features"]),
        action=VerdictAction(raw["action"]),
        source=raw["source"],
        explanation=raw["explanation"],
        extracted_patterns=raw.get("patterns", []),
        created_at=raw["created_at"],
        session_id=raw.get("session_id", "unknown"),
    )


def _serialize_features(f: OperationFeatures) -> dict:
    return {
        "op_type": f.op_type.name,
        "file_extension": f.file_extension,
        "directory_depth": f.directory_depth,
        "directory_prefix": f.directory_prefix,
        "host_domain": f.host_domain,
        "port_class": f.port_class,
        "http_method": f.http_method,
        "http_path_prefix": f.http_path_prefix,
        "mcp_tool": f.mcp_tool,
        "mcp_arg_keys": list(f.mcp_arg_keys) if f.mcp_arg_keys else None,
    }


def _deserialize_features(raw: dict) -> OperationFeatures:
    return OperationFeatures(
        op_type=OpType[raw["op_type"]],
        file_extension=raw.get("file_extension"),
        directory_depth=raw.get("directory_depth"),
        directory_prefix=raw.get("directory_prefix"),
        host_domain=raw.get("host_domain"),
        port_class=raw.get("port_class"),
        http_method=raw.get("http_method"),
        http_path_prefix=raw.get("http_path_prefix"),
        mcp_tool=raw.get("mcp_tool"),
        mcp_arg_keys=tuple(raw["mcp_arg_keys"]) if raw.get("mcp_arg_keys") else None,
    )
