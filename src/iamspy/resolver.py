"""PermissionResolver interface and static JSON-backed implementation.

Tests: tests/test_resolver.py
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path

from iamspy.models import PermissionResult


class PermissionResolver(ABC):
    """Interface for resolving SDK method calls to IAM permissions."""

    @abstractmethod
    def resolve(
        self,
        service_id: str,
        class_name: str,
        method_name: str,
    ) -> PermissionResult | None:
        """
        Resolve a GCP SDK method call to its IAM permissions.

        Args:
            service_id:  e.g. "bigquery", "storage", "cloudkms"
            class_name:  e.g. "Client", "PublisherClient"
            method_name: e.g. "query", "list_blobs", "encrypt"

        Returns:
            PermissionResult if the method is known, None otherwise.
        """
        ...

    def has_mapping(self, service_id: str, class_name: str, method_name: str) -> bool:
        """Check if a mapping exists without returning the full result."""
        return self.resolve(service_id, class_name, method_name) is not None


class StaticPermissionResolver(PermissionResolver):
    """Loads a pre-built JSON mapping file for O(1) lookups.

    Key format in JSON: "{service_id}.{class_name}.{method_name}"
    Wildcard:           "{service_id}.*.{method_name}"

    Lookup priority:
      1. Exact class-specific key
      2. Wildcard class key
    """

    def __init__(self, path: str | Path):
        with open(path) as f:
            self._data: dict[str, dict] = json.load(f)

    @property
    def keys(self) -> list[str]:
        """All mapping keys in the loaded data."""
        return list(self._data.keys())

    def resolve(
        self,
        service_id: str,
        class_name: str,
        method_name: str,
    ) -> PermissionResult | None:
        # Try class-specific key first
        key = f"{service_id}.{class_name}.{method_name}"
        entry = self._data.get(key)

        # Fall back to wildcard class key
        if entry is None:
            key = f"{service_id}.*.{method_name}"
            entry = self._data.get(key)

        if entry is None:
            return None

        return PermissionResult(
            permissions=entry.get("permissions", []),
            conditional_permissions=entry.get("conditional", []),
            is_local_helper=entry.get("local_helper", False),
            notes=entry.get("notes", ""),
        )

    def all_entries(self) -> dict[str, PermissionResult]:
        """Return all mappings as {key: PermissionResult}. Useful for CLI display."""
        result = {}
        for key, entry in self._data.items():
            result[key] = PermissionResult(
                permissions=entry.get("permissions", []),
                conditional_permissions=entry.get("conditional", []),
                is_local_helper=entry.get("local_helper", False),
                notes=entry.get("notes", ""),
            )
        return result
