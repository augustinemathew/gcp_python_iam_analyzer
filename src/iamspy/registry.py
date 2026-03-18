"""Service registry — canonical mapping from service_id to metadata.

Tests: tests/test_registry.py
"""

from __future__ import annotations

import json
from pathlib import Path

from iamspy.models import ServiceEntry


class ServiceRegistry:
    """Loads and queries service_registry.json.

    The registry maps service_id → ServiceEntry, providing the canonical
    source of truth for pip package names, display names, IAM prefixes,
    and importable module paths.
    """

    def __init__(self, entries: dict[str, ServiceEntry] | None = None):
        self._entries: dict[str, ServiceEntry] = entries or {}
        self._by_pip: dict[str, ServiceEntry] = {
            e.pip_package: e for e in self._entries.values()
        }

    @classmethod
    def from_json(cls, path: str | Path) -> ServiceRegistry:
        with open(path) as f:
            data = json.load(f)
        entries = {}
        for service_id, info in data.items():
            entries[service_id] = ServiceEntry(
                service_id=service_id,
                pip_package=info["pip_package"],
                display_name=info["display_name"],
                iam_prefix=info["iam_prefix"],
                api_service=info.get("api_service", ""),
                discovery_doc=info.get("discovery_doc", ""),
                iam_reference=info.get("iam_reference", ""),
                modules=info.get("modules", []),
            )
        return cls(entries)

    def to_json(self, path: str | Path) -> None:
        data = {}
        for service_id, entry in sorted(self._entries.items()):
            data[service_id] = {
                "pip_package": entry.pip_package,
                "display_name": entry.display_name,
                "iam_prefix": entry.iam_prefix,
                "api_service": entry.api_service,
                "discovery_doc": entry.discovery_doc,
                "iam_reference": entry.iam_reference,
                "modules": entry.modules,
            }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")

    def get(self, service_id: str) -> ServiceEntry | None:
        return self._entries.get(service_id)

    def all_entries(self) -> dict[str, ServiceEntry]:
        return dict(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, service_id: str) -> bool:
        return service_id in self._entries

    def service_ids(self) -> list[str]:
        return sorted(self._entries.keys())

    def lookup_by_pip_package(self, pip_package: str) -> ServiceEntry | None:
        return self._by_pip.get(pip_package)

    def lookup_by_module(self, module_path: str) -> ServiceEntry | None:
        for entry in self._entries.values():
            if module_path in entry.modules:
                return entry
        return None

    def __iter__(self):
        return iter(self._entries.values())

    def add(self, entry: ServiceEntry) -> None:
        self._entries[entry.service_id] = entry
        self._by_pip[entry.pip_package] = entry


def derive_service_id(pip_package: str) -> str:
    """Derive service_id from a pip package name.

    Strips known GCP package prefixes and removes hyphens.
    Examples:
      google-cloud-secret-manager → secretmanager
      google-ai-generativelanguage → generativelanguage
    """
    for prefix in ("google-cloud-", "google-ai-"):
        if pip_package.startswith(prefix):
            return pip_package.removeprefix(prefix).replace("-", "")
    return pip_package.removeprefix("google-").replace("-", "")
