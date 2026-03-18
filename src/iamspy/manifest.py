"""Manifest generation: convert scan results into a permission manifest YAML.

Tests: tests/test_manifest.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from iamspy.models import ScanResult
    from iamspy.registry import ServiceRegistry


class ManifestGenerator:
    """Build a permission manifest from scan results.

    The manifest is a structured dict that can be serialized to YAML.
    It captures the complete set of IAM permissions, GCP APIs to enable,
    and (optionally) the source locations for each permission.

    Usage::

        gen = ManifestGenerator(registry)
        manifest = gen.build(results, scanned_paths=["src/"])
        gen.write(manifest, Path("iam-manifest.yaml"))
    """

    def __init__(self, registry: ServiceRegistry) -> None:
        self._registry = registry

    def build(
        self,
        results: list[ScanResult],
        *,
        scanned_paths: list[str],
        include_sources: bool = False,
    ) -> dict:
        """Build manifest data structure from scan results.

        Args:
            results: Output from scanner.scan_files().
            scanned_paths: The CLI paths passed to iamspy scan (for generated_by).
            include_sources: If True, emit a sources section mapping each
                permission to the file/line(s) where it was detected.

        Returns:
            Dict suitable for yaml.dump().
        """
        required: set[str] = set()
        conditional: set[str] = set()
        service_ids: set[str] = set()

        sources: dict[str, list[dict]] = {}  # permission → [{file, line, method}]

        for result in results:
            for finding in result.findings:
                if finding.status == "no_api_call":
                    continue

                for perm in finding.permissions:
                    required.add(perm)
                    if include_sources:
                        sources.setdefault(perm, []).append(
                            {"file": finding.file, "line": finding.line, "method": finding.method_name}
                        )

                for perm in finding.conditional_permissions:
                    conditional.add(perm)
                    if include_sources:
                        sources.setdefault(perm, []).append(
                            {"file": finding.file, "line": finding.line, "method": finding.method_name}
                        )

                for match in finding.matched:
                    service_ids.add(match.service_id)

        api_services = self._resolve_api_services(service_ids)

        manifest: dict = {
            "version": "1",
            "generated_by": f"iamspy scan {' '.join(scanned_paths)}",
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "services": {
                "enable": sorted(api_services),
            },
            "permissions": {
                "required": sorted(required),
                "conditional": sorted(conditional),
            },
        }

        if include_sources:
            manifest["sources"] = {
                perm: locs for perm, locs in sorted(sources.items())
            }

        return manifest

    def _resolve_api_services(self, service_ids: set[str]) -> list[str]:
        """Resolve service_ids to their canonical googleapis.com names.

        Services with no api_service (empty or 'n/a') are skipped with a warning.
        """
        api_services: list[str] = []
        for sid in sorted(service_ids):
            entry = self._registry.get(sid)
            if entry is None:
                continue
            api = entry.api_service
            if not api or api == "n/a":
                print(
                    f"  warning: {sid} has no api_service — omitted from services.enable",
                    file=sys.stderr,
                )
                continue
            api_services.append(api)
        return sorted(set(api_services))

    @staticmethod
    def write(manifest: dict, output: Path) -> None:
        """Serialize manifest to YAML and write to output path."""
        import yaml

        content = yaml.dump(
            manifest,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )
        output.write_text(content)

    @staticmethod
    def to_yaml_str(manifest: dict) -> str:
        """Serialize manifest to a YAML string (for stdout output)."""
        import yaml

        return yaml.dump(
            manifest,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )
