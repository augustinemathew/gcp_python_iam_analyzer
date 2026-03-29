"""Manifest generation: convert scan results into a permission manifest YAML.

Tests: tests/test_manifest.py
"""

from __future__ import annotations

import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from iamspy.models import ScanResult
    from iamspy.registry import ServiceRegistry


class ManifestGenerator:
    """Build a permission manifest from scan results.

    The manifest is a structured dict that can be serialized to YAML.

    v2 format splits permissions by identity context (app/user/impersonated).
    v1 format is a flat permission list (backward compatible).

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
        """Build v2 manifest with identity-aware permissions.

        Findings with an identity_context go into the identities block.
        Findings without go into the top-level permissions block.
        """
        service_ids: set[str] = set()
        sources: dict[str, list[dict]] = {}

        # Compute the root for relative paths
        source_root = self._resolve_source_root(scanned_paths)

        # Per-identity buckets
        identity_required: dict[str, set[str]] = defaultdict(set)
        identity_conditional: dict[str, set[str]] = defaultdict(set)
        identity_scopes: dict[str, set[str]] = defaultdict(set)

        # Unattributed (no identity context)
        unattributed_required: set[str] = set()
        unattributed_conditional: set[str] = set()

        for result in results:
            for finding in result.findings:
                if finding.status == "no_api_call":
                    continue

                identity = str(finding.identity_context) if finding.identity_context else ""
                for match in finding.matched:
                    service_ids.add(match.service_id)

                rel_file = os.path.relpath(finding.file, source_root)

                for perm in finding.permissions:
                    if identity:
                        identity_required[identity].add(perm)
                    else:
                        unattributed_required.add(perm)
                    if include_sources:
                        source_entry: dict = {
                            "file": rel_file,
                            "line": finding.line,
                            "method": finding.method_name,
                        }
                        if identity:
                            source_entry["identity"] = identity
                        sources.setdefault(perm, []).append(source_entry)

                for perm in finding.conditional_permissions:
                    if identity:
                        identity_conditional[identity].add(perm)
                    else:
                        unattributed_conditional.add(perm)
                    if include_sources:
                        source_entry = {
                            "file": rel_file,
                            "line": finding.line,
                            "method": finding.method_name,
                        }
                        if identity:
                            source_entry["identity"] = identity
                        sources.setdefault(perm, []).append(source_entry)

        api_services = self._resolve_api_services(service_ids)

        # Collect OAuth scopes from credential provenance analysis
        # (stored on ScanResult if provenance was run)
        for result in results:
            if hasattr(result, "_provenance") and result._provenance:
                for scope_ref in result._provenance.oauth_scopes:
                    identity_scopes["user"].add(scope_ref.scope)

        manifest: dict = {
            "version": "2",
            "generated_by": f"iamspy scan {' '.join(scanned_paths)}",
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "services": {
                "enable": sorted(api_services),
            },
        }

        # Identities block — only emit identities that have findings
        all_identities = sorted(set(identity_required) | set(identity_conditional))
        if all_identities:
            identities: dict = {}
            for ident in all_identities:
                entry: dict = {
                    "permissions": {
                        "required": sorted(identity_required.get(ident, set())),
                        "conditional": sorted(identity_conditional.get(ident, set())),
                    },
                }
                if ident in identity_scopes:
                    entry["oauth_scopes"] = sorted(identity_scopes[ident])
                identities[ident] = entry
            manifest["identities"] = identities

        # Top-level permissions — unattributed findings
        manifest["permissions"] = {
            "required": sorted(unattributed_required),
            "conditional": sorted(unattributed_conditional),
        }

        if include_sources:
            manifest["sources"] = {
                perm: locs for perm, locs in sorted(sources.items())
            }

        return manifest

    @staticmethod
    def _resolve_source_root(scanned_paths: list[str]) -> str:
        """Compute the root directory for relative path computation.

        Uses the first scanned path — if it's a directory, use it directly.
        If it's a file, use its parent. Falls back to cwd.
        """
        if not scanned_paths:
            return os.getcwd()
        first = os.path.abspath(scanned_paths[0])
        return first if os.path.isdir(first) else os.path.dirname(first)

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
