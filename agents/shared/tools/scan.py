"""Scan & analyze tools — code analysis via iamspy.

Shared by both local and remote MCP servers.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from iamspy.loader import load_method_db
from iamspy.manifest import ManifestGenerator
from iamspy.registry import ServiceRegistry
from iamspy.resolver import StaticPermissionResolver
from iamspy.resources import method_db_path, permissions_path, registry_path
from iamspy.scanner import GCPCallScanner

_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".tox", ".mypy_cache"}

_scanner: GCPCallScanner | None = None
_registry: ServiceRegistry | None = None


def get_scanner() -> GCPCallScanner:
    """Get or create the scanner singleton."""
    global _scanner, _registry
    if _scanner is None:
        _registry = ServiceRegistry.from_json(registry_path())
        resolver = StaticPermissionResolver(permissions_path())
        db = load_method_db(method_db_path())
        _scanner = GCPCallScanner(db, resolver, registry=_registry)
    return _scanner


def get_registry() -> ServiceRegistry:
    """Get or create the registry singleton."""
    get_scanner()
    return _registry  # type: ignore[return-value]


def collect_python_files(paths: list[str]) -> list[Path]:
    """Collect .py files from paths (files or directories)."""
    files: list[Path] = []
    for p_str in paths:
        p = Path(p_str).resolve()
        if p.is_file() and p.suffix == ".py":
            files.append(p)
        elif p.is_dir():
            for f in p.rglob("*.py"):
                if not any(skip in f.parts for skip in _SKIP_DIRS):
                    files.append(f)
    return sorted(files)


def finding_to_dict(f) -> dict:
    """Convert a Finding to a JSON-serializable dict."""
    d: dict = {
        "file": f.file,
        "line": f.line,
        "method": f.method_name,
        "service_id": sorted({m.service_id for m in f.matched}),
        "service": sorted({m.display_name for m in f.matched}),
        "class": sorted({m.class_name for m in f.matched}),
        "permissions": f.permissions,
        "conditional": f.conditional_permissions,
        "status": f.status,
        "resolution": f.resolution.value,
        "notes": f.perm_result.notes if f.perm_result else "",
    }
    if f.identity_context:
        d["identity"] = str(f.identity_context)
        d["credential"] = str(f.credential_provenance)
    return d


def scan(paths: list[str]) -> dict:
    """Scan Python files and return structured results."""
    scanner = get_scanner()
    files = collect_python_files(paths)
    if not files:
        return {"error": "No Python files found", "paths": paths}

    results = asyncio.run(scanner.scan_files(files))
    findings = []
    for result in results:
        for f in result.findings:
            if f.status != "no_api_call":
                findings.append(finding_to_dict(f))

    all_perms: set[str] = set()
    all_cond: set[str] = set()
    services: set[str] = set()
    for f in findings:
        all_perms.update(f["permissions"])
        all_cond.update(f.get("conditional", []))
        services.update(f["service_id"])

    return {
        "files_scanned": len(files),
        "findings_count": len(findings),
        "permissions": {
            "required": sorted(all_perms),
            "conditional": sorted(all_cond),
        },
        "services": sorted(services),
        "findings": findings,
    }


def manifest(paths: list[str], output_path: str | None = None) -> str:
    """Generate YAML manifest from scan results."""
    scanner = get_scanner()
    registry = get_registry()
    files = collect_python_files(paths)
    if not files:
        return "error: No Python files found"

    results = asyncio.run(scanner.scan_files(files))
    gen = ManifestGenerator(registry)
    m = gen.build(results, scanned_paths=paths, include_sources=True)
    yaml_str = gen.to_yaml_str(m)

    if output_path:
        gen.write(m, Path(output_path))

    return yaml_str
