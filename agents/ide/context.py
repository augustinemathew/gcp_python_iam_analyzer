"""Auto-context loader — builds the agent's knowledge of the project on startup.

Checks manifest freshness, regenerates if stale, loads workspace config.
Returns a context string injected into the agent's system instruction so
it starts every conversation already knowing what the code needs.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from agents.shared.tools.scan import collect_python_files, get_scanner, get_registry
from iamspy.manifest import ManifestGenerator


def _find_project_root() -> Path:
    """Find the project root by searching upward for .iamspy/ first, then common markers.

    Prefers .iamspy/ (our own marker) over generic ones like .git to avoid
    scanning the entire monorepo when cwd is a subdirectory.
    """
    cwd = Path.cwd().resolve()

    # First pass: look for .iamspy (our marker — most specific)
    current = cwd
    while True:
        if (current / ".iamspy").exists():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent

    # Second pass: look for project markers, but stop at .git
    # (don't go above the repo root)
    current = cwd
    while True:
        for marker in ("pyproject.toml", "setup.py", "requirements.txt"):
            if (current / marker).exists():
                return current
        if (current / ".git").exists():
            return current  # stop at repo root, don't go higher
        parent = current.parent
        if parent == current:
            break
        current = parent

    return cwd


def _manifest_is_stale(manifest_path: Path, source_root: Path) -> bool:
    """Check if manifest is older than any Python source file."""
    if not manifest_path.exists():
        return True

    manifest_mtime = manifest_path.stat().st_mtime
    py_files = collect_python_files([str(source_root)])

    for f in py_files:
        if f.stat().st_mtime > manifest_mtime:
            return True
    return False


def _load_manifest(manifest_path: Path) -> dict | None:
    """Load and parse an existing manifest."""
    if not manifest_path.exists():
        return None
    try:
        return yaml.safe_load(manifest_path.read_text())
    except Exception:
        return None


def _regenerate_manifest(source_root: Path, manifest_path: Path) -> dict:
    """Regenerate the manifest from source code."""
    scanner = get_scanner()
    registry = get_registry()
    files = collect_python_files([str(source_root)])

    results = []
    for f in files:
        source = f.read_text(encoding="utf-8", errors="replace")
        results.append(scanner.scan_source(source, str(f)))

    gen = ManifestGenerator(registry)
    manifest = gen.build(results, scanned_paths=[str(source_root)])
    gen.write(manifest, manifest_path)
    return manifest


def _load_workspace_config(project_root: Path) -> dict | None:
    """Load workspace config if it exists."""
    config_path = project_root / ".iamspy" / "workspace.yaml"
    if not config_path.exists():
        return None
    try:
        return yaml.safe_load(config_path.read_text())
    except Exception:
        return None


def _format_manifest_summary(manifest: dict) -> str:
    """Format manifest into a concise context string."""
    lines = []
    identities = manifest.get("identities", {})
    for ident_name, ident_data in identities.items():
        perms = ident_data.get("permissions", {})
        required = perms.get("required", [])
        conditional = perms.get("conditional", [])
        scopes = ident_data.get("oauth_scopes", [])

        lines.append(f"  {ident_name}:")
        if required:
            lines.append(f"    required: {', '.join(required)}")
        if conditional:
            lines.append(f"    conditional: {', '.join(conditional)}")
        if scopes:
            lines.append(f"    oauth_scopes: {', '.join(scopes)}")

    # Unattributed
    unattr = manifest.get("permissions", {})
    unattr_req = unattr.get("required", [])
    unattr_cond = unattr.get("conditional", [])
    if unattr_req or unattr_cond:
        lines.append("  unattributed:")
        if unattr_req:
            lines.append(f"    required: {', '.join(unattr_req)}")
        if unattr_cond:
            lines.append(f"    conditional: {', '.join(unattr_cond)}")

    services = manifest.get("services", {}).get("enable", [])

    return (
        f"Services to enable: {', '.join(services)}\n"
        f"Permissions by identity:\n" + "\n".join(lines)
    )


def _format_workspace_summary(config: dict) -> str:
    """Format workspace config into a concise context string."""
    lines = []
    project_name = config.get("project", {}).get("name", "unknown")
    lines.append(f"Project: {project_name}")

    envs = config.get("environments", {})
    for env_name, env_data in envs.items():
        gcp_proj = env_data.get("gcp_project", "?")
        target = env_data.get("deployment", {}).get("target", "?")
        lines.append(f"  {env_name}: project={gcp_proj}, target={target}")

        identity = env_data.get("identity", {})
        for ident_name, ident_info in identity.items():
            if isinstance(ident_info, dict):
                ident_type = ident_info.get("type", "?")
                principal = ident_info.get("principal", "not set")
                lines.append(f"    {ident_name}: type={ident_type}, principal={principal}")

    return "\n".join(lines)


def build_context() -> str:
    """Build the full auto-context string for the agent.

    This runs at agent startup. It:
    1. Finds the project root
    2. Checks if iam-manifest.yaml is fresh (regenerates if stale)
    3. Loads workspace config if present
    4. Returns a context block injected into the system instruction
    """
    project_root = _find_project_root()
    manifest_path = project_root / "iam-manifest.yaml"

    parts = []

    # Manifest
    if _manifest_is_stale(manifest_path, project_root):
        py_files = collect_python_files([str(project_root)])
        if py_files:
            manifest = _regenerate_manifest(project_root, manifest_path)
            parts.append("## Code Analysis (auto-generated, manifest was stale)")
            parts.append(_format_manifest_summary(manifest))
        else:
            parts.append("## Code Analysis\nNo Python files found in project.")
    else:
        manifest = _load_manifest(manifest_path)
        if manifest:
            parts.append("## Code Analysis (from iam-manifest.yaml)")
            parts.append(_format_manifest_summary(manifest))

    # Workspace config
    config = _load_workspace_config(project_root)
    if config:
        parts.append("\n## Workspace Config (from .iamspy/workspace.yaml)")
        parts.append(_format_workspace_summary(config))
    else:
        parts.append("\n## Workspace Config\nNo .iamspy/workspace.yaml found. Ask the developer about deployment target, project, and identity.")

    return "\n".join(parts)
