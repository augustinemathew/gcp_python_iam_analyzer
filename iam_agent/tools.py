"""Workspace, scanner, GCS, and Agent Engine tools for the IAM Policy Agent."""

from __future__ import annotations

import json
import os
import subprocess
import tarfile
import tempfile
import urllib.request
import uuid
import zipfile
from pathlib import Path

import google.auth
import google.auth.transport.requests
from google.cloud import storage as gcs

from iamspy.cli import _finding_to_dict
from iamspy.loader import load_method_db
from iamspy.registry import ServiceRegistry
from iamspy.resolver import StaticPermissionResolver
from iamspy.resources import method_db_path, permissions_path, registry_path
from iamspy.scanner import GCPCallScanner

_workspaces: dict[str, str] = {}

_MAX_OUTPUT = 8000


# ---------------------------------------------------------------------------
# Agent Engine (Reasoning Engine) tools
# ---------------------------------------------------------------------------


def list_agent_engines(project_id: str, location: str = "us-central1") -> str:
    """List deployed Agent Engine instances in a GCP project.

    Args:
        project_id: The GCP project ID.
        location: Region (default ``us-central1``).

    Returns:
        JSON array of engine summaries, or an error string.
    """
    url = (
        f"https://{location}-aiplatform.googleapis.com/v1/"
        f"projects/{project_id}/locations/{location}/reasoningEngines"
    )
    try:
        body = _authed_get(url)
    except Exception as exc:
        return f"ERROR: {exc}"

    engines = body.get("reasoningEngines", [])
    return json.dumps([_summarize_engine(e) for e in engines], indent=2)


def _authed_get(url: str) -> dict:
    """HTTP GET with Application Default Credentials."""
    creds, _ = google.auth.default()
    creds.refresh(google.auth.transport.requests.Request())
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {creds.token}")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def _summarize_engine(engine: dict) -> dict:
    """Extract the useful fields from a reasoning engine response."""
    spec = engine.get("spec", {})
    pkg = spec.get("packageSpec", {})
    name = engine.get("name", "")
    engine_id = name.rsplit("/", 1)[-1] if "/" in name else name
    # Extract project number from resource name for AGENT_IDENTITY principal.
    # Format: projects/PROJECT_NUMBER/locations/LOCATION/reasoningEngines/ID
    parts = name.split("/")
    project_number = parts[1] if len(parts) >= 2 else ""
    location = parts[3] if len(parts) >= 4 else ""

    return {
        "id": engine_id,
        "resource_name": name,
        "display_name": engine.get("displayName", ""),
        "description": engine.get("description", ""),
        "framework": spec.get("agentFramework", ""),
        "pickle_uri": pkg.get("pickleObjectGcsUri", ""),
        "dependencies_uri": pkg.get("dependencyFilesGcsUri", ""),
        "requirements_uri": pkg.get("requirementsGcsUri", ""),
        "effective_identity": spec.get("effectiveIdentity", ""),
        "project_number": project_number,
        "location": location,
        "created": engine.get("createTime", ""),
    }


# ---------------------------------------------------------------------------
# GCS tools
# ---------------------------------------------------------------------------


def list_gcs(uri: str) -> str:
    """List objects under a GCS prefix.

    Args:
        uri: A gs:// URI prefix (e.g. ``gs://bucket/path/``).

    Returns:
        Newline-separated gs:// URIs, or an error string.
    """
    bucket_name, prefix = _parse_gcs_uri(uri)
    if bucket_name is None:
        return prefix  # error message

    try:
        blobs = list(
            gcs.Client().bucket(bucket_name).list_blobs(prefix=prefix, max_results=200)
        )
    except Exception as exc:
        return f"ERROR: listing failed: {exc}"

    if not blobs:
        return f"No objects found under {uri}"
    return "\n".join(f"gs://{bucket_name}/{b.name}" for b in blobs)


def download_gcs(uri: str, destination: str) -> str:
    """Download a single object from GCS.

    Args:
        uri: A gs:// URI pointing to a single object.
        destination: Local file path to write to.

    Returns:
        The local path on success, or an error string starting with ``ERROR:``.
    """
    bucket_name, blob_name = _parse_gcs_uri(uri)
    if bucket_name is None:
        return blob_name  # error message

    try:
        os.makedirs(os.path.dirname(destination) or ".", exist_ok=True)
        gcs.Client().bucket(bucket_name).blob(blob_name).download_to_filename(
            destination
        )
    except Exception as exc:
        return f"ERROR: download failed: {exc}"
    return destination


def _parse_gcs_uri(uri: str) -> tuple[str | None, str]:
    """Split ``gs://bucket/path`` into (bucket, path).

    Returns ``(None, error_message)`` on invalid input.
    """
    if not uri.startswith("gs://"):
        return None, f"ERROR: not a gs:// URI: {uri}"
    path = uri[5:]
    bucket_name, _, remainder = path.partition("/")
    if not bucket_name:
        return None, f"ERROR: missing bucket in URI: {uri}"
    return bucket_name, remainder


# ---------------------------------------------------------------------------
# Archive extraction
# ---------------------------------------------------------------------------


def _extract_tar(path: str, dest: str) -> None:
    with tarfile.open(path, "r:*") as tf:
        tf.extractall(dest, filter="data")


def _extract_zip(path: str, dest: str) -> None:
    with zipfile.ZipFile(path, "r") as zf:
        zf.extractall(dest)


def _extract_archive(path: str, dest: str) -> str | None:
    """Extract an archive to *dest*. Returns an error string or ``None``."""
    if tarfile.is_tarfile(path):
        _extract_tar(path, dest)
    elif zipfile.is_zipfile(path):
        _extract_zip(path, dest)
    else:
        return f"ERROR: unsupported archive format: {path}"
    return None


def _unwrap_single_dir(directory: str, skip: set[str]) -> str:
    """If *directory* has a single subdirectory (ignoring *skip*), return it."""
    entries = [e for e in os.listdir(directory) if e not in skip]
    if len(entries) == 1:
        candidate = os.path.join(directory, entries[0])
        if os.path.isdir(candidate):
            return candidate
    return directory


# ---------------------------------------------------------------------------
# Workspace management
# ---------------------------------------------------------------------------


def create_workspace(source: str, name: str) -> str:
    """Extract an archive (zip or tar.gz) into a temporary workspace.

    Accepts local paths and gs:// URIs.

    Args:
        source: Path to a local archive or a gs:// URI.
        name: Human-readable label for the workspace.

    Returns:
        A workspace ID string to pass to ``shell()``.
    """
    workspace_id = f"{name}-{uuid.uuid4().hex[:8]}"
    workspace_dir = os.path.join(tempfile.gettempdir(), "iam_agent", workspace_id)
    os.makedirs(workspace_dir, exist_ok=True)

    local_path = _resolve_source(source, workspace_dir)
    if local_path.startswith("ERROR:"):
        return local_path

    error = _extract_archive(local_path, workspace_dir)
    if error:
        return error

    workspace_dir = _unwrap_single_dir(
        workspace_dir, skip={"source.zip", "source.tar.gz"}
    )

    _workspaces[workspace_id] = workspace_dir
    return f"Workspace '{workspace_id}' created at {workspace_dir}"


def _resolve_source(source: str, workspace_dir: str) -> str:
    """Return a local file path, downloading from GCS if needed."""
    if not source.startswith("gs://"):
        if not os.path.isfile(source):
            return f"ERROR: file not found: {source}"
        return source

    ext = ".tar.gz" if source.endswith(".tar.gz") else os.path.splitext(source)[1]
    local_path = os.path.join(workspace_dir, f"source{ext}")
    result = download_gcs(source, local_path)
    if result.startswith("ERROR:"):
        return result
    return local_path


# ---------------------------------------------------------------------------
# IAM permission scanner
# ---------------------------------------------------------------------------

_EXCLUDED_DIRS = {".venv", "venv", "node_modules", "__pycache__", ".tox", ".git"}

_scanner: GCPCallScanner | None = None


def _get_scanner() -> GCPCallScanner:
    """Lazy-init the scanner (loads JSON data files once)."""
    global _scanner
    if _scanner is None:
        registry = ServiceRegistry.from_json(registry_path())
        resolver = StaticPermissionResolver(permissions_path())
        db = load_method_db(method_db_path())
        _scanner = GCPCallScanner(db, resolver, registry=registry)
    return _scanner


def _collect_python_files(directory: str) -> list[Path]:
    """Recursively collect .py files, skipping excluded directories."""
    files: list[Path] = []
    for root, dirs, filenames in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in _EXCLUDED_DIRS]
        for name in filenames:
            if name.endswith(".py"):
                files.append(Path(root) / name)
    return files


def scan_workspace(workspace: str) -> dict:
    """Run the IAM Python static analyzer on a workspace.

    Statically parses every Python file using tree-sitter, detects GCP SDK
    imports and method calls, and resolves each call to its required IAM
    permissions using a curated database of 8,000+ permission mappings
    across 129 GCP services.

    Args:
        workspace: Workspace ID returned by ``create_workspace()``.

    Returns:
        A dict with:
          - "stats": analysis statistics (files scanned, methods resolved, etc.)
          - "findings": list of findings with file, line, method, permissions,
            conditional permissions, service, class, status, and notes.
    """
    workspace_dir = _workspaces.get(workspace)
    if workspace_dir is None:
        return {"error": f"Unknown workspace: {workspace}"}

    scanner = _get_scanner()
    py_files = _collect_python_files(workspace_dir)

    if not py_files:
        return {"error": "No Python files found in workspace"}

    findings = []
    files_with_gcp_imports = 0
    total_methods_resolved = 0
    all_permissions: set[str] = set()
    all_services: set[str] = set()

    for py_file in py_files:
        source = py_file.read_text(encoding="utf-8", errors="replace")
        result = scanner.scan_source(source, str(py_file))
        if result.findings:
            files_with_gcp_imports += 1
        for f in result.findings:
            if f.status == "no_api_call":
                continue
            total_methods_resolved += 1
            all_permissions.update(f.permissions)
            all_permissions.update(f.conditional_permissions)
            for m in f.matched:
                all_services.add(m.display_name)
            d = _finding_to_dict(f)
            d["file"] = os.path.relpath(d["file"], workspace_dir)
            findings.append(d)

    return {
        "stats": {
            "files_scanned": len(py_files),
            "files_with_gcp_imports": files_with_gcp_imports,
            "sdk_methods_resolved": total_methods_resolved,
            "unique_permissions_found": len(all_permissions),
            "gcp_services_detected": sorted(all_services),
        },
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Shell
# ---------------------------------------------------------------------------


def shell(workspace: str, command: str) -> dict:
    """Run a shell command inside a workspace directory.

    Args:
        workspace: Workspace ID returned by ``create_workspace()``.
        command: Shell command to execute.

    Returns:
        Dict with ``stdout``, ``stderr``, ``exit_code``, and ``truncated``.
    """
    workspace_dir = _workspaces.get(workspace)
    if workspace_dir is None:
        return {
            "stdout": "",
            "stderr": f"Unknown workspace: {workspace}",
            "exit_code": 1,
            "truncated": False,
        }

    try:
        result = subprocess.run(
            command,
            shell=True,
            cwd=workspace_dir,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": "Command timed out after 60 seconds.",
            "exit_code": 124,
            "truncated": False,
        }

    return _format_shell_result(result)


def _format_shell_result(result: subprocess.CompletedProcess[str]) -> dict:
    stdout = result.stdout
    stderr = result.stderr
    truncated = False

    if len(stdout) > _MAX_OUTPUT:
        stdout = stdout[:_MAX_OUTPUT] + f"\n... truncated ({len(result.stdout)} chars)"
        truncated = True
    if len(stderr) > _MAX_OUTPUT:
        stderr = stderr[:_MAX_OUTPUT] + f"\n... truncated ({len(result.stderr)} chars)"
        truncated = True

    return {
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": result.returncode,
        "truncated": truncated,
    }
