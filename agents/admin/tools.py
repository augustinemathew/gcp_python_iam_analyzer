"""Admin agent tools — remote workspace context.

These tools work with deployed agent code pulled from GCS/Agent Engine.
Workspace management: download archives, extract, scan.
"""

from __future__ import annotations

import json
import os
import subprocess
import tarfile
import tempfile
import uuid
import zipfile
from pathlib import Path

from google.cloud import storage as gcs_client

from agents.shared.gcp import (
    get_deny_policies,
    get_iam_policy,
    get_project,
    list_agent_engines as _list_agents,
    test_iam_permissions,
)
from agents.shared.gcp import _authed_request
from agents.shared.tools.scan import (
    collect_python_files,
    finding_to_dict,
    get_scanner,
)

_workspaces: dict[str, str] = {}
_MAX_OUTPUT = 8000


# ── Agent Engine ───────────────────────────────────────────────────────


def list_agent_engines(project_id: str, location: str = "us-central1") -> str:
    """List deployed Agent Engine instances in a GCP project.

    Returns JSON with engine summaries: name, identity, source URI.
    """
    engines = _list_agents(project_id, location)
    summaries = []
    for e in engines:
        spec = e.get("spec", {})
        pkg = spec.get("packageSpec", {})
        name = e.get("name", "")
        parts = name.split("/")
        summaries.append({
            "id": name.rsplit("/", 1)[-1] if "/" in name else name,
            "resource_name": name,
            "display_name": e.get("displayName", ""),
            "framework": spec.get("agentFramework", ""),
            "dependencies_uri": pkg.get("dependencyFilesGcsUri", ""),
            "effective_identity": spec.get("effectiveIdentity", ""),
            "project_number": parts[1] if len(parts) >= 2 else "",
            "location": parts[3] if len(parts) >= 4 else "",
        })
    return json.dumps(summaries, indent=2)


# ── IAM Policy ─────────────────────────────────────────────────────────


def get_project_iam_policy(project_id: str) -> dict:
    """Get the IAM allow policy for a project."""
    policy = get_iam_policy(project_id)
    bindings = policy.get("bindings", [])
    return {
        "bindings": bindings,
        "summary": [{"role": b["role"], "member_count": len(b.get("members", []))} for b in bindings],
    }


def get_effective_iam_policy(project_id: str, member: str) -> dict:
    """Get effective permissions for a member after inheritance and deny."""
    identity = member.removeprefix("serviceAccount:")
    url = (
        f"https://cloudasset.googleapis.com/v1/"
        f"projects/{project_id}:analyzeIamPolicy"
        f"?analysisQuery.scope=projects/{project_id}"
        f"&analysisQuery.identitySelector.identity={identity}"
    )
    body = _authed_request("GET", url)
    if "error" in body:
        return body

    analyses = body.get("mainAnalysis", {}).get("analysisResults", [])
    roles: set[str] = set()
    bindings = []
    for result in analyses:
        policy = result.get("iamBinding", {})
        role = policy.get("role", "")
        if role:
            roles.add(role)
            bindings.append({
                "role": role,
                "resource": result.get("attachedResourceFullName", ""),
                "members": policy.get("members", []),
            })
    return {"roles": sorted(roles), "role_count": len(roles), "bindings": bindings}


def list_deny_policies(project_id: str) -> dict:
    """List IAM deny policies on a project."""
    policies = get_deny_policies(project_id)
    return {
        "total": len(policies),
        "policies": [
            {"name": p.get("name", ""), "rules_count": len(p.get("rules", []))}
            for p in policies
        ],
    }


# ── Workspace management ───────────────────────────────────────────────


def create_workspace(source: str, name: str) -> str:
    """Download and extract an archive into a temp workspace.

    Accepts local paths and gs:// URIs. Returns a workspace ID
    for use with scan_workspace() and shell().
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

    # Unwrap single subdirectory
    entries = [e for e in os.listdir(workspace_dir) if e not in {"source.zip", "source.tar.gz"}]
    if len(entries) == 1:
        candidate = os.path.join(workspace_dir, entries[0])
        if os.path.isdir(candidate):
            workspace_dir = candidate

    _workspaces[workspace_id] = workspace_dir
    return f"Workspace '{workspace_id}' created at {workspace_dir}"


def scan_workspace(workspace: str) -> dict:
    """Scan a remote workspace for GCP SDK calls and IAM permissions.

    Use after create_workspace(). Scans all Python files, detects GCP SDK
    calls, resolves IAM permissions, identifies credential identity context.
    """
    workspace_dir = _workspaces.get(workspace)
    if workspace_dir is None:
        return {"error": f"Unknown workspace: {workspace}"}
    return _scan_directory(workspace_dir)


# ── GCS ────────────────────────────────────────────────────────────────


def list_gcs(uri: str) -> str:
    """List objects under a GCS prefix."""
    bucket_name, prefix = _parse_gcs_uri(uri)
    if bucket_name is None:
        return prefix
    try:
        blobs = list(gcs_client.Client().bucket(bucket_name).list_blobs(prefix=prefix, max_results=200))
    except Exception as exc:
        return f"ERROR: {exc}"
    if not blobs:
        return f"No objects found under {uri}"
    return "\n".join(f"gs://{bucket_name}/{b.name}" for b in blobs)


def download_gcs(uri: str, destination: str) -> str:
    """Download a single object from GCS."""
    bucket_name, blob_name = _parse_gcs_uri(uri)
    if bucket_name is None:
        return blob_name
    try:
        os.makedirs(os.path.dirname(destination) or ".", exist_ok=True)
        gcs_client.Client().bucket(bucket_name).blob(blob_name).download_to_filename(destination)
    except Exception as exc:
        return f"ERROR: {exc}"
    return destination


# ── Shell ──────────────────────────────────────────────────────────────


def shell(workspace: str, command: str) -> dict:
    """Run a shell command inside a workspace directory."""
    workspace_dir = _workspaces.get(workspace)
    if workspace_dir is None:
        return {"stdout": "", "stderr": f"Unknown workspace: {workspace}", "exit_code": 1, "truncated": False}
    try:
        result = subprocess.run(command, shell=True, cwd=workspace_dir, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timed out after 60s", "exit_code": 124, "truncated": False}

    stdout, stderr, truncated = result.stdout, result.stderr, False
    if len(stdout) > _MAX_OUTPUT:
        stdout = stdout[:_MAX_OUTPUT] + f"\n... truncated ({len(result.stdout)} chars)"
        truncated = True
    if len(stderr) > _MAX_OUTPUT:
        stderr = stderr[:_MAX_OUTPUT] + f"\n... truncated ({len(result.stderr)} chars)"
        truncated = True
    return {"stdout": stdout, "stderr": stderr, "exit_code": result.returncode, "truncated": truncated}


# ── Internal helpers ───────────────────────────────────────────────────


def _scan_directory(directory: str) -> dict:
    scanner = get_scanner()
    py_files = list(collect_python_files([directory]))
    if not py_files:
        return {"error": "No Python files found"}

    findings = []
    files_with_gcp = 0
    all_perms: set[str] = set()
    all_services: set[str] = set()

    for py_file in py_files:
        source = py_file.read_text(encoding="utf-8", errors="replace")
        result = scanner.scan_source(source, str(py_file))
        if result.findings:
            files_with_gcp += 1
        for f in result.findings:
            if f.status == "no_api_call":
                continue
            all_perms.update(f.permissions)
            all_perms.update(f.conditional_permissions)
            for m in f.matched:
                all_services.add(m.display_name)
            d = finding_to_dict(f)
            d["file"] = os.path.relpath(d["file"], directory)
            findings.append(d)

    return {
        "stats": {
            "files_scanned": len(py_files),
            "files_with_gcp_imports": files_with_gcp,
            "sdk_methods_resolved": len(findings),
            "unique_permissions_found": len(all_perms),
            "gcp_services_detected": sorted(all_services),
        },
        "findings": findings,
    }


def _resolve_source(source: str, workspace_dir: str) -> str:
    if not source.startswith("gs://"):
        return source if os.path.isfile(source) else f"ERROR: file not found: {source}"
    ext = ".tar.gz" if source.endswith(".tar.gz") else os.path.splitext(source)[1]
    local_path = os.path.join(workspace_dir, f"source{ext}")
    result = download_gcs(source, local_path)
    return result if result.startswith("ERROR:") else local_path


def _extract_archive(path: str, dest: str) -> str | None:
    if tarfile.is_tarfile(path):
        with tarfile.open(path, "r:*") as tf:
            tf.extractall(dest, filter="data")
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path, "r") as zf:
            zf.extractall(dest)
    else:
        return f"ERROR: unsupported archive: {path}"
    return None


def _parse_gcs_uri(uri: str) -> tuple[str | None, str]:
    if not uri.startswith("gs://"):
        return None, f"ERROR: not a gs:// URI: {uri}"
    path = uri[5:]
    bucket_name, _, remainder = path.partition("/")
    return (bucket_name, remainder) if bucket_name else (None, f"ERROR: missing bucket: {uri}")
