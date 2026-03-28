"""IDE agent tools — local filesystem context.

These tools work with the developer's local files and project directories.
No GCS, no archive extraction, no workspace IDs.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from agents.shared.gcp import (
    get_deny_policies,
    get_iam_policy,
    get_project,
    list_agent_engines as _list_agents,
    list_cloud_run_services as _list_run,
    search_resources as _search_resources,
    test_iam_permissions,
)
from agents.shared.tools.scan import (
    collect_python_files,
    finding_to_dict,
    get_registry,
    get_scanner,
    manifest as _manifest,
    scan as _scan,
)


# ── Local scan tools ───────────────────────────────────────────────────


def scan_file(file_path: str) -> dict:
    """Scan a single Python file for GCP SDK calls and IAM permissions.

    Returns findings with permissions, identity context (app/user),
    and source locations.

    Args:
        file_path: Path to a Python file.
    """
    p = Path(file_path)
    if not p.is_file():
        return {"error": f"File not found: {file_path}"}
    if p.suffix != ".py":
        return {"error": f"Not a Python file: {file_path}"}

    scanner = get_scanner()
    source = p.read_text(encoding="utf-8", errors="replace")
    result = scanner.scan_source(source, str(p))

    findings = []
    all_perms: set[str] = set()
    all_services: set[str] = set()
    for f in result.findings:
        if f.status == "no_api_call":
            continue
        all_perms.update(f.permissions)
        all_perms.update(f.conditional_permissions)
        for m in f.matched:
            all_services.add(m.display_name)
        findings.append(finding_to_dict(f))

    return {
        "stats": {
            "sdk_methods_resolved": len(findings),
            "unique_permissions_found": len(all_perms),
            "gcp_services_detected": sorted(all_services),
        },
        "findings": findings,
    }


def scan_directory(directory: str) -> dict:
    """Scan all Python files in a local directory.

    Returns findings with permissions, identity, and aggregate stats.

    Args:
        directory: Path to a local directory.
    """
    return _scan([directory])


def generate_manifest(paths: list[str], output_path: str | None = None) -> str:
    """Generate an IAM permission manifest (YAML) for local code.

    The manifest lists required permissions split by identity context
    (app SA vs delegated user) and GCP services to enable.

    Args:
        paths: File or directory paths to scan.
        output_path: If provided, writes manifest to this file.

    Returns:
        YAML manifest content.
    """
    return _manifest(paths, output_path)


def check_guardrails(
    paths: list[str],
    environment: str = "prod",
    identity_type: str | None = None,
) -> str:
    """Check if the code's permissions violate security guardrails.

    Scans the code, evaluates permissions against guardrail rules.
    Flags privilege escalation, destructive ops, data exfiltration,
    and identity issues.

    Args:
        paths: File or directory paths to scan.
        environment: 'dev', 'staging', or 'prod'.
        identity_type: 'agent_identity' or 'service_account'.

    Returns:
        JSON with violations, severity, and remediation.
    """
    from agents.shared.guardrails import evaluate_guardrails

    scanner = get_scanner()
    files = list(collect_python_files(paths))
    if not files:
        return json.dumps({"error": "No Python files found"})

    results = asyncio.run(scanner.scan_files(files))
    permissions: set[str] = set()
    for result in results:
        for finding in result.findings:
            if finding.status == "no_api_call":
                continue
            permissions.update(finding.permissions)
            permissions.update(finding.conditional_permissions)

    violations = evaluate_guardrails(
        permissions=permissions,
        identity_type=identity_type,
        environment=environment,
    )

    blocks = [v for v in violations if v.severity == "block"]
    warns = [v for v in violations if v.severity == "warn"]

    return json.dumps({
        "environment": environment,
        "permissions_checked": len(permissions),
        "violations": len(violations),
        "blocks": len(blocks),
        "warnings": len(warns),
        "deploy_allowed": len(blocks) == 0,
        "details": [
            {"severity": v.severity, "category": v.category, "message": v.message,
             "permission": v.permission, "remediation": v.remediation}
            for v in violations
        ],
    }, indent=2)


# ── GCP resource tools ─────────────────────────────────────────────────


def list_agent_engines(project_id: str | None = None, location: str = "us-central1") -> str:
    """List deployed Agent Engine instances in the project."""
    proj = project_id or get_project()
    if not proj:
        return json.dumps({"error": "No project specified"})
    engines = _list_agents(proj, location)
    return json.dumps({"project": proj, "count": len(engines), "engines": engines}, indent=2)


def list_cloud_run_services(project_id: str | None = None) -> str:
    """List Cloud Run services in the project."""
    proj = project_id or get_project()
    if not proj:
        return json.dumps({"error": "No project specified"})
    services = _list_run(proj)
    return json.dumps({"project": proj, "count": len(services), "services": services}, indent=2)


# ── IAM tools ──────────────────────────────────────────────────────────


def get_project_iam_policy(project_id: str | None = None) -> str:
    """Get the IAM policy bindings for the project."""
    proj = project_id or get_project()
    if not proj:
        return json.dumps({"error": "No project specified"})
    policy = get_iam_policy(proj)
    return json.dumps({"project": proj, "bindings": policy.get("bindings", [])}, indent=2)


def analyze_permissions(paths: list[str], project_id: str | None = None) -> str:
    """Compare what the code needs vs what the caller has on the project.

    Scans code, checks IAM, shows missing and excess permissions.
    """
    from agents.shared.tools.iam import analyze
    return json.dumps(analyze(paths, project_id), indent=2)


def troubleshoot_access(permission: str, project_id: str | None = None) -> str:
    """Troubleshoot a PERMISSION_DENIED error.

    Checks caller permissions, deny policies, and suggests fix.
    """
    from agents.shared.tools.iam import troubleshoot
    return json.dumps(troubleshoot(permission, project_id), indent=2)
