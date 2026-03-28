"""IAMSpy Local MCP Server — developer-facing, runs in Antigravity.

Exposes code analysis, project exploration, IAM troubleshooting, and deploy tools.
Uses developer's ADC. Defaults to dev profile.

Usage:
    python -m mcp.local.server
"""

from __future__ import annotations

import asyncio
import json

from mcp.server.fastmcp import FastMCP

from iamspy_mcp.shared.tools import scan as scan_lib
from iamspy_mcp.shared.tools import iam as iam_lib
from iamspy_mcp.shared.tools import resources as resources_lib
from iamspy_mcp.shared.tools import deploy as deploy_lib
from iamspy_mcp.shared.gcp import get_project

server = FastMCP(
    "iamspy-local",
    instructions=(
        "You are IAMSpy, a developer assistant for GCP IAM permissions. "
        "You help developers understand what IAM permissions their code needs, "
        "explore their GCP project resources, troubleshoot access issues, "
        "and deploy with least-privilege permissions. "
        "You work with the developer's local code and their GCP project."
    ),
)


# ── Scan & Analyze ─────────────────────────────────────────────────────


@server.tool()
def scan_files(paths: list[str]) -> str:
    """Scan Python files for GCP SDK calls and their required IAM permissions.

    Pass file paths or directory paths. Returns findings with permissions,
    identity context (app/user), and source locations.

    Example: scan_files(["src/", "main.py"])
    """
    return json.dumps(scan_lib.scan(paths), indent=2)


@server.tool()
def generate_manifest(paths: list[str], output_path: str | None = None) -> str:
    """Generate an IAM permission manifest (YAML) for the scanned code.

    The manifest lists required permissions split by identity context
    (app SA vs delegated user) and GCP services to enable.
    """
    return scan_lib.manifest(paths, output_path)


@server.tool()
def search_permissions(pattern: str) -> str:
    """Search the IAM permission database for methods matching a pattern.

    Supports glob patterns: '*encrypt*', 'storage.buckets.*', 'bigquery.*.create'
    """
    import fnmatch

    scanner = scan_lib.get_scanner()
    resolver = scanner.resolver
    matches = []

    for key in resolver.all_keys():
        if fnmatch.fnmatch(key, pattern) or fnmatch.fnmatch(key, f"*{pattern}*"):
            result = resolver.resolve_by_key(key)
            if result:
                matches.append({
                    "key": key,
                    "permissions": result.permissions,
                    "conditional": result.conditional_permissions,
                    "notes": result.notes,
                })

    return json.dumps({"pattern": pattern, "matches": len(matches), "results": matches[:50]}, indent=2)


# ── GCP Resources ─────────────────────────────────────────────────────


@server.tool()
def list_agent_engines(project: str | None = None, location: str = "us-central1") -> str:
    """List deployed Agent Engine instances in your GCP project."""
    return json.dumps(resources_lib.list_agents(project, location), indent=2)


@server.tool()
def list_cloud_run_services(project: str | None = None) -> str:
    """List Cloud Run services in your GCP project."""
    return json.dumps(resources_lib.list_run_services(project), indent=2)


@server.tool()
def list_ai_resources(project: str | None = None) -> str:
    """List Cloud AI resources (Agent Engine, Vertex endpoints, models, datasets)."""
    return json.dumps(resources_lib.list_ai_resources(project), indent=2)


# ── IAM Policy ─────────────────────────────────────────────────────────


@server.tool()
def get_project_iam_policy(project: str | None = None) -> str:
    """Get the IAM policy bindings for your GCP project."""
    from iamspy_mcp.shared.gcp import get_iam_policy

    proj = project or get_project()
    if not proj:
        return json.dumps({"error": "No project specified"})
    policy = get_iam_policy(proj)
    return json.dumps({"project": proj, "bindings": policy.get("bindings", [])}, indent=2)


@server.tool()
def analyze_permissions(paths: list[str], project: str | None = None) -> str:
    """Compare what your code needs vs what you have.

    Scans the code, then checks your IAM permissions on the project.
    Shows missing permissions and what roles to request.
    """
    return json.dumps(iam_lib.analyze(paths, project), indent=2)


@server.tool()
def troubleshoot_access(permission: str, project: str | None = None) -> str:
    """Troubleshoot a PERMISSION_DENIED error.

    Checks if you have the permission, whether deny policies block it,
    and which roles to request.
    """
    return json.dumps(iam_lib.troubleshoot(permission, project), indent=2)


# ── Deploy ─────────────────────────────────────────────────────────────


@server.tool()
def deploy_agent_engine(
    source_dir: str,
    display_name: str,
    project: str | None = None,
    location: str = "us-central1",
) -> str:
    """Deploy an ADK agent to Vertex AI Agent Engine.

    Generates the deploy command. Review before running.
    """
    return json.dumps(
        deploy_lib.deploy_to_agent_engine(source_dir, display_name, project, location),
        indent=2,
    )


@server.tool()
def deploy_cloud_run(
    source_dir: str,
    service_name: str,
    project: str | None = None,
    region: str = "us-central1",
) -> str:
    """Deploy to Cloud Run. Generates the deploy command."""
    return json.dumps(
        deploy_lib.deploy_to_cloud_run(source_dir, service_name, project, region),
        indent=2,
    )


@server.tool()
def grant_iam_roles(roles: list[str], member: str, project: str | None = None) -> str:
    """Generate commands to grant IAM roles. Review before running."""
    return json.dumps(deploy_lib.grant_iam_roles(roles, member, project), indent=2)


# ── Guardrails ─────────────────────────────────────────────────────────


@server.tool()
def check_guardrails(
    paths: list[str],
    environment: str = "prod",
    identity_type: str | None = None,
) -> str:
    """Check if an agent's permissions violate security guardrails.

    Scans the code to determine required permissions, then evaluates them
    against guardrail rules for the target environment. Flags:
    - Privilege escalation risks (IAM modification, key creation)
    - Destructive operations (delete, destroy)
    - Data exfiltration risks (export, decrypt)
    - Identity issues (shared SA in prod)
    - Over-permissioning (too many permissions, too-broad roles)

    Returns violations with severity (block/warn/info) and remediation steps.
    """
    from iamspy_mcp.shared.guardrails import evaluate_guardrails

    scanner = scan_lib.get_scanner()
    files = scan_lib.collect_python_files(paths)
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
            {
                "severity": v.severity,
                "category": v.category,
                "message": v.message,
                "permission": v.permission,
                "role": v.role,
                "remediation": v.remediation,
            }
            for v in violations
        ],
    }, indent=2)


if __name__ == "__main__":
    server.run()
