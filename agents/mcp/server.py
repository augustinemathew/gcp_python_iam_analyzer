"""IAMSpy MCP Server — wraps IDE agent tools for Antigravity/VS Code.

Usage: python -m agents.mcp
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from agents.ide import tools

server = FastMCP(
    "iamspy",
    instructions=(
        "IAMSpy helps developers understand and manage GCP IAM permissions. "
        "Scan Python files, explore project resources, analyze IAM policies, "
        "and deploy with least-privilege permissions."
    ),
)


@server.tool()
def scan_file(file_path: str) -> str:
    """Scan a single Python file for GCP SDK calls and IAM permissions."""
    return json.dumps(tools.scan_file(file_path), indent=2)


@server.tool()
def scan_directory(directory: str) -> str:
    """Scan all Python files in a directory for GCP SDK calls."""
    return json.dumps(tools.scan_directory(directory), indent=2)


@server.tool()
def generate_manifest(paths: list[str], output_path: str | None = None) -> str:
    """Generate an IAM permission manifest (YAML) for the code."""
    return tools.generate_manifest(paths, output_path)


@server.tool()
def check_guardrails(paths: list[str], environment: str = "prod", identity_type: str | None = None) -> str:
    """Check if code permissions violate security guardrails."""
    return tools.check_guardrails(paths, environment, identity_type)


@server.tool()
def list_agent_engines(project_id: str | None = None, location: str = "us-central1") -> str:
    """List deployed Agent Engine instances."""
    return tools.list_agent_engines(project_id, location)


@server.tool()
def list_cloud_run_services(project_id: str | None = None) -> str:
    """List Cloud Run services."""
    return tools.list_cloud_run_services(project_id)


@server.tool()
def get_project_iam_policy(project_id: str | None = None) -> str:
    """Get IAM policy bindings for the project."""
    return tools.get_project_iam_policy(project_id)


@server.tool()
def analyze_permissions(paths: list[str], project_id: str | None = None) -> str:
    """Compare code requirements vs project IAM. Shows missing/excess."""
    return tools.analyze_permissions(paths, project_id)


@server.tool()
def troubleshoot_access(permission: str, project_id: str | None = None) -> str:
    """Troubleshoot a PERMISSION_DENIED error."""
    return tools.troubleshoot_access(permission, project_id)
