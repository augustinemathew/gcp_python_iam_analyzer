"""Deploy tools — deploy agents and manage IAM bindings.

Shared by both local and remote MCP servers.
"""

from __future__ import annotations

import json
import subprocess

from agents.shared.gcp import get_project


def deploy_to_agent_engine(
    source_dir: str,
    display_name: str,
    project: str | None = None,
    location: str = "us-central1",
    identity_type: str = "AGENT_IDENTITY",
) -> dict:
    """Deploy an ADK agent to Vertex AI Agent Engine.

    Uses gcloud CLI for deployment.
    """
    proj = project or get_project()
    if not proj:
        return {"error": "No project specified"}

    # TODO: implement via Vertex AI API or gcloud
    # For now, return the gcloud command the user should run
    cmd = (
        f"gcloud beta ai reasoning-engines create"
        f" --project={proj}"
        f" --region={location}"
        f" --display-name={display_name}"
        f" --source={source_dir}"
    )

    return {
        "status": "command_generated",
        "project": proj,
        "location": location,
        "display_name": display_name,
        "identity_type": identity_type,
        "command": cmd,
        "note": "Run this command to deploy. Automated deployment coming soon.",
    }


def deploy_to_cloud_run(
    source_dir: str,
    service_name: str,
    project: str | None = None,
    region: str = "us-central1",
) -> dict:
    """Deploy to Cloud Run.

    Uses gcloud CLI for deployment.
    """
    proj = project or get_project()
    if not proj:
        return {"error": "No project specified"}

    cmd = (
        f"gcloud run deploy {service_name}"
        f" --project={proj}"
        f" --region={region}"
        f" --source={source_dir}"
    )

    return {
        "status": "command_generated",
        "project": proj,
        "region": region,
        "service_name": service_name,
        "command": cmd,
        "note": "Run this command to deploy. Automated deployment coming soon.",
    }


def grant_iam_roles(
    roles: list[str],
    member: str,
    project: str | None = None,
) -> dict:
    """Grant IAM roles to a member on a project.

    Returns the gcloud commands to run. Does NOT auto-apply — the user
    must confirm before executing.
    """
    proj = project or get_project()
    if not proj:
        return {"error": "No project specified"}

    commands = []
    for role in roles:
        cmd = (
            f"gcloud projects add-iam-policy-binding {proj}"
            f" --member={member}"
            f" --role={role}"
        )
        commands.append(cmd)

    return {
        "status": "commands_generated",
        "project": proj,
        "member": member,
        "roles": roles,
        "commands": commands,
        "note": "Review and run these commands to grant access.",
    }
