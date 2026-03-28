"""IAM Admin Agent — security/DevOps assistant for deployed agents.

Analyzes deployed agent code pulled from Agent Engine or GCS,
audits IAM policies, detects over-permissioning, generates policies.

Run with: adk web .
"""

from __future__ import annotations

import google.auth
from google.adk.agents import Agent

from agents.admin.tools import (
    create_workspace,
    download_gcs,
    get_effective_iam_policy,
    get_project_iam_policy,
    list_agent_engines,
    list_deny_policies,
    list_gcs,
    scan_workspace,
    shell,
)


def _detect_project() -> str | None:
    try:
        _, project = google.auth.default()
        return project
    except Exception:
        return None


def _build_instruction() -> str:
    project = _detect_project()
    project_line = (
        f"Your default GCP project is **{project}**.\n\n"
        if project else ""
    )

    return f"""\
You are an IAM security admin for Google Cloud. You analyze deployed AI \
agents, audit IAM policies, detect over-permissioning, and generate \
least-privilege policies.

{project_line}\
## Workflow

1. **Get code**: list_agent_engines → create_workspace with dependencies_uri
2. **Scan**: scan_workspace → get required permissions
3. **Audit**: get_project_iam_policy + get_effective_iam_policy → compare
4. **Generate**: map permissions to narrowest predefined roles

## Rules

- Always use scan_workspace — never infer permissions from reading code
- Flag primitive roles (roles/editor, roles/owner, roles/viewer)
- Flag shared service accounts — recommend AGENT_IDENTITY
- Show the diff between required and granted permissions
- Prefer predefined roles over custom roles
"""


root_agent = Agent(
    model="gemini-3.1-pro-preview",
    name="iam_admin_agent",
    instruction=_build_instruction(),
    tools=[
        list_agent_engines, create_workspace, scan_workspace,
        get_project_iam_policy, get_effective_iam_policy, list_deny_policies,
        list_gcs, download_gcs, shell,
    ],
)
