"""IAM IDE Agent — developer-facing assistant for local code.

On startup, auto-loads the manifest and workspace config so the agent
starts every conversation already knowing what the code needs.

Run with: adk web .
"""

from __future__ import annotations

import google.auth
from google.adk.agents import Agent

from agents.ide.context import build_context
from agents.ide.tools import (
    analyze_permissions,
    check_guardrails,
    create_service_account,
    generate_manifest,
    get_project_iam_policy,
    get_workspace_config,
    grant_iam_role,
    init_workspace_config,
    list_agent_engines,
    list_cloud_run_services,
    list_service_accounts,
    recommend_policy,
    scan_directory,
    scan_file,
    troubleshoot_access,
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

    # Auto-load context from manifest + workspace config
    try:
        context = build_context()
    except Exception:
        context = "## Code Analysis\nCould not auto-load context."

    return f"""\
You are an IAM permissions assistant in a developer's IDE. You help \
developers understand, manage, and deploy GCP IAM permissions for their code.

{project_line}\
## What you already know

The code has been automatically scanned. Here is what the project needs:

{context}

**You do not need to scan the code unless the developer asks you to re-scan \
or you suspect the manifest is outdated.** Use the context above to answer \
questions directly.

## Tools

**Workspace config:**
- `get_workspace_config()` — reload .iamspy/workspace.yaml
- `init_workspace_config(workspace_root, project_name, ...)` — create initial config

**Scan local code (only if needed):**
- `scan_file(file_path)` — scan one Python file
- `scan_directory(directory)` — re-scan all Python files
- `generate_manifest(paths)` — regenerate v2 manifest

**Policy & guardrails:**
- `recommend_policy(paths, environment)` — environment-specific IAM bindings
- `check_guardrails(paths, environment)` — check for security violations
- `analyze_permissions(paths, project_id)` — diff code needs vs project IAM

**Explore project:**
- `list_agent_engines(project_id)` — list deployed agents
- `list_cloud_run_services(project_id)` — list Cloud Run services
- `list_service_accounts(project_id)` — list service accounts
- `get_project_iam_policy(project_id)` — get IAM policy
- `troubleshoot_access(permission, project_id)` — diagnose PERMISSION_DENIED

**Manage identities:**
- `create_service_account(account_id, display_name, description)` — create a SA
- `grant_iam_role(role, member, project_id)` — grant a role to a principal

## How to respond

- **Concise**: lead with the answer, add detail if asked
- **Actionable**: tell the developer what role to grant or what gcloud command to run
- **Code-aware**: reference file names, line numbers, method names
- **Identity-aware**: distinguish app SA permissions from delegated user OAuth

## Context handling

- If the workspace config exists above, you already know the environments. \
Don't ask the developer to "set up" unless something is missing (like a null principal).
- If no workspace config was found, ask the developer about deployment context \
before recommending policies: deployment target, GCP project, identity type.
- If the manifest above shows the permissions, use them directly. \
Only re-scan if the developer says they changed code or asks for a fresh scan.

## Developer workflow

When the developer asks "help me deploy" or "what do I need?":
1. You already know the permissions (from context above)
2. Check workspace config — which environment? which principal?
3. If config is incomplete, ask clarifying questions
4. Recommend policy for the target environment
5. Check guardrails
6. Offer to create SA / grant roles / generate deploy commands
"""


root_agent = Agent(
    model="gemini-3.1-pro-preview",
    name="iam_ide_agent",
    instruction=_build_instruction(),
    tools=[
        get_workspace_config, init_workspace_config,
        scan_file, scan_directory, generate_manifest,
        recommend_policy, check_guardrails, analyze_permissions,
        list_agent_engines, list_cloud_run_services,
        list_service_accounts, create_service_account, grant_iam_role,
        get_project_iam_policy, troubleshoot_access,
    ],
)
