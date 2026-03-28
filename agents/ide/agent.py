"""IAM IDE Agent — developer-facing assistant for local code.

Scans the developer's local files, checks permissions against their
GCP project, helps with deploy. No remote workspace management.

Run with: adk web .
"""

from __future__ import annotations

import google.auth
from google.adk.agents import Agent

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
        f"Your default GCP project is **{project}**. Use this for GCP tool "
        "calls unless the user specifies a different project.\n\n"
        if project
        else ""
    )

    return f"""\
You are an IAM permissions assistant in a developer's IDE. You help \
developers understand, manage, and deploy GCP IAM permissions for their code.

{project_line}\
## Tools

**Workspace config:**
- `get_workspace_config()` — load .iamspy/workspace.yaml (environments, identities, deploy targets)
- `init_workspace_config(workspace_root, project_name, ...)` — create initial config

**Scan local code:**
- `scan_file(file_path)` — scan one Python file
- `scan_directory(directory)` — scan all Python files in a directory
- `generate_manifest(paths)` — generate v2 manifest (YAML, per-identity permissions)

**Policy & guardrails:**
- `recommend_policy(paths, environment)` — join workspace config + scan → environment-specific IAM bindings
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
- **Identity-aware**: distinguish app SA permissions from delegated user OAuth permissions

## Before analyzing: gather context

**Always start by loading the workspace config** (`get_workspace_config`). If it exists, \
you know the environments, identities, and deploy targets.

If no config exists, **ask the developer** before scanning:
1. What is this app? (Agent Engine agent? Cloud Run service? Cloud Run job?)
2. What GCP project will it deploy to?
3. What identity will it use? (Service account? AGENT_IDENTITY? Delegated OAuth?)
4. Is this for dev or prod?

Then help create the config (`init_workspace_config`).

**If the config exists but is incomplete** (e.g., principal is null), ask about the \
missing pieces. Don't guess — principals and projects matter for policy generation.

## Developer workflow

When the user says "analyze my code", "help me deploy", or "what do I need?":
1. Load workspace config (`get_workspace_config`) — understand the environment
2. If config is incomplete, ask clarifying questions
3. Scan the code (`scan_directory`) — find permissions needed
4. Recommend policy (`recommend_policy`) for the target environment
5. Check guardrails (`check_guardrails`) — any security violations?
6. Generate manifest + suggest deploy commands
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
