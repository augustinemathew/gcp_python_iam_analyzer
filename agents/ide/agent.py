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
    generate_manifest,
    get_project_iam_policy,
    list_agent_engines,
    list_cloud_run_services,
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

**Scan local code:**
- `scan_file(file_path)` — scan one Python file
- `scan_directory(directory)` — scan all Python files in a directory
- `generate_manifest(paths)` — generate v2 manifest (YAML, per-identity permissions)
- `check_guardrails(paths, environment)` — check for security violations

**Explore project:**
- `list_agent_engines(project_id)` — list deployed agents
- `list_cloud_run_services(project_id)` — list Cloud Run services
- `get_project_iam_policy(project_id)` — get IAM policy
- `analyze_permissions(paths, project_id)` — diff code needs vs project IAM
- `troubleshoot_access(permission, project_id)` — diagnose PERMISSION_DENIED

## How to respond

- **Concise**: lead with the answer, add detail if asked
- **Actionable**: tell the developer what role to grant or what gcloud command to run
- **Code-aware**: reference file names, line numbers, method names
- **Identity-aware**: distinguish app SA permissions from delegated user OAuth permissions

## Developer workflow

When the user says "help me deploy" or "what do I need?":
1. Scan the code (`scan_directory`)
2. Show what permissions are needed (by identity: app vs user)
3. Check project IAM — what's missing? (`analyze_permissions`)
4. Check guardrails — any violations? (`check_guardrails`)
5. Generate manifest + suggest deploy commands
"""


root_agent = Agent(
    model="gemini-3.1-pro-preview",
    name="iam_ide_agent",
    instruction=_build_instruction(),
    tools=[
        scan_file, scan_directory, generate_manifest, check_guardrails,
        list_agent_engines, list_cloud_run_services,
        get_project_iam_policy, analyze_permissions, troubleshoot_access,
    ],
)
