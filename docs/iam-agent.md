# IAM Policy Agent — Design & Implementation

## Overview

A conversational AI agent built on [Google ADK](https://google.github.io/adk/) that analyzes Python codebases and generates least-privilege GCP IAM policies. Wraps the `iamspy` scanner with an LLM-driven workflow that explores code, detects deployment context, and produces policy artifacts.

## Architecture

```
┌──────────────────────────────────────────────────┐
│               Google ADK Runtime                 │
│                                                  │
│  ┌──────────────────────────────────────────┐    │
│  │         iam_policy_agent                  │    │
│  │         (gemini-2.5-flash)                │    │
│  │                                           │    │
│  │  Instructions:                            │    │
│  │    1. Create workspace                    │    │
│  │    2. Explore project                     │    │
│  │    3. Run iamspy scan                     │    │
│  │    4. Detect deployment context           │    │
│  │    5. Identify principal                  │    │
│  │    6. Generate policy                     │    │
│  └────────────┬──────────────────────────────┘    │
│               │                                   │
│       ┌───────┴───────┐                           │
│       ▼               ▼                           │
│  ┌──────────┐   ┌──────────┐                      │
│  │ create_  │   │  shell   │                      │
│  │workspace │   │          │                      │
│  └────┬─────┘   └────┬─────┘                      │
│       │               │                           │
└───────┼───────────────┼───────────────────────────┘
        │               │
        ▼               ▼
   zip/gs:// →     iamspy scan --json .
   temp dir        tree, grep, sed, ...
```

## Tools

### `create_workspace(source, name)`

Extracts a codebase into a temporary directory for analysis.

| Parameter | Type | Description |
|-----------|------|-------------|
| `source` | `str` | Local path to a `.zip` file or a `gs://` URI |
| `name` | `str` | Human-readable workspace name |

- Downloads from GCS if `gs://` URI (via `gsutil cp`)
- Extracts zip contents to `/tmp/iam_agent/<name>-<uuid>/`
- Unwraps single top-level directory (common zip pattern)
- Returns workspace ID for use with `shell()`

### `shell(workspace, command)`

Runs a shell command inside the workspace directory.

| Parameter | Type | Description |
|-----------|------|-------------|
| `workspace` | `str` | Workspace ID from `create_workspace()` |
| `command` | `str` | Shell command to execute |

- 60-second timeout per command
- Output truncated to 8,000 characters (with notification)
- Returns `{stdout, stderr, exit_code, truncated}`

## Agent Workflow

The agent follows a structured workflow defined in its instruction prompt:

### 1. Create workspace
Ask for a zip file (local or gs://), call `create_workspace`.

### 2. Explore
Understand the project before scanning:
```bash
tree -I __pycache__ -I .git -I node_modules
grep -r "from google.cloud" --include="*.py" -l
sed -n '1,50p' path/to/key_file.py
```

### 3. Scan
Run `iamspy scan --json .` to detect all GCP SDK calls and resolve permissions. The JSON output includes file locations, method names, required and conditional permissions, and resolution confidence.

### 4. Detect deployment context
Look for deployment artifacts to determine the runtime environment:

| File | Context | Service Account |
|------|---------|-----------------|
| `app.yaml` | App Engine | App Engine default SA |
| `Dockerfile` | Cloud Run | Cloud Run default SA |
| `cloudbuild.yaml` | Cloud Build | Cloud Build SA |
| `main.py` + functions-framework | Cloud Functions | Cloud Functions SA |

### 5. Identify principal
Determine what service account needs the permissions. If not obvious from deployment config, ask the user.

### 6. Generate policy
Produce three output formats:

**IAM Policy JSON** — direct `gcloud projects set-iam-policy` input:
```json
{
  "bindings": [
    {
      "role": "roles/storage.objectViewer",
      "members": ["serviceAccount:my-sa@project.iam.gserviceaccount.com"]
    }
  ]
}
```

**Terraform HCL** — for infrastructure-as-code workflows:
```hcl
resource "google_project_iam_member" "storage_viewer" {
  project = var.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${var.service_account}"
}
```

**Human-readable summary** — table with permission, source file:line, and explanation.

## Policy Principles

- **Least privilege**: never grant more than what the code actually uses
- **Custom roles**: recommend when >3 permissions from same service with no predefined role match
- **Explain**: every permission cites the source file and SDK call that requires it
- **Conditionals**: flag CMEK, cross-project, and service account impersonation permissions separately
- **Surgical**: grep first on large repos, then read specific line ranges

## Source Files

```
iam_agent/
├── __init__.py
├── agent.py          # ADK Agent definition + instruction prompt
├── tools.py          # create_workspace() and shell() tool functions
└── requirements.txt  # google-adk dependency
```

## Running the Agent

```bash
cd iam_agent
pip install -r requirements.txt
adk run .
```

Or deploy to Agent Engine on Google Cloud for production use.

## Current Limitations

- No Cloud Asset Inventory (CAIS) access — cannot compare against existing deployed policies
- Focus on new policy generation from source code analysis
- Single-workspace model (no multi-repo analysis in one session)

## Future Work

- **CAIS integration** — compare generated policy against what's deployed, surface over-provisioned roles
- **PAB / Deny policies** — generate Principal Access Boundary and IAM Deny policies for organization-level guardrails
- **Pulumi output** — alongside Terraform HCL
- **Interactive refinement** — security admin refines policies conversationally ("make this more restrictive", "add a condition for VPC-SC")
- **Manifest input** — accept `iam-manifest.yaml` directly instead of requiring source code
- **Multi-environment** — generate different policies for dev/staging/prod
