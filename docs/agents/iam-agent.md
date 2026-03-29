# IAM Policy Agent

Batch policy generator — analyzes Python codebases and produces
least-privilege GCP IAM Allow Policies.

## Model

`gemini-3.1-pro-preview`

## Workflow

```
list_agent_engines → create_workspace → scan_workspace → audit policy → generate output
```

### Step 1: Get the code

The agent supports multiple input methods:

- **Agent Engine deployment** (most common): list engines → download
  `dependencies.tar.gz` from GCS → extract into workspace.
- **Local zip/tar.gz**: extract directly.
- **GCS URI**: download and extract.

### Step 2: Run the IAM Python static analyzer

`scan_workspace` parses every Python file with tree-sitter, detects
GCP SDK imports, and resolves method calls against a curated database
of 8,000+ permission mappings across 129 GCP services.

Returns structured findings with:
- Stats: files scanned, GCP imports found, methods resolved, services detected
- Findings: file, line, method, required permissions, conditional permissions

### Step 3: Discover environment

Infers the deployment context from code patterns:

| Pattern | Environment |
|---|---|
| Dockerfile / app.yaml | Cloud Run / App Engine |
| cloudbuild.yaml | Cloud Build |
| functions-framework | Cloud Functions |
| AG2/ADK imports | Agent Engine |

If unclear, asks the user.

### Step 3b: Audit existing policies

Three tools for auditing the project's IAM posture:

| Tool | What it shows |
|---|---|
| `get_project_iam_policy` | Raw allow bindings on the project |
| `get_effective_iam_policy` | Effective permissions after inheritance + deny |
| `list_deny_policies` | Deny policies that may block allow bindings |

Flags excess permissions, missing permissions, and overlapping roles.

### Step 4: Generate output

Two sections:

1. **IAM Allow Policy JSON** — role bindings with the correct principal format
2. **Permission Reference Table** — every permission linked to source file,
   line number, SDK call, and whether it's required or conditional

## Principal types

The agent understands two identity types for Agent Engine:

| Type | Format |
|---|---|
| Default SA | `serviceAccount:service-PROJECT_NUMBER@gcp-sa-aiplatform-re.iam.gserviceaccount.com` |
| AGENT_IDENTITY | `principal://agents.global.proj-PROJECT_NUMBER.system.id.goog/resources/aiplatform/projects/PROJECT_NUMBER/locations/LOCATION/reasoningEngines/AGENT_ID` |

AGENT_IDENTITY agents also need `roles/aiplatform.user` for Gemini access.

## Reasoning traces

The agent explains its reasoning at each step:
- What it's about to do and why
- What it learned from each tool call
- Why it chose specific roles over alternatives
- Assumptions and ambiguities it flagged

## Example

See [EXAMPLE.md](../../iam_agent/EXAMPLE.md) for a full conversation
transcript showing the agent generating an IAM policy for the Cost
Optimizer Agent Engine deployment.
