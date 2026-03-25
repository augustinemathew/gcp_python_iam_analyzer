# IAM Policy Agent

Analyzes Python codebases and generates least-privilege GCP IAM Allow Policies.
Can pull agent source code directly from Vertex AI Agent Engine (Reasoning
Engine) deployments and generate policies with the correct principal format
— including AGENT_IDENTITY.

## Prerequisites

- **Python 3.12+**
- **gcloud CLI** — [install](https://cloud.google.com/sdk/docs/install)
- **Gemini API key** — get one at https://aistudio.google.com/apikey

## Getting Started

All commands run from the **repo root**.

```bash
# Install the project and agent dependencies
pip install -e .
pip install -r iam_agent/requirements.txt

# Authenticate with GCP (needed for Agent Engine and GCS access)
gcloud auth login
gcloud auth application-default login

# Set your Gemini API key
export GEMINI_API_KEY="your-key-here"

# Launch the web UI
adk web .
```

Open http://localhost:8000 and select **iam_agent** from the app dropdown.

## Usage

### Analyze an Agent Engine deployment

The agent can list deployed Reasoning Engine instances, download their
source code from GCS, scan it for IAM permissions, and generate a
policy — all in one conversation:

```
List the agent engines in my project and generate an IAM policy for
the Cost Optimizer agent. It uses AGENT_IDENTITY.
```

The agent will:

1. Call `list_agent_engines` to find deployed agents and their GCS artifacts
2. Download the `dependencies.tar.gz` (the agent's source code) from GCS
3. Run `iamspy scan --json .` to detect all GCP SDK calls
4. Generate an IAM Allow Policy JSON with the correct principal format:
   - `serviceAccount:...` for default service account identity
   - `principal://agents.global.proj-...` for AGENT_IDENTITY
5. Produce a permission reference table linking each permission to a
   source file and line number

### Analyze a local codebase

A sample project zip is included for quick testing:

```
Analyze this codebase: iam_agent/testdata/sample_project.zip
The service account is my-sa@my-project.iam.gserviceaccount.com
```

To analyze your own code:

```bash
cd /path/to/my-python-project
zip -r /tmp/my-app.zip . -x '*.git*' '__pycache__/*'
```

Then in the web UI:

```
Analyze this codebase: /tmp/my-app.zip
```

## Architecture

```
User (ADK Web UI)
  │
  ▼
ADK Agent (gemini-2.5-flash)
  │
  ├── list_agent_engines(project_id)
  │     Lists deployed Reasoning Engine instances via Vertex AI REST API
  │     Returns: id, display_name, dependencies_uri, effective_identity,
  │              project_number, location
  │
  ├── create_workspace(source, name)
  │     Extracts zip or tar.gz (local path or gs:// URI)
  │     into /tmp/iam_agent/<workspace-id>/
  │
  ├── list_gcs(uri) / download_gcs(uri, destination)
  │     Browse and download files from Google Cloud Storage
  │     Uses google-cloud-storage Python SDK with ADC
  │
  └── shell(workspace, command)
        Runs commands in the workspace (iamspy scan, grep, ls)
        60s timeout, output truncated to 8000 chars
```

The agent auto-detects the default GCP project from Application Default
Credentials and uses it for all GCP calls unless overridden by the user.
