# IAM Policy Agent

Analyzes Python codebases and generates least-privilege GCP IAM Allow Policies.
Can pull agent source code directly from Vertex AI Agent Engine deployments.

## Prerequisites

- **Python 3.12+**
- **gcloud CLI** — [install](https://cloud.google.com/sdk/docs/install), then:
  ```bash
  gcloud auth login
  gcloud auth application-default login
  ```
- **Gemini API key** — get one at https://aistudio.google.com/apikey

## Getting Started

```bash
# Clone and cd into the repo
git clone git@github.com:augustinemathew/gcp_python_iam_analyzer.git && cd gcp_python_iam_analyzer

# Install the project and agent dependencies
pip install -e .
pip install -r iam_agent/requirements.txt

# Set your Gemini API key
export GEMINI_API_KEY="your-key-here"

# Launch the web UI (must run from repo root)
adk web .
```

Open http://localhost:8000 and select **iam_agent** from the app dropdown.

## Usage

### Analyze an Agent Engine deployment

The agent can list deployed agents in your GCP project, download their
source code from GCS, and generate a policy — all in one conversation:

```
List the agent engines in project my-project and generate an IAM policy
for the Cost Optimizer agent.
```

The agent uses Application Default Credentials (from `gcloud auth
application-default login`) to access GCS and the Agent Engine API.

### Analyze a local codebase

A sample project zip is included at `iam_agent/testdata/sample_project.zip`:

```
Analyze this codebase: iam_agent/testdata/sample_project.zip
The service account is my-sa@my-project.iam.gserviceaccount.com, project is my-project.
```

To analyze your own code, zip it up and provide the path:

```bash
cd /path/to/my-python-project
zip -r /tmp/my-app.zip . -x '*.git*' '__pycache__/*'
```

The agent will:

1. Extract the archive and run `iamspy scan --json .` to detect GCP SDK calls
2. Discover the deployment context from the code (or ask you)
3. Output an **IAM Allow Policy JSON** and a **permission reference table**
   linking each permission to the source file and line number

## Architecture

```
User (ADK Web UI)
  │
  ▼
ADK Agent (gemini-2.5-flash)
  │
  ├── list_agent_engines(project_id)
  │     Lists deployed Agent Engine instances via Vertex AI REST API
  │     Returns: id, display_name, dependencies_uri, service_account
  │
  ├── create_workspace(source, name)
  │     Extracts zip or tar.gz (local path or gs:// URI)
  │     into /tmp/iam_agent/<workspace-id>/
  │
  ├── list_gcs(uri) / download_gcs(uri, destination)
  │     Browse and download files from Google Cloud Storage
  │
  └── shell(workspace, command)
        Runs commands in the workspace (iamspy scan, grep, ls)
        60s timeout, output truncated to 8000 chars
```

The agent uses Application Default Credentials for all GCP access (GCS,
Agent Engine API). When running locally, credentials come from
`gcloud auth application-default login`. When deployed to Agent Engine,
the agent's service account provides credentials automatically.
