# IAM Policy Agent

Analyzes Python codebases and generates least-privilege GCP IAM Allow Policies.

## Getting Started

```bash
# Clone and cd into the repo
git clone <repo-url> && cd gcp_ae

# Install the project and agent dependencies
pip install -e .
pip install -r iam_agent/requirements.txt

# Set your Gemini API key (https://aistudio.google.com/apikey)
export GEMINI_API_KEY="your-key-here"

# Launch the web UI (must run from repo root)
adk web .
```

Open http://localhost:8000 and select **iam_agent** from the app dropdown.

## Usage

Zip up a Python project and give it to the agent:

```
Analyze this codebase: /tmp/my-app.zip
The service account is my-sa@my-project.iam.gserviceaccount.com, project is my-project.
```

The agent will:

1. Extract the zip and run `iamspy scan --json .` to detect GCP SDK calls
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
  ├── create_workspace(source, name)
  │     Extracts a zip archive (local path or gs:// URI)
  │     into /tmp/iam_agent/<workspace-id>/
  │
  └── shell(workspace, command)
        Runs shell commands inside the workspace directory
        Used for: iamspy scan, grep, ls, sed
        60s timeout per command, output truncated to 8000 chars
```

The agent has two tools. `create_workspace` sets up an isolated directory
from the user's zip file. `shell` lets the agent run commands inside that
directory — primarily `iamspy scan --json .`, which uses tree-sitter to
parse Python source and resolve GCP SDK calls to IAM permissions from a
curated database. The agent then maps those permissions to IAM roles and
produces the policy.
