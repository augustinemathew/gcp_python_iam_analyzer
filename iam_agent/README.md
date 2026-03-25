# IAM Policy Agent

Analyzes Python codebases and generates least-privilege GCP IAM policies.
Built with [Google ADK](https://google.github.io/adk-docs/) and
[iamspy](../README.md).

## Prerequisites

- Python 3.12+
- A Gemini API key — get one at https://aistudio.google.com/apikey

## Setup

```bash
# From the repo root (gcp_ae/)

# 1. Install the parent project (provides the iamspy CLI)
pip install -e .

# 2. Install agent dependencies
pip install -r iam_agent/requirements.txt

# 3. Set your Gemini API key
export GEMINI_API_KEY="your-key-here"
```

Verify the CLI is available:

```bash
iamspy scan --help
adk --version
```

## Run

The web UI is the recommended way to run the agent. You must run `adk web`
from the **repo root**, not from inside `iam_agent/`:

```bash
# From the repo root (gcp_ae/)
adk web .
```

Then open http://localhost:8000 in your browser. Select **iam_agent** from
the app dropdown in the top-left corner.

### Preparing a test project

The agent expects a **zip file** containing Python source code. To create one
from an existing project:

```bash
cd /path/to/my-python-project
zip -r /tmp/my-app.zip . -x '*.git*' '__pycache__/*' 'node_modules/*'
```

### Chatting with the agent

In the web UI, send a message like:

```
Analyze this codebase: /tmp/my-app.zip
```

The agent will:

1. Call `create_workspace` to extract the zip into a temp directory
2. Run shell commands (`ls`, `grep`) to explore the project structure
3. Run `iamspy scan --json .` to detect GCP SDK calls and map them to IAM
   permissions
4. Ask you which service account or principal will run the code
5. Generate an IAM policy in three formats:
   - IAM Policy JSON (for `gcloud projects set-iam-policy`)
   - Terraform HCL
   - Human-readable summary table

The agent also supports `gs://` URIs if `gsutil` is configured on your
machine.

### CLI mode

`adk run` works for quick tests but has limitations with piped stdin — the
tool execution loop may not complete. Prefer the web UI for real usage:

```bash
adk run iam_agent
```

## API key notes

ADK requires the env var `GOOGLE_API_KEY`. The agent's `__init__.py`
automatically maps `GEMINI_API_KEY` → `GOOGLE_API_KEY` so you can use
either name. If both are set, `GOOGLE_API_KEY` takes precedence.

## Architecture

```
User (web UI)
  │
  ▼
ADK Agent (gemini-2.5-flash)
  │
  ├── create_workspace(source, name)
  │     Extract zip (local or gs://) to /tmp/iam_agent/<id>/
  │
  └── shell(workspace, command)
        Run commands in workspace dir (ls, grep, iamspy scan, etc.)
        60s timeout per command, output truncated to 8000 chars
```

Two tools. The agent drives the analysis loop by calling shell commands
iteratively until it has enough context to generate the policy.
