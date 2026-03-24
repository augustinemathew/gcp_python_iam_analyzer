# IAM Policy Agent

Analyzes Python codebases and generates least-privilege GCP IAM policies using the ADK framework and iamspy.

## Install

```bash
pip install -r requirements.txt
# iamspy must also be installed (from the parent project):
pip install -e ..
```

## Run

```bash
adk web iam_agent/
```

Then open the ADK web UI and start a conversation.

## Example conversation

```
User: Analyze this codebase: /tmp/my-app.zip
Agent: [creates workspace, explores, scans, generates policy]
```

## Architecture

```
User
  |
  v
ADK Agent (gemini-2.0-flash)
  |
  +-- create_workspace(source, name)
  |     Extract zip to temp dir, return workspace ID
  |
  +-- shell(workspace, command)
        Run any command in workspace dir
        Used for: tree, grep, cat, sed, iamspy scan
        Output truncated to 8000 chars
```

Two tools, no CAIS integration yet. The agent drives the analysis loop by calling shell commands iteratively.
