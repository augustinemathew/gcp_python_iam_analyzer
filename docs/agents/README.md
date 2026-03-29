# Agents

Three ADK-based agents that work with the IAM Python static analyzer.

| Agent | Purpose | Prompt style |
|---|---|---|
| [IAM Policy Agent](iam-agent.md) | Batch policy generation for projects and Agent Engine deployments | Full analysis, report output |
| [IAM IDE Agent](iam-ide-agent.md) | Interactive assistant for developers in IDE environments | Concise, conversational |
| [Cost Optimizer Agent](cost-optimizer-agent.md) | GCP resource inventory and cost analysis | Discovery + recommendations |

All three agents share the same tool library (`iam_agent/tools.py`). The
IAM agents add the static analyzer; the cost optimizer has its own GCP
inventory tools.

## Architecture

```
                    ADK Web UI / VS Code / Agent Engine
                              │
                    ┌─────────┼─────────┐
                    │         │         │
               iam_agent  iam_ide   cost_optimizer
               (batch)    (interactive) (inventory)
                    │         │         │
                    └────┬────┘         │
                         │              │
                  iam_agent/tools.py    gcp_cost_optimizer_agent/tools/
                  ┌──────┴──────┐      ├── assets.py
                  │             │      ├── compute.py
             Static Analyzer   GCP    ├── containers.py
             (tree-sitter +    Tools  ├── billing.py
              permission DB)    │     └── agent_engines.py
                               │
                    ┌──────────┴──────────┐
                    │                     │
              IAM Policy Tools      Agent Engine Tools
              - get_project_iam     - list_agent_engines
              - get_effective_iam   - create_workspace
              - list_deny_policies  - list/download_gcs
```

## Shared tool library

All scanning and GCP tools live in `iam_agent/tools.py`:

### Static analyzer tools

| Tool | Use case |
|---|---|
| `scan_file(path)` | Single file — IDE inline scanning |
| `scan_directory(directory)` | Local project — full directory scan |
| `scan_workspace(workspace_id)` | Remote code — Agent Engine / GCS archives |

### GCP tools

| Tool | API | Use case |
|---|---|---|
| `list_agent_engines(project)` | Vertex AI REST | Discover deployed agents |
| `get_project_iam_policy(project)` | Resource Manager | Raw allow policy |
| `get_effective_iam_policy(project, member)` | Cloud Asset | Effective permissions after inheritance + deny |
| `list_deny_policies(project)` | IAM v2 | Check deny policies |
| `list_gcs(uri)` / `download_gcs(uri, dest)` | Cloud Storage | Browse/download GCS objects |
| `create_workspace(source, name)` | Cloud Storage | Download + extract archives into scannable workspace |
| `shell(workspace, command)` | Local | Run commands in a workspace |
