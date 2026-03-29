# IAM IDE Agent

Interactive IAM assistant for developers working in IDE environments.
Same tools as the batch IAM agent, different prompt — tuned for
concise, conversational interactions.

## Model

`gemini-3.1-pro-preview`

## How it differs from the batch agent

| Aspect | Batch (iam_agent) | IDE (iam_ide_agent) |
|---|---|---|
| Response length | Full reports with tables | Short answers, code blocks |
| Primary tool | `scan_workspace` | `scan_file`, `scan_directory` |
| Interaction | Single prompt → full policy | Multi-turn conversation |
| Use case | CI/CD, policy generation | Developer coding, debugging |

## Tools

### Local scanning (most common in IDE)

| Tool | When to use |
|---|---|
| `scan_file(path)` | User asks about a specific file they're editing |
| `scan_directory(directory)` | User says "scan this project" or "scan this folder" |

### Remote scanning

| Tool | When to use |
|---|---|
| `create_workspace(source, name)` | Download + extract from GCS / Agent Engine |
| `scan_workspace(workspace_id)` | Scan a remote workspace |

### GCP policy tools

| Tool | When to use |
|---|---|
| `get_project_iam_policy(project)` | "What roles are granted?" |
| `get_effective_iam_policy(project, member)` | "Can this SA do X?" |
| `list_deny_policies(project)` | "Are there deny policies blocking this?" |

## Interaction patterns

### Single file scan

```
User: What permissions does tools/billing.py need?
Agent: → scan_file("tools/billing.py")
       billing.py needs 3 permissions:
       - bigquery.jobs.create (line 65, Client.query)
       - bigquery.tables.list (line 99, Client.list_tables)
       ...
```

### Local project scan

```
User: Scan the whole gcp_cost_optimizer_agent directory
Agent: → scan_directory("gcp_cost_optimizer_agent")
       Analyzed 11 files, 4 with GCP imports, 6 SDK methods, 9 permissions...
```

### Role suggestion

```
User: What role covers storage.buckets.get?
Agent: roles/storage.viewer — grants storage.buckets.get plus
       storage.buckets.list. gcloud command:
       gcloud projects add-iam-policy-binding PROJECT \
         --member="serviceAccount:SA" --role="roles/storage.viewer"
```

### Permission error debugging

```
User: Getting 403 PERMISSION_DENIED on container.clusters.list
Agent: → get_effective_iam_policy(project, member)
       The SA has roles/compute.viewer but not roles/container.viewer.
       Run: gcloud projects add-iam-policy-binding ...
```

### Policy audit

```
User: Does the Cost Optimizer have more permissions than it needs?
Agent: → scan_directory + get_project_iam_policy
       Excess: roles/aiplatform.viewer is granted but not used by code.
       Missing: roles/container.viewer needed for list_gke_clusters.
```
