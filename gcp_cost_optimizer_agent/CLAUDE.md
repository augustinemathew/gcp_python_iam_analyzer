# CLAUDE.md

GCP Cost Optimizer Agent — an ADK agent deployed to Vertex AI Agent Engine
(Reasoning Engine) that answers natural language questions about GCP resource
inventory and billing costs.

## Project layout

```
gcp_cost_optimizer_agent/
├── __init__.py           # GEMINI_API_KEY mapping + ADK discovery import
├── agent.py              # root_agent (ADK Agent definition)
├── tools/
│   ├── assets.py         # list_resources — Cloud Asset Inventory
│   ├── compute.py        # list_running_vms — Compute Engine
│   ├── containers.py     # list_gke_clusters, list_cloud_run_services
│   ├── agent_engines.py  # list_agent_engines — Vertex AI REST API
│   └── billing.py        # query_billing — BigQuery billing export
├── deploy.py             # deploy to Agent Engine + grant IAM
├── tests/
│   └── test_tools.py     # unit tests (mocked GCP clients)
├── requirements.txt
└── CLAUDE.md
```

## Environment

- **Project:** `agentengine-478902` (project number: 16744841236)
- **Location:** `us-central1`
- **Staging bucket:** `gs://augtestbucket`
- **Model:** `gemini-2.5-flash`
- **Framework:** ADK (`google.adk.agents.Agent`)
- **Identity:** AGENT_IDENTITY (per-agent identity via Workload Identity Federation)

## Commands

```bash
# Run locally via ADK web UI (from repo root)
adk web .

# Deploy to Agent Engine
python -m gcp_cost_optimizer_agent.deploy

# Run tests
python -m pytest gcp_cost_optimizer_agent/tests/ -v
```

## Adding a new tool

1. Create `tools/<name>.py` with a single public function
2. Good docstring — ADK uses it as the tool description for the LLM
3. Import and add to the `tools=[...]` list in `agent.py`
4. Add the pip package to **both** `requirements.txt` and `REQUIREMENTS` in `deploy.py`
5. Add the required IAM role to `AGENT_IAM_ROLES` in `deploy.py`
6. Re-deploy with `python -m gcp_cost_optimizer_agent.deploy`

**Critical: keep `requirements.txt` and `deploy.py:REQUIREMENTS` in sync.**
`requirements.txt` is for local install. `REQUIREMENTS` in deploy.py is what
gets installed on Agent Engine. If they diverge, the agent will fail with
`ModuleNotFoundError` on one environment but not the other.

## IAM roles

The agent identity needs these roles on the target project:

| Role | Used by |
|---|---|
| `roles/aiplatform.user` | Call Gemini models |
| `roles/cloudasset.viewer` | `list_resources` |
| `roles/compute.viewer` | `list_running_vms` |
| `roles/container.viewer` | `list_gke_clusters` |
| `roles/run.viewer` | `list_cloud_run_services` |
| `roles/aiplatform.viewer` | `list_agent_engines` |
| `roles/bigquery.jobUser` | `query_billing` |
| `roles/bigquery.dataViewer` | `query_billing` |

`deploy.py` grants these automatically using the `principal://agents.global.proj-PROJECT_NUMBER...` format.

## AGENT_IDENTITY principal format

```
principal://agents.global.proj-PROJECT_NUMBER.system.id.goog/resources/aiplatform/projects/PROJECT_NUMBER/locations/LOCATION/reasoningEngines/AGENT_ID
```

Note: it's `proj-` not `project-`.
