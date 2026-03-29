# Cost Optimizer Agent

GCP resource inventory and cost analysis agent. Discovers all resources
in a project, drills into specific resource types, and queries billing
data to surface cost optimization opportunities.

## Model

`gemini-2.5-flash`

## Framework

ADK (`google.adk.agents.Agent`). Ported from AG2 to fix AGENT_IDENTITY
authentication with Gemini (AG2 uses Google AI Studio endpoint which
rejects workload identity federation tokens; ADK uses Vertex AI endpoint).

## Deployment

Deploys to Vertex AI Agent Engine (Reasoning Engine) with AGENT_IDENTITY.
See `gcp_cost_optimizer_agent/deploy.py`.

```bash
# Configure project details
cp gcp_cost_optimizer_agent/.env.example gcp_cost_optimizer_agent/.env
# Edit .env with your project ID, number, and staging bucket

# Deploy
python -m gcp_cost_optimizer_agent.deploy
```

## Tools

| Tool | GCP API | What it does |
|---|---|---|
| `list_resources` | Cloud Asset Inventory | All resources grouped by type with counts |
| `list_running_vms` | Compute Engine | Running VMs with machine types, IPs, zones |
| `list_gke_clusters` | GKE | Clusters with node counts and machine types |
| `list_cloud_run_services` | Cloud Run | Services in a region with URIs |
| `list_agent_engines` | Vertex AI REST | Deployed Reasoning Engine instances |
| `query_billing` | BigQuery | Cost by service and SKU from billing export |

`query_billing` auto-discovers the billing export table in the
`billing_export` dataset. If billing export isn't configured, the agent
works with inventory data only.

## Workflow

```
list_resources → drill into resource types → query_billing → present by cost impact
```

1. List all resources via Cloud Asset Inventory
2. Identify cost-heavy types (VMs, GKE, Reasoning Engines, databases)
3. Drill into specific types with specialized tools
4. Query billing if available
5. Present findings ordered by cost priority (High/Medium/Low)

## IAM roles

The agent identity needs:

| Role | Tool |
|---|---|
| `roles/aiplatform.user` | Call Gemini models |
| `roles/cloudasset.viewer` | `list_resources` |
| `roles/compute.viewer` | `list_running_vms` |
| `roles/container.viewer` | `list_gke_clusters` |
| `roles/run.viewer` | `list_cloud_run_services` |
| `roles/aiplatform.viewer` | `list_agent_engines` |
| `roles/bigquery.jobUser` | `query_billing` |
| `roles/bigquery.dataViewer` | `query_billing` |

`deploy.py` grants these automatically using the AGENT_IDENTITY
principal format (`principal://agents.global.proj-...`).

## AGENT_IDENTITY notes

The trust domain uses `proj-` (not `project-`):

```
principal://agents.global.proj-PROJECT_NUMBER.system.id.goog/resources/aiplatform/projects/PROJECT_NUMBER/locations/LOCATION/reasoningEngines/AGENT_ID
```

AGENT_IDENTITY works with all frameworks (ADK, AG2, LangChain, etc.) —
the `identity_type` is set on `agent_engines.create()`, not on the agent
object. However, the agent framework must use the Vertex AI backend for
Gemini calls (not Google AI Studio). ADK does this by default; AG2 does not.
