# GCP Cost Optimizer Agent

Discovers GCP resources and billing data to surface cost optimization
opportunities using natural language.

## Prerequisites

- **Python 3.12+**
- **gcloud CLI** — [install](https://cloud.google.com/sdk/docs/install)

## 1. Set up environment

```bash
cd gcp_cost_optimizer_agent

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Authenticate
gcloud auth login
gcloud auth application-default login

# Enable required APIs on your project
gcloud services enable \
  cloudasset.googleapis.com \
  compute.googleapis.com \
  container.googleapis.com \
  run.googleapis.com \
  bigquery.googleapis.com \
  aiplatform.googleapis.com
```

## 2. Run locally

Run the agent locally using your ADC credentials — no deployment needed.

```bash
# Interactive REPL
python run_local.py

# Single query
python run_local.py "What resources do I have in agentengine-478902?"
```

## 3. Deploy to Agent Engine

Deploys the agent to Vertex AI Agent Engine with a per-agent identity
(AGENT_IDENTITY). After deployment, automatically grants the agent the
IAM roles it needs.

Before deploying, update the constants in `deploy.py` to match your
environment:

```python
PROJECT = "agentengine-478902"
PROJECT_NUMBER = "16744841236"
LOCATION = "us-central1"
STAGING_BUCKET = "gs://augtestbucket"
```

Then deploy:

```bash
python deploy.py
```

This takes ~2 minutes. It will:
1. Build the AG2Agent with all tools
2. Upload the agent code to GCS (`STAGING_BUCKET/cost_optimizer_agent/`)
3. Create a Reasoning Engine instance with AGENT_IDENTITY
4. Grant the agent identity the required IAM roles

The output prints a resource name like:
```
projects/16744841236/locations/us-central1/reasoningEngines/XXXXXXXXX
```

## 4. Query the deployed agent

```bash
# Interactive REPL
python query.py

# Single query
python query.py "What resources do I have?"
```

Update `DEFAULT_RESOURCE` in `query.py` with the resource name from
deployment.

## Tools

| Tool | GCP API | What it does |
|---|---|---|
| `list_resources` | Cloud Asset Inventory | Lists all resources grouped by type |
| `list_running_vms` | Compute Engine | Running VMs with machine types and IPs |
| `list_gke_clusters` | GKE | Clusters with node counts and machine types |
| `list_cloud_run_services` | Cloud Run | Services in a region |
| `list_agent_engines` | Vertex AI | Deployed Reasoning Engine instances |
| `query_billing` | BigQuery | Cost by service and SKU from billing export |

`query_billing` auto-discovers the billing export table if one exists.
If billing export is not configured, the agent works with inventory data
only.

## IAM roles

The agent identity needs these roles on the target project:

| Role | Used by |
|---|---|
| `roles/cloudasset.viewer` | `list_resources` |
| `roles/compute.viewer` | `list_running_vms` |
| `roles/container.viewer` | `list_gke_clusters` |
| `roles/run.viewer` | `list_cloud_run_services` |
| `roles/aiplatform.viewer` | `list_agent_engines` |
| `roles/bigquery.jobUser` | `query_billing` |
| `roles/bigquery.dataViewer` | `query_billing` |

`deploy.py` grants these automatically after deployment. When running
locally, your ADC identity needs these permissions instead.

## Example queries

```
What resources do I have in project agentengine-478902?
List all running VMs.
Show me my GKE clusters.
What Cloud Run services are deployed?
How many Reasoning Engines are running?
```
