# GCP Cost Optimizer Agent

Discovers GCP resources and billing data to surface cost optimization
opportunities using natural language. Built with
[Google ADK](https://google.github.io/adk-docs/).

## Prerequisites

- **Python 3.12+**
- **gcloud CLI** — [install](https://cloud.google.com/sdk/docs/install)
- **Gemini API key** — get one at https://aistudio.google.com/apikey

## 1. Set up environment

All commands run from the **repo root**.

```bash
# Install dependencies
pip install -r gcp_cost_optimizer_agent/requirements.txt

# Set your Gemini API key
export GEMINI_API_KEY="your-key-here"

# Authenticate with GCP
gcloud auth login
gcloud auth application-default login

# Enable required APIs
gcloud services enable \
  cloudasset.googleapis.com \
  compute.googleapis.com \
  container.googleapis.com \
  run.googleapis.com \
  bigquery.googleapis.com \
  aiplatform.googleapis.com
```

## 2. Run locally

```bash
adk web .
```

Open http://localhost:8000 and select **gcp_cost_optimizer_agent** from
the app dropdown.

## 3. Deploy to Agent Engine

Create a `.env` file with your project details. The `.env` file lives
inside `gcp_cost_optimizer_agent/` and is gitignored so your values
stay local:

```bash
cp gcp_cost_optimizer_agent/.env.example gcp_cost_optimizer_agent/.env
```

Edit `gcp_cost_optimizer_agent/.env`:

```
PROJECT=my-project
PROJECT_NUMBER=123456789
LOCATION=us-central1
STAGING_BUCKET=gs://my-staging-bucket
```

Look up your project number:

```bash
gcloud projects describe my-project --format='value(projectNumber)'
```

Deploy (from repo root):

```bash
python -m gcp_cost_optimizer_agent.deploy
```

This deploys the agent with AGENT_IDENTITY and grants the required IAM
roles automatically.

## Tools

| Tool | GCP API | What it does |
|---|---|---|
| `list_resources` | Cloud Asset Inventory | Lists all resources grouped by type |
| `list_running_vms` | Compute Engine | Running VMs with machine types and IPs |
| `list_gke_clusters` | GKE | Clusters with node counts and machine types |
| `list_cloud_run_services` | Cloud Run | Services in a region |
| `list_agent_engines` | Vertex AI | Deployed Reasoning Engine instances |
| `query_billing` | BigQuery | Cost by service and SKU from billing export |

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

## Example queries

```
What resources do I have?
List all running VMs.
Show me my GKE clusters.
What Cloud Run services are deployed?
How many Reasoning Engines are running?
```
