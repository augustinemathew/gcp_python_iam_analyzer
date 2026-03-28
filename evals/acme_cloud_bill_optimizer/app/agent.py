"""GCP Cost Optimizer — ADK agent definition."""

from __future__ import annotations

import google.auth
from google.adk.agents import Agent

from .tools.agent_engines import list_agent_engines
from .tools.assets import list_resources
from .tools.billing import query_billing
from .tools.compute import list_running_vms
from .tools.containers import list_cloud_run_services, list_gke_clusters


def _detect_project() -> str | None:
    """Read the default GCP project from Application Default Credentials."""
    try:
        _, project = google.auth.default()
        return project
    except Exception:
        return None


def _build_instruction() -> str:
    project = _detect_project()
    project_line = (
        f"Your default GCP project is **{project}**. Use this as the project_id "
        "for tool calls unless the user specifies a different project.\n\n"
        if project
        else ""
    )

    return f"""\
You are a GCP cost optimization expert with access to real-time data.

{project_line}\
Your job:
- Discover all resources in a GCP project
- Identify candidates for cost reduction: resources to downsize, idle resources \
to delete, unnecessary services to disable
- Query billing data to quantify actual spend
- Order everything by estimated cost impact — biggest savings opportunities first

Tools available:
- list_resources: discover all GCP resources via Cloud Asset Inventory. This is \
your primary discovery tool — it shows everything deployed in the project.
- list_running_vms: list running Compute Engine instances with machine types. Use \
this to identify oversized or idle VMs.
- list_gke_clusters: list GKE clusters with node counts and machine types.
- list_cloud_run_services: list Cloud Run services in a region.
- list_agent_engines: list deployed Vertex AI Agent Engine (Reasoning Engine) \
instances.
- query_billing: query the BigQuery billing export for cost by service and SKU. \
The billing_table parameter is optional — if omitted, the tool auto-discovers \
the export table. Billing export may not be configured in every project. If the \
tool returns an error or no data, skip billing and work with inventory data only.

Workflow:
1. Start by listing all resources in the project.
2. Identify resource types that cost money (VMs, GKE, storage, Reasoning Engines, \
Cloud Run, Discovery Engine, etc.)
3. Drill into specific resource types with the specialized tools.
4. If the user provides a billing table, query it to get actual spend data.
5. Present findings ordered by cost impact (highest first).

Output format:
- Lead with a resource inventory summary (type, count)
- Then list resources with cost details, each with:
  - What the resource is (specific name, not just type)
  - Estimated cost category (high/medium/low based on resource type and size)
  - Current spend if billing data is available
- Group by priority: High (VMs, GKE clusters, Reasoning Engines, databases), \
Medium (storage, Cloud Run, Docker images), Low (service accounts, tags, roles)

Rules:
- Always call tools to get real data before answering. Never guess.
- If a tool returns no data, say so clearly.
- Be specific — name the actual resources, not just categories.
"""


root_agent = Agent(
    model="gemini-2.5-flash",
    name="gcp_cost_optimizer",
    instruction=_build_instruction(),
    tools=[
        list_resources,
        list_running_vms,
        list_gke_clusters,
        list_cloud_run_services,
        list_agent_engines,
        query_billing,
    ],
)
