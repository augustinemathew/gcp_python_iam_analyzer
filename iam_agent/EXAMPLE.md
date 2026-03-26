# Example: Generating an IAM Policy for an Agent Engine Deployment

This transcript shows the IAM Policy Agent analyzing a deployed GCP Cost
Optimizer agent and generating a least-privilege IAM Allow Policy with
AGENT_IDENTITY.

---

> **You**
>
> Create an IAM policy for the Cost Optimizer agent deployed in my project.
> It uses AGENT_IDENTITY.

**IAM Policy Agent**

I'll start by listing the deployed Agent Engine instances in your default
project (`agentengine-478902`) to find the "Cost Optimizer" agent. This
will give me the URI of its source code and its agent ID so I can format
the `AGENT_IDENTITY` principal correctly.

*Calling `list_agent_engines(project_id="agentengine-478902")`...*

---

**IAM Policy Agent**

I found several deployments for the "GCP Cost Optimizer" agent. There are
two instances that use `AGENT_IDENTITY` (Agent IDs: `4803828424160313344`
and `8267659487561646080`). Both use the same source code archive located at
`gs://augtestbucket/cost_optimizer_agent/dependencies.tar.gz`.

I will use this archive to create a temporary workspace and then run the IAM
Python static analyzer to discover exactly what Google Cloud permissions are
required by the code.

*Calling `create_workspace(source="gs://...dependencies.tar.gz")`...*

---

**IAM Policy Agent**

Workspace created successfully. I will now run the IAM Python static analyzer
on the workspace to evaluate the source code's API calls and map them to their
required Google Cloud IAM permissions.

*Calling `scan_workspace(workspace="cost_optimizer-e304c262")`...*

---

**IAM Policy Agent**

The static analyzer has successfully inspected the source code. Here are the
statistics from the scan:

- **Files Scanned:** 11 Python files
- **Files with GCP Imports:** 4 files
- **GCP Services Detected:** 5 (Cloud Asset, BigQuery, Compute Engine, GKE, Cloud Run)
- **SDK Methods Resolved:** 6 unique method calls
- **Unique Permissions Found:** 9 (6 required, 3 conditional)

### Reasoning for Role Choices

Based on the permissions discovered by the static analyzer, I've mapped the
required access to the following least-privilege predefined roles:

- **BigQuery Roles**: The agent runs queries (`Client.query`) and lists tables
  (`Client.list_tables`). Querying requires `bigquery.jobs.create`, so I am
  granting `roles/bigquery.jobUser`. I am also granting
  `roles/bigquery.dataViewer` to cover `bigquery.tables.list`, as well as the
  conditional permissions `bigquery.tables.getData` and `bigquery.datasets.get`
  needed to actually read the data in the tables it is querying.
- **Viewer Roles**: The agent only performs `list` actions across Cloud Asset
  Inventory, Compute Engine instances, GKE clusters, and Cloud Run services.
  Therefore, I am assigning the least-privilege viewer roles for each of those
  services.
- **Vertex AI User**: Because your agent uses `AGENT_IDENTITY` (per-agent
  identity via Workload Identity Federation), it also requires
  `roles/aiplatform.user` to invoke Gemini models.

### IAM Allow Policy JSON

```json
{
  "bindings": [
    {
      "role": "roles/aiplatform.user",
      "members": [
        "principal://agents.global.proj-16744841236.system.id.goog/resources/aiplatform/projects/16744841236/locations/us-central1/reasoningEngines/4803828424160313344"
      ]
    },
    {
      "role": "roles/bigquery.dataViewer",
      "members": [
        "principal://agents.global.proj-16744841236.system.id.goog/resources/aiplatform/projects/16744841236/locations/us-central1/reasoningEngines/4803828424160313344"
      ]
    },
    {
      "role": "roles/bigquery.jobUser",
      "members": [
        "principal://agents.global.proj-16744841236.system.id.goog/resources/aiplatform/projects/16744841236/locations/us-central1/reasoningEngines/4803828424160313344"
      ]
    },
    {
      "role": "roles/cloudasset.viewer",
      "members": [
        "principal://agents.global.proj-16744841236.system.id.goog/resources/aiplatform/projects/16744841236/locations/us-central1/reasoningEngines/4803828424160313344"
      ]
    },
    {
      "role": "roles/compute.viewer",
      "members": [
        "principal://agents.global.proj-16744841236.system.id.goog/resources/aiplatform/projects/16744841236/locations/us-central1/reasoningEngines/4803828424160313344"
      ]
    },
    {
      "role": "roles/container.clusterViewer",
      "members": [
        "principal://agents.global.proj-16744841236.system.id.goog/resources/aiplatform/projects/16744841236/locations/us-central1/reasoningEngines/4803828424160313344"
      ]
    },
    {
      "role": "roles/run.viewer",
      "members": [
        "principal://agents.global.proj-16744841236.system.id.goog/resources/aiplatform/projects/16744841236/locations/us-central1/reasoningEngines/4803828424160313344"
      ]
    }
  ]
}
```

### Permission Reference

| Permission | File | Line | SDK Call | Notes |
|---|---|---|---|---|
| bigquery.jobs.create | tools/billing.py | 65 | Client.query() | required |
| bigquery.tables.getData | tools/billing.py | 65 | Client.query() | conditional: for reading source tables |
| bigquery.tables.create | tools/billing.py | 65 | Client.query() | conditional: for writing destination tables |
| bigquery.tables.list | tools/billing.py | 99 | Client.list_tables() | required |
| bigquery.datasets.get | tools/billing.py | 99 | Client.list_tables() | conditional: for accessing the dataset |
| container.clusters.list | tools/containers.py | 23 | Client.list_clusters() | required |
| run.services.list | tools/containers.py | 65 | Client.list_services() | required |
| cloudasset.assets.listResource | tools/assets.py | 32 | Client.list_assets() | required |
| compute.instances.list | tools/compute.py | 29 | Client.aggregated_list() | required |
