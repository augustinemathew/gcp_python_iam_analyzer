# GCP IAM Tools Demo — Deploying an Agent to Agent Engine

## Case Study: GCP Cost Optimization Agent

A developer has built a cost optimization agent for Agent Engine. It surveys GCP project resources, lists running VMs, and queries billing data from BigQuery. It uses three GCP client libraries: Cloud Asset Inventory, Compute Engine, and BigQuery.

We'll walk through the full lifecycle: developer writes code → static analysis detects permissions → security admin reviews → IAM Policy designer agent generates (PAB, Allow, Deny, UAP) → agent deploys with least privilege.

> This demo uses an Agent Engine agent, but the same workflow applies to **any Python code** that calls GCP APIs — Cloud Run services, Cloud Functions, data pipelines, CLI tools.

---

## The Problem

The agent is ready. But deploying it to Agent Engine means granting IAM permissions to its AGENT_IDENTITY.

Questions:

- **What IAM permissions does this agent need?** It calls `list_assets()`, `aggregated_list()`, `client.query()` — each maps to different IAM permissions across different services.
- **What APIs need to be enabled?** Three services, but which googleapis.com names?
- **What roles should the agent identity get?** `roles/editor`? That's too broad. But figuring out the exact roles means reading IAM docs for three different services.

Different personas are involved — the developer, the security admin, the policy designer — and they speak different languages. There's no shared vocabulary for the handoff.

---

## Act 1 — Agent Developer: "What does my agent need?"

### The agent code

Three tool functions, three GCP services:

```python
# agent/tools/assets.py — Cloud Asset Inventory
client = asset_v1.AssetServiceClient()
for asset in client.list_assets(request=request):
    by_type.setdefault(asset.asset_type, []).append(asset.name)
```

```python
# agent/tools/compute.py — Compute Engine
client = compute_v1.InstancesClient()
for zone, resp in client.aggregated_list(request=request):
    for vm in resp.instances:
        vms.append(_format_instance(vm))
```

```python
# agent/tools/billing.py — BigQuery (billing export)
client = bigquery.Client(project=project_id)
rows = list(client.query(query, job_config=job_config).result())
```

### GCP IAM Tools in the IDE

The developer opens the agent in VS Code (or AntiGravity). The GCP IAM extension activates and scans each file:

**CodeLens annotations appear inline:**

```
  🔑 cloudasset.assets.listResource
  client.list_assets(request=request)

  🔑 compute.instances.list
  client.aggregated_list(request=request)

  🔑 bigquery.jobs.create
  client.query(query, job_config=job_config)
```

The developer clicks **"GCP IAM: Generate Permission Manifest"** and gets `iam-manifest.yaml`:

```yaml
version: '1'
generated_by: iamspy scan /Users/augustine/gcp_cost_optimizer_agent
generated_at: '2026-03-20T18:07:52Z'
services:
  enable:
  - bigquery.googleapis.com
  - cloudasset.googleapis.com
  - compute.googleapis.com
permissions:
  required:
  - bigquery.jobs.create
  - bigquery.tables.getData
  - cloudasset.assets.listResource
  - compute.instances.list
  conditional:
  - bigquery.tables.create
```

**What just happened:**
- 3 SDK method calls → permissions across 3 services detected automatically
- **Required** permissions (always needed) separated from **conditional** (depends on query behavior)
- 3 APIs to enable identified by their googleapis.com names
- The developer didn't open a single IAM doc page

**The manifest is the common vocabulary.** The developer generated it from code. The security admin can read it. The policy designer can consume it. Everyone speaks the same language.

---

## Act 2 — Security Admin / DevOps: "Is this safe to deploy?"

### The handoff

The agent developer submits the deployment request with `iam-manifest.yaml` attached. The security admin opens it.

### What the security admin sees

**APIs to enable:**
```yaml
services:
  enable:
  - bigquery.googleapis.com         # Billing data queries
  - cloudasset.googleapis.com       # Asset inventory (read-only)
  - compute.googleapis.com          # VM metadata (read-only)
```

**Required permissions — always needed:**
```yaml
required:
  - bigquery.jobs.create            # Run billing queries
  - bigquery.tables.getData         # Read billing export table
  - cloudasset.assets.listResource  # Enumerate all resources
  - compute.instances.list          # List running VMs
```

**Conditional permissions:**
```yaml
conditional:
  - bigquery.tables.create          # Only if query creates temp tables
```

### With source tracing (`--trace`)

The security admin sees exactly where each permission comes from:

```yaml
sources:
  bigquery.jobs.create:
  - {file: agent/tools/billing.py, line: 51, method: query}
  cloudasset.assets.listResource:
  - {file: agent/tools/assets.py, line: 32, method: list_assets}
  compute.instances.list:
  - {file: agent/tools/compute.py, line: 29, method: aggregated_list}
```

### The security admin's assessment

> "4 required permissions across 3 services. Asset and Compute are read-only. BigQuery is scoped to running queries and reading a specific billing export table — no write access to data. 1 conditional for temp table creation. **Approved.**"

---

## Act 3 — Policy Designer: "What's the right policy?"

### The manifest feeds into policy generation

The security admin (or IAM Agent) takes the approved manifest and produces deployment-ready artifacts:

### Option A: Predefined Roles

Four roles cover all permissions:

```python
# deploy.py — derived from iamspy analysis
AGENT_IAM_ROLES = [
    "roles/cloudasset.viewer",    # cloudasset.assets.listResource
    "roles/compute.viewer",       # compute.instances.list
    "roles/bigquery.jobUser",     # bigquery.jobs.create
    "roles/bigquery.dataViewer",  # bigquery.tables.getData
]
```

### Option B: Terraform HCL

```hcl
locals {
  project_number = "16744841236"
  agent_id       = vertexai_reasoning_engine.cost_optimizer.id

  agent_principal = join("", [
    "principal://agents.global.project-${local.project_number}.system.id.goog",
    "/resources/aiplatform/projects/${local.project_number}",
    "/locations/us-central1/reasoningEngines/${local.agent_id}",
  ])
}

resource "google_project_iam_member" "cost_optimizer_asset_viewer" {
  project = var.project_id
  role    = "roles/cloudasset.viewer"
  member  = local.agent_principal
}

resource "google_project_iam_member" "cost_optimizer_compute_viewer" {
  project = var.project_id
  role    = "roles/compute.viewer"
  member  = local.agent_principal
}

resource "google_project_iam_member" "cost_optimizer_bq_job_user" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = local.agent_principal
}

resource "google_project_iam_member" "cost_optimizer_bq_data_viewer" {
  project = var.project_id
  role    = "roles/bigquery.dataViewer"
  member  = local.agent_principal
}
```

### Option C: Custom Role

```yaml
title: "Cost Optimizer Agent"
description: "Minimum permissions for the GCP cost optimizer agent"
stage: "GA"
includedPermissions:
  - bigquery.jobs.create
  - bigquery.tables.getData
  - cloudasset.assets.listResource
  - compute.instances.list
```

### Option D: IAM Deny (organization guardrail)

```json
{
  "deniedPermissions": ["*.delete", "*.update", "*.patch"],
  "denialCondition": {
    "expression": "resource.matchTag('env', 'production')"
  }
}
```

---

## The Deployment

The `deploy.py` script ties it all together:

```python
# 1. Deploy to Agent Engine with per-agent identity (AGENT_IDENTITY)
remote = client.agent_engines.create(
    agent=agent,
    config={
        "display_name": "GCP Cost Optimizer",
        "identity_type": types.IdentityType.AGENT_IDENTITY,
        ...
    },
)

# 2. Grant only the roles iamspy identified
for role in AGENT_IAM_ROLES:  # cloudasset.viewer, compute.viewer, bigquery.jobUser, bigquery.dataViewer
    gcloud projects add-iam-policy-binding PROJECT \
        --member="principal://agents.global.project-PROJECT_NUMBER..." \
        --role=role
```

The agent launches with exactly the permissions it needs. No `roles/editor`. No guessing. No over-provisioning.

---

## The Full Flow

```
  Agent developer writes 3 tool functions
  (list_assets, aggregated_list, query)
                    │
                    ▼
  GCP IAM Tools scans code (IDE / Agent Engine)
  Detects 3 SDK calls → resolves to IAM permissions
                    │
                    ▼
           iam-manifest.yaml
     (common vocabulary between all personas)
     4 required + 1 conditional · 3 APIs
                    │
                    ▼
  Security admin reviews manifest
  "Scoped reads + billing queries → approved"
                    │
                    ▼
  IAM Agent generates policy
  4 roles / custom role / Terraform
                    │
                    ▼
  deploy.py → Agent Engine
  AGENT_IDENTITY + 4 right-sized roles
  = least privilege deployment
```

---

## Key Takeaways

1. **Common vocabulary.** The permission manifest translates between SDK methods, IAM permissions, and policy roles. Every persona reads the same artifact.

2. **Left-shifted.** The developer sees permissions in the IDE — at the moment the code is written. Awareness starts where the problem is created.

3. **Right-sized by construction.** 4 specific roles. No editor. No owner. The agent can read resources and run billing queries but cannot modify anything.

4. **The manifest is the contract.** One YAML file flows from developer → security admin → policy generator → deployment script.

5. **Works for any code.** Cloud Run, Cloud Functions, data pipelines — anything that calls GCP APIs. The agent is just the sharpest use case.
