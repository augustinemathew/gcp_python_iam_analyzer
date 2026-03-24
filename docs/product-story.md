# IAMSpy — Product Story

## The Problem

IAM permissions are hard. Policies are harder.

Agents deployed on Google Cloud need IAM permissions to call GCP APIs. But figuring out *which* permissions — and turning those into right-sized policies — is a manual, error-prone process that spans multiple personas. The developer knows the code. The security admin knows the policies. Neither has the full picture.

The result: over-permissioned service accounts (`roles/editor` "just to get it working"), policy drift, and audit failures.

IAMSpy closes the gap between **what code does** and **what permissions it needs**. It statically analyzes source code, detects every GCP SDK call, resolves each to its IAM permissions, and produces a machine-readable permission manifest that flows from developer to security admin to deployment.

> While the primary use case is agents deployed on Agent Engine, IAMSpy works on **any Python source code** that uses GCP client libraries — Cloud Run services, Cloud Functions, App Engine apps, data pipelines, CLI tools. The analysis is the same.

## The Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   Foundation: Static Analysis Engine                            │
│   Python source → tree-sitter parse → IAM permissions           │
│   (209 services, 25K+ permission mappings)                      │
│                                                                 │
└──────────────────────────┬──────────────────────────────────────┘
                           │
     Layer 1: Agent Developer
     "What does my agent need?"
                           │
          ┌────────────────┼────────────────┐
          │                │                │
  ┌───────▼────────┐ ┌────▼─────────┐ ┌────▼──────────┐
  │  IDE            │ │ Agent Engine  │ │ CI/CD         │
  │  (VS Code /     │ │ (automated    │ │ (pipeline     │
  │   Cursor)       │ │  scanning)    │ │  on PR)       │
  └───────┬────────┘ └────┬─────────┘ └────┬──────────┘
          │                │                │
          └────────────────┼────────────────┘
                           │
                  iam-manifest.yaml
                           │
     Layer 2: Security Admin / DevOps
     "Is this safe to deploy?"
                           │
                  reviews, approves, or modifies
                           │
     Layer 3: Policy Designer
     "What's the right policy?"
                           │
          ┌────────────────┼────────────────┐
          │                │                │
  ┌───────▼────────┐ ┌────▼─────────┐ ┌────▼──────────┐
  │  IAM Allow /    │ │  Terraform / │ │  Custom roles  │
  │  Deny / PAB     │ │  Pulumi      │ │  interactive   │
  └────────────────┘ └──────────────┘ └───────────────┘
```

## Three Layers

### Layer 1 — Agent Developer: "What does my agent need?"

An agent developer builds an agent that calls GCP APIs — Cloud Storage, BigQuery, Recommender, Vertex AI. Before deploying to Agent Engine, they need to know what IAM permissions the agent requires.

IAMSpy tells them automatically. Three entry points, same engine:

| Entry Point | How | When |
|-------------|-----|------|
| **IDE** (VS Code / Cursor) | CodeLens shows permissions inline above each SDK call. Status bar shows totals. One-click manifest generation. | While writing agent code |
| **Agent Engine** | Deployed iamspy service scans uploaded agent code automatically | At deployment time |
| **CI/CD pipeline** | `iamspy scan --manifest iam-manifest.yaml` runs on every PR | Before merge |

**What the agent developer sees in VS Code:**

```python
# agent/tools/assets.py
#    🔑 cloudasset.assets.listResource          ← CodeLens annotation
client = asset_v1.AssetServiceClient()
for asset in client.list_assets(request=request):
    ...
```

The developer clicks "Generate Permission Manifest" and gets:

```yaml
version: '1'
services:
  enable:
  - cloudasset.googleapis.com
  - compute.googleapis.com
  - recommender.googleapis.com
permissions:
  required:
  - cloudasset.assets.listResource
  - compute.instances.list
  conditional:
  - recommender.computeInstanceMachineTypeRecommendations.list
  # ... 67 more conditional recommender permissions
```

The developer didn't read any IAM docs. The manifest was derived from 3 SDK method calls automatically.

The manifest travels with the agent code — checked into the repo, attached to the deployment request, or passed to the next layer.

### Layer 2 — Security Admin / DevOps: "Is this safe to deploy?"

The agent developer hands off the permission manifest (or the code itself) to the security admin or DevOps team. The manifest is a structured, auditable document that says exactly what the agent needs and why.

**The handoff:**
1. Agent developer generates `iam-manifest.yaml` (from IDE, CI, or Agent Engine)
2. Manifest attached to the deployment request / PR / ticket
3. Security admin reviews: APIs to enable, required vs. conditional permissions
4. With `--trace`, each permission links back to the exact source file and line
5. Admin approves, modifies, or requests changes — with full context

**What the security admin sees:**

- **APIs to enable:** 3 read-only services
- **Required permissions:** 2 (always needed when the agent runs)
- **Conditional permissions:** 68 (only needed if specific recommender types exist in the project)
- **Assessment:** "All read-only, no mutations. Approved."

The manifest separates **required** (always needed) from **conditional** (depends on runtime features like CMEK, cross-project access, or optional API categories). The security admin decides which conditionals to grant based on their environment.

### Layer 3 — Policy Designer: "What's the right policy for our environment?"

The security admin or IAM admin uses the manifest to generate policies that are right-sized for their organization. The IAM Policy Agent consumes the manifest and produces deployment-ready artifacts.

**Output formats:**
- **IAM Allow policies** — `gcloud projects set-iam-policy` input
- **IAM Deny policies** — organization-level guardrails
- **PAB (Principal Access Boundary)** — restrict where a principal's permissions apply
- **Terraform HCL** — infrastructure-as-code fragments
- **Pulumi** — alternative IaC
- **Custom role definitions** — when predefined roles are too broad
- **Interactive refinement** — security admin refines policies conversationally with the IAM Policy Agent

For the cost optimizer agent, the policy designer might choose:

**Predefined roles** (simplest — 3 viewer roles cover all 70 permissions):
```python
AGENT_IAM_ROLES = [
    "roles/cloudasset.viewer",
    "roles/compute.viewer",
    "roles/recommender.viewer",
]
```

**Custom role** (tightest — only the exact permissions the agent uses):
```yaml
title: "Cost Optimizer Agent"
includedPermissions:
  - cloudasset.assets.listResource
  - compute.instances.list
  - recommender.computeInstanceMachineTypeRecommendations.list
  - recommender.computeInstanceIdleResourceRecommendations.list
  # ... only the recommender types actually queried
```

**Terraform HCL** (for IaC-managed deployments):
```hcl
resource "google_project_iam_member" "cost_optimizer_asset_viewer" {
  project = var.project_id
  role    = "roles/cloudasset.viewer"
  member  = local.agent_principal
}
```

## The Permission Manifest: Universal Interchange

The `iam-manifest.yaml` is the connective tissue between all layers. Layer 1 produces it. Layer 2 reviews it. Layer 3 consumes it to generate policies.

```yaml
version: '1'
generated_by: iamspy scan src/
generated_at: '2026-03-20T19:34:22Z'
services:
  enable:
  - storage.googleapis.com
  - bigquery.googleapis.com
permissions:
  required:
  - storage.objects.get
  - bigquery.jobs.create
  conditional:
  - storage.objects.delete
sources:                          # optional, with --trace
  storage.objects.get:
  - {file: src/app.py, line: 42, method: download_blob}
```

See [permission-manifest.md](permission-manifest.md) for the full specification.

## Foundation: Static Analysis Engine

The core engine that all three layers build on. Tree-sitter parses Python source, detects GCP SDK method calls, and resolves each to IAM permissions via pre-built static mappings.

**Coverage:**
- 209 GCP services, 25,011 method signatures, 25,000+ permission mappings
- Import-aware: zero false positives (no `google.cloud` imports = no findings)
- Type-aware: Andersen's points-to analysis resolves receiver types across assignments and function returns

**How it works:**
1. Load 3 JSON files (~39ms)
2. Quick check: `"google."` in source? If not → zero findings, done
3. Tree-sitter parse → walk imports → detect which GCP services are used
4. Walk call nodes → match method name + arg count against method DB
5. O(1) permission lookup → Finding with required + conditional permissions
6. Aggregate into permission manifest

**Language support:**
- Python today. Golang next.
- Minimal per-language investment: each language only needs import detection + call walking. The service registry, permission mappings, and manifest format are shared.

## Beyond Agents

While this story focuses on agents deployed to Agent Engine, IAMSpy works on any Python code that uses GCP client libraries:

- **Cloud Run services** — scan before deploying, generate service account policy
- **Cloud Functions** — detect permissions in function handlers
- **Data pipelines** — Dataflow, Composer, batch jobs
- **App Engine apps** — scan before deploying to App Engine
- **CLI tools** — any script that calls GCP APIs

The analysis is identical. The manifest format is the same. The handoff to security works the same way. The only difference is the deployment target.

## Design Principles

1. **Meet people where they are.** Agent developers get IDE integration. Agent Engine gets automated scanning. Security gets structured artifacts. Nobody has to learn a new tool category.

2. **The manifest is the contract.** One artifact flows from developer to security admin to policy generator. Every persona sees the same truth.

3. **Static analysis, not runtime instrumentation.** Permissions are determined from source code before deployment. No agents running in production, no log analysis, no permission escalation incidents to learn from.

4. **Minimal per-language investment.** The expensive part is pipeline that pulls source code and service definitions of CPE and creates a mapping between REST API call to permissions checked. 
