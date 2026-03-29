# IAMSpy — Product Overview

## What It Is

IAMSpy is a static analysis tool + AI agent platform that tells you exactly what IAM permissions your Python code needs to run on GCP. It parses your code with tree-sitter, detects every GCP SDK call, and resolves each call to the specific IAM permissions it requires at runtime.

No credentials needed. No network calls. No guessing.

## The Problem

A developer writes `storage.Client().list_buckets()` and deploys. They get `PERMISSION_DENIED`. They Google the error, try `roles/storage.admin`, it works, they move on. Now the service account has 200 permissions it doesn't need. Multiply by 50 agents across an org.

There's no shared vocabulary between:
- **Developer**: "I just need to list buckets"
- **Security admin**: "This SA has roles/editor, why?"
- **Platform team**: "Which agents can access which resources?"

## The Solution

### Layer 1: Code Analysis (iamspy CLI + VS Code Extension)

Scan code → get permissions:

```
$ iamspy scan src/
src/pipeline.py
     30  rows = bq.query("SELECT * FROM analytics.events").result()
         → bigquery.jobs.create [app]
     48  client.encrypt(request={"name": key_name, "plaintext": data})
         → cloudkms.cryptoKeyVersions.useToEncrypt [app]
     62  blob.upload_from_string(encrypted, content_type="application/octet-stream")
         → storage.objects.create [app]
```

Every finding includes:
- The exact permission
- The file and line
- The identity context (`[app]` = SA, `[user]` = delegated OAuth)

The VS Code extension shows this inline as CodeLens — you see permissions as you write code.

### Layer 2: Permission Manifest

The scan produces `iam-manifest.yaml` — a declarative record of what the code needs:

```yaml
version: '2'
services:
  enable:
  - bigquery.googleapis.com
  - cloudkms.googleapis.com
  - storage.googleapis.com
identities:
  app:
    permissions:
      required:
      - bigquery.jobs.create
      - cloudkms.cryptoKeyVersions.useToEncrypt
      - storage.objects.create
      conditional:
      - bigquery.tables.getData
      - storage.objects.delete
```

This is checked into git. CI can diff it. Security can review it. The manifest is the shared vocabulary.

### Layer 3: IDE Agent

An AI agent in the IDE (Antigravity / VS Code) that uses the scan results + workspace config to help developers deploy:

**What the agent knows on startup** (auto-loaded, no scanning needed):
- What permissions the code needs (from manifest)
- What environments exist and their identities (from `.iamspy/workspace.yaml`)

**What the agent can do** (19 tools):
- Scan code, generate manifests, search the permission database
- Check which GCP services are enabled, enable missing ones
- List deployed agents, Cloud Run services, service accounts
- Read the project IAM policy, analyze permission gaps
- Create service accounts, grant roles (with plan → confirm → execute flow)
- Check security guardrails, troubleshoot PERMISSION_DENIED errors
- Generate deterministic role recommendations (greedy set cover, not LLM guessing)

**The workflow**:
1. Developer asks "help me deploy"
2. Agent already knows the permissions (auto-context)
3. No workspace config? Agent asks: deployment target, project, identity type
4. Agent generates a plan: create SA, enable APIs, grant 4 roles
5. Developer reviews the plan, confirms
6. Agent executes, verifies, generates manifest

### Layer 4: Admin Agent

A security/DevOps agent (deployed on Agent Engine) that audits deployed agents:

- Pulls deployed agent code from Agent Engine/GCS
- Scans it, compares required vs granted permissions
- Flags over-permissioned principals (e.g., roles/editor → needs 6 permissions)
- Recommends least-privilege replacement roles
- Checks org/folder/project deny policies

Same tools as the IDE agent, different persona and default environment (prod).

## Technical Architecture

### Scanner

Two-phase system:
- **Build time** (offline): 7-stage pipeline introspects 130+ GCP SDK packages, extracts 25,011 method signatures, maps each to IAM permissions via LLM + REST URI context. Ships as 3 JSON files.
- **Run time** (fast): Load JSON → check for `google.cloud` imports → tree-sitter parse → walk calls → resolve permissions. ~50ms per file.

### Credential Provenance

Detects which identity context feeds each GCP API call:

```python
sa_creds, project = google.auth.default()        # → APP
user_creds = Credentials(token=session["token"])  # → USER

sa_client = storage.Client(credentials=sa_creds)   # → APP identity
user_client = storage.Client(credentials=user_creds) # → USER identity

sa_client.list_buckets()   # → storage.buckets.list [app]
user_client.list_buckets() # → storage.buckets.list [user]
```

97.9% accuracy on 142 real-world `Client(credentials=X)` sites across Google's python-docs-samples and googleworkspace/python-samples.

### Permission Ring Classification

All 12,879 GCP IAM permissions classified into 4 severity rings:

| Ring | Name | Count | % | Action |
|---|---|---|---|---|
| 0 | CRITICAL | 309 | 2.4% | Always blocked for agents |
| 1 | SENSITIVE | 98 | 0.8% | Warn, require justification |
| 2 | MUTATING | 7,400 | 57.5% | Allow (create, update, delete) |
| 3 | READ | 5,072 | 39.4% | Allow (get, list) |

Used by the guardrails engine to automatically flag dangerous permissions.

### Deterministic Role Mapping

Given a set of required permissions, finds the minimum predefined roles using greedy set cover:

```
Required: {storage.objects.create, storage.objects.delete}
  → roles/storage.objectUser (covers both, 12 excess)

Required: {bigquery.jobs.create}
Conditional: {bigquery.tables.getData}
  → roles/bigquery.jobUser (covers required + conditional comes free)
```

No LLM involved. Deterministic. Same input → same output every time.

### Workspace Config

`.iamspy/workspace.yaml` defines deployment environments:

```yaml
project:
  name: acme-data-pipeline
environments:
  dev:
    gcp_project: acme-dev-123
    region: us-central1
    deployment:
      target: cloud_run_job
    identity:
      app:
        type: service_account
        principal: serviceAccount:pipeline@acme-dev-123.iam.gserviceaccount.com
```

The agent reads this to know *where* (project, region) and *who* (principal). The manifest tells it *what* (permissions). Together → environment-specific policy.

## What's Built

- [x] Core scanner: 25,011 methods, 129 services, tree-sitter parsing
- [x] CLI: scan, search, services, permissions subcommands
- [x] VS Code extension: CodeLens, status bar, manifest generation
- [x] Credential provenance: identity detection (app/user/impersonated)
- [x] v2 manifest: per-identity permissions, OAuth scopes, source tracing
- [x] IDE agent: 19 tools, auto-context, workspace config, plan→execute flow
- [x] Admin agent: workspace management, deployed agent scanning
- [x] MCP server: stdio transport for Antigravity/VS Code
- [x] Permission rings: 12,879 permissions classified into 4 severity levels
- [x] Guardrails: ring-based evaluation, identity constraints, role validation
- [x] Deterministic role mapper: greedy set cover, no LLM
- [x] Eval framework: 3 canonical app scenarios, conversation transcripts
- [x] Live GCP integration: SA creation, role grants, service enablement, IAM policy reads

## Known Limitations

### Scanner
- Static analysis only — can't detect permissions needed for dynamic method dispatch
- Import-dependent — no `google.cloud` imports = no findings (by design, zero false positives)
- Python only (Java, Go, Node planned)
- Conditional permissions are advisory — runtime paths determine which activate

### Credential Provenance
- Ambiguous when multiple clients of the same type serve different identities in the same scope
- `googleapiclient.discovery.build()` detected for identity tracking but doesn't map to IAM permissions (Workspace APIs)

### Build Pipeline
- 12.4% of LLM-suggested permissions were invalid (filtered in validation stage)
- No human-verified ground truth dataset yet
- 2.2% conditional permission rate may undercount

## Repository Structure

```
src/iamspy/                # Core scanner library (pip-installable)
  scanner.py               # GCPCallScanner — tree-sitter + permission resolution
  credential_provenance.py # Identity detection (app/user/impersonated)
  manifest.py              # v2 manifest generation
  type_inference.py        # Andersen's points-to analysis
  data/                    # Static JSON: service_registry, method_db, iam_permissions

agents/                    # Agent platform
  shared/                  # Common tools, GCP helpers, guardrails, ring classifier
    tools/                 # scan, iam, resources, deploy, role_mapper
    gcp.py                 # REST wrappers (ADC auth)
    guardrails.py          # Ring-based permission evaluation
    permission_rings.py    # 4-ring classifier
    workspace.py           # .iamspy/workspace.yaml loader
  ide/                     # Developer agent (local filesystem context)
    agent.py               # ADK agent with auto-context
    tools.py               # 19 tools for IDE workflow
    context.py             # Auto-load manifest + workspace config on startup
    plan.py                # Plan → confirm → execute for mutations
  admin/                   # Security admin agent (remote workspace context)
  mcp/                     # MCP server for Antigravity/VS Code

vscode-iamspy/             # VS Code extension (CodeLens, status bar)
build_pipeline/            # 7-stage offline pipeline
evals/                     # Canonical app scenarios + conversation eval scripts
```
