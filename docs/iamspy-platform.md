# IAMSpy Platform: IDE + Remote Agent Design

## Overview

Two agents sharing the same core toolset, differentiated by persona and context:

| | Local Agent (Antigravity) | Remote Agent (Agent Engine) |
|---|---|---|
| **Persona** | Developer building & deploying | Security admin / DevOps |
| **Runtime** | MCP server in VS Code extension | A2A on Agent Engine, exposes MCP |
| **Auth** | Developer's ADC (gcloud auth) | AGENT_IDENTITY (WIF) |
| **Scope** | Single project, active codebase | Org-wide, multiple projects |
| **Default profile** | `dev` | `prod` |
| **Primary flow** | Write code → see permissions → deploy | Audit deployed agents → find gaps → recommend fixes |

Both agents share the same tool implementations — the difference is framing, not capability.

---

## Shared Tool Surface

Every tool exists in both agents. The agent instructions and persona determine which tools get used and how results are presented.

### Scan & Analyze

| Tool | Description |
|------|-------------|
| `scan_workspace` | Run iamspy on Python files. Returns findings with permissions, lines, services. |
| `scan_deployed_agent` | Pull source from Agent Engine's GCS deps URI, extract, scan. Composite of list_agent_engines → download → scan. |
| `search_permissions` | Glob search against 25K method permission database. |
| `generate_manifest` | Produce `iam-manifest.yaml` from scan results. |

### GCP Resources

| Tool | Description |
|------|-------------|
| `list_agent_engines` | List deployed Reasoning Engine instances (ID, name, source URI, identity type, status). |
| `list_cloud_run_services` | List Cloud Run services in project/region. |
| `list_gke_clusters` | List GKE clusters. |
| `list_cais_resources` | List Cloud AI resources — Agent Engine, Vertex endpoints, models, datasets. |

### IAM Policy

| Tool | Description |
|------|-------------|
| `get_iam_policy` | Get IAM policy bindings for a project or resource. Returns members, roles, conditions. |
| `get_effective_policy` | Resolve effective permissions for a principal (includes inherited org/folder bindings). |
| `analyze_permissions` | Compare granted permissions (from IAM policy) vs required permissions (from scan). Returns: unused grants, missing grants, over-privileged roles. |
| `recommend_policy` | Generate least-privilege IAM policy from scan results + environment. Always takes a principal. For a **new principal** (no existing grants): generates ideal policy and checks deny context (org/folder/project deny policies, org constraints) to flag permissions that can't be granted. For an **existing principal**: same, plus diffs against live grants to show what to add/remove. Either way, the recommendation accounts for the real environment. |
| `get_deny_policies` | Get IAM deny policies at org, folder, and project levels. Returns deny rules that could block permissions for a principal type. |
| `get_org_constraints` | Get Organization Policy constraints that affect IAM (e.g., `iam.allowedPolicyMemberDomains`, `compute.restrictVpcPeering`). |

### Deploy & Manage

| Tool | Description |
|------|-------------|
| `deploy_agent_engine` | Deploy ADK agent to Agent Engine with AGENT_IDENTITY. |
| `deploy_cloud_run` | Deploy container to Cloud Run. |
| `grant_iam_roles` | Apply IAM bindings from generated policy (with confirmation). |

### Utility

| Tool | Description |
|------|-------------|
| `shell` | Run shell commands in workspace (60s timeout, 8KB output cap). |
| `list_gcs` | List GCS objects under a prefix. |
| `download_gcs` | Download a single GCS object. |
| `create_workspace` | Extract archive (zip/tar.gz, local or gs://) into temp workspace. |

---

## Policy Design Primitives

The core abstraction is an **environment profile** that shapes every policy output. Same scan results, different policy depending on where you're deploying.

### Environment Profiles

```yaml
# .iamspy/profiles/dev.yaml
version: "1"
environment: dev
description: Development — fast iteration, broad access, visibility into errors

identity:
  type: service_account           # shared SA is fine for dev
  allow_shared: true

iam:
  role_strategy: predefined       # use predefined roles (broader but simpler)
  allow_primitive_roles: false    # still no roles/editor, even in dev
  max_role_breadth: 50            # warn if a role grants >50 unused permissions
  include_conditional: true       # grant conditional permissions upfront (avoid debugging PERMISSION_DENIED)
  allow_cross_project: true       # dev often reads from shared data project

logging:
  data_access_logs: false         # too noisy for dev
  admin_activity_logs: true

alerts:
  on_primitive_role: warn
  on_overpermission: info
  on_shared_sa: info
```

```yaml
# .iamspy/profiles/prod.yaml
version: "1"
environment: prod
description: Production — least privilege, full audit trail

identity:
  type: agent_identity            # per-agent WIF identity required
  allow_shared: false             # no shared SAs in prod
  require_workload_identity: true

iam:
  role_strategy: minimal          # find smallest set of predefined roles
  allow_primitive_roles: false
  max_role_breadth: 10            # flag any role granting >10 unused permissions
  include_conditional: false      # only grant required permissions; conditional on-demand
  allow_cross_project: false      # must be explicitly approved per-resource
  require_conditions: true        # time-bound or resource-scoped conditions preferred
  max_ttl: "90d"                  # recommend expiring bindings

logging:
  data_access_logs: true          # full audit trail
  admin_activity_logs: true

alerts:
  on_primitive_role: block        # cannot deploy
  on_overpermission: warn         # flag in review
  on_shared_sa: block             # cannot deploy
  on_cross_project: require_approval
```

```yaml
# .iamspy/profiles/staging.yaml
version: "1"
environment: staging
description: Staging — prod-like constraints with relaxed blocking

inherits: prod                    # start from prod, override specific fields

iam:
  max_role_breadth: 20            # slightly more tolerant
  include_conditional: true       # grant conditional to catch issues before prod

alerts:
  on_primitive_role: block
  on_overpermission: warn
  on_shared_sa: warn              # warn instead of block
```

### Profile Inheritance

Profiles can inherit from a base and override. The chain is:

```
defaults (built-in) → base profile → environment profile → per-agent overrides
```

Per-agent overrides live in the agent's directory:

```yaml
# my_agent/.iamspy.yaml
inherits: prod
iam:
  allow_cross_project: true       # this agent needs to read from data-warehouse project
  cross_project_resources:
    - project: data-warehouse-prod
      permissions: ["bigquery.jobs.create", "bigquery.tables.getData"]
      justification: "Reads analytics events for cost optimization"
```

### Policy Primitives

These are the building blocks every tool uses when generating output:

#### 1. `PermissionSet`
The raw output of a scan — what the code needs. Separates app-own permissions (IAM)
from delegated user operations (OAuth/Workspace).

```python
@dataclass(frozen=True)
class PermissionSet:
    # App's own identity (SA or AGENT_IDENTITY) — IAM permissions
    required: frozenset[str]       # always needed
    conditional: frozenset[str]    # needed in some code paths
    services: frozenset[str]       # googleapis.com service names to enable
    sources: dict[str, list[SourceLocation]]  # permission → where in code

    # Delegated user identity (OAuth) — detected from code, not IAM
    # Populated when scanner detects OAuth/Workspace API usage
    delegated: DelegatedPermissions | None
```

```python
@dataclass(frozen=True)
class DelegatedPermissions:
    """What the app does on behalf of the user via OAuth."""
    oauth_scopes: frozenset[str]   # scopes requested in code (e.g., drive.readonly)
    workspace_apis: list[WorkspaceApiUsage]  # which APIs and operations
    sources: dict[str, list[SourceLocation]]  # scope/api → where in code

@dataclass(frozen=True)
class WorkspaceApiUsage:
    service: str                   # "Google Drive", "Google Docs", etc.
    operations: list[str]          # "files.list", "documents.get", etc.
```

#### 2. `GrantSet`
What a principal currently has — from IAM policy analysis.

```python
@dataclass(frozen=True)
class GrantSet:
    permissions: frozenset[str]    # all effective permissions
    roles: list[RoleBinding]       # role → members, conditions
    inherited_from: dict[str, str] # permission → org/folder/project source
```

#### 3. `DenyContext`
What the environment blocks — org, folder, and project-level deny policies and constraints.

```python
@dataclass(frozen=True)
class DenyRule:
    denied_permissions: frozenset[str]  # permissions blocked
    denied_principals: list[str]        # principal patterns (e.g., "principalSet://...")
    exception_principals: list[str]     # exempt from this deny
    source: str                         # "org:123", "folder:456", "project:proj-id"
    condition: str | None               # CEL condition on the deny rule

@dataclass(frozen=True)
class OrgConstraint:
    constraint: str                     # e.g., "iam.allowedPolicyMemberDomains"
    enforced: bool
    values: list[str]                   # allowed/denied values
    source: str                         # org/folder/project

@dataclass(frozen=True)
class DenyContext:
    deny_rules: list[DenyRule]
    org_constraints: list[OrgConstraint]

    def blocked_permissions(self, principal: str) -> frozenset[str]:
        """Permissions that can never take effect for this principal."""
        ...

    def blocked_principal_types(self) -> list[str]:
        """Principal types that can't be used (e.g., domain restriction)."""
        ...
```

#### 4. `PolicyDiff`
The gap analysis — core primitive for all recommendations.

```python
@dataclass(frozen=True)
class PolicyDiff:
    missing: frozenset[str]        # required but not granted
    excess: frozenset[str]         # granted but not required
    matched: frozenset[str]        # required and granted
    denied: frozenset[str]         # required but blocked by deny policy (can't be fixed by granting)
    overprivileged_roles: list[RoleAnalysis]  # roles granting excess
    suggested_roles: list[str]     # minimal replacement roles
```

#### 5. `EnvironmentPolicy`
The shaped output — PermissionSet + principal + environment = deployable policy.

```python
@dataclass(frozen=True)
class EnvironmentPolicy:
    environment: str               # dev / staging / prod
    principal: str                 # always provided (new or existing)

    # Full ideal policy
    iam_bindings: list[IamBinding] # ready for setIamPolicy

    # Diff against live grants (populated for existing principals)
    to_add: list[IamBinding]       # missing — need to grant
    to_remove: list[IamBinding]    # excess — should revoke
    already_correct: list[IamBinding]  # no change needed

    # Environment deny analysis (populated for all principals)
    denied: list[DeniedPermission] # required but blocked by deny policies
    deny_context: DenyContext      # full deny context for reference

    warnings: list[PolicyWarning]  # profile violations
    blocked: bool                  # true if any alert = "block"
    block_reasons: list[str]

@dataclass(frozen=True)
class DeniedPermission:
    permission: str                # the permission that's blocked
    deny_rule: DenyRule            # which deny rule blocks it
    remediation: str               # "contact org admin" / "request exception"
```

#### 5. `PolicyWarning`

```python
@dataclass(frozen=True)
class PolicyWarning:
    severity: Literal["info", "warn", "block"]
    category: str                  # overpermission, primitive_role, shared_sa, cross_project
    message: str
    remediation: str               # what to do about it
    permission: str | None         # specific permission if applicable
    role: str | None               # specific role if applicable
```

### How Primitives Flow Through Tools

```
scan_workspace
    → PermissionSet

get_deny_policies + get_org_constraints (org → folder → project)
    → DenyContext

get_iam_policy + get_effective_policy
    → GrantSet (empty for new principal)

recommend_policy(PermissionSet, principal, profile)
    │
    ├── Always: build DenyContext for the principal's environment
    │   → flag permissions that are denied (can't be fixed by granting)
    │
    ├── New principal (no existing grants):
    │   → EnvironmentPolicy
    │       ├── iam_bindings (ideal policy from scan)
    │       ├── denied (permissions blocked by environment)
    │       ├── warnings
    │       └── blocked
    │
    └── Existing principal (has grants):
        → get_effective_policy(principal) → GrantSet
        → PolicyDiff(PermissionSet, GrantSet, DenyContext)
        → EnvironmentPolicy
            ├── iam_bindings (full replacement policy)
            ├── to_add (missing grants)
            ├── to_remove (excess grants)
            ├── already_correct (no change needed)
            ├── denied (permissions blocked by environment)
            ├── warnings
            └── blocked

deploy_*(EnvironmentPolicy)
    → if blocked: refuse with reasons
    → if warnings: show and confirm
    → else: deploy + grant
```

### Profile-Aware Tool Behavior

Every tool that generates policy output accepts an `environment` parameter:

| Tool | Dev behavior | Prod behavior |
|------|-------------|---------------|
| `recommend_policy` | Predefined roles, includes conditional perms | Minimal roles, required-only, time-bound conditions |
| `analyze_permissions` | Warns on excess >50 | Warns on excess >10, blocks primitive roles |
| `deploy_*` | Allows shared SA | Requires AGENT_IDENTITY, blocks on primitive roles |
| `grant_iam_roles` | Applies directly (with confirm) | Requires approval workflow for cross-project |
| `generate_manifest` | Includes conditional permissions | Separates required/conditional, flags for review |

### Example: Same Code, Two Environments

```python
# agent code calls:
#   bigquery.Client.query()          → bigquery.jobs.create (required)
#                                    → bigquery.tables.getData (conditional)
#   secretmanager.access_secret()    → secretmanager.versions.access (required)
#   storage.Client.list_blobs()      → storage.objects.list (required)
```

**Dev — new principal** (`recommend_policy --env dev --principal serviceAccount:new-agent@proj.iam`):

New SA, no existing grants. Environment has no deny policies in dev project:

```yaml
environment: dev
principal: "serviceAccount:new-agent@proj.iam.gserviceaccount.com"

iam_bindings:
  - role: roles/bigquery.jobUser       # includes jobs.create + tables.getData
    members: ["serviceAccount:new-agent@proj.iam.gserviceaccount.com"]
  - role: roles/secretmanager.secretAccessor
    members: ["serviceAccount:new-agent@proj.iam.gserviceaccount.com"]
  - role: roles/storage.objectViewer
    members: ["serviceAccount:new-agent@proj.iam.gserviceaccount.com"]

to_add:    # same as iam_bindings — everything is new
  - role: roles/bigquery.jobUser
  - role: roles/secretmanager.secretAccessor
  - role: roles/storage.objectViewer
to_remove: []
already_correct: []

denied: []  # no deny policies in dev

warnings:
  - info: "roles/bigquery.jobUser grants 3 unused permissions (acceptable for dev)"

blocked: false
```

**Prod — new principal with deny policies** (`recommend_policy --env prod --principal principal://agents.global.proj-1674.system.id.goog/...`):

New AGENT_IDENTITY principal. Org has a deny policy blocking `secretmanager.versions.access` for agent principals:

```yaml
environment: prod
principal: "principal://agents.global.proj-1674.system.id.goog/..."

iam_bindings:
  - role: roles/bigquery.jobUser
    members: ["principal://agents.global.proj-1674.system.id.goog/..."]
    condition:
      expression: "request.time < timestamp('2026-06-27T00:00:00Z')"
      title: "90-day expiry"
  - role: roles/secretmanager.secretAccessor
    members: ["principal://agents.global.proj-1674.system.id.goog/..."]
  - role: roles/storage.objectViewer
    members: ["principal://agents.global.proj-1674.system.id.goog/..."]

to_add:
  - role: roles/bigquery.jobUser
  - role: roles/secretmanager.secretAccessor
  - role: roles/storage.objectViewer
to_remove: []
already_correct: []

denied:
  - permission: secretmanager.versions.access
    source: "org:123456789"
    deny_rule: "Deny secretmanager.versions.access for principalSet://agents.global.*"
    remediation: "Request exception from org admin or use a service account principal instead"

warnings:
  - block: "secretmanager.versions.access is required by code (src/config.py:8) but blocked by org deny policy. Granting roles/secretmanager.secretAccessor will NOT work."
  - warn: "bigquery.tables.getData is conditional — not granted."

blocked: true
block_reasons:
  - "Required permission secretmanager.versions.access blocked by org deny policy"
```

**Prod — existing principal with excess** (`recommend_policy --env prod --principal principal://agents.global.proj-1674.system.id.goog/...`):

Existing agent has `roles/editor`. recommend_policy pulls live grants and diffs:

```yaml
environment: prod
principal: "principal://agents.global.proj-1674.system.id.goog/..."

iam_bindings:  # the replacement policy
  - role: roles/bigquery.jobUser
  - role: roles/secretmanager.secretAccessor
  - role: roles/storage.objectViewer

to_add: []  # roles/editor already covers everything needed
to_remove:
  - role: roles/editor
    reason: "Primitive role grants 3,847 permissions. Agent needs 4."
already_correct: []  # nothing correctly scoped — editor is a sledgehammer

denied: []  # no deny policies blocking required permissions

warnings:
  - block: "Primitive role roles/editor detected. Replace with least-privilege roles above."
  - warn: "roles/bigquery.jobUser grants 3 unused permissions — consider custom role"
  - info: "Net change: -3,843 excess permissions"

blocked: true
block_reasons:
  - "Primitive role roles/editor in use"
```

---

## Local Agent (Antigravity Extension)

### Architecture

```
┌─────────────────────────────────────────────────┐
│  Antigravity (VS Code fork)                     │
│                                                 │
│  ┌───────────┐  ┌────────────────────────────┐  │
│  │ CodeLens  │  │  Antigravity AI Assistant   │  │
│  │ StatusBar │  │  (native MCP client)        │  │
│  │ DetailPanel│  │         │                  │  │
│  └─────┬─────┘  └─────────┼──────────────────┘  │
│        │                   │ MCP (stdio)         │
│        │ CLI               │                     │
│  ┌─────┴───────────────────┴──────────────────┐  │
│  │        vscode-iamspy extension             │  │
│  │                                            │  │
│  │  ┌──────────┐  ┌───────────────────────┐   │  │
│  │  │ UI Layer │  │  MCP Server (stdio)   │   │  │
│  │  │ codelens │  │                       │   │  │
│  │  │ statusbar│  │  tools/list → 17 tools│   │  │
│  │  │ manifest │  │  tools/call → handler │   │  │
│  │  └────┬─────┘  └───────────┬───────────┘   │  │
│  │       │                    │               │  │
│  │  ┌────┴────────────────────┴────────────┐  │  │
│  │  │  Shared Tool Layer (TypeScript)      │  │  │
│  │  │  scan, deploy, iam, resources, util  │  │  │
│  │  └────┬─────────────────────────────────┘  │  │
│  │       │                                    │  │
│  └───────┼────────────────────────────────────┘  │
│          │ subprocess / REST                     │
│  ┌───────┴──────────┐  ┌─────────────────────┐   │
│  │  iamspy CLI      │  │  gcloud / GCP APIs  │   │
│  │  (Python)        │  │  (REST)             │   │
│  └──────────────────┘  └─────────────────────┘   │
└─────────────────────────────────────────────────┘
```

### MCP Server

The extension hosts an MCP server over stdio that Antigravity's native AI assistant connects to.

**Transport**: stdio (Antigravity launches the extension process, communicates via JSON-RPC over stdin/stdout)

**Protocol**: MCP 1.0 — `initialize`, `tools/list`, `tools/call`, `resources/list`, `resources/read`

**MCP Resources** (read-only context the AI can pull):
- `iamspy://manifest` — current workspace's iam-manifest.yaml
- `iamspy://findings/{file}` — cached scan findings for a file
- `iamspy://services` — service registry (209 services)

### Developer Workflows

**1. Build with awareness**
```
Developer writes code → CodeLens shows permissions inline
Developer asks AI: "what permissions does this file need?"
  → AI calls scan_workspace, returns summary
Developer asks: "generate the IAM manifest"
  → AI calls generate_manifest, writes iam-manifest.yaml
```

**2. Explore project resources**
```
"What agents are deployed in my project?"
  → list_agent_engines(project_id)
"Show me the Cloud Run services"
  → list_cloud_run_services(project_id, region)
"What AI resources do I have?"
  → list_cais_resources(project_id)
```

**3. Deploy from IDE**
```
"Deploy this agent to Agent Engine with AGENT_IDENTITY"
  → scan_workspace (get required permissions)
  → recommend_policy --env dev (generate IAM bindings)
  → deploy_agent_engine (deploy with WIF)
  → grant_iam_roles (apply policy)
```

**4. Pre-deploy audit**
```
"Am I ready to deploy? Check my permissions."
  → scan_workspace → generate_manifest
  → get_iam_policy (current project bindings)
  → analyze_permissions --env dev (diff required vs granted)
  → "You need 3 additional permissions, and roles/editor is over-privileged"
```

### Extension Changes from Current vscode-iamspy

| Current | New |
|---------|-----|
| Shells out to `iamspy scan --json` only | Full tool suite via shared layer |
| No MCP | MCP server over stdio |
| CodeLens + status bar + manifest | Same + deploy + resource listing + IAM analysis |
| Read-only (analyze only) | Read-write (can deploy, grant roles) |
| Python CLI dependency | GCP API calls directly from TypeScript (for resource listing, IAM) |

### Implementation Notes

- **MCP server**: Use `@anthropic-ai/sdk` MCP server library or hand-roll JSON-RPC (it's simple: `tools/list` returns schema, `tools/call` dispatches)
- **GCP API calls**: Use `google-auth-library` for ADC + `node-fetch` for REST. No need for full client libraries — the APIs are simple REST.
- **iamspy integration**: Keep shelling out to `iamspy scan --json` for scanning (Python + tree-sitter). Everything else is REST calls.
- **Deploy tools**: Shell out to `gcloud` for deploy commands. The deploy.py pattern from cost_optimizer_agent shows the flow.

---

## Remote Agent (A2A on Agent Engine)

### Architecture

```
┌──────────────────────────────────────────────┐
│  Agent Engine (Vertex AI)                    │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │  IAMSpy Admin Agent (ADK)             │  │
│  │  Model: gemini-3.1-pro                │  │
│  │  Identity: AGENT_IDENTITY (WIF)       │  │
│  │                                       │  │
│  │  ┌─────────────┐  ┌───────────────┐   │  │
│  │  │ A2A Server  │  │ MCP Server    │   │  │
│  │  │ (agent-to-  │  │ (tool access  │   │  │
│  │  │  agent)     │  │  for IDEs)    │   │  │
│  │  └──────┬──────┘  └──────┬────────┘   │  │
│  │         │                │            │  │
│  │  ┌──────┴────────────────┴─────────┐  │  │
│  │  │  Shared Tool Layer (Python)     │  │  │
│  │  │  Same 17 tools as local agent   │  │  │
│  │  └──────┬──────────────────────────┘  │  │
│  │         │                             │  │
│  └─────────┼─────────────────────────────┘  │
│            │ REST + ADC                     │
│  ┌─────────┴──────────────┐                 │
│  │  GCP APIs              │                 │
│  │  - Resource Manager    │                 │
│  │  - IAM                 │                 │
│  │  - Vertex AI           │                 │
│  │  - Cloud Asset Inv.    │                 │
│  │  - Cloud Run Admin     │                 │
│  │  - GKE                 │                 │
│  └────────────────────────┘                 │
└──────────────────────────────────────────────┘

Callers:
  ├── Antigravity (via MCP, remote)
  ├── Other agents (via A2A)
  ├── ADK Web UI (direct)
  └── CLI / scripts (via A2A client)
```

### Admin / DevOps Workflows

**1. Audit deployed agents**
```
"Audit all agents in project agentengine-478902"
  → list_agent_engines(project_id)
  → for each agent:
      scan_deployed_agent(engine_id)
      get_iam_policy(project, principal=agent_identity)
      analyze_permissions --env prod (required vs granted)
  → Report: agent name, required perms, granted perms, over-granted, missing
```

**2. Find over-permissioned principals**
```
"Which service accounts have more permissions than they need?"
  → list_agent_engines (get all agent identities)
  → for each:
      scan_deployed_agent → required permissions
      get_effective_policy → granted permissions
      analyze_permissions → diff
  → "agent-sa@proj.iam has roles/editor but only needs 4 permissions"
  → recommend_policy --env prod → replacement bindings
```

**3. Troubleshoot access denied**
```
"Agent X is getting PERMISSION_DENIED on bigquery.jobs.create"
  → scan_deployed_agent(X) → confirm it calls bigquery.Client.query()
  → get_effective_policy(principal=X_identity)
  → "X has roles/bigquery.dataViewer which doesn't include bigquery.jobs.create"
  → "X needs roles/bigquery.jobUser. Here's the IAM binding to add."
  → grant_iam_roles (with admin confirmation)
```

**4. Security posture review**
```
"Give me a security overview of all deployed agents"
  → list_agent_engines
  → for each:
      identity type (AGENT_IDENTITY vs shared SA)
      scan → permissions required
      policy → permissions granted
  → Report:
      - Agents using shared SA (recommend AGENT_IDENTITY migration)
      - Over-privileged agents (specific excess roles)
      - Agents with access to sensitive services (KMS, IAM, Secret Manager)
```

### Agent Instructions (persona)

```
You are an IAM security admin agent for Google Cloud. You help DevOps
and security teams audit deployed AI agents, analyze IAM policies, detect
over-permissioning, troubleshoot access issues, and enforce least-privilege.

You are thorough and conservative:
- Flag any use of primitive roles (roles/editor, roles/owner, roles/viewer)
- Flag shared service accounts across multiple agents
- Recommend AGENT_IDENTITY for all Agent Engine deployments
- Always show the diff between required and granted permissions
- Never grant permissions without showing what they allow
- Prefer predefined roles over custom roles when they match exactly
```

### A2A Card

```json
{
  "name": "iamspy-admin",
  "description": "IAM security admin for GCP AI agents. Audits deployed agents, analyzes IAM policies, detects over-permissioning, troubleshoots access, recommends least-privilege policies.",
  "url": "https://<agent-engine-url>",
  "capabilities": {
    "tools": true,
    "multiTurn": true
  },
  "skills": [
    "Audit deployed Agent Engine instances for IAM permissions",
    "Compare required vs granted permissions (over-permissioning detection)",
    "Troubleshoot PERMISSION_DENIED errors",
    "Generate least-privilege IAM policies",
    "Security posture review across projects"
  ]
}
```

---

## Implementation Plan

### Phase 1: Policy primitives + profiles

New package `src/iamspy/policy/`:

```
src/iamspy/policy/
  __init__.py
  primitives.py     # PermissionSet, GrantSet, PolicyDiff, EnvironmentPolicy, PolicyWarning
  profiles.py       # load, validate, inherit profiles from .iamspy/profiles/*.yaml
  defaults.py       # built-in dev/staging/prod profiles (no file needed)
  diff.py           # analyze(PermissionSet, GrantSet, profile) → PolicyDiff
  recommend.py      # recommend(PermissionSet, profile) → EnvironmentPolicy
  roles.py          # map permissions → minimal predefined roles via iam_roles.json
```

### Phase 2: Shared tool layer

Extract tools from `iam_agent/tools.py` into shared package, wire up policy primitives:

```
src/iamspy_tools/
  __init__.py
  scan.py          # scan_workspace, scan_deployed_agent, search_permissions, generate_manifest
  resources.py     # list_agent_engines, list_cloud_run_services, list_gke_clusters, list_cais_resources
  iam.py           # get_iam_policy, get_effective_policy, analyze_permissions, recommend_policy
  deploy.py        # deploy_agent_engine, deploy_cloud_run, grant_iam_roles
  util.py          # shell, list_gcs, download_gcs, create_workspace
```

### Phase 3: Remote agent (A2A on Agent Engine)

Evolve `iam_agent/` into admin agent with security persona. Uses shared tools + policy primitives. Defaults to `prod` profile.

### Phase 4: Local agent (Antigravity MCP extension)

Add MCP server to `vscode-iamspy/`. Uses shared tools + policy primitives. Defaults to `dev` profile, switchable via command palette or `.iamspy.yaml`.

---

## New Tools Not in Current Codebase

These tools need to be built:

| Tool | GCP API | Notes |
|------|---------|-------|
| `list_cloud_run_services` | Cloud Run Admin v2 | `GET /v2/projects/{}/locations/{}/services` |
| `list_gke_clusters` | GKE v1 | `GET /v1/projects/{}/locations/-/clusters` |
| `list_cais_resources` | Cloud Asset Inventory | `POST /v1/{}:searchAllResources` with asset types filter |
| `get_iam_policy` | Resource Manager v3 | `POST /v3/projects/{}:getIamPolicy` |
| `get_effective_policy` | Policy Analyzer | `POST /v1/{}:analyzeIamPolicy` (or IAM API testIamPermissions) |
| `analyze_permissions` | None (local logic) | Set diff: granted ∩ required, granted - required, required - granted |
| `recommend_policy` | None (local logic) | Map permissions → minimal predefined roles via `iam_roles.json` |
| `deploy_agent_engine` | Vertex AI v1beta1 | Pattern from `gcp_cost_optimizer_agent/deploy.py` |
| `deploy_cloud_run` | Cloud Run Admin v2 | Or shell out to `gcloud run deploy` |
| `grant_iam_roles` | Resource Manager v3 | `POST /v3/projects/{}:setIamPolicy` (additive merge) |
| `get_deny_policies` | IAM v2 | `GET /v2/policies` at org/folder/project levels |
| `get_org_constraints` | Org Policy v2 | `GET /v2/projects/{}/policies`, `GET /v2/folders/{}/policies`, `GET /v2/organizations/{}/policies` |

---

## Security Considerations

- **Local agent**: Runs with developer's ADC. Can only do what the developer can do. Deploy/grant tools require explicit confirmation in the AI assistant conversation.
- **Remote agent**: Runs with AGENT_IDENTITY. Scoped to `securityReviewer` + `projectIamAdmin`. Cannot create resources, only read + modify IAM.
- **grant_iam_roles**: Both agents must show the full diff before applying. Never auto-apply.
- **deploy_***: Show what will be deployed, confirm before executing.
- **Org-wide queries**: Remote agent only. Local agent cannot see across projects unless the developer has org-level roles.
