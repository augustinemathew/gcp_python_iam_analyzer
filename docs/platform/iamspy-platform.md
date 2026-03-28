# IAMSpy Platform: IDE Agent + Remote Admin Agent

## Overview

Two agents sharing the same tools and libraries:

| | Developer Agent (IDE) | Admin Agent (Agent Engine) |
|---|---|---|
| **Persona** | Developer building & deploying | Security admin / DevOps |
| **Runtime** | MCP server (Antigravity/VS Code) + ADK agent for testing | ADK agent on Agent Engine, uses shared tools |
| **Auth** | Developer's ADC | AGENT_IDENTITY (WIF) |
| **Scope** | Single project, active codebase | Org-wide, multiple projects |
| **Primary flow** | Write code → understand permissions → deploy | Audit deployed agents → recommend policies → enforce guardrails |

Both agents import from `iamspy_mcp.shared.tools`. The MCP server exposes them for IDE integration. The admin agent (evolved `iam_agent/`) calls them directly.

---

## Developer Experience (Antigravity / VS Code)

The developer flow is a single continuous loop, not separate phases:

### The Loop

```
Write code
  ↓
CodeLens shows permissions inline: 🔑 storage.objects.get [app]
  ↓
Ask AI: "what does my code need? can I deploy?"
  ↓
AI scans code → checks project IAM → shows gaps
  ↓
AI generates manifest + deploy commands
  ↓
Developer deploys (or requests missing permissions)
  ↓
If PERMISSION_DENIED → troubleshoot in same chat
```

### What the AI Can Do (MCP Tools)

**Understand the code:**
- `scan_files` — what GCP calls does this code make? what permissions? which identity?
- `search_permissions` — look up any permission in the 25K method database
- `generate_manifest` — produce the v2 manifest (per-identity permissions + services)

**Understand the project:**
- `list_agent_engines` — what agents are deployed?
- `list_cloud_run_services` — what services are running?
- `list_ai_resources` — what Vertex AI resources exist?
- `get_project_iam_policy` — what IAM bindings exist?

**Act on it:**
- `analyze_permissions` — diff code requirements vs project IAM (what's missing?)
- `troubleshoot_access` — diagnose PERMISSION_DENIED (deny policies, missing roles)
- `deploy_agent_engine` / `deploy_cloud_run` — generate deploy commands
- `grant_iam_roles` — generate IAM grant commands
- `check_guardrails` — validate permissions against security policy

### Ambient Awareness (VS Code Extension)

Runs without asking — visual layer over the code:
- **CodeLens**: permission + identity above each GCP SDK call
- **Status bar**: aggregate permission count, click for summary
- **Detail panel**: full permission breakdown with GCP docs links

### IDE Integration

**Antigravity** (native MCP): AI assistant connects to `iamspy_mcp.local.server` over stdio.

**VS Code** (no native agent loop): MCP server still works for tools. Agent loop via ADK web UI or CLI agent for now. Evaluate OSS agent loops (Cline, Continue, etc.) for future integration.

**Both**: CodeLens/status bar from existing `vscode-iamspy` extension work unchanged.

---

## Admin Agent (Agent Engine)

The existing `iam_agent/` evolves to use `iamspy_mcp.shared.tools` directly. Same tools, security admin persona, deployed on Agent Engine with AGENT_IDENTITY.

### Admin Workflows

**Audit deployed agents:**
```
→ list_agent_engines
→ for each: scan code + get IAM policy + analyze_permissions
→ Report: over-permissioned agents, shared SAs, missing AGENT_IDENTITY
```

**Troubleshoot access denied:**
```
→ troubleshoot_access(permission)
→ Checks caller permissions, deny policies, suggests fix
```

**Security posture review:**
```
→ list all agents + their permissions vs grants
→ Flag primitive roles, shared SAs, sensitive permissions
```

---

## Shared Tool Layer

```
iamspy_mcp/
  shared/
    gcp.py                   # REST wrappers (ADC auth)
    permission_rings.py      # Permission classification (Ring 0-3)
    guardrails.py            # Guardrail evaluation
    tools/
      scan.py                # scan, manifest, search
      iam.py                 # analyze, troubleshoot
      resources.py           # list agents, run services, AI resources
      deploy.py              # deploy, grant roles
  local/
    server.py                # MCP server for IDE (13 tools)
```

Both the MCP server and the ADK admin agent import from `iamspy_mcp.shared`.

---

## Manifest Format (v2)

Per-identity permissions. Single services list at project level.

```yaml
version: '2'
services:
  enable:
  - secretmanager.googleapis.com
  - storage.googleapis.com
  - drive.googleapis.com

identities:
  app:
    permissions:
      required:
      - secretmanager.versions.access
      - storage.buckets.list
      conditional: []

  user:
    oauth_scopes:
    - https://www.googleapis.com/auth/drive.readonly
    - https://www.googleapis.com/auth/devstorage.read_only
    permissions:
      required:
      - storage.buckets.list
      conditional: []

permissions:
  required: []
  conditional: []
```

---

## Permission Ring Classification

All 12,879 GCP IAM permissions classified into 4 rings:

| Ring | Name | Count | % | Description |
|---|---|---|---|---|
| 0 | CRITICAL | 309 | 2.4% | Privilege escalation (setIamPolicy, SA key creation) |
| 1 | SENSITIVE | 98 | 0.8% | Secrets, crypto, data export |
| 2 | MUTATING | 7,400 | 57.5% | All state changes (create, update, delete) |
| 3 | READ | 5,072 | 39.4% | Read-only (get, list) |

API: `classify(permission) → Ring`

Used for deny policy generation and guardrail evaluation. Ring 0 permissions are always denied for agents. Ring 1 requires justification.

---

## Policy Design Primitives

### `PermissionSet`
What the code needs (from scan). Split by identity context.

### `GrantSet`
What a principal currently has (from IAM policy).

### `DenyContext`
What the environment blocks (org/folder/project deny policies).

### `PolicyDiff`
Gap analysis: missing, excess, matched, denied.

### `EnvironmentPolicy`
Shaped output: iam_bindings + warnings + blocked flag.

`recommend_policy` always takes a principal. For new principals, checks deny context. For existing principals, diffs against live grants.

---

## What's Built

- [x] Credential provenance analyzer (97.9% accuracy)
- [x] Scanner integration (identity/credential fields on findings)
- [x] CLI output (terminal + JSON with identity)
- [x] v2 manifest format (per-identity permissions)
- [x] MCP server with 13 tools
- [x] Permission ring classifier (12,879 permissions)
- [x] Guardrails evaluation engine
- [x] Shared tool layer for both agents
- [x] Delegated identity experiment (validated on Cloud Run)

## What's Next

- [ ] ADK agent prototype for testing the developer flow end-to-end
- [ ] Eval set: canonical scenarios with expected policy output
- [ ] Wire admin agent (iam_agent/) to shared tools
- [ ] Deny policy generation from ring classification
- [ ] Principal Access Boundary (PAB) recommendations
- [ ] VS Code extension: add identity context to CodeLens display
- [ ] Antigravity MCP integration testing
