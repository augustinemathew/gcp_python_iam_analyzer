# IAMSpy Platform — Technical Design

> For product overview see [product.md](product.md).
> For action items see [code-review-action-items.md](code-review-action-items.md).

## Policy Design Primitives

### `PermissionSet`
What the code needs (from scan). Split by identity context.

```python
@dataclass(frozen=True)
class PermissionSet:
    required: frozenset[str]
    conditional: frozenset[str]
    services: frozenset[str]
    sources: dict[str, list[SourceLocation]]
    delegated: DelegatedPermissions | None  # OAuth scopes + Workspace APIs
```

### `GrantSet`
What a principal currently has (from IAM policy + role expansion).

```python
@dataclass(frozen=True)
class GrantSet:
    permissions: frozenset[str]
    roles: list[RoleBinding]
    inherited_from: dict[str, str]
```

### `DenyContext`
What the environment blocks (org/folder/project deny policies).

```python
@dataclass(frozen=True)
class DenyContext:
    deny_rules: list[DenyRule]
    org_constraints: list[OrgConstraint]

    def blocked_permissions(self, principal: str) -> frozenset[str]: ...
```

### `PolicyDiff`
Gap analysis: `PermissionSet` vs `GrantSet` vs `DenyContext`.

```python
@dataclass(frozen=True)
class PolicyDiff:
    missing: frozenset[str]
    excess: frozenset[str]
    matched: frozenset[str]
    denied: frozenset[str]  # blocked by deny policy
    overprivileged_roles: list[RoleAnalysis]
    suggested_roles: list[str]
```

### `EnvironmentPolicy`
Shaped output: `PermissionSet` + principal + environment → deployable policy.

```python
@dataclass(frozen=True)
class EnvironmentPolicy:
    environment: str
    principal: str
    iam_bindings: list[IamBinding]
    to_add: list[IamBinding]
    to_remove: list[IamBinding]
    already_correct: list[IamBinding]
    denied: list[DeniedPermission]
    warnings: list[PolicyWarning]
    blocked: bool
    block_reasons: list[str]
```

## `recommend_policy` — Always Takes a Principal

Two modes:
1. **New principal** (no grants): generates ideal policy, checks deny context
2. **Existing principal** (has grants): diffs against live grants + deny context

```
recommend_policy(PermissionSet, principal, profile)
  → build DenyContext (org → folder → project)
  → get GrantSet (role expansion via IAM API)
  → PolicyDiff
  → EnvironmentPolicy
```

## Environment Profiles

Workspace config (`.iamspy/workspace.yaml`) drives policy shape per environment.

**Dev**: Predefined roles, conditional permissions granted upfront, shared SA ok.
**Prod**: Minimal roles, required-only, AGENT_IDENTITY required, time-bound conditions.

## Identity Types

| Type | Use Case | How Detected in Code |
|---|---|---|
| `service_account` | Cloud Run, GCE, GKE | `google.auth.default()`, no `credentials=` arg |
| `agent_identity` | Agent Engine (WIF) | Workspace config, not in code |
| `oauth` (delegated) | User-facing apps | `google.oauth2.credentials.Credentials`, `Flow.from_client_config` |
| `impersonated` | SA impersonation | `impersonated_credentials.Credentials`, `.with_subject()` |

## Plan → Execute Flow

Mutating operations go through a confirmation gate:

```
plan_iam_changes(paths, environment)
  → IamPlan {plan_id, actions: [create_sa, grant_role, enable_service]}

# Developer reviews plan

execute_iam_plan(plan_id)
  → Creates SA, grants roles, enables services
  → Auto-updates workspace.yaml with new principal
```

## New GCP API Tools

| Tool | GCP API | Method |
|---|---|---|
| `list_agent_engines` | Vertex AI v1beta1 | `GET /reasoningEngines` |
| `list_cloud_run_services` | Cloud Run v2 | `GET /services` |
| `get_iam_policy` | Resource Manager v3 | `POST /projects/{id}:getIamPolicy` |
| `get_deny_policies` | IAM v2 | `GET /v2/policies/.../denypolicies` |
| `list_enabled_services` | Service Usage v1 | `GET /services?filter=state:ENABLED` |
| `enable_services` | Service Usage v1 | `POST /services:batchEnable` |
| `list_service_accounts` | IAM v1 | `GET /serviceAccounts` |
| `create_service_account` | IAM v1 | `POST /serviceAccounts` |
| `add_iam_binding` | Resource Manager v3 | `POST /projects/{id}:setIamPolicy` (read-modify-write) |
| `_get_role_permissions` | IAM v1 | `GET /v1/roles/{role}` (cached) |
| `test_iam_permissions` | Resource Manager v3 | `POST /projects/{id}:testIamPermissions` |
