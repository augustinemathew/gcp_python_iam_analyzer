"""Agent guardrails — admin-defined boundaries for agent permissions.

Guardrails define what agents are NEVER allowed to do, regardless of what
their code requires. They're the admin's safety net against:
- Agent developers accidentally requesting dangerous permissions
- Agents performing destructive operations
- Privilege escalation (agent grants itself more access)
- Data exfiltration (agent exports data to external destinations)

Guardrails are evaluated against a manifest to produce violations.
A violation blocks deployment in prod, warns in dev.

Guardrail categories:
1. Denied permissions — specific IAM permissions that are never allowed
2. Denied roles — roles too broad for any agent
3. Resource boundaries — what resources agents can/cannot touch
4. Identity constraints — how agents must authenticate
5. Destructive action rules — operations that require extra scrutiny
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    BLOCK = "block"
    WARN = "warn"
    INFO = "info"


class Category(StrEnum):
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DESTRUCTIVE_ACTION = "destructive_action"
    DATA_EXFILTRATION = "data_exfiltration"
    OVERPERMISSION = "overpermission"
    IDENTITY = "identity"
    RESOURCE_BOUNDARY = "resource_boundary"


@dataclass(frozen=True)
class Violation:
    """A guardrail violation found during policy evaluation."""

    severity: Severity
    category: Category
    rule: str
    message: str
    permission: str | None = None
    role: str | None = None
    remediation: str = ""


@dataclass(frozen=True)
class GuardrailPolicy:
    """Admin-defined guardrails for agent permissions."""

    # Permissions that no agent may ever have
    denied_permissions: frozenset[str] = frozenset()

    # Permission patterns (glob) that are denied
    denied_permission_patterns: frozenset[str] = frozenset()

    # Roles that are never acceptable for agents
    denied_roles: frozenset[str] = frozenset()

    # Maximum number of permissions an agent can request
    max_permissions: int = 50

    # Identity constraints
    require_agent_identity: bool = True
    allow_shared_sa: bool = False
    allow_impersonation: bool = False
    allow_dwd: bool = False

    # Resource boundaries
    allowed_services: frozenset[str] | None = None  # None = all allowed
    denied_services: frozenset[str] = frozenset()

    # Custom rules
    custom_rules: list[str] = field(default_factory=list)


# ── Built-in guardrail rules ──────────────────────────────────────────

# Permissions that enable privilege escalation — an agent with these can
# grant itself (or others) more access than intended.
PRIVILEGE_ESCALATION_PERMISSIONS = frozenset({
    # IAM policy modification
    "resourcemanager.projects.setIamPolicy",
    "resourcemanager.folders.setIamPolicy",
    "resourcemanager.organizations.setIamPolicy",
    # Service account key creation (can exfil long-lived credentials)
    "iam.serviceAccountKeys.create",
    "iam.serviceAccountKeys.get",
    # Service account creation (can create new identities)
    "iam.serviceAccounts.create",
    # Service account token creation (can mint tokens for other SAs)
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.signJwt",
    "iam.serviceAccounts.implicitDelegation",
    # Role modification
    "iam.roles.create",
    "iam.roles.update",
    # Org policy modification
    "orgpolicy.policy.set",
})

# Permissions that enable destructive operations at scale
DESTRUCTIVE_PERMISSIONS = frozenset({
    # Project deletion
    "resourcemanager.projects.delete",
    # Bulk data deletion
    "bigquery.datasets.delete",
    "storage.buckets.delete",
    "bigtable.instances.delete",
    "spanner.databases.drop",
    "firestore.databases.delete",
    # Compute destruction
    "compute.instances.delete",
    "compute.disks.delete",
    "container.clusters.delete",
    # Secret/key destruction
    "secretmanager.secrets.delete",
    "cloudkms.cryptoKeys.destroy",
    "cloudkms.cryptoKeyVersions.destroy",
})

# Permissions that enable data exfiltration
EXFILTRATION_PERMISSIONS = frozenset({
    # Export data to external destinations
    "bigquery.tables.export",
    # Read all data (when combined with network access)
    "storage.objects.list",
    "storage.objects.get",
    # Access secrets
    "secretmanager.versions.access",
    # Access KMS keys (can decrypt data)
    "cloudkms.cryptoKeyVersions.useToDecrypt",
})

# Roles too broad for any agent
DENIED_ROLES = frozenset({
    "roles/owner",
    "roles/editor",
    "roles/viewer",  # surprisingly broad — grants read on everything
    "roles/iam.securityAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/resourcemanager.organizationAdmin",
})


# ── Default policies ──────────────────────────────────────────────────


def default_dev_guardrails() -> GuardrailPolicy:
    """Default guardrails for dev environments.

    Blocks privilege escalation and project deletion.
    Allows most other operations for iteration speed.
    """
    return GuardrailPolicy(
        denied_permissions=PRIVILEGE_ESCALATION_PERMISSIONS | frozenset({
            "resourcemanager.projects.delete",
        }),
        denied_roles=frozenset({
            "roles/owner",
            "roles/editor",
        }),
        max_permissions=100,
        require_agent_identity=False,
        allow_shared_sa=True,
        allow_impersonation=False,
        allow_dwd=False,
    )


def default_prod_guardrails() -> GuardrailPolicy:
    """Default guardrails for production environments.

    Strict: blocks privilege escalation, destructive actions, and
    requires AGENT_IDENTITY. Exfiltration permissions are flagged
    as warnings (they may be legitimately needed).
    """
    return GuardrailPolicy(
        denied_permissions=PRIVILEGE_ESCALATION_PERMISSIONS | DESTRUCTIVE_PERMISSIONS,
        denied_roles=DENIED_ROLES,
        max_permissions=50,
        require_agent_identity=True,
        allow_shared_sa=False,
        allow_impersonation=False,
        allow_dwd=False,
    )


# ── Evaluation ────────────────────────────────────────────────────────


def evaluate_guardrails(
    permissions: set[str],
    roles: list[str] | None = None,
    identity_type: str | None = None,
    policy: GuardrailPolicy | None = None,
    environment: str = "prod",
) -> list[Violation]:
    """Evaluate permissions against guardrails.

    Args:
        permissions: The IAM permissions the agent requests.
        roles: Specific roles being granted (if known).
        identity_type: 'agent_identity', 'service_account', etc.
        policy: Custom guardrail policy. If None, uses default for environment.
        environment: 'dev', 'staging', or 'prod'.

    Returns:
        List of violations, sorted by severity (block first).
    """
    if policy is None:
        policy = default_prod_guardrails() if environment == "prod" else default_dev_guardrails()

    violations: list[Violation] = []

    # Check denied permissions
    for perm in sorted(permissions):
        if perm in policy.denied_permissions:
            category = _categorize_permission(perm)
            violations.append(Violation(
                severity=Severity.BLOCK,
                category=category,
                rule="denied_permission",
                message=f"Permission '{perm}' is not allowed for agents",
                permission=perm,
                remediation=_remediation_for_category(category),
            ))

    # Check denied permission patterns
    import fnmatch
    for perm in sorted(permissions):
        for pattern in policy.denied_permission_patterns:
            if fnmatch.fnmatch(perm, pattern):
                violations.append(Violation(
                    severity=Severity.BLOCK,
                    category=Category.OVERPERMISSION,
                    rule="denied_permission_pattern",
                    message=f"Permission '{perm}' matches denied pattern '{pattern}'",
                    permission=perm,
                ))

    # Check denied roles
    for role in (roles or []):
        if role in policy.denied_roles:
            violations.append(Violation(
                severity=Severity.BLOCK,
                category=Category.OVERPERMISSION,
                rule="denied_role",
                message=f"Role '{role}' is too broad for agents",
                role=role,
                remediation="Use a predefined narrow role or custom role instead",
            ))

    # Check permission count
    if len(permissions) > policy.max_permissions:
        violations.append(Violation(
            severity=Severity.WARN,
            category=Category.OVERPERMISSION,
            rule="max_permissions",
            message=f"Agent requests {len(permissions)} permissions (max: {policy.max_permissions})",
            remediation="Review whether all permissions are necessary",
        ))

    # Check identity constraints
    if identity_type:
        if policy.require_agent_identity and identity_type != "agent_identity":
            violations.append(Violation(
                severity=Severity.BLOCK,
                category=Category.IDENTITY,
                rule="require_agent_identity",
                message=f"Agent uses '{identity_type}' but AGENT_IDENTITY is required",
                remediation="Deploy with identity_type=AGENT_IDENTITY",
            ))

        if not policy.allow_shared_sa and identity_type == "service_account":
            violations.append(Violation(
                severity=Severity.BLOCK,
                category=Category.IDENTITY,
                rule="no_shared_sa",
                message="Shared service accounts are not allowed",
                remediation="Use AGENT_IDENTITY for per-agent isolation",
            ))

        if not policy.allow_impersonation and identity_type == "impersonated":
            violations.append(Violation(
                severity=Severity.BLOCK,
                category=Category.IDENTITY,
                rule="no_impersonation",
                message="SA impersonation is not allowed for agents",
                remediation="Use AGENT_IDENTITY instead of impersonating another SA",
            ))

    # Check exfiltration risk (warn, don't block — may be legitimate)
    exfil_perms = permissions & EXFILTRATION_PERMISSIONS
    if exfil_perms:
        violations.append(Violation(
            severity=Severity.WARN,
            category=Category.DATA_EXFILTRATION,
            rule="exfiltration_risk",
            message=f"Agent has {len(exfil_perms)} permissions that could enable data exfiltration: {', '.join(sorted(exfil_perms))}",
            remediation="Ensure these are necessary and add resource-level restrictions",
        ))

    # Check denied services
    if policy.denied_services:
        for perm in sorted(permissions):
            service = perm.split(".")[0] if "." in perm else ""
            if service in policy.denied_services:
                violations.append(Violation(
                    severity=Severity.BLOCK,
                    category=Category.RESOURCE_BOUNDARY,
                    rule="denied_service",
                    message=f"Service '{service}' is not allowed for agents",
                    permission=perm,
                ))

    # Check allowed services (if specified)
    if policy.allowed_services is not None:
        for perm in sorted(permissions):
            service = perm.split(".")[0] if "." in perm else ""
            if service and service not in policy.allowed_services:
                violations.append(Violation(
                    severity=Severity.BLOCK,
                    category=Category.RESOURCE_BOUNDARY,
                    rule="service_not_allowed",
                    message=f"Service '{service}' is not in the allowed list",
                    permission=perm,
                ))

    # Sort: blocks first, then warns, then info
    violations.sort(key=lambda v: {"block": 0, "warn": 1, "info": 2}[v.severity])
    return violations


def _categorize_permission(perm: str) -> Category:
    """Categorize a denied permission."""
    if perm in PRIVILEGE_ESCALATION_PERMISSIONS:
        return Category.PRIVILEGE_ESCALATION
    if perm in DESTRUCTIVE_PERMISSIONS:
        return Category.DESTRUCTIVE_ACTION
    if perm in EXFILTRATION_PERMISSIONS:
        return Category.DATA_EXFILTRATION
    return Category.OVERPERMISSION


def _remediation_for_category(category: Category) -> str:
    """Suggest remediation for a violation category."""
    return {
        Category.PRIVILEGE_ESCALATION: "Remove this permission. Agents must not be able to modify IAM policies or create credentials.",
        Category.DESTRUCTIVE_ACTION: "Remove this permission. Use a separate admin workflow for destructive operations.",
        Category.DATA_EXFILTRATION: "Restrict to specific resources via IAM conditions, or remove if not needed.",
        Category.OVERPERMISSION: "Use a narrower role or custom role.",
        Category.IDENTITY: "Use AGENT_IDENTITY for production deployments.",
        Category.RESOURCE_BOUNDARY: "Restrict agent to approved services only.",
    }.get(category, "Review and remediate.")
