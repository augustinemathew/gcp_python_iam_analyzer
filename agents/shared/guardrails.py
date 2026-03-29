"""Agent guardrails — admin-defined boundaries for agent permissions.

Uses the permission ring classifier as the source of truth for permission
severity. Ring 0 (CRITICAL) permissions are blocked. Ring 1 (SENSITIVE)
permissions are warned. Roles and identity constraints use their own rules.

Ring classification: agents/shared/permission_rings.py
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import StrEnum

from agents.shared.permission_rings import Ring, classify


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

    # Permission patterns (glob) that are denied
    denied_permission_patterns: frozenset[str] = frozenset()

    # Roles that are never acceptable for agents
    denied_roles: frozenset[str] = frozenset()

    # Maximum number of permissions an agent can request
    max_permissions: int = 50

    # Ring thresholds: which rings to block vs warn
    block_rings: frozenset[Ring] = frozenset({Ring.CRITICAL})
    warn_rings: frozenset[Ring] = frozenset({Ring.SENSITIVE})

    # Identity constraints
    require_agent_identity: bool = True
    allow_shared_sa: bool = False
    allow_impersonation: bool = False
    allow_dwd: bool = False

    # Resource boundaries
    allowed_services: frozenset[str] | None = None  # None = all allowed
    denied_services: frozenset[str] = frozenset()


# ── Roles too broad for any agent ─────────────────────────────────────

DENIED_ROLES = frozenset({
    "roles/owner",
    "roles/editor",
    "roles/viewer",
    "roles/iam.securityAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/resourcemanager.organizationAdmin",
})


# ── Ring → Category mapping ───────────────────────────────────────────

_RING_TO_CATEGORY = {
    Ring.CRITICAL: Category.PRIVILEGE_ESCALATION,
    Ring.SENSITIVE: Category.DATA_EXFILTRATION,
    Ring.MUTATING: Category.DESTRUCTIVE_ACTION,
    Ring.READ: Category.OVERPERMISSION,
}

_RING_REMEDIATION = {
    Ring.CRITICAL: "Remove this permission. Agents must not modify IAM policies or create credentials.",
    Ring.SENSITIVE: "Ensure this is necessary. Restrict to specific resources via IAM conditions.",
    Ring.MUTATING: "Review whether this state change is needed.",
    Ring.READ: "",
}


# ── Default policies ──────────────────────────────────────────────────


def default_dev_guardrails() -> GuardrailPolicy:
    """Dev: block Ring 0, warn nothing. Broad roles blocked."""
    return GuardrailPolicy(
        denied_roles=frozenset({"roles/owner", "roles/editor"}),
        max_permissions=100,
        block_rings=frozenset({Ring.CRITICAL}),
        warn_rings=frozenset(),
        require_agent_identity=False,
        allow_shared_sa=True,
        allow_impersonation=False,
        allow_dwd=False,
    )


def default_prod_guardrails() -> GuardrailPolicy:
    """Prod: block Ring 0, warn Ring 1. Block high-impact destructive ops."""
    return GuardrailPolicy(
        denied_roles=DENIED_ROLES,
        denied_permission_patterns=frozenset({
            # High-impact destructive ops — blocked even though Ring 2
            "resourcemanager.projects.delete",
            "resourcemanager.folders.delete",
            "cloudkms.cryptoKeyVersions.destroy",
            "secretmanager.versions.destroy",
            "storage.buckets.delete",
            "bigquery.datasets.delete",
            "spanner.databases.drop",
            "bigtable.instances.delete",
            "container.clusters.delete",
        }),
        max_permissions=50,
        block_rings=frozenset({Ring.CRITICAL}),
        warn_rings=frozenset({Ring.SENSITIVE}),
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
    """Evaluate permissions against guardrails."""
    if policy is None:
        policy = default_prod_guardrails() if environment == "prod" else default_dev_guardrails()

    violations: list[Violation] = []

    _check_permission_rings(permissions, policy, violations)
    _check_denied_patterns(permissions, policy, violations)
    _check_denied_roles(roles, policy, violations)
    _check_permission_count(permissions, policy, violations)
    _check_identity_constraints(identity_type, policy, violations)
    _check_service_boundaries(permissions, policy, violations)

    violations.sort(key=lambda v: {"block": 0, "warn": 1, "info": 2}[v.severity])
    return violations


def _check_permission_rings(
    permissions: set[str], policy: GuardrailPolicy, violations: list[Violation],
) -> None:
    """Check each permission's ring against block/warn thresholds."""
    for perm in sorted(permissions):
        ring = classify(perm)

        if ring in policy.block_rings:
            violations.append(Violation(
                severity=Severity.BLOCK,
                category=_RING_TO_CATEGORY[ring],
                rule=f"ring_{ring.value}_blocked",
                message=f"Permission '{perm}' is Ring {ring.value} ({ring.name}) — not allowed for agents",
                permission=perm,
                remediation=_RING_REMEDIATION[ring],
            ))
        elif ring in policy.warn_rings:
            violations.append(Violation(
                severity=Severity.WARN,
                category=_RING_TO_CATEGORY[ring],
                rule=f"ring_{ring.value}_warning",
                message=f"Permission '{perm}' is Ring {ring.value} ({ring.name}) — review required",
                permission=perm,
                remediation=_RING_REMEDIATION[ring],
            ))


def _check_denied_patterns(
    permissions: set[str], policy: GuardrailPolicy, violations: list[Violation],
) -> None:
    """Check permissions against denied glob patterns."""
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


def _check_denied_roles(
    roles: list[str] | None, policy: GuardrailPolicy, violations: list[Violation],
) -> None:
    """Check roles against denied list."""
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


def _check_permission_count(
    permissions: set[str], policy: GuardrailPolicy, violations: list[Violation],
) -> None:
    """Check total permission count against max."""
    if len(permissions) > policy.max_permissions:
        violations.append(Violation(
            severity=Severity.WARN,
            category=Category.OVERPERMISSION,
            rule="max_permissions",
            message=f"Agent requests {len(permissions)} permissions (max: {policy.max_permissions})",
            remediation="Review whether all permissions are necessary",
        ))


def _check_identity_constraints(
    identity_type: str | None, policy: GuardrailPolicy, violations: list[Violation],
) -> None:
    """Check identity type against policy constraints."""
    if not identity_type:
        return

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


def _check_service_boundaries(
    permissions: set[str], policy: GuardrailPolicy, violations: list[Violation],
) -> None:
    """Check permissions against service allow/deny lists."""
    for perm in sorted(permissions):
        service = perm.split(".")[0] if "." in perm else ""
        if not service:
            continue

        if service in policy.denied_services:
            violations.append(Violation(
                severity=Severity.BLOCK,
                category=Category.RESOURCE_BOUNDARY,
                rule="denied_service",
                message=f"Service '{service}' is not allowed for agents",
                permission=perm,
            ))

        if policy.allowed_services is not None and service not in policy.allowed_services:
            violations.append(Violation(
                severity=Severity.BLOCK,
                category=Category.RESOURCE_BOUNDARY,
                rule="service_not_allowed",
                message=f"Service '{service}' is not in the allowed list",
                permission=perm,
            ))
