"""Deterministic role mapper — finds minimum predefined roles for a permission set.

Uses the IAM API (roles.get) to fetch permissions per role, then runs
greedy set cover to find the smallest set of predefined roles that
covers all required permissions.

This replaces LLM-driven role selection with a deterministic algorithm.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agents.shared.tools.iam import _get_role_permissions


@dataclass(frozen=True)
class RoleRecommendation:
    """A recommended IAM role with justification."""

    role: str
    covers: list[str]
    excess_count: int
    reason: str


# ── Candidate role discovery ───────────────────────────────────────────

# Map permission service prefix to candidate predefined roles.
# These are the commonly used narrow roles per service.
# The mapper tries these first before falling back to broader roles.
_SERVICE_CANDIDATE_ROLES: dict[str, list[str]] = {
    "storage": [
        "roles/storage.objectViewer",
        "roles/storage.objectCreator",
        "roles/storage.objectUser",
        "roles/storage.objectAdmin",
        "roles/storage.admin",
    ],
    "bigquery": [
        "roles/bigquery.dataViewer",
        "roles/bigquery.dataEditor",
        "roles/bigquery.jobUser",
        "roles/bigquery.user",
        "roles/bigquery.admin",
    ],
    "secretmanager": [
        "roles/secretmanager.secretAccessor",
        "roles/secretmanager.secretVersionAdder",
        "roles/secretmanager.admin",
    ],
    "cloudkms": [
        "roles/cloudkms.cryptoKeyEncrypter",
        "roles/cloudkms.cryptoKeyDecrypter",
        "roles/cloudkms.cryptoKeyEncrypterDecrypter",
        "roles/cloudkms.admin",
    ],
    "compute": [
        "roles/compute.viewer",
        "roles/compute.instanceAdmin.v1",
        "roles/compute.admin",
    ],
    "container": [
        "roles/container.viewer",
        "roles/container.developer",
        "roles/container.admin",
    ],
    "run": [
        "roles/run.viewer",
        "roles/run.invoker",
        "roles/run.developer",
        "roles/run.admin",
    ],
    "cloudasset": [
        "roles/cloudasset.viewer",
        "roles/cloudasset.owner",
    ],
    "aiplatform": [
        "roles/aiplatform.viewer",
        "roles/aiplatform.user",
        "roles/aiplatform.admin",
    ],
    "iam": [
        "roles/iam.serviceAccountUser",
        "roles/iam.serviceAccountTokenCreator",
    ],
    "resourcemanager": [
        "roles/resourcemanager.projectViewer",
    ],
    "pubsub": [
        "roles/pubsub.viewer",
        "roles/pubsub.publisher",
        "roles/pubsub.subscriber",
        "roles/pubsub.editor",
    ],
    "spanner": [
        "roles/spanner.databaseReader",
        "roles/spanner.databaseUser",
        "roles/spanner.databaseAdmin",
    ],
    "firestore": [
        "roles/datastore.viewer",
        "roles/datastore.user",
    ],
}


def _get_candidate_roles(permissions: set[str]) -> list[str]:
    """Get candidate predefined roles for a set of permissions."""
    services = {p.split(".")[0] for p in permissions if "." in p}
    candidates: list[str] = []
    for service in sorted(services):
        candidates.extend(_SERVICE_CANDIDATE_ROLES.get(service, []))
    return candidates


# ── Greedy set cover ───────────────────────────────────────────────────


def permissions_to_roles(
    required: set[str],
    conditional: set[str] | None = None,
) -> list[RoleRecommendation]:
    """Find the minimum set of predefined roles covering the required permissions.

    Algorithm:
    1. Get candidate roles for the services involved
    2. Fetch permissions for each candidate role (via IAM API, cached)
    3. Greedy set cover: pick the role that covers the most uncovered perms
    4. After covering required, note which conditional perms come free

    Args:
        required: Permissions that must be covered.
        conditional: Permissions that are nice-to-have (covered if a role
                     already grants them, but won't add a role just for these).

    Returns:
        Ordered list of role recommendations with coverage details.
    """
    if not required:
        return []

    conditional = conditional or set()
    uncovered = set(required)
    candidates = _get_candidate_roles(required | conditional)

    # Fetch permissions for all candidates
    role_perms: dict[str, set[str]] = {}
    for role in candidates:
        perms = _get_role_permissions(role)
        if perms:
            role_perms[role] = set(perms)

    selected: list[RoleRecommendation] = []

    # Greedy set cover
    while uncovered:
        best_role = None
        best_coverage: set[str] = set()
        best_total_perms = float("inf")

        for role, perms in role_perms.items():
            coverage = uncovered & perms
            if len(coverage) > len(best_coverage):
                best_role = role
                best_coverage = coverage
                best_total_perms = len(perms)
            elif len(coverage) == len(best_coverage) and len(coverage) > 0:
                # Prefer narrower role (fewer total permissions)
                if len(perms) < best_total_perms:
                    best_role = role
                    best_coverage = coverage
                    best_total_perms = len(perms)

        if best_role is None:
            # No candidate covers remaining permissions
            break

        # Select this role
        uncovered -= best_coverage
        all_role_perms = role_perms[best_role]

        # Check which conditional perms come free
        conditional_covered = conditional & all_role_perms
        excess = len(all_role_perms) - len(best_coverage) - len(conditional_covered)

        covers = sorted(best_coverage)
        cond_bonus = sorted(conditional_covered)
        reason_parts = [f"covers {', '.join(covers)}"]
        if cond_bonus:
            reason_parts.append(f"also covers conditional: {', '.join(cond_bonus)}")

        selected.append(RoleRecommendation(
            role=best_role,
            covers=covers + cond_bonus,
            excess_count=max(0, excess),
            reason="; ".join(reason_parts),
        ))

        # Remove this role from candidates
        del role_perms[best_role]

    # Report uncovered permissions (need custom role or different candidate)
    if uncovered:
        selected.append(RoleRecommendation(
            role="(custom role needed)",
            covers=sorted(uncovered),
            excess_count=0,
            reason=f"No predefined role covers: {', '.join(sorted(uncovered))}",
        ))

    return selected
