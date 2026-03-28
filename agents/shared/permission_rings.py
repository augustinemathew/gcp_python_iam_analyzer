"""Permission classification into severity rings.

Classifies GCP IAM permissions into 4 concentric security rings:

  Ring 0 — CRITICAL: Privilege escalation. Permissions that let an identity
           grant itself or others more access, create credentials, or
           modify security policies. An agent with these can escape any
           other constraint.

  Ring 1 — SENSITIVE: Data access and secrets. Permissions that read/write
           sensitive data, access secrets, use encryption keys, or export
           data to external destinations.

  Ring 2 — MUTATING: All state-changing operations. Create, update, delete,
           destroy, deploy, start, stop. Includes destructive operations.

  Ring 3 — READ: Read-only operations. List, get, describe — no state change.

API:
    classify(permission) -> Ring
    classify_all(permissions) -> dict[Ring, list[ClassifiedPermission]]
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path


class Ring(IntEnum):
    CRITICAL = 0
    SENSITIVE = 1
    MUTATING = 2
    READ = 3


_RING_LABELS = {
    Ring.CRITICAL: "critical",
    Ring.SENSITIVE: "sensitive",
    Ring.MUTATING: "mutating",
    Ring.READ: "read",
}


@dataclass(frozen=True)
class ClassifiedPermission:
    permission: str
    ring: Ring
    reason: str

    @property
    def label(self) -> str:
        return _RING_LABELS[self.ring]


# ── Ring 0: CRITICAL — privilege escalation ────────────────────────────

_RING0_EXACT = frozenset({
    # IAM policy modification
    "resourcemanager.projects.setIamPolicy",
    "resourcemanager.folders.setIamPolicy",
    "resourcemanager.organizations.setIamPolicy",
    # Service account credential creation/use
    "iam.serviceAccountKeys.create",
    "iam.serviceAccountKeys.get",
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.getOpenIdToken",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.signJwt",
    "iam.serviceAccounts.implicitDelegation",
    # Service account lifecycle
    "iam.serviceAccounts.create",
    "iam.serviceAccounts.actAs",
    # Role definition
    "iam.roles.create",
    "iam.roles.update",
    # Organization policy
    "orgpolicy.policy.set",
    "orgpolicy.constraints.set",
    # Workload identity federation
    "iam.workloadIdentityPools.create",
    "iam.workloadIdentityPoolProviders.create",
})

_RING0_PATTERN = re.compile(r"\.setIamPolicy$")

# ── Ring 1: SENSITIVE — data access, secrets, crypto ───────────────────

_RING1_EXACT = frozenset({
    "secretmanager.versions.access",
    "cloudkms.cryptoKeyVersions.useToDecrypt",
    "cloudkms.cryptoKeyVersions.useToEncrypt",
    "cloudkms.cryptoKeyVersions.useToSign",
})

_RING1_VERBS = frozenset({
    "export",
    "download",
    "access",
    "decrypt",
})

_RING1_PATTERNS = [
    re.compile(r"\.getData$"),
    re.compile(r"\.readRows$"),
    re.compile(r"^secretmanager\."),
    re.compile(r"^cloudkms\..*\.use"),
]

# ── Ring 3: READ — read-only ──────────────────────────────────────────

_RING3_VERBS = frozenset({
    "get",
    "list",
    "search",
    "query",
    "getStatus",
    "getIamPolicy",
    "listTagBindings",
    "listEffectiveTags",
    "searchPolicyBindings",
    "validate",
    "predict",
    "generate",
    "useReadOnly",
})

# ── Classification ─────────────────────────────────────────────────────


def classify(permission: str) -> Ring:
    """Classify a single IAM permission into a security ring.

    This is the core API. Returns a Ring enum value (0-3).
    """
    return _classify(permission).ring


def classify_detailed(permission: str) -> ClassifiedPermission:
    """Classify with reason string. Use when you need the explanation."""
    return _classify(permission)


def _classify(permission: str) -> ClassifiedPermission:
    # Ring 0: exact
    if permission in _RING0_EXACT:
        return ClassifiedPermission(permission, Ring.CRITICAL, "privilege escalation")

    # Ring 0: setIamPolicy pattern
    if _RING0_PATTERN.search(permission):
        return ClassifiedPermission(permission, Ring.CRITICAL, "IAM policy modification")

    # Ring 1: exact
    if permission in _RING1_EXACT:
        return ClassifiedPermission(permission, Ring.SENSITIVE, "sensitive data access")

    # Ring 1: patterns
    for pattern in _RING1_PATTERNS:
        if pattern.search(permission):
            return ClassifiedPermission(permission, Ring.SENSITIVE, "sensitive data access")

    # Extract verb
    verb = permission.rsplit(".", 1)[-1] if "." in permission else ""

    # Ring 1: sensitive verbs
    if verb in _RING1_VERBS:
        return ClassifiedPermission(permission, Ring.SENSITIVE, f"sensitive operation ({verb})")

    # Ring 3: read-only verbs
    if verb in _RING3_VERBS:
        return ClassifiedPermission(permission, Ring.READ, "read-only")

    # Ring 2: everything else is mutating
    return ClassifiedPermission(permission, Ring.MUTATING, f"state change ({verb})")


def classify_all(permissions: set[str]) -> dict[Ring, list[ClassifiedPermission]]:
    """Classify a set of permissions, grouped by ring."""
    by_ring: dict[Ring, list[ClassifiedPermission]] = {r: [] for r in Ring}
    for perm in sorted(permissions):
        cp = _classify(perm)
        by_ring[cp.ring].append(cp)
    return by_ring


def classify_from_role_db(role_db_path: str | Path) -> dict[Ring, int]:
    """Classify all permissions in the role database. Returns ring → count."""
    data = json.loads(Path(role_db_path).read_text())
    all_perms = set(p for pl in data.values() for p in pl)
    by_ring = classify_all(all_perms)
    return {ring: len(perms) for ring, perms in by_ring.items()}
