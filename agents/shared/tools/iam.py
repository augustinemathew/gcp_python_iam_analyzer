"""IAM policy tools — analyze, diff, troubleshoot.

Shared by both local and remote MCP servers.

analyze() works by expanding the principal's roles to permissions using
the local role→permission database. It does NOT use testIamPermissions
(which only tests the caller's own access). This means it accurately
checks what a specific SA or AGENT_IDENTITY principal can do.
"""

from __future__ import annotations

import json
from pathlib import Path

from agents.shared.gcp import (
    get_deny_policies,
    get_iam_policy,
    get_project,
)
from agents.shared.tools.scan import collect_python_files, get_scanner


# ── Role → Permission expansion ───────────────────────────────────────

_role_permissions_cache: dict[str, list[str]] | None = None


def _load_role_permissions() -> dict[str, list[str]]:
    """Load/build the role → permissions cache.

    Uses the IAM API (roles.get) to fetch permissions for each role
    we encounter. Results are cached for the session.
    """
    global _role_permissions_cache
    if _role_permissions_cache is None:
        _role_permissions_cache = {}
    return _role_permissions_cache


def _get_role_permissions(role: str) -> list[str]:
    """Get permissions for a single role, fetching from API if not cached."""
    cache = _load_role_permissions()
    if role in cache:
        return cache[role]

    from agents.shared.gcp import _authed_request
    url = f"https://iam.googleapis.com/v1/{role}"
    resp = _authed_request("GET", url)
    perms = resp.get("includedPermissions", [])
    cache[role] = perms
    return perms


def _expand_roles_to_permissions(roles: list[str]) -> set[str]:
    """Expand a list of IAM roles to the set of permissions they grant."""
    permissions: set[str] = set()
    for role in roles:
        permissions.update(_get_role_permissions(role))
    return permissions


def _find_roles_for_principal(project: str, principal: str) -> list[str]:
    """Find all roles granted to a principal on a project."""
    policy = get_iam_policy(project)
    bindings = policy.get("bindings", [])
    roles: list[str] = []
    for binding in bindings:
        members = binding.get("members", [])
        if principal in members:
            roles.append(binding["role"])
    return sorted(roles)


def _find_roles_for_permission(permission: str) -> list[str]:
    """Find predefined roles that include a permission."""
    role_db = _load_role_permissions()
    return sorted(role for role, perms in role_db.items() if permission in perms)


# ── Analyze ────────────────────────────────────────────────────────────


def analyze(
    paths: list[str],
    project: str | None = None,
    principal: str | None = None,
) -> dict:
    """Compare required permissions from code against a principal's granted permissions.

    Uses role expansion (not testIamPermissions) so it accurately checks
    what a specific SA or AGENT_IDENTITY can do, not just the caller.

    Args:
        paths: Code paths to scan.
        project: GCP project ID.
        principal: The principal to check (e.g., "serviceAccount:sa@proj.iam").
                   If None, lists what's needed without checking grants.
    """
    proj = project or get_project()
    if not proj:
        return {"error": "No project specified and no default project found"}

    scanner = get_scanner()
    files = collect_python_files(paths)
    if not files:
        return {"error": "No Python files found"}

    results = [
        scanner.scan_source(f.read_text(encoding="utf-8", errors="replace"), str(f))
        for f in files
    ]
    required: set[str] = set()
    conditional: set[str] = set()
    for result in results:
        for finding in result.findings:
            if finding.status == "no_api_call":
                continue
            required.update(finding.permissions)
            conditional.update(finding.conditional_permissions)

    all_needed = required | conditional
    if not all_needed:
        return {"message": "No GCP permissions required by this code"}

    response: dict = {
        "project": proj,
        "code_requires": {
            "required": sorted(required),
            "conditional": sorted(conditional),
        },
    }

    # If a principal is specified, check their actual grants via role expansion
    if principal:
        roles = _find_roles_for_principal(proj, principal)
        granted_permissions = _expand_roles_to_permissions(roles)

        missing = sorted(required - granted_permissions)
        excess_perms = granted_permissions - all_needed
        matched = sorted(required & granted_permissions)
        conditional_granted = sorted(conditional & granted_permissions)

        response["principal"] = principal
        response["granted_roles"] = roles
        response["granted_permission_count"] = len(granted_permissions)
        response["analysis"] = {
            "matched": matched,
            "missing": missing,
            "conditional_granted": conditional_granted,
            "excess_permission_count": len(excess_perms),
        }
        response["summary"] = (
            f"{len(matched)}/{len(required)} required permissions granted"
            + (f", {len(missing)} missing" if missing else "")
            + (f", {len(excess_perms)} excess" if excess_perms else "")
        )
    else:
        response["note"] = "No principal specified — showing what the code needs. Provide a principal to check grants."

    return response


# ── Troubleshoot ───────────────────────────────────────────────────────


def troubleshoot(
    permission: str,
    project: str | None = None,
    principal: str | None = None,
) -> dict:
    """Troubleshoot a PERMISSION_DENIED error.

    If a principal is specified, checks their roles via expansion.
    Also checks deny policies.
    """
    proj = project or get_project()
    if not proj:
        return {"error": "No project specified"}

    has_it = False
    roles: list[str] = []
    if principal:
        roles = _find_roles_for_principal(proj, principal)
        granted = _expand_roles_to_permissions(roles)
        has_it = permission in granted

    # Check deny policies
    denies = get_deny_policies(proj)
    blocked_by_deny = []
    for policy in denies:
        for rule in policy.get("rules", []):
            deny_rule = rule.get("denyRule", {})
            if permission in deny_rule.get("deniedPermissions", []):
                blocked_by_deny.append({
                    "policy": policy.get("name", "unknown"),
                    "denied_principals": deny_rule.get("deniedPrincipals", []),
                })

    # Find roles that grant this permission
    roles_with_perm = _find_roles_for_permission(permission)

    result: dict = {
        "permission": permission,
        "project": proj,
    }

    if principal:
        result["principal"] = principal
        result["principal_has_permission"] = has_it
        result["principal_roles"] = roles
    else:
        result["note"] = "No principal specified — provide one to check specific access"

    result["blocked_by_deny_policy"] = len(blocked_by_deny) > 0
    result["deny_details"] = blocked_by_deny
    result["roles_that_grant_this"] = roles_with_perm[:10]

    if principal and has_it:
        result["recommendation"] = "Principal has this permission. Check resource-level IAM, conditions, or VPC-SC."
    elif blocked_by_deny:
        result["recommendation"] = "Blocked by deny policy. Contact org admin for exception."
    elif principal:
        result["recommendation"] = f"Grant one of: {', '.join(roles_with_perm[:3])}"
    else:
        result["recommendation"] = f"Roles that include this permission: {', '.join(roles_with_perm[:5])}"

    return result
