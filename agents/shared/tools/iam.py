"""IAM policy tools — analyze, diff, troubleshoot.

Shared by both local and remote MCP servers.
"""

from __future__ import annotations

import asyncio
import json

from agents.shared.gcp import (  # noqa: E402
    get_deny_policies,
    get_iam_policy,
    get_project,
    test_iam_permissions,
)
from agents.shared.tools.scan import collect_python_files, get_scanner


def analyze(
    paths: list[str], project: str | None = None,
) -> dict:
    """Compare required permissions from code against granted permissions."""
    proj = project or get_project()
    if not proj:
        return {"error": "No project specified and no default project found"}

    scanner = get_scanner()
    files = collect_python_files(paths)
    if not files:
        return {"error": "No Python files found"}

    results = [scanner.scan_source(f.read_text(encoding="utf-8", errors="replace"), str(f)) for f in files]
    required: set[str] = set()
    conditional: set[str] = set()
    for result in results:
        for finding in result.findings:
            if finding.status == "no_api_call":
                continue
            required.update(finding.permissions)
            conditional.update(finding.conditional_permissions)

    all_needed = sorted(required | conditional)
    if not all_needed:
        return {"message": "No GCP permissions required by this code"}

    granted = set(test_iam_permissions(proj, all_needed))
    missing = sorted(required - granted)
    matched = sorted(required & granted)

    return {
        "project": proj,
        "code_requires": {
            "required": sorted(required),
            "conditional": sorted(conditional),
        },
        "analysis": {
            "matched": matched,
            "missing": missing,
        },
        "summary": f"{len(matched)} granted, {len(missing)} missing",
    }


def troubleshoot(permission: str, project: str | None = None) -> dict:
    """Troubleshoot a PERMISSION_DENIED error."""
    proj = project or get_project()
    if not proj:
        return {"error": "No project specified"}

    granted = test_iam_permissions(proj, [permission])
    has_it = permission in granted

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
        "caller_has_permission": has_it,
        "blocked_by_deny_policy": len(blocked_by_deny) > 0,
        "deny_details": blocked_by_deny,
        "roles_that_grant_this": roles_with_perm[:10],
    }

    if has_it:
        result["recommendation"] = "Caller has this permission. Check resource-level IAM or VPC-SC."
    elif blocked_by_deny:
        result["recommendation"] = "Blocked by deny policy. Contact org admin for exception."
    else:
        result["recommendation"] = f"Grant one of: {', '.join(roles_with_perm[:3])}"

    return result


def _find_roles_for_permission(permission: str) -> list[str]:
    """Find predefined roles that include a permission."""
    try:
        from iamspy.resources import iam_role_permissions_path
        role_perms = json.loads(iam_role_permissions_path().read_text())
        return [role for role, perms in role_perms.items() if permission in perms]
    except Exception:
        return []
