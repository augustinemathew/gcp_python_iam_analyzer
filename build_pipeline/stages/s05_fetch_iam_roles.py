"""Stage s05: Fetch IAM role catalog via Python IAM Admin API.

Downloads all predefined GCP IAM roles with full permission lists,
titles, and descriptions. Stores as data/iam_roles.json (checked into repo).
Also derives iam_role_permissions.json (flat permission index) for backward compat.

No gcloud CLI dependency — uses google.cloud.iam_admin_v1.IAMClient directly.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path


def get_default_project() -> str:
    """Get project ID from gcloud config, fall back to google.auth.default()."""
    try:
        result = subprocess.run(
            ["gcloud", "config", "get-value", "project"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    try:
        import google.auth

        _, project = google.auth.default()
        return project or ""
    except Exception:
        return ""


def role_to_dict(role: object) -> dict:
    """Convert an IAM role proto object to a plain dict."""
    stage_val = getattr(role, "stage", 0)
    # Stage enum: 0=UNSPECIFIED, 1=GA, 2=BETA, 3=ALPHA, 4=DEPRECATED, 5=DISABLED, 6=EAP
    stage_names = {
        0: "LAUNCH_STAGE_UNSPECIFIED",
        1: "GA",
        2: "BETA",
        3: "ALPHA",
        4: "DEPRECATED",
        5: "DISABLED",
        6: "EAP",
    }
    stage_str = stage_names.get(int(stage_val), str(stage_val))

    return {
        "name": getattr(role, "name", ""),
        "title": getattr(role, "title", ""),
        "description": getattr(role, "description", ""),
        "included_permissions": list(getattr(role, "included_permissions", [])),
        "stage": stage_str,
    }


def fetch_predefined_roles() -> list[dict]:
    """Fetch all predefined IAM roles via the Python IAM Admin API.

    Uses IAMClient.list_roles() with RoleView.FULL to get includedPermissions.
    Paginates automatically. Returns list of role dicts.
    """
    from google.cloud import iam_admin_v1

    client = iam_admin_v1.IAMClient()

    roles = []
    for role in client.list_roles(
        request=iam_admin_v1.ListRolesRequest(
            view=iam_admin_v1.RoleView.FULL,
            page_size=1000,
        )
    ):
        roles.append(role_to_dict(role))

    return roles


def fetch_project_roles(project_id: str) -> list[dict]:
    """Fetch custom roles for a specific project."""
    from google.cloud import iam_admin_v1

    client = iam_admin_v1.IAMClient()

    roles = []
    for role in client.list_roles(
        request=iam_admin_v1.ListRolesRequest(
            parent=f"projects/{project_id}",
            view=iam_admin_v1.RoleView.FULL,
            page_size=1000,
        )
    ):
        roles.append(role_to_dict(role))

    return roles


def load_roles_from_file(path: Path) -> list[dict]:
    """Load roles from a pre-downloaded JSON file.

    Handles both gcloud JSON format (includedPermissions) and our internal
    format (included_permissions).
    """
    if not path.exists():
        raise FileNotFoundError(f"Roles file not found: {path}")

    with open(path) as f:
        raw = json.load(f)

    roles = []
    for entry in raw:
        roles.append({
            "name": entry.get("name", ""),
            "title": entry.get("title", ""),
            "description": entry.get("description", ""),
            "included_permissions": (
                entry.get("included_permissions")
                or entry.get("includedPermissions")
                or []
            ),
            "stage": entry.get("stage", "GA"),
        })
    return roles


def derive_permission_index(roles: list[dict]) -> dict[str, list[str]]:
    """Derive a flat permission index grouped by IAM prefix.

    Input: list of role dicts with included_permissions.
    Output: {"storage": ["storage.buckets.create", ...], "compute": [...]}

    Permissions are deduplicated and sorted within each prefix.
    """
    by_prefix: dict[str, set[str]] = defaultdict(set)

    for role in roles:
        for perm in role.get("included_permissions", []):
            parts = perm.split(".")
            if len(parts) >= 2:
                by_prefix[parts[0]].add(perm)

    return {prefix: sorted(perms) for prefix, perms in sorted(by_prefix.items())}


def save_roles(roles: list[dict], output_path: Path) -> None:
    """Save role catalog to JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(roles, f, indent=2)
        f.write("\n")


def save_permission_index(index: dict[str, list[str]], output_path: Path) -> None:
    """Save flat permission index to JSON (backward compat with iam_role_permissions.json)."""
    with open(output_path, "w") as f:
        json.dump(index, f, indent=2)
        f.write("\n")


def main() -> None:
    """CLI entry point for standalone execution."""
    import argparse

    parser = argparse.ArgumentParser(description="Fetch IAM role catalog")
    parser.add_argument("--project", default=None, help="GCP project ID (for custom roles)")
    parser.add_argument(
        "--from-file", default=None, help="Load from pre-downloaded JSON instead of API"
    )
    parser.add_argument(
        "--output", "-o", default="data/iam_roles.json", help="Output path for role catalog"
    )
    parser.add_argument(
        "--permissions-output",
        default="iam_role_permissions.json",
        help="Output path for flat permission index",
    )
    parser.add_argument("--monorepo", default="/tmp/google-cloud-python",
                        help="Path to monorepo (default: /tmp/google-cloud-python)")
    args = parser.parse_args()

    output_path = Path(args.output)
    perms_output = Path(args.permissions_output)

    if args.from_file:
        print(f"Loading roles from {args.from_file}", file=sys.stderr)
        roles = load_roles_from_file(Path(args.from_file))
    else:
        project = args.project or get_default_project()
        print("Fetching predefined IAM roles...", file=sys.stderr)
        t0 = time.perf_counter()
        roles = fetch_predefined_roles()
        elapsed = time.perf_counter() - t0
        print(f"  Fetched {len(roles)} predefined roles in {elapsed:.1f}s", file=sys.stderr)

        if project:
            print(f"Fetching custom roles for project {project}...", file=sys.stderr)
            custom = fetch_project_roles(project)
            roles.extend(custom)
            print(f"  Fetched {len(custom)} custom roles", file=sys.stderr)

    # Save role catalog
    save_roles(roles, output_path)
    print(f"Wrote {output_path} ({len(roles)} roles)", file=sys.stderr)

    # Derive and save flat permission index
    index = derive_permission_index(roles)
    save_permission_index(index, perms_output)
    total_perms = sum(len(v) for v in index.values())
    print(
        f"Wrote {perms_output} ({len(index)} prefixes, {total_perms} permissions)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
