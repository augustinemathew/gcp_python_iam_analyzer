"""IDE agent tools — local filesystem context.

These tools work with the developer's local files and project directories.
No GCS, no archive extraction, no workspace IDs.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from agents.shared.gcp import (
    get_deny_policies,
    get_iam_policy,
    get_project,
    list_agent_engines as _list_agents,
    list_cloud_run_services as _list_run,
    search_resources as _search_resources,
    test_iam_permissions,
)
from agents.shared.tools.scan import (
    collect_python_files,
    finding_to_dict,
    get_registry,
    get_scanner,
    manifest as _manifest,
    scan as _scan,
)


# ── Local scan tools ───────────────────────────────────────────────────


def scan_file(file_path: str) -> dict:
    """Scan a single Python file for GCP SDK calls and IAM permissions.

    Returns findings with permissions, identity context (app/user),
    and source locations.

    Args:
        file_path: Path to a Python file.
    """
    p = Path(file_path)
    if not p.is_file():
        return {"error": f"File not found: {file_path}"}
    if p.suffix != ".py":
        return {"error": f"Not a Python file: {file_path}"}

    scanner = get_scanner()
    source = p.read_text(encoding="utf-8", errors="replace")
    result = scanner.scan_source(source, str(p))

    findings = []
    all_perms: set[str] = set()
    all_services: set[str] = set()
    for f in result.findings:
        if f.status == "no_api_call":
            continue
        all_perms.update(f.permissions)
        all_perms.update(f.conditional_permissions)
        for m in f.matched:
            all_services.add(m.display_name)
        findings.append(finding_to_dict(f))

    return {
        "stats": {
            "sdk_methods_resolved": len(findings),
            "unique_permissions_found": len(all_perms),
            "gcp_services_detected": sorted(all_services),
        },
        "findings": findings,
    }


def scan_directory(directory: str) -> dict:
    """Scan all Python files in a local directory.

    Returns findings with permissions, identity, and aggregate stats.

    Args:
        directory: Path to a local directory.
    """
    return _scan([directory])


def generate_manifest(paths: list[str], output_path: str | None = None) -> str:
    """Generate an IAM permission manifest (YAML) for local code.

    The manifest lists required permissions split by identity context
    (app SA vs delegated user) and GCP services to enable.

    Args:
        paths: File or directory paths to scan.
        output_path: If provided, writes manifest to this file.

    Returns:
        YAML manifest content.
    """
    return _manifest(paths, output_path)


def check_guardrails(
    paths: list[str],
    environment: str = "prod",
    identity_type: str | None = None,
) -> str:
    """Check if the code's permissions violate security guardrails.

    Scans the code, evaluates permissions against guardrail rules.
    Flags privilege escalation, destructive ops, data exfiltration,
    and identity issues.

    Args:
        paths: File or directory paths to scan.
        environment: 'dev', 'staging', or 'prod'.
        identity_type: 'agent_identity' or 'service_account'.

    Returns:
        JSON with violations, severity, and remediation.
    """
    from agents.shared.guardrails import evaluate_guardrails

    scanner = get_scanner()
    files = list(collect_python_files(paths))
    if not files:
        return json.dumps({"error": "No Python files found"})

    results = [scanner.scan_source(f.read_text(encoding="utf-8", errors="replace"), str(f)) for f in files]
    permissions: set[str] = set()
    for result in results:
        for finding in result.findings:
            if finding.status == "no_api_call":
                continue
            permissions.update(finding.permissions)
            permissions.update(finding.conditional_permissions)

    violations = evaluate_guardrails(
        permissions=permissions,
        identity_type=identity_type,
        environment=environment,
    )

    blocks = [v for v in violations if v.severity == "block"]
    warns = [v for v in violations if v.severity == "warn"]

    return json.dumps({
        "environment": environment,
        "permissions_checked": len(permissions),
        "violations": len(violations),
        "blocks": len(blocks),
        "warnings": len(warns),
        "deploy_allowed": len(blocks) == 0,
        "details": [
            {"severity": v.severity, "category": v.category, "message": v.message,
             "permission": v.permission, "remediation": v.remediation}
            for v in violations
        ],
    }, indent=2)


# ── Service enablement ─────────────────────────────────────────────────


def check_enabled_services(project_id: str | None = None) -> str:
    """Check which GCP API services are enabled in the project.

    Compares against what the code needs (from the manifest) and
    shows which services are missing.
    """
    from agents.shared.gcp import list_enabled_services

    proj = project_id or get_project()
    if not proj:
        return json.dumps({"error": "No project specified"})

    enabled = set(list_enabled_services(proj))

    # Load manifest to see what's needed
    from pathlib import Path
    manifest_path = Path("iam-manifest.yaml")
    needed: set[str] = set()
    if manifest_path.exists():
        import yaml
        manifest = yaml.safe_load(manifest_path.read_text())
        needed = set(manifest.get("services", {}).get("enable", []))

    missing = sorted(needed - enabled)
    already = sorted(needed & enabled)

    return json.dumps({
        "project": proj,
        "needed_by_code": sorted(needed),
        "already_enabled": already,
        "missing": missing,
        "all_good": len(missing) == 0,
    }, indent=2)


def enable_services(service_names: list[str], project_id: str | None = None) -> str:
    """Enable GCP API services in the project.

    Args:
        service_names: List of services (e.g., ["bigquery.googleapis.com"]).
        project_id: GCP project. Uses default if not specified.
    """
    from agents.shared.gcp import enable_services as _enable

    proj = project_id or get_project()
    if not proj:
        return json.dumps({"error": "No project specified"})

    result = _enable(proj, service_names)
    if "error" in result:
        return json.dumps(result, indent=2)

    return json.dumps({
        "enabled": True,
        "services": service_names,
        "project": proj,
    }, indent=2)


# ── GCP resource tools ─────────────────────────────────────────────────


def list_agent_engines(project_id: str | None = None, location: str = "us-central1") -> str:
    """List deployed Agent Engine instances in the project."""
    proj = project_id or get_project()
    if not proj:
        return json.dumps({"error": "No project specified"})
    engines = _list_agents(proj, location)
    return json.dumps({"project": proj, "count": len(engines), "engines": engines}, indent=2)


def list_cloud_run_services(project_id: str | None = None) -> str:
    """List Cloud Run services in the project."""
    proj = project_id or get_project()
    if not proj:
        return json.dumps({"error": "No project specified"})
    services = _list_run(proj)
    return json.dumps({"project": proj, "count": len(services), "services": services}, indent=2)


# ── Service account tools ──────────────────────────────────────────────


def list_service_accounts(project_id: str | None = None) -> str:
    """List service accounts in the project.

    Shows account email, display name, and status.
    """
    from agents.shared.gcp import list_service_accounts as _list_sas

    proj = project_id or get_project()
    if not proj:
        return json.dumps({"error": "No project specified"})

    accounts = _list_sas(proj)
    entries = []
    for sa in accounts:
        entries.append({
            "email": sa.get("email", ""),
            "display_name": sa.get("displayName", ""),
            "disabled": sa.get("disabled", False),
            "description": sa.get("description", ""),
        })
    return json.dumps({"project": proj, "count": len(entries), "accounts": entries}, indent=2)


def create_service_account(
    account_id: str,
    display_name: str = "",
    description: str = "",
    project_id: str | None = None,
) -> str:
    """Create a new service account in the project.

    Args:
        account_id: SA name (becomes <account_id>@<project>.iam.gserviceaccount.com).
        display_name: Human-readable name.
        description: What this SA is for.
        project_id: GCP project. Uses default if not specified.

    Returns:
        The created SA details including full email.
    """
    from agents.shared.gcp import create_service_account as _create_sa

    proj = project_id or get_project()
    if not proj:
        return json.dumps({"error": "No project specified"})

    result = _create_sa(proj, account_id, display_name, description)
    if "error" in result:
        return json.dumps(result, indent=2)

    sa_email = result.get("email", "")

    # Auto-update workspace config with the new principal
    workspace_updated = False
    if sa_email:
        from agents.shared.workspace import load_workspace, update_workspace_principal
        config = load_workspace()
        if config:
            # Find the first environment matching this project and update its principal
            principal_str = f"serviceAccount:{sa_email}"
            for env_name, env in config.environments.items():
                if env.gcp_project == proj:
                    for ident_name, ident in env.identities.items():
                        if ident.type == "service_account" and not ident.principal:
                            workspace_updated = update_workspace_principal(
                                ".", env_name, ident_name, principal_str,
                            )
                            break
                    if workspace_updated:
                        break

    return json.dumps({
        "created": True,
        "email": sa_email,
        "display_name": result.get("displayName", ""),
        "project": proj,
        "workspace_updated": workspace_updated,
    }, indent=2)


def grant_iam_role(
    role: str,
    member: str,
    project_id: str | None = None,
) -> str:
    """Grant an IAM role to a member on the project.

    Args:
        role: The IAM role (e.g., 'roles/storage.objectViewer').
        member: The principal (e.g., 'serviceAccount:sa@proj.iam.gserviceaccount.com').
        project_id: GCP project.

    Returns:
        Confirmation or error.
    """
    from agents.shared.gcp import add_iam_binding

    proj = project_id or get_project()
    if not proj:
        return json.dumps({"error": "No project specified"})

    result = add_iam_binding(proj, role, member)
    if "error" in result:
        return json.dumps(result, indent=2)

    return json.dumps({
        "granted": True,
        "role": role,
        "member": member,
        "project": proj,
    }, indent=2)


# ── IAM change plans ──────────────────────────────────────────────────


def plan_iam_changes(
    paths: list[str],
    environment: str = "dev",
    workspace_root: str | None = None,
) -> str:
    """Generate a plan for IAM changes WITHOUT executing them.

    Scans code, looks up workspace config, computes what needs to happen:
    - SA to create (if principal is null)
    - Roles to grant (from deterministic role mapper)
    - Services to enable (if missing)

    Returns a plan ID. Present the plan to the developer and wait for
    confirmation before calling execute_iam_plan().
    """
    from agents.shared.workspace import load_workspace
    from agents.shared.tools.role_mapper import permissions_to_roles
    from agents.ide.plan import PlannedAction, create_plan, plan_to_dict

    config = load_workspace(workspace_root)
    if config is None:
        return json.dumps({"error": "No .iamspy/workspace.yaml found"})

    env = config.get_env(environment)
    if env is None:
        return json.dumps({"error": f"Environment '{environment}' not found", "available": config.env_names})

    if not env.gcp_project:
        return json.dumps({"error": f"No gcp_project set for environment '{environment}'"})

    # Scan code
    scan_result = _scan(paths)
    if "error" in scan_result:
        return json.dumps(scan_result)

    required = set(scan_result["permissions"]["required"])
    conditional = set(scan_result["permissions"]["conditional"])

    actions: list[PlannedAction] = []

    # Check if SA needs to be created
    for ident_name, ident in env.identities.items():
        if ident.type == "service_account" and not ident.principal:
            sa_name = f"{config.project_name.lower().replace(' ', '-')}-{environment}"
            actions.append(PlannedAction(
                action="create_sa",
                params={"account_id": sa_name, "display_name": config.project_name},
                description=f"Create SA: {sa_name}@{env.gcp_project}.iam.gserviceaccount.com",
            ))

    # Check services to enable
    from agents.shared.gcp import list_enabled_services
    try:
        from pathlib import Path as _Path
        manifest_path = _Path("iam-manifest.yaml")
        needed_services: set[str] = set()
        if manifest_path.exists():
            import yaml
            manifest = yaml.safe_load(manifest_path.read_text())
            needed_services = set(manifest.get("services", {}).get("enable", []))

        if needed_services:
            enabled = set(list_enabled_services(env.gcp_project))
            missing = needed_services - enabled
            if missing:
                actions.append(PlannedAction(
                    action="enable_service",
                    params={"services": sorted(missing)},
                    description=f"Enable APIs: {', '.join(sorted(missing))}",
                ))
    except Exception:
        pass  # non-critical

    # Compute roles to grant
    role_recs = permissions_to_roles(required, conditional)
    for ident_name, ident in env.identities.items():
        principal = ident.principal
        if not principal and actions and actions[0].action == "create_sa":
            # Will be created — use projected email
            sa_name = actions[0].params["account_id"]
            principal = f"serviceAccount:{sa_name}@{env.gcp_project}.iam.gserviceaccount.com"

        if principal:
            for rec in role_recs:
                if rec.role == "(custom role needed)":
                    continue
                actions.append(PlannedAction(
                    action="grant_role",
                    params={"role": rec.role, "member": principal},
                    description=f"Grant {rec.role} → {rec.reason}",
                ))

    plan = create_plan(environment, env.gcp_project, actions)
    return json.dumps(plan_to_dict(plan), indent=2)


def execute_iam_plan(plan_id: str) -> str:
    """Execute a previously generated IAM plan after developer confirmation.

    The developer should have reviewed the plan from plan_iam_changes() first.
    This creates the SA, grants roles, and enables services.
    """
    from agents.ide.plan import execute_plan
    return json.dumps(execute_plan(plan_id), indent=2)


# ── IAM tools ──────────────────────────────────────────────────────────


def get_project_iam_policy(project_id: str | None = None) -> str:
    """Get the IAM policy bindings for the project."""
    proj = project_id or get_project()
    if not proj:
        return json.dumps({"error": "No project specified"})
    policy = get_iam_policy(proj)
    return json.dumps({"project": proj, "bindings": policy.get("bindings", [])}, indent=2)


def analyze_permissions(
    paths: list[str],
    principal: str | None = None,
    project_id: str | None = None,
) -> str:
    """Compare what the code needs vs what a principal actually has.

    Expands the principal's IAM roles to permissions using the local
    role database (12,879 permissions). Does NOT use testIamPermissions
    (which only checks the caller). This accurately shows what a specific
    SA or AGENT_IDENTITY can do.

    Args:
        paths: Code paths to scan.
        principal: The principal to check (e.g., "serviceAccount:sa@proj.iam").
        project_id: GCP project.
    """
    from agents.shared.tools.iam import analyze
    return json.dumps(analyze(paths, project_id, principal), indent=2)


def troubleshoot_access(
    permission: str,
    principal: str | None = None,
    project_id: str | None = None,
) -> str:
    """Troubleshoot a PERMISSION_DENIED error for a specific principal.

    Checks the principal's roles (via expansion), deny policies, and
    suggests which role to grant.

    Args:
        permission: The permission that was denied (e.g., "storage.objects.create").
        principal: The principal getting the error (e.g., "serviceAccount:sa@proj.iam").
        project_id: GCP project.
    """
    from agents.shared.tools.iam import troubleshoot
    return json.dumps(troubleshoot(permission, project_id, principal), indent=2)


# ── Workspace config ───────────────────────────────────────────────────


def get_workspace_config(workspace_root: str | None = None) -> str:
    """Load the IAM workspace config (.iamspy/workspace.yaml).

    The workspace config defines deployment environments (dev, staging, prod)
    with GCP project, region, deployment target, and identity information.

    Returns the full config as JSON, or an error if not found.
    Use this to understand the deployment context before generating policies.
    """
    from agents.shared.workspace import load_workspace

    config = load_workspace(workspace_root)
    if config is None:
        return json.dumps({
            "error": "No .iamspy/workspace.yaml found",
            "hint": "Run init_workspace_config to create one",
        })

    envs = {}
    for name, env in config.environments.items():
        envs[name] = {
            "gcp_project": env.gcp_project,
            "region": env.region,
            "deployment": {
                "target": env.deployment.target,
                "service_name": env.deployment.service_name,
                "display_name": env.deployment.display_name,
            },
            "identity": {
                ident_name: {"type": ident.type, "principal": ident.principal}
                for ident_name, ident in env.identities.items()
            },
        }

    return json.dumps({
        "project_name": config.project_name,
        "config_path": str(config.path),
        "environments": envs,
    }, indent=2)


def init_workspace_config(
    workspace_root: str,
    project_name: str,
    gcp_project_dev: str | None = None,
    gcp_project_prod: str | None = None,
    deployment_target: str = "cloud_run",
    identity_type: str = "service_account",
) -> str:
    """Initialize a .iamspy/workspace.yaml for a project.

    Creates the config file with dev and prod environments.
    The developer can edit it afterward to fill in details.

    Args:
        workspace_root: Project root directory.
        project_name: Human-readable project name.
        gcp_project_dev: GCP project ID for dev (optional).
        gcp_project_prod: GCP project ID for prod (optional).
        deployment_target: cloud_run, cloud_run_job, or agent_engine.
        identity_type: service_account or agent_identity.
    """
    from agents.shared.workspace import init_workspace

    environments = {
        "dev": {
            "gcp_project": gcp_project_dev or "",
            "region": "us-central1",
            "deployment": {"target": deployment_target},
            "identity": {
                "app": {"type": identity_type, "principal": None},
            },
        },
        "prod": {
            "gcp_project": gcp_project_prod or "",
            "region": "us-central1",
            "deployment": {"target": deployment_target},
            "identity": {
                "app": {"type": identity_type, "principal": None},
            },
        },
    }

    path = init_workspace(workspace_root, project_name, environments)
    return json.dumps({
        "created": str(path),
        "project_name": project_name,
        "environments": ["dev", "prod"],
        "next_steps": [
            f"Edit {path} to fill in GCP project IDs and principals",
            "Run scan_directory to generate iam-manifest.yaml",
        ],
    }, indent=2)


def recommend_policy(
    paths: list[str],
    environment: str = "dev",
    workspace_root: str | None = None,
) -> str:
    """Generate an IAM policy recommendation for a specific environment.

    Joins the workspace config (who/where) with the scan results (what)
    to produce environment-specific IAM bindings.

    Args:
        paths: Code paths to scan.
        environment: Target environment name from workspace.yaml.
        workspace_root: Project root (searches for .iamspy/workspace.yaml).
    """
    from agents.shared.workspace import load_workspace

    # Load workspace config
    config = load_workspace(workspace_root)
    if config is None:
        return json.dumps({"error": "No .iamspy/workspace.yaml found"})

    env = config.get_env(environment)
    if env is None:
        return json.dumps({
            "error": f"Environment '{environment}' not found",
            "available": config.env_names,
        })

    # Scan code
    scan_result = _scan(paths)
    if "error" in scan_result:
        return json.dumps(scan_result)

    required = set(scan_result["permissions"]["required"])
    conditional = set(scan_result["permissions"]["conditional"])

    # Build recommendation per identity
    recommendations: dict = {
        "environment": environment,
        "gcp_project": env.gcp_project,
        "deployment": {
            "target": env.deployment.target,
            "service_name": env.deployment.service_name,
            "display_name": env.deployment.display_name,
        },
        "identities": {},
    }

    for ident_name, ident in env.identities.items():
        # Filter permissions for this identity from scan findings
        ident_perms = set()
        ident_cond = set()
        for finding in scan_result.get("findings", []):
            finding_identity = finding.get("identity", "")
            # Match if identity matches, or if multi-identity includes this one
            if ident_name in finding_identity or not finding_identity:
                ident_perms.update(finding.get("permissions", []))
                ident_cond.update(finding.get("conditional", []))

        if not ident_perms and not ident_cond:
            continue

        # Deterministic role mapping
        from agents.shared.tools.role_mapper import permissions_to_roles
        role_recs = permissions_to_roles(ident_perms, ident_cond)

        rec: dict = {
            "type": ident.type,
            "principal": ident.principal or "(not yet configured in workspace.yaml)",
            "permissions": {
                "required": sorted(ident_perms),
                "conditional": sorted(ident_cond),
            },
            "recommended_roles": [
                {"role": r.role, "covers": r.covers, "excess": r.excess_count, "reason": r.reason}
                for r in role_recs
            ],
        }

        # Check if principal exists and has grants (via role expansion)
        if ident.principal and env.gcp_project:
            from agents.shared.tools.iam import _find_roles_for_principal, _expand_roles_to_permissions
            try:
                roles = _find_roles_for_principal(env.gcp_project, ident.principal)
                granted = _expand_roles_to_permissions(roles)
                rec["granted_roles"] = roles
                rec["analysis"] = {
                    "granted": sorted(granted & ident_perms),
                    "missing": sorted(ident_perms - granted),
                    "conditional_granted": sorted(granted & ident_cond),
                    "excess_permission_count": len(granted - ident_perms - ident_cond),
                }
            except Exception:
                rec["analysis"] = {"error": "Could not check live permissions"}

        recommendations["identities"][ident_name] = rec

    # Guardrail check
    from agents.shared.guardrails import evaluate_guardrails

    identity_type = None
    for ident in env.identities.values():
        identity_type = ident.type
        break

    violations = evaluate_guardrails(
        permissions=required | conditional,
        identity_type=identity_type,
        environment=environment,
    )
    blocks = [v for v in violations if v.severity == "block"]
    recommendations["guardrails"] = {
        "violations": len(violations),
        "blocks": len(blocks),
        "deploy_allowed": len(blocks) == 0,
    }
    if violations:
        recommendations["guardrails"]["details"] = [
            {"severity": v.severity, "category": v.category, "message": v.message}
            for v in violations
        ]

    return json.dumps(recommendations, indent=2)
