"""GCP API helpers — thin REST wrappers using ADC.

All calls use the developer's Application Default Credentials.
Shared by both local and remote MCP servers.
"""

from __future__ import annotations

import json
from functools import lru_cache
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import google.auth
import google.auth.transport.requests


@lru_cache
def _get_credentials() -> tuple[google.auth.credentials.Credentials, str]:
    """Get ADC credentials and default project."""
    credentials, project = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )
    return credentials, project or ""


def get_project() -> str:
    """Get the default GCP project from ADC."""
    _, project = _get_credentials()
    return project


def _authed_request(method: str, url: str, body: dict | None = None) -> dict:
    """Make an authenticated GCP REST API call."""
    credentials, _ = _get_credentials()
    credentials.refresh(google.auth.transport.requests.Request())

    headers = {
        "Authorization": f"Bearer {credentials.token}",
        "Content-Type": "application/json",
    }

    data = json.dumps(body).encode() if body else None
    req = Request(url, data=data, headers=headers, method=method)

    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        error_body = e.read().decode() if e.fp else ""
        return {"error": f"{e.code} {e.reason}", "details": error_body}


def list_agent_engines(project: str, location: str = "us-central1") -> list[dict]:
    """List Vertex AI Agent Engine (Reasoning Engine) instances."""
    url = (
        f"https://{location}-aiplatform.googleapis.com/v1beta1"
        f"/projects/{project}/locations/{location}/reasoningEngines"
    )
    resp = _authed_request("GET", url)
    return resp.get("reasoningEngines", [])


def list_cloud_run_services(project: str, location: str = "-") -> list[dict]:
    """List Cloud Run services."""
    url = (
        f"https://run.googleapis.com/v2"
        f"/projects/{project}/locations/{location}/services"
    )
    resp = _authed_request("GET", url)
    return resp.get("services", [])


def get_iam_policy(project: str) -> dict:
    """Get IAM policy for a project."""
    url = (
        f"https://cloudresourcemanager.googleapis.com/v3"
        f"/projects/{project}:getIamPolicy"
    )
    return _authed_request("POST", url, body={"options": {"requestedPolicyVersion": 3}})


def get_deny_policies(project: str) -> list[dict]:
    """Get IAM deny policies for a project."""
    url = (
        f"https://iam.googleapis.com/v2"
        f"/policies/cloudresourcemanager.googleapis.com%2Fprojects%2F{project}"
        f"/denypolicies"
    )
    resp = _authed_request("GET", url)
    if "error" in resp:
        return []
    return resp.get("policies", [])


def search_resources(
    project: str, asset_types: list[str] | None = None,
) -> list[dict]:
    """Search resources via Cloud Asset Inventory."""
    scope = f"projects/{project}"
    url = f"https://cloudasset.googleapis.com/v1/{scope}:searchAllResources"
    params = [f"assetTypes={t}" for t in (asset_types or [])]
    if params:
        url += "?" + "&".join(params)
    resp = _authed_request("GET", url)
    return resp.get("results", [])


def test_iam_permissions(
    project: str, permissions: list[str],
) -> list[str]:
    """Test which permissions the caller has on a project."""
    url = (
        f"https://cloudresourcemanager.googleapis.com/v3"
        f"/projects/{project}:testIamPermissions"
    )
    resp = _authed_request("POST", url, body={"permissions": permissions})
    return resp.get("permissions", [])


# ── Service Account management ─────────────────────────────────────────


def list_service_accounts(project: str) -> list[dict]:
    """List service accounts in a project."""
    url = (
        f"https://iam.googleapis.com/v1"
        f"/projects/{project}/serviceAccounts"
    )
    resp = _authed_request("GET", url)
    return resp.get("accounts", [])


def create_service_account(
    project: str,
    account_id: str,
    display_name: str = "",
    description: str = "",
) -> dict:
    """Create a service account in a project.

    Args:
        project: GCP project ID.
        account_id: The account ID (becomes <account_id>@<project>.iam.gserviceaccount.com).
        display_name: Human-readable name.
        description: Description of what this SA is for.

    Returns:
        The created service account resource, or error dict.
    """
    url = (
        f"https://iam.googleapis.com/v1"
        f"/projects/{project}/serviceAccounts"
    )
    body = {
        "accountId": account_id,
        "serviceAccount": {
            "displayName": display_name or account_id,
            "description": description,
        },
    }
    return _authed_request("POST", url, body=body)


def get_service_account(project: str, email: str) -> dict:
    """Get details of a specific service account."""
    url = (
        f"https://iam.googleapis.com/v1"
        f"/projects/{project}/serviceAccounts/{email}"
    )
    return _authed_request("GET", url)


def add_iam_binding(
    project: str,
    role: str,
    member: str,
) -> dict:
    """Add a single IAM binding to a project (read-modify-write).

    This is additive — it won't remove existing bindings.
    """
    # Get current policy
    policy = get_iam_policy(project)
    if "error" in policy:
        return policy

    bindings = policy.get("bindings", [])

    # Find or create the binding for this role
    found = False
    for binding in bindings:
        if binding["role"] == role:
            members = binding.get("members", [])
            if member not in members:
                members.append(member)
                binding["members"] = members
            found = True
            break

    if not found:
        bindings.append({"role": role, "members": [member]})

    # Set the updated policy
    url = (
        f"https://cloudresourcemanager.googleapis.com/v3"
        f"/projects/{project}:setIamPolicy"
    )
    set_body = {
        "policy": {
            "bindings": bindings,
            "etag": policy.get("etag", ""),
            "version": policy.get("version", 3),
        },
    }
    return _authed_request("POST", url, body=set_body)
