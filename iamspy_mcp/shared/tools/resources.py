"""GCP resource discovery tools.

Shared by both local and remote MCP servers.
"""

from __future__ import annotations

from iamspy_mcp.shared.gcp import (
    get_project,
    list_agent_engines,
    list_cloud_run_services,
    search_resources,
)

# Cloud AI asset types for search_resources
_CAIS_ASSET_TYPES = [
    "aiplatform.googleapis.com/Endpoint",
    "aiplatform.googleapis.com/Model",
    "aiplatform.googleapis.com/Dataset",
    "aiplatform.googleapis.com/ReasoningEngine",
]


def list_agents(project: str | None = None, location: str = "us-central1") -> dict:
    """List deployed Agent Engine instances."""
    proj = project or get_project()
    if not proj:
        return {"error": "No project specified"}

    engines = list_agent_engines(proj, location)
    entries = []
    for e in engines:
        name = e.get("name", "")
        entries.append({
            "name": name,
            "display_name": e.get("displayName", ""),
            "state": e.get("state", ""),
            "create_time": e.get("createTime", ""),
        })

    return {"project": proj, "location": location, "count": len(entries), "engines": entries}


def list_run_services(project: str | None = None, location: str = "-") -> dict:
    """List Cloud Run services."""
    proj = project or get_project()
    if not proj:
        return {"error": "No project specified"}

    services = list_cloud_run_services(proj, location)
    entries = []
    for s in services:
        entries.append({
            "name": s.get("name", ""),
            "uri": s.get("uri", ""),
            "creator": s.get("creator", ""),
            "last_modifier": s.get("lastModifier", ""),
        })

    return {"project": proj, "count": len(entries), "services": entries}


def list_ai_resources(project: str | None = None) -> dict:
    """List Cloud AI resources (Agent Engine, Vertex endpoints, models, datasets)."""
    proj = project or get_project()
    if not proj:
        return {"error": "No project specified"}

    results = search_resources(proj, asset_types=_CAIS_ASSET_TYPES)
    entries = []
    for r in results:
        entries.append({
            "name": r.get("name", ""),
            "asset_type": r.get("assetType", ""),
            "display_name": r.get("displayName", ""),
            "location": r.get("location", ""),
            "state": r.get("state", ""),
        })

    return {"project": proj, "count": len(entries), "resources": entries}
