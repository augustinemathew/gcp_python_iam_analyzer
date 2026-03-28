"""Cloud Asset Inventory tool — list all GCP resources in a project."""

from __future__ import annotations

from google.cloud import asset_v1


def list_resources(project_id: str, asset_types: list[str] = []) -> dict:  # noqa: B006
    """List all GCP resources in a project, grouped by type.

    Args:
        project_id: The GCP project ID (e.g. "my-project").
        asset_types: Optional list of asset types to filter by, e.g.
            ["compute.googleapis.com/Instance", "storage.googleapis.com/Bucket"].
            If omitted, returns all resource types.

    Returns:
        A dict with:
          - "total": total number of resources found
          - "by_type": dict mapping asset_type -> list of resource names
          - "summary": list of {"asset_type": str, "count": int} sorted by count desc
    """
    client = asset_v1.AssetServiceClient()
    request = asset_v1.ListAssetsRequest(
        parent=f"projects/{project_id}",
        asset_types=asset_types,
        content_type=asset_v1.ContentType.RESOURCE,
        page_size=1000,
    )

    by_type: dict[str, list[str]] = {}
    for asset in client.list_assets(request=request):
        by_type.setdefault(asset.asset_type, []).append(asset.name)

    summary = sorted(
        [{"asset_type": t, "count": len(names)} for t, names in by_type.items()],
        key=lambda x: x["count"],
        reverse=True,
    )

    return {
        "total": sum(len(v) for v in by_type.values()),
        "by_type": by_type,
        "summary": summary,
    }
