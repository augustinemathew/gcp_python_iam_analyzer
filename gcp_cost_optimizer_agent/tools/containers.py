"""GKE and Cloud Run tools — list container workloads in a project."""

from __future__ import annotations

from google.cloud import container_v1
from google.cloud import run_v2


def list_gke_clusters(project_id: str) -> dict:
    """List all GKE clusters in a project.

    Args:
        project_id: The GCP project ID.

    Returns:
        A dict with:
          - "total": number of clusters
          - "clusters": list of cluster dicts with name, location, status,
            node_count, machine_type, and current_master_version
    """
    client = container_v1.ClusterManagerClient()
    parent = f"projects/{project_id}/locations/-"
    response = client.list_clusters(parent=parent)

    clusters = [_format_cluster(c) for c in response.clusters]
    return {"total": len(clusters), "clusters": clusters}


def _format_cluster(cluster: container_v1.Cluster) -> dict:
    """Extract key fields from a GKE Cluster."""
    node_count = 0
    machine_type = ""
    for pool in cluster.node_pools:
        node_count += pool.initial_node_count
        if not machine_type and pool.config:
            machine_type = pool.config.machine_type

    return {
        "name": cluster.name,
        "location": cluster.location,
        "status": container_v1.Cluster.Status(cluster.status).name,
        "node_count": node_count,
        "machine_type": machine_type,
        "master_version": cluster.current_master_version,
    }


def list_cloud_run_services(project_id: str, region: str = "us-central1") -> dict:
    """List Cloud Run services in a project and region.

    Args:
        project_id: The GCP project ID.
        region: Region to query (default ``us-central1``).

    Returns:
        A dict with:
          - "total": number of services
          - "services": list of service dicts with name, region, uri,
            last_modifier, and update_time
    """
    client = run_v2.ServicesClient()
    parent = f"projects/{project_id}/locations/{region}"

    services = []
    for svc in client.list_services(parent=parent):
        services.append(_format_run_service(svc, region))

    return {"total": len(services), "services": services}


def _format_run_service(svc: run_v2.Service, region: str) -> dict:
    """Extract key fields from a Cloud Run Service."""
    return {
        "name": svc.name.split("/")[-1],
        "region": region,
        "uri": svc.uri,
        "last_modifier": svc.last_modifier,
        "update_time": svc.update_time.isoformat() if svc.update_time else "",
    }
