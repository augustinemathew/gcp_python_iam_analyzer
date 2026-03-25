"""Compute Engine tool — list running VM instances in a project."""

from __future__ import annotations

from google.cloud import compute_v1


def list_running_vms(project_id: str) -> dict:
    """List all running VM instances in a project.

    Args:
        project_id: The GCP project ID (e.g. "my-project").

    Returns:
        A dict with:
          - "total": number of running instances
          - "by_zone": dict mapping zone -> list of VM dicts, each with:
              name, machine_type, status, internal_ip, external_ip (if any)
          - "summary": list of {"zone": str, "count": int} sorted by count desc
    """
    client = compute_v1.InstancesClient()
    request = compute_v1.AggregatedListInstancesRequest(
        project=project_id,
        filter="status=RUNNING",
    )

    by_zone: dict[str, list[dict]] = {}
    
    for zone, instances_scoped_list in client.aggregated_list(request=request):
        vms = instances_scoped_list.instances
        if not vms:
            continue
        zone_name = zone.removeprefix("zones/")
        by_zone[zone_name] = [_format_instance(vm) for vm in vms]

    summary = sorted(
        [{"zone": z, "count": len(vms)} for z, vms in by_zone.items()],
        key=lambda x: x["count"],
        reverse=True,
    )

    return {
        "total": sum(len(v) for v in by_zone.values()),
        "by_zone": by_zone,
        "summary": summary,
    }


def _format_instance(vm: compute_v1.Instance) -> dict:
    """Extract key fields from a Compute Instance into a plain dict."""
    internal_ip = None
    external_ip = None
    for iface in vm.network_interfaces:
        internal_ip = iface.network_i_p
        for config in iface.access_configs:
            if config.nat_i_p:
                external_ip = config.nat_i_p
        break  # first interface is enough

    return {
        "name": vm.name,
        "machine_type": vm.machine_type.split("/")[-1],
        "status": vm.status,
        "internal_ip": internal_ip,
        "external_ip": external_ip,
    }
