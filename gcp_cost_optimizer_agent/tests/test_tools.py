"""Tests for cost optimizer agent tools.

Unit tests mock external GCP clients. Integration tests (marked slow)
hit real APIs and require ADC credentials.
"""

from __future__ import annotations

from unittest import mock

from agent.tools.agent_engines import _format_engine
from agent.tools.assets import list_resources
from agent.tools.billing import _discover_billing_table, query_billing
from agent.tools.compute import _format_instance, list_running_vms
from agent.tools.containers import _format_cluster, _format_run_service


# ---------------------------------------------------------------------------
# assets.py
# ---------------------------------------------------------------------------


class TestListResources:
    def test_groups_by_type(self) -> None:
        fake_assets = [
            mock.Mock(asset_type="compute.googleapis.com/Instance", name="vm-1"),
            mock.Mock(asset_type="compute.googleapis.com/Instance", name="vm-2"),
            mock.Mock(asset_type="storage.googleapis.com/Bucket", name="bucket-1"),
        ]
        with mock.patch("agent.tools.assets.asset_v1.AssetServiceClient") as mock_client:
            mock_client.return_value.list_assets.return_value = fake_assets
            result = list_resources("test-project")

        assert result["total"] == 3
        assert len(result["by_type"]) == 2
        assert len(result["by_type"]["compute.googleapis.com/Instance"]) == 2
        assert result["summary"][0]["asset_type"] == "compute.googleapis.com/Instance"

    def test_empty_project(self) -> None:
        with mock.patch("agent.tools.assets.asset_v1.AssetServiceClient") as mock_client:
            mock_client.return_value.list_assets.return_value = []
            result = list_resources("empty-project")

        assert result["total"] == 0
        assert result["by_type"] == {}


# ---------------------------------------------------------------------------
# compute.py
# ---------------------------------------------------------------------------


class TestFormatInstance:
    def test_extracts_fields(self) -> None:
        iface = mock.Mock()
        iface.network_i_p = "10.0.0.1"
        access = mock.Mock()
        access.nat_i_p = "34.1.2.3"
        iface.access_configs = [access]

        vm = mock.Mock()
        vm.name = "my-vm"
        vm.machine_type = "zones/us-central1-a/machineTypes/e2-medium"
        vm.status = "RUNNING"
        vm.network_interfaces = [iface]

        result = _format_instance(vm)
        assert result["name"] == "my-vm"
        assert result["machine_type"] == "e2-medium"
        assert result["internal_ip"] == "10.0.0.1"
        assert result["external_ip"] == "34.1.2.3"


class TestListRunningVms:
    def test_groups_by_zone(self) -> None:
        vm = mock.Mock()
        vm.name = "test-vm"
        vm.machine_type = "zones/us-central1-a/machineTypes/n1-standard-1"
        vm.status = "RUNNING"
        iface = mock.Mock()
        iface.network_i_p = "10.0.0.1"
        iface.access_configs = []
        vm.network_interfaces = [iface]

        scoped = mock.Mock()
        scoped.instances = [vm]

        with mock.patch("agent.tools.compute.compute_v1.InstancesClient") as mock_client:
            mock_client.return_value.aggregated_list.return_value = [
                ("zones/us-central1-a", scoped),
            ]
            result = list_running_vms("test-project")

        assert result["total"] == 1
        assert "us-central1-a" in result["by_zone"]

    def test_no_vms(self) -> None:
        scoped = mock.Mock()
        scoped.instances = []

        with mock.patch("agent.tools.compute.compute_v1.InstancesClient") as mock_client:
            mock_client.return_value.aggregated_list.return_value = [
                ("zones/us-central1-a", scoped),
            ]
            result = list_running_vms("test-project")

        assert result["total"] == 0


# ---------------------------------------------------------------------------
# containers.py
# ---------------------------------------------------------------------------


class TestFormatCluster:
    def test_extracts_fields(self) -> None:
        pool = mock.Mock()
        pool.initial_node_count = 3
        pool.config = mock.Mock()
        pool.config.machine_type = "e2-standard-4"

        cluster = mock.Mock()
        cluster.name = "my-cluster"
        cluster.location = "us-central1"
        cluster.status = 2  # RUNNING
        cluster.current_master_version = "1.29.1-gke.100"
        cluster.node_pools = [pool]

        result = _format_cluster(cluster)
        assert result["name"] == "my-cluster"
        assert result["node_count"] == 3
        assert result["machine_type"] == "e2-standard-4"


class TestFormatRunService:
    def test_extracts_fields(self) -> None:
        svc = mock.Mock()
        svc.name = "projects/p/locations/us-central1/services/my-svc"
        svc.uri = "https://my-svc-abc123.a.run.app"
        svc.last_modifier = "user@example.com"
        svc.update_time = None

        result = _format_run_service(svc, "us-central1")
        assert result["name"] == "my-svc"
        assert result["uri"] == "https://my-svc-abc123.a.run.app"
        assert result["update_time"] == ""


# ---------------------------------------------------------------------------
# agent_engines.py
# ---------------------------------------------------------------------------


class TestFormatEngine:
    def test_full_engine(self) -> None:
        engine = {
            "name": "projects/123/locations/us-central1/reasoningEngines/456",
            "displayName": "My Agent",
            "description": "Does stuff",
            "spec": {"agentFramework": "ag2"},
            "createTime": "2026-03-17T00:00:00Z",
        }
        result = _format_engine(engine)
        assert result["id"] == "456"
        assert result["display_name"] == "My Agent"
        assert result["framework"] == "ag2"

    def test_minimal_engine(self) -> None:
        result = _format_engine({"name": "engines/789"})
        assert result["id"] == "789"
        assert result["display_name"] == ""


# ---------------------------------------------------------------------------
# billing.py
# ---------------------------------------------------------------------------


class TestDiscoverBillingTable:
    def test_finds_table(self) -> None:
        table = mock.Mock()
        table.table_id = "gcp_billing_export_v1_ABCDEF"
        client = mock.Mock()
        client.list_tables.return_value = [table]

        result = _discover_billing_table(client, "my-project")
        assert result == "my-project.billing_export.gcp_billing_export_v1_ABCDEF"

    def test_no_tables(self) -> None:
        client = mock.Mock()
        client.list_tables.return_value = []

        result = _discover_billing_table(client, "my-project")
        assert result is None

    def test_no_dataset(self) -> None:
        client = mock.Mock()
        client.list_tables.side_effect = Exception("Not found")

        result = _discover_billing_table(client, "my-project")
        assert result is None


class TestQueryBilling:
    def test_no_billing_table_no_discovery(self) -> None:
        with mock.patch("agent.tools.billing.bigquery.Client") as mock_bq:
            mock_bq.return_value.list_tables.return_value = []
            result = query_billing("test-project")

        assert "error" in result
        assert result["total_cost"] == 0

    def test_with_explicit_table(self) -> None:
        row = mock.Mock()
        row.service = "Compute Engine"
        row.sku = "N1 Standard"
        row.net_cost = 42.50
        row.currency = "USD"

        mock_query_job = mock.Mock()
        mock_query_job.result.return_value = [row]

        with mock.patch("agent.tools.billing.bigquery.Client") as mock_bq:
            mock_bq.return_value.query.return_value = mock_query_job
            result = query_billing("test-project", "p.ds.table", days=7)

        assert result["total_cost"] == 42.50
        assert result["by_service"][0]["service"] == "Compute Engine"
        assert result["currency"] == "USD"

    def test_empty_results(self) -> None:
        mock_query_job = mock.Mock()
        mock_query_job.result.return_value = []

        with mock.patch("agent.tools.billing.bigquery.Client") as mock_bq:
            mock_bq.return_value.query.return_value = mock_query_job
            result = query_billing("test-project", "p.ds.table")

        assert result["total_cost"] == 0
        assert result["by_service"] == []
