"""Tests for s04_method_context: end-to-end method context assembly."""

from __future__ import annotations

from pathlib import Path

import pytest
from build_pipeline.stages.s04_method_context import build_method_context

PROJECT_ROOT = Path(__file__).parent.parent


@pytest.mark.slow
class TestMethodContextKMS:
    """End-to-end extraction for KMS — a gapic service."""

    @pytest.fixture(scope="class")
    def kms_context(self):
        return build_method_context(
            method_db_path=PROJECT_ROOT / "method_db.json",
            registry_path=PROJECT_ROOT / "service_registry.json",
            filter_services=["kms"],
        )

    def test_encrypt_has_rest_uri(self, kms_context):
        ctx = kms_context["kms.KeyManagementServiceClient.encrypt"]
        assert ctx["rest_method"] == "POST"
        assert ":encrypt" in ctx["rest_uri"]
        assert "cryptoKeys" in ctx["rest_uri"]
        assert ctx["client_type"] == "gapic"

    def test_encrypt_has_docstring(self, kms_context):
        ctx = kms_context["kms.KeyManagementServiceClient.encrypt"]
        assert "Encrypts data" in ctx["description"]
        assert "[google.cloud" not in ctx["description"]

    def test_decrypt_has_rest_uri(self, kms_context):
        ctx = kms_context["kms.KeyManagementServiceClient.decrypt"]
        assert ctx["rest_method"] == "POST"
        assert ":decrypt" in ctx["rest_uri"]

    def test_create_key_ring_is_post(self, kms_context):
        ctx = kms_context["kms.KeyManagementServiceClient.create_key_ring"]
        assert ctx["rest_method"] == "POST"
        assert "/keyRings" in ctx["rest_uri"]

    def test_get_crypto_key_is_get(self, kms_context):
        ctx = kms_context["kms.KeyManagementServiceClient.get_crypto_key"]
        assert ctx["rest_method"] == "GET"

    def test_list_crypto_keys_is_get(self, kms_context):
        ctx = kms_context["kms.KeyManagementServiceClient.list_crypto_keys"]
        assert ctx["rest_method"] == "GET"

    def test_get_iam_policy_has_multi_uris(self, kms_context):
        ctx = kms_context["kms.KeyManagementServiceClient.get_iam_policy"]
        assert ctx["rest_method"] == "GET"
        assert len(ctx["rest_all_uris"]) >= 3
        assert ":getIamPolicy" in ctx["rest_uri"]

    def test_path_helpers_are_unknown(self, kms_context):
        """Path builder methods should have client_type=unknown, no REST URI."""
        path_keys = [k for k in kms_context if "_path" in k.split(".")[-1]]
        assert len(path_keys) >= 10
        for key in path_keys:
            ctx = kms_context[key]
            assert ctx["rest_uri"] is None
            assert ctx["client_type"] == "unknown"
            assert "path" in ctx["description"].lower() or "string" in ctx["description"].lower()

    def test_all_api_methods_are_gapic(self, kms_context):
        """All non-path, non-infrastructure methods should be gapic."""
        api_methods = {
            k: v for k, v in kms_context.items()
            if "_path" not in k.split(".")[-1]
            and "common_" not in k.split(".")[-1]
        }
        gapic_count = sum(1 for v in api_methods.values() if v["client_type"] == "gapic")
        assert gapic_count >= 30


@pytest.mark.slow
class TestMethodContextBigQuery:
    """End-to-end extraction for BigQuery — a hand-written service."""

    @pytest.fixture(scope="class")
    def bq_context(self):
        return build_method_context(
            method_db_path=PROJECT_ROOT / "method_db.json",
            registry_path=PROJECT_ROOT / "service_registry.json",
            filter_services=["bigquery"],
        )

    def test_get_dataset_has_span_name(self, bq_context):
        ctx = bq_context["bigquery.Client.get_dataset"]
        assert ctx["span_name"] == "BigQuery.getDataset"
        assert ctx["rest_method"] == "GET"
        assert ctx["client_type"] == "handwritten"

    def test_create_table_is_post(self, bq_context):
        ctx = bq_context["bigquery.Client.create_table"]
        assert ctx["rest_method"] == "POST"
        assert "createTable" in ctx["span_name"]

    def test_delete_dataset_is_delete(self, bq_context):
        ctx = bq_context["bigquery.Client.delete_dataset"]
        assert ctx["rest_method"] == "DELETE"
        assert "deleteDataset" in ctx["span_name"]

    def test_get_dataset_has_docstring(self, bq_context):
        ctx = bq_context["bigquery.Client.get_dataset"]
        assert "dataset" in ctx["description"].lower()

    def test_handwritten_method_count(self, bq_context):
        hw = sum(1 for v in bq_context.values() if v["client_type"] == "handwritten")
        assert hw >= 20, f"Expected 20+ handwritten methods, got {hw}"


@pytest.mark.slow
class TestMethodContextAllServices:
    """Broad coverage tests across all services."""

    @pytest.fixture(scope="class")
    def all_context(self):
        return build_method_context(
            method_db_path=PROJECT_ROOT / "method_db.json",
            registry_path=PROJECT_ROOT / "service_registry.json",
        )

    def test_total_method_count(self, all_context):
        assert len(all_context) >= 3000, f"Expected 3000+ methods, got {len(all_context)}"

    def test_gapic_coverage(self, all_context):
        gapic = sum(1 for v in all_context.values() if v["client_type"] == "gapic")
        assert gapic >= 1000, f"Expected 1000+ gapic methods, got {gapic}"

    def test_every_method_has_description(self, all_context):
        """Every method should have some docstring (even path helpers)."""
        no_desc = [k for k, v in all_context.items() if not v["description"]]
        # Allow some misses (properties, __init__) but should be rare
        miss_rate = len(no_desc) / len(all_context)
        assert miss_rate < 0.1, f"{len(no_desc)} methods ({miss_rate:.0%}) have no description"

    def test_output_schema(self, all_context):
        """Every entry should have the expected fields."""
        required_fields = {
            "service_id", "class_name", "method_name", "rest_method",
            "rest_uri", "description", "client_type",
        }
        for key, ctx in list(all_context.items())[:100]:
            assert required_fields.issubset(ctx.keys()), f"Missing fields in {key}: {required_fields - ctx.keys()}"

    def test_no_async_clients(self, all_context):
        """AsyncClient methods should be filtered out."""
        async_keys = [k for k in all_context if "Async" in k]
        assert async_keys == [], f"Found async client entries: {async_keys[:5]}"
