"""Tests for ServiceRegistry and service_id derivation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gcp_sdk_detector.models import ServiceEntry
from gcp_sdk_detector.registry import ServiceRegistry, derive_service_id


class TestDeriveServiceId:
    def test_simple(self):
        assert derive_service_id("google-cloud-bigquery") == "bigquery"

    def test_hyphenated(self):
        assert derive_service_id("google-cloud-secret-manager") == "secretmanager"

    def test_kms(self):
        assert derive_service_id("google-cloud-kms") == "kms"

    def test_aiplatform(self):
        assert derive_service_id("google-cloud-aiplatform") == "aiplatform"

    def test_resource_manager(self):
        assert derive_service_id("google-cloud-resource-manager") == "resourcemanager"

    def test_pubsub(self):
        assert derive_service_id("google-cloud-pubsub") == "pubsub"


class TestServiceRegistry:
    def test_from_json(self, sample_service_registry: Path):
        reg = ServiceRegistry.from_json(sample_service_registry)
        assert len(reg) == 2
        assert "bigquery" in reg
        assert "storage" in reg

    def test_get(self, sample_service_registry: Path):
        reg = ServiceRegistry.from_json(sample_service_registry)
        entry = reg.get("bigquery")
        assert entry is not None
        assert entry.display_name == "BigQuery"
        assert entry.pip_package == "google-cloud-bigquery"
        assert entry.iam_prefix == "bigquery"
        assert "google.cloud.bigquery" in entry.modules

    def test_get_missing(self, sample_service_registry: Path):
        reg = ServiceRegistry.from_json(sample_service_registry)
        assert reg.get("nosuchservice") is None

    def test_contains(self, sample_service_registry: Path):
        reg = ServiceRegistry.from_json(sample_service_registry)
        assert "bigquery" in reg
        assert "nosuchservice" not in reg

    def test_service_ids(self, sample_service_registry: Path):
        reg = ServiceRegistry.from_json(sample_service_registry)
        assert reg.service_ids() == ["bigquery", "storage"]

    def test_all_entries(self, sample_service_registry: Path):
        reg = ServiceRegistry.from_json(sample_service_registry)
        entries = reg.all_entries()
        assert len(entries) == 2
        assert isinstance(entries["bigquery"], ServiceEntry)

    def test_lookup_by_pip_package(self, sample_service_registry: Path):
        reg = ServiceRegistry.from_json(sample_service_registry)
        entry = reg.lookup_by_pip_package("google-cloud-bigquery")
        assert entry is not None
        assert entry.service_id == "bigquery"

    def test_lookup_by_pip_package_missing(self, sample_service_registry: Path):
        reg = ServiceRegistry.from_json(sample_service_registry)
        assert reg.lookup_by_pip_package("google-cloud-nosuch") is None

    def test_lookup_by_module(self, sample_service_registry: Path):
        reg = ServiceRegistry.from_json(sample_service_registry)
        entry = reg.lookup_by_module("google.cloud.bigquery")
        assert entry is not None
        assert entry.service_id == "bigquery"

    def test_lookup_by_module_missing(self, sample_service_registry: Path):
        reg = ServiceRegistry.from_json(sample_service_registry)
        assert reg.lookup_by_module("google.cloud.nosuch") is None

    def test_add(self):
        reg = ServiceRegistry()
        assert len(reg) == 0
        entry = ServiceEntry(
            service_id="pubsub",
            pip_package="google-cloud-pubsub",
            display_name="Pub/Sub",
            iam_prefix="pubsub",
            modules=["google.cloud.pubsub_v1"],
        )
        reg.add(entry)
        assert len(reg) == 1
        assert reg.get("pubsub") is entry

    def test_round_trip_json(self, data_dir: Path):
        reg = ServiceRegistry()
        reg.add(
            ServiceEntry(
                service_id="bigquery",
                pip_package="google-cloud-bigquery",
                display_name="BigQuery",
                iam_prefix="bigquery",
                discovery_doc="https://bigquery.googleapis.com/$discovery/rest?version=v2",
                modules=["google.cloud.bigquery"],
            )
        )
        reg.add(
            ServiceEntry(
                service_id="storage",
                pip_package="google-cloud-storage",
                display_name="Cloud Storage",
                iam_prefix="storage",
                modules=["google.cloud.storage"],
            )
        )

        path = data_dir / "roundtrip.json"
        reg.to_json(path)

        reg2 = ServiceRegistry.from_json(path)
        assert len(reg2) == 2
        bq = reg2.get("bigquery")
        assert bq is not None
        assert bq.display_name == "BigQuery"
        assert bq.discovery_doc == "https://bigquery.googleapis.com/$discovery/rest?version=v2"
        assert bq.modules == ["google.cloud.bigquery"]

    def test_from_json_file_not_found(self, data_dir: Path):
        with pytest.raises(FileNotFoundError):
            ServiceRegistry.from_json(data_dir / "nope.json")

    def test_from_json_missing_optional_fields(self, data_dir: Path):
        """Registry JSON with only required fields."""
        data = {
            "storage": {
                "pip_package": "google-cloud-storage",
                "display_name": "Cloud Storage",
                "iam_prefix": "storage",
            }
        }
        path = data_dir / "minimal.json"
        path.write_text(json.dumps(data))
        reg = ServiceRegistry.from_json(path)
        entry = reg.get("storage")
        assert entry is not None
        assert entry.discovery_doc == ""
        assert entry.modules == []

    def test_empty_registry(self):
        reg = ServiceRegistry()
        assert len(reg) == 0
        assert reg.service_ids() == []
        assert reg.all_entries() == {}
