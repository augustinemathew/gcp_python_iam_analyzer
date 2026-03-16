"""Shared test fixtures for gcp-sdk-detector."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gcp_sdk_detector.models import ServiceEntry
from gcp_sdk_detector.registry import ServiceRegistry

# Single source of truth for test services.
# Used by both test_registry (ServiceRegistry object) and sample_service_registry (JSON file).
TEST_SERVICES = {
    "bigquery": {
        "pip_package": "google-cloud-bigquery",
        "display_name": "BigQuery",
        "iam_prefix": "bigquery",
        "modules": ["google.cloud.bigquery", "google.cloud.bigquery_v2"],
    },
    "storage": {
        "pip_package": "google-cloud-storage",
        "display_name": "Cloud Storage",
        "iam_prefix": "storage",
        "modules": ["google.cloud.storage"],
    },
    "kms": {
        "pip_package": "google-cloud-kms",
        "display_name": "Cloud KMS",
        "iam_prefix": "cloudkms",
        "modules": ["google.cloud.kms", "google.cloud.kms_v1"],
    },
    "pubsub": {
        "pip_package": "google-cloud-pubsub",
        "display_name": "Pub/Sub",
        "iam_prefix": "pubsub",
        "modules": ["google.cloud.pubsub", "google.cloud.pubsub_v1", "google.pubsub_v1"],
    },
    "dlp": {
        "pip_package": "google-cloud-dlp",
        "display_name": "Cloud DLP",
        "iam_prefix": "dlp",
        "modules": ["google.cloud.dlp", "google.cloud.dlp_v2"],
    },
}


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    """Provide a temporary data directory for test artifacts."""
    return tmp_path


@pytest.fixture
def test_registry() -> ServiceRegistry:
    """ServiceRegistry loaded from TEST_SERVICES."""
    reg = ServiceRegistry()
    for sid, entry in TEST_SERVICES.items():
        reg.add(ServiceEntry(
            service_id=sid,
            pip_package=entry["pip_package"],
            display_name=entry["display_name"],
            iam_prefix=entry["iam_prefix"],
            modules=entry["modules"],
        ))
    return reg


@pytest.fixture
def sample_service_registry(data_dir: Path) -> Path:
    """Minimal service_registry.json for registry-specific tests."""
    registry = {
        "bigquery": TEST_SERVICES["bigquery"],
        "storage": TEST_SERVICES["storage"],
    }
    path = data_dir / "service_registry.json"
    path.write_text(json.dumps(registry, indent=2))
    return path


@pytest.fixture
def sample_permissions_json(data_dir: Path) -> Path:
    """Create a minimal iam_permissions.json for resolver tests."""
    mapping = {
        "bigquery.Client.query": {
            "permissions": ["bigquery.jobs.create"],
            "conditional": [],
            "local_helper": False,
            "notes": "Also requires bigquery.tables.getData on target tables",
        },
        "bigquery.Client.dataset": {
            "permissions": [],
            "conditional": [],
            "local_helper": True,
            "notes": "Local reference constructor, no API call",
        },
        "storage.Client.get_bucket": {
            "permissions": ["storage.buckets.get"],
            "conditional": [],
            "local_helper": False,
        },
        "storage.*.upload_from_filename": {
            "permissions": ["storage.objects.create"],
            "conditional": ["storage.objects.delete"],
            "notes": "Conditional delete permission required if overwriting",
        },
        "cloudkms.KeyManagementServiceClient.encrypt": {
            "permissions": ["cloudkms.cryptoKeyVersions.useToEncrypt"],
            "conditional": [],
            "local_helper": False,
        },
        "pubsub.PublisherClient.publish": {
            "permissions": ["pubsub.topics.publish"],
            "conditional": [],
            "local_helper": False,
        },
    }
    path = data_dir / "iam_permissions.json"
    path.write_text(json.dumps(mapping, indent=2))
    return path
