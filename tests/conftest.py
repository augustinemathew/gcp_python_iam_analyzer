"""Shared test fixtures for gcp-sdk-detector."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    """Provide a temporary data directory for test artifacts."""
    return tmp_path


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


@pytest.fixture
def sample_service_registry(data_dir: Path) -> Path:
    """Create a minimal service_registry.json for registry tests."""
    registry = {
        "bigquery": {
            "pip_package": "google-cloud-bigquery",
            "display_name": "BigQuery",
            "iam_prefix": "bigquery",
            "discovery_doc": "https://bigquery.googleapis.com/$discovery/rest?version=v2",
            "iam_reference": "https://cloud.google.com/iam/docs/roles-permissions/bigquery",
            "modules": ["google.cloud.bigquery", "google.cloud.bigquery_v2"],
        },
        "storage": {
            "pip_package": "google-cloud-storage",
            "display_name": "Cloud Storage",
            "iam_prefix": "storage",
            "discovery_doc": "https://storage.googleapis.com/$discovery/rest?version=v1",
            "iam_reference": "https://cloud.google.com/iam/docs/roles-permissions/storage",
            "modules": ["google.cloud.storage"],
        },
    }
    path = data_dir / "service_registry.json"
    path.write_text(json.dumps(registry, indent=2))
    return path
