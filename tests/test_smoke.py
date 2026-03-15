"""Smoke tests to verify the project bootstraps correctly."""

from __future__ import annotations


def test_package_imports():
    import gcp_sdk_detector

    assert gcp_sdk_detector.__version__ == "0.1.0"


def test_fixtures_load(sample_permissions_json, sample_service_registry):
    """Verify conftest fixtures produce valid files."""
    import json

    perms = json.loads(sample_permissions_json.read_text())
    assert "bigquery.Client.query" in perms

    registry = json.loads(sample_service_registry.read_text())
    assert "bigquery" in registry
    assert registry["bigquery"]["display_name"] == "BigQuery"
