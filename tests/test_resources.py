"""Tests for package resource loading.

Verifies that data files are discoverable via importlib.resources
and contain valid JSON.
"""

from __future__ import annotations

import json

from iamspy.resources import method_db_path, permissions_path, registry_path


class TestResourcePaths:
    def test_registry_exists(self):
        path = registry_path()
        assert path.exists(), f"service_registry.json not found at {path}"

    def test_permissions_exists(self):
        path = permissions_path()
        assert path.exists(), f"iam_permissions.json not found at {path}"

    def test_method_db_exists(self):
        path = method_db_path()
        assert path.exists(), f"method_db.json not found at {path}"

    def test_registry_valid_json(self):
        data = json.loads(registry_path().read_text())
        assert isinstance(data, dict)
        assert len(data) > 100  # sanity: should have 200+ services

    def test_permissions_valid_json(self):
        data = json.loads(permissions_path().read_text())
        assert isinstance(data, dict)
        assert len(data) > 100  # sanity: should have thousands of mappings

    def test_method_db_valid_json(self):
        data = json.loads(method_db_path().read_text())
        assert isinstance(data, dict)
        assert len(data) > 100  # sanity: should have thousands of methods
