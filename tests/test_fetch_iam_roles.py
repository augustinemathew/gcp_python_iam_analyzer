"""Tests for s05_fetch_iam_roles: IAM role catalog download and processing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from build_pipeline.stages.s05_fetch_iam_roles import (
    derive_permission_index,
    get_default_project,
    load_roles_from_file,
    role_to_dict,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestRoleToDict:
    """Test conversion of IAM role proto to plain dict."""

    def test_converts_all_fields(self):
        role = type("FakeRole", (), {
            "name": "roles/storage.admin",
            "title": "Storage Admin",
            "description": "Full control of GCS resources.",
            "included_permissions": ["storage.buckets.create", "storage.buckets.delete"],
            "stage": 1,
        })()
        d = role_to_dict(role)
        assert d["name"] == "roles/storage.admin"
        assert d["title"] == "Storage Admin"
        assert d["description"] == "Full control of GCS resources."
        assert d["included_permissions"] == ["storage.buckets.create", "storage.buckets.delete"]
        assert isinstance(d["stage"], str)

    def test_empty_permissions(self):
        role = type("FakeRole", (), {
            "name": "roles/viewer",
            "title": "Viewer",
            "description": "Read access.",
            "included_permissions": [],
            "stage": 1,
        })()
        d = role_to_dict(role)
        assert d["included_permissions"] == []


class TestDerivePermissionIndex:
    """Test deriving flat permission index from role catalog."""

    def test_groups_by_prefix(self):
        roles = [
            {
                "name": "roles/storage.admin",
                "title": "Storage Admin",
                "description": "Full control.",
                "included_permissions": [
                    "storage.buckets.create",
                    "storage.buckets.delete",
                    "storage.objects.get",
                ],
                "stage": "GA",
            },
            {
                "name": "roles/compute.viewer",
                "title": "Compute Viewer",
                "description": "Read access.",
                "included_permissions": [
                    "compute.instances.get",
                    "compute.instances.list",
                ],
                "stage": "GA",
            },
        ]
        index = derive_permission_index(roles)
        assert "storage" in index
        assert "compute" in index
        assert "storage.buckets.create" in index["storage"]
        assert "storage.objects.get" in index["storage"]
        assert "compute.instances.get" in index["compute"]

    def test_deduplicates_permissions(self):
        """Same permission in multiple roles should appear once."""
        roles = [
            {
                "name": "roles/storage.admin",
                "included_permissions": ["storage.buckets.get"],
                "title": "", "description": "", "stage": "GA",
            },
            {
                "name": "roles/storage.viewer",
                "included_permissions": ["storage.buckets.get", "storage.buckets.list"],
                "title": "", "description": "", "stage": "GA",
            },
        ]
        index = derive_permission_index(roles)
        assert index["storage"].count("storage.buckets.get") == 1

    def test_sorts_permissions(self):
        roles = [
            {
                "name": "roles/test",
                "included_permissions": ["z.b.c", "z.a.b", "z.c.a"],
                "title": "", "description": "", "stage": "GA",
            },
        ]
        index = derive_permission_index(roles)
        assert index["z"] == ["z.a.b", "z.b.c", "z.c.a"]

    def test_empty_roles_returns_empty(self):
        assert derive_permission_index([]) == {}


class TestLoadRolesFromFile:
    """Test loading roles from a pre-downloaded JSON file."""

    def test_loads_json_array(self, tmp_path):
        roles = [
            {
                "name": "roles/test.admin",
                "title": "Test Admin",
                "description": "Full access.",
                "includedPermissions": ["test.resources.create"],
                "stage": "GA",
            }
        ]
        f = tmp_path / "roles.json"
        f.write_text(json.dumps(roles))

        loaded = load_roles_from_file(f)
        assert len(loaded) == 1
        assert loaded[0]["name"] == "roles/test.admin"
        # Should normalize includedPermissions → included_permissions
        assert loaded[0]["included_permissions"] == ["test.resources.create"]

    def test_nonexistent_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_roles_from_file(Path("/nonexistent/roles.json"))


class TestGetDefaultProject:
    """Test project ID resolution."""

    def test_returns_string(self):
        """Should return a non-empty string (from gcloud or google.auth)."""
        project = get_default_project()
        # May be empty if no auth configured, but shouldn't crash
        assert isinstance(project, str)


@pytest.mark.slow
class TestFetchIamRolesIntegration:
    """Integration tests against real GCP API. Requires valid credentials."""

    def test_existing_iam_roles_file_is_valid(self):
        """The previously-downloaded data/iam_roles.json should be well-formed."""
        roles_path = Path(__file__).parent.parent / "data" / "iam_roles.json"
        if not roles_path.exists():
            pytest.skip("data/iam_roles.json not present")

        with open(roles_path) as f:
            roles = json.load(f)

        assert isinstance(roles, list)
        assert len(roles) >= 2000, f"Expected 2000+ roles, got {len(roles)}"

        # Spot-check structure
        role = roles[0]
        assert "name" in role
        assert "title" in role
        assert "description" in role
        assert "included_permissions" in role
        assert role["name"].startswith("roles/")

    def test_derive_index_from_existing_file(self):
        """Derive permission index from existing data/iam_roles.json."""
        roles_path = Path(__file__).parent.parent / "data" / "iam_roles.json"
        if not roles_path.exists():
            pytest.skip("data/iam_roles.json not present")

        with open(roles_path) as f:
            roles = json.load(f)

        index = derive_permission_index(roles)
        assert len(index) >= 250, f"Expected 250+ prefixes, got {len(index)}"

        # Known prefixes should exist
        assert "storage" in index
        assert "compute" in index
        assert "bigquery" in index
        assert "cloudkms" in index

        # Known permissions should be present
        assert "storage.buckets.create" in index["storage"]
        assert "compute.instances.create" in index["compute"]
        assert "bigquery.jobs.create" in index["bigquery"]

        total_perms = sum(len(v) for v in index.values())
        assert total_perms >= 10000, f"Expected 10000+ permissions, got {total_perms}"
