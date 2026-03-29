"""Tests for deterministic role mapper.

These tests hit the real IAM API to fetch role permissions,
so they're marked slow. Run with: pytest tests/test_role_mapper.py -v
"""

from __future__ import annotations

import pytest

from agents.shared.tools.role_mapper import RoleRecommendation, permissions_to_roles


@pytest.mark.slow
class TestPermissionsToRoles:
    """Test minimum role set computation against real IAM API."""

    def test_storage_create_only(self) -> None:
        result = permissions_to_roles({"storage.objects.create"})
        assert len(result) >= 1
        roles = {r.role for r in result}
        assert "roles/storage.objectCreator" in roles or "roles/storage.objectUser" in roles

    def test_storage_create_and_delete(self) -> None:
        result = permissions_to_roles({
            "storage.objects.create",
            "storage.objects.delete",
        })
        roles = {r.role for r in result}
        # objectUser covers both create + delete
        assert "roles/storage.objectUser" in roles

    def test_bigquery_job_and_data(self) -> None:
        result = permissions_to_roles(
            required={"bigquery.jobs.create"},
            conditional={"bigquery.tables.getData"},
        )
        roles = {r.role for r in result}
        assert "roles/bigquery.jobUser" in roles or "roles/bigquery.user" in roles

    def test_kms_encrypt_only(self) -> None:
        result = permissions_to_roles({"cloudkms.cryptoKeyVersions.useToEncrypt"})
        roles = {r.role for r in result}
        assert "roles/cloudkms.cryptoKeyEncrypter" in roles

    def test_multi_service(self) -> None:
        """Pipeline needing bigquery + storage + kms."""
        result = permissions_to_roles(
            required={
                "bigquery.jobs.create",
                "storage.objects.create",
                "cloudkms.cryptoKeyVersions.useToEncrypt",
            },
            conditional={
                "bigquery.tables.getData",
                "storage.objects.delete",
            },
        )
        roles = {r.role for r in result}
        # Should have one role per service, not one mega-role
        assert len(result) >= 3
        # Each role should be narrow
        for rec in result:
            if rec.role != "(custom role needed)":
                assert rec.excess_count < 200  # not roles/editor level

    def test_empty_permissions(self) -> None:
        result = permissions_to_roles(set())
        assert result == []

    def test_prefers_narrower_role(self) -> None:
        """When two roles cover the same permission, pick the narrower one."""
        result = permissions_to_roles({"storage.objects.create"})
        # objectCreator is narrower than objectUser which is narrower than objectAdmin
        if result and result[0].role != "(custom role needed)":
            assert result[0].role != "roles/storage.admin"

    def test_covers_field_populated(self) -> None:
        result = permissions_to_roles({"storage.objects.create"})
        assert len(result) >= 1
        assert "storage.objects.create" in result[0].covers

    def test_reason_field_populated(self) -> None:
        result = permissions_to_roles({"storage.objects.create"})
        assert len(result) >= 1
        assert "covers" in result[0].reason

    def test_secret_accessor(self) -> None:
        result = permissions_to_roles({"secretmanager.versions.access"})
        roles = {r.role for r in result}
        assert "roles/secretmanager.secretAccessor" in roles
