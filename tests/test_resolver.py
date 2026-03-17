"""Tests for PermissionResolver interface and StaticPermissionResolver."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iamspy.resolver import PermissionResolver, StaticPermissionResolver


class TestStaticPermissionResolver:
    def test_exact_class_lookup(self, sample_permissions_json: Path):
        r = StaticPermissionResolver(sample_permissions_json)
        result = r.resolve("bigquery", "Client", "query")
        assert result is not None
        assert result.permissions == ["bigquery.jobs.create"]
        assert result.conditional_permissions == []
        assert not result.is_local_helper

    def test_wildcard_class_lookup(self, sample_permissions_json: Path):
        r = StaticPermissionResolver(sample_permissions_json)
        result = r.resolve("storage", "Blob", "upload_from_filename")
        assert result is not None
        assert result.permissions == ["storage.objects.create"]
        assert result.conditional_permissions == ["storage.objects.delete"]

    def test_exact_takes_priority_over_wildcard(self, data_dir: Path):
        """When both exact and wildcard keys exist, exact wins."""
        mapping = {
            "storage.Client.upload_from_filename": {
                "permissions": ["storage.objects.create"],
                "conditional": [],
            },
            "storage.*.upload_from_filename": {
                "permissions": ["storage.objects.create"],
                "conditional": ["storage.objects.delete"],
            },
        }
        path = data_dir / "perms.json"
        path.write_text(json.dumps(mapping))
        r = StaticPermissionResolver(path)

        # Exact match — no conditional
        result = r.resolve("storage", "Client", "upload_from_filename")
        assert result is not None
        assert result.conditional_permissions == []

        # Different class falls through to wildcard
        result = r.resolve("storage", "Blob", "upload_from_filename")
        assert result is not None
        assert result.conditional_permissions == ["storage.objects.delete"]

    def test_local_helper(self, sample_permissions_json: Path):
        r = StaticPermissionResolver(sample_permissions_json)
        result = r.resolve("bigquery", "Client", "dataset")
        assert result is not None
        assert result.is_local_helper
        assert result.permissions == []
        assert result.status == "no_api_call"

    def test_unknown_method_returns_none(self, sample_permissions_json: Path):
        r = StaticPermissionResolver(sample_permissions_json)
        assert r.resolve("bigquery", "Client", "nonexistent") is None

    def test_unknown_service_returns_none(self, sample_permissions_json: Path):
        r = StaticPermissionResolver(sample_permissions_json)
        assert r.resolve("nosuchservice", "Client", "query") is None

    def test_has_mapping(self, sample_permissions_json: Path):
        r = StaticPermissionResolver(sample_permissions_json)
        assert r.has_mapping("bigquery", "Client", "query")
        assert not r.has_mapping("bigquery", "Client", "nonexistent")

    def test_notes_field(self, sample_permissions_json: Path):
        r = StaticPermissionResolver(sample_permissions_json)
        result = r.resolve("bigquery", "Client", "query")
        assert result is not None
        assert "bigquery.tables.getData" in result.notes

    def test_keys_property(self, sample_permissions_json: Path):
        r = StaticPermissionResolver(sample_permissions_json)
        keys = r.keys
        assert "bigquery.Client.query" in keys
        assert "storage.*.upload_from_filename" in keys
        assert len(keys) == 6

    def test_all_entries(self, sample_permissions_json: Path):
        r = StaticPermissionResolver(sample_permissions_json)
        entries = r.all_entries()
        assert len(entries) == 6
        assert entries["bigquery.Client.query"].permissions == ["bigquery.jobs.create"]
        assert entries["bigquery.Client.dataset"].is_local_helper

    def test_missing_optional_fields(self, data_dir: Path):
        """JSON entries with minimal fields should still work."""
        mapping = {
            "storage.Client.get_bucket": {
                "permissions": ["storage.buckets.get"],
            },
        }
        path = data_dir / "minimal.json"
        path.write_text(json.dumps(mapping))
        r = StaticPermissionResolver(path)

        result = r.resolve("storage", "Client", "get_bucket")
        assert result is not None
        assert result.permissions == ["storage.buckets.get"]
        assert result.conditional_permissions == []
        assert not result.is_local_helper
        assert result.notes == ""

    def test_file_not_found(self, data_dir: Path):
        with pytest.raises(FileNotFoundError):
            StaticPermissionResolver(data_dir / "does_not_exist.json")

    def test_invalid_json(self, data_dir: Path):
        path = data_dir / "bad.json"
        path.write_text("not json")
        with pytest.raises(json.JSONDecodeError):
            StaticPermissionResolver(path)


class TestPermissionResolverIsABC:
    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            PermissionResolver()  # type: ignore[abstract]

    def test_subclass_must_implement_resolve(self):
        class BadResolver(PermissionResolver):
            pass

        with pytest.raises(TypeError):
            BadResolver()  # type: ignore[abstract]

    def test_custom_resolver(self):
        """A concrete subclass works correctly."""
        from iamspy.models import PermissionResult

        class DictResolver(PermissionResolver):
            def __init__(self, data: dict[str, PermissionResult]):
                self._data = data

            def resolve(self, service_id, class_name, method_name):
                return self._data.get(f"{service_id}.{class_name}.{method_name}")

        resolver = DictResolver(
            {
                "bigquery.Client.query": PermissionResult(
                    permissions=["bigquery.jobs.create"],
                ),
            }
        )
        result = resolver.resolve("bigquery", "Client", "query")
        assert result is not None
        assert result.permissions == ["bigquery.jobs.create"]
        assert resolver.resolve("bigquery", "Client", "nope") is None
