"""Tests for SDK introspection — discover_gcp_packages and build_method_db."""

from __future__ import annotations

import types
from unittest.mock import patch

from iamspy.introspect import (
    GENERIC_SKIP,
    DiscoveredPackage,
    build_method_db,
    find_client_classes,
)


class TestFindClientClasses:
    def test_finds_client_class(self):
        mod = types.ModuleType("google.cloud.fake")
        mod.__name__ = "google.cloud.fake"

        class FakeClient:
            __module__ = "google.cloud.fake"

        class HelperUtil:
            __module__ = "google.cloud.fake"

        mod.FakeClient = FakeClient
        mod.HelperUtil = HelperUtil

        results = find_client_classes(mod)
        names = [name for name, _ in results]
        assert "FakeClient" in names
        assert "HelperUtil" not in names

    def test_finds_transport_class(self):
        mod = types.ModuleType("google.cloud.fake")

        class GrpcTransport:
            __module__ = "google.cloud.fake"

        mod.GrpcTransport = GrpcTransport

        results = find_client_classes(mod)
        names = [name for name, _ in results]
        assert "GrpcTransport" in names

    def test_skips_non_google_classes(self):
        mod = types.ModuleType("google.cloud.fake")

        class ExternalClient:
            __module__ = "some_other_lib"

        mod.ExternalClient = ExternalClient

        results = find_client_classes(mod)
        assert len(results) == 0


class TestBuildMethodDb:
    def _make_package(self, service_id="testservice", display_name="Test Service"):
        return DiscoveredPackage(
            pip_package=f"google-cloud-{service_id}",
            service_id=service_id,
            display_name=display_name,
            modules=["google.cloud.testmod"],
        )

    def _make_mock_module(self):
        """Create a mock module with a Client class that has real methods."""
        mod = types.ModuleType("google.cloud.testmod")

        class TestClient:
            __module__ = "google.cloud.testmod"

            def query(self, sql: str, timeout: int = 30):
                pass

            def dataset(self, dataset_id: str):
                pass

            def list_tables(self, dataset: str, max_results: int = 100):
                pass

            def _private_method(self):
                pass

            def get(self, resource_id: str):
                pass

        mod.TestClient = TestClient
        return mod

    @patch("iamspy.introspect.importlib.import_module")
    def test_builds_db(self, mock_import):
        mock_import.return_value = self._make_mock_module()
        pkg = self._make_package()

        db = build_method_db(packages=[pkg])

        assert "query" in db
        assert "dataset" in db
        assert "list_tables" in db

    @patch("iamspy.introspect.importlib.import_module")
    def test_skips_private(self, mock_import):
        mock_import.return_value = self._make_mock_module()
        pkg = self._make_package()

        db = build_method_db(packages=[pkg], skip_private=True)
        assert "_private_method" not in db

    @patch("iamspy.introspect.importlib.import_module")
    def test_includes_private_when_disabled(self, mock_import):
        mock_import.return_value = self._make_mock_module()
        pkg = self._make_package()

        db = build_method_db(packages=[pkg], skip_private=False)
        assert "_private_method" in db

    @patch("iamspy.introspect.importlib.import_module")
    def test_skips_generic(self, mock_import):
        mock_import.return_value = self._make_mock_module()
        pkg = self._make_package()

        db = build_method_db(packages=[pkg], skip_generic=True)
        # CRUD methods like "get" are no longer skipped (points-to analysis
        # handles disambiguation). Only Python builtins/dunders are skipped.
        assert "get" in db
        assert "__init__" not in db
        assert "keys" not in db

    @patch("iamspy.introspect.importlib.import_module")
    def test_includes_generic_when_disabled(self, mock_import):
        mock_import.return_value = self._make_mock_module()
        pkg = self._make_package()

        db = build_method_db(packages=[pkg], skip_generic=False)
        assert "get" in db

    @patch("iamspy.introspect.importlib.import_module")
    def test_method_sig_fields(self, mock_import):
        mock_import.return_value = self._make_mock_module()
        pkg = self._make_package(service_id="myservice", display_name="My Service")

        db = build_method_db(packages=[pkg])
        sigs = db["query"]
        assert len(sigs) == 1

        sig = sigs[0]
        assert sig.class_name == "TestClient"
        assert sig.service_id == "myservice"
        assert sig.display_name == "My Service"
        assert sig.min_args == 1  # sql is required
        assert sig.max_args == 2  # sql + timeout
        assert not sig.has_var_kwargs

    @patch("iamspy.introspect.importlib.import_module")
    def test_deduplicates(self, mock_import):
        mock_import.return_value = self._make_mock_module()
        pkg = self._make_package()

        # Pass same package twice — should deduplicate
        db = build_method_db(packages=[pkg, pkg])
        for sigs in db.values():
            seen = set()
            for s in sigs:
                key = (s.min_args, s.max_args, s.has_var_kwargs, s.class_name, s.service_id)
                assert key not in seen, f"Duplicate signature: {key}"
                seen.add(key)

    @patch("iamspy.introspect.importlib.import_module")
    def test_handles_import_error(self, mock_import):
        mock_import.side_effect = ImportError("no such module")
        pkg = self._make_package()

        db = build_method_db(packages=[pkg])
        assert len(db) == 0

    @patch("iamspy.introspect.importlib.import_module")
    def test_var_kwargs_detection(self, mock_import):
        mod = types.ModuleType("google.cloud.testmod")

        class KwargsClient:
            __module__ = "google.cloud.testmod"

            def publish(self, topic: str, data: bytes, **attrs):
                pass

        mod.KwargsClient = KwargsClient
        mock_import.return_value = mod
        pkg = self._make_package()

        db = build_method_db(packages=[pkg])
        sig = db["publish"][0]
        assert sig.has_var_kwargs
        assert sig.min_args == 2  # topic, data
        assert sig.max_args == 2

    def test_empty_packages(self):
        db = build_method_db(packages=[])
        assert len(db) == 0


class TestGenericSkip:
    def test_contains_python_builtins(self):
        for name in ["keys", "values", "items", "pop", "clear"]:
            assert name in GENERIC_SKIP

    def test_contains_io_plumbing(self):
        for name in ["close", "open", "flush", "send"]:
            assert name in GENERIC_SKIP

    def test_contains_dunder_methods(self):
        for name in ["__init__", "__repr__", "__enter__", "__exit__"]:
            assert name in GENERIC_SKIP

    def test_crud_methods_not_skipped(self):
        """CRUD methods are real GCP API calls — points-to analysis disambiguates."""
        for name in ["get", "set", "delete", "list", "create", "update",
                      "read", "write", "put", "post", "patch", "run",
                      "start", "stop", "reset", "copy", "move", "exists"]:
            assert name not in GENERIC_SKIP

    def test_does_not_contain_gcp_specific(self):
        for name in ["query", "publish", "encrypt", "get_bucket"]:
            assert name not in GENERIC_SKIP
