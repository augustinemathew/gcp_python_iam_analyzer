"""Tests for s06_permission_mapping and prompt construction."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from build_pipeline.llm.prompt import build_config_d_prompt, build_v1_fallback_prompt
from build_pipeline.stages.s06_permission_mapping import (
    _try_auto_resolve_cross_service,
    map_permissions,
)


class TestConfigDPrompt:
    """Test Config D prompt construction."""

    def test_includes_rest_uri(self):
        methods = [
            {
                "class_name": "KeyManagementServiceClient",
                "method_name": "encrypt",
                "rest_method": "POST",
                "rest_uri": "/v1/{name=projects/*/locations/*/keyRings/*/cryptoKeys/**}:encrypt",
                "description": "Encrypts data.",
                "span_name": None,
            }
        ]
        prompt = build_config_d_prompt("kms", "Cloud KMS", "cloudkms", methods)
        assert "POST /v1/" in prompt
        assert ":encrypt" in prompt
        assert "cloudkms" in prompt
        assert "Encrypts data." in prompt

    def test_includes_span_name(self):
        methods = [
            {
                "class_name": "Client",
                "method_name": "get_dataset",
                "rest_method": "GET",
                "rest_uri": None,
                "description": "Fetch the dataset.",
                "span_name": "BigQuery.getDataset",
            }
        ]
        prompt = build_config_d_prompt("bigquery", "BigQuery", "bigquery", methods)
        assert "BigQuery.getDataset" in prompt

    def test_method_without_rest_uri(self):
        """Methods without REST URI should still be included."""
        methods = [
            {
                "class_name": "Client",
                "method_name": "query",
                "rest_method": None,
                "rest_uri": None,
                "description": "Run a query.",
                "span_name": None,
            }
        ]
        prompt = build_config_d_prompt("bigquery", "BigQuery", "bigquery", methods)
        assert "Client.query" in prompt
        assert "Run a query." in prompt
        assert "REST:" not in prompt  # no REST line for this method

    def test_batch_of_multiple_methods(self):
        methods = [
            {"class_name": "C", "method_name": f"method_{i}",
             "rest_method": "GET", "rest_uri": f"/v1/test/{i}",
             "description": f"Method {i}.", "span_name": None}
            for i in range(15)
        ]
        prompt = build_config_d_prompt("test", "Test", "test", methods)
        assert "method_0" in prompt
        assert "method_14" in prompt
        assert prompt.count("REST: GET") == 15

    def test_iam_prefix_in_prompt(self):
        methods = [
            {"class_name": "C", "method_name": "m",
             "rest_method": None, "rest_uri": None,
             "description": "", "span_name": None}
        ]
        prompt = build_config_d_prompt("kms", "Cloud KMS", "cloudkms", methods)
        assert "cloudkms.{resource}.{action}" in prompt

    def test_long_description_truncated(self):
        methods = [
            {"class_name": "C", "method_name": "m",
             "rest_method": None, "rest_uri": None,
             "description": "x" * 500, "span_name": None}
        ]
        prompt = build_config_d_prompt("test", "Test", "test", methods)
        # Description should be truncated to 200 chars
        assert "x" * 201 not in prompt


class TestCrossServiceAutoResolve:
    """Test auto-resolution of cross-service utility methods."""

    def test_get_operation(self):
        result = _try_auto_resolve_cross_service("get_operation", "DatasetServiceClient", "aiplatform")
        assert result is not None
        assert result["permissions"] == ["aiplatform.operations.get"]
        assert "cross-service" in result["notes"]

    def test_cancel_operation(self):
        result = _try_auto_resolve_cross_service("cancel_operation", "EndpointServiceClient", "aiplatform")
        assert result["permissions"] == ["aiplatform.operations.cancel"]

    def test_delete_operation(self):
        result = _try_auto_resolve_cross_service("delete_operation", "JobServiceClient", "aiplatform")
        assert result["permissions"] == ["aiplatform.operations.delete"]

    def test_list_operations(self):
        result = _try_auto_resolve_cross_service("list_operations", "PipelineServiceClient", "aiplatform")
        assert result["permissions"] == ["aiplatform.operations.list"]

    def test_wait_operation(self):
        result = _try_auto_resolve_cross_service("wait_operation", "ModelServiceClient", "aiplatform")
        assert result["permissions"] == ["aiplatform.operations.get"]

    def test_get_location(self):
        result = _try_auto_resolve_cross_service("get_location", "SpannerClient", "spanner")
        assert result["permissions"] == ["spanner.locations.get"]

    def test_list_locations(self):
        result = _try_auto_resolve_cross_service("list_locations", "SpannerClient", "spanner")
        assert result["permissions"] == ["spanner.locations.list"]

    def test_get_iam_policy_resource_scoped(self):
        result = _try_auto_resolve_cross_service("get_iam_policy", "KeyManagementServiceClient", "cloudkms")
        assert result is not None
        perm = result["permissions"][0]
        assert perm.startswith("cloudkms.")
        assert "getIamPolicy" in perm

    def test_set_iam_policy_resource_scoped(self):
        result = _try_auto_resolve_cross_service("set_iam_policy", "DatasetServiceClient", "aiplatform")
        assert result is not None
        perm = result["permissions"][0]
        assert "setIamPolicy" in perm

    def test_test_iam_permissions_resource_scoped(self):
        result = _try_auto_resolve_cross_service("test_iam_permissions", "BucketClient", "storage")
        assert result is not None
        perm = result["permissions"][0]
        assert "testIamPermissions" in perm

    def test_unknown_method_returns_none(self):
        result = _try_auto_resolve_cross_service("create_dataset", "DatasetServiceClient", "aiplatform")
        assert result is None

    def test_not_a_local_helper(self):
        """Cross-service methods should NOT be marked as local helpers."""
        result = _try_auto_resolve_cross_service("get_operation", "Client", "bigquery")
        assert result["local_helper"] is False

    def test_different_iam_prefixes(self):
        """Should use the iam_prefix, not service_id."""
        r1 = _try_auto_resolve_cross_service("get_operation", "Client", "cloudkms")
        assert r1["permissions"] == ["cloudkms.operations.get"]
        r2 = _try_auto_resolve_cross_service("get_operation", "Client", "compute")
        assert r2["permissions"] == ["compute.operations.get"]


class TestV1FallbackPrompt:
    """Test v1-style fallback prompt with permission list."""

    def test_includes_permission_list(self):
        methods = [
            {"class_name": "C", "method_name": "do_thing",
             "description": "Does a thing."}
        ]
        perms = ["svc.resources.create", "svc.resources.get"]
        prompt = build_v1_fallback_prompt("svc", "Service", methods, perms)
        assert "svc.resources.create" in prompt
        assert "svc.resources.get" in prompt
        assert "C.do_thing" in prompt

    def test_says_prefer_not_must(self):
        """v1 fallback should say 'prefer' not 'MUST be from'."""
        methods = [{"class_name": "C", "method_name": "m", "description": ""}]
        prompt = build_v1_fallback_prompt("svc", "Svc", methods, ["svc.a.b"])
        assert "prefer" in prompt.lower()


class TestPermissionMapping:
    """Test the mapping orchestrator with mocked Claude API."""

    @pytest.fixture
    def kms_context_file(self, tmp_path):
        """Create a minimal method_context.json with 3 KMS methods."""
        ctx = {
            "kms.KeyManagementServiceClient.encrypt": {
                "service_id": "kms",
                "class_name": "KeyManagementServiceClient",
                "method_name": "encrypt",
                "rest_method": "POST",
                "rest_uri": "/v1/{name=projects/*/locations/*/keyRings/*/cryptoKeys/**}:encrypt",
                "description": "Encrypts data.",
                "span_name": None,
                "client_type": "gapic",
            },
            "kms.KeyManagementServiceClient.decrypt": {
                "service_id": "kms",
                "class_name": "KeyManagementServiceClient",
                "method_name": "decrypt",
                "rest_method": "POST",
                "rest_uri": "/v1/{name=.../cryptoKeys/*}:decrypt",
                "description": "Decrypts data.",
                "span_name": None,
                "client_type": "gapic",
            },
            "kms.KeyManagementServiceClient.key_ring_path": {
                "service_id": "kms",
                "class_name": "KeyManagementServiceClient",
                "method_name": "key_ring_path",
                "rest_method": None,
                "rest_uri": None,
                "description": "Returns a key ring path.",
                "span_name": None,
                "client_type": "unknown",
            },
        }
        p = tmp_path / "method_context.json"
        p.write_text(json.dumps(ctx))
        return p

    @pytest.fixture
    def registry_file(self, tmp_path):
        reg = {
            "kms": {
                "service_id": "kms",
                "display_name": "Cloud KMS",
                "iam_prefix": "cloudkms",
                "pip_package": "google-cloud-kms",
            }
        }
        p = tmp_path / "service_registry.json"
        p.write_text(json.dumps(reg))
        return p

    @pytest.fixture
    def perms_file(self, tmp_path):
        perms = {
            "cloudkms": [
                "cloudkms.cryptoKeyVersions.useToEncrypt",
                "cloudkms.cryptoKeyVersions.useToDecrypt",
                "cloudkms.keyRings.create",
            ]
        }
        p = tmp_path / "iam_role_permissions.json"
        p.write_text(json.dumps(perms))
        return p

    def test_auto_resolves_path_helpers(self, kms_context_file, registry_file, perms_file, tmp_path):
        """Path helpers should be auto-resolved without calling Claude."""
        output = tmp_path / "iam_permissions.json"

        # Mock Claude to return empty — path helpers shouldn't need it
        fake_response = json.dumps({
            "KeyManagementServiceClient.encrypt": {
                "permissions": ["cloudkms.cryptoKeyVersions.useToEncrypt"],
                "conditional": [],
                "local_helper": False,
                "notes": "Encrypts data",
            },
            "KeyManagementServiceClient.decrypt": {
                "permissions": ["cloudkms.cryptoKeyVersions.useToDecrypt"],
                "conditional": [],
                "local_helper": False,
                "notes": "Decrypts data",
            },
        })

        with patch("build_pipeline.stages.s06_permission_mapping.call_claude", return_value=fake_response):
            result = map_permissions(
                method_context_path=kms_context_file,
                registry_path=registry_file,
                output_path=output,
                perms_path=perms_file,
                resume=False,
                log_dir=tmp_path / "logs",
            )

        # Path helper should be auto-resolved
        assert "kms.KeyManagementServiceClient.key_ring_path" in result
        assert result["kms.KeyManagementServiceClient.key_ring_path"]["local_helper"] is True

    def test_maps_encrypt_correctly(self, kms_context_file, registry_file, perms_file, tmp_path):
        output = tmp_path / "iam_permissions.json"

        fake_response = json.dumps({
            "KeyManagementServiceClient.encrypt": {
                "permissions": ["cloudkms.cryptoKeyVersions.useToEncrypt"],
                "conditional": [],
                "local_helper": False,
                "notes": "Encrypts data",
            },
            "KeyManagementServiceClient.decrypt": {
                "permissions": ["cloudkms.cryptoKeyVersions.useToDecrypt"],
                "conditional": [],
                "local_helper": False,
                "notes": "Decrypts data",
            },
        })

        with patch("build_pipeline.stages.s06_permission_mapping.call_claude", return_value=fake_response):
            result = map_permissions(
                method_context_path=kms_context_file,
                registry_path=registry_file,
                output_path=output,
                perms_path=perms_file,
                resume=False,
                log_dir=tmp_path / "logs",
            )

        assert "kms.KeyManagementServiceClient.encrypt" in result
        assert result["kms.KeyManagementServiceClient.encrypt"]["permissions"] == [
            "cloudkms.cryptoKeyVersions.useToEncrypt"
        ]

    def test_strips_invalid_permissions(self, kms_context_file, registry_file, perms_file, tmp_path):
        """Permissions not in iam_role_permissions.json should be stripped."""
        output = tmp_path / "iam_permissions.json"

        fake_response = json.dumps({
            "KeyManagementServiceClient.encrypt": {
                "permissions": [
                    "cloudkms.cryptoKeyVersions.useToEncrypt",
                    "cloudkms.fake.hallucinated",
                ],
                "conditional": ["cloudkms.also.fake"],
                "local_helper": False,
                "notes": "",
            },
            "KeyManagementServiceClient.decrypt": {
                "permissions": ["cloudkms.cryptoKeyVersions.useToDecrypt"],
                "conditional": [],
                "local_helper": False,
                "notes": "",
            },
        })

        with patch("build_pipeline.stages.s06_permission_mapping.call_claude", return_value=fake_response):
            result = map_permissions(
                method_context_path=kms_context_file,
                registry_path=registry_file,
                output_path=output,
                perms_path=perms_file,
                resume=False,
                log_dir=tmp_path / "logs",
            )

        enc = result["kms.KeyManagementServiceClient.encrypt"]
        assert "cloudkms.cryptoKeyVersions.useToEncrypt" in enc["permissions"]
        assert "cloudkms.fake.hallucinated" not in enc["permissions"]
        assert "cloudkms.also.fake" not in enc["conditional"]

    def test_saves_to_output_file(self, kms_context_file, registry_file, perms_file, tmp_path):
        output = tmp_path / "iam_permissions.json"

        fake_response = json.dumps({
            "KeyManagementServiceClient.encrypt": {
                "permissions": ["cloudkms.cryptoKeyVersions.useToEncrypt"],
                "conditional": [], "local_helper": False, "notes": "",
            },
            "KeyManagementServiceClient.decrypt": {
                "permissions": ["cloudkms.cryptoKeyVersions.useToDecrypt"],
                "conditional": [], "local_helper": False, "notes": "",
            },
        })

        with patch("build_pipeline.stages.s06_permission_mapping.call_claude", return_value=fake_response):
            map_permissions(
                method_context_path=kms_context_file,
                registry_path=registry_file,
                output_path=output,
                perms_path=perms_file,
                resume=False,
                log_dir=tmp_path / "logs",
            )

        assert output.exists()
        with open(output) as f:
            saved = json.load(f)
        assert len(saved) >= 3  # 2 LLM + 1 auto-resolved

    def test_resume_skips_existing(self, kms_context_file, registry_file, perms_file, tmp_path):
        """When resuming, already-mapped methods should not be sent to LLM."""
        output = tmp_path / "iam_permissions.json"

        # Pre-populate with all methods already mapped
        existing = {
            "kms.KeyManagementServiceClient.encrypt": {
                "permissions": ["cloudkms.cryptoKeyVersions.useToEncrypt"],
                "conditional": [], "local_helper": False, "notes": "",
            },
            "kms.KeyManagementServiceClient.decrypt": {
                "permissions": ["cloudkms.cryptoKeyVersions.useToDecrypt"],
                "conditional": [], "local_helper": False, "notes": "",
            },
        }
        output.write_text(json.dumps(existing))

        # Claude should NOT be called
        with patch("build_pipeline.stages.s06_permission_mapping.call_claude") as mock_claude:
            result = map_permissions(
                method_context_path=kms_context_file,
                registry_path=registry_file,
                output_path=output,
                perms_path=perms_file,
                resume=True,
                log_dir=tmp_path / "logs",
            )

        mock_claude.assert_not_called()
        assert len(result) >= 3  # 2 existing + 1 auto-resolved path helper
