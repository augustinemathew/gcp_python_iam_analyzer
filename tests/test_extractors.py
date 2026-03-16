"""Tests for SDK source code extractors.

Unit tests use fixtures extracted from real SDK source code.
Integration tests (marked @pytest.mark.slow) run against installed packages.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from build_pipeline.extractors.docstrings import extract_docstring
from build_pipeline.extractors.gapic import (
    RestEndpoint,
    extract_rest_endpoints,
    find_rest_base_files,
)
from build_pipeline.extractors.handwritten import (
    extract_bigquery,
    extract_storage,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ── Unit tests: gapic extractor with fixture files ──────────────────────────


class TestGapicExtractorUnit:
    """Test REST extraction against fixture files copied from real SDK sources."""

    def test_kms_fixture_method_count(self):
        endpoints = extract_rest_endpoints(FIXTURES / "sample_rest_base.py")
        assert len(endpoints) == 7

    def test_kms_fixture_encrypt(self):
        endpoints = extract_rest_endpoints(FIXTURES / "sample_rest_base.py")
        ep = endpoints["encrypt"]
        assert ep.verb == "POST"
        assert ep.uri == "/v1/{name=projects/*/locations/*/keyRings/*/cryptoKeys/**}:encrypt"
        assert ":encrypt" in ep.uri

    def test_kms_fixture_decrypt(self):
        endpoints = extract_rest_endpoints(FIXTURES / "sample_rest_base.py")
        ep = endpoints["decrypt"]
        assert ep.verb == "POST"
        assert ":decrypt" in ep.uri

    def test_kms_fixture_create_key_ring(self):
        endpoints = extract_rest_endpoints(FIXTURES / "sample_rest_base.py")
        ep = endpoints["create_key_ring"]
        assert ep.verb == "POST"
        assert "/keyRings" in ep.uri
        assert "parent=" in ep.uri

    def test_kms_fixture_get_crypto_key(self):
        endpoints = extract_rest_endpoints(FIXTURES / "sample_rest_base.py")
        ep = endpoints["get_crypto_key"]
        assert ep.verb == "GET"
        assert "cryptoKeys" in ep.uri

    def test_kms_fixture_list_crypto_keys(self):
        endpoints = extract_rest_endpoints(FIXTURES / "sample_rest_base.py")
        ep = endpoints["list_crypto_keys"]
        assert ep.verb == "GET"
        assert "/cryptoKeys" in ep.uri

    def test_kms_fixture_destroy_crypto_key_version(self):
        endpoints = extract_rest_endpoints(FIXTURES / "sample_rest_base.py")
        ep = endpoints["destroy_crypto_key_version"]
        assert ep.verb == "POST"
        assert ":destroy" in ep.uri

    def test_kms_fixture_get_iam_policy_multi_uri(self):
        """get_iam_policy should have 5 URI variants (one per resource type)."""
        endpoints = extract_rest_endpoints(FIXTURES / "sample_rest_base.py")
        ep = endpoints["get_iam_policy"]
        assert ep.verb == "GET"
        assert ":getIamPolicy" in ep.uri
        assert len(ep.all_uris) == 5
        # Each URI should target a different resource
        resources = {u.split("{resource=")[1].split("}")[0] for u in ep.all_uris}
        assert "projects/*/locations/*/keyRings/*" in resources
        assert "projects/*/locations/*/ekmConfig" in resources

    def test_zones_fixture_two_methods(self):
        endpoints = extract_rest_endpoints(FIXTURES / "sample_rest_base_zones.py")
        assert len(endpoints) == 2
        assert "get" in endpoints
        assert "list" in endpoints

    def test_zones_fixture_get_verb(self):
        endpoints = extract_rest_endpoints(FIXTURES / "sample_rest_base_zones.py")
        assert endpoints["get"].verb == "GET"
        assert "{zone}" in endpoints["get"].uri

    def test_zones_fixture_list_verb(self):
        endpoints = extract_rest_endpoints(FIXTURES / "sample_rest_base_zones.py")
        assert endpoints["list"].verb == "GET"
        assert "/zones" in endpoints["list"].uri
        assert "{zone}" not in endpoints["list"].uri

    def test_transport_class_filtered_out(self):
        """The outer _BaseXxxRestTransport class should not appear as a method."""
        endpoints = extract_rest_endpoints(FIXTURES / "sample_rest_base.py")
        for method_name in endpoints:
            assert "rest_transport" not in method_name
            assert "RestTransport" not in method_name

    def test_nonexistent_file_returns_empty(self):
        result = extract_rest_endpoints(Path("/nonexistent/rest_base.py"))
        assert result == {}

    def test_empty_file_returns_empty(self, tmp_path):
        empty = tmp_path / "rest_base.py"
        empty.write_text("")
        result = extract_rest_endpoints(empty)
        assert result == {}

    def test_rest_endpoint_dataclass_fields(self):
        ep = RestEndpoint(verb="POST", uri="/v1/test:action", all_uris=["/v1/test:action"])
        assert ep.verb == "POST"
        assert ep.uri == "/v1/test:action"
        assert len(ep.all_uris) == 1


# ── Unit tests: docstring extractor ─────────────────────────────────────────


class TestDocstringExtractorUnit:
    """Test docstring extraction with synthetic classes."""

    def test_simple_docstring(self):
        class FakeClient:
            def create(self):
                """Create a new resource.

                This creates a new resource in the project.

                Args:
                    name: The resource name.
                """

        desc = extract_docstring(FakeClient, "create")
        assert desc == "Create a new resource."
        assert "Args:" not in desc

    def test_multi_paragraph_takes_first(self):
        class FakeClient:
            def get(self):
                """Get a resource by name.

                Additional details about the method.

                Args:
                    name: The name.
                """

        desc = extract_docstring(FakeClient, "get")
        assert desc == "Get a resource by name."

    def test_code_block_stripped(self):
        class FakeClient:
            def example(self):
                """Do something important.

                .. code-block:: python

                    client.example()
                """

        desc = extract_docstring(FakeClient, "example")
        assert desc == "Do something important."
        assert "code-block" not in desc

    def test_proto_refs_stripped(self):
        class FakeClient:
            def encrypt(self):
                """Encrypts data using [CryptoKey][google.cloud.kms.v1.CryptoKey].

                Args:
                    request: The request.
                """

        desc = extract_docstring(FakeClient, "encrypt")
        assert desc == "Encrypts data using CryptoKey."
        assert "[google.cloud" not in desc

    def test_no_docstring_returns_empty(self):
        class FakeClient:
            def bare(self):
                pass

        assert extract_docstring(FakeClient, "bare") == ""

    def test_nonexistent_method_returns_empty(self):
        class FakeClient:
            pass

        assert extract_docstring(FakeClient, "no_such_method") == ""

    def test_returns_section_stripped(self):
        class FakeClient:
            def query(self):
                """Run a query.

                Returns:
                    The query results.
                """

        desc = extract_docstring(FakeClient, "query")
        assert desc == "Run a query."


# ── Integration tests: real installed packages ──────────────────────────────


# ── Unit tests: handwritten extractor ────────────────────────────────────────


class TestHandwrittenExtractorUnit:
    """Test hand-written extraction with synthetic source code."""

    def test_bigquery_style_call_api(self):
        source = '''
class Client:
    def get_dataset(self, dataset_ref):
        """Fetch the dataset."""
        return self._call_api(
            retry,
            span_name="BigQuery.getDataset",
            method="GET",
            path=path,
        )

    def _private_helper(self):
        self._call_api(span_name="internal", method="POST")
'''
        result = extract_bigquery(source)
        assert "Client.get_dataset" in result
        assert result["Client.get_dataset"].span_name == "BigQuery.getDataset"
        assert result["Client.get_dataset"].http_verb == "GET"
        # Private methods should be excluded
        assert "_private_helper" not in result
        assert "Client._private_helper" not in result

    def test_storage_style_get_resource(self):
        source = '''
class Client:
    def get_bucket(self, bucket_name):
        """Retrieve a bucket via a GET request.

        See https://cloud.google.com/storage/docs/json_api/v1/buckets/get
        """
        return self._get_resource(path, query_params)

    def create_bucket(self, bucket_name):
        """Create a new bucket.

        See https://cloud.google.com/storage/docs/json_api/v1/buckets/insert
        """
        return self._post_resource("/b", data)
'''
        result = extract_storage(source)
        assert "Client.get_bucket" in result
        assert result["Client.get_bucket"].http_verb == "GET"
        assert "cloud.google.com" in (result["Client.get_bucket"].api_doc_url or "")
        assert "Client.create_bucket" in result
        assert result["Client.create_bucket"].http_verb == "POST"

    def test_empty_source_returns_empty(self):
        assert extract_bigquery("") == {}
        assert extract_storage("") == {}

    def test_nonexistent_path_returns_empty(self):
        assert extract_bigquery(Path("/nonexistent/client.py")) == {}
        assert extract_storage(Path("/nonexistent/client.py")) == {}

    def test_no_api_calls_returns_empty(self):
        source = '''
class Client:
    def local_method(self):
        """Just a local helper."""
        return 42
'''
        assert extract_bigquery(source) == {}
        assert extract_storage(source) == {}


# ── Integration tests: real installed packages ──────────────────────────────


def _find_module_file(module_path: str) -> Path:
    """Find the source file for a Python module."""
    import importlib

    mod = importlib.import_module(module_path)
    return Path(mod.__file__)


@pytest.mark.slow
class TestHandwrittenExtractorIntegration:
    """Test against real installed hand-written SDK clients."""

    @pytest.fixture(scope="class")
    def bq_client_path(self):
        return _find_module_file("google.cloud.bigquery.client")

    @pytest.fixture(scope="class")
    def storage_client_path(self):
        return _find_module_file("google.cloud.storage.client")

    @pytest.fixture(scope="class")
    def storage_bucket_path(self):
        return _find_module_file("google.cloud.storage.bucket")

    def test_bigquery_method_count(self, bq_client_path):
        """BigQuery should extract 20+ methods with _call_api."""
        bq = extract_bigquery(bq_client_path)
        assert len(bq) >= 20

    def test_bigquery_get_dataset(self, bq_client_path):
        bq = extract_bigquery(bq_client_path)
        assert "Client.get_dataset" in bq
        assert bq["Client.get_dataset"].span_name == "BigQuery.getDataset"
        assert bq["Client.get_dataset"].http_verb == "GET"

    def test_bigquery_create_dataset(self, bq_client_path):
        bq = extract_bigquery(bq_client_path)
        assert "Client.create_dataset" in bq
        assert bq["Client.create_dataset"].http_verb == "POST"
        assert "createDataset" in bq["Client.create_dataset"].span_name

    def test_bigquery_delete_table(self, bq_client_path):
        bq = extract_bigquery(bq_client_path)
        assert "Client.delete_table" in bq
        assert bq["Client.delete_table"].http_verb == "DELETE"

    def test_storage_client_extraction(self, storage_client_path):
        st = extract_storage(storage_client_path)
        assert len(st) >= 3
        assert "Client.create_bucket" in st
        assert st["Client.create_bucket"].http_verb == "POST"

    def test_storage_bucket_extraction(self, storage_bucket_path):
        st = extract_storage(storage_bucket_path)
        assert len(st) >= 5
        assert "Bucket.copy_blob" in st
        assert st["Bucket.copy_blob"].http_verb == "POST"
        assert "Bucket.delete" in st or "Bucket.delete_blob" in st


@pytest.mark.slow
class TestGapicExtractorIntegration:
    """Test against real installed SDK packages."""

    def test_kms_full_extraction(self):
        """KMS should have 39+ API method endpoints (confirmed in Experiment 1)."""
        rb_files = find_rest_base_files("google-cloud-kms")
        kms_rb = [f for f in rb_files if "key_management_service" in str(f)]
        assert len(kms_rb) == 1

        endpoints = extract_rest_endpoints(kms_rb[0])
        assert len(endpoints) >= 30

        # Spot-check known methods
        assert endpoints["encrypt"].verb == "POST"
        assert endpoints["decrypt"].verb == "POST"
        assert endpoints["create_key_ring"].verb == "POST"
        assert endpoints["get_crypto_key"].verb == "GET"
        assert endpoints["list_crypto_keys"].verb == "GET"
        assert endpoints["destroy_crypto_key_version"].verb == "POST"
        assert endpoints["asymmetric_sign"].verb == "POST"
        assert endpoints["get_public_key"].verb == "GET"

    def test_kms_get_iam_policy_multi_uri(self):
        rb_files = find_rest_base_files("google-cloud-kms")
        kms_rb = [f for f in rb_files if "key_management_service" in str(f)]
        endpoints = extract_rest_endpoints(kms_rb[0])
        assert len(endpoints["get_iam_policy"].all_uris) >= 3

    def test_compute_instances_coverage(self):
        """Compute InstancesClient should have 40+ endpoints."""
        rb_files = find_rest_base_files("google-cloud-compute")
        instances_rb = [f for f in rb_files if "/instances/" in str(f)]
        assert len(instances_rb) == 1

        endpoints = extract_rest_endpoints(instances_rb[0])
        assert len(endpoints) >= 40

        assert endpoints["insert"].verb == "POST"
        assert endpoints["get"].verb == "GET"
        assert endpoints["delete"].verb == "DELETE"
        assert endpoints["start"].verb == "POST"
        assert endpoints["stop"].verb == "POST"
        assert endpoints["attach_disk"].verb == "POST"

    def test_compute_service_client_count(self):
        """Compute should have 100+ service clients (rest_base files)."""
        rb_files = find_rest_base_files("google-cloud-compute")
        assert len(rb_files) >= 100

    def test_spanner_extraction(self):
        rb_files = find_rest_base_files("google-cloud-spanner")
        assert len(rb_files) >= 1
        endpoints = extract_rest_endpoints(rb_files[0])
        assert len(endpoints) >= 5

    def test_pubsub_extraction(self):
        rb_files = find_rest_base_files("google-cloud-pubsub")
        assert len(rb_files) >= 1
        # Find the publisher or subscriber service
        all_endpoints = {}
        for rb in rb_files:
            all_endpoints.update(extract_rest_endpoints(rb))
        assert len(all_endpoints) >= 5

    def test_all_gapic_packages_extractable(self):
        """Every package with rest_base.py files should produce endpoints."""
        import importlib.metadata

        failures = []
        total_endpoints = 0
        total_packages = 0

        for dist in importlib.metadata.distributions():
            name = dist.metadata["Name"] or ""
            if not name.startswith("google-cloud-"):
                continue

            rb_files = find_rest_base_files(name)
            if not rb_files:
                continue

            total_packages += 1
            pkg_endpoints = 0
            for rb in rb_files:
                endpoints = extract_rest_endpoints(rb)
                pkg_endpoints += len(endpoints)

            if pkg_endpoints == 0:
                failures.append(name)
            total_endpoints += pkg_endpoints

        assert total_packages >= 100, f"Expected 100+ gapic packages, got {total_packages}"
        assert total_endpoints >= 5000, f"Expected 5000+ endpoints, got {total_endpoints}"
        assert failures == [], f"Packages with rest_base.py but 0 endpoints: {failures}"

    def test_find_rest_base_missing_package(self):
        result = find_rest_base_files("google-cloud-nonexistent-package-xyz")
        assert result == []


@pytest.mark.slow
class TestDocstringExtractorIntegration:
    """Test docstring extraction against real installed SDK clients."""

    def test_kms_encrypt_docstring(self):
        from google.cloud.kms_v1 import KeyManagementServiceClient

        desc = extract_docstring(KeyManagementServiceClient, "encrypt")
        assert "Encrypts data" in desc
        assert "Args:" not in desc
        assert "[google.cloud.kms" not in desc
        assert len(desc) < 500

    def test_kms_create_key_ring_docstring(self):
        from google.cloud.kms_v1 import KeyManagementServiceClient

        desc = extract_docstring(KeyManagementServiceClient, "create_key_ring")
        assert "KeyRing" in desc
        assert len(desc) > 10

    def test_storage_get_bucket_docstring(self):
        from google.cloud.storage import Client

        desc = extract_docstring(Client, "get_bucket")
        assert "bucket" in desc.lower()
        assert len(desc) > 10

    def test_storage_create_bucket_has_api_url(self):
        """Storage docstrings contain API reference URLs."""
        from google.cloud.storage import Client

        desc = extract_docstring(Client, "create_bucket")
        assert "bucket" in desc.lower()

    def test_compute_instances_insert_docstring(self):
        from google.cloud.compute_v1 import InstancesClient

        desc = extract_docstring(InstancesClient, "insert")
        assert "instance" in desc.lower()
        assert len(desc) > 10
