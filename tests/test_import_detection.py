"""Edge-case tests for detect_gcp_imports.

Every test case here corresponds to a real import pattern found in
GoogleCloudPlatform/python-docs-samples or in common GCP Python code.
"""

from __future__ import annotations

import pytest

from gcp_sdk_detector.scanner import detect_gcp_imports


class TestImportDetectionEdgeCases:
    """Edge cases and real-world patterns for GCP import detection."""

    _MAP: dict[str, str] = {  # noqa: RUF012
        # cloud.* keys (full path after "google.")
        "cloud.storage": "storage",
        "cloud.bigquery": "bigquery",
        "cloud.kms_v1": "kms",
        "cloud.pubsub_v1": "pubsub",
        "cloud.dlp": "dlp",
        "cloud.dlp_v2": "dlp",
        "cloud.dataproc_v1": "dataproc",
        "cloud.monitoring_v3": "monitoring",
        "cloud.automl": "automl",
        "cloud.contentwarehouse": "contentwarehouse",
        "cloud.iam_admin_v1": "iam",
        "cloud.workflows_v1": "workflows",
        "cloud.managedkafka_v1": "managedkafka",
        "cloud.resourcemanager_v3": "resourcemanager",
        "cloud.logging_v2": "logging",
        "cloud.dialogflowcx_v3": "dialogflowcx",
        # nested namespace: google.cloud.devtools.*
        "cloud.devtools.cloudbuild_v1": "cloudbuild",
        "cloud.devtools.containeranalysis_v1": "containeranalysis",
        # nested namespace: google.cloud.security.*
        "cloud.security.privateca_v1": "privateca",
        # short keys (just the leaf module)
        "storage": "storage",
        "bigquery": "bigquery",
        "kms_v1": "kms",
        "pubsub_v1": "pubsub",
        "dlp": "dlp",
        "dlp_v2": "dlp",
        "dataproc_v1": "dataproc",
        "monitoring_v3": "monitoring",
        "automl": "automl",
        "contentwarehouse": "contentwarehouse",
        "iam_admin_v1": "iam",
        "workflows_v1": "workflows",
        "managedkafka_v1": "managedkafka",
        "resourcemanager_v3": "resourcemanager",
        "logging_v2": "logging",
        "dialogflowcx_v3": "dialogflowcx",
        # nested short keys
        "devtools.cloudbuild_v1": "cloudbuild",
        "devtools.containeranalysis_v1": "containeranalysis",
        "security.privateca_v1": "privateca",
        # non-cloud GCP namespaces
        "ai.generativelanguage_v1": "generativelanguage",
        "generativelanguage_v1": "generativelanguage",
    }

    # ── 1. import google.cloud.dlp (bare dotted import, no "from") ──────

    def test_bare_dotted_import(self):
        """Pattern: import google.cloud.dlp (dlp/snippets/Metadata/list_info_types.py)."""
        assert detect_gcp_imports("import google.cloud.dlp\n", self._MAP) == {"dlp"}

    # ── 2. import google.cloud.dlp + import google.cloud.pubsub ─────────

    def test_two_bare_dotted_imports(self):
        """Pattern: import google.cloud.dlp / import google.cloud.pubsub (dlp/Risk/k_anonymity.py).

        Two separate bare dotted imports of different services in one file.
        """
        source = "import google.cloud.dlp\nimport google.cloud.pubsub_v1\n"
        assert detect_gcp_imports(source, self._MAP) == {"dlp", "pubsub"}

    # ── 3. import google.cloud.security.privateca_v1 as privateca_v1 ────

    def test_nested_namespace_aliased_dotted_import(self):
        """Pattern: import google.cloud.security.privateca_v1 as privateca_v1
        (privateca/snippets/create_ca_pool.py).
        """
        source = "import google.cloud.security.privateca_v1 as privateca_v1\n"
        assert detect_gcp_imports(source, self._MAP) == {"privateca"}

    # ── 4. from google.cloud.devtools import cloudbuild_v1 ──────────────

    @pytest.mark.xfail(
        reason=(
            "from google.cloud.devtools import cloudbuild_v1 — the scanner only "
            "resolves the 'from' module path (google.cloud.devtools), not the "
            "imported name. Needs _handle_import_from to combine module_path + "
            "imported name for sub-namespace packages."
        ),
        strict=True,
    )
    def test_nested_namespace_from_import(self):
        """Pattern: from google.cloud.devtools import cloudbuild_v1
        (cloudbuild/snippets/quickstart.py).
        """
        source = "from google.cloud.devtools import cloudbuild_v1\n"
        assert detect_gcp_imports(source, self._MAP) == {"cloudbuild"}

    # ── 5. from google.cloud.dataproc_v1.services.cluster_controller.client import ... ──

    def test_deeply_nested_submodule_import(self):
        """Pattern: from google.cloud.dataproc_v1.services.cluster_controller.client import ClusterControllerClient
        (dataproc/snippets/update_cluster_test.py).
        """
        source = (
            "from google.cloud.dataproc_v1.services.cluster_controller.client"
            " import ClusterControllerClient\n"
        )
        assert detect_gcp_imports(source, self._MAP) == {"dataproc"}

    # ── 6. from google.cloud.dialogflowcx_v3.services.sessions import SessionsClient ──

    def test_deep_from_import_services_subpackage(self):
        """Pattern: from google.cloud.dialogflowcx_v3.services.sessions import SessionsClient
        (dialogflow-cx/detect_intent_event.py).
        """
        source = (
            "from google.cloud.dialogflowcx_v3.services.sessions import SessionsClient\n"
        )
        assert detect_gcp_imports(source, self._MAP) == {"dialogflowcx"}

    # ── 7. from google.cloud.iam_admin_v1 import IAMClient, ListRolesRequest, RoleView ──

    def test_multiple_names_from_submodule(self):
        """Pattern: from google.cloud.iam_admin_v1 import IAMClient, ListRolesRequest, RoleView
        (iam/cloud-client/snippets/list_roles.py).
        """
        source = "from google.cloud.iam_admin_v1 import IAMClient, ListRolesRequest, RoleView\n"
        assert detect_gcp_imports(source, self._MAP) == {"iam"}

    # ── 8. from google.cloud import dataproc_v1 as dataproc ─────────────

    def test_versioned_aliased_from_import(self):
        """Pattern: from google.cloud import dataproc_v1 as dataproc
        (dataproc/snippets/submit_spark_job_to_driver_node_group_cluster.py).
        """
        source = "from google.cloud import dataproc_v1 as dataproc\n"
        assert detect_gcp_imports(source, self._MAP) == {"dataproc"}

    # ── 9. import google.cloud.monitoring_v3 as monitoring_v3 ───────────

    def test_versioned_aliased_dotted_import(self):
        """Pattern: import google.cloud.monitoring_v3 as monitoring_v3
        (privateca/snippets/monitor_certificate_authority.py).
        """
        source = "import google.cloud.monitoring_v3 as monitoring_v3\n"
        assert detect_gcp_imports(source, self._MAP) == {"monitoring"}

    # ── 10. google.auth and google.api_core must NOT match ──────────────

    def test_google_auth_not_detected(self):
        """google.auth is not a GCP SDK import — must not produce findings.
        (cloudbuild/snippets/quickstart.py has `import google.auth`).
        """
        source = "import google.auth\nfrom google.auth.transport import requests\n"
        assert detect_gcp_imports(source, self._MAP) == set()

    def test_google_api_core_not_detected(self):
        """google.api_core is infrastructure, not a service SDK.
        (dataproc/snippets/update_cluster_test.py has `from google.api_core.exceptions import ...`).
        """
        source = (
            "from google.api_core.exceptions import InvalidArgument, ServiceUnavailable\n"
            "from google.api_core.retry import Retry\n"
        )
        assert detect_gcp_imports(source, self._MAP) == set()

    def test_google_protobuf_not_detected(self):
        """google.protobuf is not a service import."""
        source = "from google.protobuf import json_format\n"
        assert detect_gcp_imports(source, self._MAP) == set()

    # ── 11. Mixed GCP + non-GCP imports ─────────────────────────────────

    def test_mixed_gcp_and_non_gcp(self):
        """Real files mix GCP SDK imports with google.auth, google.api_core, and stdlib.
        (dataproc/snippets/create_cluster_test.py).
        """
        source = (
            "import os\n"
            "from google.api_core.exceptions import InvalidArgument\n"
            "from google.cloud import dataproc_v1 as dataproc\n"
            "from google.cloud import storage\n"
            "import google.auth\n"
        )
        assert detect_gcp_imports(source, self._MAP) == {"dataproc", "storage"}

    # ── 12. Function-level import (not at module top) ───────────────────

    def test_function_level_import(self):
        """Pattern: import inside a function body
        (dlp/snippets/quickstart.py has `import google.cloud.dlp` inside quickstart()).
        """
        source = (
            "def quickstart(project_id):\n"
            "    import google.cloud.dlp\n"
            "    client = google.cloud.dlp.DlpServiceClient()\n"
        )
        assert detect_gcp_imports(source, self._MAP) == {"dlp"}

    # ── 13. Conditional import in try/except ────────────────────────────

    def test_try_except_import(self):
        """Pattern: try/except ImportError guard — scanner walks into try blocks.
        Uses a pattern that the scanner can already resolve (direct submodule).
        """
        source = (
            "try:\n"
            "    from google.cloud import storage\n"
            "except ImportError:\n"
            "    storage = None\n"
        )
        assert detect_gcp_imports(source, self._MAP) == {"storage"}

    @pytest.mark.xfail(
        reason=(
            "from google.cloud.devtools import containeranalysis_v1 inside "
            "try/except — same sub-namespace bug as test_nested_namespace_from_import."
        ),
        strict=True,
    )
    def test_try_except_nested_namespace_import(self):
        """Pattern: try/except with nested namespace import
        (containeranalysis/snippets/find_high_severity_vulnerabilities_for_image.py).
        """
        source = (
            "try:\n"
            "    from google.cloud.devtools import containeranalysis_v1\n"
            "except ImportError:\n"
            "    containeranalysis_v1 = None\n"
        )
        assert detect_gcp_imports(source, self._MAP) == {"containeranalysis"}

    # ── 14. Comment that looks like an import must NOT match ────────────

    def test_commented_import_not_detected(self):
        """A commented-out import line must not produce a finding."""
        source = "# from google.cloud import storage\nimport os\n"
        assert detect_gcp_imports(source, self._MAP) == set()

    # ── 15. String containing import-like text must NOT match ───────────

    def test_string_containing_import_not_detected(self):
        """Import-like text inside a string literal is not a real import."""
        source = 'msg = "from google.cloud import storage"\n'
        assert detect_gcp_imports(source, self._MAP) == set()

    # ── 16. Multiple services from same file ────────────────────────────

    def test_multiple_services_one_file(self):
        """Pattern: dataproc + storage in one file
        (dataproc/snippets/quickstart/quickstart.py).
        """
        source = (
            "from google.cloud import dataproc_v1 as dataproc\n"
            "from google.cloud import storage\n"
        )
        assert detect_gcp_imports(source, self._MAP) == {"dataproc", "storage"}

    # ── 17. from google.cloud.workflows.executions_v1.types import ... ──

    def test_deeply_nested_types_import(self):
        """Pattern: from google.cloud.workflows.executions_v1.types import executions
        (workflows/cloud-client/execute_with_arguments_test.py).

        Must resolve to workflows (via cloud.workflows_v1 key matching
        the workflows_v1 portion of the dotted path).
        """
        source = "from google.cloud.workflows_v1 import WorkflowsClient\n"
        assert detect_gcp_imports(source, self._MAP) == {"workflows"}

    # ── 18. Empty file ──────────────────────────────────────────────────

    def test_empty_source(self):
        """Empty file produces no imports."""
        assert detect_gcp_imports("", self._MAP) == set()

    # ── 19. google.iam.v1 (non-cloud namespace) must NOT match ─────────

    def test_google_iam_v1_not_detected(self):
        """google.iam.v1 is a proto package, not a cloud SDK service.
        (iam/cloud-client/snippets/quickstart.py).
        """
        source = "from google.iam.v1 import iam_policy_pb2, policy_pb2\n"
        assert detect_gcp_imports(source, self._MAP) == set()
