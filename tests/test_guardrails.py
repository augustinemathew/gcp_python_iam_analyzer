"""Tests for agent guardrails evaluation."""

from __future__ import annotations

from iamspy_mcp.shared.guardrails import (
    Category,
    GuardrailPolicy,
    Severity,
    default_dev_guardrails,
    default_prod_guardrails,
    evaluate_guardrails,
)


class TestPrivilegeEscalation:
    """Guardrails block privilege escalation permissions."""

    def test_set_iam_policy_blocked(self) -> None:
        perms = {"resourcemanager.projects.setIamPolicy", "storage.objects.get"}
        violations = evaluate_guardrails(perms, environment="prod")
        blocks = [v for v in violations if v.severity == Severity.BLOCK]
        assert any(v.permission == "resourcemanager.projects.setIamPolicy" for v in blocks)

    def test_sa_key_creation_blocked(self) -> None:
        perms = {"iam.serviceAccountKeys.create"}
        violations = evaluate_guardrails(perms, environment="prod")
        assert any(v.category == Category.PRIVILEGE_ESCALATION for v in violations)

    def test_sa_token_minting_blocked(self) -> None:
        perms = {"iam.serviceAccounts.getAccessToken"}
        violations = evaluate_guardrails(perms, environment="prod")
        assert any(v.severity == Severity.BLOCK for v in violations)

    def test_role_creation_blocked(self) -> None:
        perms = {"iam.roles.create"}
        violations = evaluate_guardrails(perms, environment="prod")
        assert any(v.category == Category.PRIVILEGE_ESCALATION for v in violations)

    def test_priv_esc_blocked_in_dev_too(self) -> None:
        """Privilege escalation is blocked even in dev."""
        perms = {"resourcemanager.projects.setIamPolicy"}
        violations = evaluate_guardrails(perms, environment="dev")
        assert any(v.severity == Severity.BLOCK for v in violations)


class TestDestructiveActions:
    """Guardrails block destructive operations in prod."""

    def test_project_delete_blocked(self) -> None:
        perms = {"resourcemanager.projects.delete"}
        violations = evaluate_guardrails(perms, environment="prod")
        assert any(
            v.permission == "resourcemanager.projects.delete" and v.severity == Severity.BLOCK
            for v in violations
        )

    def test_bucket_delete_blocked(self) -> None:
        perms = {"storage.buckets.delete"}
        violations = evaluate_guardrails(perms, environment="prod")
        assert any(v.category == Category.DESTRUCTIVE_ACTION for v in violations)

    def test_kms_destroy_blocked(self) -> None:
        perms = {"cloudkms.cryptoKeyVersions.destroy"}
        violations = evaluate_guardrails(perms, environment="prod")
        assert any(v.severity == Severity.BLOCK for v in violations)

    def test_destructive_allowed_in_dev(self) -> None:
        """Most destructive ops are allowed in dev (except project delete)."""
        perms = {"storage.buckets.delete", "bigquery.datasets.delete"}
        violations = evaluate_guardrails(perms, environment="dev")
        # Dev only blocks project delete and priv esc, not general destructive
        blocks = [v for v in violations if v.severity == Severity.BLOCK]
        assert len(blocks) == 0


class TestDataExfiltration:
    """Guardrails warn on exfiltration risk."""

    def test_export_warned(self) -> None:
        perms = {"bigquery.tables.export"}
        violations = evaluate_guardrails(perms, environment="prod")
        warns = [v for v in violations if v.category == Category.DATA_EXFILTRATION]
        assert len(warns) > 0
        assert warns[0].severity == Severity.WARN  # warn, not block

    def test_secret_access_warned(self) -> None:
        perms = {"secretmanager.versions.access"}
        violations = evaluate_guardrails(perms, environment="prod")
        assert any(v.category == Category.DATA_EXFILTRATION for v in violations)


class TestIdentityConstraints:
    """Guardrails enforce identity requirements."""

    def test_shared_sa_blocked_in_prod(self) -> None:
        violations = evaluate_guardrails(
            permissions={"storage.objects.get"},
            identity_type="service_account",
            environment="prod",
        )
        assert any(v.category == Category.IDENTITY for v in violations)

    def test_shared_sa_allowed_in_dev(self) -> None:
        violations = evaluate_guardrails(
            permissions={"storage.objects.get"},
            identity_type="service_account",
            environment="dev",
        )
        identity_blocks = [v for v in violations if v.category == Category.IDENTITY and v.severity == Severity.BLOCK]
        assert len(identity_blocks) == 0

    def test_agent_identity_passes(self) -> None:
        violations = evaluate_guardrails(
            permissions={"storage.objects.get"},
            identity_type="agent_identity",
            environment="prod",
        )
        identity_blocks = [v for v in violations if v.category == Category.IDENTITY]
        assert len(identity_blocks) == 0

    def test_impersonation_blocked(self) -> None:
        violations = evaluate_guardrails(
            permissions={"storage.objects.get"},
            identity_type="impersonated",
            environment="prod",
        )
        assert any(v.category == Category.IDENTITY for v in violations)


class TestDeniedRoles:
    """Guardrails block overly broad roles."""

    def test_editor_blocked_in_prod(self) -> None:
        violations = evaluate_guardrails(
            permissions=set(),
            roles=["roles/editor"],
            environment="prod",
        )
        assert any(v.role == "roles/editor" for v in violations)

    def test_owner_blocked(self) -> None:
        violations = evaluate_guardrails(
            permissions=set(),
            roles=["roles/owner"],
            environment="prod",
        )
        assert any(v.severity == Severity.BLOCK for v in violations)

    def test_narrow_role_passes(self) -> None:
        violations = evaluate_guardrails(
            permissions=set(),
            roles=["roles/storage.objectViewer"],
            environment="prod",
        )
        role_violations = [v for v in violations if v.rule == "denied_role"]
        assert len(role_violations) == 0


class TestOverpermissioning:
    """Guardrails flag too many permissions."""

    def test_over_max_permissions_warned(self) -> None:
        perms = {f"fake.permission.{i}" for i in range(60)}
        violations = evaluate_guardrails(perms, environment="prod")
        assert any(v.rule == "max_permissions" for v in violations)

    def test_under_max_passes(self) -> None:
        perms = {"storage.objects.get", "storage.objects.list"}
        violations = evaluate_guardrails(perms, environment="prod")
        assert not any(v.rule == "max_permissions" for v in violations)


class TestCustomPolicy:
    """Custom guardrail policies."""

    def test_denied_service(self) -> None:
        policy = GuardrailPolicy(denied_services=frozenset({"compute"}))
        violations = evaluate_guardrails(
            permissions={"compute.instances.list"},
            policy=policy,
        )
        assert any(v.category == Category.RESOURCE_BOUNDARY for v in violations)

    def test_allowed_services_only(self) -> None:
        policy = GuardrailPolicy(allowed_services=frozenset({"storage", "bigquery"}))
        violations = evaluate_guardrails(
            permissions={"storage.objects.get", "compute.instances.list"},
            policy=policy,
        )
        boundary = [v for v in violations if v.category == Category.RESOURCE_BOUNDARY]
        assert len(boundary) == 1
        assert boundary[0].permission == "compute.instances.list"

    def test_denied_pattern(self) -> None:
        policy = GuardrailPolicy(denied_permission_patterns=frozenset({"*.*.delete"}))
        violations = evaluate_guardrails(
            permissions={"storage.objects.delete", "storage.objects.get"},
            policy=policy,
        )
        assert any(v.permission == "storage.objects.delete" for v in violations)


class TestSafePermissions:
    """Normal permissions should pass without violations."""

    def test_typical_agent_passes(self) -> None:
        """A typical read-heavy agent should have no blocks in prod."""
        perms = {
            "bigquery.jobs.create",
            "bigquery.tables.getData",
            "storage.objects.get",
            "storage.objects.list",
        }
        violations = evaluate_guardrails(
            perms, identity_type="agent_identity", environment="prod",
        )
        blocks = [v for v in violations if v.severity == Severity.BLOCK]
        assert len(blocks) == 0

    def test_empty_permissions_passes(self) -> None:
        violations = evaluate_guardrails(set(), environment="prod")
        assert len(violations) == 0


class TestViolationOrdering:
    """Violations are sorted by severity."""

    def test_blocks_first(self) -> None:
        perms = {
            "resourcemanager.projects.setIamPolicy",  # block
            "bigquery.tables.export",  # warn (exfil)
        }
        violations = evaluate_guardrails(perms, environment="prod")
        assert len(violations) >= 2
        assert violations[0].severity == Severity.BLOCK
