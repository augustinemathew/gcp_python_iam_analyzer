"""Tests for IAM workspace config loading."""

from __future__ import annotations

from pathlib import Path

from agents.shared.workspace import (
    WorkspaceConfig,
    init_workspace,
    load_workspace,
    update_workspace_principal,
)


class TestLoadWorkspace:
    def test_loads_valid_config(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".iamspy"
        config_dir.mkdir()
        (config_dir / "workspace.yaml").write_text("""\
project:
  name: test-app

environments:
  dev:
    gcp_project: test-dev-123
    region: us-central1
    deployment:
      target: cloud_run
      service_name: my-service
    identity:
      app:
        type: service_account
        principal: sa@test-dev-123.iam.gserviceaccount.com
  prod:
    gcp_project: test-prod-456
    region: us-central1
    deployment:
      target: cloud_run
      service_name: my-service
    identity:
      app:
        type: service_account
        principal: sa@test-prod-456.iam.gserviceaccount.com
      user:
        type: oauth
""")

        config = load_workspace(tmp_path)
        assert config is not None
        assert config.project_name == "test-app"
        assert config.env_names == ["dev", "prod"]

        dev = config.get_env("dev")
        assert dev is not None
        assert dev.gcp_project == "test-dev-123"
        assert dev.deployment.target == "cloud_run"
        assert dev.deployment.service_name == "my-service"
        assert dev.identities["app"].type == "service_account"
        assert dev.identities["app"].principal == "sa@test-dev-123.iam.gserviceaccount.com"

        prod = config.get_env("prod")
        assert prod is not None
        assert "user" in prod.identities
        assert prod.identities["user"].type == "oauth"
        assert prod.identities["user"].principal is None

    def test_returns_none_when_not_found(self, tmp_path: Path) -> None:
        config = load_workspace(tmp_path)
        assert config is None

    def test_agent_engine_config(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".iamspy"
        config_dir.mkdir()
        (config_dir / "workspace.yaml").write_text("""\
project:
  name: bill-optimizer

environments:
  dev:
    gcp_project: acme-dev
    deployment:
      target: agent_engine
      display_name: bill-optimizer-dev
    identity:
      app:
        type: agent_identity
""")

        config = load_workspace(tmp_path)
        assert config is not None
        dev = config.get_env("dev")
        assert dev.deployment.target == "agent_engine"
        assert dev.deployment.display_name == "bill-optimizer-dev"
        assert dev.identities["app"].type == "agent_identity"
        assert dev.identities["app"].principal is None


class TestInitWorkspace:
    def test_creates_config(self, tmp_path: Path) -> None:
        path = init_workspace(tmp_path, "my-project")
        assert path.exists()
        assert path.name == "workspace.yaml"
        assert path.parent.name == ".iamspy"

        config = load_workspace(tmp_path)
        assert config is not None
        assert config.project_name == "my-project"
        assert "dev" in config.environments

    def test_custom_environments(self, tmp_path: Path) -> None:
        envs = {
            "staging": {
                "gcp_project": "acme-staging",
                "deployment": {"target": "agent_engine"},
                "identity": {"app": {"type": "agent_identity"}},
            },
        }
        init_workspace(tmp_path, "my-agent", environments=envs)

        config = load_workspace(tmp_path)
        assert config is not None
        assert config.env_names == ["staging"]
        assert config.get_env("staging").deployment.target == "agent_engine"


class TestUpdateWorkspacePrincipal:
    def test_updates_null_principal(self, tmp_path: Path) -> None:
        init_workspace(tmp_path, "test", environments={
            "dev": {
                "gcp_project": "proj-123",
                "identity": {"app": {"type": "service_account", "principal": None}},
            },
        })

        updated = update_workspace_principal(tmp_path, "dev", "app", "serviceAccount:sa@proj.iam")
        assert updated is True

        config = load_workspace(tmp_path)
        assert config.get_env("dev").identities["app"].principal == "serviceAccount:sa@proj.iam"

    def test_updates_existing_principal(self, tmp_path: Path) -> None:
        init_workspace(tmp_path, "test", environments={
            "dev": {
                "gcp_project": "proj-123",
                "identity": {"app": {"type": "service_account", "principal": "old@proj.iam"}},
            },
        })

        updated = update_workspace_principal(tmp_path, "dev", "app", "serviceAccount:new@proj.iam")
        assert updated is True

        config = load_workspace(tmp_path)
        assert config.get_env("dev").identities["app"].principal == "serviceAccount:new@proj.iam"

    def test_returns_false_for_missing_env(self, tmp_path: Path) -> None:
        init_workspace(tmp_path, "test")
        assert update_workspace_principal(tmp_path, "staging", "app", "sa@proj.iam") is False

    def test_returns_false_for_missing_identity(self, tmp_path: Path) -> None:
        init_workspace(tmp_path, "test")
        assert update_workspace_principal(tmp_path, "dev", "user", "sa@proj.iam") is False

    def test_returns_false_for_no_config(self, tmp_path: Path) -> None:
        assert update_workspace_principal(tmp_path, "dev", "app", "sa@proj.iam") is False
