"""IAM workspace config — loads .iamspy/workspace.yaml.

The workspace config defines deployment environments (dev, staging, prod)
with GCP project, region, deployment target, and identity information.

Paired with iam-manifest.yaml (what the code needs) to produce
environment-specific IAM policy recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Identity:
    """An identity definition within an environment."""

    type: str  # service_account, agent_identity, oauth
    principal: str | None = None  # filled in after deploy, or known


@dataclass(frozen=True)
class Deployment:
    """Deployment target configuration."""

    target: str  # cloud_run, cloud_run_job, agent_engine
    service_name: str | None = None
    display_name: str | None = None


@dataclass(frozen=True)
class Environment:
    """A single deployment environment."""

    name: str
    gcp_project: str
    region: str = "us-central1"
    deployment: Deployment = field(default_factory=lambda: Deployment(target="cloud_run"))
    identities: dict[str, Identity] = field(default_factory=dict)


@dataclass(frozen=True)
class WorkspaceConfig:
    """Loaded .iamspy/workspace.yaml."""

    project_name: str
    environments: dict[str, Environment]
    path: Path | None = None  # where the file was loaded from

    def get_env(self, name: str) -> Environment | None:
        return self.environments.get(name)

    @property
    def env_names(self) -> list[str]:
        return sorted(self.environments.keys())


def load_workspace(workspace_root: str | Path | None = None) -> WorkspaceConfig | None:
    """Load .iamspy/workspace.yaml from the workspace root.

    Searches upward from workspace_root (or cwd) to find .iamspy/workspace.yaml.
    Returns None if not found.
    """
    start = Path(workspace_root) if workspace_root else Path.cwd()
    config_path = _find_config(start)
    if config_path is None:
        return None
    return _parse_config(config_path)


def _find_config(start: Path) -> Path | None:
    """Search upward for .iamspy/workspace.yaml."""
    current = start.resolve()
    while True:
        candidate = current / ".iamspy" / "workspace.yaml"
        if candidate.is_file():
            return candidate
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def _parse_config(path: Path) -> WorkspaceConfig:
    """Parse a workspace.yaml file into a WorkspaceConfig."""
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"Invalid workspace config: {path}")

    project_name = data.get("project", {}).get("name", "")
    envs_data = data.get("environments", {})

    environments: dict[str, Environment] = {}
    for env_name, env_data in envs_data.items():
        if not isinstance(env_data, dict):
            continue

        # Parse deployment
        deploy_data = env_data.get("deployment", {})
        deployment = Deployment(
            target=deploy_data.get("target", "cloud_run"),
            service_name=deploy_data.get("service_name"),
            display_name=deploy_data.get("display_name"),
        )

        # Parse identities
        identities: dict[str, Identity] = {}
        ident_data = env_data.get("identity", {})
        for ident_name, ident_info in ident_data.items():
            if isinstance(ident_info, dict):
                identities[ident_name] = Identity(
                    type=ident_info.get("type", "service_account"),
                    principal=ident_info.get("principal"),
                )
            elif isinstance(ident_info, str):
                # Shorthand: just the type
                identities[ident_name] = Identity(type=ident_info)

        environments[env_name] = Environment(
            name=env_name,
            gcp_project=env_data.get("gcp_project", ""),
            region=env_data.get("region", "us-central1"),
            deployment=deployment,
            identities=identities,
        )

    return WorkspaceConfig(
        project_name=project_name,
        environments=environments,
        path=path,
    )


def init_workspace(
    workspace_root: str | Path,
    project_name: str,
    environments: dict[str, dict] | None = None,
) -> Path:
    """Create a .iamspy/workspace.yaml with initial config.

    Returns the path to the created file.
    """
    root = Path(workspace_root)
    config_dir = root / ".iamspy"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "workspace.yaml"

    data: dict = {
        "project": {"name": project_name},
        "environments": environments or {
            "dev": {
                "gcp_project": "",
                "region": "us-central1",
                "deployment": {"target": "cloud_run"},
                "identity": {
                    "app": {"type": "service_account", "principal": None},
                },
            },
        },
    }

    config_path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
    return config_path


def update_workspace_principal(
    workspace_root: str | Path,
    environment: str,
    identity_name: str,
    principal: str,
) -> bool:
    """Update the principal for an identity in a specific environment.

    Reads .iamspy/workspace.yaml, updates the principal field, writes back.

    Returns True if updated, False if environment/identity not found.
    """
    config_path = _find_config(Path(workspace_root).resolve())
    if config_path is None:
        return False

    data = yaml.safe_load(config_path.read_text())
    if not isinstance(data, dict):
        return False

    envs = data.get("environments", {})
    env = envs.get(environment)
    if env is None:
        return False

    identities = env.get("identity", {})
    ident = identities.get(identity_name)
    if ident is None:
        return False

    if isinstance(ident, dict):
        ident["principal"] = principal
    else:
        identities[identity_name] = {"type": str(ident), "principal": principal}

    config_path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
    return True
