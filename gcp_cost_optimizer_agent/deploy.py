"""Deploy the GCP Cost Optimizer to Vertex AI Agent Engine.

Uses AGENT_IDENTITY so the agent gets a per-agent identity (not a shared service account).
After deployment, grants the agent identity exactly the IAM roles it needs per iamspy analysis:
  - roles/cloudasset.viewer    (list_assets → cloudasset.assets.listResource)
  - roles/compute.viewer       (aggregated_list → compute.instances.list)

Usage:
    python deploy.py

Prints the resource name of the deployed agent, which you pass to query.py.
"""

from __future__ import annotations

import subprocess

import vertexai
from vertexai import types

from agent.build import build_agent

PROJECT = "agentengine-478902"
PROJECT_NUMBER = "16744841236"
LOCATION = "us-central1"
STAGING_BUCKET = "gs://augtestbucket"

REQUIREMENTS = [
    "google-cloud-aiplatform[agent_engines,ag2]>=1.93",
    "google-cloud-asset>=3.0",
    "google-cloud-compute>=1.0",
]

# IAM roles needed — derived from iamspy scan of agent/tools/
# cloudasset.assets.listResource  → roles/cloudasset.viewer
# compute.instances.list          → roles/compute.viewer
AGENT_IAM_ROLES = [
    "roles/cloudasset.viewer",
    "roles/compute.viewer",
]


def main() -> None:
    # vertexai.init() needed by AG2Agent constructor to read project/location
    vertexai.init(project=PROJECT, location=LOCATION)

    # vertexai.Client with v1beta1 is needed for AGENT_IDENTITY support
    client = vertexai.Client(
        project=PROJECT,
        location=LOCATION,
        http_options={"api_version": "v1beta1"},
    )

    print("Building agent...")
    agent = build_agent()

    print("Deploying to Agent Engine with AGENT_IDENTITY (this takes ~2 min)...")
    remote = client.agent_engines.create(
        agent=agent,
        config={
            "display_name": "GCP Cost Optimizer",
            "description": "Analyzes GCP resources and surfaces cost optimization recommendations.",
            "requirements": REQUIREMENTS,
            "extra_packages": ["agent"],
            "gcs_dir_name": "cost_optimizer_agent",
            "staging_bucket": STAGING_BUCKET,
            "identity_type": types.IdentityType.AGENT_IDENTITY,
        },
    )

    resource_name = remote.name
    agent_id = resource_name.split("/")[-1]

    print(f"\nDeployed: {resource_name}")
    print("\nGranting agent identity IAM roles...")
    _grant_agent_iam(agent_id)

    print(f"\nDone. Update DEFAULT_RESOURCE in query.py:")
    print(f'  {resource_name}')


def _grant_agent_iam(agent_id: str) -> None:
    """Grant the agent's AGENT_IDENTITY the IAM roles it needs.

    For orgless projects, trust domain is:
    agents.global.project-PROJECT_NUMBER.system.id.goog
    """
    principal = (
        f"principal://agents.global.project-{PROJECT_NUMBER}.system.id.goog"
        f"/resources/aiplatform/projects/{PROJECT_NUMBER}"
        f"/locations/{LOCATION}/reasoningEngines/{agent_id}"
    )

    for role in AGENT_IAM_ROLES:
        print(f"  Granting {role}...")
        result = subprocess.run(
            [
                "gcloud", "projects", "add-iam-policy-binding", PROJECT,
                f"--member={principal}",
                f"--role={role}",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"  WARNING: {result.stderr.strip()}")
        else:
            print(f"  ✓ {role}")


if __name__ == "__main__":
    main()
