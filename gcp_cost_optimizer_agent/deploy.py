"""Deploy the GCP Cost Optimizer to Vertex AI Agent Engine.

Uses AGENT_IDENTITY so the agent gets a per-agent identity (not a shared SA).
After deployment, grants the agent identity the IAM roles it needs.

Usage:
    python deploy.py
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import vertexai
from dotenv import load_dotenv
from vertexai import types

from gcp_cost_optimizer_agent.agent import root_agent

# Load .env from the same directory as this script.
load_dotenv(Path(__file__).parent / ".env")

PROJECT = os.environ["PROJECT"]
PROJECT_NUMBER = os.environ["PROJECT_NUMBER"]
LOCATION = os.environ.get("LOCATION", "us-central1")
STAGING_BUCKET = os.environ["STAGING_BUCKET"]

REQUIREMENTS = [
    "google-adk>=1.0.0",
    "google-cloud-aiplatform[agent_engines,adk]>=1.93",
    "google-cloud-asset>=3.0",
    "google-cloud-bigquery>=3.0",
    "google-cloud-compute>=1.0",
    "google-cloud-container>=2.0",
    "google-cloud-run>=0.10.0",
    "google-auth>=2.0",
    "cryptography>=42.0",
]

# IAM roles needed — derived from iamspy scan of agent/tools/
AGENT_IAM_ROLES = [
    "roles/aiplatform.user",       # call Gemini models
    "roles/cloudasset.viewer",     # list_resources
    "roles/compute.viewer",       # list_running_vms
    "roles/container.viewer",     # list_gke_clusters
    "roles/run.viewer",           # list_cloud_run_services
    "roles/aiplatform.viewer",    # list_agent_engines
    "roles/bigquery.jobUser",     # query_billing
    "roles/bigquery.dataViewer",  # query_billing
]


def main() -> None:
    vertexai.init(project=PROJECT, location=LOCATION)

    # v1beta1 needed for AGENT_IDENTITY support
    client = vertexai.Client(
        project=PROJECT,
        location=LOCATION,
        http_options={"api_version": "v1beta1"},
    )

    print("Deploying ADK agent to Agent Engine with AGENT_IDENTITY (~2 min)...")
    remote = client.agent_engines.create(
        agent=root_agent,
        config={
            "display_name": "GCP Cost Optimizer",
            "description": "Analyzes GCP resources and surfaces cost optimization recommendations.",
            "requirements": REQUIREMENTS,
            "extra_packages": ["gcp_cost_optimizer_agent"],
            "gcs_dir_name": "cost_optimizer_agent",
            "staging_bucket": STAGING_BUCKET,
            "identity_type": types.IdentityType.AGENT_IDENTITY,
        },
    )

    resource_name = remote.api_resource.name
    agent_id = resource_name.split("/")[-1]

    print(f"\nDeployed: {resource_name}")
    print("\nGranting agent identity IAM roles...")
    _grant_agent_iam(agent_id)

    print(f"\nDone. Update DEFAULT_RESOURCE in query.py:")
    print(f"  {resource_name}")


def _grant_agent_iam(agent_id: str) -> None:
    """Grant the agent's AGENT_IDENTITY the IAM roles it needs."""
    principal = (
        f"principal://agents.global.proj-{PROJECT_NUMBER}.system.id.goog"
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
