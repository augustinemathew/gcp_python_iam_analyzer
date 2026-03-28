"""Canonical eval scenarios for the developer agent.

Each scenario is a Python code snippet + expected analysis output.
Used to validate the full pipeline: scan → manifest → policy recommendation.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ExpectedManifest:
    """Expected manifest output for an eval scenario."""

    app_permissions: list[str] = field(default_factory=list)
    app_conditional: list[str] = field(default_factory=list)
    user_permissions: list[str] = field(default_factory=list)
    user_oauth_scopes: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Scenario:
    """A canonical eval scenario."""

    name: str
    description: str
    code: str
    expected: ExpectedManifest


SCENARIOS: list[Scenario] = [
    # ── 1. Simple SA app ──────────────────────────────────────────────
    Scenario(
        name="simple_storage_app",
        description="Basic app reading from Cloud Storage using default credentials",
        code="""\
from google.cloud import storage

client = storage.Client()
buckets = list(client.list_buckets())
for bucket in buckets:
    blobs = list(bucket.list_blobs(max_results=10))
""",
        expected=ExpectedManifest(
            app_permissions=[
                "storage.buckets.list",
                "storage.objects.list",
            ],
            services=["storage.googleapis.com"],
        ),
    ),

    # ── 2. Multi-service agent ────────────────────────────────────────
    Scenario(
        name="multi_service_agent",
        description="Agent using BigQuery, Storage, and Secret Manager",
        code="""\
from google.cloud import bigquery, storage, secretmanager

# Read config from Secret Manager
sm = secretmanager.SecretManagerServiceClient()
secret = sm.access_secret_version(request={"name": "projects/p/secrets/config/versions/latest"})

# Query BigQuery
bq = bigquery.Client()
rows = bq.query("SELECT * FROM dataset.table LIMIT 100").result()

# Write results to GCS
gcs = storage.Client()
bucket = gcs.bucket("output-bucket")
blob = bucket.blob("results.json")
blob.upload_from_string('{"results": []}')
""",
        expected=ExpectedManifest(
            app_permissions=[
                "bigquery.jobs.create",
                "secretmanager.versions.access",
                "storage.objects.create",
            ],
            app_conditional=[
                "bigquery.tables.getData",
            ],
            services=[
                "bigquery.googleapis.com",
                "secretmanager.googleapis.com",
                "storage.googleapis.com",
            ],
        ),
    ),

    # ── 3. Dual identity — SA + OAuth user ────────────────────────────
    Scenario(
        name="dual_identity_app",
        description="App with SA for infra + OAuth user token for Drive",
        code="""\
import google.auth
from google.oauth2.credentials import Credentials
from google.cloud import storage
from googleapiclient.discovery import build

# App's own SA — access GCS
sa_creds, project = google.auth.default()
gcs = storage.Client(credentials=sa_creds, project=project)
buckets = list(gcs.list_buckets())

# User's OAuth token — access Drive
user_creds = Credentials(token=session["token"])
drive = build("drive", "v3", credentials=user_creds)
files = drive.files().list(pageSize=10).execute()
""",
        expected=ExpectedManifest(
            app_permissions=[
                "storage.buckets.list",
            ],
            user_permissions=[],  # Drive permissions are Workspace, not IAM
            services=[
                "storage.googleapis.com",
            ],
        ),
    ),

    # ── 4. Google Workspace quickstart pattern ────────────────────────
    Scenario(
        name="workspace_quickstart",
        description="Standard Google OAuth quickstart for Workspace APIs",
        code="""\
import os
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]

def main():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)

    service = build("drive", "v3", credentials=creds)
    results = service.files().list(pageSize=10).execute()
""",
        expected=ExpectedManifest(
            user_oauth_scopes=["https://www.googleapis.com/auth/drive.readonly"],
            # No IAM permissions — pure Workspace
            services=[],
        ),
    ),

    # ── 5. KMS encryption ─────────────────────────────────────────────
    Scenario(
        name="kms_encryption",
        description="App using KMS for encryption/decryption",
        code="""\
from google.cloud import kms

client = kms.KeyManagementServiceClient()

key_name = client.crypto_key_path("project", "global", "keyring", "key")

# Encrypt
encrypt_response = client.encrypt(
    request={"name": key_name, "plaintext": b"secret data"}
)

# Decrypt
decrypt_response = client.decrypt(
    request={"name": key_name, "ciphertext": encrypt_response.ciphertext}
)
""",
        expected=ExpectedManifest(
            app_permissions=[
                "cloudkms.cryptoKeyVersions.useToDecrypt",
                "cloudkms.cryptoKeyVersions.useToEncrypt",
            ],
            services=["cloudkms.googleapis.com"],
        ),
    ),

    # ── 6. Dangerous permissions ──────────────────────────────────────
    Scenario(
        name="dangerous_iam_admin",
        description="Code that modifies IAM policies — should trigger guardrails",
        code="""\
from google.cloud import resourcemanager_v3

client = resourcemanager_v3.ProjectsClient()

# Get current policy
policy = client.get_iam_policy(request={"resource": "projects/my-project"})

# Add a binding
policy.bindings.append({"role": "roles/editor", "members": ["user:someone@example.com"]})

# Set the modified policy
client.set_iam_policy(request={"resource": "projects/my-project", "policy": policy})
""",
        expected=ExpectedManifest(
            app_permissions=[
                "resourcemanager.projects.getIamPolicy",
                "resourcemanager.projects.setIamPolicy",
            ],
            services=["cloudresourcemanager.googleapis.com"],
            # Note: setIamPolicy is Ring 0 CRITICAL — guardrails should block this
        ),
    ),

    # ── 7. Domain-wide delegation ─────────────────────────────────────
    Scenario(
        name="dwd_workspace",
        description="SA with domain-wide delegation impersonating users",
        code="""\
from google.oauth2 import service_account
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

sa_creds = service_account.Credentials.from_service_account_file(
    "service-account.json", scopes=SCOPES
)
delegated_creds = sa_creds.with_subject("user@company.com")

service = build("gmail", "v1", credentials=delegated_creds)
messages = service.users().messages().list(userId="me").execute()
""",
        expected=ExpectedManifest(
            # DWD — impersonated identity, no IAM permissions needed
            # but the SA needs domain-wide delegation configured
            user_oauth_scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            services=[],
        ),
    ),

    # ── 8. Read-only agent (should pass all guardrails) ───────────────
    Scenario(
        name="readonly_agent",
        description="Agent that only reads — perfect guardrails candidate",
        code="""\
from google.cloud import bigquery, storage

bq = bigquery.Client()
tables = list(bq.list_tables("my-project.my_dataset"))

gcs = storage.Client()
blobs = list(gcs.list_blobs("my-bucket", max_results=100))
""",
        expected=ExpectedManifest(
            app_permissions=[
                "bigquery.tables.list",
                "storage.objects.list",
            ],
            services=[
                "bigquery.googleapis.com",
                "storage.googleapis.com",
            ],
        ),
    ),
]
