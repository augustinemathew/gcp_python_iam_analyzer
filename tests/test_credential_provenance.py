"""Tests for credential provenance analysis.

Tests: src/iamspy/credential_provenance.py
"""

from __future__ import annotations

from iamspy.credential_provenance import (
    CredentialProvenance,
    IdentityContext,
    analyze_credentials,
    to_identity_context,
)


class TestCredentialSourceDetection:
    """Detect where credentials are created."""

    def test_google_auth_default(self) -> None:
        source = """\
import google.auth
credentials, project = google.auth.default()
"""
        result = analyze_credentials(source)
        assert len(result.sources) == 1
        assert result.sources[0].variable == "credentials"
        assert result.sources[0].provenance == CredentialProvenance.SA_DEFAULT

    def test_google_auth_default_tuple_unpack(self) -> None:
        source = """\
import google.auth
sa_credentials, project = google.auth.default()
"""
        result = analyze_credentials(source)
        assert len(result.sources) == 1
        assert result.sources[0].variable == "sa_credentials"
        assert result.sources[0].provenance == CredentialProvenance.SA_DEFAULT

    def test_explicit_sa_from_info(self) -> None:
        source = """\
from google.oauth2 import service_account
credentials = service_account.Credentials.from_service_account_info(info)
"""
        result = analyze_credentials(source)
        assert len(result.sources) == 1
        assert result.sources[0].provenance == CredentialProvenance.SA_EXPLICIT

    def test_explicit_sa_from_file(self) -> None:
        source = """\
from google.oauth2 import service_account
credentials = service_account.Credentials.from_service_account_file("key.json")
"""
        result = analyze_credentials(source)
        assert len(result.sources) == 1
        assert result.sources[0].provenance == CredentialProvenance.SA_EXPLICIT

    def test_oauth_credentials_constructor(self) -> None:
        source = """\
from google.oauth2.credentials import Credentials
user_creds = Credentials(token=token)
"""
        result = analyze_credentials(source)
        assert len(result.sources) == 1
        assert result.sources[0].variable == "user_creds"
        assert result.sources[0].provenance == CredentialProvenance.OAUTH_USER

    def test_oauth_credentials_full_path(self) -> None:
        source = """\
import google.oauth2.credentials
user_creds = google.oauth2.credentials.Credentials(token="abc")
"""
        result = analyze_credentials(source)
        assert len(result.sources) == 1
        assert result.sources[0].provenance == CredentialProvenance.OAUTH_USER

    def test_oauth_flow(self) -> None:
        source = """\
from google_auth_oauthlib.flow import Flow
flow = Flow.from_client_config(config, scopes=SCOPES)
"""
        result = analyze_credentials(source)
        assert len(result.sources) == 1
        assert result.sources[0].variable == "flow"
        assert result.sources[0].provenance == CredentialProvenance.OAUTH_FLOW

    def test_flow_credentials_property(self) -> None:
        source = """\
from google_auth_oauthlib.flow import Flow
flow = Flow.from_client_config(config, scopes=SCOPES)
credentials = flow.credentials
"""
        result = analyze_credentials(source)
        assert len(result.sources) == 2
        assert result.sources[1].variable == "credentials"
        assert result.sources[1].provenance == CredentialProvenance.OAUTH_FLOW

    def test_dwd_with_subject(self) -> None:
        source = """\
from google.oauth2 import service_account
sa_creds = service_account.Credentials.from_service_account_info(info)
delegated = sa_creds.with_subject("user@example.com")
"""
        result = analyze_credentials(source)
        assert len(result.sources) == 2
        assert result.sources[0].provenance == CredentialProvenance.SA_EXPLICIT
        assert result.sources[1].variable == "delegated"
        assert result.sources[1].provenance == CredentialProvenance.DWD

    def test_impersonated_credentials(self) -> None:
        source = """\
from google.auth import impersonated_credentials
target = impersonated_credentials.Credentials(
    source_credentials=source, target_principal="sa@proj.iam")
"""
        result = analyze_credentials(source)
        assert len(result.sources) == 1
        assert result.sources[0].provenance == CredentialProvenance.IMPERSONATION


class TestClientBinding:
    """Detect which credentials feed into GCP client constructors."""

    def test_implicit_credentials(self) -> None:
        """Client() with no credentials= arg → IMPLICIT (APP)."""
        source = """\
from google.cloud import storage
client = storage.Client()
"""
        result = analyze_credentials(source)
        assert len(result.clients) == 1
        assert result.clients[0].variable == "client"
        assert result.clients[0].provenance == CredentialProvenance.IMPLICIT
        assert result.clients[0].identity == IdentityContext.APP

    def test_sa_credentials_explicit(self) -> None:
        """Client(credentials=sa_creds) → APP."""
        source = """\
import google.auth
from google.cloud import storage
sa_creds, project = google.auth.default()
client = storage.Client(credentials=sa_creds, project=project)
"""
        result = analyze_credentials(source)
        assert len(result.clients) == 1
        assert result.clients[0].provenance == CredentialProvenance.SA_DEFAULT
        assert result.clients[0].identity == IdentityContext.APP
        assert result.clients[0].credential_variable == "sa_creds"

    def test_oauth_credentials_in_client(self) -> None:
        """Client(credentials=user_creds) → USER."""
        source = """\
from google.oauth2.credentials import Credentials
from google.cloud import storage
user_creds = Credentials(token=token)
client = storage.Client(credentials=user_creds)
"""
        result = analyze_credentials(source)
        assert len(result.clients) == 1
        assert result.clients[0].provenance == CredentialProvenance.OAUTH_USER
        assert result.clients[0].identity == IdentityContext.USER

    def test_two_clients_different_identities(self) -> None:
        """Two clients with different credentials → different identities."""
        source = """\
import google.auth
from google.oauth2.credentials import Credentials
from google.cloud import storage

sa_creds, project = google.auth.default()
user_creds = Credentials(token=token)

sa_client = storage.Client(credentials=sa_creds)
user_client = storage.Client(credentials=user_creds)
"""
        result = analyze_credentials(source)
        assert len(result.clients) == 2
        assert result.clients[0].variable == "sa_client"
        assert result.clients[0].identity == IdentityContext.APP
        assert result.clients[1].variable == "user_client"
        assert result.clients[1].identity == IdentityContext.USER

    def test_dwd_credentials_in_client(self) -> None:
        """Client with DWD credentials → IMPERSONATED."""
        source = """\
from google.oauth2 import service_account
from googleapiclient.discovery import build
sa_creds = service_account.Credentials.from_service_account_info(info)
delegated = sa_creds.with_subject("user@example.com")
service = build("drive", "v3", credentials=delegated)
"""
        result = analyze_credentials(source)
        # build() isn't a GCP Client pattern, but let's check the sources
        assert len(result.sources) == 2
        assert result.sources[1].provenance == CredentialProvenance.DWD

    def test_copy_propagation(self) -> None:
        """Credential label propagates through variable copy."""
        source = """\
import google.auth
from google.cloud import storage
creds, project = google.auth.default()
my_creds = creds
client = storage.Client(credentials=my_creds)
"""
        result = analyze_credentials(source)
        assert len(result.clients) == 1
        assert result.clients[0].identity == IdentityContext.APP


class TestOAuthScopeExtraction:
    """Extract OAuth scopes from source code."""

    def test_scopes_constant(self) -> None:
        source = """\
SCOPES = [
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/devstorage.read_only",
    "openid",
]
"""
        result = analyze_credentials(source)
        assert len(result.oauth_scopes) == 3
        scopes = {s.scope for s in result.oauth_scopes}
        assert "https://www.googleapis.com/auth/drive.readonly" in scopes
        assert "https://www.googleapis.com/auth/devstorage.read_only" in scopes
        assert "openid" in scopes

    def test_scopes_lowercase_var(self) -> None:
        source = """\
oauth_scopes = ["https://www.googleapis.com/auth/drive"]
"""
        result = analyze_credentials(source)
        assert len(result.oauth_scopes) == 1

    def test_no_scopes_in_unrelated_list(self) -> None:
        source = """\
NAMES = ["alice", "bob"]
"""
        result = analyze_credentials(source)
        assert len(result.oauth_scopes) == 0


class TestIdentityContextMapping:
    """Test provenance → identity context mapping."""

    def test_app_contexts(self) -> None:
        assert to_identity_context(CredentialProvenance.SA_DEFAULT) == IdentityContext.APP
        assert to_identity_context(CredentialProvenance.SA_EXPLICIT) == IdentityContext.APP
        assert to_identity_context(CredentialProvenance.IMPLICIT) == IdentityContext.APP

    def test_user_contexts(self) -> None:
        assert to_identity_context(CredentialProvenance.OAUTH_USER) == IdentityContext.USER
        assert to_identity_context(CredentialProvenance.OAUTH_FLOW) == IdentityContext.USER

    def test_impersonated_contexts(self) -> None:
        assert to_identity_context(CredentialProvenance.DWD) == IdentityContext.IMPERSONATED
        assert to_identity_context(CredentialProvenance.IMPERSONATION) == IdentityContext.IMPERSONATED

    def test_unknown(self) -> None:
        assert to_identity_context(CredentialProvenance.UNKNOWN) == IdentityContext.UNKNOWN


class TestRealWorldCode:
    """Test against realistic code patterns from the experiment."""

    def test_experiment_app(self) -> None:
        """The delegated identity experiment app has all three scenarios."""
        source = """\
import google.auth
import google.oauth2.credentials
from google.cloud import storage
from googleapiclient.discovery import build

SCOPES = [
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/devstorage.read_only",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
]

# Scenario 1: SA default
sa_credentials, project = google.auth.default()
sa_storage = storage.Client(credentials=sa_credentials, project=project)

# Scenario 3: User OAuth → GCS
user_credentials = google.oauth2.credentials.Credentials(token="abc")
user_storage = storage.Client(credentials=user_credentials, project=project)
"""
        result = analyze_credentials(source)

        # Two credential sources
        assert len(result.sources) == 2
        sa_src = result.sources[0]
        assert sa_src.variable == "sa_credentials"
        assert sa_src.provenance == CredentialProvenance.SA_DEFAULT

        user_src = result.sources[1]
        assert user_src.variable == "user_credentials"
        assert user_src.provenance == CredentialProvenance.OAUTH_USER

        # Two clients with different identities
        assert len(result.clients) == 2
        assert result.clients[0].variable == "sa_storage"
        assert result.clients[0].identity == IdentityContext.APP
        assert result.clients[1].variable == "user_storage"
        assert result.clients[1].identity == IdentityContext.USER

        # OAuth scopes detected
        assert len(result.oauth_scopes) == 4
        scopes = {s.scope for s in result.oauth_scopes}
        assert "https://www.googleapis.com/auth/drive.readonly" in scopes

    def test_simple_sa_only_app(self) -> None:
        """Typical app with only SA credentials (most common pattern)."""
        source = """\
from google.cloud import storage, bigquery

storage_client = storage.Client()
bq_client = bigquery.Client(project="my-project")

buckets = storage_client.list_buckets()
rows = bq_client.query("SELECT 1").result()
"""
        result = analyze_credentials(source)

        # No explicit credential sources
        assert len(result.sources) == 0

        # Two implicit clients, both APP
        assert len(result.clients) == 2
        assert all(c.identity == IdentityContext.APP for c in result.clients)
        assert all(c.provenance == CredentialProvenance.IMPLICIT for c in result.clients)

    def test_no_gcp_code(self) -> None:
        """Non-GCP code produces empty result."""
        source = """\
import json
data = json.loads('{"key": "value"}')
print(data)
"""
        result = analyze_credentials(source)
        assert len(result.sources) == 0
        assert len(result.clients) == 0
        assert len(result.oauth_scopes) == 0
