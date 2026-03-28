"""Delegated Identity Experiment — Cloud Run app with three identity scenarios.

Demonstrates:
1. App's SA calls GCS (SA's IAM permissions)
2. User's OAuth token calls Drive (user's Workspace access)
3. User's OAuth token calls GCS (user's IAM permissions via OAuth)

Scenario 3 is the key question: when the user's OAuth token includes the
cloud-platform scope, can the app access GCP resources using the USER's
IAM permissions (not the SA's)? This means the same GCS bucket could be
accessible via the user's token but not the SA's, or vice versa.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache

import flask
import google.auth
import google.auth.transport.requests
import google.oauth2.credentials
import google_auth_oauthlib.flow
from google.cloud import secretmanager, storage
from googleapiclient.discovery import build

app = flask.Flask(__name__)
app.secret_key = os.urandom(32)

# Cloud Run terminates TLS at the load balancer — Flask sees http://.
# ProxyFix trusts X-Forwarded-Proto so flask.url_for generates https:// URLs.
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

OAUTH_CLIENT_ID = os.environ["OAUTH_CLIENT_ID"]
PROJECT_ID = os.environ["PROJECT_ID"]

# OAuth scopes — include cloud-platform to test user accessing GCP resources
SCOPES = [
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/devstorage.read_only",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
]


@lru_cache
def _get_client_secret() -> str:
    """Fetch OAuth client secret from Secret Manager (using app's SA)."""
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{PROJECT_ID}/secrets/oauth-client-secret/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("utf-8")


def _build_flow(redirect_uri: str) -> google_auth_oauthlib.flow.Flow:
    """Build OAuth flow from client ID + secret."""
    client_config = {
        "web": {
            "client_id": OAUTH_CLIENT_ID,
            "client_secret": _get_client_secret(),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }
    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        client_config, scopes=SCOPES
    )
    flow.redirect_uri = redirect_uri
    return flow


def _get_user_credentials() -> google.oauth2.credentials.Credentials | None:
    """Build user credentials from session."""
    cred_data = flask.session.get("credentials")
    if not cred_data:
        return None
    return google.oauth2.credentials.Credentials(**cred_data)


@app.route("/")
def index() -> str:
    """Landing page."""
    return """
    <h1>Delegated Identity Experiment</h1>
    <p>Three identity scenarios on Cloud Run:</p>
    <ol>
      <li><b>SA → GCS</b>: App's service account lists buckets</li>
      <li><b>User → Drive</b>: Your OAuth token lists your Drive files</li>
      <li><b>User → GCS</b>: Your OAuth token lists buckets (your IAM permissions)</li>
    </ol>
    <p>Scenario 3 is the key test: does the GCS API see <em>your</em> IAM permissions
    when called with your OAuth token, even though the app has its own SA?</p>
    <a href="/login">Sign in with Google to start</a>
    """


@app.route("/login")
def login() -> flask.Response:
    """Start OAuth consent flow."""
    redirect_uri = flask.url_for("callback", _external=True)
    flow = _build_flow(redirect_uri)
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    flask.session["state"] = state
    # Save PKCE code_verifier — the flow object won't survive between requests
    flask.session["code_verifier"] = flow.code_verifier
    return flask.redirect(authorization_url)


@app.route("/callback")
def callback() -> flask.Response:
    """Handle OAuth callback, store credentials in session."""
    redirect_uri = flask.url_for("callback", _external=True)
    flow = _build_flow(redirect_uri)
    # Restore PKCE code_verifier from session
    flow.code_verifier = flask.session.get("code_verifier")
    flow.fetch_token(authorization_response=flask.request.url)

    credentials = flow.credentials
    flask.session["credentials"] = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": list(credentials.scopes or []),
    }
    return flask.redirect("/demo")


@app.route("/demo")
def demo() -> str:
    """The main experiment: three identity scenarios in one request."""
    user_credentials = _get_user_credentials()
    if not user_credentials:
        return flask.redirect("/login")

    results: dict[str, object] = {}

    # =========================================================
    # Scenario 1: App's SA → GCS
    # Uses the Cloud Run attached service account
    # =========================================================
    sa_credentials, project = google.auth.default()
    sa_email = getattr(sa_credentials, "service_account_email", "default")
    results["scenario_1_sa_gcs"] = {"identity": sa_email}

    try:
        sa_storage = storage.Client(credentials=sa_credentials, project=project)
        buckets = [b.name for b in sa_storage.list_buckets(max_results=5)]
        results["scenario_1_sa_gcs"]["status"] = "ok"
        results["scenario_1_sa_gcs"]["buckets"] = buckets
    except Exception as e:
        results["scenario_1_sa_gcs"]["status"] = "error"
        results["scenario_1_sa_gcs"]["error"] = str(e)

    # =========================================================
    # Scenario 2: User OAuth → Drive
    # Uses the user's OAuth token for Workspace API
    # =========================================================
    results["scenario_2_user_drive"] = {}

    # Get user info first
    try:
        oauth2_svc = build("oauth2", "v2", credentials=user_credentials)
        user_info = oauth2_svc.userinfo().get().execute()
        user_email = user_info.get("email", "unknown")
        results["scenario_2_user_drive"]["identity"] = user_email
    except Exception as e:
        user_email = f"error: {e}"
        results["scenario_2_user_drive"]["identity"] = user_email

    try:
        drive_svc = build("drive", "v3", credentials=user_credentials)
        drive_resp = (
            drive_svc.files()
            .list(pageSize=5, fields="files(id, name, mimeType)")
            .execute()
        )
        files = drive_resp.get("files", [])
        results["scenario_2_user_drive"]["status"] = "ok"
        results["scenario_2_user_drive"]["files"] = [
            {"name": f["name"], "type": f["mimeType"]} for f in files
        ]
    except Exception as e:
        results["scenario_2_user_drive"]["status"] = "error"
        results["scenario_2_user_drive"]["error"] = str(e)

    # =========================================================
    # Scenario 3: User OAuth → GCS
    # Uses the user's OAuth token for a GCP API (Cloud Storage)
    # Key question: does GCS see the USER's IAM permissions?
    # =========================================================
    results["scenario_3_user_gcs"] = {"identity": user_email}

    try:
        # Create a storage client with the USER's credentials, not the SA
        user_storage = storage.Client(
            credentials=user_credentials, project=project
        )
        user_buckets = [b.name for b in user_storage.list_buckets(max_results=5)]
        results["scenario_3_user_gcs"]["status"] = "ok"
        results["scenario_3_user_gcs"]["buckets"] = user_buckets
    except Exception as e:
        results["scenario_3_user_gcs"]["status"] = "error"
        results["scenario_3_user_gcs"]["error"] = str(e)

    # =========================================================
    # Comparison: did the two GCS calls see different things?
    # =========================================================
    sa_buckets = set(results["scenario_1_sa_gcs"].get("buckets", []))
    user_buckets_set = set(results["scenario_3_user_gcs"].get("buckets", []))

    results["comparison"] = {
        "sa_identity": sa_email,
        "user_identity": user_email,
        "sa_gcs_ok": results["scenario_1_sa_gcs"]["status"] == "ok",
        "user_drive_ok": results["scenario_2_user_drive"]["status"] == "ok",
        "user_gcs_ok": results["scenario_3_user_gcs"]["status"] == "ok",
        "same_gcs_results": sa_buckets == user_buckets_set,
        "sa_only_buckets": sorted(sa_buckets - user_buckets_set),
        "user_only_buckets": sorted(user_buckets_set - sa_buckets),
        "both_see": sorted(sa_buckets & user_buckets_set),
    }

    return f"""
    <h1>Experiment Results</h1>
    <pre>{json.dumps(results, indent=2)}</pre>
    <hr>
    <h2>Analysis</h2>
    <table border="1" cellpadding="8">
      <tr><th>Scenario</th><th>Identity</th><th>API</th><th>Result</th></tr>
      <tr>
        <td>1. SA → GCS</td>
        <td>{sa_email}</td>
        <td>storage.buckets.list</td>
        <td>{results['scenario_1_sa_gcs']['status']}</td>
      </tr>
      <tr>
        <td>2. User → Drive</td>
        <td>{user_email}</td>
        <td>drive.files.list</td>
        <td>{results['scenario_2_user_drive']['status']}</td>
      </tr>
      <tr>
        <td>3. User → GCS</td>
        <td>{user_email}</td>
        <td>storage.buckets.list</td>
        <td>{results['scenario_3_user_gcs']['status']}</td>
      </tr>
    </table>
    <h3>Key Finding</h3>
    <p>Same GCS results for SA and user? <b>{results['comparison']['same_gcs_results']}</b></p>
    <p>SA-only buckets: {results['comparison']['sa_only_buckets']}</p>
    <p>User-only buckets: {results['comparison']['user_only_buckets']}</p>
    <a href="/demo">Refresh</a> | <a href="/logout">Logout</a>
    """


@app.route("/logout")
def logout() -> flask.Response:
    """Clear session."""
    flask.session.clear()
    return flask.redirect("/")


if __name__ == "__main__":
    # Allow HTTP for local testing (OAuth requires HTTPS in production)
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
