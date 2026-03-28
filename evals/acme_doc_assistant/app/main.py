"""Acme Doc Assistant — Cloud Run app with delegated user identity.

Users sign in with Google OAuth. The app accesses their Google Docs
and stores summaries in Cloud Storage using the app's own SA.

Two identity contexts:
- App SA: Cloud Storage (storing summaries), Secret Manager (OAuth secret)
- Delegated user: Google Docs (reading user's documents)
"""

from __future__ import annotations

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

from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

PROJECT_ID = os.environ.get("PROJECT_ID", "acme-prod")
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "")

SCOPES = [
    "https://www.googleapis.com/auth/documents.readonly",
    "https://www.googleapis.com/auth/drive.readonly",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
]


@lru_cache
def _get_oauth_secret() -> str:
    """Fetch OAuth client secret from Secret Manager (app's SA)."""
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{PROJECT_ID}/secrets/oauth-client-secret/versions/latest"
    resp = client.access_secret_version(request={"name": name})
    return resp.payload.data.decode("utf-8")


def _build_flow(redirect_uri: str) -> google_auth_oauthlib.flow.Flow:
    config = {
        "web": {
            "client_id": OAUTH_CLIENT_ID,
            "client_secret": _get_oauth_secret(),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }
    flow = google_auth_oauthlib.flow.Flow.from_client_config(config, scopes=SCOPES)
    flow.redirect_uri = redirect_uri
    return flow


@app.route("/login")
def login():
    redirect_uri = flask.url_for("callback", _external=True)
    flow = _build_flow(redirect_uri)
    url, state = flow.authorization_url(access_type="offline", prompt="consent")
    flask.session["state"] = state
    flask.session["code_verifier"] = flow.code_verifier
    return flask.redirect(url)


@app.route("/callback")
def callback():
    redirect_uri = flask.url_for("callback", _external=True)
    flow = _build_flow(redirect_uri)
    flow.code_verifier = flask.session.get("code_verifier")
    flow.fetch_token(authorization_response=flask.request.url)
    flask.session["credentials"] = {
        "token": flow.credentials.token,
        "refresh_token": flow.credentials.refresh_token,
        "token_uri": flow.credentials.token_uri,
        "client_id": flow.credentials.client_id,
        "client_secret": flow.credentials.client_secret,
        "scopes": list(flow.credentials.scopes or []),
    }
    return flask.redirect("/summarize")


@app.route("/summarize")
def summarize():
    """Read user's recent Docs, summarize, store in GCS."""
    if "credentials" not in flask.session:
        return flask.redirect("/login")

    # --- User identity: read their Google Docs ---
    user_creds = google.oauth2.credentials.Credentials(**flask.session["credentials"])

    drive = build("drive", "v3", credentials=user_creds)
    files = drive.files().list(
        q="mimeType='application/vnd.google-apps.document'",
        pageSize=5,
        fields="files(id, name)",
    ).execute().get("files", [])

    docs_service = build("docs", "v1", credentials=user_creds)
    summaries = []
    for f in files:
        doc = docs_service.documents().get(documentId=f["id"]).execute()
        title = doc.get("title", "Untitled")
        summaries.append({"id": f["id"], "title": title})

    # --- App SA identity: store summaries in GCS ---
    sa_creds, project = google.auth.default()
    gcs = storage.Client(credentials=sa_creds, project=project)
    bucket = gcs.bucket("acme-doc-summaries")
    blob = bucket.blob(f"summaries/{flask.session.get('user_email', 'unknown')}.json")

    import json
    blob.upload_from_string(json.dumps(summaries), content_type="application/json")

    return flask.jsonify({"summaries": summaries, "stored": True})


if __name__ == "__main__":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    app.run(host="0.0.0.0", port=8080, debug=True)
