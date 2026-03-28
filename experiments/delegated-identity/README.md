# Experiment: Delegated Identities on GCP

## Question

Can a Cloud Run app operate with **two identity contexts simultaneously**?

1. **App's own identity** (SA) — for GCP infrastructure (Secret Manager, Cloud Storage, BigQuery)
2. **Delegated user identity** (OAuth) — for user-scoped resources (Google Docs, Drive, Gmail)

And critically: **what does iamspy need to model?** If an app has both identity types, the manifest needs to capture permissions for each separately.

## Hypothesis

A Cloud Run app with an OAuth client ID can:
- Use its attached SA for GCP API calls (storage, bigquery, etc.)
- Use OAuth access tokens (from user consent) for Workspace API calls (docs, drive)
- The two identity contexts are completely independent
- The effective permissions are: SA permissions for GCP, user permissions (scoped by OAuth consent) for Workspace

## What We're Testing

### Test 1: OAuth web flow on Cloud Run
Deploy a minimal Flask app on Cloud Run that:
1. Redirects user to Google OAuth consent (requesting `drive.readonly` scope)
2. Exchanges auth code for access token
3. Lists the user's recent Google Drive files using the **user's** token
4. Lists GCS buckets using the **app's SA** token
5. Returns both results — proving two identity contexts in one request

### Test 2: Token inspection
For each API call, capture:
- What identity the API sees (from response headers / audit logs)
- What permissions were checked
- Whether scope or IAM was the limiting factor

### Test 3: Identity model for iamspy manifest
Based on findings, define how the manifest should represent dual-identity apps:

```yaml
# Hypothesized manifest structure
identities:
  service_account:
    principal: "serviceAccount:app-sa@proj.iam.gserviceaccount.com"
    permissions:
      required:
        - storage.buckets.list
        - storage.objects.get
        - secretmanager.versions.access
  delegated_user:
    oauth_scopes:
      - "https://www.googleapis.com/auth/drive.readonly"
      - "https://www.googleapis.com/auth/documents.readonly"
    # No IAM permissions listed — user's own access applies
    # iamspy can't know what the user has access to
    # But we CAN list what Workspace APIs the code calls
    workspace_apis:
      - service: Google Drive
        operations: [files.list, files.get]
      - service: Google Docs
        operations: [documents.get]
```

## Architecture

```
                    ┌──────────────────────────┐
                    │  Cloud Run Service        │
                    │  SA: app-sa@proj.iam      │
                    │  OAuth Client: <client_id>│
                    │                           │
  User ──browser──→ │  /login                   │──→ Google OAuth consent
                    │  /callback                │←── auth code
                    │                           │
                    │  /demo                    │
                    │   ├─ user_token ──────────│──→ Drive API (as user)
                    │   └─ sa_credentials ──────│──→ GCS API (as SA)
                    │                           │
                    └──────────────────────────┘
```

## Setup

### Prerequisites
- GCP project with billing enabled
- OAuth consent screen configured (internal or testing mode)
- OAuth 2.0 Web Application client ID created
- Cloud Run API enabled
- `gcloud` authenticated

### Steps

```bash
# 1. Set project
export PROJECT_ID=agentengine-478902
export REGION=us-central1
gcloud config set project $PROJECT_ID

# 2. Create OAuth client (or use existing)
# Go to: https://console.cloud.google.com/apis/credentials
# Create OAuth 2.0 Client ID → Web application
# Authorized redirect URI: will be set after deploy

# 3. Store client secret
echo -n "YOUR_CLIENT_SECRET" | gcloud secrets create oauth-client-secret \
  --data-file=- --replication-policy=automatic

# 4. Create SA with minimal permissions
gcloud iam service-accounts create delegated-id-experiment \
  --display-name="Delegated Identity Experiment"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:delegated-id-experiment@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer"

gcloud secrets add-iam-policy-binding oauth-client-secret \
  --member="serviceAccount:delegated-id-experiment@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# 5. Deploy
gcloud run deploy delegated-id-experiment \
  --source=. \
  --region=$REGION \
  --service-account=delegated-id-experiment@$PROJECT_ID.iam.gserviceaccount.com \
  --allow-unauthenticated \
  --set-env-vars="OAUTH_CLIENT_ID=<your-client-id>,PROJECT_ID=$PROJECT_ID"

# 6. Update OAuth redirect URI
# Add https://<cloud-run-url>/callback to authorized redirect URIs in console

# 7. Test
open https://<cloud-run-url>/login
```

## What to Observe

1. **Drive API call**: Does it return the user's files? (confirms delegation works)
2. **GCS API call**: Does it use the SA? (confirms app identity is separate)
3. **Error cases**:
   - What happens if user revokes OAuth consent?
   - What happens if SA lacks a GCP permission?
   - What happens if user lacks access to a Drive file?
4. **Audit logs**: Check Cloud Audit Logs — do Drive calls show user principal? Do GCS calls show SA principal?

## Implications for iamspy

### New identity type: `delegated_user`

The current iamspy model has two identity types:
- `service_account` — SA with IAM permissions
- `agent_identity` — AGENT_IDENTITY with WIF principal

We may need a third:
- `delegated_user` — OAuth-delegated user identity

But this is fundamentally different from the other two:
- **SA / AGENT_IDENTITY**: iamspy knows exactly what permissions are needed (from code scan)
- **Delegated user**: iamspy can detect which Workspace APIs the code calls, but **cannot know what the user has access to**. The user's permissions are determined by Workspace sharing, not IAM policies.

### What iamspy CAN do for delegated identity

1. **Detect OAuth usage in code**: Look for `google_auth_oauthlib`, `google.oauth2.credentials`, `Flow`, etc.
2. **Extract requested scopes**: The code specifies OAuth scopes — iamspy can extract them
3. **Map scopes to Workspace API operations**: `drive.readonly` → can call `files.list`, `files.get`, etc.
4. **Separate SA permissions from user operations**: The manifest should clearly distinguish "app needs these IAM permissions for its SA" from "app accesses these user resources via OAuth"

### What iamspy CANNOT do

1. **Predict user's access**: Whether the user can access a specific Doc is determined by sharing settings, not IAM
2. **Recommend IAM roles for delegated access**: There are no IAM roles to grant — the user's existing Workspace access is what applies
3. **Detect DWD usage**: Domain-wide delegation uses SA impersonation — iamspy could detect the pattern (`credentials.with_subject()`) but can't know which users will be impersonated

## Success Criteria

- [ ] Cloud Run app deploys and serves
- [ ] OAuth consent flow completes (user redirected, token obtained)
- [ ] Drive API call succeeds with user's token (returns user's files)
- [ ] GCS API call succeeds with SA token (returns buckets/objects)
- [ ] Both calls work in the same request handler
- [ ] Audit logs show different principals for each call
- [ ] We have a clear model for how the manifest should represent this
