# Experiment Results: Delegated Identities on GCP

**Date**: 2026-03-28
**Project**: agentengine-478902
**Runtime**: Cloud Run (us-central1)

## Setup

- Cloud Run service with attached SA (`delegated-id-exp@agentengine-478902.iam.gserviceaccount.com`)
- SA has `roles/storage.objectViewer` + `roles/secretmanager.secretAccessor`
- OAuth client with scopes: `drive.readonly`, `devstorage.read_only`, `openid`, `userinfo.email`
- User: `augustine.mathew@gmail.com` (project owner)

## Results

| Scenario | Identity | API | Result | Notes |
|----------|----------|-----|--------|-------|
| SA → GCS | delegated-id-exp SA | storage.buckets.list | **DENIED** | SA has objectViewer, not buckets.list |
| User → Drive | augustine.mathew@gmail.com | drive.files.list | **OK** | Returned user's Drive files |
| User → GCS | augustine.mathew@gmail.com | storage.buckets.list | **OK** | Returned 4 buckets (project owner) |

## Key Findings

### 1. Two independent identity contexts confirmed
Same Cloud Run request handler, same `storage.Client` class, different `credentials` argument → completely different access. The SA couldn't list buckets; the user (project owner) could list all 4.

### 2. Identity is determined by the token, not the runtime
Cloud Run's attached SA is just the default. The app can create clients with any valid credential — SA token, user OAuth token, or even another SA's token via impersonation. The GCP API checks the token's identity, not where the request originates.

### 3. OAuth scopes gate Workspace access, IAM gates GCP access
- Drive call used user's OAuth token + `drive.readonly` scope → user's Workspace sharing determines access
- GCS call used user's OAuth token + `devstorage.read_only` scope → user's IAM roles determine access
- Both scope AND IAM must allow the action (intersection)

### 4. SA identity shows as "default" on Cloud Run
`google.auth.default()` returns credentials where `service_account_email` is "default" (metadata server credential). The actual SA email appears in error messages and audit logs.

## Implications for iamspy Manifest

### The manifest must track permissions per identity type

An app that uses both SA and delegated user credentials calls the same GCP methods but with different effective permissions. iamspy needs to:

1. **Detect which credentials are used for each call** — is it `google.auth.default()` (SA) or a user-constructed `Credentials` object (delegated)?
2. **Separate permissions by identity** in the manifest
3. **Track OAuth scopes** for delegated identity — the app requests specific scopes during consent

### Proposed manifest structure

```yaml
version: "1"
identities:
  service_account:
    # Permissions for the app's own SA (from iamspy scan of SA-credential calls)
    permissions:
      required:
        - secretmanager.versions.access    # fetching OAuth client secret
      conditional: []
    services:
      - secretmanager.googleapis.com

  delegated_user:
    # OAuth scopes the app requests (extracted from code)
    oauth_scopes:
      - https://www.googleapis.com/auth/drive.readonly
      - https://www.googleapis.com/auth/devstorage.read_only
    # GCP permissions used via user's token (from iamspy scan of user-credential calls)
    gcp_permissions:
      - storage.buckets.list
      - storage.objects.list
    # Workspace APIs called (not IAM-gated, but useful for documentation)
    workspace_apis:
      - service: Google Drive
        operations: [files.list]
    services:
      - storage.googleapis.com
      - drive.googleapis.com
```

### Detection heuristics for iamspy

To determine which identity is used for a GCP call, look for:

**SA (default credentials)**:
- `google.auth.default()` → variable flows into client constructor
- `storage.Client()` with no `credentials=` argument (uses ADC)
- `secretmanager.SecretManagerServiceClient()` with no credentials

**Delegated user (OAuth)**:
- `google.oauth2.credentials.Credentials(...)` → variable flows into client
- `google_auth_oauthlib.flow.Flow` → `.credentials` → flows into client
- `storage.Client(credentials=user_creds)` where user_creds traces to OAuth flow

**Scope extraction**:
- Look for `SCOPES = [...]` or `scopes=[...]` in Flow construction
- These are the OAuth scopes the app requests

This is a **points-to analysis problem** — iamspy already has Andersen's-style type inference. Extending it to track credential provenance (SA vs OAuth) is feasible.

## Resources Created (to clean up)

- Cloud Run service: `delegated-id-experiment`
- Service account: `delegated-id-exp@agentengine-478902.iam.gserviceaccount.com`
- Secret: `oauth-client-secret`
- OAuth client: `16744841236-sq7p4s7cicovg34195lkalac8q5k6j0s.apps.googleusercontent.com`
- IAM binding: `roles/storage.objectViewer` for the SA
