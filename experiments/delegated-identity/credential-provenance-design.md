# Credential Provenance Analysis — Design

## Problem

When code does:
```python
sa_creds, project = google.auth.default()
user_creds = google.oauth2.credentials.Credentials(token=token)

sa_storage = storage.Client(credentials=sa_creds)       # SA identity
user_storage = storage.Client(credentials=user_creds)    # User identity

sa_storage.list_buckets()      # → needs SA to have storage.buckets.list
user_storage.list_buckets()    # → needs USER to have storage.buckets.list
```

Both calls resolve to the same method signature and same IAM permission. But the
permission applies to **different principals**. iamspy currently can't distinguish
them — it would report `storage.buckets.list` once, attributed to whoever.

## Solution: Extend Points-To with Credential Labels

The existing `PointsToAnalysis` tracks: **variable → set of class names**.

We add a parallel lattice: **variable → credential provenance label**.

### Credential Provenance Labels

```python
class CredentialProvenance(Enum):
    SA_DEFAULT = "sa_default"          # google.auth.default()
    SA_EXPLICIT = "sa_explicit"        # service_account.Credentials.from_service_account_info(...)
    SA_IMPERSONATION = "sa_imperson"   # impersonated_credentials.Credentials(...)
    OAUTH_USER = "oauth_user"          # google.oauth2.credentials.Credentials(...)
    OAUTH_FLOW = "oauth_flow"          # flow.credentials (from google_auth_oauthlib)
    DWD = "dwd"                        # service_account.Credentials(...).with_subject(email)
    UNKNOWN = "unknown"                # can't determine
    IMPLICIT = "implicit"              # no credentials= arg (uses ADC → SA_DEFAULT)
```

Simplified to three categories for the manifest:

```python
class IdentityContext(Enum):
    APP = "app"           # SA_DEFAULT, SA_EXPLICIT, IMPLICIT → app's own identity
    USER = "user"         # OAUTH_USER, OAUTH_FLOW → delegated user identity
    IMPERSONATED = "imp"  # SA_IMPERSONATION, DWD → acting as another identity
```

### Detection Patterns (tree-sitter)

Each pattern is a specific AST shape we match during the CST walk.

#### APP identity sources

```python
# Pattern 1: google.auth.default()
credentials, project = google.auth.default()
# AST: assignment, rhs=call, func="google.auth.default" or "default" after import
# Label: SA_DEFAULT

# Pattern 2: Explicit SA credentials
credentials = service_account.Credentials.from_service_account_info(info)
credentials = service_account.Credentials.from_service_account_file(path)
# AST: assignment, rhs=call, func chain ends with from_service_account_*
# Label: SA_EXPLICIT

# Pattern 3: No credentials argument (implicit ADC)
client = storage.Client()
client = bigquery.Client(project="my-project")
# AST: call, no keyword_argument with name "credentials"
# Label: IMPLICIT (→ APP)
```

#### USER identity sources

```python
# Pattern 4: OAuth credentials constructor
credentials = google.oauth2.credentials.Credentials(token=token)
credentials = Credentials(**session_data)
# AST: call, class_name="Credentials", from google.oauth2.credentials import
# Label: OAUTH_USER

# Pattern 5: OAuth flow .credentials property
flow = google_auth_oauthlib.flow.Flow.from_client_config(config, scopes)
flow.fetch_token(authorization_response=url)
credentials = flow.credentials
# AST: assignment, rhs=attribute access on flow object, attr="credentials"
# Requires: flow var traces to Flow class from google_auth_oauthlib
# Label: OAUTH_FLOW

# Pattern 6: InstalledAppFlow (desktop OAuth)
flow = InstalledAppFlow.from_client_secrets_file(path, scopes)
credentials = flow.run_local_server()
# AST: call_ret, func="run_local_server", on Flow/InstalledAppFlow object
# Label: OAUTH_FLOW
```

#### IMPERSONATED identity sources

```python
# Pattern 7: SA impersonation
target_credentials = impersonated_credentials.Credentials(
    source_credentials=source, target_principal=target_sa)
# AST: call, class from google.auth.impersonated_credentials
# Label: SA_IMPERSONATION

# Pattern 8: Domain-wide delegation
delegated = credentials.with_subject("user@example.com")
# AST: call, method="with_subject" on a credentials variable
# Label: DWD
```

### Propagation Rules

Credential labels propagate through the same paths as types:

```
# Direct assignment
creds = google.auth.default()    → creds: SA_DEFAULT
my_creds = creds                 → my_creds: SA_DEFAULT (copy)

# Function return
def get_creds():
    return google.auth.default()
c = get_creds()                  → c: SA_DEFAULT (call_ret)

# Field store/load
self.creds = creds               → Field(self, creds): SA_DEFAULT
x = self.creds                   → x: SA_DEFAULT (field load)

# Tuple unpacking
creds, project = google.auth.default() → creds: SA_DEFAULT
```

### Client Constructor → Credential Binding

When we see a GCP client constructor, check the `credentials=` keyword argument:

```python
client = storage.Client(credentials=some_var)
```

1. Look up `some_var` in credential label map
2. Bind the client variable to that label
3. All method calls on that client inherit the label

If no `credentials=` argument:
```python
client = storage.Client()           # → IMPLICIT (APP)
client = storage.Client(project=p)  # → IMPLICIT (APP)
```

### Integration with Existing Scanner

The scanner currently does:
```
parse → imports → walk calls → match signatures → resolve permissions → Finding
```

We add credential context to Finding:

```python
@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    method: str
    service_id: list[str]
    # ... existing fields ...
    identity_context: IdentityContext    # NEW: app, user, or impersonated
    credential_provenance: str          # NEW: sa_default, oauth_flow, etc.
    oauth_scopes: list[str] | None      # NEW: scopes if user context
```

### Implementation Approach

**Option A: Extend PointsToAnalysis** (clean but larger change)

Add a parallel `cred_labels: dict[str, set[CredentialProvenance]]` to each Scope,
alongside the existing `bindings: dict[str, set[str]]`. Same worklist solver
propagates both class names and credential labels.

Pros: Unified analysis, single CST walk, correct propagation through all paths.
Cons: Touches the core type inference code.

**Option B: Second pass with pattern matching** (simpler, pragmatic)

After the existing scan, do a second lighter pass:
1. Find all credential-source patterns (google.auth.default, Credentials constructor, etc.)
2. Track which variables they flow into (simple forward dataflow, not full Andersen's)
3. Find all `Client(credentials=X)` calls, look up X's provenance
4. Annotate each Finding with the client's credential context

Pros: Doesn't touch existing code. Simpler. Covers 90% of cases.
Cons: Won't handle complex flows (credentials stored in dicts, passed through 3 functions).

**Recommendation: Option B first, upgrade to A if needed.**

Most real code has simple credential flows:
```python
creds = google.auth.default()          # or Credentials(...)
client = storage.Client(credentials=creds)
client.list_buckets()
```

The credentials variable is usually within 5 lines of the client constructor.
A forward dataflow pass handles this without touching the core solver.

### OAuth Scope Extraction

Separately, extract OAuth scopes from the code:

```python
# Pattern: SCOPES constant
SCOPES = ["https://www.googleapis.com/auth/drive.readonly", ...]
# AST: assignment, lhs ends with "SCOPES" or "scopes", rhs is list of strings

# Pattern: scopes= argument
flow = Flow.from_client_config(config, scopes=["drive.readonly", ...])
# AST: keyword_argument name="scopes" in a Flow constructor call

# Pattern: scopes in Credentials
credentials = service_account.Credentials.from_service_account_info(
    info, scopes=["https://www.googleapis.com/auth/cloud-platform"])
```

Extract all string literals from these patterns → `oauth_scopes` in manifest.

### Manifest Output

```yaml
version: "2"
identities:
  app:
    # Permissions needed by the app's own SA
    permissions:
      required:
        - secretmanager.versions.access
      conditional: []
    services:
      - secretmanager.googleapis.com
    sources:
      secretmanager.versions.access:
        - file: app.py
          line: 41
          method: access_secret_version
          credential: sa_default

  user:
    # Permissions used with the user's delegated OAuth token
    oauth_scopes:
      - https://www.googleapis.com/auth/drive.readonly
      - https://www.googleapis.com/auth/devstorage.read_only
    gcp_permissions:
      required:
        - storage.buckets.list
        - storage.objects.list
      conditional: []
    workspace_apis:
      - service: Google Drive
        operations: [files.list]
    services:
      - storage.googleapis.com
      - drive.googleapis.com
    sources:
      storage.buckets.list:
        - file: app.py
          line: 155
          method: list_buckets
          credential: oauth_user
```

### What This Enables

1. **iamspy scan** separates findings by identity context in output
2. **Manifest** has per-identity permission blocks
3. **recommend_policy** knows which permissions to grant to the SA vs which are the user's responsibility
4. **CodeLens** can show different icons/colors for SA vs user-delegated calls
5. **Security audit**: flag cases where SA has permissions that should be user-delegated (principle of least privilege — don't give the app permissions the user already has)
