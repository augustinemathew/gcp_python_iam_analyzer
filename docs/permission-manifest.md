# Permission Manifest — Specification

## Overview

The permission manifest (`iam-manifest.yaml`) is the universal interchange format between all IAMSpy layers. It captures the complete set of IAM permissions a workload requires, derived from static analysis of its source code.

Any layer can produce it (CLI, IDE, agent) and any downstream layer can consume it (security review, policy generation, IaC templates, CI gates).

## Generating a Manifest

### CLI
```bash
# Scan files and write manifest
iamspy scan --manifest iam-manifest.yaml src/

# Include source tracing (file:line for each permission)
iamspy scan --manifest iam-manifest.yaml --trace src/
```

### VS Code Extension
Command Palette → **GCP IAM: Generate Permission Manifest** → choose scope (file or workspace) → save location.

### IAM Policy Agent
The agent runs `iamspy scan --json .` internally and can produce the manifest as part of its workflow.

### Programmatic (Python)
```python
from iamspy.scanner import GCPCallScanner
from iamspy.manifest import ManifestGenerator
from iamspy.registry import ServiceRegistry
from iamspy.resolver import StaticPermissionResolver
from iamspy.loader import load_method_db
from iamspy.resources import registry_path, permissions_path, method_db_path

registry = ServiceRegistry.from_json(registry_path())
resolver = StaticPermissionResolver(permissions_path())
method_db = load_method_db(method_db_path())
scanner = GCPCallScanner(method_db, resolver, registry)

results = asyncio.run(scanner.scan_files(paths))

gen = ManifestGenerator(registry)
manifest = gen.build(results, scanned_paths=["src/"], include_sources=True)
gen.write(manifest, Path("iam-manifest.yaml"))
```

## Format Specification

### Version 2 (current)

Version 2 splits permissions by identity context. An app with both SA and OAuth credentials gets separate permission blocks.

```yaml
version: '2'
generated_by: iamspy scan src/
generated_at: '2026-03-29T00:00:00Z'
services:
  enable:
  - bigquery.googleapis.com
  - storage.googleapis.com
identities:
  app:
    permissions:
      required:
      - bigquery.jobs.create
      - storage.objects.create
      conditional:
      - bigquery.tables.getData
  user:
    oauth_scopes:
    - https://www.googleapis.com/auth/drive.readonly
    permissions:
      required: []
      conditional: []
# Unattributed findings (identity couldn't be determined)
permissions:
  required: []
  conditional: []
sources:
  bigquery.jobs.create:
  - file: main.py
    line: 30
    method: query
    identity: app
```

**New fields in v2:**
- `identities` — permissions grouped by identity context (`app`, `user`, `impersonated`)
- `identities.*.oauth_scopes` — OAuth scopes detected in code (for delegated user identity)
- `sources.*.identity` — which identity context the finding belongs to

**Backward compatibility:** Top-level `permissions` block still exists for unattributed findings. Tools that only read `permissions` will get findings that couldn't be attributed to an identity.

### Version 1 (legacy)

```yaml
# Required: format version
version: '1'

# Required: what command generated this manifest
generated_by: iamspy scan src/

# Required: UTC timestamp
generated_at: '2026-03-20T19:34:22Z'

# Required: GCP APIs that must be enabled for this workload
services:
  enable:
  - bigquery.googleapis.com
  - cloudkms.googleapis.com
  - storage.googleapis.com

# Required: IAM permissions detected in the source code
permissions:
  # Permissions that are always required when the code runs
  required:
  - bigquery.jobs.create
  - bigquery.tables.create
  - storage.objects.get
  - storage.objects.list

  # Permissions that are only needed under certain conditions
  # (e.g., CMEK encryption, cross-project access, optional features)
  conditional:
  - cloudkms.cryptoKeyVersions.useToEncrypt
  - storage.objects.delete

# Optional: source tracing (generated with --trace flag)
# Maps each permission to the source locations that require it
sources:
  bigquery.jobs.create:
  - file: src/etl.py
    line: 87
    method: query
  storage.objects.get:
  - file: src/loader.py
    line: 23
    method: download_blob
  - file: src/backup.py
    line: 41
    method: download_as_bytes
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `version` | string | Yes | Format version. Currently `"1"`. |
| `generated_by` | string | Yes | The command that produced this manifest. |
| `generated_at` | string | Yes | UTC ISO 8601 timestamp. |
| `services.enable` | list[string] | Yes | googleapis.com service names to enable. Sorted. |
| `permissions.required` | list[string] | Yes | Always-needed permissions. Sorted. |
| `permissions.conditional` | list[string] | Yes | Conditionally-needed permissions. Sorted. May be empty. |
| `sources` | map[string, list] | No | Permission → list of `{file, line, method}` locations. Only present with `--trace`. |

### Permission Strings

Permissions follow the GCP IAM format: `<service>.<resource>.<action>`

Examples:
- `storage.objects.get` — read an object from Cloud Storage
- `bigquery.jobs.create` — run a BigQuery query
- `cloudkms.cryptoKeyVersions.useToEncrypt` — encrypt with a Cloud KMS key
- `secretmanager.versions.access` — read a secret version

### Required vs. Conditional

**Required** permissions are always needed when the code path executes. If the code calls `client.download_blob()`, then `storage.objects.get` is always required.

**Conditional** permissions depend on runtime parameters or optional features:
- **CMEK**: `kms_key_name` parameter enables customer-managed encryption
- **Cross-project**: accessing resources in a different project
- **Service account impersonation**: `impersonated_credentials` parameter
- **Optional deletes**: methods that create-or-replace may conditionally delete

The separation lets policy designers make informed decisions: required permissions are non-negotiable, conditional ones can be granted or withheld based on whether the feature is actually used in the deployment.

## Using the Manifest

### Check into source control
When a PR adds a new GCP call that requires a new permission, the manifest diff shows it in code review.

### CI gate
Regenerate the manifest in CI and diff against the checked-in version:
```yaml
# .github/workflows/iam-check.yml
- run: |
    iamspy scan --manifest /tmp/manifest.yaml src/
    diff iam-manifest.yaml /tmp/manifest.yaml
```

### Security review
Attach the manifest to a deployment PR. The reviewer sees:
- What GCP APIs need to be enabled
- Exactly which permissions are required and why (with `--trace`)
- Which permissions are conditional and under what circumstances

### Policy generation
Feed the manifest to the IAM Policy Agent to produce right-sized IAM bindings, Terraform resources, or custom role definitions.

### Manual provisioning
Read the manifest and run the corresponding `gcloud` commands:
```bash
# Enable APIs
gcloud services enable bigquery.googleapis.com --project=PROJECT

# Grant permissions (via predefined role or custom role)
gcloud projects add-iam-policy-binding PROJECT \
  --member="serviceAccount:SA@PROJECT.iam.gserviceaccount.com" \
  --role="roles/bigquery.jobUser"
```

### Drift detection (future)
Compare `iam-manifest.yaml` against Cloud Asset Inventory to detect:
- Over-provisioned roles (granted permissions not in the manifest)
- Missing permissions (manifest requires permissions not granted)
- Stale policies (permissions for code paths that no longer exist)

## Design Decisions

**Why YAML, not JSON?** YAML is human-readable and diff-friendly. Security admins review these in PRs and tickets. JSON is available via `iamspy scan --json` for machine consumption.

**Why separate required/conditional?** A policy that grants everything in `required` is correct by construction. `conditional` permissions are a decision point — the policy designer chooses based on their deployment context.

**Why source tracing is optional?** The `sources` section can be large for big codebases. The default (no `--trace`) keeps manifests compact for IaC consumption. Enable tracing for audit and review workflows.

**Why sorted lists?** Deterministic output means `git diff` shows only real changes between manifest versions. No spurious diffs from iteration order.

## Not Yet Implemented

- **`roles` section** — suggested predefined roles and custom role YAML generation
- **`project` field** — target project for provisioning
- **`iamspy apply`** — automated provisioning via `gcloud`
- **`iamspy diff`** — detect drift between manifest and source code
- **Conditional `reason` field** — structured entries with human-readable reasons
- **Bindings section** — which service account gets which role
