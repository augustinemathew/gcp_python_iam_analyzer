# Service Registry

Canonical source of truth mapping GCP services to their identifiers, display names, and IAM prefixes.

## Three-Part Tuple

Every GCP service is identified by:

| Field | Example | Derivation |
|---|---|---|
| `service_id` | `secretmanager` | Strip `google-cloud-`, remove hyphens |
| `display_name` | `Secret Manager` | From `service_registry.json` |
| `iam_prefix` | `secretmanager` | IAM permission namespace |

## The `service_id` != `iam_prefix` Problem

The `service_id` is derived mechanically from the pip package name. But the IAM permission prefix used by GCP often differs:

| pip package | `service_id` | `iam_prefix` | Why |
|---|---|---|---|
| `google-cloud-kms` | `kms` | `cloudkms` | GCP prefixes with "cloud" |
| `google-cloud-firestore` | `firestore` | `datastore` | Firestore uses Datastore IAM |
| `google-cloud-asset` | `asset` | `cloudasset` | GCP prefixes with "cloud" |
| `google-cloud-deploy` | `deploy` | `clouddeploy` | Same pattern |
| `google-cloud-functions` | `cloudfunctions` | `cloudfunctions` | Happens to match |
| `google-cloud-trace` | `trace` | `cloudtrace` | GCP prefixes with "cloud" |
| `google-cloud-filestore` | `filestore` | `file` | Completely different |

**This is critical.** If `iam_prefix` is wrong, permission resolution returns wrong results. There is no reliable heuristic to derive `iam_prefix` from `service_id` — it must be looked up from GCP IAM documentation.

### Solution: Gemini-assisted validation

Stage s02 of the build pipeline uses Gemini to validate and correct `iam_prefix` and `display_name` for all services:

```bash
# Run metadata correction stage
python -m build_pipeline run --stage s02
```

This should be run after adding new services to the registry.

## Known Services (129)

See `service_registry.json` for the full authoritative list. Key services:

| pip package | `service_id` | `display_name` | IAM prefix |
|---|---|---|---|
| `google-cloud-bigquery` | `bigquery` | BigQuery | `bigquery` |
| `google-cloud-storage` | `storage` | Cloud Storage | `storage` |
| `google-cloud-pubsub` | `pubsub` | Pub/Sub | `pubsub` |
| `google-cloud-secret-manager` | `secretmanager` | Secret Manager | `secretmanager` |
| `google-cloud-kms` | `kms` | Cloud KMS | `cloudkms` |
| `google-cloud-compute` | `compute` | Compute Engine | `compute` |
| `google-cloud-aiplatform` | `aiplatform` | Vertex AI | `aiplatform` |
| `google-cloud-firestore` | `firestore` | Firestore | `datastore` |
| `google-cloud-spanner` | `spanner` | Spanner | `spanner` |
| `google-cloud-container` | `container` | GKE | `container` |

## `service_registry.json` Format

```json
{
  "bigquery": {
    "pip_package": "google-cloud-bigquery",
    "display_name": "BigQuery",
    "iam_prefix": "bigquery",
    "discovery_doc": "https://bigquery.googleapis.com/$discovery/rest?version=v2",
    "iam_reference": "https://cloud.google.com/iam/docs/roles-permissions/bigquery",
    "modules": ["google.cloud.bigquery", "google.cloud.bigquery_v2"]
  }
}
```

## What the registry drives

The registry is the single source of truth. Multiple components derive their behavior from it:

| Field | Used by | Purpose |
|---|---|---|
| `display_name` | Scanner output, CLI | Human-readable service name |
| `iam_prefix` | Permission resolver, Gemini mapping | IAM permission namespace |
| `modules` | Scanner import detection | Module→service_id mapping for filtering findings |
| `discovery_doc` | Build pipeline | Fetch REST API metadata |
| `iam_reference` | Build pipeline | Fetch valid IAM permissions list |

## Adding a new service

1. Install the pip package: `pip install google-cloud-<name>`
2. Run `python -m build_pipeline run --stage s01` — auto-discovers modules
3. Run `python -m build_pipeline run --stage s02` — fixes IAM prefix and display name
4. Run `python -m build_pipeline run --stage s06` — generates permission mappings
5. Commit `service_registry.json` and `iam_permissions.json`

No code changes needed. The scanner automatically picks up the new service.

## Generation

Stage s01 (`build_pipeline/stages/s01_service_registry.py`) discovers installed `google-cloud-*` packages and populates:
- `service_id` — derived from pip package name
- `modules` — discovered from package file records
- `display_name` and `iam_prefix` — defaults that need Gemini correction

## `service_id` Derivation

`derive_service_id()` in `registry.py`:
```
google-cloud-bigquery        → bigquery
google-cloud-secret-manager  → secretmanager
google-cloud-kms             → kms
google-cloud-resource-manager → resourcemanager
```
