# RFC: Dynamic Permission Enumeration in the Build Pipeline

**Status:** Draft — awaiting review before implementation
**Scope:** `build_pipeline/stages/s06_permission_mapping.py` (prompt changes only; no schema changes)

---

## Background

IAMSpy's `iam_permissions.json` stores a static map from SDK method keys to required IAM permissions. The pipeline runs Claude (Config D+) to produce this map. Most methods map cleanly to one or two fixed permissions. A subset do not — the required permission depends on values only known at runtime.

This RFC classifies dynamic permission behavior into categories, documents what is already handled, and proposes prompt-only changes for the unhandled cases.

---

## Categories of Dynamic Permission Behavior

### Category 1 — URI type-selector *(already implemented)*

**What it is:** The permission *name itself* varies based on a type string encoded in the URL path. The method is generic; the resource type determines which family member is required.

**GCP examples:**
```
RecommenderClient.list_recommendations
  REST: GET {parent=projects/*/locations/*/recommenders/*}/recommendations
  Required: recommender.{recommenderType}Recommendations.list
  e.g. recommender.computeInstanceMachineTypeRecommendations.list

RecommenderClient.list_insights
  REST: GET {parent=projects/*/locations/*/insightTypes/*}/insights
  Required: recommender.{insightType}Insights.list
  e.g. recommender.googleCloudCostInsights.list
```

**Signal (detectable from REST URI):** A wildcard resource-type segment before the endpoint noun:
- `{parent=.../recommenders/*}/recommendations`
- `{parent=.../insightTypes/*}/insights`
- `{name=.../recommenders/*/recommendations/*}:markFailed`

**What is implemented:**
- `_pinned_family_permissions()` detects these URI patterns and forces all matching family members into the LLM hint list
- Prompt includes an explicit `PARAMETERIZED PERMISSIONS` instruction: set `permissions=[]` and enumerate *all* matching family permissions as `conditional`
- `max_tokens` increased to 16000 to accommodate large conditional lists

**Experiment results (recommender refresh, 2026-03-17):**
| Method | Before | After |
|---|---|---|
| `list_recommendations` | 0 → 0 (empty) | 0 → 56 (full family) |
| `list_insights` | 0 → 0 (empty) | 0 → 82 (full family) |
| `mark_*` methods | 2 guessed | 54/56 (2 obscure excluded by LLM) |

Static regression: PASS for asset, kms, storage, bigquery, pubsub.

---

### Category 2 — Request body references another GCP resource *(not yet handled)*

**What it is:** The method's *primary* permission is fixed (e.g., `compute.instances.insert`), but it also requires a permission on a *second* resource referenced in the request body. Whether the second permission is required depends on whether the caller provides that optional parameter.

**GCP examples:**

| Method | Primary permission | Conditional extra permission | Trigger |
|---|---|---|---|
| `compute.InstancesClient.insert(...)` | `compute.instances.create` | `iam.serviceAccounts.actAs` | `instance.service_accounts` non-empty |
| `pubsub.PublisherClient.create_topic(kms_key_name=...)` | `pubsub.topics.create` | `cloudkms.cryptoKeyVersions.useToEncrypt` | `kms_key_name` provided |
| `bigquery.Client.create_table(encryption_configuration=...)` | `bigquery.tables.create` | `cloudkms.cryptoKeyVersions.useToEncrypt` | `encryption_configuration` set |
| `gke.ClusterManagerClient.create_cluster(node_config.service_account=...)` | `container.clusters.create` | `iam.serviceAccounts.actAs` | service account parameter non-default |
| `dataflow.JobsV1Beta3Client.create_job(worker_pool.service_account=...)` | `dataflow.jobs.create` | `iam.serviceAccounts.actAs` | custom service account |

**Signal:** No reliable REST URI signal. The extra permission cross-references a different service's IAM prefix (`iam.*`, `cloudkms.*`). Docstrings and parameter names are the best available signal at prompt time.

**What is not implemented:** The prompt has no instruction to look for cross-service parameter references.

---

### Category 3 — Multi-resource operations *(partially handled by chance)*

**What it is:** A single method operates on two distinct GCP resources and needs permissions on both. The call is not parameterized — both permissions are *always* required — but they land in different namespaces.

**GCP examples:**

| Method | Permissions required |
|---|---|
| `storage.Client.copy_blob(source_bucket, source_blob, dest_bucket, ...)` | `storage.objects.get` (source) + `storage.objects.create` (dest) |
| `storage.Client.rewrite(...)` | Same as copy_blob |
| `cloudbuild.CloudBuildClient.create_build(build.artifacts=...)` | `cloudbuild.builds.create` + `storage.objects.create` (artifact upload) |
| `bigquery.Client.load_table_from_uri(source_uris=["gs://..."])` | `bigquery.jobs.create` + `storage.objects.get` |

**Signal:** REST URI and method name. The current prompt does not address this — the LLM may include both permissions in `permissions` or may omit the cross-service one.

**What is not implemented:** Explicit instruction for multi-resource operations.

---

### Category 4 — Scope / hierarchy level *(out of scope for IAMSpy)*

**What it is:** The same permission is applied at different hierarchy levels (project, folder, organization). The permission *name* does not change — only where the IAM binding must be placed. This is an IAM binding placement question, not a permission name question.

**Examples:** `resourcemanager.projects.get` works at project scope; `resourcemanager.folders.get` at folder scope. These are different permissions already correctly mapped by the pipeline.

**Decision:** Not an IAMSpy concern. The scanner reports *which permissions are needed*, not *at which resource hierarchy level* to grant them. No changes needed.

---

### Category 5 — Feature-flag parameters *(not yet handled)*

**What it is:** An optional parameter enables a feature that requires an additional permission. The method works without it (with fewer permissions) but needs the extra permission when the feature is enabled.

**GCP examples:**

| Method | Default permissions | Extra permission | Trigger |
|---|---|---|---|
| `logging.Client.logger(...)` — log writes to a custom log bucket | `logging.logEntries.create` | `logging.buckets.write` | `bucket` parameter set |
| `secretmanager.SecretManagerServiceClient.create_secret(replication.customer_managed_encryption.kms_key_name=...)` | `secretmanager.secrets.create` | `cloudkms.cryptoKeyVersions.useToEncrypt` | CMEK enabled |
| `spanner.DatabaseAdminClient.create_database(encryption_config.kms_key_name=...)` | `spanner.databases.create` | `cloudkms.cryptoKeyVersions.useToDecrypt` + `cloudkms.cryptoKeyVersions.useToEncrypt` | CMEK enabled |
| `compute.BackendServicesClient.insert(iap=...)` | `compute.backendServices.create` | `iam.serviceAccounts.actAs` | IAP configured with service account |

Note: Categories 2 and 5 overlap substantially. The distinguishing characteristic is whether the extra permission references a *resource identity* (Category 2) or a *feature toggle* (Category 5). In practice they can be handled by the same prompt instruction.

---

## What the Prompt Currently Says

```
PARAMETERIZED PERMISSIONS — read carefully:
Some methods require a permission that depends on a resource type encoded in the URL path at runtime.
Signs: the REST URI contains a wildcard resource-type segment such as
  {parent=.../recommenders/*}/recommendations  or  {parent=.../insightTypes/*}/insights
In these cases the required permission is ONE of a family, e.g. recommender.{type}Recommendations.list.
For these methods: set "permissions" to [] and put ALL permissions from the hint list that match
the family pattern into "conditional" — do not guess a subset.
The caller needs exactly one, determined by the resource type they pass at runtime.
```

This handles Category 1 only.

---

## Proposed Prompt Additions

The following three paragraphs would be appended to the `PARAMETERIZED PERMISSIONS` section in `build_prompt_with_rest_context()` and added as a new section to `build_prompt_with_permission_list()`.

### For Categories 2 + 5 — cross-resource and feature-flag conditionals

```
CROSS-RESOURCE AND FEATURE-FLAG PERMISSIONS:
Some methods accept optional parameters that reference a second GCP resource or enable a feature,
each of which requires an additional IAM permission from a different service.
Common patterns:
  - service_account / service_accounts parameter → iam.serviceAccounts.actAs
  - kms_key_name / encryption_configuration parameter → cloudkms.cryptoKeyVersions.useToEncrypt
  - CMEK (customer-managed encryption) on create/update → cloudkms.cryptoKeyVersions.useToDecrypt
  - iap (Identity-Aware Proxy) configuration → iam.serviceAccounts.actAs
For these, the primary permission is always required. The cross-service permission is conditional
on the caller providing the relevant parameter. Put it in "conditional", not "permissions".
```

### For Category 3 — multi-resource operations

```
MULTI-RESOURCE OPERATIONS:
Some methods operate on two distinct resources (e.g. copy, rewrite, load from GCS).
Common patterns:
  - copy / rewrite / transfer: source needs read permission, destination needs write/create permission
  - load from GCS: needs the primary resource permission and storage.objects.get (source)
  - create with artifact upload: needs the primary permission and storage.objects.create (destination)
For these, put secondary resource permissions in "conditional" — IAMSpy cannot verify resource type
at static scan time, so conditional is the correct representation.
```

---

## Experiment Design

Before landing the new prompt text, run the following to measure before/after and check for regression.

### Regression baseline (static methods — must not change)

| Service | Method | Expected permissions |
|---|---|---|
| `storage` | `BlobClient.upload_from_filename` | `storage.objects.create` |
| `kms` | `KeyManagementServiceClient.get_crypto_key` | `cloudkms.cryptoKeys.get` |
| `bigquery` | `Client.get_table` | `bigquery.tables.get` |
| `pubsub` | `PublisherClient.publish` | `pubsub.topics.publish` |
| `asset` | `AssetServiceClient.list_assets` | `cloudasset.assets.listResource` |

### Improvement targets (dynamic methods — should gain conditionals)

| Service | Method | Expected improvement |
|---|---|---|
| `compute` | `InstancesClient.insert` | gains `iam.serviceAccounts.actAs` in conditional |
| `pubsub` | `PublisherClient.create_topic` | gains `cloudkms.cryptoKeyVersions.useToEncrypt` in conditional |
| `storage` | `Client.copy_blob` | both `storage.objects.get` + `storage.objects.create` in permissions |
| `secretmanager` | `SecretManagerServiceClient.create_secret` | gains `cloudkms.cryptoKeyVersions.useToEncrypt` in conditional |

### How to run

```bash
# Refresh only the target services (does not touch other entries)
python -m build_pipeline refresh --service compute
python -m build_pipeline refresh --service pubsub
python -m build_pipeline refresh --service storage
python -m build_pipeline refresh --service secretmanager

# Then spot-check
python -m iamspy permissions --service compute | grep insert
python -m iamspy permissions --service storage | grep copy
```

---

## Risk and Scope

**No schema changes.** `iam_permissions.json` format is unchanged. Conditionals go in `"conditional"` as they do today. Scanner output is unchanged.

**No code changes to s06 logic.** All proposed changes are to the prompt strings in `build_prompt_with_rest_context()` and `build_prompt_with_permission_list()`. The `_pinned_family_permissions()` mechanism (Category 1) already lands, untouched.

**LLM hallucination risk.** Explicit cross-service permission names (`iam.serviceAccounts.actAs`) in the prompt could cause the LLM to add them where they don't apply. Mitigation: the validation step (s07) filters against the known-valid permission set (`iam_role_permissions.json`), so invalid permission strings are dropped automatically.

**Token budget.** The Category 2/5 additions are ~120 tokens per batch. No `max_tokens` increase needed.

---

## Decisions

1. **`build_prompt_with_permission_list()` (v1 fallback)** — Yes, receives the same dynamic permission instructions. Categories 2/3/5 added; Category 1 (URI type-selector) is omitted since this path is only reached when no REST URI is available.

2. **Multi-resource cross-service permissions** — Go in `conditional`, not `permissions`. Even when the secondary resource parameter is required, at static scan time IAMSpy cannot verify the resource type, so surfacing it as conditional is the safer representation.

3. **54/56 for `mark_*` methods** — Acceptable. The 2 excluded permissions are obscure recommender types; the full 56-member family is available if a re-run is needed in the future.