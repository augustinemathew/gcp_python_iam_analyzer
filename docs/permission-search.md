# Permission Search for Gemini Prompts

Finding the right IAM permissions to include in the Gemini mapping prompt.

## The Problem

To constrain Gemini's output, we include valid IAM permissions in the prompt. The full list is 12,879 permissions across 301 prefixes — too many for a prompt. We need the ~50-200 most relevant ones per method batch.

The naive approach (match by `iam_prefix`) fails because:
- `service_id` != `iam_prefix` (e.g. `kms` → `cloudkms`)
- Methods may need cross-service permissions (e.g. `storage` method needs `iam.serviceAccounts.signBlob`)
- Resource type naming varies between SDK and IAM (e.g. `InstancesClient` → `compute.instances.*`)

## Approaches Explored

We evaluated 5 search strategies, measured on a 20-method test set with known ground truth.

### 1. Prefix match (baseline)

Match by `iam_prefix` from the service registry.

- Returns all permissions for the service (e.g. 1,029 for compute)
- Misses cross-service deps, too large for prompt, wrong when `iam_prefix` is incorrect

### 2. Fuzzy prefix match

Try `iam_prefix`, `service_id`, and `cloud{service_id}` as prefixes.

- Handles naming mismatches (finds `cloudkms` from `kms`)
- Still returns full service list

### 3. Resource-type filter

Extract resource type from client class name, filter permissions by substring.

`InstancesClient` → filter for `instances.`, `disks.`, `networks.`, `images.*`

- Reduces prompt from 1,029 to ~170 permissions (compute)
- High precision on primary permissions
- Misses cross-service dependencies

### 4. Embedding-based semantic search

Pre-embed all 12,879 permissions using `gemini-embedding-001`. At query time, embed a description of the SDK method, find nearest permissions by cosine similarity.

### 5. Hybrid: resource filter + embedding search

Combine approaches 3 and 4. Resource filter for primary permissions, embedding search for cross-service deps.

## Experiment Results

### Query formulation (embedding search)

Tested different query strings for the same method (`compute.InstancesClient.insert`):

| Query | Found `compute.instances.create`? | Rank | Similarity |
|---|---|---|---|
| `InstancesClient.insert` | No (got `notebooks.instances.create`) | - | 0.770 |
| `create a new compute engine VM instance` | Yes | 1 | 0.742 |
| **`compute InstancesClient insert create instance`** | **Yes** | **1** | **0.823** |
| `compute.instances.create` (cheat) | Yes | 1 | 1.000 |
| Docstring text | Yes | 3 | 0.738 |

**Best query formulation: `"{service} {ClassName} {method_name}"`** — combines service context with method semantics.

Method name alone fails because embeddings can't distinguish between services (e.g. `notebooks.instances.create` vs `compute.instances.create`).

### Cross-service search accuracy

| SDK method description | Expected permission | Found? | Rank |
|---|---|---|---|
| encrypt data with KMS key | `cloudkms.cryptoKeyVersions.useToEncrypt` | Yes | 2 |
| read secret from secret manager | `secretmanager.versions.access` | Yes | 1 |
| upload file to storage bucket | `storage.objects.create` | Yes | 2 |
| publish message to pubsub topic | `pubsub.topics.publish` | Yes | 1 |
| query bigquery table | `bigquery.jobs.create` | **No** | - |
| attach disk to compute instance | `compute.instances.attachDisk` | Yes | 1 |

5/6 found in top 5. The BigQuery miss is expected — `bigquery.jobs.create` is semantically distant from "query table" because BQ queries are implemented as jobs. This is exactly the case where the resource-type filter (approach 3) catches it, because the method is on `Client` in the `bigquery` service.

### Gemini output quality (A/B comparison)

Tested on Compute Engine with 6 methods:

| Prompt strategy | All permissions valid? | Conditional deps found? | Time |
|---|---|---|---|
| No permission context | 93% (1 hallucinated) | Yes, rich | 11s |
| Full service list (1,029) | 100% | Minimal | 19s (timeout risk) |
| **Filtered list (~170)** | **100%** | **Yes, rich and correct** | **8s** |

The filtered list is the sweet spot: all valid output, rich conditional dependencies, fast enough.

Example output with filtered permissions:

```
InstancesClient.insert:
  required:    [compute.instances.create]
  conditional: [compute.disks.use, compute.disks.create, compute.images.useReadOnly,
                compute.networks.use, compute.subnetworks.use,
                compute.instances.setServiceAccount]
  notes: conditional deps depend on instance config
```

## Decision: Hybrid Approach

The hybrid approach wins:

1. **Resource-type filter** → primary permissions for the service (high precision, no API call)
2. **Embedding search** → cross-service dependencies (high recall, catches naming mismatches)
3. **Post-process** → strip any permission not in `iam_role_permissions.json` (zero hallucinations)

Design principle: **over-permissioned is safe, under-permissioned breaks things.**

## Evaluation Framework

### Ground truth

204 hand-verified mappings from curated `iam_perms.py` across 7 services.

### Metrics

| Metric | Definition | Target |
|---|---|---|
| **Recall@K** | % of ground truth permissions in top K search results | ≥ 90% |
| **Precision@K** | % of top K results that are ground truth | informational |
| **Output validity** | % of Gemini output in `iam_role_permissions.json` | ≥ 95% |
| **Hallucination rate** | % of Gemini output not in any valid list | < 5% |
| **Prompt size** | Permissions in prompt | < 200 |

### Winner criteria

1. Output recall ≥ 90% (find the correct permissions)
2. Hallucination rate < 5% (don't invent permissions)
3. Prompt size < 200 (don't timeout Gemini)
4. Prefer simpler approaches given the above

## Implementation

### Pre-computed artifacts

| File | Contents | Recompute when |
|---|---|---|
| `iam_role_permissions.json` | 12,879 valid permissions by prefix | New GCP roles released |
| `data/permission_embeddings.json` | Embedding vectors for all permissions | Permissions list changes |

### Build-time flow

```
For each SDK method batch:
  1. Resource-type filter → ~100-200 primary permissions
  2. Embedding search (query = "{service} {class} {method}") → top 20 cross-service
  3. Merge, dedupe → prompt permissions
  4. Gemini maps methods using constrained permission list
  5. Post-process: strip invalid permissions, keep all valid ones
```
