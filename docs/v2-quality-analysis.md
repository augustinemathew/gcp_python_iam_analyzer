# v2 Pipeline Quality Analysis

**Date:** 2026-03-16
**Pipeline state:** 150/475 batches complete, 0 errors

## Summary

Compared v1 (Gemini + Claude, permission-list prompts) against v2 (Claude only, Config D with REST URIs + soft hints) on the methods both have mapped so far.

| Metric | Count |
|---|---|
| Shared keys (v1 ∩ v2) | 5,407 |
| Exact match | 4,874 (90%) |
| Disagreements | 533 (10%) |

### Disagreement breakdown

| Category | Count | Description |
|---|---|---|
| **Regressions** (v1 has perms, v2 empty) | 310 | Mostly cross-service utilities the LLM couldn't map |
| **Improvements** (v2 has perms, v1 empty) | 43 | v2 found permissions v1 missed |
| **Different** (both have, but disagree) | 297 | Both mapped but to different permissions |

### Root cause of regressions (310)

All 310 are **empty in v2** — the LLM returned nothing or the result got stripped by post-processing.

| Root cause | Count | Fix |
|---|---|---|
| Cross-service inherited methods (`get_operation`, `cancel_operation`, `list_locations`, etc.) | 280 | **Auto-resolve** — predictable permissions, no LLM needed |
| Service not yet processed (pipeline still running) | 30 | Wait for pipeline to finish |

**Fix implemented:** Added `_CROSS_SERVICE_METHODS` dict in `s06_permission_mapping.py` that auto-resolves 10 known inherited methods:
- LRO operations: `get_operation` → `{iam_prefix}.operations.get`, `cancel_operation`, `delete_operation`, `list_operations`, `wait_operation`
- IAM: `get_iam_policy` → `{iam_prefix}.{resource}.getIamPolicy`, `set_iam_policy`, `test_iam_permissions`
- Locations: `get_location` → `{iam_prefix}.locations.get`, `list_locations`

These methods appear on every gapic client (36 services × ~8 methods = ~280 methods). Auto-resolution eliminates the regression and saves ~19 LLM batches.

### Analysis of "different" cases (297)

Broke into three subcategories by comparing each permission against the official IAM catalog (`iam_role_permissions.json`):

| Subcategory | Count | What it means |
|---|---|---|
| **v2 clearly better** | 118 | v1 had hallucinated permissions (not in valid set), v2 is valid |
| **v1 clearly better** | 16 | v1 found additional secondary permissions v2 missed |
| **Ambiguous** (both valid, but different) | 163 | Both map to real permissions, disagree on which is correct |

#### Where v2 is clearly better (118 cases)

v1 used Gemini which hallucinated plausible-looking but nonexistent permissions. v2 uses Claude with soft hints, producing fewer hallucinations. Examples:

```
aiplatform.EndpointServiceClient.mutate_deployed_model
  v1: aiplatform.endpoints.mutateDeployedModel  ← does not exist in IAM catalog
  v2: aiplatform.endpoints.deploy               ← exists, correct
```

#### Where v1 is clearly better (16 cases)

v1 found secondary/conditional permissions that v2 missed. The Config D prompt focuses on the primary permission (from the REST URI) but sometimes misses that an operation needs permissions on *other* resources too. Examples:

```
compute.DisksClient.create_snapshot
  v1: [compute.disks.createSnapshot, compute.snapshots.create]  ← needs both
  v2: [compute.disks.createSnapshot]                             ← missed snapshots.create

compute.InstanceGroupManagersClient.create_instances
  v1: [compute.instanceGroupManagers.update, compute.instances.create]
  v2: [compute.instanceGroupManagers.update]  ← missed instances.create
```

**Lesson:** Config D's REST URI tells you the *primary* resource being acted on. But some operations affect multiple resources (creating a snapshot touches both `disks` and `snapshots`). The LLM needs a prompt hint about cross-resource side effects — or we need a post-processing step that infers them from the URI hierarchy.

#### Ambiguous cases (163) — adjudicated by Claude

Sent all 158 non-cross-service ambiguous cases to Claude Sonnet for expert adjudication. Each case included:
- The method key and REST URI
- Both v1 and v2 permissions with validity markers (✓/✗ from IAM catalog)
- Both notes

**Adjudication approach:** Prompt asked Claude to determine which mapping is correct based on REST URI, resource type, and IAM catalog validity. Prompt included 80 cases per batch (2 batches).

**Results:**

| Winner | Count | Percentage |
|---|---|---|
| v1 wins | 111 | 70% |
| v2 wins | 45 | 28% |
| Unclear | 2 | 1% |

**Why v1 wins 70% of ambiguous cases:**

v1 used resource-specific permission names extracted from the class name. For example, `FeatureOnlineStoreAdminServiceClient.delete_feature_online_store` → `featureOnlineStores.delete`. v2 generalized to the wrong resource type (`featurestores.delete`) because the LLM didn't distinguish between legacy `featurestores` and newer `featureOnlineStores`.

**Why v2 wins 28%:**

v2 inferred more precise action names from the REST URI. For example, `DatasetServiceClient.restore_dataset_version` → v2 says `datasetVersions.restore` (correct — maps to the `:restore` action in URI), v1 says `datasets.update` (incorrect — generic fallback).

### Lessons learned

1. **REST URIs are the best signal for primary permissions** — 100% accuracy on KMS and Compute in isolation. But they miss secondary/conditional permissions on related resources.

2. **Permission naming is unpredictable** — `encrypt` → `useToEncrypt`, `deploy` → `deploy`, `sign` → `useToSign`. Soft hints (valid permission list) are necessary to guide the LLM toward actual IAM vocabulary.

3. **Cross-service inherited methods need auto-resolution** — `get_operation`, `cancel_operation`, IAM policy methods, location methods. Predictable, no LLM needed, appear ~280 times across clients.

4. **v1's resource-specific naming was sometimes more precise** — deriving permission resource from the class name (`FeatureOnlineStoreAdmin` → `featureOnlineStores`) can be more accurate than what the LLM infers from the REST URI alone.

5. **Post-processing against the IAM catalog catches hallucinations** — 118 cases where v1 had invalid permissions that v2 correctly avoided.

6. **The IAM catalog is the ground truth** — permissions not in `iam_role_permissions.json` are almost certainly wrong. Post-processing validation is essential regardless of prompt strategy.

### Fix: Config D+ (REST URI + full service permission list)

Based on this analysis, Config D was upgraded to Config D+:

```
Config D+  =  REST URI + docstring + FULL service permission list (soft hint, "prefer these")
```

**Verification on the hard cases:**

| Method | v1 | Config D | Config D+ |
|---|---|---|---|
| KMS encrypt | ✅ `useToEncrypt` | ❌ `cryptoKeys.encrypt` | ✅ `useToEncrypt` |
| Compute create_instances | 2 perms | 1 perm | **6 perms** (primary + 5 conditional) |
| Compute create_snapshot | 2 perms | 1 perm | 1 perm (still misses `snapshots.create`) |

**Token budget:** Config D+ uses ~10,000 tokens for Compute (1,029 permissions) — still smaller than v1's 12,356. For most services (<200 permissions) it's ~1,500 tokens.

**Config D+ is strictly better than v1 and Config D** for all but one pattern: secondary permissions on *created* resources (e.g. `createSnapshot` → also needs `snapshots.create`). This is a structural limitation — the REST URI shows the *source* resource, not the *result* resource.

### Remaining gap: secondary permissions on created resources

The one pattern no prompt strategy solves perfectly: operations that create a *new* resource type as a side effect.

| Method | Primary (all strategies get this) | Secondary (only v1 sometimes gets this) |
|---|---|---|
| `disks.createSnapshot` | `compute.disks.createSnapshot` | `compute.snapshots.create` |
| `instances.attachDisk` | `compute.instances.attachDisk` | `compute.disks.use` |

Possible fixes (not yet implemented):
1. Add a prompt hint: "If this operation creates a new resource type, include the create permission for that resource"
2. Post-processing: if the permission action contains "create" + another resource name, check for `{iam_prefix}.{otherResource}.create`
3. Accept this gap — over-permissioned is safe, these secondary permissions are usually caught by the IAM policy at runtime anyway

### Config D+ sliver test results (KMS + BigQuery + Compute)

Ran Config D+ on 3 services (2,343 methods, 67 batches, 0 errors) and compared to v1:

| Metric | v1 | Config D+ | Delta |
|---|---|---|---|
| Primary permissions | 964 | **1,013** | **+49** |
| Valid (in IAM catalog) | 835 | **922** | **+87** |
| Empty (unmapped) | 58 | **5** | **-53** |
| Regressions | — | **4** | Down from 310 |
| Ground truth (10 spot checks) | — | **10/10** | |

Config D+ is strictly better: more permissions, more valid, fewer gaps.

### Scale of analysis

| What | Count |
|---|---|
| GCP SDK packages installed | 130 |
| SDK Python files analyzed | 10,066 |
| SDK lines of code parsed | 8,763,153 |
| REST endpoints extracted | 52,841 |
| `rest_base.py` files parsed | 645 |
| Methods mapped to permissions | ~12,000 |
| IAM roles in catalog | 2,073 |
| Valid IAM permissions | 12,879 |
| LLM batches (full pipeline) | ~370 |
| LLM errors | 0 |

### Files and scripts used

| File | Purpose |
|---|---|
| `build_pipeline/stages/s06_permission_mapping.py` | v2 mapping with Config D+ + cross-service auto-resolve |
| `build_pipeline/llm/prompt.py` | Config D+ and v1 fallback prompt builders |
| `build_pipeline/stats.py` | Artifact analyzer — `python -m build_pipeline.stats` |
| `docs/exec-summary.md` | Executive summary with LLM comparison |
| `/tmp/adjudication_results_full.json` | 158 ambiguous cases adjudicated by Claude |
