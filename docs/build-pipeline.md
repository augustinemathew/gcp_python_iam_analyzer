# Build Pipeline

Generates static JSON artifacts for the runtime scanner. Runs offline at build time. Runtime requires zero network calls.

## Pipeline Steps

```
pip install google-cloud-*          # prerequisites (62 packages)
                │
                ▼
build_service_registry.py           # → service_registry.json (modules, default metadata)
                │
                ▼
fix_registry_metadata.py            # Gemini corrects iam_prefix + display_name
                │
                ▼
build_method_db.py                  # → method_db.json (SDK introspection, 2,688 methods)
                │
                ▼
gcloud iam roles list               # → iam_role_permissions.json (12,879 permissions)
                │
                ▼
build_permission_mapping.py         # → iam_permissions.json (Gemini, initial pass)
                │
                ▼
fill_mapping_gaps.py                # fills gaps using Claude (reliable, 0 errors)
```

## Step 1: Service Registry (`build_service_registry.py`)

Discovers all installed `google-cloud-*` pip packages and builds a registry of 62 services with module paths and default metadata.

Output: `service_registry.json`

## Step 2: Fix Registry Metadata (`fix_registry_metadata.py`)

Uses Gemini to correct `iam_prefix` and `display_name` for each service. Many services have `service_id != iam_prefix` (e.g. `kms` → `cloudkms`, `firestore` → `datastore`).

```bash
GEMINI_API_KEY=... python -m build.fix_registry_metadata
```

## Step 3: Method DB (`build_method_db.py`)

Introspects all installed SDK packages. For each Client class, records every public method's signature (min/max args, var kwargs, class name, service_id).

Output: `method_db.json` (2.8MB, 2,688 methods, 14,101 signatures)

This is the step that takes 13.4s (importing 63 packages). The output is pre-built so the runtime scanner loads it in ~39ms.

## Step 4: IAM Ground Truth (`gcloud iam roles list`)

Extracts all valid IAM permission strings from GCP. Used for:
- Filtering prompts (give LLM only relevant permissions)
- Post-processing validation (strip hallucinated permissions)

Output: `iam_role_permissions.json` (12,879 permissions)

## Step 5: Permission Mapping (`build_permission_mapping.py`)

Sends batches of 15 methods to Gemini with filtered valid permissions for the service. Gemini maps each method to required and conditional IAM permissions.

```bash
GEMINI_API_KEY=... python -m build.build_permission_mapping --resume
GEMINI_API_KEY=... python -m build.build_permission_mapping --service compute --merge
```

Saves after each batch (resumable). Post-processing strips permissions not in `iam_role_permissions.json`.

Output: `iam_permissions.json`

## Step 6: Fill Gaps (`fill_mapping_gaps.py`)

Uses Claude to fill any methods that Gemini failed to map (timeouts, JSON errors). Claude is more reliable for structured output — 251 batches with 0 errors in production.

All LLM requests/responses are logged to `data/llm_logs/` for replay and auditing.

Output: merged into `iam_permissions.json`

## LLM Reliability

| LLM | Reliability | Speed | Notes |
|---|---|---|---|
| Gemini Flash | Unreliable (504 timeouts, 53 errors in one run) | 8s/batch | Good for initial pass |
| Claude Sonnet | Reliable (0 errors in 251 batches) | Fast | Primary for gap-filling |

## Incremental Updates

When a new SDK version adds methods:
1. Re-run `build_method_db.py` → diff against existing
2. Only send new/changed methods through the mapping pipeline
3. Merge results into existing `iam_permissions.json`
