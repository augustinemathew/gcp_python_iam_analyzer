# Gemini Mapping Engine

Maps Python SDK methods to IAM permissions using Gemini with constrained output.

## Experiment Results

Tested 5 prompt strategies on Compute Engine (hardest service, 1,029 permissions):

| Strategy | Validity | Conditional deps | Time | Notes |
|---|---|---|---|---|
| No context | 93% | Rich but may hallucinate | 5-11s | Guesses permission names |
| Prefix hint only | 100% | Minimal | 4-5s | Correct but shallow |
| Full permission list (1,029) | 100% | Minimal | 19s | Timeout risk on large lists |
| **Filtered permissions (~170)** | **100%** | **Rich and correct** | **8s** | Best overall |
| List + few-shot examples | 100% | Rich | 10s | Good but slower |

**Winner: Filtered permission list.**
- Filter `iam_role_permissions.json` by resource types extracted from the class name
- `InstancesClient` → include permissions matching `instances.`, `disks.`, `networks.`, `images.`
- Keeps prompt small (~170 permissions vs 1,029), avoids timeouts
- Gemini finds real conditional dependencies (e.g. `compute.disks.use` for `attach_disk`)

### Design principle: over-permissioned is safe

We'd rather report a permission that might not be needed than miss one that is. The post-processing step strips hallucinations (permissions not in `iam_role_permissions.json`), but keeps all valid permissions Gemini identifies.

## Permission Context

The prompt includes **filtered** valid IAM permissions for the service, sourced from `iam_role_permissions.json` (12,879 permissions from `gcloud iam roles list`).

### Fuzzy Permission Lookup

`service_id` doesn't always match the IAM prefix. The lookup tries:
1. Direct match on `iam_prefix` from service registry
2. Fallback to `service_id`
3. Try `cloud{service_id}` variant
4. Filter by resource type extracted from the client class name
5. (Future) Embedding-based semantic search across all permissions

### Post-processing

After Gemini returns mappings:
1. Validate every permission against `iam_role_permissions.json`
2. Strip invalid permissions (hallucinations)
3. Keep all valid permissions (over-permissioned is OK)
4. Flag methods with zero valid permissions for manual review

## Prompt Template

```
You are mapping Google Cloud Python SDK methods to IAM permissions.
Service: {service_id} ({display_name})

Methods to map:
  - ClassName.method_name(min_args=N, max_args=M)
  ...

Valid IAM permissions for these resources:
{filtered_valid_permissions}

For EACH method, provide:
- "permissions": primary required permissions (from the list above)
- "conditional": permissions needed depending on configuration
- "notes": what triggers conditional permissions

Return ONLY valid JSON.
```

## Batching

- 15 methods per Gemini request
- ~10-15s per batch (Flash), ~30-60s (Pro)
- Grouped by service to share permission context
- Save to disk after each batch (resumable)

## Validation

After Gemini returns mappings:
1. **Permission string validation**: every permission must exist in `iam_role_permissions.json`
2. **Coverage check**: flag methods with empty permissions that aren't `local_helper`
3. **Cross-reference**: compare against curated ground truth from `iam_perms.py`

## Build Artifacts

| File | Source | Contents |
|---|---|---|
| `iam_role_permissions.json` | `gcloud iam roles list` | 12,879 valid permissions grouped by prefix |
| `iam_permissions.json` | Gemini + curated seed | method → permission mappings |

## Running

```bash
# Full run (skips already-mapped services)
GEMINI_API_KEY=... python -m build.build_permission_mapping --resume

# Single service
GEMINI_API_KEY=... python -m build.build_permission_mapping --service compute --merge

# Rebuild IAM permissions inventory
gcloud iam roles list --format=json > /tmp/roles.json  # or use build script
```
