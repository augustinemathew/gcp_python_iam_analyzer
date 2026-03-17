# Accuracy

## Benchmark

We tested IAMSpy against [GoogleCloudPlatform/python-docs-samples](https://github.com/GoogleCloudPlatform/python-docs-samples) — Google's own reference implementations for every GCP service.

| | |
|---|---|
| Python files scanned | 3,642 |
| GCP SDK calls detected | 3,144 |
| Mapped to permissions | **3,144 (100%)** |
| Unique permissions identified | 706 |
| Services covered | 73 |

Zero unmapped calls across the entire corpus.

## How the data was built

The permission mappings are pre-built — no LLM inference at scan time.

**Build pipeline (offline, ~$8, ~75 min):**

1. Discover 205 installed SDK packages
2. Extract REST URIs and docstrings from 8.8M lines of SDK source code
3. Use Claude to map each method to its IAM permission(s)
4. Validate against the full IAM role catalog (12,879 known permissions as ground truth)

The result is a static `iam_permissions.json` checked into the repo. The scanner does a dictionary lookup — nothing more.

## Coverage

| | |
|---|---|
| GCP services | 205 |
| SDK methods mapped | 25,011 |
| Valid IAM permissions (ground truth) | 12,879 |
| python-docs-samples accuracy | 100% |

## Known limitations

**Static analysis only.** IAMSpy reads your source code — it doesn't trace runtime values. If you dynamically construct a method name or call GCP through a generic HTTP client, it won't be detected.

**Import-dependent.** A file with no `google.cloud` imports produces zero findings, by design. If you alias imports in unusual ways (e.g. `from mymodule import gcs_client`) the import won't resolve.

**Conditional permissions are advisory.** A `⚠ conditional` permission is required only in specific circumstances (e.g. `storage.objects.delete` when overwriting an existing object). Whether you need it depends on your workload.
