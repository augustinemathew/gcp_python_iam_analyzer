# GCP SDK IAM Permission Detector

Statically analyzes Python source code to detect GCP SDK method calls and tells you exactly which IAM permissions your code requires — before deployment.

```
$ gcp-sdk-detector scan encrypt_symmetric.py create_secret.py grant_access_to_dataset.py

encrypt_symmetric.py
    56  encrypt_response = client.encrypt(
        → cloudkms.cryptoKeyVersions.useToEncrypt

create_secret.py
    61  response = client.create_secret(
        → secretmanager.secrets.create

grant_access_to_dataset.py
    51  dataset = client.get_dataset(dataset_id)
        → bigquery.datasets.get
    77  dataset = client.update_dataset(
        → bigquery.datasets.update
        ⚠ conditional: bigquery.datasets.get

──────────────────────────────────────────────────
3 file(s), 4 finding(s)
Services: bigquery, kms, secretmanager

Required permissions:
  • bigquery.datasets.get
  • bigquery.datasets.update
  • cloudkms.cryptoKeyVersions.useToEncrypt
  • secretmanager.secrets.create
```

For each GCP SDK call: the file, line number, code snippet, and the IAM permission required. The summary lists all unique permissions — that's the minimum IAM role needed to run the code.

## Scale

Tested against [GoogleCloudPlatform/python-docs-samples](https://github.com/GoogleCloudPlatform/python-docs-samples) (3,642 Python files):

| Metric | Count |
|---|---|
| GCP SDK calls detected | 2,375 |
| Mapped to permissions | 2,363 (**99%**) |
| Unique permissions found | 463 |
| Services detected | 73 |
| Time | <30s |

## Install

```bash
pip install -e .
```

## Usage

```bash
# Scan a file or directory
gcp-sdk-detector scan app.py
gcp-sdk-detector scan src/

# Scan a cloned repo
git clone --depth 1 https://github.com/GoogleCloudPlatform/python-docs-samples /tmp/samples
gcp-sdk-detector scan /tmp/samples/kms/
gcp-sdk-detector scan /tmp/samples/

# JSON output (for CI/tooling)
gcp-sdk-detector scan --json app.py

# Compact one-line-per-finding (like ruff/mypy)
gcp-sdk-detector scan --compact src/

# List all mapped GCP services
gcp-sdk-detector services

# Show permission mappings for a service
gcp-sdk-detector permissions --service storage
gcp-sdk-detector permissions --service bigquery

# JSON output for all mappings
gcp-sdk-detector permissions --json
```

Or use `python -m gcp_sdk_detector` instead of `gcp-sdk-detector`.

## How it works

1. Checks if the file imports from `google.cloud` — no imports means no findings (zero false positives)
2. Parses the Python source with tree-sitter to find method calls
3. Matches calls against a database of 13,193 GCP SDK method signatures
4. Resolves each match to IAM permissions via a pre-built mapping

Runtime: <50ms per file. Zero network calls. All data is pre-built JSON.

## What's in the box

| File | What |
|---|---|
| `iam_permissions.json` | 13,193 method → permission mappings across 123 services |
| `method_db.json` | 13,193 SDK method signatures for call matching |
| `service_registry.json` | 123 GCP services with module paths and IAM prefixes |
| `data/iam_roles.json` | 2,073 IAM roles with 12,879 valid permissions (ground truth) |

## Adding a new GCP service

If the scanner reports "unmapped" for a service you need, add it in three steps:

```bash
# 1. Install the SDK package
pip install google-cloud-newservice

# 2. Rebuild registry + method DB + context (no LLM, ~60 seconds)
python -m build_pipeline --from s01

# 3. Map only the new methods (~$0.10, resume skips existing)
ANTHROPIC_API_KEY=... python -m build_pipeline --stage s06
```

The pipeline is incremental — it only processes methods not already in `iam_permissions.json`.

## Build pipeline

The permission mappings are pre-built and checked into the repo. You only need to re-run the build pipeline if SDK versions change or you want to add new services.

The build pipeline analyzes 8.8 million lines of GCP SDK source code, extracts 52,841 REST API endpoints, and uses Claude Sonnet to map methods to permissions.

```bash
python -m build_pipeline              # run all stages (~50 min, ~$6)
python -m build_pipeline --stage s04  # extract REST URIs from SDK source
python -m build_pipeline --from s04   # run from s04 onwards
python -m build_pipeline --dry-run    # show what would run
python -m build_pipeline.stats        # pipeline stats
```

| Stage | What | LLM? |
|---|---|---|
| s01 | Discover installed SDK packages | No |
| s02 | Fix iam_prefix via Gemini | Gemini |
| s03 | Introspect SDK method signatures | No |
| s04 | Extract REST URIs + docstrings from SDK source | No |
| s05 | Download IAM role catalog (2,073 roles) | No |
| s06 | Map methods → permissions (Config D+) | Claude |
| s07 | Validate output with embeddings | No |

See `docs/build-pipeline.md` for the full design, experiments, and decisions.

## Development

```bash
pip install -e ".[dev]"
make test     # 277 tests
make lint     # ruff check
make fmt      # ruff format
```
