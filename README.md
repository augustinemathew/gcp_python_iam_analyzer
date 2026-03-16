# GCP SDK IAM Permission Detector

Statically analyzes Python source code to detect GCP SDK method calls and tells you exactly which IAM permissions your code requires.

```
$ gcp-sdk-detector scan app.py

app.py
    12  client.create_key_ring(request={"parent": parent, "key_ring_id": id})
        → cloudkms.keyRings.create

    18  client.encrypt(request={"name": key_name, "plaintext": data})
        → cloudkms.cryptoKeyVersions.useToEncrypt

──────────────────────────────────────────────────
1 file(s), 2 finding(s)

Required permissions:
  • cloudkms.keyRings.create
  • cloudkms.cryptoKeyVersions.useToEncrypt
```

## Install

```bash
pip install -e .
```

## Usage

```bash
# Scan a file or directory
gcp-sdk-detector scan app.py
gcp-sdk-detector scan src/

# JSON output (for CI/tooling)
gcp-sdk-detector scan --json app.py

# Compact one-line-per-finding (like ruff/mypy)
gcp-sdk-detector scan --compact src/

# Include local helpers (path builders, constructors)
gcp-sdk-detector scan --show-all app.py

# List all 119 mapped GCP services
gcp-sdk-detector services

# Show permission mappings for a service
gcp-sdk-detector permissions --service storage
gcp-sdk-detector permissions --service bigquery
```

Or use `python -m gcp_sdk_detector` instead of `gcp-sdk-detector`.

## How it works

1. Checks if the file imports from `google.cloud` — no imports means no findings (zero false positives)
2. Parses the Python source with tree-sitter to find method calls
3. Matches calls against a database of 12,961 GCP SDK method signatures
4. Resolves each match to IAM permissions via a pre-built mapping

Runtime: <50ms per file. Zero network calls. All data is pre-built JSON.

## What's in the box

| File | What |
|---|---|
| `iam_permissions_v2.json` | 12,960 method → permission mappings across 119 services |
| `method_db.json` | 12,961 SDK method signatures for call matching |
| `service_registry.json` | 120 GCP services with module paths and IAM prefixes |
| `data/iam_roles.json` | 2,073 IAM roles with 12,879 valid permissions (ground truth) |

## Example: scan a real repo

```bash
git clone --depth 1 https://github.com/GoogleCloudPlatform/python-docs-samples /tmp/samples
gcp-sdk-detector scan /tmp/samples/kms/
```

Output shows every GCP SDK call with its file, line number, code snippet, and the IAM permission required. The summary lists all unique permissions — that's the minimum IAM role needed to run the code.

## Build pipeline

The permission mappings are pre-built and checked into the repo. You only need to re-run the build pipeline if SDK versions change or you want to add new services.

```bash
# Install SDK packages
pip install -e ".[dev]"

# Run the full pipeline (~50 min, ~$6 in Claude API costs)
python -m build_pipeline

# Or run individual stages
python -m build_pipeline --stage s04    # extract REST URIs from SDK source
python -m build_pipeline --stage s06    # map permissions with LLM

# Pipeline stats
python -m build_pipeline.stats
```

See `docs/build-pipeline.md` for the full design and how it works.

## Development

```bash
pip install -e ".[dev]"
make test     # 277 tests
make lint     # ruff check
make fmt      # ruff format
```

## Project docs

| Doc | What |
|---|---|
| `docs/build-pipeline.md` | Build pipeline design, experiments, and decisions |
| `docs/case-study-gemini-vs-claude.md` | LLM comparison for structured output pipelines |
| `docs/v2-quality-analysis.md` | v1 vs v2 accuracy analysis |
| `docs/exec-summary.md` | Executive summary with scale stats |
| `docs/scanner.md` | Runtime scanner architecture |
| `docs/cli.md` | CLI subcommands reference |
