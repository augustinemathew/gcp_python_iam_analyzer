```
  ___    _    __  __   ____
 |_ _|  / \  |  \/  | / ___| _ __  _   _
  | |  / _ \ | |\/| | \___ \| '_ \| | | |
  | | / ___ \| |  | |  ___) | |_) | |_| |
 |___/_/   \_\_|  |_| |____/| .__/ \__, |
                             |_|    |___/
```

# IAMSpy

**Spy on your Python code to find exactly which GCP IAM permissions it needs.**

```
$ iamspy scan app.py

app.py
    12  client.create_key_ring(request={"parent": parent, "key_ring_id": id})
        → cloudkms.keyRings.create

    18  client.encrypt(request={"name": key_name, "plaintext": data})
        → cloudkms.cryptoKeyVersions.useToEncrypt

    25  bucket = storage_client.get_bucket("my-data")
        → storage.buckets.get

──────────────────────────────────────────────────
1 file(s), 3 finding(s)

Required permissions:
  • cloudkms.keyRings.create
  • cloudkms.cryptoKeyVersions.useToEncrypt
  • storage.buckets.get
```

⚡ No runtime imports. 🌐 No network calls. 🔑 No GCP credentials.

**100% accurate** on Google's [python-docs-samples](https://github.com/GoogleCloudPlatform/python-docs-samples) — 3,144 SDK calls, every one mapped. → [How we validated](docs/accuracy.md)

| | |
|---|---|
| ⚡ **Fast** | < 50ms per file. 3,600 files in < 30 seconds. |
| 🎯 **Accurate** | >93% on python-docs-samples (3,144 calls, 706 permissions) |
| 📦 **Complete** | 25,011 methods across 205 GCP services |
| 🛡️ **Zero false positives** | No GCP imports = no findings. Period. |

## Install

```bash
pip install -e .
iamspy --help
```

## Usage

```bash
# Scan a file or directory
iamspy scan app.py
iamspy scan src/

# Output formats
iamspy scan --compact src/    # one line per finding (like ruff)
iamspy scan --json app.py     # JSON for CI/tooling
iamspy scan --show-all app.py # include path builders and constructors
```

Search any method or permission without scanning a file:

```
$ iamspy search '*encrypt*'

  Method                                            Permissions
  ────────────────────────────────────────────────  ───────────────────────────────────────
  kms.KeyManagementServiceClient.encrypt            cloudkms.cryptoKeyVersions.useToEncrypt
  kms.KeyManagementServiceClient.raw_encrypt        cloudkms.cryptoKeyVersions.useToEncrypt
  compute.InstancesClient.start_with_encryption_key compute.instances.startWithEncryptionKey

  19 result(s) for '*encrypt*'
```

## How it works

```
Your Python code
    │
    ▼
┌─────────────────────────────────────────────┐
│  1. 🔍 Check imports                        │
│     "google.cloud" in source? No → skip     │
│                                             │
│  2. 🌳 Parse with tree-sitter               │
│     Build AST, find method calls            │
│                                             │
│  3. 🎯 Match against 25,011 signatures      │
│     Method name + arg count → service match │
│                                             │
│  4. 🔑 Resolve IAM permissions              │
│     Method → permission(s) via pre-built DB │
└─────────────────────────────────────────────┘
    │
    ▼
Required permissions: bigquery.jobs.create, storage.buckets.get, ...
```

All data is pre-built JSON. No SDK imports, no network calls, no credentials. The scanner loads 3 JSON files (~10MB) and parses your source — that's it.

## Coverage

| | |
|---|---|
| GCP services | 205 |
| SDK methods mapped | 25,011 |
| Method signatures | 24,330 |
| IAM permissions tracked | 12,879 |
| python-docs-samples accuracy | 100% (3,144/3,144) |

## Examples

Browse [examples/](examples/) — ready-to-scan GCP scripts with expected `iamspy` output:

| File | What it shows |
|---|---|
| [kms_encrypt_decrypt.py](examples/kms_encrypt_decrypt.py) | Create key, encrypt, decrypt — 4 permissions |
| [bigquery_pipeline.py](examples/bigquery_pipeline.py) | Load, query, export — with conditional permissions |
| [secret_manager.py](examples/secret_manager.py) | Full secret lifecycle |
| [storage_pipeline.py](examples/storage_pipeline.py) | Upload, download, copy, delete |

## Docs

| | |
|---|---|
| [Getting started](docs/getting-started.md) | Reading output, scanning directories, output formats |
| [CI integration](docs/ci-integration.md) | GitHub Actions, Cloud Build, failing on unmapped |
| [Accuracy](docs/accuracy.md) | How we validated, methodology, known limitations |
| [Architecture](docs/architecture.md) | How the scanner works (for contributors) |
| [Build pipeline](docs/build-pipeline.md) | Rebuilding the permission database |

## Adding a service

```bash
pip install google-cloud-newservice
python -m build_pipeline add google-cloud-newservice
```

Incremental — only maps new methods.

## Development

```bash
pip install -e ".[dev]"
make test   # 316 tests
make lint
```

---

<p align="center"><i>Built by analyzing 8.8M lines of GCP SDK code so you don't have to read them.</i></p>
