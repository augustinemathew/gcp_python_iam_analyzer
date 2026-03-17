```
  ___    _    __  __   ____
 |_ _|  / \  |  \/  | / ___| _ __  _   _
  | |  / _ \ | |\/| | \___ \| '_ \| | | |
  | | / ___ \| |  | |  ___) | |_) | |_| |
 |___/_/   \_\_|  |_| |____/| .__/ \__, |
                             |_|    |___/
```

# IAMSpy 🔍🕵️

**Spy on your Python code to find exactly which GCP IAM permissions it needs.**

> *"What permissions does my code need?"* — Every GCP developer, every deployment.

IAMSpy statically analyzes your Python source code, detects every GCP SDK method call, and tells you the precise IAM permissions required — **before you deploy**.

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

⚡ No runtime imports. 🌐 No network calls. 🔑 No GCP credentials. Just point it at your code.

## Why IAMSpy? 🤔

**You're deploying a service that uses 5 GCP APIs.** What IAM role do you create?

You could spend an hour reading permission docs for each API. Or:

```bash
iamspy scan src/
```

Done. Exact permission list. Seconds.

| | |
|---|---|
| ⚡ **Fast** | <50ms per file. 3,600 files in <30 seconds. |
| 🎯 **Accurate** | 100% on Google's [python-docs-samples](https://github.com/GoogleCloudPlatform/python-docs-samples) (3,144 calls, 706 permissions) |
| 📦 **Complete** | 25,011 methods across 205 GCP services |
| 🛡️ **Zero false positives** | No GCP imports = no findings. Period. |

## Install

```bash
pip install -e .
iamspy --help
```

Or with a virtual environment:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Quick start

```bash
# Scan a file
iamspy scan app.py

# Scan an entire project
iamspy scan src/

# Scan a cloned repo
git clone --depth 1 https://github.com/GoogleCloudPlatform/python-docs-samples /tmp/samples
iamspy scan /tmp/samples/kms/
```

## Scan output

IAMSpy shows every GCP SDK call with its file, line number, code snippet, and the IAM permission required:

```
$ iamspy scan /tmp/samples/secretmanager/

secretmanager/snippets/create_secret.py
    61  response = client.create_secret(
        → secretmanager.secrets.create

secretmanager/snippets/add_secret_version.py
    51  response = client.add_secret_version(
        → secretmanager.versions.add

secretmanager/snippets/access_secret_version.py
    48  response = client.access_secret_version(
        → secretmanager.versions.access
        ⚠ conditional: secretmanager.secrets.get

──────────────────────────────────────────────────
74 file(s), 140 finding(s)

Required permissions:
  • secretmanager.secrets.create
  • secretmanager.secrets.delete
  • secretmanager.secrets.get
  • secretmanager.secrets.list
  • secretmanager.secrets.update
  • secretmanager.versions.access
  • secretmanager.versions.add
  • secretmanager.versions.destroy
  ...
```

### Output formats

```bash
iamspy scan app.py                # colored terminal output
iamspy scan --json app.py         # JSON (for CI/tooling)
iamspy scan --compact src/        # one-line-per-finding (like ruff)
iamspy scan --show-all app.py     # include local helpers
```

## Search permissions

Find any method or permission with glob wildcards:

```bash
$ iamspy search '*encrypt*'

  Method                                              Permissions                                       Conditional
  ──────────────────────────────────────────────────  ────────────────────────────────────────────────  ──────────────────────────────
  kms.KeyManagementServiceClient.encrypt              cloudkms.cryptoKeyVersions.useToEncrypt
  kms.KeyManagementServiceClient.raw_encrypt          cloudkms.cryptoKeyVersions.useToEncrypt
  compute.InstancesClient.start_with_encryption_key   compute.instances.startWithEncryptionKey

  19 result(s) for '*encrypt*'

$ iamspy search '*.create_role'

  iamadmin.IAMClient.create_role                      iam.roles.create

$ iamspy search 'iam.roles.*'

  iamadmin.IAMClient.create_role                      iam.roles.create
  iamadmin.IAMClient.delete_role                      iam.roles.delete
  iamadmin.IAMClient.get_role                         iam.roles.get
  iamadmin.IAMClient.list_roles                       iam.roles.list
  iamadmin.IAMClient.undelete_role                    iam.roles.undelete
  iamadmin.IAMClient.update_role                      iam.roles.update
```

## List services

```bash
$ iamspy services

service_id                display_name                   iam_prefix           pip_package
────────────────────────────────────────────────────────────────────────────────────────
aiplatform                Vertex AI                      aiplatform           google-cloud-aiplatform
bigquery                  BigQuery                       bigquery             google-cloud-bigquery
compute                   Compute Engine                 compute              google-cloud-compute
kms                       Cloud KMS                      cloudkms             google-cloud-kms
storage                   Cloud Storage                  storage              google-cloud-storage
...

205 services
```

## How it works 🧠

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

All data is pre-built JSON. No SDK imports, no network calls, no GCP credentials. The scanner loads 3 JSON files (~10MB) and parses your source — that's it.

## Adding a new service

```bash
# If iamspy reports "unmapped" for a service you need:
pip install google-cloud-newservice
python -m build_pipeline add google-cloud-newservice
```

The build pipeline discovers the package, extracts REST URIs from the SDK source code, and uses Claude to map methods to permissions. Incremental — only maps new methods.

## Performance ⚡

| What | Speed |
|---|---|
| Single file | <50ms |
| 100 files | <2s |
| 3,642 files (python-docs-samples) | <30s |
| Startup (load JSON data) | ~39ms |

## Coverage 📊

| What | Count |
|---|---|
| 🏢 GCP services | 205 |
| 🔧 SDK methods mapped | 25,011 |
| ✍️ Method signatures | 24,330 |
| 🔑 IAM permissions tracked | 12,879 |
| ✅ python-docs-samples accuracy | 100% (3,144/3,144) |

## Build pipeline 🏗️

The permission mappings are pre-built and checked into the repo. The build pipeline analyzes **8.8 million lines** of GCP SDK source code, extracts 52,841 REST API endpoints, and uses Claude to map methods to permissions.

```bash
python -m build_pipeline diff                   # 🔍 what's missing?
python -m build_pipeline add google-cloud-X     # ➕ add a service
python -m build_pipeline refresh --service kms  # 🔄 re-map a service
python -m build_pipeline stats                  # 📊 pipeline stats
python -m build_pipeline run                    # 🚀 full pipeline (~$8, ~75 min)
```

See [docs/build-pipeline.md](docs/build-pipeline.md) for the full architecture.

## Development 🛠️

```bash
pip install -e ".[dev]"
make test     # 311 tests
make lint     # ruff check
make fmt      # ruff format
```

## Docs 📚

| Doc | What |
|---|---|
| [Build Pipeline](docs/build-pipeline.md) | Architecture, prompt design, monorepo integration |
| [Gemini vs Claude](docs/case-study-gemini-vs-claude.md) | LLM comparison for structured output |
| [Quality Analysis](docs/v2-quality-analysis.md) | v1 vs v2 accuracy study |

---

<p align="center">
  <i>Built by analyzing 8.8M lines of GCP SDK code so you don't have to read them.</i>
</p>
