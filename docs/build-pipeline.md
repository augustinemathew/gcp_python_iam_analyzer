# Build Pipeline

Generates `iam_permissions.json` — the static mapping from SDK methods to IAM permissions. Runs offline at build time. Runtime requires zero network calls.

## Pipeline Steps

```
pip install google-cloud-*          # prerequisites
                │
                ▼
build_service_registry.py           # → service_registry.json (modules, default metadata)
                │
                ▼
fix_registry_metadata.py            # Gemini fixes iam_prefix + display_name
                │
                ▼
build_method_inventory.py           # → method_inventory.json
                │
     ┌──────────┼──────────┐
     ▼                     ▼
fetch_discovery_docs.py    fetch_iam_reference.py     (async, concurrent)
     │                     │
     ▼                     ▼
discovery_docs/            iam_reference/
{service_id}.json          {service_id}.json
     │                     │
     └──────────┬──────────┘
                ▼
build_permission_mapping.py         # calls Gemini 3.0
                │
                ▼
        iam_permissions.json        # final static mapping
                │
                ▼
        validate_mapping.py         # cross-check, coverage report
```

## Step 1: SDK Introspection (`build_method_inventory.py`)

Scans all installed `google-cloud-*` packages and produces a method inventory:

```python
def build_method_inventory() -> list[MethodEntry]:
    """
    For each installed google-cloud-* pip package:
    1. Discover importable modules via importlib.metadata file records
    2. Find all classes containing "Client" in the name
    3. Introspect public methods with inspect.signature()
    4. Record (service_id, class_name, method_name, min_args,
       max_args, docstring_snippet)
    """
```

Output: `data/method_inventory.json`

## Step 2: Fetch Discovery Documents (`fetch_discovery_docs.py`)

Pulls API metadata from the Google APIs Discovery Service using async HTTP (`aiohttp`):

```
GET https://discovery.googleapis.com/discovery/v1/apis
GET https://{service}.googleapis.com/$discovery/rest?version={version}
```

Each discovery document contains:
- `resources`: nested REST resources with their methods
- Each method has `id`, `httpMethod`, `path`, `scopes`, `parameters`, `description`

The `id` field (e.g. `bigquery.datasets.get`) provides a strong correlation signal for mapping SDK methods → REST methods → IAM permissions.

Output: `data/discovery_docs/{service_id}.json`

## Step 3: Fetch IAM Permission Tables (`fetch_iam_reference.py`)

For each service, fetch the IAM reference page (async):

```
https://docs.cloud.google.com/iam/docs/roles-permissions/{service_id}
```

Lists every valid IAM permission string for the service.

Output: `data/iam_reference/{service_id}.json`

## Step 4: Gemini Mapping Engine (`build_permission_mapping.py`)

See [docs/gemini-mapping.md](gemini-mapping.md) for prompt design, batching, and validation.

## Incremental Updates

When a new SDK version adds methods:
1. Re-run `build_method_inventory.py` → diff against existing inventory
2. Only send new/changed methods to Gemini
3. Merge results into existing `iam_permissions.json`
