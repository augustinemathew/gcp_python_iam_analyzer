# Scanner

Single `scanner.py` module. Async file I/O, sync tree-sitter parse.

## Architecture

```
scan_files(paths)                        # async: concurrent file reads
  └─▶ scan_source(source, filename)      # sync: two-phase detection
        ├─▶ "google.cloud" in source?    # fast string check, early exit if absent
        ├─▶ tree-sitter parse            # single parse, shared below
        ├─▶ detect_gcp_imports(tree)     # walk import nodes → set of service_ids
        ├─▶ _walk(root_node)             # walk call nodes, filter by imported services
        └─▶ resolver.resolve(...)        # O(1) permission lookup
```

`scan_source` is the core — pure function on a string. `scan_files` wraps it with async I/O via `aiofiles` + `asyncio.Semaphore(64)`.

## Import Detection

**No GCP imports = no findings.** Files without `google.cloud` imports produce zero results, eliminating false positives.

### Two-phase approach

1. **Fast string check**: `"google.cloud" in source` — O(n) substring search. If absent, return immediately. No tree-sitter parse.
2. **AST-based extraction**: Walk tree-sitter `import_from_statement` and `import_statement` nodes. Correct handling of all Python import syntax.

### Why tree-sitter, not regex

Regex-based import detection is fragile:
- Multi-line parenthesized imports need state tracking
- Whitespace variations break patterns
- Comments between import tokens cause false matches
- Backslash continuations are hard to handle

Tree-sitter already parses the file and gives us proper AST nodes for imports. Since we're parsing anyway (for call detection), we share the single parse between import detection and call walking — zero extra cost.

### Import patterns handled

All standard Python import syntax works because tree-sitter handles the parsing:

```python
# Category 1: from google.cloud import <module>
from google.cloud import storage
from google.cloud import storage as gcs
from google.cloud import storage, bigquery
from google.cloud import (
    storage,
    bigquery,
)

# Category 2: from google.cloud.<module> import <name>
from google.cloud.storage import Client
from google.cloud.kms_v1 import KeyManagementServiceClient
from google.cloud.firestore_v1 import Client as FirestoreClient

# Category 3: import google.cloud.<module>
import google.cloud.storage
import google.cloud.storage as gcs
```

### Module name → service_id

Extracted module names (e.g. `storage`, `kms_v1`) resolve to `service_id` via `_module_to_service`, which is **derived from `service_registry.json`** at scanner init time. Adding a new service to the registry automatically enables import detection for it — no hardcoded mapping to maintain.

```python
build_module_to_service(registry) -> dict[str, str]
# Reads registry modules like ["google.cloud.kms", "google.cloud.kms_v1"]
# Produces: {"kms": "kms", "kms_v1": "kms"}
```

### Not detected

- `import google.cloud` (too broad — can't determine which service)
- `from google import cloud` (same)
- Dynamic imports (`importlib.import_module(...)`)

### Filtering behavior

When GCP imports are detected, `_check_call` filters matched signatures to only services present in the import set:

- `pandas.query("col > 5")` with no GCP imports → **no findings**
- `client.query("SELECT 1")` importing only `storage` → **no findings** (bigquery not imported)
- `client.query("SELECT 1")` importing `bigquery` → **finding** (correct service)

## Detection Strategy

1. Fast string check for `"google.cloud"` → early exit if absent
2. Single tree-sitter parse (shared between import detection and call walking)
3. Walk import nodes → set of imported service_ids
4. Walk call nodes → extract method name, count args, match sigs filtered by imports
5. Resolve permissions via `PermissionResolver`

## Method Name Extraction

```python
_extract_method_name(call_node) -> str | None
```

Extracts the **rightmost** identifier from attribute chains:
- `client.query(sql)` → `"query"`
- `bucket.blob("f").upload_from_filename("x")` → `"upload_from_filename"`
- `some_func()` → `"some_func"` (bare function call)

**Limitation**: Class context is lost — we only see the method name, not which class called it. Type inference is out of scope.

## Argument Counting

```python
_count_positional_args(call_node) -> int
```

Counts **positional** arguments only. Excludes `keyword_argument`, `dictionary_splat`, `list_splat`.

| Call Pattern | Count | Notes |
|---|---|---|
| `client.query(sql)` | 1 | Standard |
| `client.query(sql, timeout=30)` | 1 | Keyword ignored |
| `client.query(request={"query": sql})` | 0 | All-keyword (common in GCP SDK) |
| `publisher.publish(topic, data, **attrs)` | 2 | Splat ignored |

**The all-keyword pattern** is the biggest gap. Many GCP SDK methods accept a single `request` keyword argument. The signature must set `min_args=0` to match.

## Signature Matching

A call matches a `MethodSig` if:
1. Method name exists in `MethodDB` (dict lookup, O(1))
2. `service_id` is in the file's imported services
3. Positional arg count within `[min_args, max_args]`, or `has_var_kwargs=True` and count >= `min_args`

## Permission Resolution

For each matched `MethodSig`, calls `resolver.resolve(service_id, class_name, method_name)`. Priority:
1. Exact key: `{service_id}.{class_name}.{method_name}`
2. Wildcard: `{service_id}.*.{method_name}`
3. `None` → unmapped
