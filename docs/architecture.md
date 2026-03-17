# Architecture

IAMSpy is a two-phase system. All expensive work happens at build time and ships as static JSON. The scanner just loads files and looks things up.

## Runtime (the hot path)

```
Load 3 JSON files (~39ms)
    │
    ▼
"google." in source?  →  No  →  done (zero findings)
    │ Yes
    ▼
tree-sitter parse  →  walk imports  →  detect GCP services
    │
    ▼
walk call nodes  →  method name + arg count
    │
    ▼
match against method_db.json  →  filter by imported services
    │
    ▼
O(1) lookup in iam_permissions.json  →  Finding
```

**Three JSON files loaded at startup:**

| File | Size | Contents |
|---|---|---|
| `service_registry.json` | 33 KB | 205 services — pip package, IAM prefix, importable modules |
| `method_db.json` | 4.7 MB | 25,011 methods, 24,330 signatures (min/max args, class, service) |
| `iam_permissions.json` | 3 MB | Method → permission mappings for all 205 services |

## Import detection

The scanner only produces findings for services that are actually imported. `from google.cloud import bigquery` enables BigQuery detection; nothing else does.

This is the zero-false-positive guarantee: if `google.` doesn't appear in the source, parsing is skipped entirely.

## Signature matching

Each method call is matched by name + argument count against `method_db.json`. A call to `client.encrypt(request={...})` has 1 argument, which must fall within `[min_args, max_args]` for the signature to match — or the method must have `**kwargs`.

This prevents `df.query("SELECT 1")` (pandas) from matching `client.query("SELECT 1")` (BigQuery) — they have the same method name but the scanner only fires when a BigQuery import is present.

## Build time

Seven pipeline stages build the static artifacts:

```
s01  Discover 205 SDK packages           → service_registry.json
s02  Fix IAM prefixes (LLM-assisted)     → service_registry.json
s03  Introspect SDK classes              → method_db.json
s04  Extract REST URIs + docstrings      → method_context.json
s05  Download IAM role catalog           → data/iam_roles.json
s06  LLM mapping (Claude, Config D+)     → iam_permissions.json
s07  Validate against role catalog       → validation report
```

See [build-pipeline.md](build-pipeline.md) for full details.

## Key source files

```
src/iamspy/
├── scanner.py      # GCPCallScanner — tree-sitter parse + match + resolve
├── resolver.py     # StaticPermissionResolver — O(1) JSON lookup
├── registry.py     # ServiceRegistry — service_id, iam_prefix, modules
├── models.py       # PermissionResult, MethodSig, Finding, ScanResult
├── loader.py       # Deserialize method_db.json
└── cli.py          # scan / search / services subcommands
```
