# Performance

## Measured Bottleneck

Profiled on the project itself (25 files):

```
Startup (one-time):
  Load registry+resolver:       0.3ms
  SDK introspection:        13,350ms  ← 99.7% of total time
  Scanner init:                 0.0ms

Scan phase:
  File discovery (rglob):       1.3ms  (25 files)
  Scan all files:              17ms

Per-file:
  GCP files:     avg 0.05ms  (tree-sitter parse + walk + resolve)
  Non-GCP files: avg 0.00ms  ("google.cloud" string check exits immediately)
```

**SDK introspection is the bottleneck.** It imports 63 packages and calls `inspect.signature()` on 14K methods. The actual scanning is sub-millisecond per file.

## Fix: Pre-built Method DB

`method_db.json` is generated at build time and loaded at runtime (~1ms). The scanner never imports GCP SDK packages.

```
Runtime: load 3 JSON files (~1ms) → scan N files (~0.05ms/file)
Build:   introspect SDKs (13s) → write method_db.json
```

## Runtime Hot Path

```
"google.cloud" in source?  →  tree-sitter parse  →  walk imports  →  walk calls  →  resolve
       O(n) string               ~0.05ms             O(imports)       O(calls)      O(1) dict
```

- **String check**: if `"google.cloud"` not in source, return immediately. Skips ~80% of files.
- **Single parse**: tree-sitter parse shared between import detection and call walking.
- **Resolution**: two `dict.get()` calls (exact key, wildcard fallback).

## Targets

| Metric | Target | Measured |
|---|---|---|
| Startup (JSON load) | < 5ms | 0.3ms |
| Single file (1K lines) | < 1ms | 0.05ms |
| 100 files | < 50ms | ~5ms |
| Non-GCP file | < 0.01ms | 0.0ms |

## Async I/O

`scan_files()` uses `aiofiles` + `asyncio.Semaphore(64)` for concurrent file reads. For small files, asyncio overhead can exceed the I/O benefit. Sync `scan_source()` is available for single-file use.
