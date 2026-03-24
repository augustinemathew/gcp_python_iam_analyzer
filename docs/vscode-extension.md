# VS Code Extension — Design & Implementation

## Overview

A VS Code extension that surfaces GCP IAM permissions inline in Python files. Thin UI layer over the `iamspy` CLI — all analysis logic stays in Python.

## User Journey

1. **Open Python file** — extension activates on `google.cloud` imports, scans in background
2. **CodeLens inline** — permissions shown above each GCP SDK call; click for full detail (conditionals, notes, confidence)
3. **Status bar summary** — aggregate permission count; click for service-grouped quick pick
4. **Generate manifest** — command palette → scan file or workspace → prompt for save location (defaults to `iam-manifest.yaml`) → opens result

## Architecture

```
  ┌──────────────┐  file events   ┌────────────┐   execFile    ┌─────────┐
  │  VS Code     │ ─────────────→ │ scanner.ts │ ────────────→ │ iamspy  │
  │  FileWatcher │                │  (cache)   │ ←── JSON ──── │  CLI    │
  └──────────────┘                └────────────┘               └─────────┘
                                       │
                          ┌────────────┼──────────┐
                          ▼            ▼          ▼
                    ┌──────────┐ ┌──────────┐ ┌──────────┐
                    │ CodeLens │ │ StatusBar│ │ Manifest │
                    └──────────┘ └──────────┘ └──────────┘
```

### How scanning works

- On save, open, create, or change of any `*.py` file, `scanner.ts` shells out to `iamspy scan --json <file>`
- ~180ms per invocation (Python startup + JSON load + tree-sitter parse)
- Results cached in `Map<filePath, Finding[]>`, invalidated on re-scan
- In-flight scans cancelled if file changes again before completion
- `FileSystemWatcher` on `**/*.py` handles background file changes

### Module layout

| File | Role | VS Code API? |
|------|------|:---:|
| `types.ts` | `IamspyFinding` interface (mirrors CLI JSON) | No |
| `format.ts` | `formatTitle`, `formatTooltip`, `countPermissions`, `groupByService` | No |
| `scanner.ts` | `scanPath` — shells out to CLI, parses JSON | No |
| `codelens.ts` | `IamspyCodeLensProvider` — maps findings to CodeLens | Yes |
| `statusBar.ts` | Status bar item + summary quick pick | Yes |
| `manifest.ts` | "Generate Manifest" command handler | Yes |
| `extension.ts` | `activate`/`deactivate` — wires everything together | Yes |

Pure logic (types, format, scanner) is fully unit-testable without VS Code. VS Code-dependent modules are tested via integration tests.

## Configuration

| Setting | Default | Purpose |
|---------|---------|---------|
| `iamspy.cliPath` | `"iamspy"` | Path to CLI executable |
| `iamspy.scanOnSave` | `true` | Auto-scan on file save |

## Testing

- **Unit tests**: `mocha` — test pure functions (parseFindings, formatTitle, countPermissions, groupByService)
- **Integration tests**: `@vscode/test-cli` + `@vscode/test-electron` — launch real VS Code, open fixture, verify CodeLens

## Installation

Package the extension and install in any VS Code-compatible editor:

```bash
cd vscode-iamspy
npm run package                # builds vscode-iamspy-0.1.0.vsix
```

| Editor | CLI install |
|--------|-------------|
| VS Code | `code --install-extension vscode-iamspy-0.1.0.vsix` |
| Cursor | `cursor --install-extension vscode-iamspy-0.1.0.vsix` |
| Antigravity | `antigravity --install-extension vscode-iamspy-0.1.0.vsix` |

Or use **Extensions sidebar → ⋯ → Install from VSIX...** in any editor.

After installing, set `iamspy.cliPath` in Settings to the path to your `iamspy` CLI executable.

## Future: `iamspy serve` daemon

Current approach pays ~180ms Python startup per scan. If latency becomes an issue:
- Add `iamspy serve` subcommand — stdin/stdout JSON-RPC daemon
- Loads JSON once, responds to scan requests in ~1ms
- Extension keeps a single child process alive, sends requests over stdin
- No protocol overhead — simpler than LSP

## What we're NOT doing

- No LSP server (overkill for CLI wrapper)
- No TypeScript reimplementation of the scanner
- No diagnostics/problems panel
- No deployed policy diff (future agent feature)
