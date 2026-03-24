# IAMSpy VS Code Extension — Quickstart

## Setup

```bash
cd vscode-iamspy
./scripts/setup.sh
```

This will:
1. Check prerequisites (Node >= 18, Python >= 3.12)
2. Create `.venv/` with `iamspy` installed in editable mode
3. Configure VS Code to use the venv's `iamspy`
4. Install npm dependencies, build, lint, and run unit tests

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Node.js | >= 18 | [nodejs.org](https://nodejs.org/) |
| Python | >= 3.12 | [python.org](https://www.python.org/) |
| VS Code | any recent | [code.visualstudio.com](https://code.visualstudio.com/) |

Everything else is installed by the setup script into the venv.

## Installing the extension

### Package the `.vsix`

```bash
cd vscode-iamspy
npm run package
# Creates vscode-iamspy-0.1.0.vsix
```

### VS Code

```bash
code --install-extension vscode-iamspy-0.1.0.vsix
```

### Cursor

```bash
cursor --install-extension vscode-iamspy-0.1.0.vsix
```

### Antigravity

```bash
antigravity --install-extension vscode-iamspy-0.1.0.vsix
```

### Manual install (any VS Code fork)

1. Open the Extensions sidebar
2. Click **⋯** → **Install from VSIX...**
3. Select `vscode-iamspy-0.1.0.vsix`

> **Note:** After installing, configure `iamspy.cliPath` in Settings to point to your `iamspy` CLI (e.g. `.venv/bin/iamspy`). The setup script does this automatically for development.

## Running in development mode

1. Open `vscode-iamspy/` in VS Code
2. Press **F5** — launches a new VS Code window with the extension loaded
3. Open any Python file with `google.cloud` imports
4. 🔑 annotations appear above each GCP SDK call

## What you'll see

- **🔑 CodeLens** above each GCP SDK call showing required IAM permissions
- **Status bar** (bottom right): permission count — click for grouped summary
- **Command palette** → "IAMSpy: Generate Permission Manifest"

## Configuration

| Setting | Default | Purpose |
|---------|---------|---------|
| `iamspy.cliPath` | `.venv/bin/iamspy` | Path to CLI (set by setup script) |
| `iamspy.scanOnSave` | `true` | Auto-scan on file save |

## Development commands

```bash
npm run compile          # type-check + lint + bundle
npm run watch            # rebuild on file changes
npm run test:unit        # unit tests (fast, no VS Code)
npm run test:integration # integration tests (launches VS Code)
npm run lint             # ESLint only
npm run lint:fix         # auto-fix lint issues
```

## Troubleshooting

**No CodeLens appearing?**
- File must have `from google.cloud import ...` — no imports = no findings
- Check Output panel → "IAMSpy" for errors
- Verify: `.venv/bin/iamspy scan --json yourfile.py`

**Slow?**
- Each scan is ~180ms (Python startup). Per-save, not per-keystroke.
- See `docs/vscode-extension.md` for the planned `iamspy serve` daemon upgrade.
