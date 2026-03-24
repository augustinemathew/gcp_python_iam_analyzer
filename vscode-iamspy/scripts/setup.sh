#!/usr/bin/env bash
# Setup script for vscode-iamspy development.
# Creates a Python venv with iamspy, installs npm deps, builds, and tests.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✔${NC} $1"; }
fail() { echo -e "  ${RED}✘${NC} $1"; }
warn() { echo -e "  ${YELLOW}!${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_ROOT="$(cd "$EXT_DIR/.." && pwd)"
VENV_DIR="$EXT_DIR/.venv"

ERRORS=0

echo ""
echo "=== vscode-iamspy setup ==="
echo ""

# ── 1. Node.js ──────────────────────────────────────────────────────────
echo "Checking prerequisites..."

if command -v node &>/dev/null; then
  NODE_VERSION=$(node --version)
  NODE_MAJOR=$(echo "$NODE_VERSION" | sed 's/v\([0-9]*\).*/\1/')
  if [ "$NODE_MAJOR" -ge 18 ]; then
    pass "Node.js $NODE_VERSION"
  else
    fail "Node.js $NODE_VERSION (need >= 18)"
    ERRORS=$((ERRORS + 1))
  fi
else
  fail "Node.js not found. Install from https://nodejs.org/"
  ERRORS=$((ERRORS + 1))
fi

# ── 2. npm ──────────────────────────────────────────────────────────────
if command -v npm &>/dev/null; then
  pass "npm $(npm --version)"
else
  fail "npm not found"
  ERRORS=$((ERRORS + 1))
fi

# ── 3. Python ───────────────────────────────────────────────────────────
if command -v python3 &>/dev/null; then
  PY_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
  PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
  PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
  if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 12 ]; then
    pass "Python $PY_VERSION"
  else
    fail "Python $PY_VERSION (need >= 3.12)"
    ERRORS=$((ERRORS + 1))
  fi
else
  fail "Python 3 not found"
  ERRORS=$((ERRORS + 1))
fi

# ── 4. VS Code (optional) ──────────────────────────────────────────────
if command -v code &>/dev/null; then
  pass "VS Code CLI ($(code --version | head -1))"
else
  warn "VS Code CLI not found (optional — needed for VSIX install)"
fi

echo ""

# ── Bail if prerequisites missing ───────────────────────────────────────
if [ "$ERRORS" -gt 0 ]; then
  echo -e "${RED}$ERRORS prerequisite(s) missing. Fix the issues above and re-run.${NC}"
  exit 1
fi

# ── 5. Create Python venv and install iamspy ────────────────────────────
echo "Setting up Python venv..."

if [ -d "$VENV_DIR" ]; then
  pass "venv already exists at .venv/"
else
  python3 -m venv "$VENV_DIR"
  pass "created venv at .venv/"
fi

# Activate and install iamspy in editable mode.
source "$VENV_DIR/bin/activate"

pip install -q -e "$PROJECT_ROOT[dev]"
pass "iamspy installed in venv"

# Verify it works.
if "$VENV_DIR/bin/iamspy" --help &>/dev/null; then
  pass "iamspy CLI works ($VENV_DIR/bin/iamspy)"
else
  fail "iamspy CLI failed to run"
  exit 1
fi

# ── 6. Write iamspy.cliPath into project root's VS Code settings ────────
# F5 opens the project root (gcp_ae/) as the debug workspace, so the
# setting must live there — not in vscode-iamspy/.vscode/settings.json.
PROJECT_VSCODE_DIR="$PROJECT_ROOT/.vscode"
PROJECT_SETTINGS="$PROJECT_VSCODE_DIR/settings.json"
mkdir -p "$PROJECT_VSCODE_DIR"

CLI_PATH="$VENV_DIR/bin/iamspy"

if [ -f "$PROJECT_SETTINGS" ]; then
  if grep -q "iamspy.cliPath" "$PROJECT_SETTINGS"; then
    # Update existing value.
    sed -i '' "s|\"iamspy.cliPath\":.*|\"iamspy.cliPath\": \"$CLI_PATH\"|" "$PROJECT_SETTINGS"
    pass "updated iamspy.cliPath in $PROJECT_SETTINGS"
  else
    # Add to existing settings: insert comma after last property, add new key.
    # Use python for reliable JSON manipulation.
    python3 -c "
import json, pathlib
p = pathlib.Path('$PROJECT_SETTINGS')
d = json.loads(p.read_text())
d['iamspy.cliPath'] = '$CLI_PATH'
p.write_text(json.dumps(d, indent=4) + '\n')
"
    pass "added iamspy.cliPath to $PROJECT_SETTINGS"
  fi
else
  cat > "$PROJECT_SETTINGS" << EOF
{
    "iamspy.cliPath": "$CLI_PATH"
}
EOF
  pass "wrote $PROJECT_SETTINGS (iamspy.cliPath → venv)"
fi

echo ""

# ── 7. Install npm dependencies ────────────────────────────────────────
echo "Installing npm dependencies..."
cd "$EXT_DIR"
npm install --no-audit --no-fund 2>&1 | tail -1
pass "npm install"

# ── 8. Type-check ──────────────────────────────────────────────────────
echo "Type-checking..."
npx tsc --noEmit
pass "tsc --noEmit"

# ── 9. Lint ─────────────────────────────────────────────────────────────
echo "Linting..."
npx eslint src/ test/
pass "eslint"

# ── 10. Build ───────────────────────────────────────────────────────────
echo "Building..."
node esbuild.mjs
pass "esbuild → dist/extension.js"

# ── 11. Compile tests ──────────────────────────────────────────────────
echo "Compiling tests..."
npx tsc -p tsconfig.test.json
pass "test compilation"

# ── 12. Unit tests ─────────────────────────────────────────────────────
echo "Running unit tests..."
npx mocha out/test/suite/**/*.test.js
pass "unit tests"

echo ""
echo -e "${GREEN}Setup complete!${NC}"
echo ""
echo "iamspy CLI: $VENV_DIR/bin/iamspy"
echo ""
echo "Next steps:"
echo "  1. Open vscode-iamspy/ in VS Code"
echo "  2. Press F5 to launch the extension in debug mode"
echo "  3. Open a Python file with GCP imports"
echo "  4. Look for 🔑 annotations above SDK calls"
echo ""
echo "Other commands:"
echo "  npm run watch              # rebuild on file changes"
echo "  npm run test:unit          # unit tests (fast)"
echo "  npm run test:integration   # integration tests (launches VS Code)"
echo "  npm run package            # build .vsix for installation"
