# Code Review Action Items

**Date**: 2026-03-29
**Reviewer**: Claude + Augustine
**Scope**: Full codebase — agents/, src/iamspy/, evals/, tests/

## Summary

The core scanner (iamspy) is solid — 282 tests, 97.9% credential provenance accuracy, deterministic tree-sitter parsing. The agent conversation flow works end-to-end with real GCP APIs. But the surrounding code has significant debt: three copies of the codebase, no programmatic conversation eval assertions, non-deterministic role selection, inconsistent error handling, and several functions exceeding the project's 40-line style guide.

---

## P0 — Must Fix

### P0-1: Fix manifest absolute paths
**Status**: [ ] Not started
**Files**: `src/iamspy/manifest.py`

**Problem**: The `sources` section in `iam-manifest.yaml` emits absolute paths:
```yaml
sources:
  bigquery.jobs.create:
  - file: /Users/augustine/gcp_ae/evals/acme_data_pipeline/app/main.py
    line: 30
```
This is machine-specific and useless for anyone else. Committed manifests would differ per developer.

**Fix**: In `ManifestGenerator.build()`, compute paths relative to the first scanned path (the project root). The `scanned_paths` argument already has this info.

**Location**: `src/iamspy/manifest.py`, lines 66-76 (the loop that builds `sources`). Change:
```python
sources.setdefault(perm, []).append(
    {"file": finding.file, "line": finding.line, "method": finding.method_name}
)
```
To compute relative path:
```python
import os
rel_file = os.path.relpath(finding.file, scanned_paths[0]) if scanned_paths else finding.file
sources.setdefault(perm, []).append(
    {"file": rel_file, "line": finding.line, "method": finding.method_name}
)
```

**Also fix**: The `identity` field in sources (line 75) — same issue. And `agents/admin/tools.py:_scan_directory()` which does `os.path.relpath(d["file"], directory)` correctly — follow that pattern.

**Tests to update**: `tests/test_manifest.py` — any test that checks `sources` paths. The `run_evals.py` harness doesn't check source paths so should be unaffected.

**Verify**: Run `python -m iamspy scan --manifest /tmp/test.yaml evals/acme_data_pipeline/app/` and check that paths are relative (e.g., `main.py` not `/Users/.../main.py`).

---

### P0-2: Delete old directories, fix all imports
**Status**: [ ] Not started
**Files**: `iam_agent/`, `iam_ide_agent/`, `iamspy_mcp/`

**Problem**: Three copies of the codebase coexist:
- `iam_agent/` — old admin agent, superseded by `agents/admin/`
- `iam_ide_agent/` — old IDE agent, superseded by `agents/ide/`
- `iamspy_mcp/` — old MCP/shared layer, superseded by `agents/shared/` and `agents/mcp/`

Tests import from different sources creating a fragile web:
- `tests/test_guardrails.py` imports from `iamspy_mcp.shared.guardrails`
- `tests/test_iam_agent_tools.py` imports from `agents.admin.tools`
- `evals/run_evals.py` imports from `agents.shared.permission_rings`

**Fix** (in order):

1. **Update test imports**:
   - `tests/test_guardrails.py`: change `from iamspy_mcp.shared.guardrails` → `from agents.shared.guardrails`
   - `tests/test_guardrails.py`: change `from iamspy_mcp.shared.permission_rings` → `from agents.shared.permission_rings` (if referenced)
   - Any other file importing from `iamspy_mcp.*` → `agents.*`

2. **Search for ALL references** to old modules:
   ```bash
   grep -r "from iam_agent\." --include="*.py" .
   grep -r "from iam_ide_agent\." --include="*.py" .
   grep -r "from iamspy_mcp\." --include="*.py" .
   grep -r "import iam_agent" --include="*.py" .
   grep -r "import iam_ide_agent" --include="*.py" .
   grep -r "import iamspy_mcp" --include="*.py" .
   ```
   Fix every hit.

3. **Run full test suite** to verify nothing breaks: `python -m pytest tests/ -q`

4. **Delete the directories**:
   ```bash
   rm -rf iam_agent/ iam_ide_agent/ iamspy_mcp/
   ```

5. **Run tests again** to confirm clean.

6. **Update `pyproject.toml`** if any entry points reference old modules.

7. **Update CLAUDE.md** if it references old directory paths.

**Do NOT delete** `gcp_cost_optimizer_agent/` — it's a separate real agent, not a duplicate.

---

### P0-3: Build deterministic `permissions_to_roles()`
**Status**: [ ] Not started
**Files**: New file `agents/shared/tools/role_mapper.py`

**Problem**: The agent picks IAM roles via LLM reasoning. Across runs it inconsistently chooses:
- `roles/storage.objectAdmin` (too broad — includes bucket-level perms)
- `roles/storage.objectUser` (correct — create + delete objects)
- `roles/storage.objectCreator` (too narrow — misses conditional delete)

We have the data to solve this deterministically. The IAM API `roles.get` returns `includedPermissions` for each role. We already call this in `agents/shared/tools/iam.py:_get_role_permissions()`.

**Fix**: Create `agents/shared/tools/role_mapper.py` with:

```python
def permissions_to_roles(
    required: set[str],
    conditional: set[str] | None = None,
) -> list[dict]:
    """Find the minimum set of predefined roles covering the required permissions.

    Algorithm:
    1. Load all predefined roles for the services involved
    2. For each role, compute coverage (how many required perms it grants)
    3. Greedy set cover: pick the role with most uncovered perms, repeat
    4. Return the minimal set with excess analysis

    Returns list of:
        {"role": "roles/storage.objectUser",
         "covers": ["storage.objects.create", "storage.objects.delete"],
         "excess": 12,
         "reason": "Covers storage.objects.create (main.py:62) and conditional storage.objects.delete"}
    """
```

**Key details**:
- Filter candidate roles to only predefined roles (prefix `roles/`) for the relevant services
- Use the IAM API to fetch permissions per role (with caching from `_get_role_permissions`)
- The greedy set cover is O(roles × perms) — fast enough for <100 candidate roles
- Include `excess` count so the agent can explain tradeoffs
- Handle conditional permissions: include them if a role already covers required perms + conditional comes free

**Wire into**:
- `agents/ide/tools.py:recommend_policy()` — call `permissions_to_roles()` and include results
- `agents/ide/agent.py` prompt — tell agent to use the deterministic role mapping, not guess

**Tests**: `tests/test_role_mapper.py` — test with known permission sets:
- `{storage.objects.create}` → `roles/storage.objectCreator`
- `{storage.objects.create, storage.objects.delete}` → `roles/storage.objectUser`
- `{bigquery.jobs.create, bigquery.tables.getData}` → `roles/bigquery.jobUser` + `roles/bigquery.dataViewer`

---

### P0-4: Add confirmation gate for mutating tools
**Status**: [ ] Not started
**Files**: `agents/ide/tools.py`, `agents/ide/agent.py`

**Problem**: `grant_iam_role`, `create_service_account`, and `enable_services` mutate real GCP state immediately. In the transcript, Turn 2 created a SA and granted 4 IAM roles without any confirmation from the developer. The prompt says "would you like me to grant these?" but the agent already did it in the same turn.

**Fix**: Split into plan + execute:

1. **`plan_iam_changes()`** — returns a plan dict with proposed actions:
   ```python
   def plan_iam_changes(
       paths: list[str],
       environment: str = "dev",
       workspace_root: str | None = None,
   ) -> str:
       """Generate a plan for IAM changes without executing them.

       Returns a plan with:
       - service_account_to_create (if needed)
       - roles_to_grant: [{role, member, reason}]
       - services_to_enable: [service_name]
       - guardrail_check results

       The developer reviews this plan, then calls execute_iam_plan() to apply.
       """
   ```

2. **`execute_iam_plan(plan_id: str)`** — executes a previously generated plan:
   ```python
   def execute_iam_plan(plan_id: str) -> str:
       """Execute a previously generated IAM plan.

       Looks up the plan by ID (stored in memory), creates SA, grants roles,
       enables services. Returns results for each action.
       """
   ```

3. **Store plans in memory** with a simple dict: `_pending_plans: dict[str, dict] = {}`

4. **Update agent prompt** to enforce the pattern:
   ```
   ## Mutating operations

   NEVER call grant_iam_role, create_service_account, or enable_services directly.
   Always use plan_iam_changes() first to generate a plan, present it to the developer,
   and wait for confirmation before calling execute_iam_plan().
   ```

5. **Keep the raw tools available** for the admin agent (which may auto-execute in batch mode).

---

### P0-5: Auto-update workspace config after SA creation
**Status**: [ ] Not started
**Files**: `agents/shared/workspace.py`, `agents/ide/tools.py`

**Problem**: Agent creates SA, grants roles, but `principal: null` stays null in `.iamspy/workspace.yaml`. Developer has to manually edit. Next conversation reads stale config.

**Fix**: Add `update_workspace_principal()` to `agents/shared/workspace.py`:

```python
def update_workspace_principal(
    workspace_root: str | Path,
    environment: str,
    identity_name: str,
    principal: str,
) -> None:
    """Update the principal for an identity in a specific environment.

    Reads .iamspy/workspace.yaml, updates the principal field,
    writes back. Preserves all other fields and comments.
    """
```

**Call it from** `agents/ide/tools.py:create_service_account()` — after creating the SA, update the workspace config:
```python
# After successful creation
from agents.shared.workspace import update_workspace_principal
sa_email = f"serviceAccount:{result['email']}"
update_workspace_principal(".", "dev", "app", sa_email)
```

**Implementation note**: Use `yaml.safe_load` + `yaml.dump` (we already do this). YAML comments will be lost — acceptable for now. Could use `ruamel.yaml` for comment preservation later.

**Tests**: Add to `tests/test_workspace.py`:
- Create config → update principal → reload → verify principal is set
- Update non-existent environment → error
- Update non-existent identity → error

---

## P1 — Should Fix

### P1-1: Add programmatic assertions to conversation evals
**Status**: [ ] Not started
**Files**: `evals/run_scenario_1_autocontext.py` and all `run_*.py` scripts

**Problem**: All 6 conversation eval scripts just print output. No assertions. No way to detect regressions.

**Fix**: After `runner.run_debug()`, parse the events and assert:

```python
events = await runner.run_debug(messages, ...)

# Parse tool calls from events
tool_calls = []
for event in events:
    if hasattr(event, 'actions') and event.actions:
        for action in event.actions.parts:
            if hasattr(action, 'function_call'):
                tool_calls.append({
                    "name": action.function_call.name,
                    "args": dict(action.function_call.args),
                })

# Assert expected tool calls
tool_names = [tc["name"] for tc in tool_calls]
assert "get_workspace_config" in tool_names, "Agent should check workspace config"
assert "scan_directory" not in tool_names, "Agent should NOT re-scan (auto-context)"

# Assert SA was created (check GCP state)
from agents.shared.gcp import list_service_accounts
sas = list_service_accounts("agentengine-478902")
sa_emails = [sa["email"] for sa in sas]
assert "acme-pipeline-auto@agentengine-478902.iam.gserviceaccount.com" in sa_emails

# Assert roles were granted
from agents.shared.tools.iam import _find_roles_for_principal
roles = _find_roles_for_principal("agentengine-478902",
    "serviceAccount:acme-pipeline-auto@agentengine-478902.iam.gserviceaccount.com")
assert "roles/bigquery.user" in roles or "roles/bigquery.jobUser" in roles
```

**Note**: The ADK `Event` API may differ — check `google.adk.events` for the actual structure. The key is to parse tool call names and arguments from the event stream.

---

### P1-2: Fix manifest paths to be relative
**Status**: [ ] Covered by P0-1 (same issue)

---

### P1-3: Unify error handling
**Status**: [ ] Not started
**Files**: `agents/shared/gcp.py`, `agents/shared/tools/*.py`, `agents/ide/tools.py`, `agents/admin/tools.py`

**Problem**: Four inconsistent error patterns:
1. Return `{"error": "message"}` dict — `agents/shared/gcp.py:_authed_request()`
2. Return `"ERROR: message"` string — `agents/admin/tools.py:download_gcs()`
3. Raise exception — `src/iamspy/scanner.py`
4. Return `None` silently — `agents/shared/workspace.py:load_workspace()`

Callers have to check `if "error" in result` AND `if result.startswith("ERROR:")` AND `if result is None`.

**Fix**: Standardize on one pattern for the tools layer:

```python
# agents/shared/errors.py
from dataclasses import dataclass

@dataclass(frozen=True)
class ToolError:
    message: str
    code: str = "unknown"  # e.g., "not_found", "permission_denied", "invalid_input"

class ToolResult:
    """Wrapper for tool return values."""

    @staticmethod
    def ok(data: dict) -> dict:
        return data

    @staticmethod
    def error(message: str, code: str = "unknown") -> dict:
        return {"error": message, "error_code": code}
```

Then all tools return either a dict with data or a dict with `"error"` key. No strings, no None, no exceptions crossing the tool boundary.

**Scope**: This is a refactor across ~15 tool functions. Do it incrementally — fix one file at a time, run tests after each.

---

### P1-4: Remove unused imports
**Status**: [ ] Not started

**Exact locations**:
- `agents/shared/tools/iam.py:13` — `import json` (no longer used after refactor, verify)
- `agents/shared/tools/iam.py:14` — `from pathlib import Path` (no longer used after refactor, verify)
- `agents/admin/tools.py:28` — `get_project` imported but never called
- `agents/admin/tools.py:29` — `test_iam_permissions` imported but never called

**Fix**: Remove the imports. Run `python -m pytest tests/ -q` to verify.

---

### P1-5: Connect guardrails.py and permission_rings.py
**Status**: [ ] Not started
**Files**: `agents/shared/guardrails.py`, `agents/shared/permission_rings.py`

**Problem**: Two separate classification systems:
- `guardrails.py` has hardcoded sets: `PRIVILEGE_ESCALATION_PERMISSIONS`, `DESTRUCTIVE_PERMISSIONS`, `EXFILTRATION_PERMISSIONS`
- `permission_rings.py` has a 4-ring classifier: CRITICAL, SENSITIVE, MUTATING, READ

They don't share data. The agent uses guardrails in conversation but never references ring numbers. The ring classifier was built, tested on 12,879 permissions, but never wired in.

**Fix**: Refactor `evaluate_guardrails()` to use the ring classifier as the source of truth:

```python
from agents.shared.permission_rings import classify, Ring

def evaluate_guardrails(permissions, ...):
    for perm in permissions:
        ring = classify(perm)
        if ring == Ring.CRITICAL:
            violations.append(Violation(severity=Severity.BLOCK, ...))
        elif ring == Ring.SENSITIVE:
            violations.append(Violation(severity=Severity.WARN, ...))
```

Delete the hardcoded permission sets from guardrails.py. Keep `DENIED_ROLES` (that's about roles, not permissions).

**Tests**: Update `tests/test_guardrails.py` — tests should still pass since the ring classifier covers all the same permissions (verify by checking that every permission in the old hardcoded sets maps to Ring.CRITICAL or Ring.SENSITIVE).

---

### P1-6: Fix `test_guardrails.py` import to use `agents.shared`
**Status**: [ ] Not started
**File**: `tests/test_guardrails.py`

**Problem**: Imports from `iamspy_mcp.shared.guardrails` which is the old module. Will break when P0-2 deletes `iamspy_mcp/`.

**Fix**:
```python
# Change:
from iamspy_mcp.shared.guardrails import ...
# To:
from agents.shared.guardrails import ...
```

**Must be done before or simultaneously with P0-2.**

---

## P2 — Nice to Have

### P2-1: Reduce double tree-sitter parsing
**Status**: [ ] Not started
**Files**: `src/iamspy/scanner.py`, `src/iamspy/credential_provenance.py`

**Problem**: `scan_source()` parses with tree-sitter, then `_annotate_credential_provenance()` calls `CredentialProvenanceAnalyzer().analyze()` which parses the same source again.

**Fix**: Pass the parsed tree from the scanner to the provenance analyzer. Change `CredentialProvenanceAnalyzer.analyze()` to accept an optional `tree` parameter:

```python
def analyze(self, source: str, filename: str = "<stdin>", tree=None) -> ProvenanceResult:
    src = source.encode("utf-8")
    if tree is None:
        tree = Parser(_LANGUAGE).parse(src)
    # ... rest of analysis uses the shared tree
```

Then in `scanner.py:scan_source()`:
```python
tree = self._parser.parse(src)
# ... existing scan ...
# Pass tree to provenance
prov = CredentialProvenanceAnalyzer().analyze(source, filename, tree=tree)
```

**Impact**: ~2x speedup on per-file analysis. Matters for large codebases.

---

### P2-2: Fix multi-identity string representation
**Status**: [ ] Not started
**Files**: `src/iamspy/scanner.py`, `src/iamspy/manifest.py`, `src/iamspy/models.py`

**Problem**: `identity_context` field is a comma-joined string: `"app,user"`. This means "ambiguous" but looks like "both." The manifest gets keys like `app,user:` which is valid YAML but confusing.

**Fix**: Change `identity_context` to a list in `Finding`:
```python
identity_context: list[str] = field(default_factory=list)
# ["app"] = definitely app
# ["app", "user"] = ambiguous, could be either
# [] = unknown
```

Update the scanner's `_annotate_credential_provenance` to build lists. Update the manifest builder to handle list keys (merge ambiguous identities into the dominant identity, or into "unattributed").

**Breaking change**: JSON output format changes. Update `_finding_to_dict()` in `cli.py` and `agents/shared/tools/scan.py`.

---

### P2-3: Refactor functions exceeding 40 lines
**Status**: [ ] Not started

**By file**:

`agents/shared/guardrails.py:evaluate_guardrails()` — 142 lines → split into:
- `_check_denied_permissions(permissions, policy)`
- `_check_denied_patterns(permissions, policy)`
- `_check_denied_roles(roles, policy)`
- `_check_permission_count(permissions, policy)`
- `_check_identity_constraints(identity_type, policy)`
- `_check_exfiltration_risk(permissions)`
- `_check_service_boundaries(permissions, policy)`

`agents/ide/tools.py:recommend_policy()` — 116 lines → split into:
- `_load_env_from_workspace(environment, workspace_root)`
- `_build_identity_recommendations(env, scan_result)`
- `_check_guardrails_for_env(env, permissions)`

`src/iamspy/credential_provenance.py:CredentialProvenanceAnalyzer` — 315 lines → extract:
- `_CredentialSourceDetector` — finds where credentials are created
- `_ClientBindingResolver` — binds clients to credential sources
- `_OAuthScopeExtractor` — finds OAuth scope definitions

`agents/ide/agent.py:_build_instruction()` — 132 lines. This is a prompt string, not logic. Consider moving to a separate `.txt` or `.md` file loaded at runtime, or at minimum extract into `_build_tool_docs()`, `_build_response_rules()`, `_build_workflow_rules()`.

---

### P2-4: Add negative eval scenarios
**Status**: [ ] Not started
**Files**: New scenarios in `evals/`

Missing scenarios that should exist:
1. **Dangerous code**: App with `setIamPolicy` → guardrails should block deployment
2. **Over-permissioned principal**: Agent has `roles/editor` → should flag and recommend replacement
3. **Deny policy conflict**: Required permission blocked by org deny policy → should surface
4. **Invalid workspace config**: Malformed YAML, missing project, invalid identity type → should handle gracefully
5. **Empty project**: No Python files → should say "nothing to scan"

---

### P2-5: Eval scenario.yaml workflows are defined but not executed
**Status**: [ ] Not started
**Files**: `evals/run_evals.py`, `evals/*/scenario.yaml`

**Problem**: Each scenario.yaml defines `workflows` with `assertions` but `run_evals.py` ignores them entirely. It only compares manifest permissions.

**Fix**: Add an assertion executor to `run_evals.py`:

```python
ASSERTION_CHECKS = {
    "all_required_permissions_found": lambda checks: all(
        len(c.get("missing", [])) == 0 for c in checks if c["check"].startswith("permissions_")
    ),
    "no_guardrail_blocks": lambda checks: all(
        c.get("ring_0_actual", 0) == 0 for c in checks if c["check"] == "guardrails"
    ),
    "kms_usage_flagged_as_sensitive": lambda result: any(
        "cloudkms" in p for p in result.get("permissions", [])
    ),
    # ... etc
}
```

---

### P2-6: Thread safety for global singletons
**Status**: [ ] Not started
**Files**: `agents/shared/tools/scan.py`, `agents/shared/tools/iam.py`

**Problem**: `_scanner`, `_registry`, `_role_permissions_cache` are module-level mutable globals without locks. The role permissions cache grows unboundedly.

**Fix**: Use `@functools.lru_cache` for the scanner/registry (immutable after creation). For the role permissions cache, add a max size or use `@lru_cache` on `_get_role_permissions()`:

```python
@functools.lru_cache(maxsize=256)
def _get_role_permissions(role: str) -> tuple[str, ...]:
    """Cached role → permissions lookup. Returns tuple for hashability."""
    ...
```

---

### P2-7: `build()` client binding false positives
**Status**: [ ] Not started
**Files**: `src/iamspy/credential_provenance.py`

**Problem**: `_is_gcp_client_constructor()` returns `"build"` for `googleapiclient.discovery.build()`. This is correct for detecting OAuth identity, but produces phantom client bindings for Workspace API services that have no IAM permissions.

**Fix**: When `client_class == "build"`, don't treat it as a GCP client for permission purposes. Only use it for identity resolution. Add a flag:

```python
@dataclass(frozen=True)
class ClientBinding:
    ...
    is_workspace_api: bool = False  # True for build() — identity-only, no IAM permissions
```

Set `is_workspace_api=True` when `client_class == "build"`. The manifest builder skips workspace API clients when aggregating permissions but uses them for identity context.

---

## Tracking

| ID | Priority | Status | Description |
|---|---|---|---|
| P0-1 | P0 | [ ] | Fix manifest absolute paths → relative |
| P0-2 | P0 | [ ] | Delete old directories, fix all imports |
| P0-3 | P0 | [ ] | Build deterministic `permissions_to_roles()` |
| P0-4 | P0 | [ ] | Add confirmation gate for mutating tools |
| P0-5 | P0 | [ ] | Auto-update workspace config after SA creation |
| P1-1 | P1 | [ ] | Add programmatic assertions to conversation evals |
| P1-2 | P1 | [ ] | (Covered by P0-1) |
| P1-3 | P1 | [ ] | Unify error handling across tools layer |
| P1-4 | P1 | [ ] | Remove unused imports |
| P1-5 | P1 | [ ] | Connect guardrails.py and permission_rings.py |
| P1-6 | P1 | [ ] | Fix test_guardrails.py import to use agents.shared |
| P2-1 | P2 | [ ] | Reduce double tree-sitter parsing |
| P2-2 | P2 | [ ] | Fix multi-identity string representation |
| P2-3 | P2 | [ ] | Refactor functions exceeding 40 lines |
| P2-4 | P2 | [ ] | Add negative eval scenarios |
| P2-5 | P2 | [ ] | Execute scenario.yaml workflow assertions |
| P2-6 | P2 | [ ] | Thread safety for global singletons |
| P2-7 | P2 | [ ] | build() client binding false positives |
