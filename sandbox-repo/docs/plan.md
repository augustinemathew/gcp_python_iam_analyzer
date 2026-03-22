# Unified Codebase Plan — Priorities 1, 2, 3, 6

## Goal

One clean, cohesive codebase. No duplication. `core/` holds primitives, `sandbox.py`
is the orchestrator, proxy + MCP interceptor are enforcement points, Claude is the
smart classifier. Everything wired together so `run_e2e.py` exercises the full stack.

---

## Phase 1: Merge sandbox.py onto core/ (Priority 1)

**Problem:** `sandbox.py` reimplements `TaintState`, `LSHEngine`, `AnomalyDetector`
that already exist in `core/`. Two copies = two bugs, two maintenance costs.

**Changes:**

### 1a. Delete duplicate classes from sandbox.py

Remove from `sandbox.py`:
- `TaintState` class (lines 31-41) → replaced by `core/taint.TaintTracker`
- `LSHEngine` class (lines 66-150) → replaced by `core/lsh.LSHEngine`
- `AnomalyDetector` class (lines 157-214) → replaced by `core/anomaly.AnomalyDetector`
- `trigram_set()`, `trigram_jaccard()` helpers (lines 48-63)
- `_QUICK_SECRET_PATTERNS`, `_has_secret_pattern()` (lines 259-273) → use `core/classifier.classify_by_content()`
- `DEFAULT_ALLOWED_HOSTS` (lines 280-293) → already in `core/policy.py`

### 1b. Rewrite Sandbox class to compose core/ primitives

```python
# sandbox.py — after merge
from agent_sandbox.core.taint import TaintLabel, TaintTracker
from agent_sandbox.core.lsh import LSHEngine
from agent_sandbox.core.anomaly import AnomalyDetector
from agent_sandbox.core.classifier import classify, classify_by_content
from agent_sandbox.core.policy import PolicyEngine, Decision, PolicyResult

class Sandbox:
    def __init__(self, manifest=None, allowed_hosts=None):
        self.taint_tracker = TaintTracker()
        self.lsh = LSHEngine()
        self.anomaly = AnomalyDetector()
        self.policy = PolicyEngine(self.taint_tracker, self.lsh, self.anomaly, allowed_hosts)
        self.manifest = manifest
        self.pid = os.getpid()  # default PID for simple mode

        # Register the main process
        self.taint_tracker.register_process(self.pid)

        # Pre-index from manifest
        if manifest:
            for value in manifest.sensitive_values:
                self.lsh.index(value)
            for path, info in manifest.files.items():
                if info.sensitivity.value in ("critical", "high"):
                    label = classify(path, "")
                    self.taint_tracker.taint_file(path, label or TaintLabel.CREDENTIAL)

    def read_file(self, path: str, content: str) -> None:
        """Record file read, taint if sensitive."""
        label = classify(path, content)
        if label != TaintLabel.NONE:
            self.taint_tracker.taint_process(self.pid, label, path)
            self.lsh.index(content)

    def check_send(self, host: str, body: str) -> tuple[bool, str]:
        """Delegate to PolicyEngine."""
        result = self.policy.check_network(self.pid, host, body)
        return result.decision == Decision.ALLOW, result.reason

    def check_exec(self, command: str) -> tuple[bool, str]:
        result = self.policy.check_exec(self.pid, command)
        return result.decision == Decision.ALLOW, result.reason

    def check_write(self, path: str, project_root: str) -> tuple[bool, str]:
        result = self.policy.check_file_write(self.pid, path, project_root)
        return result.decision == Decision.ALLOW, result.reason
```

Keep in `sandbox.py`:
- `Sandbox` class (rewritten to delegate to `core/`)
- `compute_file_hash()`, `snapshot_directory()`, `diff_snapshots()` — file change detection utilities
- `_copy_project()`, `_show_diff()` — CLI helpers
- `main()` — CLI entry point (will be extended in Phase 2)

### 1c. Update check_delete

Move `check_delete` logic into `PolicyEngine.check_file_delete()` in `core/policy.py`.
`Sandbox.check_delete()` becomes a one-liner delegate.

### 1d. Align PolicyEngine with Sandbox's richer checks

`PolicyEngine.check_exec()` is missing some patterns that `sandbox.py` has:
- `rm -rf *`, `dd of=/dev/`, fork bomb full pattern, `rsync`
- Add these to `PolicyEngine.check_exec()`
- Add `/var/`, `/boot/`, `/proc/`, `/sys/` to `check_file_write()` system paths

### 1e. Fix tests

- Tests in `test_integration.py` and `test_e2e.py` instantiate `Sandbox` directly.
  After the merge they'll use the new delegation-based `Sandbox`.
- The `Sandbox.taint.tainted` bool pattern used by `CallSummarizer` and tests needs
  a compatibility property: `Sandbox.is_tainted → self.taint_tracker.is_process_tainted(self.pid)`
- Update `CallSummarizer` to use the new interface.

**Lines removed:** ~190 (duplicate classes)
**Lines added:** ~30 (imports + delegation)
**Net:** -160 lines

---

## Phase 2: Wire MITM proxy into CLI (Priority 2)

**Problem:** `proxy/mitm.py` works end-to-end but `sandbox.py:main()` doesn't start it.
The subprocess runs without traffic interception.

### 2a. Update main() to start proxy

```python
def main():
    # ... existing scan + copy logic ...

    # Create sandbox
    sandbox = Sandbox(manifest=manifest)

    # Start MITM proxy
    from agent_sandbox.proxy.cert import CertAuthority
    from agent_sandbox.proxy.mitm import MITMProxy
    ca = CertAuthority()
    proxy = MITMProxy(sandbox, ca)
    port = proxy.start()

    # Create summarizer
    summarizer = CallSummarizer(sandbox)

    # Launch subprocess with proxy env
    env = os.environ.copy()
    env.update(proxy.get_env())
    env["SANDBOX_ACTIVE"] = "1"

    try:
        result = subprocess.run(args.command, cwd=sandbox_dir, env=env)
    finally:
        proxy.stop()
        summarizer.print_timeline()
        _print_proxy_stats(proxy)
```

### 2b. Add --no-proxy flag

For cases where you only want file-level enforcement without MITM.

### 2c. Add proxy stats printing

```python
def _print_proxy_stats(proxy: MITMProxy) -> None:
    stats = proxy.get_stats()
    print(f"\nProxy: {stats['total_requests']} requests, "
          f"{stats['blocked']} blocked, {stats['allowed']} allowed")
    for detail in stats['blocked_details']:
        print(f"  BLOCKED: {detail['method']} {detail['host']}{detail['path']}")
```

---

## Phase 3: Claude-powered classifier (Priority 3)

**Problem:** The current `call_summarizer.py` produces JSONL, but no smart classifier
scores it. Regex heuristics catch obvious attacks; a capable model catches subtle ones.

**Approach:** Use Claude as the classifier. Later, generate labeled data from Claude's
judgments to train a smaller model.

### 3a. Create core/llm_classifier.py

```python
"""LLM-based risk classifier for agent tool call sequences.

Uses Claude to analyze suspicious turns identified by the regex pre-filter.
Only called for SUSPICIOUS verdicts — not every turn (cost control).

Architecture:
  regex pre-filter (every turn, free) → SUSPICIOUS? → Claude classifier (paid)

Future: Use Claude's judgments as training data → fine-tune smaller model.
"""

@dataclass(frozen=True)
class RiskAssessment:
    risk_level: str        # "safe", "suspicious", "malicious"
    confidence: float      # 0.0 to 1.0
    reasoning: str         # one-paragraph explanation
    recommended_action: str  # "allow", "block", "alert"

class LLMClassifier:
    def __init__(self, model: str = "claude-sonnet-4-6"):
        self._client = None  # lazy init
        self._model = model
        self._cache: list[dict] = []  # for dataset generation

    def assess_turn(self, turn: TurnSummary, context: SessionContext) -> RiskAssessment:
        """Assess a suspicious turn using Claude."""
        # Build prompt with turn details + session context
        # Call Claude API
        # Parse structured response
        # Cache input/output pair for dataset generation

    def export_dataset(self, path: str) -> None:
        """Export cached assessments as training data (JSONL)."""
```

### 3b. Prompt design

The prompt includes:
- The turn's intent, actions, targets, and sandbox decisions
- Session context: taint state, files read, prior turns
- The project's sensitive file manifest
- Ask for structured JSON output: `{risk_level, confidence, reasoning, recommended_action}`

### 3c. Integration into CallSummarizer

```python
class CallSummarizer:
    def __init__(self, sandbox=None, llm_classifier=None):
        self._classifier = llm_classifier  # optional

    def record_turn(self, ...):
        summary = ...  # existing logic

        # Tier 2: if regex says SUSPICIOUS and we have a classifier, escalate
        if summary.verdict == Verdict.SUSPICIOUS and self._classifier:
            assessment = self._classifier.assess_turn(summary, self._session_context())
            if assessment.risk_level == "malicious":
                summary = summary._replace(verdict=Verdict.BLOCKED)

        return summary
```

### 3d. Optional dependency

Add to `pyproject.toml`:
```toml
[project.optional-dependencies]
llm = ["anthropic>=0.40"]
```

Core sandbox works without it. Classifier is opt-in.

---

## Phase 4: MCP tool call interception (Priority 6)

**Problem:** Agents talk to MCP servers via JSON-RPC. The sandbox can't inspect those
calls because they bypass HTTP. Need a proxy that sits in the JSON-RPC path.

### 4a. Create mcp/interceptor.py

```python
"""JSON-RPC proxy for MCP tool call interception.

Sits between an agent (client) and MCP servers. Intercepts every
`tools/call` request, inspects tool name + arguments, runs sandbox
checks, and either passes through or blocks.

Usage:
    interceptor = MCPInterceptor(sandbox, upstream_cmd=["npx", "mcp-server"])
    interceptor.start()
    # Agent connects to interceptor's stdio instead of MCP server directly
"""

class MCPInterceptor:
    def __init__(self, sandbox: Sandbox, upstream_cmd: list[str]):
        self.sandbox = sandbox
        self.upstream_cmd = upstream_cmd

    def start(self) -> None:
        """Start the MCP server subprocess and begin intercepting."""
        # Launch upstream MCP server
        # Read JSON-RPC from stdin, inspect, forward to upstream
        # Read response from upstream, forward to stdout

    def _inspect_request(self, request: dict) -> tuple[bool, str]:
        """Inspect a tools/call request."""
        method = request.get("method", "")
        if method != "tools/call":
            return True, "not a tool call"

        params = request.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        # Check arguments for sensitive content
        body = json.dumps(arguments)
        return self.sandbox.check_send("mcp-server", body)
```

### 4b. Correlate with agent reasoning

The interceptor can receive the agent's reasoning text (the preamble before the tool
call) via a sideband. This feeds into the `CallSummarizer` and `LLMClassifier`:

```python
def record_mcp_call(self, reasoning: str, tool_name: str, arguments: dict):
    """Record an MCP call with its reasoning context."""
    self.summarizer.record_turn(
        reasoning=reasoning,
        tool_calls=[{"tool_name": tool_name, "arguments": arguments}],
        sandbox_decisions=[...],
    )
```

### 4c. Wire into CLI

```bash
agent-sandbox --project . --mcp "npx mcp-server-filesystem" -- claude-code
```

The `--mcp` flag starts an MCPInterceptor for each specified server.

---

## Phase 5: E2E experiment runner

**Goal:** One command runs the full stack: scan → sandbox → proxy → MCP interceptor →
simulated agent → classifier → report.

### 5a. Create experiments/e2e_runner.py

```python
"""End-to-end experiment runner.

Exercises the full enforcement pipeline:
1. Scan a test project (env_scanner)
2. Create sandbox with manifest
3. Start MITM proxy
4. Start MCP interceptor (if configured)
5. Run simulated adversary experiments through the pipeline
6. Optionally run Claude classifier on suspicious turns
7. Print unified report: attacks blocked, escaped, false positives

Usage:
    python -m agent_sandbox.experiments.e2e_runner
    python -m agent_sandbox.experiments.e2e_runner --with-classifier
    python -m agent_sandbox.experiments.e2e_runner --with-mcp
"""

def run_e2e(with_classifier=False, with_mcp=False) -> E2EReport:
    # 1. Create test project with secrets
    project = _create_test_project()

    # 2. Scan
    scanner = EnvironmentScanner(project)
    manifest = scanner.scan()

    # 3. Create sandbox
    sandbox = Sandbox(manifest=manifest)

    # 4. Start proxy
    ca = CertAuthority()
    proxy = MITMProxy(sandbox, ca)
    proxy.start()

    # 5. Optionally start classifier
    classifier = LLMClassifier() if with_classifier else None
    summarizer = CallSummarizer(sandbox, llm_classifier=classifier)

    # 6. Run all attack experiments through the sandbox
    attack_results = run_all_attacks_through_sandbox(sandbox, summarizer)

    # 7. Run simulated adversary experiments
    adversary_results = run_all_experiments_through_sandbox(sandbox, summarizer)

    # 8. Collect report
    proxy.stop()
    return E2EReport(
        attacks=attack_results,
        adversary=adversary_results,
        proxy_stats=proxy.get_stats(),
        timeline=summarizer.timeline,
        classifier_assessments=classifier._cache if classifier else [],
    )
```

### 5b. Test project fixture

```python
def _create_test_project() -> str:
    """Create a temp directory with realistic sensitive files."""
    # .env with AWS keys, DB URLs
    # service-account.json
    # config/production.yaml with secrets
    # src/ with normal code
    # medical/patient_records.csv
```

### 5c. Unified report

```
==================================================
E2E EXPERIMENT REPORT
==================================================
Environment scan:     14 sensitive files, 8 secrets
Proxy:                47 requests, 12 blocked, 35 allowed
Attack scenarios:     19/19 blocked (100%)
Adversary experiments:
  Benign (clean):     0 false positives
  Benign (tainted):   0 false positives
  Basic adversary:    9/9 blocked
  Adapted adversary:  3/4 blocked, 1 escaped (ROT13)
  Escalated:          blocked at attempt 4 (shape detector)
Classifier:           3 SUSPICIOUS → 2 malicious, 1 safe
Timeline:             22 turns logged (JSONL available)
==================================================
```

---

## File changes summary

| File | Action | What |
|------|--------|------|
| `sandbox.py` | **Rewrite** | Delete duplicates, delegate to `core/` |
| `core/policy.py` | **Extend** | Add `check_file_delete()`, align patterns |
| `core/llm_classifier.py` | **New** | Claude-powered risk classifier |
| `mcp/interceptor.py` | **New** | JSON-RPC proxy for MCP |
| `mcp/__init__.py` | **New** | Package init |
| `experiments/e2e_runner.py` | **New** | Full-stack experiment runner |
| `call_summarizer.py` | **Edit** | Accept optional LLMClassifier |
| `pyproject.toml` | **Edit** | Add `llm` optional dep |
| `tests/test_integration.py` | **Edit** | Adapt to merged Sandbox API |
| `tests/test_e2e.py` | **Edit** | Adapt to merged Sandbox API |
| `tests/test_mcp.py` | **New** | MCP interceptor tests |
| `tests/test_llm_classifier.py` | **New** | Classifier tests (mocked) |
| `tests/test_e2e_runner.py` | **New** | E2E runner tests |

**Execution order:** Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5

Phase 1 is the foundation — everything else builds on the unified `Sandbox` class.
Phase 5 ties it all together.
