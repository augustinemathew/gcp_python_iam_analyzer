# Overwatch: Adaptive Behavioral Anomaly Detection

Overwatch is a preemptive security layer for sandboxed AI agents. It intercepts
every security-sensitive syscall from a gVisor container and evaluates it against
a learned behavioral baseline *before* the syscall proceeds. Two tiers:

- **L1** — fast statistical check (~0.1ms): six deviation signals scored against
  an EMA baseline. Below threshold = ALLOW, above = escalate.
- **L2** — LLM agent (Claude): reasons about the flagged operation with full
  context (baseline summary, recent ops, taint state, similar past decisions).
  Returns ALLOW, BLOCK, or DEFER (pause container and ask the user).

User feedback refines both tiers across sessions.

## How It Works

```
Agent Process (inside gVisor container)
    |
    | syscall (open, connect, execve, ...)
    v
gVisor Sentry --seccheck--> OverwatchSink (Go, in-kernel)
                                |
                          SOCK_SEQPACKET Unix socket
                                |
                                v
                       OverwatchServer (Python, on host)
                                |
                    +-----------+-----------+
                    |                       |
              L1 Baseline              L2 LLM Agent
              (EMA, ~0.1ms)            (Claude, ~500ms)
                    |                       |
              score < 0.45           ALLOW / BLOCK / DEFER
                = ALLOW                     |
                    |                 +-----+-----+
                    |              ALLOW  BLOCK  DEFER
                    |                |     |      |
                    |                |     |   docker pause
                    |                |     |   user prompt
                    |                |     |   docker unpause
                    |                |     |      |
                    +---------------> baseline + memory update
```

1. **gVisor Sentry** intercepts every syscall in its userspace kernel. The
   seccheck framework serializes security-sensitive syscalls (open, connect,
   execve, etc.) to protobuf and dispatches them to registered sinks.

2. **OverwatchSink** (Go, compiled into the Sentry) sends each event over a
   `SOCK_SEQPACKET` Unix socket to the host and blocks until it reads back a
   verdict. Lifecycle events (container start, clone, exit) are fire-and-forget
   to avoid blocking the boot path.

3. **OverwatchServer** (Python, on the host) receives events and runs them
   through the L1/L2 pipeline. L1 scores the operation. If above threshold,
   L2 analyzes with Claude. DEFER freezes the container via `docker pause`.

4. **Memory** persists user decisions and baseline snapshots across sessions.
   Features are extracted from user explanations ("Python files are safe" ->
   `file_extension:.py`). Baselines carry over to avoid cold-start false
   positives.

## Building & Running End-to-End

There are three layers to build: the gVisor fork (Go/Bazel), the agent sandbox
(Python), and optionally the E2E test image (Docker-in-Docker). Each layer can
be built and tested independently.

### Prerequisites

- Docker Desktop (macOS) or Docker Engine (Linux)
- Python 3.12+ with pip
- For gVisor build: Docker with `--platform linux/arm64` support (Docker Desktop
  has this by default on Apple Silicon)

```bash
# macOS
brew install --cask docker
open -a Docker
```

### Step 1: Build the gVisor fork (`runsc-overwatch`)

The fork adds a single seccheck sink (`overwatch`) to gVisor. The build runs
inside a Docker container (Ubuntu 22.04 + Bazel) since gVisor only builds on
Linux.

```bash
cd agent_sandbox/gvisor-overwatch

# Build runsc with the Overwatch sink compiled in (~10-15 min first time,
# Bazel caches subsequent builds)
docker build --platform linux/arm64 \
  -f Dockerfile.build \
  -t gvisor-overwatch-build .

# Extract the statically-linked runsc binary
container_id=$(docker create gvisor-overwatch-build)
docker cp "$container_id:/build/bazel-bin/runsc/runsc_/runsc" ./runsc-overwatch
docker rm "$container_id"

# Verify it built correctly
file ./runsc-overwatch
# => ELF 64-bit LSB executable, ARM aarch64, statically linked
```

A pre-built `runsc-overwatch` binary (arm64) is included in the repo for
convenience. Rebuild from source if you need x86_64 or want to modify the sink.

### Step 2: Install the gVisor runtime

Register `runsc-overwatch` as a Docker runtime so containers can use it.

```bash
# Copy the binary
sudo cp agent_sandbox/gvisor-overwatch/runsc-overwatch /usr/local/bin/runsc
sudo chmod +x /usr/local/bin/runsc

# Register as a Docker runtime
# Add to /etc/docker/daemon.json (create if it doesn't exist):
cat <<'EOF' | sudo tee /etc/docker/daemon.json
{
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc"
    },
    "runsc-overwatch": {
      "path": "/usr/local/bin/runsc"
    }
  }
}
EOF

# Restart Docker to pick up the new runtime
sudo systemctl restart docker   # Linux
# or: restart Docker Desktop     # macOS

# Verify
docker info | grep -i runsc
# => runsc runsc-overwatch
```

### Step 3: Install the Python package

```bash
# From the repo root
pip install -e ".[dev]"

# Or just the agent_sandbox deps
pip install celpy pyyaml anthropic
```

### Step 4: Build an agent container image

The sandbox runs agents inside Docker containers. You need an image with your
agent's runtime (Python, Node, etc.).

```bash
# Example: Python agent image with common packages
cat > Dockerfile.agent <<'EOF'
FROM python:3.12-slim
RUN pip install requests anthropic openai
EOF

docker build -t gvisor-python:latest -f Dockerfile.agent .
```

### Step 5: Write a policy

```yaml
# policy.yaml
version: "1"
name: my-agent

defaults:
  file: deny
  network: deny

file:
  read:
    - "/workspace/**"
    - "/tmp/**"
  write:
    - "/tmp/out/**"
  execute:
    - "/usr/bin/python3*"
    - "/usr/local/bin/python3*"
  deny:
    - "/workspace/.env"
    - "/workspace/**/.git/**"

network:
  allow:
    - host: api.anthropic.com
      port: 443
      http:
        methods: [POST]
        paths: ["/v1/messages"]
    - host: "*.googleapis.com"
      port: 443
  deny:
    - host: "169.254.169.254"   # block IMDS
```

### Step 6: Run an agent with Overwatch

```bash
# Basic: run agent.py with policy enforcement + Overwatch anomaly detection
agent-sandbox -p policy.yaml --overwatch \
  --app-description "Code review agent that reads source files and calls Claude" \
  -w ./src \
  -o ./results \
  -- python3 /workspace/agent.py

# Without Overwatch (policy enforcement only — no L1/L2 scoring)
agent-sandbox -p policy.yaml \
  -w ./src -o ./results \
  -- python3 /workspace/agent.py

# Inspect the compiled config without running anything
agent-sandbox -p policy.yaml --describe

# Dry run: print the docker command that would be executed
agent-sandbox -p policy.yaml --dry-run -- python3 agent.py
```

What happens at runtime:
1. `agent-sandbox` loads the policy and compiles it into Docker run arguments
2. If `--overwatch`: starts the Overwatch server on a Unix socket
3. Launches a gVisor container with `--runtime=runsc`:
   - Filesystem: read-only container + tmpfs for writable paths
   - Network L3/L4: iptables rules in gVisor Netstack
   - Network L7: Envoy sidecar with Lua filter (if HTTP/MCP rules exist)
   - Privilege separation: Envoy starts as root, agent drops to uid 65534
4. If `--overwatch`: the gVisor seccheck session routes syscall events to the
   Overwatch server via Unix socket for L1/L2 evaluation
5. Agent runs, stdout/stderr are captured and returned

### Step 7 (optional): Run the E2E test

The E2E test validates the full stack: gVisor + seccheck sink + wire protocol +
policy server. It uses Docker-in-Docker so a gVisor container runs *inside*
another container.

```bash
cd agent_sandbox/gvisor-overwatch

# Build the E2E test image (includes runsc-overwatch + Python policy server)
docker build --platform linux/arm64 \
  -f e2e/Dockerfile.e2e \
  -t overwatch-e2e .

# Run the full E2E test
docker run --rm --privileged --platform linux/arm64 \
  overwatch-e2e python3 /opt/overwatch/e2e_test.py
```

The E2E test:
1. Starts dockerd inside the container (Docker-in-Docker)
2. Registers `runsc-overwatch` as a Docker runtime
3. Starts the Overwatch policy server on a Unix socket
4. Pulls `alpine:latest` and runs it under gVisor
5. Runs three test cases:
   - `echo hello` — should succeed (ALLOW)
   - `cat /etc/hostname` — should succeed (ALLOW)
   - `cat /etc/shadow` — should fail (BLOCK)
6. Collects the event log and verifies correct verdicts

You can also run the E2E interactively to see the syscall stream:

```bash
docker run --rm -it --privileged --platform linux/arm64 \
  overwatch-e2e sh -c '
    # Start Docker-in-Docker
    dockerd &>/dev/null &
    for i in $(seq 1 30); do docker info &>/dev/null && break; sleep 1; done

    # Start the Overwatch policy server
    mkdir -p /run/overwatch
    python3 /opt/overwatch/overwatch_server.py /run/overwatch/policy.sock &
    sleep 1

    # Configure runsc-overwatch as a Docker runtime
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json <<EOF
    {"runtimes":{"runsc-overwatch":{"path":"/usr/local/bin/runsc","runtimeArgs":["--ignore-cgroups","--pod-init-config=/opt/overwatch/session.json"]}}}
EOF
    kill $(pidof dockerd); sleep 2; dockerd &>/dev/null &
    for i in $(seq 1 30); do docker info 2>/dev/null | grep -q runsc && break; sleep 1; done
    docker pull alpine:latest &>/dev/null

    # Run a container — watch syscalls stream in real time
    docker run --rm --runtime=runsc-overwatch \
      -v /run/overwatch/policy.sock:/run/overwatch/policy.sock \
      alpine:latest sh -c "echo hello && ls /tmp && cat /etc/hostname"
  '
```

### Running the Go tests (wire protocol)

The overwatch sink has unit tests for the wire protocol (marshal/unmarshal
roundtrips, byte layout compatibility with the Python server). These run inside
the gVisor Bazel build system:

```bash
cd agent_sandbox/gvisor-overwatch

# Run the overwatch wire protocol tests
bazel test //pkg/sentry/seccheck/sinks/overwatch:overwatch_test

# Or build and run via Docker if you don't have Bazel locally
docker run --rm --platform linux/arm64 \
  -v "$(pwd):/build" -w /build \
  gvisor-overwatch-build \
  bazel test //pkg/sentry/seccheck/sinks/overwatch:overwatch_test
```

The tests verify:
- Request header roundtrip (marshal -> read back individual fields)
- Response roundtrip (MarshalResponse -> UnmarshalResponse)
- Padding bytes are zeroed (prevents info leaks)
- Exact byte layout matches the Python server's `struct.pack` format
- Size and action constants are stable

### Running the Python tests (no Docker required)

The unit tests for the Overwatch Python modules run without Docker or gVisor:

```bash
# All sandbox + overwatch tests
pytest tests/sandbox/ -v

# Just the overwatch tests
pytest tests/sandbox/test_overwatch.py -v

# gVisor config generation tests (unit tests pass, E2E tests skip without Docker)
pytest tests/test_gvisor.py -v
```

## gVisor Fork (`agent_sandbox/gvisor-overwatch/`)

The fork adds a single new seccheck sink to gVisor. The rest of the gVisor
codebase is unmodified.

### Custom files

```
agent_sandbox/gvisor-overwatch/
  pkg/sentry/seccheck/sinks/overwatch/
    overwatch.go   # Seccheck sink — sends events, reads verdicts
    wire.go        # Binary wire protocol (request/response headers)
    BUILD          # Bazel build target
  e2e/
    Dockerfile.e2e       # Docker-in-Docker test image
    overwatch_server.py  # Standalone policy server for testing
    e2e_test.py          # Full E2E test script
    session.json         # Seccheck session configuration
  Dockerfile.build       # Linux build container for runsc
  runsc-overwatch        # Pre-built binary (arm64, statically linked)
```

### Wire protocol

The sink communicates with the host over a `SOCK_SEQPACKET` Unix socket using a
simple binary protocol:

**Request** (sink -> host): 12-byte header + protobuf payload

```
 0          16          32          64          96
 | HeaderSize | MsgType  | DroppedCnt | RequestID |  protobuf...
 +---- 16 ---+--- 16 ---+---- 32 ---+---- 32 ---+
```

**Response** (host -> sink): 8 bytes

```
 0          32    40          64
 | RequestID | Act |  Padding  |
 +---- 32 --+- 8 -+--- 24 ---+
```

Actions: `0` = ALLOW, `1` = BLOCK, `2` = DEFER.

### Handshake

On connection, the sink sends a protobuf `Handshake{Version: N}` message. The
host echoes it back. If the version is too old, the connection is rejected.

### Sink behavior

| Event | Seccheck point | Behavior |
|-------|---------------|----------|
| Container start | `container/start` | notify (non-blocking, marks boot complete) |
| Process clone | `sentry/clone` | notify |
| Process exec | `sentry/execve` | notify |
| Task exit | `sentry/task_exit` | notify |
| File open | `syscall/openat/enter` | notify (blocking enforcement planned) |
| Network connect | `syscall/connect/enter` | notify |
| Process execve | `syscall/execve/enter` | notify |
| Socket create | `syscall/socket/enter` | notify |
| Socket bind | `syscall/bind/enter` | notify |

Lifecycle events (clone, exec, exit) use `notify()` which sends the event and
reads the response but always returns nil — they cannot block. Syscall events
also use `notify()` currently. Full blocking enforcement (returning EPERM to
reject the syscall) requires tuning gVisor's URPC timeout and will be enabled
in a future iteration.

On timeout or socket error, the sink falls back to a configurable default
(`default_on_timeout: "allow"` or `"block"` in the session config).

### Session configuration (`session.json`)

```json
{
  "trace_session": {
    "name": "overwatch",
    "points": [
      {"name": "syscall/openat/enter", "context_fields": ["container_id", "credentials", "cwd"]},
      {"name": "syscall/connect/enter", "context_fields": ["container_id", "credentials"]},
      {"name": "syscall/execve/enter", "context_fields": ["container_id", "credentials", "cwd"]}
    ],
    "sinks": [{
      "name": "overwatch",
      "config": {
        "endpoint": "/run/overwatch/policy.sock",
        "timeout": "5s",
        "default_on_timeout": "allow"
      }
    }]
  }
}
```

## Python Modules (`agent_sandbox/overwatch/`)

### Core pipeline

| Module | Purpose |
|--------|---------|
| `__init__.py` | `OverwatchEngine` — orchestrates L1/L2 pipeline, taint, memory |
| `_types.py` | Frozen dataclasses: `Operation`, `L1Result`, `L2Verdict`, `MemoryRecord`, enums |
| `_features.py` | Extract comparable features from ops (file ext, host, tool name, etc.) |
| `_baseline.py` | EMA-based statistical baseline with warmup, bigram tracking, snapshots |
| `_scorer.py` | Six deviation signals -> weighted composite anomaly score |
| `_analyzer.py` | L2 LLM agent — builds prompt with context, calls Claude, parses verdict |
| `_server.py` | Unix socket server bridging seccheck events to the Python pipeline |

### Security layers

| Module | Purpose |
|--------|---------|
| `_taint.py` | Information flow tracking with labels (CREDENTIAL, PII, FINANCIAL, MEDICAL). Monotonic and transitive: once tainted, always tainted. Propagates via file reads and process forks. |
| `_lsh.py` | Locality-sensitive hashing for content matching. Detects secrets after transformation (base64, hex, URL encoding) via trigram bloom filter -> MinHash LSH -> detailed scoring. |
| `_content.py` | Inspects request bodies for leaked secrets. Combines LSH matching with anomaly detection. |
| `_anomaly.py` | Three detectors for exfiltration patterns: rate (req/min), shape (repeated request skeletons), accumulator (total bytes from many small requests). |
| `_env_scanner.py` | Pre-scans workspace for credentials, API keys, and infrastructure secrets. Seeds taint tracker and LSH index before the agent starts. |

### Infrastructure

| Module | Purpose |
|--------|---------|
| `_freezer.py` | `docker pause`/`unpause` or `SIGSTOP`/`SIGCONT` for DEFER |
| `_memory.py` | JSON persistence for user decisions and baseline snapshots across sessions |

## L1 Signals

| Signal | Weight | What it detects |
|--------|--------|-----------------|
| Novelty | 0.30 | Unseen hosts, file types, tools |
| Sequence | 0.20 | Unusual operation ordering (bigrams) |
| Rate | 0.15 | Abnormal request frequency vs EMA |
| Breadth | 0.15 | Many distinct resources in 60s window |
| Burst | 0.10 | 5+ ops in 100ms |
| Pattern | 0.10 | Matches previously blocked operations |

Additional signals from taint tracking and content inspection are added when
applicable:

| Signal | Condition | Effect |
|--------|-----------|--------|
| Taint flow | PID is tainted + network op | +0.9 score |
| Content alert | LSH matches secret in body | +0.9 score |

Composite score >= 0.45 triggers L2 escalation.

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--overwatch` | off | Enable Overwatch |
| `--overwatch-model MODEL` | `claude-sonnet-4-6` | Claude model for L2 |
| `--overwatch-threshold N` | `0.45` | L1 escalation threshold |
| `--app-description TEXT` | `""` | Agent purpose (provides L2 context) |

## Cross-Session Memory

Stored in `~/.agent_sandbox/overwatch_memory.json`:

```json
{
  "version": 1,
  "records": [
    {
      "features": {"op_type": "FILE_READ", "file_extension": ".py"},
      "action": "allow",
      "source": "user",
      "explanation": "Python files in /workspace are always safe",
      "patterns": ["file_extension:.py", "directory_prefix:/workspace"],
      "created_at": 1711152000.0,
      "session_id": "abc123"
    }
  ],
  "baseline_snapshot": { "..." : "..." }
}
```

Memory records come from two sources:
- **User decisions** (after DEFER): include the user's explanation, from which
  feature patterns are extracted automatically.
- **L2 verdicts** (ALLOW or BLOCK): include Claude's reasoning for audit.

The baseline snapshot lets the next session start warm — no cold-start false
positives from an empty baseline.

## Data Flow: Secret Exfiltration Detection

A concrete example of how the layers interact:

1. **Pre-scan**: `_env_scanner` finds `.env` with `STRIPE_KEY=sk_live_...`.
   Seeds `_taint` (marks `.env` as CREDENTIAL) and `_lsh` (indexes the key).

2. **Agent reads `.env`**: `_taint` propagates CREDENTIAL label to the agent's
   PID. L1 sees a file read — normal, ALLOW.

3. **Agent sends HTTP POST to `webhook.site`**: L1 scores the operation.
   `_scorer` adds taint_flow signal (+0.9) because the PID is tainted.
   `_content` runs LSH on the request body — matches `sk_live_...` encoded as
   base64. Content alert signal (+0.9). Composite score >> 0.45.

4. **L2 receives the flagged event** with full context: "PID is tainted with
   CREDENTIAL from `.env`, request body contains a secret matching
   `sk_live_...`". Claude returns BLOCK.

5. The syscall is blocked (or the container is paused for user review).
