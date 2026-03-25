# Architecture

## System overview

The agent sandbox runs arbitrary executables inside a gVisor container with
declarative policy enforcement.  A single YAML policy compiles to three
enforcement layers that are applied automatically.

```
                         policy.yaml
                             │
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
     ┌─────────────┐  ┌──────────────┐  ┌──────────────┐
     │  Filesystem  │  │   Network    │  │  Application │
     │  (gVisor)    │  │  (Envoy)     │  │  (hooks)     │
     │              │  │              │  │              │
     │  ro rootfs   │  │  iptables    │  │  CEL guards  │
     │  tmpfs write │  │  L7 routes   │  │  audit hooks │
     │  cap-drop    │  │  Lua filter  │  │  tool wrap   │
     └─────────────┘  └──────────────┘  └──────────────┘
      Cannot bypass    Cannot bypass     Defense-in-depth
```

**Any two layers catch all known threats.** See [design.md](design.md) for the
full threat matrix.

## Runtime flow

```
agent-sandbox -p policy.yaml -w ./src -o ./results -- python3 /workspace/agent.py
         │
         ▼
  ┌─ load_policy() ──────────────────────────────────────────┐
  │  Parse YAML → Policy dataclass (frozen, immutable)       │
  └──────────────────────────────────────┬───────────────────┘
                                         │
  ┌─ GVisorSandbox._do_run() ───────────▼───────────────────┐
  │                                                          │
  │  1. Detect mode:                                         │
  │     no network?  → Mode 1: --network=none, cap-drop=ALL  │
  │     L3/L4 only?  → Mode 2: iptables, NET_ADMIN           │
  │     L7 (http/mcp)? → Mode 3: Envoy + privilege drop      │
  │                                                          │
  │  2. Write artifacts to tmpdir:                           │
  │     cmd.json, net-init.sh, agent-entry.py                │
  │     envoy.yaml, envoy-entry.py (Mode 3 only)            │
  │                                                          │
  │  3. Build docker run command:                            │
  │     --runtime=runsc                                      │
  │     --read-only + tmpfs (from file rules)                │
  │     -v workspace:ro, -v output:rw                        │
  │     -v /sandbox/*:ro (entrypoints)                       │
  │                                                          │
  │  4. Execute:                                             │
  │     docker run → gVisor Sentry boots → entrypoint.py     │
  └──────────────────────────────────────────────────────────┘
```

## Three execution modes

The sandbox auto-selects the mode based on what the policy requires.

### Mode 1: No network

When `defaults.network: deny` and no `network.allow` rules exist.

```
docker run --runtime=runsc --rm
  --cap-drop=ALL
  --network=none        ← no network stack at all
  --read-only           ← from defaults.file: deny
  --tmpfs /tmp:rw       ← from file.write: ["/tmp/**"]
  -v workspace:ro
  -v output:rw
  gvisor-python:latest
  python3 /sandbox/agent-entry.py
```

The container has zero network capabilities. The entrypoint reads `/sandbox/cmd.json`
and `execvp()`s the agent command.

### Mode 2: Network with L3/L4 filtering

When `network.allow` rules exist but none have `http` or `mcp` sub-rules.

```
docker run --runtime=runsc --rm
  --cap-drop=ALL
  --cap-add=NET_ADMIN   ← for iptables
  --read-only
  ...
```

The agent entrypoint runs `net-init.sh` (iptables script that allows only
the listed host:port pairs) then `execvp()`s the agent command.  No Envoy.

### Mode 3: Envoy + privilege drop

When any `network.allow` rule has `http` or `mcp` sub-rules.

```
docker run --runtime=runsc --rm
  --cap-drop=ALL
  --cap-add=NET_ADMIN   ← iptables (best-effort)
  --cap-add=SETUID      ← to drop to uid 65534
  --cap-add=SETGID      ← to drop to gid 65534
  --read-only
  ...
  python3 /sandbox/envoy-entry.py
```

The entrypoint runs in two phases:

```
Phase 1: ROOT (pid 1)
  ├── iptables REDIRECT 80/443 → Envoy :15001
  ├── Start Envoy (pid 2, stays as root)
  ├── Wait for Envoy listener to be ready
  ├── os.setgid(65534)
  ├── os.setuid(65534)   ← PRIVILEGE DROP
  │
Phase 2: NOBODY (uid 65534)
  └── subprocess.run(agent_command)
       agent cannot:
         setuid(0)       → PermissionError
         modify iptables → no NET_ADMIN
         re-escalate     → SETUID/SETGID caps consumed
```

## Envoy L7 enforcement

Envoy is configured with virtual hosts generated from the policy:

```
network.allow:
  - host: api.anthropic.com     ──→  Virtual host "api.anthropic.com"
    port: 443                         Route: POST /v1/messages → cluster
    http:                             Default: 403
      methods: [POST]
      paths: ["/v1/messages"]

  - host: localhost              ──→  Virtual host "localhost"
    port: 3000                        Lua filter inspects MCP JSON-RPC
    mcp:                              Tool allow/deny + CEL evaluation
      tools: [read_file, ...]

  (all other hosts)              ──→  Virtual host "*" → 403
```

The Lua filter:
1. Parses the HTTP request body as JSON-RPC
2. Extracts the MCP tool name and arguments
3. Checks the tool name against the policy allowlist
4. Evaluates CEL `when` expressions against the arguments
5. Returns 403 if denied, forwards if allowed

See [envoy_config.py](../envoy_config.py) for the full config generator.

## Filesystem enforcement

When `defaults.file: deny`:

| Source | Container path | Access | Mechanism |
|---|---|---|---|
| Host workspace | `/workspace` | Read-only | `-v path:/workspace:ro` |
| Host output dir | `/output` | Read-write | `-v path:/output:rw` |
| Policy `file.write` | Various | Read-write | `--tmpfs path:rw,exec,size=256m` |
| Everything else | `/` | Read-only | `--read-only` |

The agent sees a read-only root filesystem with writable tmpfs overlays
at the paths specified in `file.write`. The workspace and output directories
are bind-mounted from the host.

## Overwatch: adaptive anomaly detection

When `--overwatch` is enabled, a fourth layer activates: the Overwatch
behavioral anomaly detector. Unlike the other three layers which enforce
static policy rules, Overwatch learns what "normal" looks like and flags
deviations.

```
                         policy.yaml
                             │
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
     ┌─────────────┐  ┌──────────────┐  ┌──────────────┐
     │  Filesystem  │  │   Network    │  │  Application │
     │  (gVisor)    │  │  (Envoy)     │  │  (hooks)     │
     └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
            │                 │                  │
            └────────────┬────┘──────────────────┘
                         │
                   gVisor Sentry
                    seccheck
                         │
                  ┌──────▼──────┐
                  │  Overwatch   │   ← NEW: adaptive layer
                  │  L1 baseline │
                  │  L2 LLM      │
                  │  user memory │
                  └─────────────┘
```

Overwatch intercepts syscalls via gVisor's seccheck system. A custom
`OverwatchSink` (Go) in the Sentry sends each event over a Unix socket
to the host-side Python engine. See [overwatch/README.md](../overwatch/README.md)
for the full design.

## Module map

```
agent_sandbox/
├── __main__.py          CLI entrypoint (argparse → GVisorSandbox)
├── policy.py            YAML parser → frozen Policy dataclasses
├── gvisor.py            Docker/gVisor orchestration, 3 execution modes
├── envoy_config.py      Policy → Envoy YAML (virtual hosts, routes, Lua)
├── engine.py            PolicyEngine (check_file, check_network, check_mcp)
├── sandbox.py           In-process sandbox (audit hooks, subprocess wrapper)
├── hooks.py             Python sys.addaudithook() integration
├── errors.py            PolicyViolation, PolicyLoadError
├── example.policy.yaml  Full-featured example policy
├── overwatch/           Adaptive behavioral anomaly detection
│   ├── __init__.py      OverwatchEngine orchestrator
│   ├── _baseline.py     L1 EMA baseline
│   ├── _scorer.py       6 deviation signals → composite score
│   ├── _analyzer.py     L2 LLM agent (Claude)
│   ├── _memory.py       Cross-session persistence
│   ├── _freezer.py      Container pause/resume
│   ├── _server.py       Unix socket server (seccheck bridge)
│   ├── _features.py     Feature extraction
│   └── _types.py        Frozen dataclasses
├── examples/
│   ├── adk_agent.py     ADK agent example
│   └── adk_policy.yaml  ADK-specific policy
└── docs/
    ├── architecture.md  ← you are here
    ├── design.md        Three-layer design, GCP deployment, threat matrix
    ├── isolation-model.md  Privilege separation, gVisor limits, future options
    ├── policy-reference.md Complete policy YAML reference
    ├── decisions.md     Architectural decision records
    └── user-guide.md    Quick start, CLI reference, examples
```

## Cross-references

- **Policy YAML syntax** → [policy-reference.md](policy-reference.md)
- **Three-layer design + GCP deployment** → [design.md](design.md)
- **Isolation model + future directions** → [isolation-model.md](isolation-model.md)
- **Why we made specific choices** → [decisions.md](decisions.md)
- **Quick start + CLI** → [user-guide.md](user-guide.md)
- **Overwatch adaptive detection** → [overwatch/README.md](../overwatch/README.md)
