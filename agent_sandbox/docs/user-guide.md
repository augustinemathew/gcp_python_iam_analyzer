# Agent Sandbox — User Guide

Run any agent executable inside a gVisor sandbox with declarative YAML policies
that control filesystem access, network endpoints, HTTP methods/paths, and MCP
tool calls.

## Quick start

```python
from agent_sandbox.policy import load_policy
from agent_sandbox.gvisor import GVisorSandbox

policy = load_policy("my-policy.yaml")
sb = GVisorSandbox(policy)
result = sb.run(["python3", "agent.py"])

print(result.stdout)
print(result.stderr)
print(result.returncode)
```

That's it. The sandbox handles gVisor, Envoy, iptables, privilege separation,
and cleanup automatically.

## Prerequisites

| Dependency | Version | Purpose |
|---|---|---|
| Docker | 20.10+ | Container runtime |
| gVisor (runsc) | latest | Kernel-level syscall sandbox |
| Envoy | 1.28+ | L7 HTTP/MCP proxy (baked into container image) |
| Python | 3.12+ | Host-side orchestration |

Install gVisor as a Docker runtime:
```bash
# https://gvisor.dev/docs/user_guide/install/
sudo runsc install
sudo systemctl reload docker
```

Build the container image (one-time):
```bash
# The image must contain: python3, envoy, iptables, sh
docker build -t gvisor-python:latest -f Dockerfile.sandbox .
```

## Writing a policy

A policy is a YAML file with three sections: **file**, **network**, and
**defaults**.

### Minimal policy — no network

```yaml
version: "1"
name: offline-agent

defaults:
  file: deny
  network: deny

file:
  read:
    - "/workspace/**"
  write:
    - "/tmp/**"
  execute:
    - "/usr/bin/python3"
```

The agent can read `/workspace`, write to `/tmp`, execute `python3`, and
nothing else. No network access at all (`--network=none`).

### API-calling agent

```yaml
version: "1"
name: llm-agent

defaults:
  file: deny
  network: deny

file:
  read:
    - "/workspace/**"
  write:
    - "/tmp/**"

network:
  allow:
    - host: api.anthropic.com
      port: 443
      http:
        methods: [POST]
        paths: ["/v1/messages"]

    - host: api.openai.com
      port: 443
      http:
        methods: [POST]
        paths: ["/v1/chat/completions"]

  deny:
    - host: "169.254.169.254"     # block cloud IMDS
    - host: "metadata.google.internal"
```

The agent can POST to two LLM APIs and nothing else. GET, PUT, DELETE
are blocked. Other paths on those hosts are blocked. All other hosts are
blocked. Cloud metadata endpoints are explicitly denied.

### Agent with MCP tools

```yaml
version: "1"
name: mcp-agent

defaults:
  file: deny
  network: deny

file:
  read:
    - "/workspace/**"
  write:
    - "/tmp/agent-out/**"

network:
  allow:
    - host: api.anthropic.com
      port: 443
      http:
        methods: [POST]
        paths: ["/v1/messages"]

    - host: localhost
      port: 3000
      mcp:
        tools:
          - read_file
          - search
          - name: write_file
            when: 'args.path.startsWith("/tmp/")'
          - name: run_sql
            when: '!args.query.contains("DROP")'
        resources:
          - "file:///workspace/**"
```

MCP tool rules support two forms:

| Form | Example | Meaning |
|---|---|---|
| Simple string | `read_file` | Tool allowed unconditionally |
| Object with CEL | `{name: write_file, when: 'expr'}` | Tool allowed only when the CEL expression is true |

The `when` expression receives `args` (a map of the tool's arguments).

## Launching executables

### Python script

```python
result = sb.run(["python3", "/workspace/agent.py"])
```

### Node.js agent

```python
result = sb.run(["node", "/workspace/agent.js"])
```

### Any binary

```python
result = sb.run(["/workspace/my-agent", "--config", "/workspace/config.json"])
```

### With a working directory

```python
result = sb.run(
    ["python3", "agent.py"],
    workdir="/path/to/project",  # mounted read-only at /workspace
)
```

The `workdir` is bind-mounted read-only at `/workspace` inside the container.

## How enforcement works

```
┌── gVisor container (docker run --runtime=runsc) ─────────────┐
│                                                              │
│  Phase 1: ROOT (entrypoint, pid 1)                           │
│    ├── Start Envoy on :15001                                 │
│    ├── iptables REDIRECT 80/443 → :15001 (best-effort)       │
│    ├── os.setuid(65534)               ← PRIVILEGE DROP       │
│    │                                                         │
│  Phase 2: NOBODY (uid 65534)                                 │
│    └── exec(agent_command)                                   │
│         ├── Cannot setuid(0)         → PermissionError       │
│         ├── Cannot modify iptables   → no NET_ADMIN          │
│         └── Cannot re-escalate       → caps dropped          │
│                                                              │
│  Envoy (root, pid 2)                                         │
│    ├── Virtual hosts: unknown host → 403                     │
│    ├── Route rules: unlisted path → 403                      │
│    └── Lua filter: unlisted HTTP method → 403                │
│                                                              │
│  Filesystem: read-only root, tmpfs at writable paths         │
└──────────────────────────────────────────────────────────────┘
```

Three modes, selected automatically based on the policy:

| Policy has... | Mode | Capabilities |
|---|---|---|
| `network: deny`, no allow rules | `--network=none` | `--cap-drop=ALL` |
| Allow rules, no `http`/`mcp` | iptables only | `NET_ADMIN` |
| Allow rules with `http` or `mcp` | Envoy + privilege drop | `NET_ADMIN`, `SETUID`, `SETGID` |

## Policy reference

### `defaults`

```yaml
defaults:
  file: deny    # deny | allow
  network: deny # deny | allow
```

Start with `deny` for both. `allow` is available but means you're opting out
of that enforcement layer.

### `file`

```yaml
file:
  read:     ["/path/**"]         # glob patterns for read access
  write:    ["/tmp/workspace/**"] # writable paths (get tmpfs mounts)
  execute:  ["/usr/bin/python3"]  # executable paths
  deny:     ["/etc/shadow"]       # explicit denials (override reads)
```

When `defaults.file: deny`, the entire container filesystem is read-only.
Write paths get tmpfs overlays (256 MB each). File rules use glob patterns.

### `network`

```yaml
network:
  allow:
    - host: api.example.com       # exact hostname
      port: 443                   # optional port
      http:                       # optional L7 rules (triggers Envoy)
        methods: [GET, POST]
        paths: ["/v1/**"]
      mcp:                        # optional MCP rules (triggers Envoy)
        tools: [...]
        resources: [...]
  deny:
    - host: "169.254.169.254"     # block specific hosts
    - host: "*.evil.com"          # wildcards in deny rules
```

- If **no** allow rules exist and `defaults.network: deny`, the container
  runs with `--network=none` (complete isolation).
- If allow rules exist **without** `http`/`mcp`, iptables filters by
  host/port only.
- If allow rules have `http` or `mcp`, Envoy starts as a transparent proxy
  and the agent drops to uid 65534 before executing.

### `http` rules

```yaml
http:
  methods: [GET, POST]       # allowed HTTP methods (uppercase)
  paths:                     # allowed URL paths
    - "/v1/messages"
    - "/v1/models"
```

Requests to unlisted methods or paths get a `403 Forbidden`.

### `mcp` rules

```yaml
mcp:
  tools:
    - read_file                                    # unconditional
    - name: write_file                             # conditional (CEL)
      when: 'args.path.startsWith("/workspace/")'
    - name: run_sql
      when: '!args.query.contains("DROP")'
  resources:
    - "file:///workspace/**"                       # allowed resource URIs
```

## Inspecting compiled enforcement

```python
policy = load_policy("my-policy.yaml")
sb = GVisorSandbox(policy)

config = sb.describe()
print(config["network_init"])   # iptables script
print(config["envoy_config"])   # Envoy YAML (if L7 rules exist)
print(config["seccomp"])        # seccomp profile
print(config["mounts"])         # Docker mount flags
```

## Error handling

```python
result = sb.run(["python3", "agent.py"])

if result.returncode != 0:
    print(f"Agent failed (exit {result.returncode})")
    print(result.stderr)
```

| Exit code | Meaning |
|---|---|
| 0 | Success |
| 1 | Agent error |
| 137 | OOM killed (SIGKILL) |
| 143 | SIGTERM (timeout or container killed) |

The sandbox raises `RuntimeError` if Docker/gVisor setup fails (image not
found, runtime not installed, etc.). Agent errors are returned in `RunResult`,
not raised.

## Tips

- **Start restrictive.** Begin with `defaults: {file: deny, network: deny}`
  and add only what the agent needs.
- **Block IMDS.** Always deny `169.254.169.254` and `metadata.google.internal`
  to prevent credential theft from cloud VMs.
- **Use path restrictions.** Don't just allowlist a host — restrict to specific
  API paths (`/v1/messages`, not `/**`).
- **CEL guards on MCP.** Use `when` expressions to prevent destructive tool
  calls (`!args.query.contains("DROP")`).
- **Inspect before running.** Use `sb.describe()` to see the compiled iptables
  script and Envoy config before launching the agent.
