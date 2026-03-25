# User Guide

Run any executable inside a gVisor sandbox governed by a YAML policy.

## Install

```bash
# 1. Install gVisor as a Docker runtime
#    https://gvisor.dev/docs/user_guide/install/
sudo runsc install
sudo systemctl reload docker

# 2. Build the container image (must contain python3, envoy, iptables, sh)
docker build -t gvisor-python:latest -f Dockerfile.sandbox .

# 3. Install the CLI
pip install -e .
```

## Quick start

### 1. Write a policy

```yaml
# my-policy.yaml
version: "1"
name: my-agent

defaults:
  file: deny
  network: deny

file:
  write:
    - "/tmp/**"

network:
  allow:
    - host: api.anthropic.com
      port: 443
      http:
        methods: [POST]
        paths: ["/v1/messages"]
  deny:
    - host: "169.254.169.254"
```

### 2. Run an agent

```bash
# Python agent with workspace
agent-sandbox -p my-policy.yaml -w ./src -- python3 /workspace/agent.py

# With writable output directory
agent-sandbox -p my-policy.yaml -w ./src -o ./results -- python3 /workspace/agent.py

# Node.js agent
agent-sandbox -p my-policy.yaml -w ./src -- node /workspace/agent.js

# Any binary
agent-sandbox -p my-policy.yaml -- /path/to/my-agent --config config.json
```

### 3. Check what will happen (before running)

```bash
agent-sandbox -p my-policy.yaml --describe
```

## CLI reference

```
agent-sandbox -p POLICY [options] -- COMMAND [ARGS...]
```

| Flag | Short | Description |
|---|---|---|
| `--policy PATH` | `-p` | YAML policy file (required) |
| `--workspace DIR` | `-w` | Host dir mounted read-only at `/workspace` |
| `--output DIR` | `-o` | Host dir mounted read-write at `/output` |
| `--workspace-mount PATH` | | Override workspace container path |
| `--output-mount PATH` | | Override output container path |
| `--timeout SECONDS` | `-t` | Kill after N seconds (default: 300) |
| `--image IMAGE` | | Container image (default: gvisor-python:latest) |
| `--describe` | | Print compiled config and exit |
| `--dry-run` | | Print docker command and exit |
| `--overwatch` | | Enable adaptive anomaly detection |
| `--overwatch-model MODEL` | | Claude model for L2 (default: claude-sonnet-4-6) |
| `--overwatch-threshold N` | | L1 escalation threshold (default: 0.45) |
| `--app-description TEXT` | | Agent purpose description (L2 context) |

## Python API

```python
from agent_sandbox.policy import load_policy
from agent_sandbox.gvisor import GVisorSandbox

policy = load_policy("my-policy.yaml")
sb = GVisorSandbox(policy, image="gvisor-python:latest", timeout=300)

# Basic run
result = sb.run(["python3", "agent.py"])

# With workspace + output
result = sb.run(
    ["python3", "/workspace/agent.py", "--out", "/output/report.json"],
    workdir="/path/to/project",          # → /workspace (read-only)
    output_dir="/path/to/results",       # → /output (read-write)
)

# Custom mount points
result = sb.run(
    ["python3", "/code/agent.py"],
    workdir="/path/to/project",
    workdir_mount="/code",               # override default /workspace
    output_dir="/path/to/results",
    output_mount="/results",             # override default /output
)

# Inspect result
print(result.stdout)
print(result.stderr)
print(result.returncode)   # 0=ok, 1=error, 137=OOM, 143=timeout

# Inspect compiled config
config = sb.describe()
print(config["network_init"])    # iptables script
print(config["envoy_config"])    # Envoy YAML (if L7 rules)
```

## Common policy patterns

### Offline agent (no network)

```yaml
version: "1"
name: offline
defaults: { file: deny, network: deny }
file:
  write: ["/tmp/**"]
```

### LLM API agent

```yaml
version: "1"
name: llm-caller
defaults: { file: deny, network: deny }
file:
  write: ["/tmp/**"]
network:
  allow:
    - host: api.anthropic.com
      port: 443
      http: { methods: [POST], paths: ["/v1/messages"] }
    - host: api.openai.com
      port: 443
      http: { methods: [POST], paths: ["/v1/chat/completions"] }
  deny:
    - host: "169.254.169.254"
    - host: "metadata.google.internal"
```

### Agent with MCP tools

```yaml
version: "1"
name: mcp-agent
defaults: { file: deny, network: deny }
file:
  write: ["/tmp/**"]
network:
  allow:
    - host: api.anthropic.com
      port: 443
      http: { methods: [POST], paths: ["/v1/messages"] }
    - host: localhost
      port: 3000
      mcp:
        tools:
          - read_file
          - name: write_file
            when: 'args.path.startsWith("/tmp/")'
          - name: run_sql
            when: '!args.query.contains("DROP")'
        resources: ["file:///workspace/**"]
  deny:
    - host: "169.254.169.254"
```

## Overwatch (adaptive anomaly detection)

Add `--overwatch` to any command to enable behavioral monitoring. Overwatch
intercepts every syscall via gVisor's seccheck system and evaluates it against
a learned baseline.

```bash
# Basic — Overwatch learns what's normal, flags deviations
agent-sandbox -p my-policy.yaml --overwatch -- python3 agent.py

# With app context for smarter L2 analysis
agent-sandbox -p my-policy.yaml --overwatch \
  --app-description "Code review agent that reads PRs and posts comments" \
  -w ./repo -o ./results \
  -- python3 /workspace/reviewer.py

# Lower threshold = more sensitive (flags more events for L2 review)
agent-sandbox -p my-policy.yaml --overwatch \
  --overwatch-threshold 0.3 \
  -- ./my-agent

# Any binary works — Overwatch operates at the syscall level
agent-sandbox -p my-policy.yaml --overwatch \
  -- /usr/bin/node agent.js
```

### What happens when Overwatch flags something

1. **L1** scores the operation against the baseline (< 0.1ms).
2. If the score exceeds the threshold, **L2** (Claude) analyzes with full context.
3. L2 decides:
   - **ALLOW** — update baseline, continue.
   - **BLOCK** — reject the syscall, log to memory.
   - **DEFER** — pause the container, prompt the user.
4. If DEFER, you'll see a prompt like:

```
============================================================
OVERWATCH: Operation requires human review
============================================================
Operation: FILE_READ
Path: /etc/shadow
L1 Score: 0.72
  novelty: 0.90 - 2/2 features unseen
  pattern_match: 1.00 - matches blocked pattern
L2 Analysis: Novel file access to sensitive system file...
Container is PAUSED. Respond with:
  allow <explanation>  - permit and remember
  block <explanation>  - deny and remember
============================================================
```

Your decision is remembered across sessions. If you say "system files like
this are never safe," Overwatch will auto-block similar access in future
sessions without asking again.

### Overwatch requirements

- **gVisor fork**: Build `runsc-overwatch` from `agent_sandbox/gvisor-overwatch/`. See
  [overwatch/README.md](../overwatch/README.md) for build instructions.
- **L2 (optional)**: Set `ANTHROPIC_API_KEY` for Claude-powered analysis.
  Without it, L1 still flags anomalies but defers all escalations to the user.

## Tips

- **Start with `deny`/`deny`.** Add only what the agent needs.
- **Always block IMDS** — deny `169.254.169.254` and `metadata.google.internal`.
- **Restrict paths, not just hosts** — `/v1/messages` not `/**`.
- **Use `-o` for output** — don't write to the read-only workspace.
- **Inspect first** — `--describe` shows iptables + Envoy config before execution.
- **CEL guards on MCP** — `!args.query.contains("DROP")` prevents destructive calls.

## Further reading

- [Policy YAML reference](policy-reference.md) — complete field-by-field spec
- [Architecture](architecture.md) — runtime flow, module map, execution modes
- [Isolation model](isolation-model.md) — privilege separation, known limits, future options
- [Design](design.md) — three-layer design, GCP deployment, threat matrix
- [Decisions](decisions.md) — why we chose gVisor, Envoy, single container, etc.
- [Overwatch](../overwatch/README.md) — adaptive anomaly detection design, E2E demo, seccheck events
