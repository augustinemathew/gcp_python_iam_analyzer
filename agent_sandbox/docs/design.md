# Agent Sandbox: System Design

## Overview

A three-layer sandbox for running AI agents on GCP with enforced policy
constraints on file access, network, and protocol-level operations.

```
┌─────────────────────────────────────────────────────────────┐
│                     Policy YAML                             │
│  file rules · network rules · HTTP rules · MCP+CEL rules   │
└──────────┬──────────────────┬──────────────────┬────────────┘
           │                  │                  │
           ▼                  ▼                  ▼
┌──────────────────┐ ┌────────────────┐ ┌─────────────────────┐
│  Layer 1: gVisor │ │ Layer 2: Proxy │ │ Layer 3: Application│
│  (kernel-level)  │ │ (network-level)│ │ (tool-level)        │
│                  │ │                │ │                     │
│  OCI mounts:     │ │ Envoy sidecar: │ │ SandboxedTool:      │
│  · ro bind mounts│ │ · host/port    │ │ · CEL guards on     │
│  · tmpfs for /tmp│ │   allowlist    │ │   tool arguments    │
│  · no /etc,/root │ │ · HTTP method/ │ │ · Python audit hooks│
│                  │ │   path filter  │ │   (defense-in-depth)│
│  Syscall filter: │ │ · MCP tool/    │ │                     │
│  · no exec       │ │   resource     │ │                     │
│  · no raw socket │ │   inspection   │ │                     │
│  · no mount      │ │ · TLS termn.   │ │                     │
└──────────────────┘ └────────────────┘ └─────────────────────┘
         ▲                   ▲                    ▲
         │                   │                    │
    Cannot bypass       Cannot bypass        Can be bypassed
    (syscall level)     (all traffic routed  (Python-level only,
                         through proxy)       last resort)
```

## GCP Deployment Options

### Option A: Cloud Run (simplest)

Cloud Run uses gVisor (`runsc`) as its default sandbox runtime. This gives
us Layer 1 for free.

```
┌─────────────────────────── Cloud Run Service ────────────────────────────┐
│                                                                          │
│  ┌──────────────────────────── gVisor (runsc) ──────────────────────┐   │
│  │                                                                   │   │
│  │  ┌─────────────┐    ┌──────────────┐    ┌────────────────────┐  │   │
│  │  │ Envoy proxy │◄──►│ Policy       │◄──►│ Agent process     │  │   │
│  │  │ (sidecar)   │    │ controller   │    │ (ADK + tools)     │  │   │
│  │  └──────┬──────┘    └──────────────┘    └────────────────────┘  │   │
│  │         │                                                        │   │
│  │         │ iptables REDIRECT                                      │   │
│  │         │ (all egress → proxy)                                   │   │
│  │         ▼                                                        │   │
│  │  ┌──────────────┐                                                │   │
│  │  │  Netstack    │  gVisor's userspace TCP/IP                     │   │
│  │  └──────┬───────┘                                                │   │
│  └─────────┼────────────────────────────────────────────────────────┘   │
│            │                                                             │
│            ▼ VPC network                                                 │
│     Only allowed endpoints reach the internet                            │
└──────────────────────────────────────────────────────────────────────────┘
```

**Limitations**: Cloud Run doesn't expose the OCI spec directly. Mount
restrictions are limited to what Cloud Run volumes support (Cloud Storage
FUSE, in-memory volumes, NFS). Can't customize seccomp profiles.

### Option B: GKE with Sandbox mode (most control)

GKE Sandbox (`gvisor` RuntimeClass) gives full OCI spec control.

```yaml
# GKE Pod spec
apiVersion: v1
kind: Pod
metadata:
  name: sandboxed-agent
spec:
  runtimeClassName: gvisor    # ← uses runsc
  containers:
    - name: agent
      image: gcr.io/project/agent-sandbox:latest
      volumeMounts:
        - name: workspace
          mountPath: /workspace
        - name: tmp
          mountPath: /tmp
      securityContext:
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
    - name: proxy
      image: envoyproxy/envoy:v1.31
      volumeMounts:
        - name: proxy-config
          mountPath: /etc/envoy
  volumes:
    - name: workspace
      emptyDir:
        sizeLimit: 1Gi
    - name: tmp
      emptyDir:
        medium: Memory
        sizeLimit: 256Mi
    - name: proxy-config
      configMap:
        name: agent-sandbox-envoy
```

**Advantages**: Full control over mounts, seccomp, capabilities, network
policies. Can combine with Kubernetes NetworkPolicy for cluster-level
network rules.

### Option C: Compute Engine + runsc (maximum flexibility)

Run `runsc` directly on a GCE VM. Full control over the OCI runtime spec.

```bash
# Install runsc
gcloud compute ssh agent-vm -- 'sudo apt install runsc'

# Generate OCI spec from policy
agent-sandbox generate-oci --policy agent.policy.yaml > config.json

# Run the agent
runsc run --rootless --network=none agent-container
```

**When to use**: Custom kernel configurations, GPU workloads, or when you
need direct control over the gVisor configuration flags.

## Prior Art: kubernetes-sigs/agent-sandbox

The Kubernetes SIG launched `kubernetes-sigs/agent-sandbox` at KubeCon
Atlanta (Nov 2025) — a K8s controller for managing gVisor-sandboxed pods
specifically for AI agent code execution. It provides a CRD API for
declarative sandbox management.

Our system differs in two ways:
1. **Policy language with CEL** — their sandbox is binary (allow/deny at
   container level); ours expresses fine-grained per-tool argument rules.
2. **Protocol-aware proxy** — they handle network at L3/L4; we inspect
   HTTP paths and MCP tool calls at L7.

We should evaluate building on their controller for the GKE deployment
path rather than reimplementing pod lifecycle management.

## Layer 1: gVisor Filesystem Mediation

### Architecture: Sentry + Gofer + Directfs

```
Agent process                gVisor internals              Host OS
─────────────               ────────────────              ────────
open("/tmp/f")  ──ptrace──►  Sentry
                             (userspace kernel,
                              ~200 syscalls in Go)
                             │
                             │ directfs: Sentry uses donated FDs
                             │   with openat(2) + seccomp O_NOFOLLOW
                             │ fallback: LISAFS RPC to Gofer
                             ▼
                             Gofer ──────────────────────► Host FS
                             (file proxy, seccomp-ed)       (only
                              · donates FDs at startup       mounted
                              · validates paths              paths)
                              · enforces ro/rw
```

Key points:
- **Sentry** intercepts all syscalls via ptrace or KVM. The agent process
  never talks to the real kernel. Sentry itself is seccomp-restricted to
  ~70 host syscalls.
- **Gofer** is a separate process that mediates host filesystem I/O.
  It only has access to explicitly mounted paths.
- **Directfs** (now default): Gofer donates file descriptors at startup.
  Sentry uses `openat(2)` with seccomp-enforced `O_NOFOLLOW` to traverse
  the donated FD trees directly, avoiding per-syscall RPC overhead.
- **LISAFS** protocol (successor to 9P) is the fallback when directfs
  is disabled.
- The agent cannot escape the mount namespace — there is no host path
  to escape to.
- gVisor also supports **EROFS** images that are memory-mapped directly
  into the Sentry, bypassing host FS syscalls entirely (useful for
  read-only application code).

### Translating Policy → OCI Mounts

The policy compiler reads the YAML policy and generates OCI-compliant
mount specifications:

```python
# Policy YAML                        # Generated OCI mount
file:                                 {
  read:                                 "destination": "/home/user/src",
    - "/home/user/src/**"               "source": "/host/user/src",
  write:                                "type": "bind",
    - "/tmp/workspace/**"               "options": ["ro", "rbind"]
                                      },
                                      {
                                        "destination": "/tmp/workspace",
                                        "source": "/host/workspace",
                                        "type": "bind",
                                        "options": ["rw", "rbind", "noexec"]
                                      },
                                      {
                                        "destination": "/tmp",
                                        "type": "tmpfs",
                                        "options": ["nosuid", "noexec", "size=256m"]
                                      }
```

**Rules for translation:**
| Policy rule       | OCI mount option           |
|-------------------|----------------------------|
| `file.read`       | bind mount with `ro`       |
| `file.write`      | bind mount with `rw,noexec`|
| `file.execute`    | bind mount with `ro,exec`  |
| `file.deny`       | not mounted at all         |
| (everything else) | not mounted (default deny) |

### What gVisor doesn't do

gVisor mediates at the syscall/mount level. It cannot:
- Filter by glob pattern within a mounted directory (e.g., allow
  `/workspace/*.py` but deny `/workspace/*.sh`).
- Inspect file contents or enforce content-based rules.
- Make per-tool decisions — it doesn't know which "tool" triggered a write.

**This is where Layer 3 (application) fills the gap.** gVisor provides the
hard boundary; the PolicyEngine provides the fine-grained rules.

## Layer 2: Network Proxy

### gVisor Network Modes

gVisor's `--network` flag controls network isolation:

| Mode      | Description                          | Use case                    |
|-----------|--------------------------------------|-----------------------------|
| `sandbox` | Netstack (userspace TCP/IP in Go)    | Default, strongest isolation|
| `host`    | Passthrough to host kernel stack     | Weaker, adds ~15 syscalls   |
| `none`    | Loopback only, no external network   | Maximum isolation           |

**Recommended: `--network=none` + sidecar proxy.** The agent container
gets no network at all. A separate sidecar container (outside gVisor)
handles all external communication, forwarding only policy-approved
requests. This gives us:
- Zero network attack surface from the agent container
- All traffic must pass through the proxy — no bypass possible
- The proxy runs outside gVisor with full network access

```
┌─── gVisor (--network=none) ───┐     ┌─── Normal container ───┐
│                                │     │                         │
│  Agent ──► unix socket ────────┼────►│  Envoy proxy ──► Internet
│            (only escape hatch) │     │  (policy enforced)      │
│                                │     │                         │
└────────────────────────────────┘     └─────────────────────────┘
```

gVisor's netstack does not natively filter by host/port. For L3/L4
filtering, use Kubernetes NetworkPolicy or host iptables on the veth.
For L7 (HTTP paths, MCP tools), we need the proxy.

### Architecture

```
Agent process          Envoy sidecar              External
─────────────         ──────────────              ────────

requests.post() ──►  iptables REDIRECT ──►  Envoy listener
                      (port 15001)           │
                                             ├─ Route: api.anthropic.com:443
                                             │   └─ allowed: POST /v1/messages
                                             │
                                             ├─ Route: localhost:3000 (MCP)
                                             │   └─ Lua filter: check tool/args
                                             │
                                             └─ Default: return 403
```

### Envoy Configuration (generated from policy)

```yaml
# Generated from policy.network rules
static_resources:
  listeners:
    - name: outbound
      address:
        socket_address: { address: 127.0.0.1, port_value: 15001 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": ...HttpConnectionManager
                route_config:
                  virtual_hosts:
                    # From: network.allow[0]
                    - name: anthropic
                      domains: ["api.anthropic.com"]
                      routes:
                        - match: { prefix: "/v1/messages" }
                          route: { cluster: anthropic_cluster }
                          request_headers_to_remove: [x-internal-header]
                    # Default: deny
                    - name: deny_all
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          direct_response:
                            status: 403
                            body: { inline_string: "sandbox: network denied by policy" }

  clusters:
    - name: anthropic_cluster
      type: STRICT_DNS
      load_assignment:
        cluster_name: anthropic_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: api.anthropic.com, port_value: 443 }
      transport_socket:
        name: envoy.transport_sockets.tls
```

### MCP Protocol Inspection

For MCP endpoints, the proxy inspects JSON-RPC messages:

```
Agent ──► Envoy ──► Lua/Wasm filter ──► MCP server
                    │
                    ├─ Parse JSON-RPC body
                    ├─ Extract method + params
                    ├─ Check tool name against policy
                    ├─ Evaluate CEL on params
                    └─ Allow or return 403
```

The Lua filter:
```lua
-- Envoy Lua filter for MCP tool inspection
function envoy_on_request(handle)
  local body = handle:body():getBytes(0, handle:body():length())
  local rpc = json.decode(body)

  if rpc.method == "tools/call" then
    local tool_name = rpc.params.name
    local tool_args = rpc.params.arguments

    -- Call the policy engine (via gRPC sidecar or embedded)
    local allowed = check_policy(tool_name, tool_args)
    if not allowed then
      handle:respond({[":status"] = "403"}, "sandbox: tool denied")
    end
  end
end
```

**Alternative**: Instead of Lua, use a lightweight Go/Python sidecar that
acts as an MCP-aware reverse proxy with the CEL engine embedded.

## Layer 3: Application-Level (Defense in Depth)

This is what we have today — `SandboxedTool` + `PolicyEngine` + CEL.

In the full system, Layer 3 serves as **defense in depth**:
- Catches things the proxy can't see (e.g., tool args constructed
  dynamically inside the agent)
- Provides better error messages to the LLM ("tool denied because...")
- Enables the agent to self-correct (retry with different args)

```python
# Layer 3 is already implemented
class SandboxedTool:
    def __call__(self, **kwargs):
        self._engine.check_mcp(host, port, tool=name, args=kwargs)
        return self._func(**kwargs)
```

## Policy Compilation Pipeline

The YAML policy is the single source of truth. A compiler generates
artifacts for each layer:

```
                    ┌─────────────────┐
                    │  policy.yaml    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ Policy Compiler │
                    └──┬──────┬────┬──┘
                       │      │    │
          ┌────────────┘      │    └────────────┐
          ▼                   ▼                  ▼
   ┌──────────────┐  ┌───────────────┐  ┌───────────────┐
   │ OCI config   │  │ Envoy config  │  │ Python engine │
   │ (config.json)│  │ (envoy.yaml)  │  │ (PolicyEngine)│
   │              │  │               │  │               │
   │ · mounts     │  │ · routes      │  │ · CEL guards  │
   │ · seccomp    │  │ · clusters    │  │ · audit hooks │
   │ · caps       │  │ · lua filters │  │ · tool wrap   │
   └──────────────┘  └───────────────┘  └───────────────┘
        Layer 1           Layer 2            Layer 3
```

### Implementation: `agent-sandbox compile`

```bash
# Generate all deployment artifacts from a single policy
agent-sandbox compile \
  --policy agent.policy.yaml \
  --target gke \
  --output ./deploy/

# Outputs:
#   deploy/pod.yaml          - GKE pod spec with gVisor + mounts
#   deploy/envoy.yaml        - Envoy sidecar config
#   deploy/networkpolicy.yaml - K8s NetworkPolicy
#   deploy/configmap.yaml    - Policy JSON for the Python engine
```

## Security Properties

| Threat                        | Layer 1 (gVisor) | Layer 2 (Proxy) | Layer 3 (App) |
|-------------------------------|------------------|-----------------|---------------|
| Read /etc/shadow              | **Blocked** (not mounted) | — | Blocked |
| Write outside workspace       | **Blocked** (ro mount) | — | Blocked |
| Connect to evil.com           | — | **Blocked** (no route) | Blocked |
| POST to /admin on allowed host| — | **Blocked** (path filter) | — |
| MCP tool: `rm -rf /`         | **Blocked** (no exec) | **Blocked** (tool denied) | Blocked |
| MCP tool: `write_file("/etc")`| **Blocked** (ro mount) | **Blocked** (CEL guard) | Blocked |
| SQL injection via tool args   | — | — | **Blocked** (CEL guard) |
| Python audit hook bypass      | **Blocked** (still in gVisor) | **Blocked** (still proxied) | Bypassed |
| Container escape              | **Blocked** (gVisor Sentry) | — | — |
| IMDS token theft              | — | **Blocked** (deny rule) | Blocked |

The key property: **no single layer is sufficient, but any two layers
catch all known threats.** Layer 3 (application) is the weakest but
provides the best UX (agent sees structured errors and can retry).

## Deployment on GCP: Recommended Path

### Phase 1: Cloud Run (now)

- Deploy agent container to Cloud Run (gVisor built-in)
- Use VPC Service Controls for network egress filtering
- Application-layer enforcement via SandboxedTool + CEL
- No Envoy sidecar (Cloud Run handles TLS/routing)

```bash
gcloud run deploy agent-sandbox \
  --image gcr.io/project/agent-sandbox \
  --execution-environment gen1 \  # gen1 = gVisor
  --vpc-egress all-traffic \
  --vpc-connector agent-vpc
```

### Phase 2: GKE Sandbox (when you need full control)

- GKE with `gvisor` RuntimeClass
- Envoy sidecar for HTTP/MCP inspection
- Kubernetes NetworkPolicy for L3/L4 filtering
- OCI spec generated from policy YAML

### Phase 3: Custom runsc (specialized workloads)

- Direct `runsc` on Compute Engine
- Custom OCI config.json from policy compiler
- Full control over filesystem, seccomp, and capabilities

## Why gVisor over seccomp-bpf

| Aspect                  | seccomp-bpf                         | gVisor                                  |
|-------------------------|--------------------------------------|-----------------------------------------|
| Approach                | Kernel-level syscall filter          | Userspace kernel reimplementation       |
| Host kernel exposure    | ~300 syscalls pass through           | Sentry uses ~70 restricted syscalls     |
| Filesystem mediation    | Cannot filter by path (FDs only)     | Gofer mediates all access by path       |
| Network isolation       | Cannot inspect packets               | Full userspace TCP/IP stack             |
| Single-bug impact       | One allowed syscall bug = host owned | Multiple layers must be breached        |
| Performance             | Nanoseconds per syscall              | Microseconds (directfs reduces this)    |
| Compatibility           | All syscalls available               | ~200 of ~340 reimplemented              |

**For AI agents executing untrusted code, gVisor is the right choice.**
seccomp-bpf is a policy on the real kernel — allowed syscalls still run
with the full kernel attack surface. gVisor is a separate kernel — even
"allowed" syscalls execute in a sandboxed Go process. gVisor also applies
seccomp to itself as defense in depth.

## References

- [gVisor Architecture](https://gvisor.dev/docs/architecture_guide/intro/)
- [gVisor Filesystem Guide](https://gvisor.dev/docs/user_guide/filesystem/)
- [gVisor Networking Security](https://gvisor.dev/blog/2020/04/02/gvisor-networking-security/)
- [Directfs Blog Post](https://gvisor.dev/blog/2023/06/27/directfs/)
- [OCI Runtime Spec](https://github.com/opencontainers/runtime-spec/blob/main/config.md)
- [kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox)
- [GKE Sandbox Docs](https://cloud.google.com/kubernetes-engine/docs/how-to/sandbox-pods)
