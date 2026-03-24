# Architectural Decisions

Decisions made during implementation, why, and what was rejected.

## ADR-001: gVisor over seccomp-bpf

**Date:** 2026-03
**Status:** Accepted

**Context:** Need a syscall-level sandbox for arbitrary agent executables.
Two options: seccomp-bpf (kernel-level filter) or gVisor (userspace kernel).

**Decision:** gVisor.

**Rationale:**
- seccomp-bpf cannot filter by filesystem path (only syscall number + args)
- seccomp-bpf passes allowed syscalls to the real kernel — one kernel bug = host compromise
- gVisor reimplements ~200 syscalls in Go — even "allowed" syscalls run in userspace
- gVisor applies seccomp to its own Sentry (~70 host syscalls) as defense-in-depth
- gVisor provides filesystem mediation via Gofer (separate process)

**Tradeoff:** ~2-5x syscall overhead vs. bare metal. Acceptable for agent workloads
(agent latency is dominated by LLM API calls, not syscalls).

## ADR-002: Single container with privilege drop (not two containers)

**Date:** 2026-03
**Status:** Accepted

**Context:** Initial design used two containers sharing a network namespace:
Envoy container (NET_ADMIN) + agent container (no caps). This prevents the
agent from killing Envoy or modifying iptables.

**Decision:** Single container with `setuid(65534)` privilege drop.

**Rationale:** gVisor does not support `--network=container:` for sharing
network namespaces between gVisor sandboxes. Each `docker run --runtime=runsc`
gets its own Netstack instance. Two containers cannot share loopback.

Attempted alternatives:
1. **Two containers, bridge network** — would require Envoy to listen on
   0.0.0.0 and the agent to connect via Docker bridge IP. Adds latency,
   complexity, and exposes Envoy to the Docker network.
2. **Two containers, host network** — defeats the purpose of network isolation.

Single container with uid drop provides:
- ✓ Agent cannot modify iptables (no NET_ADMIN after drop)
- ✓ Agent cannot re-escalate (no SETUID cap after drop)
- ✗ Agent can signal PID 1 (gVisor allows cross-UID signals)

The PID 1 signaling issue is a known limitation, fixable in production via
GKE sidecar containers with separate PID namespaces.

**See:** [isolation-model.md](isolation-model.md) for the full analysis.

## ADR-003: Envoy for L7 enforcement (not custom proxy)

**Date:** 2026-03
**Status:** Accepted

**Context:** Need to filter HTTP requests by method/path and inspect MCP
JSON-RPC tool calls. Options: custom Python/Go proxy, Envoy, nginx.

**Decision:** Envoy with Lua filter.

**Rationale:**
- Envoy's virtual host routing maps directly to our `network.allow` rules
- Lua filter is sufficient for MCP JSON-RPC inspection (parse body, check
  tool name, evaluate CEL guard)
- Envoy handles TLS termination, connection pooling, retries
- Battle-tested in production (Istio, GKE, Cloud Run all use Envoy)
- Static binary (~20MB) that can be baked into the container image

**Rejected:**
- Custom Python proxy — would need to reimplement TLS, connection pooling,
  HTTP/2, and would be slower
- nginx — less programmable, Lua support is via a separate module
- Go sidecar — more code to maintain, less battle-tested

## ADR-004: iptables as best-effort (Envoy is the real enforcement)

**Date:** 2026-03
**Status:** Accepted

**Context:** gVisor's Netstack implements the legacy iptables API, but the
`iptables` binary in most container images is `iptables-nft`, which uses
the nftables backend. nftables requires kernel modules that gVisor doesn't
provide.

**Decision:** Run iptables in the entrypoint (best-effort, silently ignore
failures). Envoy is the real enforcement layer.

**Rationale:**
- iptables-nft fails with "Protocol not supported" in gVisor
- iptables-legacy requires the legacy kernel API (`/proc/net/ip_tables_names`)
  which gVisor's synthetic /proc doesn't fully implement
- Envoy's virtual host routing + Lua filter already enforces all L7 rules
- Even if iptables worked, it would only add L3/L4 filtering — Envoy already
  does this via its route configuration

**Future:** When deploying on real Linux (Firecracker, GKE), iptables will
work correctly. The `net-init.sh` script is still generated and will take
effect on platforms with a real kernel.

## ADR-005: Policy YAML as single source of truth

**Date:** 2026-03
**Status:** Accepted

**Context:** Three enforcement layers each need different configuration
(Docker flags, Envoy YAML, Python engine). Keeping them in sync manually
is error-prone.

**Decision:** Single YAML policy compiled to all three layers.

**Rationale:**
- One file to review, one file to audit
- Compiler generates Docker flags, Envoy config, seccomp profile, iptables
  script from the same Policy object
- Changes to the policy automatically propagate to all layers
- `--describe` flag lets operators inspect the compiled config before running

**See:** [policy-reference.md](policy-reference.md) for the full YAML spec.

## ADR-006: Workspace/output as CLI args (not policy fields)

**Date:** 2026-03
**Status:** Accepted

**Context:** Agents need access to source code (read-only) and a place to
write results (read-write). These paths are deployment-specific, not
policy-specific.

**Decision:** Workspace (`-w`) and output (`-o`) are CLI flags, not fields
in the policy YAML.

**Rationale:**
- The policy describes *what the agent is allowed to do* (capabilities)
- The CLI args describe *where the agent runs* (environment)
- Same policy can be used with different workspace paths across deployments
- Policy `file.write` rules control tmpfs mounts on the rootfs; `-o` controls
  a bind mount from the host — they serve different purposes

**Usage:**
```bash
# Same policy, different workspaces
agent-sandbox -p llm-agent.yaml -w ./project-a -o ./results-a -- python3 /workspace/agent.py
agent-sandbox -p llm-agent.yaml -w ./project-b -o ./results-b -- python3 /workspace/agent.py
```

## ADR-007: No unikernel, no custom libc

**Date:** 2026-03
**Status:** Rejected (unikernels and custom libc)

**Context:** Evaluated replacing the kernel interface entirely with a
unikernel or custom libc to prevent syscall-level escape.

**Decision:** Neither approach is viable for arbitrary agent executables.

**Rationale:**

*Custom libc:*
- Python C extension ecosystem (grpcio, numpy, cryptography, pydantic-core)
  ships manylinux wheels that dynamically link glibc
- Replacing glibc with musl breaks all of them
- LD_PRELOAD shim is bypassable via raw `syscall()` instruction

*Unikernels:*
- Single-address-space, single-process by design
- No fork(), no exec(), no subprocess.run()
- Most agent frameworks (LangChain, CrewAI, ADK) need all three
- Python support is experimental at best (no pip, no C extensions)

**See:** [isolation-model.md](isolation-model.md) for the full evaluation
matrix.

**Future path:** Firecracker microVMs provide hardware isolation with full
Linux compatibility. Planned for Phase 3.
