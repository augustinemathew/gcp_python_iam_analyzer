# Policy Reference

Complete reference for the agent sandbox policy YAML format.

## Structure

```yaml
version: "1"           # required, must be "1"
name: my-agent         # required, identifier for logging/debugging

defaults:
  file: deny           # deny | allow — default stance for filesystem
  network: deny        # deny | allow — default stance for network

file:                  # optional — filesystem access rules
  read: [...]
  write: [...]
  execute: [...]
  deny: [...]

network:               # optional — network access rules
  allow: [...]
  deny: [...]
```

## `defaults`

Controls the default stance for each enforcement domain.

| Field | Values | Effect |
|---|---|---|
| `file` | `deny` (recommended) | Container rootfs is read-only. Only paths in `file.write` are writable. |
| `file` | `allow` | Container rootfs is writable. `file.deny` paths are still blocked. |
| `network` | `deny` (recommended) | No network access unless explicitly allowed. |
| `network` | `allow` | All outbound allowed. `network.deny` rules still apply. |

## `file`

Filesystem access rules using glob patterns.

```yaml
file:
  read:
    - "/workspace/**"          # recursive glob
    - "/etc/ssl/certs/**"      # read CA certificates
  write:
    - "/tmp/**"                # scratch space
    - "/output/**"             # agent results
  execute:
    - "/usr/bin/python3"       # exact path
    - "/usr/bin/node"
  deny:
    - "/etc/shadow"            # override read rules
    - "/etc/passwd"
```

### How file rules translate to Docker flags

| Rule | Docker flag | Notes |
|---|---|---|
| `defaults.file: deny` | `--read-only` | Entire rootfs read-only |
| `file.write: ["/tmp/**"]` | `--tmpfs /tmp:rw,exec,size=256m` | tmpfs overlay, 256MB |
| `file.read` | Policy-level enforcement | Not enforced at container level (gVisor serves synthetic FS) |
| `file.execute` | Policy-level enforcement | Checked by application layer |
| `file.deny` | Not mounted | Path not available in container |

### Glob patterns

- `*` — matches any filename within one directory level
- `**` — matches recursively through subdirectories
- Patterns are matched using Python `fnmatch` semantics

### Workspace and output mounts

The `-w` / `--workspace` and `-o` / `--output` CLI flags add additional
bind mounts that are separate from the `file` rules:

| CLI flag | Container path | Access | Default path |
|---|---|---|---|
| `-w DIR` | `/workspace` | Read-only | Overridable with `--workspace-mount` |
| `-o DIR` | `/output` | Read-write | Overridable with `--output-mount` |

These mounts are always added when the flags are provided, regardless of
the `file` rules. The `file.write` rules control tmpfs mounts on the rootfs;
`-o` controls a bind mount from the host.

## `network`

### `network.allow`

Each entry specifies an allowed outbound endpoint, optionally with L7 rules.

```yaml
network:
  allow:
    # L3/L4 only (host + port)
    - host: api.example.com
      port: 443

    # L7: HTTP method + path filtering
    - host: api.anthropic.com
      port: 443
      http:
        methods: [POST]
        paths: ["/v1/messages", "/v1/complete"]

    # L7: MCP tool + resource filtering
    - host: localhost
      port: 3000
      mcp:
        tools:
          - read_file
          - name: write_file
            when: 'args.path.startsWith("/tmp/")'
        resources:
          - "file:///workspace/**"
```

#### Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `host` | string | yes | Hostname or IP. Wildcards only in `deny` rules. |
| `port` | integer | no | Port number. Omit to allow any port. |
| `http` | object | no | L7 HTTP rules. Triggers Envoy proxy. |
| `mcp` | object | no | L7 MCP rules. Triggers Envoy proxy. |

#### `http` rules

```yaml
http:
  methods: [GET, POST, PUT, DELETE]    # uppercase HTTP methods
  paths:                               # URL path prefixes
    - "/v1/messages"
    - "/v1/models"
```

| Field | Type | Required | Description |
|---|---|---|---|
| `methods` | list[string] | no | Allowed HTTP methods (uppercase). Empty = all methods allowed. |
| `paths` | list[string] | no | Allowed URL path prefixes. Empty = all paths allowed. |

Requests to unlisted methods or paths receive `403 Forbidden`.

#### `mcp` rules

```yaml
mcp:
  tools:
    - read_file                                     # unconditional
    - name: write_file                              # conditional (CEL)
      when: 'args.path.startsWith("/workspace/")'
    - name: run_sql
      when: '!args.query.contains("DROP")'
  resources:
    - "file:///workspace/**"
```

| Field | Type | Required | Description |
|---|---|---|---|
| `tools` | list | no | Allowed MCP tools. See tool rule formats below. |
| `resources` | list[string] | no | Allowed MCP resource URI patterns (glob). |

#### MCP tool rule formats

**Simple string** — tool allowed unconditionally:
```yaml
tools:
  - read_file
  - search
```

**Object with CEL guard** — tool allowed only when the expression is true:
```yaml
tools:
  - name: write_file
    when: 'args.path.startsWith("/tmp/")'
  - name: run_sql
    when: '!args.query.contains("DROP") && !args.query.contains("DELETE")'
```

The `when` expression is a [CEL](https://github.com/google/cel-spec)
expression. It receives `args` — a map of the tool's arguments as submitted
by the agent. The expression must return a boolean.

**CEL examples:**

| Expression | Meaning |
|---|---|
| `args.path.startsWith("/tmp/")` | Path must be under /tmp |
| `!args.query.contains("DROP")` | SQL must not contain DROP |
| `args.count < 100` | Numeric limit on an argument |
| `args.url.startsWith("https://")` | URL must be HTTPS |

### `network.deny`

Explicit deny rules. Applied after allow rules. Support wildcards.

```yaml
network:
  deny:
    - host: "169.254.169.254"          # block cloud IMDS
    - host: "metadata.google.internal"  # block GCP metadata
    - host: "*.evil.com"               # wildcard deny
    - host: "10.0.0.0/8"              # block private networks
      port: 443
```

| Field | Type | Required | Description |
|---|---|---|---|
| `host` | string | yes | Hostname, IP, or wildcard pattern (`*.evil.com`). |
| `port` | integer | no | Port number. Omit to deny all ports on this host. |

**Note:** Wildcard hosts (`*.evil.com`) work in deny rules but are skipped
in iptables allow rules (iptables can't resolve wildcards). Envoy handles
wildcard deny via its default deny-all virtual host.

## How the mode is selected

The sandbox auto-selects the execution mode based on the network rules:

```
defaults.network: deny AND no network.allow rules?
  → Mode 1: --network=none, --cap-drop=ALL

network.allow rules exist, but none have http or mcp?
  → Mode 2: iptables filtering, NET_ADMIN

network.allow rules have http or mcp sub-rules?
  → Mode 3: Envoy sidecar + privilege drop
```

| Mode | Network | Capabilities | Envoy |
|---|---|---|---|
| 1 (offline) | `--network=none` | `--cap-drop=ALL` | No |
| 2 (L3/L4) | Bridge | `NET_ADMIN` | No |
| 3 (L7) | Bridge | `NET_ADMIN`, `SETUID`, `SETGID` | Yes |

## Full example

```yaml
version: "1"
name: production-agent

defaults:
  file: deny
  network: deny

file:
  read:
    - "/workspace/**"
    - "/etc/ssl/certs/**"
  write:
    - "/tmp/**"
  execute:
    - "/usr/bin/python3"
    - "/usr/bin/git"
  deny:
    - "/etc/shadow"
    - "/etc/passwd"
    - "/root/**"

network:
  allow:
    # LLM API — only POST to message endpoints
    - host: api.anthropic.com
      port: 443
      http:
        methods: [POST]
        paths:
          - "/v1/messages"

    # Google AI — only POST
    - host: generativelanguage.googleapis.com
      port: 443
      http:
        methods: [POST]

    # MCP tool server — restricted tools
    - host: localhost
      port: 3000
      mcp:
        tools:
          - read_file
          - search
          - name: write_file
            when: 'args.path.startsWith("/tmp/agent-workspace/")'
          - name: run_sql
            when: >
              !args.query.contains("DROP") &&
              !args.query.contains("DELETE") &&
              !args.query.contains("TRUNCATE")
        resources:
          - "file:///workspace/**"
          - "file:///tmp/agent-workspace/**"

  deny:
    - host: "169.254.169.254"
    - host: "metadata.google.internal"
    - host: "*.internal"
```
