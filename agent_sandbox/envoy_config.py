"""Compile YAML policy → Envoy configuration.

Generates an Envoy proxy config that enforces L7 (HTTP) rules from the policy:

  - **Route matching**: only allowed host:port pairs get upstream clusters.
  - **HTTP method filtering**: Lua filter rejects disallowed methods.
  - **Path filtering**: Lua filter rejects disallowed paths.
  - **MCP tool enforcement**: Lua filter inspects JSON-RPC ``tools/call``
    requests and rejects disallowed tools.

The generated config runs Envoy as a forward proxy on localhost:15001.
Agent traffic is redirected through Envoy via iptables (transparent proxy).

Architecture::

    Agent ──► iptables REDIRECT ──► Envoy :15001 ──► upstream
                                       │
                                       ├─ virtual_host per allowed endpoint
                                       ├─ Lua filter: method/path/MCP checks
                                       └─ deny all unmatched routes

"""

from __future__ import annotations

import json
from typing import Any

import yaml

from agent_sandbox.policy import HttpRules, McpRules, NetworkEndpoint, Policy


ENVOY_LISTENER_PORT = 15001


def compile_envoy_config(policy: Policy) -> dict[str, Any]:
    """Compile a Policy into a complete Envoy bootstrap config."""
    clusters = _build_clusters(policy)
    virtual_hosts = _build_virtual_hosts(policy)
    lua_code = _build_lua_filter(policy)

    http_filters = []
    if lua_code:
        http_filters.append({
            "name": "envoy.filters.http.lua",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua",
                "source_codes": {
                    "policy.lua": {
                        "inline_string": lua_code,
                    },
                },
                "default_source_code": {
                    "inline_string": lua_code,
                },
            },
        })
    http_filters.append({"name": "envoy.filters.http.router",
                         "typed_config": {
                             "@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
                         }})

    config = {
        "static_resources": {
            "listeners": [
                {
                    "name": "policy_listener",
                    "address": {
                        "socket_address": {
                            "address": "0.0.0.0",
                            "port_value": ENVOY_LISTENER_PORT,
                        },
                    },
                    "filter_chains": [
                        {
                            "filters": [
                                {
                                    "name": "envoy.filters.network.http_connection_manager",
                                    "typed_config": {
                                        "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                                        "stat_prefix": "policy_proxy",
                                        "codec_type": "AUTO",
                                        "route_config": {
                                            "name": "policy_routes",
                                            "virtual_hosts": virtual_hosts,
                                        },
                                        "http_filters": http_filters,
                                    },
                                },
                            ],
                        },
                    ],
                },
            ],
            "clusters": clusters,
        },
        "admin": {
            "address": {
                "socket_address": {
                    "address": "127.0.0.1",
                    "port_value": 15000,
                },
            },
        },
    }

    return config


def compile_envoy_yaml(policy: Policy) -> str:
    """Compile a Policy into Envoy YAML config string."""
    return yaml.dump(compile_envoy_config(policy), default_flow_style=False)


# ---------------------------------------------------------------------------
# Clusters (upstream endpoints)
# ---------------------------------------------------------------------------

def _cluster_name(ep: NetworkEndpoint) -> str:
    """Deterministic cluster name for an endpoint."""
    host = ep.host.replace("*", "wildcard").replace(".", "_")
    port = ep.port or 443
    return f"cluster_{host}_{port}"


def _build_clusters(policy: Policy) -> list[dict[str, Any]]:
    """Build an Envoy cluster for each allowed endpoint."""
    clusters = []
    for ep in policy.network.allow:
        # Skip wildcard hosts — can't route to *.foo.com as a single cluster.
        if "*" in ep.host:
            continue

        port = ep.port or 443

        # All clusters use STATIC type to avoid DNS resolution, which
        # blocks Envoy startup inside gVisor containers (no DNS server).
        # The Lua filter + virtual host routing handle L7 policy;
        # upstream connectivity is handled by gVisor's Netstack + iptables.
        is_local = ep.host in ("localhost", "127.0.0.1", "::1")
        cluster_address = "127.0.0.1" if is_local else "0.0.0.0"

        cluster: dict[str, Any] = {
            "name": _cluster_name(ep),
            "connect_timeout": "5s",
            "type": "STATIC",
            "load_assignment": {
                "cluster_name": _cluster_name(ep),
                "endpoints": [
                    {
                        "lb_endpoints": [
                            {
                                "endpoint": {
                                    "address": {
                                        "socket_address": {
                                            "address": cluster_address,
                                            "port_value": port,
                                        },
                                    },
                                },
                            },
                        ],
                    },
                ],
            },
        }

        # TLS for port 443
        if port == 443:
            cluster["transport_socket"] = {
                "name": "envoy.transport_sockets.tls",
                "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                    "sni": ep.host,
                },
            }

        clusters.append(cluster)

    return clusters


# ---------------------------------------------------------------------------
# Virtual hosts (route matching)
# ---------------------------------------------------------------------------

def _build_virtual_hosts(policy: Policy) -> list[dict[str, Any]]:
    """Build virtual hosts: one per allowed endpoint + a catch-all deny."""
    hosts = []

    for ep in policy.network.allow:
        if "*" in ep.host:
            continue

        port = ep.port or 443
        domain = f"{ep.host}:{port}" if ep.port else ep.host

        route: dict[str, Any] = {
            "match": {"prefix": "/"},
            "route": {
                "cluster": _cluster_name(ep),
                "host_rewrite_literal": ep.host,
            },
        }

        # If HTTP path rules exist, add path-specific routes first
        if ep.http and ep.http.paths:
            path_routes = []
            for path_pattern in ep.http.paths:
                path_routes.append({
                    "match": {"prefix": path_pattern},
                    "route": {
                        "cluster": _cluster_name(ep),
                        "host_rewrite_literal": ep.host,
                    },
                })
            # Catch-all for this host → 403
            path_routes.append({
                "match": {"prefix": "/"},
                "direct_response": {
                    "status": 403,
                    "body": {"inline_string": "policy: path not allowed"},
                },
            })
            routes = path_routes
        else:
            routes = [route]

        hosts.append({
            "name": _cluster_name(ep),
            "domains": [domain, ep.host],
            "routes": routes,
        })

    # Catch-all: deny everything else
    hosts.append({
        "name": "deny_all",
        "domains": ["*"],
        "routes": [
            {
                "match": {"prefix": "/"},
                "direct_response": {
                    "status": 403,
                    "body": {
                        "inline_string": "policy: host not allowed",
                    },
                },
            },
        ],
    })

    return hosts


# ---------------------------------------------------------------------------
# Lua filter (method + MCP enforcement)
# ---------------------------------------------------------------------------

def _build_lua_filter(policy: Policy) -> str | None:
    """Build a Lua filter that enforces HTTP methods and MCP tool rules.

    Returns None if no L7 rules exist (no Lua filter needed).
    """
    has_http_rules = any(
        ep.http and ep.http.methods
        for ep in policy.network.allow
    )
    has_mcp_rules = any(
        ep.mcp and ep.mcp.tools
        for ep in policy.network.allow
    )

    if not has_http_rules and not has_mcp_rules:
        return None

    # Build the method allow-map: host → {methods}
    method_rules: dict[str, list[str]] = {}
    for ep in policy.network.allow:
        if ep.http and ep.http.methods:
            key = ep.host
            method_rules[key] = ep.http.methods

    # Build MCP tool allow-map: host → [tool_names]
    mcp_rules: dict[str, list[str]] = {}
    for ep in policy.network.allow:
        if ep.mcp and ep.mcp.tools:
            key = ep.host
            mcp_rules[key] = [t.name for t in ep.mcp.tools]

    method_map_lua = _lua_table(method_rules)
    mcp_map_lua = _lua_table(mcp_rules)

    return f"""\
-- Policy enforcement Lua filter (auto-generated)

local method_rules = {method_map_lua}
local mcp_tool_rules = {mcp_map_lua}

function envoy_on_request(handle)
    local host = handle:headers():get(":authority") or ""
    -- Strip port from host
    local bare_host = host:match("^([^:]+)") or host

    -- 1. HTTP method enforcement
    local allowed_methods = method_rules[bare_host]
    if allowed_methods then
        local method = handle:headers():get(":method") or ""
        local found = false
        for _, m in ipairs(allowed_methods) do
            if m == method then
                found = true
                break
            end
        end
        if not found then
            handle:respond(
                {{[":status"] = "403"}},
                "policy: method " .. method .. " not allowed for " .. bare_host
            )
            return
        end
    end

    -- 2. MCP tool enforcement (inspect JSON-RPC body for tools/call)
    local allowed_tools = mcp_tool_rules[bare_host]
    if allowed_tools then
        local method = handle:headers():get(":method") or ""
        local content_type = handle:headers():get("content-type") or ""
        if method == "POST" and content_type:find("json") then
            local body = handle:body():getBytes(0, handle:body():length())
            if body then
                local body_str = tostring(body)
                -- Look for JSON-RPC method: "tools/call" or "tools/execute"
                if body_str:find('"tools/call"') or body_str:find('"tools/execute"') then
                    -- Extract tool name from "name":"<tool>"
                    local tool_name = body_str:match('"name"%s*:%s*"([^"]+)"')
                    if tool_name then
                        local tool_found = false
                        for _, t in ipairs(allowed_tools) do
                            if t == tool_name then
                                tool_found = true
                                break
                            end
                        end
                        if not tool_found then
                            handle:respond(
                                {{[":status"] = "403"}},
                                "policy: MCP tool " .. tool_name .. " not allowed"
                            )
                            return
                        end
                    end
                end
            end
        end
    end
end
"""


def _lua_table(d: dict[str, list[str]]) -> str:
    """Convert a Python dict of string→list[str] to a Lua table literal."""
    if not d:
        return "{}"
    entries = []
    for key, values in d.items():
        vals = ", ".join(f'"{v}"' for v in values)
        entries.append(f'    ["{key}"] = {{{vals}}}')
    return "{\n" + ",\n".join(entries) + "\n}"
