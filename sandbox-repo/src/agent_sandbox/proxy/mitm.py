"""HTTPS MITM proxy with TLS termination and content inspection.

Handles HTTP CONNECT tunnels by generating per-host certificates signed
by our CA. Terminates TLS on both sides, reads plaintext request bodies,
and passes them through the sandbox enforcement layer.

Usage:
    proxy = MITMProxy(sandbox, ca, port=8080)
    proxy.start()  # starts in background thread
    # ... launch subprocess with HTTP_PROXY=http://localhost:8080
    proxy.stop()
"""

from __future__ import annotations

import http.client
import io
import logging
import re
import select
import socket
import ssl
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler

from agent_sandbox.proxy.cert import CertAuthority

logger = logging.getLogger(__name__)


@dataclass
class ProxyStats:
    """Statistics from proxy operation."""

    total_requests: int = 0
    blocked_requests: int = 0
    allowed_requests: int = 0
    connect_tunnels: int = 0
    errors: int = 0
    inspected_bytes: int = 0
    blocked_details: list[dict[str, str]] = field(default_factory=list)


class _ProxyHandler(BaseHTTPRequestHandler):
    """HTTP request handler that implements CONNECT-based MITM."""

    # Set by MITMProxy before starting
    ca: CertAuthority
    sandbox: object  # sandbox.sandbox.Sandbox
    stats: ProxyStats
    _lock: threading.Lock

    def do_CONNECT(self) -> None:
        """Handle CONNECT tunnel — MITM the TLS connection."""
        host, _, port_str = self.path.partition(":")
        port = int(port_str) if port_str else 443

        with self._lock:
            self.stats.connect_tunnels += 1

        # Tell client the tunnel is established
        self.send_response(200, "Connection Established")
        self.end_headers()

        # Get a cert for this host
        try:
            cert_path, key_path = self.ca.get_cert_for_host(host)
        except Exception as e:
            logger.error("Failed to generate cert for %s: %s", host, e)
            with self._lock:
                self.stats.errors += 1
            return

        # Wrap client connection with TLS (we are the "server" to the client)
        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        client_ctx.load_cert_chain(cert_path, key_path)

        try:
            client_tls = client_ctx.wrap_socket(
                self.connection,
                server_side=True,
            )
        except ssl.SSLError as e:
            logger.debug("Client TLS handshake failed for %s: %s", host, e)
            with self._lock:
                self.stats.errors += 1
            return

        # Read the actual HTTP request from the client (now decrypted)
        try:
            self._handle_tunneled_request(client_tls, host, port)
        except Exception as e:
            logger.debug("Tunneled request handling error for %s: %s", host, e)
            with self._lock:
                self.stats.errors += 1
        finally:
            try:
                client_tls.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                client_tls.close()
            except Exception:
                pass

    def _handle_tunneled_request(
        self, client_tls: ssl.SSLSocket, host: str, port: int
    ) -> None:
        """Read decrypted HTTP request, inspect, forward or block."""
        # Read raw HTTP request from client
        raw_request = self._read_http_request(client_tls)
        if not raw_request:
            return

        # Parse the request
        method, path, headers, body = self._parse_raw_request(raw_request)

        with self._lock:
            self.stats.total_requests += 1
            self.stats.inspected_bytes += len(body)

        logger.info("MITM: %s %s://%s%s [%d bytes body]", method, "https", host, path, len(body))

        # --- ENFORCEMENT: check with sandbox ---
        allowed, reason = self.sandbox.check_send(host, body.decode("utf-8", errors="replace"))

        if not allowed:
            logger.warning("BLOCKED: %s %s://%s%s — %s", method, "https", host, path, reason)
            with self._lock:
                self.stats.blocked_requests += 1
                self.stats.blocked_details.append({
                    "method": method,
                    "host": host,
                    "path": path,
                    "body_size": len(body),
                    "reason": reason,
                })
            # Send 403 back to client
            response = (
                b"HTTP/1.1 403 Forbidden\r\n"
                b"Content-Type: text/plain\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"Blocked by sandbox: " + reason.encode() + b"\r\n"
            )
            client_tls.sendall(response)
            return

        with self._lock:
            self.stats.allowed_requests += 1

        # Forward to real server
        try:
            server_ctx = ssl.create_default_context()
            server_sock = socket.create_connection((host, port), timeout=10)
            server_tls = server_ctx.wrap_socket(server_sock, server_hostname=host)
        except Exception as e:
            logger.debug("Failed to connect to %s:%d: %s", host, port, e)
            response = (
                b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Content-Type: text/plain\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"Failed to connect to upstream: " + str(e).encode() + b"\r\n"
            )
            client_tls.sendall(response)
            return

        try:
            # Send request to real server
            server_tls.sendall(raw_request)

            # Read response from real server and forward to client
            self._relay_response(server_tls, client_tls)
        finally:
            try:
                server_tls.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            server_tls.close()

    def _read_http_request(self, sock: ssl.SSLSocket) -> bytes:
        """Read a complete HTTP request from a socket."""
        data = b""
        sock.settimeout(5)
        try:
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data += chunk
                # Check if we have the full headers
                if b"\r\n\r\n" in data:
                    header_end = data.index(b"\r\n\r\n") + 4
                    headers_raw = data[:header_end].decode("utf-8", errors="replace")
                    # Check Content-Length
                    cl_match = re.search(r"Content-Length:\s*(\d+)", headers_raw, re.IGNORECASE)
                    if cl_match:
                        content_length = int(cl_match.group(1))
                        body_so_far = len(data) - header_end
                        remaining = content_length - body_so_far
                        while remaining > 0:
                            chunk = sock.recv(min(remaining, 8192))
                            if not chunk:
                                break
                            data += chunk
                            remaining -= len(chunk)
                    break
        except socket.timeout:
            pass
        return data

    def _parse_raw_request(self, raw: bytes) -> tuple[str, str, dict[str, str], bytes]:
        """Parse a raw HTTP request into components."""
        if b"\r\n\r\n" not in raw:
            return "GET", "/", {}, b""

        header_end = raw.index(b"\r\n\r\n") + 4
        header_section = raw[:header_end].decode("utf-8", errors="replace")
        body = raw[header_end:]

        lines = header_section.split("\r\n")
        request_line = lines[0] if lines else "GET / HTTP/1.1"
        parts = request_line.split(" ", 2)
        method = parts[0] if parts else "GET"
        path = parts[1] if len(parts) > 1 else "/"

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ": " in line:
                key, _, value = line.partition(": ")
                headers[key.lower()] = value

        return method, path, headers, body

    def _relay_response(self, server: ssl.SSLSocket, client: ssl.SSLSocket) -> None:
        """Relay server response back to client."""
        server.settimeout(10)
        try:
            while True:
                chunk = server.recv(8192)
                if not chunk:
                    break
                client.sendall(chunk)
        except socket.timeout:
            pass
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self) -> None:
        """Handle plain HTTP GET (non-CONNECT)."""
        self._handle_plain_request("GET")

    def do_POST(self) -> None:
        """Handle plain HTTP POST (non-CONNECT)."""
        self._handle_plain_request("POST")

    def do_PUT(self) -> None:
        """Handle plain HTTP PUT."""
        self._handle_plain_request("PUT")

    def _handle_plain_request(self, method: str) -> None:
        """Handle a plain HTTP (non-TLS) request."""
        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        # Extract host from URL or Host header
        host = self.headers.get("Host", "")
        if not host and "://" in self.path:
            host = self.path.split("://", 1)[1].split("/", 1)[0]

        with self._lock:
            self.stats.total_requests += 1
            self.stats.inspected_bytes += len(body)

        # Enforce
        allowed, reason = self.sandbox.check_send(
            host, body.decode("utf-8", errors="replace")
        )

        if not allowed:
            with self._lock:
                self.stats.blocked_requests += 1
                self.stats.blocked_details.append({
                    "method": method,
                    "host": host,
                    "path": self.path,
                    "body_size": len(body),
                    "reason": reason,
                })
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"Blocked by sandbox: {reason}\n".encode())
            return

        with self._lock:
            self.stats.allowed_requests += 1

        # Forward plain HTTP
        try:
            conn = http.client.HTTPConnection(host, timeout=10)
            conn.request(method, self.path, body, dict(self.headers))
            resp = conn.getresponse()
            self.send_response(resp.status)
            for key, val in resp.getheaders():
                if key.lower() not in ("transfer-encoding",):
                    self.send_header(key, val)
            self.end_headers()
            self.wfile.write(resp.read())
            conn.close()
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"Upstream error: {e}\n".encode())

    def log_message(self, format: str, *args: object) -> None:
        """Suppress default logging — we use our own logger."""
        logger.debug(format, *args)


class MITMProxy:
    """HTTPS MITM proxy with sandbox enforcement.

    Starts a local HTTP proxy that handles CONNECT tunnels. For each
    HTTPS connection, generates a per-host cert signed by our CA,
    terminates TLS, inspects plaintext traffic, and enforces policy.
    """

    def __init__(
        self,
        sandbox: object,
        ca: CertAuthority,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.sandbox = sandbox
        self.ca = ca
        self.host = host
        self.port = port
        self.stats = ProxyStats()
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._lock = threading.Lock()

    def start(self) -> int:
        """Start the proxy in a background thread. Returns the actual port."""
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(32)
        self._server.settimeout(1)
        self.port = self._server.getsockname()[1]

        # Configure the handler class
        _ProxyHandler.ca = self.ca
        _ProxyHandler.sandbox = self.sandbox
        _ProxyHandler.stats = self.stats
        _ProxyHandler._lock = self._lock

        self._running = True
        self._thread = threading.Thread(target=self._serve_loop, daemon=True)
        self._thread.start()

        logger.info("MITM proxy started on %s:%d", self.host, self.port)
        return self.port

    def _serve_loop(self) -> None:
        """Accept and handle connections in a loop."""
        while self._running:
            try:
                client_sock, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            # Handle each connection in a new thread
            t = threading.Thread(
                target=self._handle_connection,
                args=(client_sock, addr),
                daemon=True,
            )
            t.start()

    def _handle_connection(
        self, client_sock: socket.socket, addr: tuple[str, int]
    ) -> None:
        """Handle a single client connection."""
        try:
            handler = _ProxyHandler(
                request=client_sock,
                client_address=addr,
                server=self._server,
            )
        except Exception as e:
            logger.debug("Handler error from %s: %s", addr, e)
            with self._lock:
                self.stats.errors += 1
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def stop(self) -> None:
        """Stop the proxy."""
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("MITM proxy stopped. Stats: %s", self.get_stats())

    def get_stats(self) -> dict[str, object]:
        """Get proxy statistics."""
        with self._lock:
            return {
                "total_requests": self.stats.total_requests,
                "blocked": self.stats.blocked_requests,
                "allowed": self.stats.allowed_requests,
                "tunnels": self.stats.connect_tunnels,
                "errors": self.stats.errors,
                "inspected_bytes": self.stats.inspected_bytes,
                "blocked_details": list(self.stats.blocked_details),
            }

    def get_proxy_url(self) -> str:
        """Get the proxy URL for HTTP_PROXY/HTTPS_PROXY env vars."""
        return f"http://{self.host}:{self.port}"

    def get_env(self) -> dict[str, str]:
        """Get environment variables to route subprocess traffic through proxy."""
        url = self.get_proxy_url()
        ca_bundle = self.ca.get_ca_bundle()
        return {
            "HTTP_PROXY": url,
            "HTTPS_PROXY": url,
            "http_proxy": url,
            "https_proxy": url,
            "REQUESTS_CA_BUNDLE": ca_bundle,
            "SSL_CERT_FILE": ca_bundle,
            "CURL_CA_BUNDLE": ca_bundle,
            "NODE_EXTRA_CA_CERTS": str(self.ca.ca_cert),
        }
