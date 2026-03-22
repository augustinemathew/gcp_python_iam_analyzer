"""CA certificate generation and per-host cert signing.

Generates a root CA at sandbox startup, then creates per-host certificates
on the fly for MITM TLS termination. Certs are cached in a temp directory.
"""

from __future__ import annotations

import datetime
import os
import subprocess
import tempfile
from pathlib import Path


class CertAuthority:
    """Manages a root CA and signs per-host certificates for MITM."""

    def __init__(self, cert_dir: str | None = None) -> None:
        self.cert_dir = Path(cert_dir) if cert_dir else Path(tempfile.mkdtemp(prefix="sandbox-certs-"))
        self.ca_key = self.cert_dir / "ca.key"
        self.ca_cert = self.cert_dir / "ca.pem"
        self._host_cache: dict[str, tuple[str, str]] = {}

        if not self.ca_cert.exists():
            self._generate_ca()

    def _generate_ca(self) -> None:
        """Generate a root CA key and self-signed certificate."""
        # Generate CA private key
        subprocess.run(
            ["openssl", "genrsa", "-out", str(self.ca_key), "2048"],
            capture_output=True, check=True,
        )

        # Generate self-signed CA cert
        subprocess.run(
            [
                "openssl", "req", "-new", "-x509",
                "-key", str(self.ca_key),
                "-out", str(self.ca_cert),
                "-days", "1",
                "-subj", "/CN=Sandbox CA/O=Agent Sandbox/C=US",
            ],
            capture_output=True, check=True,
        )

    def get_cert_for_host(self, hostname: str) -> tuple[str, str]:
        """Get or create a TLS certificate for a hostname.

        Returns (cert_path, key_path).
        """
        if hostname in self._host_cache:
            return self._host_cache[hostname]

        safe_name = hostname.replace(".", "_").replace(":", "_")
        host_key = self.cert_dir / f"{safe_name}.key"
        host_cert = self.cert_dir / f"{safe_name}.pem"
        host_csr = self.cert_dir / f"{safe_name}.csr"
        host_ext = self.cert_dir / f"{safe_name}.ext"

        # Generate host private key
        subprocess.run(
            ["openssl", "genrsa", "-out", str(host_key), "2048"],
            capture_output=True, check=True,
        )

        # Generate CSR
        subprocess.run(
            [
                "openssl", "req", "-new",
                "-key", str(host_key),
                "-out", str(host_csr),
                "-subj", f"/CN={hostname}",
            ],
            capture_output=True, check=True,
        )

        # Write SAN extension file
        host_ext.write_text(
            f"subjectAltName=DNS:{hostname}\n"
            f"basicConstraints=CA:FALSE\n"
            f"keyUsage=digitalSignature,keyEncipherment\n"
            f"extendedKeyUsage=serverAuth\n"
        )

        # Sign with CA
        subprocess.run(
            [
                "openssl", "x509", "-req",
                "-in", str(host_csr),
                "-CA", str(self.ca_cert),
                "-CAkey", str(self.ca_key),
                "-CAcreateserial",
                "-out", str(host_cert),
                "-days", "1",
                "-extfile", str(host_ext),
            ],
            capture_output=True, check=True,
        )

        result = (str(host_cert), str(host_key))
        self._host_cache[hostname] = result
        return result

    def get_ca_bundle(self) -> str:
        """Get path to a CA bundle that includes our CA cert + system certs.

        This bundle can be used as REQUESTS_CA_BUNDLE or SSL_CERT_FILE
        so the subprocess trusts our MITM certs.
        """
        bundle_path = self.cert_dir / "ca-bundle.pem"
        if bundle_path.exists():
            return str(bundle_path)

        # Start with system CA bundle
        system_bundle = ""
        for candidate in [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ]:
            if os.path.exists(candidate):
                system_bundle = Path(candidate).read_text()
                break

        if not system_bundle:
            # Try certifi
            try:
                import certifi
                system_bundle = Path(certifi.where()).read_text()
            except ImportError:
                pass

        # Append our CA cert
        our_ca = self.ca_cert.read_text()
        bundle_path.write_text(system_bundle + "\n" + our_ca)

        return str(bundle_path)

    def cleanup(self) -> None:
        """Remove all generated certificates."""
        import shutil
        if self.cert_dir.exists():
            shutil.rmtree(self.cert_dir, ignore_errors=True)
