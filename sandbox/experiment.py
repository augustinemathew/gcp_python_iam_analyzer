"""End-to-end experiment comparing blind vs informed sandbox.

Creates a test project with various sensitive files, runs the scanner,
then tests both blind and informed modes against the same attack set.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from sandbox.env_scanner import EnvironmentScanner
from sandbox.sandbox import Sandbox


def _create_test_project(root: Path) -> None:
    """Create a test project with sensitive files."""
    # .env with standard secrets
    (root / ".env").write_text(
        "DATABASE_URL=postgres://admin:password@db:5432/prod\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "STRIPE_SECRET_KEY=sk_live_51H7example1234567890\n"
    )

    # Vault token (non-standard format)
    (root / "config").mkdir(exist_ok=True)
    (root / "config" / "vault.yaml").write_text(
        "vault:\n"
        "  token: hvs.CAESIJlRm8example_vault_token_here\n"
        "  address: https://vault.internal:8200\n"
    )

    # SSH config
    (root / ".ssh").mkdir(exist_ok=True)
    (root / ".ssh" / "config").write_text(
        "Host production\n"
        "  HostName 10.0.1.50\n"
        "  User deploy\n"
        "  IdentityFile ~/.ssh/id_rsa_prod\n"
    )

    # Normal source code
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/')\n"
        "def hello():\n"
        "    return 'Hello World'\n"
    )

    # Internal API token (non-standard)
    (root / "config" / "internal.yaml").write_text(
        "services:\n"
        "  analytics:\n"
        "    token: int_tk_a1b2c3d4e5f6g7h8i9j0\n"
    )


def run_experiment() -> None:
    """Compare blind vs informed sandbox on the same attacks."""
    with tempfile.TemporaryDirectory(prefix="sandbox-exp-") as tmp:
        root = Path(tmp)
        _create_test_project(root)

        # Scan
        scanner = EnvironmentScanner(str(root))
        manifest = scanner.scan()

        print("=== SCAN RESULTS ===")
        scanner.print_report()
        print()

        # Attacks to test
        attacks = [
            ("Vault token to evil.com", "evil.com", "hvs.CAESIJlRm8example_vault_token_here"),
            ("SSH config to evil.com", "evil.com", "Host production\nHostName 10.0.1.50\nUser deploy"),
            ("Vault token to allowlisted", "api.github.com", "hvs.CAESIJlRm8example_vault_token_here"),
            ("Internal token to evil.com", "evil.com", "int_tk_a1b2c3d4e5f6g7h8i9j0"),
        ]

        print("=== BLIND VS INFORMED ===")
        print(f"{'Attack':<35s}  {'BLIND':>8s}  {'INFORMED':>8s}")
        print("-" * 60)

        for name, host, payload in attacks:
            # Blind sandbox
            blind = Sandbox()
            for fpath in [".env", "config/vault.yaml", ".ssh/config", "config/internal.yaml"]:
                full = root / fpath
                if full.exists():
                    blind.read_file(fpath, full.read_text())
            allowed_blind, _ = blind.check_send(host, payload)

            # Informed sandbox
            informed = Sandbox(manifest=manifest)
            for fpath in [".env", "config/vault.yaml", ".ssh/config", "config/internal.yaml"]:
                full = root / fpath
                if full.exists():
                    informed.read_file(fpath, full.read_text())
            allowed_informed, _ = informed.check_send(host, payload)

            blind_status = "ESCAPED" if allowed_blind else "BLOCKED"
            informed_status = "ESCAPED" if allowed_informed else "BLOCKED"
            print(f"{name:<35s}  {blind_status:>8s}  {informed_status:>8s}")


if __name__ == "__main__":
    run_experiment()
