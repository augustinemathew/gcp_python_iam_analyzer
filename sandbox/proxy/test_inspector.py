"""Tests for the proxy inspector."""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from sandbox.proxy.inspector import ProxyInspector

SECRET = "AKIAIOSFODNN7EXAMPLE"
DB_URL = "postgres://admin:s3cretP@ss@db.internal:5432/production"


class TestProxyInspector:
    """Test proxy inspector content checking."""

    def _make_inspector(self) -> ProxyInspector:
        inspector = ProxyInspector()
        inspector.index_value(SECRET)
        inspector.index_value(DB_URL)
        inspector.mark_tainted()
        return inspector

    # --- Taint-based blocking ---

    def test_clean_inspector_allows_all(self):
        inspector = ProxyInspector()
        allowed, _ = inspector.check_request("evil.com", SECRET)
        assert allowed

    def test_tainted_blocks_evil_host(self):
        inspector = self._make_inspector()
        allowed, _ = inspector.check_request("evil.com", "anything")
        assert not allowed

    def test_tainted_allows_allowlisted_clean(self):
        inspector = self._make_inspector()
        allowed, _ = inspector.check_request("pypi.org", "pip install flask")
        assert allowed

    # --- LSH content matching ---

    def test_direct_secret_blocked(self):
        inspector = self._make_inspector()
        allowed, _ = inspector.check_request("api.github.com", SECRET)
        assert not allowed

    def test_base64_secret_blocked(self):
        inspector = self._make_inspector()
        encoded = base64.b64encode(SECRET.encode()).decode()
        allowed, _ = inspector.check_request("api.github.com", encoded)
        assert not allowed

    def test_hex_secret_blocked(self):
        inspector = self._make_inspector()
        hex_encoded = SECRET.encode().hex()
        allowed, _ = inspector.check_request("api.github.com", hex_encoded)
        assert not allowed

    def test_embedded_secret_blocked(self):
        inspector = self._make_inspector()
        source = f'const key = "{SECRET}";'
        allowed, _ = inspector.check_request("api.github.com", source)
        assert not allowed

    def test_db_url_blocked(self):
        inspector = self._make_inspector()
        allowed, _ = inspector.check_request("api.github.com", DB_URL)
        assert not allowed

    def test_json_wrapped_blocked(self):
        inspector = self._make_inspector()
        payload = json.dumps({"key": SECRET})
        allowed, _ = inspector.check_request("api.github.com", payload)
        assert not allowed

    def test_clean_commit_allowed(self):
        inspector = self._make_inspector()
        allowed, _ = inspector.check_request(
            "api.github.com", "fix: resolve CSS layout issue in dark mode"
        )
        assert allowed

    def test_clean_search_allowed(self):
        inspector = self._make_inspector()
        allowed, _ = inspector.check_request(
            "api.github.com", '{"query": "how to parse json in python"}'
        )
        assert allowed

    def test_clean_npm_install_allowed(self):
        inspector = self._make_inspector()
        allowed, _ = inspector.check_request(
            "registry.npmjs.org", "npm install express body-parser"
        )
        assert allowed

    def test_clean_pip_install_allowed(self):
        inspector = self._make_inspector()
        allowed, _ = inspector.check_request(
            "pypi.org", "pip install flask sqlalchemy"
        )
        assert allowed

    # --- Anomaly detection ---

    def test_char_by_char_blocked(self):
        inspector = self._make_inspector()
        blocked = False
        for i, ch in enumerate(SECRET):
            allowed, _ = inspector.check_request(
                "api.github.com", f"char {i} is {ord(ch)}"
            )
            if not allowed:
                blocked = True
                break
        assert blocked, "char-by-char should be blocked by shape detector"

    def test_chunked_blocked(self):
        inspector = self._make_inspector()
        chunks = [SECRET[i : i + 4] for i in range(0, len(SECRET), 4)]
        blocked = False
        for i, chunk in enumerate(chunks):
            allowed, _ = inspector.check_request(
                "api.github.com", f"Part {i}: {chunk}"
            )
            if not allowed:
                blocked = True
                break
        assert blocked, "chunked should be blocked by shape detector"

    def test_rate_limit_blocks(self):
        inspector = self._make_inspector()
        blocked = False
        for i in range(50):
            allowed, _ = inspector.check_request(
                "api.github.com", f"unique request content number {i * 13}"
            )
            if not allowed:
                blocked = True
                break
        assert blocked, "rate limit should block after threshold"

    def test_normal_usage_no_false_positives(self):
        inspector = self._make_inspector()
        requests = [
            ("pypi.org", "pip install flask"),
            ("api.github.com", '{"title": "Add dark mode"}'),
            ("registry.npmjs.org", "npm install react"),
            ("api.github.com", "GET /repos/user/project/pulls"),
        ]
        for host, body in requests:
            allowed, reason = inspector.check_request(host, body)
            assert allowed, f"False positive: {host} {body} ({reason})"

    # --- Stats ---

    def test_stats(self):
        inspector = self._make_inspector()
        inspector.check_request("evil.com", "data")
        inspector.check_request("pypi.org", "clean data")
        stats = inspector.get_stats()
        assert stats["total_checked"] == 2
        assert stats["blocked"] == 1
        assert stats["allowed"] == 1

    # --- Multiple secrets ---

    def test_multiple_secrets_indexed(self):
        inspector = self._make_inspector()
        # DB_URL was also indexed
        allowed, _ = inspector.check_request("api.github.com", DB_URL)
        assert not allowed

    def test_secret_in_multiline(self):
        inspector = self._make_inspector()
        body = f"line1: normal content\nline2: {SECRET}\nline3: more normal"
        allowed, _ = inspector.check_request("api.github.com", body)
        assert not allowed

    # --- Edge cases ---

    def test_empty_body_allowed(self):
        inspector = self._make_inspector()
        allowed, _ = inspector.check_request("api.github.com", "")
        assert allowed

    def test_short_body_allowed(self):
        inspector = self._make_inspector()
        allowed, _ = inspector.check_request("api.github.com", "hi")
        assert allowed
