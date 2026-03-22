"""Tests for LSH content matching engine."""

from __future__ import annotations

import base64
import urllib.parse

from agent_sandbox.core.lsh import (
    LSHEngine,
    minhash_jaccard,
    minhash_signature,
    simhash,
    simhash_distance,
    trigram_jaccard,
    trigram_set,
)

SAMPLE_SECRET = "AKIAIOSFODNN7EXAMPLE"
SAMPLE_DB_URL = "postgres://admin:s3cretP@ss@db.internal:5432/production"


class TestTrigramOperations:
    """Test basic trigram operations."""

    def test_trigram_set_short_string(self):
        assert trigram_set("ab") == set()

    def test_trigram_set_exact_three(self):
        assert trigram_set("abc") == {"abc"}

    def test_trigram_set_longer(self):
        result = trigram_set("abcde")
        assert result == {"abc", "bcd", "cde"}

    def test_jaccard_identical(self):
        sim = trigram_jaccard("hello world", "hello world")
        assert sim == 1.0

    def test_jaccard_similar(self):
        sim = trigram_jaccard("hello world", "hello world!")
        assert sim > 0.8

    def test_jaccard_different(self):
        sim = trigram_jaccard("hello world", "completely different text")
        assert sim < 0.1


class TestSimHash:
    """Test SimHash fingerprinting."""

    def test_identical_strings(self):
        a = simhash("the quick brown fox")
        b = simhash("the quick brown fox")
        assert a == b

    def test_similar_strings_close(self):
        a = simhash("the quick brown fox jumps")
        b = simhash("the quick brown fox leaps")
        dist = simhash_distance(a, b)
        assert dist > 0.5

    def test_different_strings_far(self):
        a = simhash("AKIAIOSFODNN7EXAMPLE")
        b = simhash("totally unrelated content here")
        dist = simhash_distance(a, b)
        assert dist < 0.8


class TestMinHash:
    """Test MinHash signatures."""

    def test_identical_strings(self):
        a = minhash_signature("hello world foo bar baz")
        b = minhash_signature("hello world foo bar baz")
        sim = minhash_jaccard(a, b)
        assert sim == 1.0

    def test_similar_strings(self):
        a = minhash_signature("the quick brown fox jumps over the lazy dog")
        b = minhash_signature("the quick brown fox leaps over the lazy dog")
        sim = minhash_jaccard(a, b)
        assert sim > 0.3


class TestLSHEngine:
    """Test the full LSH engine."""

    def test_exact_match(self):
        engine = LSHEngine()
        engine.index(SAMPLE_SECRET)
        matched, score, reason = engine.check(SAMPLE_SECRET)
        assert matched
        assert score > 0.5

    def test_near_duplicate(self):
        engine = LSHEngine()
        engine.index(SAMPLE_SECRET)
        near = SAMPLE_SECRET + "X"
        matched, score, reason = engine.check(near)
        assert matched
        assert score > 0.3

    def test_base64_encoded(self):
        engine = LSHEngine()
        engine.index(SAMPLE_SECRET)
        encoded = base64.b64encode(SAMPLE_SECRET.encode()).decode()
        matched, score, reason = engine.check(encoded)
        assert matched, f"Base64 should match (score={score})"

    def test_hex_encoded(self):
        engine = LSHEngine()
        engine.index(SAMPLE_SECRET)
        hex_encoded = SAMPLE_SECRET.encode().hex()
        matched, score, reason = engine.check(hex_encoded)
        assert matched, f"Hex should match (score={score})"

    def test_url_encoded(self):
        engine = LSHEngine()
        engine.index(SAMPLE_DB_URL)
        url_encoded = urllib.parse.quote(SAMPLE_DB_URL)
        matched, score, reason = engine.check(url_encoded)
        assert matched, f"URL-encoded should match (score={score})"

    def test_embedded_in_source(self):
        engine = LSHEngine()
        engine.index(SAMPLE_SECRET)
        source = f'const API_KEY = "{SAMPLE_SECRET}";'
        matched, score, reason = engine.check(source)
        assert matched, f"Embedded in source should match (score={score})"

    def test_clean_data_no_match(self):
        engine = LSHEngine()
        engine.index(SAMPLE_SECRET)
        clean = "This is a completely normal commit message about fixing a bug in the CSS layout."
        matched, score, reason = engine.check(clean)
        assert not matched, f"Clean data should not match (score={score})"

    def test_short_string_no_match(self):
        engine = LSHEngine()
        engine.index(SAMPLE_SECRET)
        matched, score, reason = engine.check("hi")
        assert not matched

    def test_empty_engine(self):
        engine = LSHEngine()
        matched, score, reason = engine.check(SAMPLE_SECRET)
        assert not matched

    def test_multiline_secret(self):
        engine = LSHEngine()
        secret = "line1: AKIAIOSFODNN7EXAMPLE\nline2: sk_live_51H7example"
        engine.index(secret)
        # Should match individual lines
        matched, score, reason = engine.check("AKIAIOSFODNN7EXAMPLE")
        assert matched, "Should match individual line from multiline secret"

    def test_false_positive_rate(self):
        """Clean data should not trigger false positives."""
        engine = LSHEngine()
        engine.index(SAMPLE_SECRET)
        engine.index(SAMPLE_DB_URL)

        clean_texts = [
            "git commit -m 'fix: resolve layout issue'",
            "Running pytest tests/test_scanner.py",
            "npm install express body-parser cors",
            '{"title": "Add dark mode toggle", "body": "Implements dark mode"}',
            "pip install flask sqlalchemy pytest",
        ]

        for text in clean_texts:
            matched, score, _ = engine.check(text)
            assert not matched, f"False positive on: {text} (score={score})"
