"""Tests for the LLM classifier module.

Tests use mocked responses — no real API calls.
"""

from __future__ import annotations

import json
import tempfile
from unittest.mock import MagicMock, patch

from agent_sandbox.core.llm_classifier import (
    LLMClassifier,
    SessionContext,
    _build_user_prompt,
    _parse_response,
)


class TestParseResponse:
    """Test LLM response parsing."""

    def test_valid_json(self):
        resp = json.dumps({
            "risk_level": "malicious",
            "confidence": 0.95,
            "reasoning": "Agent encoded secrets and sent to evil.com",
            "recommended_action": "block",
        })
        result = _parse_response(resp)
        assert result.risk_level == "malicious"
        assert result.confidence == 0.95
        assert result.recommended_action == "block"

    def test_json_in_code_fence(self):
        resp = (
            '```json\n{"risk_level": "safe", "confidence": 0.9,'
            ' "reasoning": "ok", "recommended_action": "allow"}\n```'
        )
        result = _parse_response(resp)
        assert result.risk_level == "safe"

    def test_invalid_json_returns_suspicious(self):
        result = _parse_response("this is not json")
        assert result.risk_level == "suspicious"
        assert result.confidence == 0.5

    def test_missing_fields_default(self):
        result = _parse_response("{}")
        assert result.risk_level == "suspicious"
        assert result.recommended_action == "alert"


class TestBuildPrompt:
    """Test prompt construction."""

    def test_includes_turn_data(self):
        turn_data = {"intent": "exfiltrate", "actions": []}
        context = SessionContext(tainted=True, blocked_count=3)
        prompt = _build_user_prompt(turn_data, context)
        parsed = json.loads(prompt)
        assert parsed["turn"]["intent"] == "exfiltrate"
        assert parsed["session_context"]["tainted"] is True
        assert parsed["session_context"]["blocked_count"] == 3

    def test_truncates_files_read(self):
        context = SessionContext(files_read=[f"file_{i}.py" for i in range(20)])
        prompt = _build_user_prompt({}, context)
        parsed = json.loads(prompt)
        assert len(parsed["session_context"]["files_read"]) == 10


class TestLLMClassifier:
    """Test the classifier with mocked API calls."""

    def _make_mock_response(self, risk_level: str, confidence: float) -> MagicMock:
        resp = MagicMock()
        content_block = MagicMock()
        content_block.text = json.dumps({
            "risk_level": risk_level,
            "confidence": confidence,
            "reasoning": "test reasoning",
            "recommended_action": "block" if risk_level == "malicious" else "allow",
        })
        resp.content = [content_block]
        return resp

    def test_assess_turn_malicious(self):
        classifier = LLMClassifier()
        mock_client = MagicMock()
        mock_client.messages.create.return_value = self._make_mock_response("malicious", 0.95)
        classifier._client = mock_client

        result = classifier.assess_turn(
            {"intent": "exfiltrate secrets", "actions": []},
            SessionContext(tainted=True),
        )
        assert result.risk_level == "malicious"
        assert result.confidence == 0.95
        assert result.latency_ms >= 0

    def test_assess_turn_safe(self):
        classifier = LLMClassifier()
        mock_client = MagicMock()
        mock_client.messages.create.return_value = self._make_mock_response("safe", 0.9)
        classifier._client = mock_client

        result = classifier.assess_turn(
            {"intent": "fix bug", "actions": []},
            SessionContext(tainted=False),
        )
        assert result.risk_level == "safe"

    def test_caches_assessments(self):
        classifier = LLMClassifier()
        mock_client = MagicMock()
        mock_client.messages.create.return_value = self._make_mock_response("safe", 0.8)
        classifier._client = mock_client

        classifier.assess_turn({"intent": "test"}, SessionContext())
        classifier.assess_turn({"intent": "test2"}, SessionContext())
        assert classifier.cache_size == 2

    def test_export_dataset(self):
        classifier = LLMClassifier()
        mock_client = MagicMock()
        mock_client.messages.create.return_value = self._make_mock_response("safe", 0.8)
        classifier._client = mock_client

        classifier.assess_turn({"intent": "test"}, SessionContext())

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name

        count = classifier.export_dataset(path)
        assert count == 1

        with open(path) as f:
            line = f.readline()
            record = json.loads(line)
            assert "input" in record
            assert "output" in record
            assert record["output"]["risk_level"] == "safe"

    def test_import_error_without_anthropic(self):
        classifier = LLMClassifier()
        classifier._client = None
        with patch.dict("sys.modules", {"anthropic": None}):
            try:
                classifier._get_client()
                assert False, "Should have raised ImportError"
            except ImportError as e:
                assert "anthropic" in str(e)
