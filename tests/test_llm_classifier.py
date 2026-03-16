"""Unit tests for bounty_guard.llm_classifier.

All OpenAI API calls are mocked; no real network access is required.

Covers:
- classify_issue returns LLMResult(skipped=True) when disabled.
- classify_issue returns LLMResult(skipped=True, error=...) when no API key.
- Successful classification: valid JSON parsed into LLMResult.
- Response with markdown fences around JSON is handled.
- Missing 'spam_probability' key returns skipped with error.
- Invalid JSON returns skipped with error.
- RateLimitError returns skipped with error.
- APITimeoutError returns skipped with error.
- APIConnectionError returns skipped with error.
- Generic APIError returns skipped with error.
- Empty choices list returns skipped with error.
- spam_probability is clamped to [0.0, 1.0].
- _truncate helper works correctly.
- _parse_llm_response handles various response shapes.
- Body and title are truncated to configured limits.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from openai import APIConnectionError, APIError, APITimeoutError, RateLimitError

from bounty_guard.llm_classifier import (
    _MAX_BODY_CHARS,
    _MAX_TITLE_CHARS,
    _parse_llm_response,
    _truncate,
    classify_issue,
)
from bounty_guard.models import LLMResult


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TEST_API_KEY = "sk-test-key"
TEST_MODEL = "gpt-4o-mini"
SPAM_BODY = "Dear Security Team, I found a critical RCE in all versions."
LEGIT_BODY = "Steps to reproduce:\n1. Send this payload...\n```http\nGET /api\n```"


# ---------------------------------------------------------------------------
# Helper: build a mock OpenAI response
# ---------------------------------------------------------------------------


def _mock_openai_response(content: str) -> MagicMock:
    """Build a minimal mock of the OpenAI chat completion response object."""
    message = MagicMock()
    message.content = content
    choice = MagicMock()
    choice.message = message
    response = MagicMock()
    response.choices = [choice]
    return response


# ---------------------------------------------------------------------------
# Tests: classify_issue disabled / missing key
# ---------------------------------------------------------------------------


class TestClassifyIssueDisabled:
    def test_returns_skipped_when_disabled(self):
        result = classify_issue(SPAM_BODY, enabled=False)
        assert result.skipped is True
        assert result.spam_probability == 0.0
        assert result.error is None

    def test_returns_skipped_when_no_api_key(self):
        result = classify_issue(SPAM_BODY, enabled=True, api_key=None, model=TEST_MODEL)
        assert result.skipped is True
        assert result.error is not None
        assert "API key" in result.error

    def test_none_body_treated_as_empty_when_disabled(self):
        result = classify_issue(None, enabled=False)
        assert result.skipped is True


# ---------------------------------------------------------------------------
# Tests: successful classification
# ---------------------------------------------------------------------------


class TestClassifyIssueSuccess:
    def _make_client_and_patch(self, content: str):
        """Return a context manager that patches OpenAI client."""
        response = _mock_openai_response(content)
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = response
        return mock_client

    def test_spam_probability_populated(self):
        mock_client = self._make_client_and_patch(
            '{"spam_probability": 0.92, "reasoning": "Vague, no repro steps."}'
        )
        with patch("bounty_guard.llm_classifier.OpenAI", return_value=mock_client):
            result = classify_issue(
                SPAM_BODY,
                issue_title="Critical RCE",
                api_key=TEST_API_KEY,
                model=TEST_MODEL,
                enabled=True,
            )
        assert result.skipped is False
        assert result.spam_probability == pytest.approx(0.92)
        assert "repro" in result.reasoning.lower()
        assert result.model == TEST_MODEL

    def test_legitimate_report_low_probability(self):
        mock_client = self._make_client_and_patch(
            '{"spam_probability": 0.05, "reasoning": "Detailed repro and PoC provided."}'
        )
        with patch("bounty_guard.llm_classifier.OpenAI", return_value=mock_client):
            result = classify_issue(
                LEGIT_BODY,
                api_key=TEST_API_KEY,
                model=TEST_MODEL,
                enabled=True,
            )
        assert result.skipped is False
        assert result.spam_probability == pytest.approx(0.05)

    def test_probability_exactly_zero(self):
        mock_client = self._make_client_and_patch(
            '{"spam_probability": 0.0, "reasoning": "Genuine report."}'
        )
        with patch("bounty_guard.llm_classifier.OpenAI", return_value=mock_client):
            result = classify_issue(
                LEGIT_BODY, api_key=TEST_API_KEY, model=TEST_MODEL, enabled=True
            )
        assert result.spam_probability == 0.0

    def test_probability_exactly_one(self):
        mock_client = self._make_client_and_patch(
            '{"spam_probability": 1.0, "reasoning": "Pure spam."}'
        )
        with patch("bounty_guard.llm_classifier.OpenAI", return_value=mock_client):
            result = classify_issue(
                SPAM_BODY, api_key=TEST_API_KEY, model=TEST_MODEL, enabled=True
            )
        assert result.spam_probability == 1.0

    def test_none_body_is_handled(self):
        mock_client = self._make_client_and_patch(
            '{"spam_probability": 0.8, "reasoning": "Empty body."}'
        )
        with patch("bounty_guard.llm_classifier.OpenAI", return_value=mock_client):
            result = classify_issue(
                None, api_key=TEST_API_KEY, model=TEST_MODEL, enabled=True
            )
        assert result.skipped is False

    def test_openai_called_with_json_mode(self):
        mock_client = self._make_client_and_patch(
            '{"spam_probability": 0.5, "reasoning": "Borderline."}'
        )
        with patch("bounty_guard.llm_classifier.OpenAI", return_value=mock_client):
            classify_issue(
                SPAM_BODY, api_key=TEST_API_KEY, model=TEST_MODEL, enabled=True
            )
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert call_kwargs["response_format"] == {"type": "json_object"}
        assert call_kwargs["temperature"] == 0.0

    def test_system_and_user_messages_sent(self):
        mock_client = self._make_client_and_patch(
            '{"spam_probability": 0.5, "reasoning": "OK."}'
        )
        with patch("bounty_guard.llm_classifier.OpenAI", return_value=mock_client):
            classify_issue(
                "test body",
                issue_title="test title",
                api_key=TEST_API_KEY,
                model=TEST_MODEL,
                enabled=True,
            )
        messages = mock_client.chat.completions.create.call_args[1]["messages"]
        roles = [m["role"] for m in messages]
        assert "system" in roles
        assert "user" in roles


# ---------------------------------------------------------------------------
# Tests: response parsing edge cases
# ---------------------------------------------------------------------------


class TestClassifyIssueParsingEdgeCases:
    def _call_with_content(self, content: str) -> LLMResult:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _mock_openai_response(
            content
        )
        with patch("bounty_guard.llm_classifier.OpenAI", return_value=mock_client):
            return classify_issue(
                SPAM_BODY, api_key=TEST_API_KEY, model=TEST_MODEL, enabled=True
            )

    def test_markdown_fences_stripped(self):
        content = '```json\n{"spam_probability": 0.75, "reasoning": "Fenced JSON."}\n```'
        result = self._call_with_content(content)
        assert result.skipped is False
        assert result.spam_probability == pytest.approx(0.75)

    def test_missing_spam_probability_returns_skipped(self):
        result = self._call_with_content('{"reasoning": "No probability."}')
        assert result.skipped is True
        assert result.error is not None
        assert "spam_probability" in result.error

    def test_invalid_json_returns_skipped(self):
        result = self._call_with_content("this is not json at all")
        assert result.skipped is True
        assert result.error is not None

    def test_empty_content_returns_skipped(self):
        result = self._call_with_content("")
        assert result.skipped is True

    def test_probability_above_one_clamped(self):
        result = self._call_with_content(
            '{"spam_probability": 1.5, "reasoning": "Over max."}'
        )
        assert result.skipped is False
        assert result.spam_probability == 1.0

    def test_probability_below_zero_clamped(self):
        result = self._call_with_content(
            '{"spam_probability": -0.5, "reasoning": "Below min."}'
        )
        assert result.skipped is False
        assert result.spam_probability == 0.0

    def test_invalid_probability_type_returns_skipped(self):
        result = self._call_with_content(
            '{"spam_probability": "not_a_float", "reasoning": "Bad type."}'
        )
        assert result.skipped is True

    def test_missing_reasoning_defaults_to_empty(self):
        result = self._call_with_content('{"spam_probability": 0.5}')
        assert result.skipped is False
        assert result.reasoning == ""

    def test_no_choices_returns_skipped(self):
        mock_client = MagicMock()
        response = MagicMock()
        response.choices = []
        mock_client.chat.completions.create.return_value = response
        with patch("bounty_guard.llm_classifier.OpenAI", return_value=mock_client):
            result = classify_issue(
                SPAM_BODY, api_key=TEST_API_KEY, model=TEST_MODEL, enabled=True
            )
        assert result.skipped is True
        assert result.error is not None


# ---------------------------------------------------------------------------
# Tests: error handling
# ---------------------------------------------------------------------------


class TestClassifyIssueErrorHandling:
    def _call_with_side_effect(self, side_effect) -> LLMResult:
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = side_effect
        with patch("bounty_guard.llm_classifier.OpenAI", return_value=mock_client):
            return classify_issue(
                SPAM_BODY, api_key=TEST_API_KEY, model=TEST_MODEL, enabled=True
            )

    def test_rate_limit_error_returns_skipped(self):
        error = RateLimitError(
            message="Rate limit exceeded",
            response=MagicMock(status_code=429),
            body={},
        )
        result = self._call_with_side_effect(error)
        assert result.skipped is True
        assert result.error is not None
        assert "Rate limit" in result.error or "rate" in result.error.lower()

    def test_timeout_error_returns_skipped(self):
        error = APITimeoutError(request=MagicMock())
        result = self._call_with_side_effect(error)
        assert result.skipped is True
        assert result.error is not None
        assert "timeout" in result.error.lower()

    def test_connection_error_returns_skipped(self):
        error = APIConnectionError(request=MagicMock())
        result = self._call_with_side_effect(error)
        assert result.skipped is True
        assert result.error is not None
        assert "connection" in result.error.lower()

    def test_generic_api_error_returns_skipped(self):
        error = APIError(
            message="Internal server error",
            request=MagicMock(),
            body={},
        )
        result = self._call_with_side_effect(error)
        assert result.skipped is True
        assert result.error is not None

    def test_skipped_result_has_model_set(self):
        error = RateLimitError(
            message="Rate limit",
            response=MagicMock(status_code=429),
            body={},
        )
        result = self._call_with_side_effect(error)
        assert result.model == TEST_MODEL


# ---------------------------------------------------------------------------
# Tests: _truncate helper
# ---------------------------------------------------------------------------


class TestTruncate:
    def test_short_string_unchanged(self):
        assert _truncate("hello", 10) == "hello"

    def test_string_at_limit_unchanged(self):
        s = "x" * 100
        assert _truncate(s, 100) == s

    def test_long_string_truncated(self):
        s = "x" * 200
        result = _truncate(s, 100)
        assert len(result) == 100
        assert result.endswith("...")

    def test_empty_string_unchanged(self):
        assert _truncate("", 10) == ""

    def test_body_truncated_to_max_chars(self):
        long_body = "a" * (_MAX_BODY_CHARS + 500)
        result = _truncate(long_body, _MAX_BODY_CHARS)
        assert len(result) == _MAX_BODY_CHARS
        assert result.endswith("...")

    def test_title_truncated_to_max_chars(self):
        long_title = "b" * (_MAX_TITLE_CHARS + 50)
        result = _truncate(long_title, _MAX_TITLE_CHARS)
        assert len(result) == _MAX_TITLE_CHARS


# ---------------------------------------------------------------------------
# Tests: _parse_llm_response
# ---------------------------------------------------------------------------


class TestParseLLMResponse:
    MODEL = "gpt-4o-mini"

    def test_valid_json_parsed(self):
        content = '{"spam_probability": 0.8, "reasoning": "Looks spammy."}'
        result = _parse_llm_response(content, self.MODEL)
        assert result.skipped is False
        assert result.spam_probability == pytest.approx(0.8)
        assert result.reasoning == "Looks spammy."
        assert result.model == self.MODEL

    def test_json_with_extra_whitespace(self):
        content = '  \n  {"spam_probability": 0.3, "reasoning": "OK."}  \n  '
        result = _parse_llm_response(content, self.MODEL)
        assert result.skipped is False

    def test_json_embedded_in_text(self):
        content = 'Here is the result: {"spam_probability": 0.6, "reasoning": "Borderline."}'
        result = _parse_llm_response(content, self.MODEL)
        assert result.skipped is False
        assert result.spam_probability == pytest.approx(0.6)

    def test_no_json_object_returns_skipped(self):
        result = _parse_llm_response("No JSON here at all.", self.MODEL)
        assert result.skipped is True
        assert result.error is not None

    def test_malformed_json_returns_skipped(self):
        result = _parse_llm_response("{spam_probability: 0.5}", self.MODEL)
        assert result.skipped is True

    def test_missing_key_returns_skipped(self):
        result = _parse_llm_response('{"reasoning": "No prob."}', self.MODEL)
        assert result.skipped is True
        assert "spam_probability" in result.error

    def test_model_preserved_on_error(self):
        result = _parse_llm_response("not json", "custom-model")
        assert result.model == "custom-model"
