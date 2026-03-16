"""Optional LLM-based classifier for BountyGuard.

Provides a second-opinion spam classification on top of the rule-based scorer
by calling the OpenAI Chat Completions API.  The classifier returns a
:class:`~bounty_guard.models.LLMResult` containing a spam probability in
[0.0, 1.0] and a human-readable reasoning string.

Design decisions
----------------
- The classifier is fully optional: when ``LLM_ENABLED=false`` (the default)
  the function returns immediately with ``LLMResult(skipped=True)``.
- All OpenAI API calls are made through the ``openai`` library's synchronous
  client.  The async variant is not used here; callers that need async
  behaviour should run this in a thread via ``asyncio.to_thread``.
- The prompt is carefully structured so that the model must respond with a
  JSON object containing exactly two keys: ``spam_probability`` (float) and
  ``reasoning`` (str).  A JSON-mode system prompt is used when the model
  supports it.
- Errors are caught and returned as ``LLMResult(skipped=True, error=...)``
  rather than propagating exceptions, so a flaky LLM does not block triage.

Example usage::

    from bounty_guard.llm_classifier import classify_issue
    from bounty_guard.config import settings

    result = classify_issue(
        issue_body="Dear team, I found a critical RCE...",
        issue_title="Critical vulnerability",
    )
    print(result.spam_probability)  # e.g. 0.92
    print(result.reasoning)         # e.g. "Missing repro steps, vague claims..."
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from openai import OpenAI, APIError, APIConnectionError, RateLimitError, APITimeoutError

from bounty_guard.models import LLMResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a security triage assistant for open-source software projects.
Your task is to evaluate whether an incoming GitHub issue that claims to be a
security vulnerability report is likely to be AI-generated spam or a
low-quality, copy-paste submission rather than a genuine, well-researched
security report.

You must respond ONLY with a JSON object containing exactly two keys:
  - "spam_probability": a float between 0.0 and 1.0 where:
      0.0 = almost certainly a genuine, high-quality security report
      0.5 = borderline / uncertain
      1.0 = almost certainly spam, AI-generated, or low-quality
  - "reasoning": a concise (2-4 sentences) plain-English explanation of your
    assessment, noting which specific signals influenced the score.

Do NOT include any other text, markdown formatting, or keys in your response.
Respond with valid JSON only.

Signals that suggest SPAM / low quality:
- Generic or formulaic greetings ("Dear Security Team", "I hope this finds you well")
- Missing or vague reproduction steps
- No code blocks, HTTP requests, stack traces, or proof-of-concept evidence
- Boilerplate CVE template fields (Severity:, Remediation:, Affected versions:)
- Multiple high-severity claims without technical justification
- Very short body text with little technical detail
- Copy-pasted language that applies to any application generically

Signals that suggest LEGITIMATE reports:
- Specific version numbers, file paths, or endpoint URLs
- Working reproduction steps with concrete inputs and outputs
- Code samples, HTTP request/response pairs, or stack traces
- References to specific CVEs, CWEs, or OWASP categories with context
- Technical jargon used correctly and precisely
- Clear, bounded impact description with supporting evidence
"""

_USER_PROMPT_TEMPLATE = """\
Please evaluate the following GitHub security issue report.

--- ISSUE TITLE ---
{title}

--- ISSUE BODY ---
{body}

--- END OF ISSUE ---

Respond with a JSON object containing "spam_probability" and "reasoning".
"""

# Maximum body length sent to the LLM to avoid excessive token usage.
_MAX_BODY_CHARS = 4000
_MAX_TITLE_CHARS = 200

# Accepted probability value range.
_PROB_MIN = 0.0
_PROB_MAX = 1.0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _truncate(text: str, max_chars: int) -> str:
    """Truncate *text* to at most *max_chars* characters with an ellipsis.

    Args:
        text:      Input string.
        max_chars: Maximum allowed character count.

    Returns:
        The original string if it is within the limit, otherwise the first
        ``max_chars - 3`` characters followed by ``"..."``.
    """
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def _parse_llm_response(content: str, model: str) -> LLMResult:
    """Parse the raw LLM response string into an :class:`~bounty_guard.models.LLMResult`.

    Attempts to locate and parse a JSON object in *content*.  Handles cases
    where the model wraps the JSON in markdown fences despite instructions.

    Args:
        content: Raw string content from the LLM chat completion.
        model:   Name of the model that produced the response.

    Returns:
        A populated :class:`~bounty_guard.models.LLMResult`.  On parse
        failure returns ``LLMResult(skipped=True, error=...)``.  On
        out-of-range probability the value is clamped by the Pydantic model.
    """
    # Strip markdown fences if present.
    cleaned = content.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        # Remove opening and closing fence lines.
        inner_lines = []
        in_fence = False
        for line in lines:
            if line.startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence or not cleaned.startswith("```"):
                inner_lines.append(line)
        cleaned = "\n".join(inner_lines).strip()

    # Attempt to find the first JSON object.
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        logger.warning(
            "LLM response did not contain a JSON object. Raw: %r", content[:200]
        )
        return LLMResult(
            skipped=True,
            model=model,
            error=f"LLM response did not contain valid JSON: {content[:100]!r}",
        )

    json_str = cleaned[start : end + 1]
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse LLM JSON response: %s", exc)
        return LLMResult(
            skipped=True,
            model=model,
            error=f"JSON parse error: {exc}",
        )

    # Validate required keys.
    if "spam_probability" not in data:
        logger.warning("LLM JSON missing 'spam_probability' key: %s", data)
        return LLMResult(
            skipped=True,
            model=model,
            error="LLM JSON missing 'spam_probability' key.",
        )

    try:
        probability = float(data["spam_probability"])
    except (TypeError, ValueError) as exc:
        return LLMResult(
            skipped=True,
            model=model,
            error=f"Invalid spam_probability value: {exc}",
        )

    reasoning = str(data.get("reasoning", ""))

    return LLMResult(
        spam_probability=probability,  # clamped by Pydantic validator
        reasoning=reasoning,
        model=model,
        skipped=False,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify_issue(
    issue_body: Optional[str],
    issue_title: str = "",
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> LLMResult:
    """Classify a GitHub issue as spam or legitimate using the OpenAI API.

    When LLM classification is disabled (``LLM_ENABLED=false`` or
    *enabled=False*) the function returns immediately with
    ``LLMResult(skipped=True)`` without making any network calls.

    All exceptions from the OpenAI API are caught and returned as
    ``LLMResult(skipped=True, error=...)`` to avoid blocking the triage
    pipeline.

    Args:
        issue_body:  Raw Markdown body of the GitHub issue.  ``None`` is
                     treated as an empty string.
        issue_title: Title of the issue (used as additional context).
        api_key:     Override for the OpenAI API key.  When ``None`` the
                     value from application settings is used.
        model:       Override for the OpenAI model name.  When ``None`` the
                     value from application settings is used.
        enabled:     Override for the LLM-enabled flag.  When ``None`` the
                     value from application settings is used.

    Returns:
        An :class:`~bounty_guard.models.LLMResult` instance.  On success
        ``skipped=False`` and ``spam_probability`` is populated.  When
        disabled or on error ``skipped=True`` and ``error`` may be set.

    Example::

        result = classify_issue(
            issue_body="Dear team, critical RCE in all versions...",
            issue_title="RCE vulnerability",
        )
        if not result.skipped and result.spam_probability > 0.7:
            print("LLM flagged as spam:", result.reasoning)
    """
    # Resolve settings.
    _api_key, _model, _enabled = _resolve_settings(
        api_key=api_key, model=model, enabled=enabled
    )

    if not _enabled:
        logger.debug("LLM classification is disabled; skipping.")
        return LLMResult(skipped=True)

    if not _api_key:
        logger.warning(
            "LLM classification is enabled but no API key is configured; skipping."
        )
        return LLMResult(
            skipped=True,
            error="OpenAI API key not configured.",
        )

    body_text = _truncate(issue_body or "", _MAX_BODY_CHARS)
    title_text = _truncate(issue_title or "(no title)", _MAX_TITLE_CHARS)

    user_prompt = _USER_PROMPT_TEMPLATE.format(
        title=title_text,
        body=body_text,
    )

    try:
        client = OpenAI(api_key=_api_key)
        logger.debug(
            "Sending issue to LLM classifier (model=%s, body_len=%d)",
            _model,
            len(body_text),
        )
        response = client.chat.completions.create(
            model=_model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
            temperature=0.0,
            max_tokens=512,
        )
    except RateLimitError as exc:
        logger.warning("OpenAI rate limit exceeded: %s", exc)
        return LLMResult(
            skipped=True,
            model=_model,
            error=f"Rate limit exceeded: {exc}",
        )
    except APITimeoutError as exc:
        logger.warning("OpenAI API timeout: %s", exc)
        return LLMResult(
            skipped=True,
            model=_model,
            error=f"API timeout: {exc}",
        )
    except APIConnectionError as exc:
        logger.warning("OpenAI API connection error: %s", exc)
        return LLMResult(
            skipped=True,
            model=_model,
            error=f"Connection error: {exc}",
        )
    except APIError as exc:
        logger.warning("OpenAI API error: %s", exc)
        return LLMResult(
            skipped=True,
            model=_model,
            error=f"API error: {exc}",
        )
    except Exception as exc:  # pragma: no cover – unexpected errors
        logger.exception("Unexpected error during LLM classification: %s", exc)
        return LLMResult(
            skipped=True,
            model=_model,
            error=f"Unexpected error: {exc}",
        )

    # Extract content from the first choice.
    if not response.choices:
        logger.warning("LLM returned no choices in response.")
        return LLMResult(
            skipped=True,
            model=_model,
            error="LLM returned no choices.",
        )

    raw_content = response.choices[0].message.content or ""
    logger.debug("LLM raw response: %r", raw_content[:200])

    result = _parse_llm_response(raw_content, model=_model)
    logger.info(
        "LLM classification complete: spam_probability=%.3f skipped=%s",
        result.spam_probability,
        result.skipped,
    )
    return result


def _resolve_settings(
    api_key: Optional[str],
    model: Optional[str],
    enabled: Optional[bool],
) -> tuple[Optional[str], str, bool]:
    """Resolve LLM settings, falling back to application config.

    Attempts to import ``bounty_guard.config.settings`` for defaults.  If
    the import fails (e.g. in tests without env vars) safe defaults are used.

    Args:
        api_key: Caller-supplied API key override, or ``None``.
        model:   Caller-supplied model override, or ``None``.
        enabled: Caller-supplied enabled flag override, or ``None``.

    Returns:
        A 3-tuple ``(resolved_api_key, resolved_model, resolved_enabled)``.
    """
    _default_api_key: Optional[str] = None
    _default_model: str = "gpt-4o-mini"
    _default_enabled: bool = False

    try:
        from bounty_guard.config import settings as _settings

        if _settings is not None:
            _default_api_key = _settings.openai_api_key
            _default_model = _settings.openai_model
            _default_enabled = _settings.llm_enabled
    except Exception:
        pass  # Use hardcoded defaults.

    resolved_api_key = api_key if api_key is not None else _default_api_key
    resolved_model = model if model is not None else _default_model
    resolved_enabled = enabled if enabled is not None else _default_enabled

    return resolved_api_key, resolved_model, resolved_enabled
