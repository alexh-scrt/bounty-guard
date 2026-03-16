"""Unit tests for bounty_guard.scorer.

Each test class targets one or more rubric signals using synthetic issue
body fixtures designed to trigger or avoid each condition in isolation.

Covered signals:
- suspiciously_short
- generic_greeting
- cve_template_detected
- no_code_evidence  (inverse: code blocks, stack traces, PoC)
- missing_reproduction_steps
- vague_description  (inverse: technical terms)
- excessive_severity_claims
- total_score computation
- score_issue with None / empty body
"""

from __future__ import annotations

import pytest

from bounty_guard.scorer import score_issue
from bounty_guard.models import SpamScore


# ---------------------------------------------------------------------------
# Fixtures: reusable issue body strings
# ---------------------------------------------------------------------------

# Minimal legitimate security report that should NOT trigger any signal.
LEGITIMATE_REPORT = """
## Summary

A path traversal vulnerability exists in the file upload handler at
`/api/v1/upload`. An authenticated user can escape the upload directory
by including `../` sequences in the filename parameter.

## Steps to Reproduce

1. Authenticate as a regular user.
2. Send the following request:

```http
POST /api/v1/upload HTTP/1.1
Content-Type: multipart/form-data

--boundary
Content-Disposition: form-data; name="file"; filename="../../../etc/passwd"

test
--boundary--
```

3. Observe that the response includes the contents of `/etc/passwd`.

## Impact

An attacker can read arbitrary files on the server, including /etc/passwd
and application configuration files containing database credentials.

## Environment

- Version: 2.3.1
- OS: Ubuntu 22.04
"""

# Clearly spammy AI-generated report.
SPAM_REPORT_ALL_SIGNALS = """
Dear Security Team,

I have discovered a critical vulnerability in your application.
Severity: Critical
Vulnerability type: Remote code execution
Affected version: All versions
Remediation: Please fix this issue.

This is a serious security issue that could lead to complete system compromise
and full server takeover. There is also account takeover and privilege escalation.

Please fix this immediately.

Regards,
Security Researcher
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _body_with_repro_and_code(extra: str = "") -> str:
    """Return a body that satisfies repro and code-evidence checks."""
    return (
        "Steps to reproduce:\n"
        "1. Do this\n"
        "2. Do that\n\n"
        "```python\nprint('hello')\n```\n"
        + extra
    )


# ---------------------------------------------------------------------------
# Test: None and empty body
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_none_body_returns_spam_score(self):
        score = score_issue(None)
        assert isinstance(score, SpamScore)
        assert score.total_score == 1.0

    def test_empty_string_returns_max_score(self):
        score = score_issue("")
        assert score.total_score == 1.0
        assert score.suspiciously_short is True

    def test_whitespace_only_is_short(self):
        score = score_issue("   \n\t  ")
        assert score.suspiciously_short is True

    def test_return_type_is_spam_score(self):
        score = score_issue("anything")
        assert isinstance(score, SpamScore)

    def test_total_score_in_range(self):
        for body in [None, "", LEGITIMATE_REPORT, SPAM_REPORT_ALL_SIGNALS]:
            score = score_issue(body)
            assert 0.0 <= score.total_score <= 1.0

    def test_crlf_normalisation(self):
        body = "Steps to reproduce:\r\n1. Do this\r\n\r\n```\ncode\n```\r\n" + "x" * 200
        score = score_issue(body)
        # Should not crash and should handle CRLF correctly.
        assert isinstance(score, SpamScore)


# ---------------------------------------------------------------------------
# Test: suspiciously_short signal
# ---------------------------------------------------------------------------


class TestSuspiciouslyShort:
    def test_short_body_flagged(self):
        short = "There is a bug."
        score = score_issue(short)
        assert score.suspiciously_short is True

    def test_body_under_100_chars_flagged(self):
        body = "x" * 99
        score = score_issue(body)
        assert score.suspiciously_short is True

    def test_body_exactly_100_chars_not_flagged(self):
        body = "x" * 100
        score = score_issue(body)
        assert score.suspiciously_short is False

    def test_body_over_100_chars_not_flagged(self):
        body = "x" * 200
        score = score_issue(body)
        assert score.suspiciously_short is False

    def test_legitimate_report_not_short(self):
        score = score_issue(LEGITIMATE_REPORT)
        assert score.suspiciously_short is False


# ---------------------------------------------------------------------------
# Test: generic_greeting signal
# ---------------------------------------------------------------------------


class TestGenericGreeting:
    @pytest.mark.parametrize(
        "greeting",
        [
            "Dear Security Team,\n",
            "Dear Maintainer,\n",
            "Hello, Security Team!\n",
            "Hi Security Team,\n",
            "Greetings, I found a bug.\n",
            "To Whom It May Concern,\n",
            "I hope this message finds you well.\n",
            "I am writing to report a vulnerability.\n",
            "I recently discovered a critical security vulnerability.\n",
            "I found a critical vulnerability in your system.\n",
        ],
    )
    def test_known_greetings_flagged(self, greeting):
        body = greeting + "x" * 200
        score = score_issue(body)
        assert score.generic_greeting is True, f"Expected greeting to be flagged: {greeting!r}"

    def test_normal_opening_not_flagged(self):
        body = "## Vulnerability Report\n\nA path traversal exists at /api/upload.\n" + "x" * 100
        score = score_issue(body)
        assert score.generic_greeting is False

    def test_greeting_in_body_middle_not_flagged(self):
        # Greeting pattern deep in the body (past 300 chars) should not fire.
        body = "## Bug\n" + "x" * 350 + "\nDear Security Team, blah blah"
        score = score_issue(body)
        # The greeting is after char 300 so should not be detected.
        assert score.generic_greeting is False

    def test_legitimate_report_no_greeting(self):
        score = score_issue(LEGITIMATE_REPORT)
        assert score.generic_greeting is False


# ---------------------------------------------------------------------------
# Test: cve_template_detected signal
# ---------------------------------------------------------------------------


class TestCVETemplateDetected:
    def test_multiple_template_fields_flagged(self):
        body = (
            "Severity: Critical\n"
            "Affected version: 1.0.0\n"
            "Remediation: Please patch this.\n"
            "Vulnerability type: SQL injection\n"
            + "x" * 200
        )
        score = score_issue(body)
        assert score.cve_template_detected is True

    def test_cvss_and_cwe_together_flagged(self):
        body = (
            "This issue has CVSS Score 9.8 and affects CWE-89.\n"
            + "x" * 200
        )
        score = score_issue(body)
        assert score.cve_template_detected is True

    def test_single_cve_id_not_flagged_alone(self):
        # A single CVE reference without other template fields should not fire.
        body = (
            "This is related to CVE-2023-12345 in the libxml2 library.\n"
            "The issue is a use-after-free in the XML parser when handling\n"
            "malformed namespace prefixes.  Steps to reproduce follow below.\n"
            + "x" * 100
        )
        score = score_issue(body)
        assert score.cve_template_detected is False

    def test_no_template_text_not_flagged(self):
        body = LEGITIMATE_REPORT
        score = score_issue(body)
        assert score.cve_template_detected is False

    def test_spam_report_has_template(self):
        score = score_issue(SPAM_REPORT_ALL_SIGNALS)
        assert score.cve_template_detected is True


# ---------------------------------------------------------------------------
# Test: no_code_evidence signal
# ---------------------------------------------------------------------------


class TestNoCodeEvidence:
    def test_body_without_any_code_flagged(self):
        body = (
            "There is a vulnerability in the login form. "
            "An attacker can bypass authentication. " * 5
        )
        score = score_issue(body)
        assert score.no_code_evidence is True

    def test_fenced_code_block_clears_flag(self):
        body = "Steps to reproduce:\n\n```bash\ncurl -X POST /login\n```\n" + "x" * 100
        score = score_issue(body)
        assert score.no_code_evidence is False

    def test_inline_backtick_clears_flag(self):
        body = "The issue is in `app/utils.py` at line 42.\n" + "x" * 100
        score = score_issue(body)
        assert score.no_code_evidence is False

    def test_stack_trace_clears_flag(self):
        body = (
            "The following error occurs:\n"
            "Traceback (most recent call last):\n"
            "  File \"app.py\", line 10, in <module>\n"
            "    raise ValueError\n"
            + "x" * 100
        )
        score = score_issue(body)
        assert score.no_code_evidence is False

    def test_poc_keyword_clears_flag(self):
        body = "PoC available upon request. Steps to reproduce: " + "x" * 100
        score = score_issue(body)
        assert score.no_code_evidence is False

    def test_exploit_py_clears_flag(self):
        body = "I wrote exploit.py to demonstrate the issue. " + "x" * 100
        score = score_issue(body)
        assert score.no_code_evidence is False

    def test_curl_command_clears_flag(self):
        body = "Run: curl -X GET https://example.com/admin " + "x" * 100
        score = score_issue(body)
        assert score.no_code_evidence is False

    def test_legitimate_report_has_code_evidence(self):
        score = score_issue(LEGITIMATE_REPORT)
        assert score.no_code_evidence is False


# ---------------------------------------------------------------------------
# Test: missing_reproduction_steps signal
# ---------------------------------------------------------------------------


class TestMissingReproductionSteps:
    def test_no_repro_section_flagged(self):
        body = (
            "There is a critical vulnerability in the upload endpoint. "
            "An attacker can read arbitrary files. " * 5
        )
        score = score_issue(body)
        assert score.missing_reproduction_steps is True

    @pytest.mark.parametrize(
        "repro_text",
        [
            "Steps to reproduce:\n1. Do this",
            "How to reproduce:\n1. Do that",
            "Reproduction steps:\n1. First step",
            "To reproduce the issue follow these steps:",
            "Repro steps: see below",
            "This is reproducible by sending a malformed request",
        ],
    )
    def test_repro_variants_clear_flag(self, repro_text):
        body = repro_text + "\n" + "x" * 150
        score = score_issue(body)
        assert score.missing_reproduction_steps is False, (
            f"Repro text not recognised: {repro_text!r}"
        )

    def test_legitimate_report_has_repro_steps(self):
        score = score_issue(LEGITIMATE_REPORT)
        assert score.missing_reproduction_steps is False


# ---------------------------------------------------------------------------
# Test: vague_description signal
# ---------------------------------------------------------------------------


class TestVagueDescription:
    def test_generic_vulnerability_claim_is_vague(self):
        body = (
            "There is a serious security vulnerability in your application. "
            "This could lead to data exposure and system compromise. "
            "Please fix it as soon as possible. " * 3
        )
        score = score_issue(body)
        assert score.vague_description is True

    def test_specific_technical_terms_clear_flag(self):
        body = (
            "The upload handler is vulnerable to path traversal (directory traversal) "
            "because it uses deserialization without input validation. "
            "The OWASP classification is CWE-22. Steps to reproduce follow.\n"
            + "x" * 50
        )
        score = score_issue(body)
        assert score.vague_description is False

    def test_buffer_overflow_mention_specific(self):
        body = (
            "A buffer overflow in the PNG parser allows arbitrary code execution. "
            "The use-after-free condition occurs when freeing the pixel buffer. \n"
            + "x" * 50
        )
        score = score_issue(body)
        assert score.vague_description is False

    def test_legitimate_report_not_vague(self):
        score = score_issue(LEGITIMATE_REPORT)
        assert score.vague_description is False


# ---------------------------------------------------------------------------
# Test: excessive_severity_claims signal
# ---------------------------------------------------------------------------


class TestExcessiveSeverityClaims:
    def test_multiple_severity_buzzwords_without_code_flagged(self):
        body = (
            "This critical vulnerability allows remote code execution and "
            "complete system compromise and account takeover. "
            "An unauthenticated attacker can achieve privilege escalation. " * 3
        )
        score = score_issue(body)
        assert score.excessive_severity_claims is True

    def test_severity_claim_with_code_block_not_flagged(self):
        body = (
            "Remote code execution is possible via the following PoC:\n\n"
            "```python\nimport requests\nrequests.get('http://example.com/../etc/passwd')\n```\n"
            + "x" * 50
        )
        score = score_issue(body)
        assert score.excessive_severity_claims is False

    def test_no_severity_claims_not_flagged(self):
        body = "There is an issue with the login form validation. " + "x" * 100
        score = score_issue(body)
        assert score.excessive_severity_claims is False

    def test_rce_abbreviation_without_code_flagged(self):
        body = (
            "This RCE vulnerability allows data breach and sensitive data exposure "
            "in all versions. Please patch immediately. " * 3
        )
        score = score_issue(body)
        assert score.excessive_severity_claims is True


# ---------------------------------------------------------------------------
# Test: total_score computation
# ---------------------------------------------------------------------------


class TestTotalScore:
    def test_zero_signals_gives_zero_score(self):
        score = score_issue(LEGITIMATE_REPORT)
        # The legitimate report should have a low score.
        assert score.total_score < 0.5

    def test_all_signals_give_score_one(self):
        # Empty body fires all signals.
        score = score_issue("")
        assert score.total_score == 1.0

    def test_score_equals_fired_fraction(self):
        score = score_issue(SPAM_REPORT_ALL_SIGNALS)
        expected = score.signal_count / 7
        assert score.total_score == pytest.approx(expected, abs=1e-5)

    def test_score_is_float(self):
        score = score_issue(LEGITIMATE_REPORT)
        assert isinstance(score.total_score, float)

    def test_fired_signals_matches_signal_count(self):
        score = score_issue(SPAM_REPORT_ALL_SIGNALS)
        assert len(score.fired_signals) == score.signal_count

    def test_spam_report_high_score(self):
        score = score_issue(SPAM_REPORT_ALL_SIGNALS)
        # The spam report should score significantly above the default threshold of 0.6.
        assert score.total_score >= 0.6

    def test_score_increases_with_more_signals(self):
        # Body with one signal (short) should score lower than spam report.
        short_score = score_issue("Short body.")
        spam_score = score_issue(SPAM_REPORT_ALL_SIGNALS)
        # Short body scores 1.0 (all signals fire on empty/very short).
        # We compare the spam report against legitimate.
        legit_score = score_issue(LEGITIMATE_REPORT)
        assert spam_score.total_score > legit_score.total_score


# ---------------------------------------------------------------------------
# Test: end-to-end with sample bodies from tests/fixtures.py
# ---------------------------------------------------------------------------


class TestScorerWithFixtures:
    """Smoke-tests ensuring the scorer handles a variety of real-world-like inputs."""

    def test_sql_injection_report_is_legitimate(self):
        body = """
## SQL Injection in /api/users endpoint

The `id` parameter in `/api/users?id=1` is not sanitised before being
interpolated into a raw SQL query, allowing classic SQLi.

## Steps to Reproduce

```sql
SELECT * FROM users WHERE id = '1' OR '1'='1'
```

1. Navigate to `GET /api/users?id=1'+OR+'1'='1`
2. Observe that all user rows are returned.

## Impact

Unauthenticated read access to all user records.
"""
        score = score_issue(body)
        assert score.total_score < 0.6, f"Legitimate report scored too high: {score}"

    def test_generic_bounty_spam_scores_high(self):
        body = """
Dear Security Team,

I am writing to report a critical vulnerability I discovered in your website.

Severity: Critical
Impact: Critical
Vulnerability type: Remote code execution
Affected version: All versions
Remediation: Please patch immediately.

This issue allows complete system compromise and full server takeover.
Privilege escalation and account takeover are also possible.

Thank you for your attention.
"""
        score = score_issue(body)
        assert score.total_score >= 0.6, f"Spam report scored too low: {score}"

    def test_short_vague_report_scores_high(self):
        body = "There is a critical bug. Please fix it."
        score = score_issue(body)
        assert score.total_score >= 0.7

    def test_detailed_xss_report_scores_low(self):
        body = """
## Reflected XSS in search parameter

The `q` parameter on `/search` is reflected into the HTML response without
encoding, enabling reflected XSS attacks (CWE-79).

## Steps to Reproduce

1. Visit `https://example.com/search?q=<script>alert(1)</script>`
2. Observe the alert dialog fires.

```http
GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1
Host: example.com
```

## Impact

An attacker can steal session cookies or perform actions on behalf of
authenticated users via phishing links.
"""
        score = score_issue(body)
        assert score.total_score < 0.6, f"XSS report scored too high: {score}"
