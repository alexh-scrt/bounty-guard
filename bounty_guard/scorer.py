"""Rule-based spam scoring rubric for security issue reports.

This module analyses the plain text of a GitHub issue body and returns a
:class:`~bounty_guard.models.SpamScore` dataclass that breaks down which
spam signals fired and provides an overall ``total_score`` in [0.0, 1.0].

Scoring signals (equal weight unless noted):

1. ``vague_description``         - Body lacks specific technical terms.
2. ``missing_reproduction_steps`` - No reproduction / steps-to-reproduce section.
3. ``cve_template_detected``      - Boilerplate CVE template text is present.
4. ``no_code_evidence``           - No code blocks, stack traces, or PoC fragments.
5. ``excessive_severity_claims``  - Unsupported high-severity buzzwords without
                                    supporting technical evidence.
6. ``generic_greeting``           - Body opens with a generic greeting typical of
                                    AI-generated or copy-pasted content.
7. ``suspiciously_short``         - Body is far too short to contain a real report.

All signals carry equal weight.  The total score is the fraction of signals
that fired: ``signal_count / TOTAL_SIGNALS``.

Example usage::

    from bounty_guard.scorer import score_issue

    spam_score = score_issue(issue_body)
    if spam_score.total_score >= 0.6:
        print("Suspected spam:", spam_score.fired_signals)
"""

from __future__ import annotations

import logging
import re
from typing import Final

from bounty_guard.models import SpamScore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Total number of boolean signals.  Used to compute total_score.
_TOTAL_SIGNALS: Final[int] = 7

# Minimum character count for a body not to be flagged as suspiciously short.
_MIN_BODY_LENGTH: Final[int] = 100

# Minimum number of "technical" keyword matches required to avoid the
# vague_description flag.
_MIN_TECHNICAL_TERM_COUNT: Final[int] = 2

# ---------------------------------------------------------------------------
# Compiled regular expressions
# ---------------------------------------------------------------------------

# Matches a markdown or fenced code block (``` ... ``` or ~~~...~~~) or an
# indented code block (4-space / tab prefix), or an inline backtick span.
_RE_CODE_BLOCK: Final[re.Pattern[str]] = re.compile(
    r"(?:```[\s\S]*?```|~~~[\s\S]*?~~~|(?:^(?:    |\t).+$)+|`[^`\n]+`)",
    re.MULTILINE,
)

# Matches common stack-trace indicators across languages.
_RE_STACK_TRACE: Final[re.Pattern[str]] = re.compile(
    r"(?:"
    r"Traceback \(most recent call last\)"
    r"|at \S+\.\w+\(\S+:\d+\)"
    r"|\bat\s+\w[\w.$]+\(\w.*?:\d+\)"
    r"|Exception in thread"
    r"|\bStackTrace\b"
    r"|\bstack trace\b"
    r")",
    re.IGNORECASE,
)

# Matches Proof-of-Concept / exploit script indicators.
_RE_POC_INDICATOR: Final[re.Pattern[str]] = re.compile(
    r"(?:"
    r"\bPoC\b"
    r"|proof[- ]of[- ]concept"
    r"|exploit\.py"
    r"|payload\s*[:=]"
    r"|\bcurl\s+-"
    r"|\bnmap\b"
    r"|\bsqlmap\b"
    r"|\bburpsuite\b"
    r"|\bmetasploit\b"
    r"|\$ \S+"
    r")",
    re.IGNORECASE,
)

# Reproduction steps section header patterns.
_RE_REPRO_SECTION: Final[re.Pattern[str]] = re.compile(
    r"(?:"
    r"(?:steps?\s+to\s+(?:reproduce|replicate))"
    r"|(?:how\s+to\s+reproduce)"
    r"|(?:reproduction\s+steps?)"
    r"|(?:repro\s+steps?)"
    r"|(?:to\s+reproduce)"
    r"|(?:reproduc(?:e|tion|ible))"
    r")",
    re.IGNORECASE,
)

# Generic greetings typical of AI-generated or template content.
_RE_GENERIC_GREETING: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:"
    r"dear\s+(?:security\s+)?team"
    r"|dear\s+(?:maintainer|developer|admin|sir|madam)"
    r"|hello[,!\s]+(?:security\s+)?team"
    r"|hi[,!\s]+(?:security\s+)?team"
    r"|greetings[,!\s]"
    r"|to\s+whom\s+it\s+may\s+concern"
    r"|i\s+hope\s+this\s+(?:message|email|report)\s+finds\s+you"
    r"|i\s+am\s+writing\s+to\s+report"
    r"|i\s+(?:recently\s+)?(?:discovered|found|identified)\s+a\s+(?:critical|severe|serious)?"
    r"\s*(?:security\s+)?vulnerability"
    r")",
    re.IGNORECASE | re.MULTILINE,
)

# CVE / bounty template boilerplate indicators.
_RE_CVE_TEMPLATE: Final[re.Pattern[str]] = re.compile(
    r"(?:"
    r"CVE-\d{4}-\d{4,7}"\                   # CVE identifier
    r"|CVSS\s*(?:Score|v\d)"\               # CVSS score mention
    r"|CWE-\d+"\                            # CWE identifier
    r"|\baffected\s+version(?:s)?\s*:"\     # template field
    r"|\bimpact\s*:\s*(?:critical|high|medium|low)"
    r"|\bremediation\s*:"\                  # template field
    r"|\bvulnerability\s+type\s*:"\         # template field
    r"|\bseverity\s*:\s*(?:critical|high|medium|low|info)"
    r"|\bproof\s+of\s+concept\s*:"\         # template field
    r"|\breferences?\s*:\s*\n\s*-\s*http"  # link list typical of templates
    r")",
    re.IGNORECASE,
)

# High-severity buzzwords that often appear in spam without supporting detail.
_RE_SEVERITY_BUZZWORDS: Final[re.Pattern[str]] = re.compile(
    r"\b(?:"
    r"critical\s+(?:vulnerability|issue|bug|flaw|security\s+flaw)"
    r"|remote\s+code\s+execution"
    r"|\bRCE\b"
    r"|arbitrary\s+code\s+execution"
    r"|full\s+(?:system|server|database)\s+(?:compromise|access|takeover)"
    r"|complete\s+(?:takeover|compromise|access)"
    r"|account\s+takeover"
    r"|authentication\s+bypass"
    r"|privilege\s+escalation"
    r"|zero[- ]day"
    r"|data\s+breach"
    r"|sensitive\s+data\s+(?:exposure|leak|exfiltration)"
    r"|unauthenticated\s+(?:access|rce|ssrf|idor)"
    r"|\bSSRF\b"
    r"|\bSQLi\b"
    r"|\bXSS\b"
    r"|\bIDOR\b"
    r"|path\s+traversal"
    r"|directory\s+traversal"
    r"|insecure\s+direct\s+object"
    r"|broken\s+access\s+control"
    r"|hardcoded\s+(?:secret|credential|password|key|token)"
    r"|exposed\s+(?:secret|credential|password|api\s+key)"
    r")",
    re.IGNORECASE,
)

# Technical specificity keywords: language-level, network, or security terms
# that suggest the author understands what they're reporting.
_RE_TECHNICAL_TERMS: Final[re.Pattern[str]] = re.compile(
    r"\b(?:"
    # Programming / runtime
    r"null\s+(?:pointer|dereference|reference)"
    r"|use[- ]after[- ]free"
    r"|buffer\s+overflow"
    r"|heap\s+(?:overflow|spray|corruption)"
    r"|stack\s+(?:overflow|smashing|canary)"
    r"|integer\s+overflow"
    r"|format\s+string"
    r"|race\s+condition"
    r"|type\s+confusion"
    r"|deserialization"
    r"|deserializ"
    r"|prototype\s+pollution"
    r"|command\s+injection"
    r"|code\s+injection"
    r"|template\s+injection"
    r"|SSTI"
    r"|XXE"
    r"|CSRF"
    r"|open\s+redirect"
    r"|header\s+injection"
    r"|CRLF"
    r"|HTTP\s+(?:request\s+smuggling|splitting)"
    r"|regex\s+(?:denial|DoS|ReDoS)"
    r"|ReDoS"
    # Network / protocol
    r"|TCP\/IP"
    r"|TLS\s+\d"
    r"|certificate\s+(?:pinning|validation|chain)"
    r"|DNS\s+(?:rebinding|poisoning|hijacking)"
    r"|ARP\s+(?:spoofing|poisoning)"
    r"|MITM"
    r"|man-in-the-middle"
    # Specific tools / identifiers
    r"|CVE-\d{4}-\d+"
    r"|CWE-\d+"
    r"|OWASP"
    r"|CVSS"
    # File / memory forensics
    r"|\bmemcpy\b"
    r"|\bmalloc\b"
    r"|\bfree\(\)"
    r"|\bsprintf\b"
    r"|\bgets\b"
    r"|\bstrcpy\b"
    r"|gadget\s+chain"
    r"|ROP\s+chain"
    r"|shellcode"
    r"|return\s+oriented"
    # Endpoints / configuration
    r"|/etc/passwd"
    r"|/proc/self"
    r"|\.\.[\\/]"
    r"|127\.0\.0\.1"
    r"|localhost:\d"
    r"|(?:GET|POST|PUT|DELETE|PATCH)\s+\/\S+"
    r"|HTTP\/\d\.\d"
    r"|Content-Type:"
    r"|Authorization:\s+Bearer"
    r"|X-Forwarded-For"
    r")",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Individual signal detectors
# ---------------------------------------------------------------------------


def _detect_suspiciously_short(body: str) -> bool:
    """Return True when the stripped body is shorter than the minimum length.

    Args:
        body: Stripped issue body text.

    Returns:
        True if the body has fewer than :data:`_MIN_BODY_LENGTH` characters.
    """
    return len(body.strip()) < _MIN_BODY_LENGTH


def _detect_generic_greeting(body: str) -> bool:
    """Return True when the body opens with a generic templated greeting.

    The check is applied only to the first 300 characters of the body to
    avoid false positives in longer, detailed reports.

    Args:
        body: Issue body text.

    Returns:
        True if a generic greeting pattern is found near the start.
    """
    head = body[:300]
    return bool(_RE_GENERIC_GREETING.search(head))


def _detect_cve_template(body: str) -> bool:
    """Return True when boilerplate CVE / vulnerability template text is found.

    A single CVE/CWE identifier is not necessarily spam; we look for *two or
    more* template-style field markers (``Severity:``, ``Remediation:``, etc.)
    OR a bare CVE ID combined with at least one template field.

    Args:
        body: Issue body text.

    Returns:
        True if template boilerplate is detected.
    """
    matches = _RE_CVE_TEMPLATE.findall(body)
    # More than one distinct template-field match indicates copy-paste.
    return len(matches) >= 2


def _detect_no_code_evidence(body: str) -> bool:
    """Return True when the body contains no code blocks, traces, or PoC hints.

    Legitimate security reports almost always include at least one of:
    - A fenced/indented code block or inline backtick span
    - A stack trace
    - A Proof-of-Concept indicator

    Args:
        body: Issue body text.

    Returns:
        True if none of the above evidence types are found.
    """
    has_code = bool(_RE_CODE_BLOCK.search(body))
    has_trace = bool(_RE_STACK_TRACE.search(body))
    has_poc = bool(_RE_POC_INDICATOR.search(body))
    return not (has_code or has_trace or has_poc)


def _detect_missing_reproduction_steps(body: str) -> bool:
    """Return True when the body contains no reproduction steps section.

    Args:
        body: Issue body text.

    Returns:
        True if no recognisable reproduction-steps pattern is found.
    """
    return not bool(_RE_REPRO_SECTION.search(body))


def _detect_vague_description(body: str) -> bool:
    """Return True when the body lacks specific technical terminology.

    The heuristic counts the number of distinct technical-term matches.  If
    fewer than :data:`_MIN_TECHNICAL_TERM_COUNT` distinct terms appear, the
    description is considered vague.

    Args:
        body: Issue body text.

    Returns:
        True if the body contains fewer than the required technical terms.
    """
    matches = _RE_TECHNICAL_TERMS.findall(body)
    # Normalise matches to lower-case strings and count unique occurrences.
    unique_terms = {m.strip().lower() for m in matches if m.strip()}
    return len(unique_terms) < _MIN_TECHNICAL_TERM_COUNT


def _detect_excessive_severity_claims(body: str, has_code_evidence: bool) -> bool:
    """Return True when high-severity buzzwords appear without code evidence.

    A single severity claim backed by a code sample is acceptable.  The flag
    fires when *multiple* severity buzzwords appear AND there is no code
    evidence in the body (relying on :func:`_detect_no_code_evidence` result).

    Args:
        body:             Issue body text.
        has_code_evidence: True when code evidence was found (inverse of
                           :func:`_detect_no_code_evidence`).

    Returns:
        True if the body makes unsupported severity claims.
    """
    severity_matches = _RE_SEVERITY_BUZZWORDS.findall(body)
    if not severity_matches:
        return False
    # Multiple distinct high-severity claims without code evidence is suspicious.
    unique_claims = {m.strip().lower() for m in severity_matches}
    if len(unique_claims) >= 2 and not has_code_evidence:
        return True
    # Single claim is acceptable; only flag when no supporting code.
    if len(unique_claims) >= 1 and not has_code_evidence:
        # Only flag if the body is also vague (no technical terms).
        technical_matches = _RE_TECHNICAL_TERMS.findall(body)
        unique_technical = {m.strip().lower() for m in technical_matches if m.strip()}
        if len(unique_technical) < _MIN_TECHNICAL_TERM_COUNT:
            return True
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def score_issue(issue_body: str | None) -> SpamScore:
    """Analyse an issue body and return a per-signal :class:`~bounty_guard.models.SpamScore`.

    The function is intentionally stateless and side-effect free so it can be
    called concurrently from async request handlers without any locking.

    Scoring algorithm:
        Each of the seven boolean signals is evaluated independently.  The
        ``total_score`` is computed as ``fired_signal_count / _TOTAL_SIGNALS``
        and clamped to [0.0, 1.0].

    Args:
        issue_body: The raw Markdown body text of the GitHub issue.  ``None``
                    and empty strings both result in every signal firing
                    (score 1.0).

    Returns:
        A :class:`~bounty_guard.models.SpamScore` instance with all signal
        fields populated and ``total_score`` set.

    Example::

        score = score_issue("")
        assert score.total_score == 1.0

        score = score_issue("steps to reproduce: ...\n```python\nprint()\n```")
        assert score.suspiciously_short is False
    """
    # Treat None as an empty string; normalise line endings.
    body: str = (issue_body or "").replace("\r\n", "\n").replace("\r", "\n")

    # Compute code-evidence once so both no_code_evidence and
    # excessive_severity_claims can reuse the result.
    has_code = bool(_RE_CODE_BLOCK.search(body))
    has_trace = bool(_RE_STACK_TRACE.search(body))
    has_poc = bool(_RE_POC_INDICATOR.search(body))
    code_evidence_present = has_code or has_trace or has_poc

    suspiciously_short = _detect_suspiciously_short(body)
    generic_greeting = _detect_generic_greeting(body)
    cve_template_detected = _detect_cve_template(body)
    no_code_evidence = not code_evidence_present
    missing_reproduction_steps = _detect_missing_reproduction_steps(body)
    vague_description = _detect_vague_description(body)
    excessive_severity_claims = _detect_excessive_severity_claims(
        body, has_code_evidence=code_evidence_present
    )

    fired_count = sum(
        [
            suspiciously_short,
            generic_greeting,
            cve_template_detected,
            no_code_evidence,
            missing_reproduction_steps,
            vague_description,
            excessive_severity_claims,
        ]
    )
    total_score = round(fired_count / _TOTAL_SIGNALS, 6)

    spam_score = SpamScore(
        vague_description=vague_description,
        missing_reproduction_steps=missing_reproduction_steps,
        cve_template_detected=cve_template_detected,
        no_code_evidence=no_code_evidence,
        excessive_severity_claims=excessive_severity_claims,
        generic_greeting=generic_greeting,
        suspiciously_short=suspiciously_short,
        total_score=total_score,
    )

    logger.debug(
        "Scored issue: total_score=%.3f signals=%s",
        spam_score.total_score,
        spam_score.fired_signals,
    )
    return spam_score
