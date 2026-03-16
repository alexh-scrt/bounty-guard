# BountyGuard

**BountyGuard** is a GitHub App that automatically triages incoming security issue reports on open-source repositories. It scores each report against a spam-detection rubric designed to catch AI-generated or low-quality submissions, applies labels to suspicious reports, and optionally holds them from maintainer notification. An optional LLM classification layer (powered by the OpenAI API) provides a second-opinion score with human-readable reasoning.

Maintainers get a clean dashboard of flagged vs. legitimate reports — giving them back control over their bug bounty inboxes without shutting down their security programs entirely.

---

## Table of Contents

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Quick Start](#quick-start)
- [GitHub App Setup](#github-app-setup)
- [Environment Variable Reference](#environment-variable-reference)
- [Scoring Rubric Documentation](#scoring-rubric-documentation)
- [LLM Classifier](#llm-classifier)
- [Dashboard API](#dashboard-api)
- [Development](#development)
- [Running Tests](#running-tests)
- [Deployment](#deployment)
- [Security Considerations](#security-considerations)

---

## Features

- **Rule-based spam scoring rubric** — Detects vague descriptions, missing reproduction steps, CVE template copy-paste, no code evidence, and unsupported severity claims. Each signal is individually tracked with a per-signal score breakdown.
- **Optional LLM second-opinion classifier** — Calls the OpenAI Chat Completions API to produce a spam probability and human-readable reasoning string alongside the rule-based score.
- **GitHub App webhook integration** — Automatically applies configurable labels (e.g. `spam-suspected`) and posts a templated clarification comment on flagged issues.
- **SQLite-backed triage history** — Maintainers can review past decisions, adjust thresholds, and retriage issues after updating configuration.
- **HMAC-SHA256 webhook signature verification** — All incoming webhook deliveries are cryptographically verified before processing.
- **Environment-driven configuration** — Zero-trust deployment with all secrets loaded from environment variables.
- **Paginated dashboard endpoint** — `GET /dashboard` returns triage history with optional filters for repository and decision type.

---

## Architecture Overview

```
GitHub Webhook
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  POST /webhook  (bounty_guard/app.py)               │
│                                                     │
│  1. HMAC-SHA256 signature verification              │
│  2. Parse JSON payload                              │
│  3. Route issues:opened / issues:reopened events   │
└─────────────────────────┬───────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│  TriageOrchestrator  (bounty_guard/triage.py)       │
│                                                     │
│  ┌───────────────────┐  ┌──────────────────────┐   │
│  │  Rule-based Scorer│  │  LLM Classifier      │   │
│  │  (scorer.py)      │  │  (llm_classifier.py) │   │
│  │                   │  │  [optional]          │   │
│  │  SpamScore with   │  │  LLMResult with      │   │
│  │  7 signal flags   │  │  spam_probability    │   │
│  └─────────┬─────────┘  └──────────┬───────────┘   │
│            └──────────┬────────────┘               │
│                       │                             │
│              Combined Decision                      │
│              (any | all mode)                       │
│                       │                             │
│              ┌────────▼────────┐                   │
│              │  GitHubClient   │                   │
│              │  Apply label    │                   │
│              │  Post comment   │                   │
│              └────────┬────────┘                   │
│                       │                             │
│              ┌────────▼────────┐                   │
│              │  TriageRepository│                  │
│              │  (SQLite)        │                  │
│              └─────────────────┘                   │
└─────────────────────────────────────────────────────┘
```

**Data flow:**

1. GitHub delivers a webhook `POST /webhook` signed with HMAC-SHA256.
2. `webhook_validator.py` verifies the signature.
3. For `issues:opened` and `issues:reopened` events, the `TriageOrchestrator` is invoked.
4. `scorer.py` evaluates the issue body against seven spam signals.
5. `llm_classifier.py` optionally calls the OpenAI API for a second opinion.
6. A final `TriageDecision` (`spam` / `legitimate` / `uncertain`) is derived.
7. `github_client.py` applies a label and posts a comment if the issue is flagged.
8. The result is persisted to SQLite via `TriageRepository`.
9. Maintainers query `GET /dashboard` to review triage history.

---

## Quick Start

### Prerequisites

- Python 3.11 or later
- A GitHub App installed on your repository (see [GitHub App Setup](#github-app-setup))
- (Optional) An OpenAI API key for the LLM classifier

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/bounty-guard.git
cd bounty-guard

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install the package and runtime dependencies
pip install -e .

# Install development dependencies (for tests)
pip install -e ".[dev]"
```

### Minimal Configuration

Create a `.env` file in the project root with the required variables:

```dotenv
# Required
GITHUB_WEBHOOK_SECRET=your-webhook-secret-here
GITHUB_APP_ID=123456
GITHUB_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----
GITHUB_INSTALLATION_ID=78901234

# Optional: enable LLM classifier
LLM_ENABLED=false
# OPENAI_API_KEY=sk-...
```

> **Note:** Multi-line PEM keys can be represented with literal `\n` sequences in the `.env` file. BountyGuard automatically expands them.

### Start the Server

```bash
# Using the CLI entry point
bounty-guard

# Or directly with Uvicorn
uvicorn bounty_guard.app:app --host 0.0.0.0 --port 8000

# Or via Python
python -m bounty_guard.app
```

Verify the server is running:

```bash
curl http://localhost:8000/health
# {"status": "ok", "version": "0.1.0"}
```

---

## GitHub App Setup

### 1. Create the GitHub App

1. Go to **GitHub Settings → Developer settings → GitHub Apps → New GitHub App**.
2. Fill in the required fields:
   - **GitHub App name:** `BountyGuard` (or your preferred name)
   - **Homepage URL:** Your server URL
   - **Webhook URL:** `https://your-server.example.com/webhook`
   - **Webhook secret:** Generate a strong random secret (e.g. `openssl rand -hex 32`) — this becomes `GITHUB_WEBHOOK_SECRET`
3. Set **Permissions**:
   - **Issues:** Read & Write (to apply labels and post comments)
   - **Metadata:** Read-only (required for repository access)
4. Subscribe to **Events**:
   - Check **Issues**
5. Click **Create GitHub App**.

### 2. Generate a Private Key

1. On the App settings page, scroll to **Private keys**.
2. Click **Generate a private key** — a `.pem` file will be downloaded.
3. Set the file contents as the `GITHUB_PRIVATE_KEY` environment variable. For deployment environments that don't support multi-line variables, replace newlines with `\n`:

```bash
cat your-app.private-key.pem | awk '{printf "%s\\n", $0}'
```

### 3. Install the App on a Repository

1. Go to **GitHub Settings → Developer settings → GitHub Apps → Your App → Install App**.
2. Select the organisation or user account.
3. Choose **Only select repositories** and select the target repository.
4. Click **Install**.
5. Note the **Installation ID** from the URL (`/installations/<ID>`) — this becomes `GITHUB_INSTALLATION_ID`.

### 4. Configure the Webhook

If the app is deployed behind a reverse proxy or firewall, ensure that GitHub's IP ranges can reach your webhook endpoint. GitHub publishes its webhook source IPs at:

```
https://api.github.com/meta
```

For local development, use a tunnel such as [ngrok](https://ngrok.com/) or [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/):

```bash
ngrok http 8000
# Update the webhook URL in your GitHub App settings to the ngrok URL
```

### 5. Verify the Webhook

After configuring the App, GitHub will send a `ping` event. Check the logs:

```
INFO  Received webhook event=ping action=None
INFO  BountyGuard started. Database: bounty_guard.db
```

---

## Environment Variable Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `GITHUB_WEBHOOK_SECRET` | ✅ Yes | — | Shared HMAC-SHA256 secret configured in GitHub App settings. |
| `GITHUB_APP_ID` | ✅ Yes | — | Numeric GitHub App ID from the App settings page. |
| `GITHUB_PRIVATE_KEY` | ✅ Yes | — | PEM-encoded RSA private key. Literal `\n` sequences are expanded automatically. |
| `GITHUB_INSTALLATION_ID` | No | `None` | Installation ID override. Resolved dynamically from the webhook payload when not set. |
| `OPENAI_API_KEY` | When LLM enabled | `None` | OpenAI API key. Required when `LLM_ENABLED=true`. |
| `OPENAI_MODEL` | No | `gpt-4o-mini` | OpenAI chat completion model to use for classification. |
| `LLM_ENABLED` | No | `false` | Enable the LLM second-opinion classifier. |
| `SPAM_LABEL` | No | `spam-suspected` | GitHub label applied to suspected spam issues. |
| `HOLD_NOTIFICATION` | No | `true` | When `true`, posts a clarification comment instead of silently labelling. |
| `SPAM_SCORE_THRESHOLD` | No | `0.6` | Minimum rule-based score (0.0–1.0) to flag an issue as spam. |
| `LLM_SPAM_THRESHOLD` | No | `0.7` | Minimum LLM probability (0.0–1.0) to flag an issue as spam. |
| `COMBINED_MODE` | No | `any` | How to combine rule and LLM scores: `any` (either exceeds threshold) or `all` (both must exceed). |
| `DATABASE_URL` | No | `bounty_guard.db` | SQLite database file path. Use `:memory:` for tests. |
| `LOG_LEVEL` | No | `INFO` | Python logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `HOST` | No | `0.0.0.0` | Host address for Uvicorn to bind to. |
| `PORT` | No | `8000` | Port for Uvicorn to listen on. |

### Example `.env` File

```dotenv
# GitHub App credentials
GITHUB_WEBHOOK_SECRET=super-secret-webhook-key-change-me
GITHUB_APP_ID=123456
GITHUB_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xHn...\n-----END RSA PRIVATE KEY-----
GITHUB_INSTALLATION_ID=78901234

# LLM classifier (optional)
LLM_ENABLED=true
OPENAI_API_KEY=sk-proj-...
OPENAI_MODEL=gpt-4o-mini

# Triage behaviour
SPAM_SCORE_THRESHOLD=0.6
LLM_SPAM_THRESHOLD=0.7
COMBINED_MODE=any
SPAM_LABEL=spam-suspected
HOLD_NOTIFICATION=true

# Persistence
DATABASE_URL=bounty_guard.db

# Server
HOST=0.0.0.0
PORT=8000
LOG_LEVEL=INFO
```

---

## Scoring Rubric Documentation

BountyGuard evaluates each incoming issue body against **seven boolean signals**. Each signal that fires increments the spam score. The `total_score` is the fraction of signals that fired:

```
total_score = fired_signal_count / 7
```

A `total_score` at or above the `SPAM_SCORE_THRESHOLD` (default `0.6`) triggers the spam decision. Scores between `0.75 × threshold` and the threshold produce an `uncertain` decision recommending human review.

### Signal Breakdown

#### 1. `suspiciously_short`

**Fires when:** The issue body is shorter than 100 characters (stripped).

**Rationale:** Genuine security reports require space to describe the vulnerability, provide reproduction steps, and document the impact. A body under 100 characters cannot contain sufficient detail.

**Example triggering body:**
```
There is a critical security bug. Please fix it.
```

---

#### 2. `generic_greeting`

**Fires when:** The body opens (within the first 300 characters) with a generic templated greeting.

**Rationale:** AI-generated spam and copy-paste submissions often begin with formulaic openers that are inconsistent with how experienced security researchers write to project maintainers.

**Detected patterns include:**
- `Dear Security Team,`
- `Dear Maintainer,` / `Dear Developer,`
- `Hello, Security Team!` / `Hi Security Team,`
- `Greetings,`
- `To Whom It May Concern,`
- `I hope this message finds you well.`
- `I am writing to report a vulnerability.`
- `I recently discovered a critical security vulnerability.`
- `I found a critical vulnerability in your system.`

**Example triggering body:**
```
Dear Security Team,

I am writing to report a critical vulnerability I discovered in your application...
```

---

#### 3. `cve_template_detected`

**Fires when:** The body contains **two or more** boilerplate CVE/vulnerability template field markers.

**Rationale:** Mass-produced AI spam often uses a fill-in-the-blanks template copied from CVE disclosure forms. A single CVE identifier in a detailed report is legitimate; multiple template fields indicate copy-paste behaviour.

**Detected fields include:**
- `CVE-YYYY-NNNNN` (CVE identifier)
- `CVSS Score` / `CVSS v3`
- `CWE-NNN` (CWE identifier)
- `Affected version(s):`
- `Impact: critical/high/medium/low`
- `Remediation:`
- `Vulnerability type:`
- `Severity: critical/high/medium/low`
- `Proof of Concept:`
- `References:` followed by a link list

**Example triggering body:**
```
Severity: Critical
Vulnerability type: Remote code execution
Affected version: All versions
Remediation: Please patch this immediately.
```

---

#### 4. `no_code_evidence`

**Fires when:** The body contains **none** of the following:
- A fenced code block (` ``` `) or tilde code block (`~~~`)
- An indented code block (4-space or tab prefix)
- An inline backtick span (`` `code` ``)
- A stack trace (`Traceback (most recent call last)`, `at ClassName.method(File:line)`, etc.)
- A Proof-of-Concept indicator (`PoC`, `exploit.py`, `payload =`, `curl -`, `sqlmap`, `nmap`, `$`, etc.)

**Rationale:** Every credible security report should include at minimum a code snippet, HTTP request sample, stack trace, or PoC demonstration. Reports without any of these are almost always vague or AI-generated.

**Example clearing the flag:**
````
```http
GET /admin?id=1' OR '1'='1 HTTP/1.1
Host: example.com
```
````

---

#### 5. `missing_reproduction_steps`

**Fires when:** The body contains no recognisable reproduction steps section.

**Rationale:** Reproduction steps are the minimum necessary information for a maintainer to verify a vulnerability. Without them, the report cannot be acted upon regardless of its other qualities.

**Detected patterns include:**
- `Steps to reproduce:`
- `How to reproduce:`
- `Reproduction steps:`
- `Repro steps:`
- `To reproduce`
- `reproducible` / `reproduced` / `reproduce`

---

#### 6. `vague_description`

**Fires when:** The body contains fewer than **2 distinct technical terms** from a curated vocabulary of security and programming concepts.

**Rationale:** Legitimate reports use precise technical language because the author understands what they found. Vague language like "critical vulnerability" or "data exposure" without any supporting specifics is a strong spam indicator.

**Vocabulary includes (partial list):**

| Category | Terms |
|---|---|
| Memory safety | `null pointer dereference`, `use-after-free`, `buffer overflow`, `heap spray`, `integer overflow`, `format string` |
| Web vulnerabilities | `prototype pollution`, `command injection`, `template injection`, `SSTI`, `XXE`, `CSRF`, `open redirect`, `CRLF`, `HTTP request smuggling` |
| Cryptography / network | `TLS 1.x`, `certificate pinning`, `DNS rebinding`, `MITM`, `man-in-the-middle` |
| Classification | `CVE-YYYY-NNNNN`, `CWE-NNN`, `OWASP`, `CVSS` |
| C/system programming | `memcpy`, `malloc`, `strcpy`, `gets`, `gadget chain`, `ROP chain`, `shellcode` |
| Path / request indicators | `/etc/passwd`, `../`, `GET /api/...`, `Content-Type:`, `Authorization: Bearer` |
| Common abbreviations | `SQLi`, `XSS`, `IDOR`, `SSRF`, `RCE`, `deserialization`, `path traversal`, `directory traversal` |

---

#### 7. `excessive_severity_claims`

**Fires when:** The body contains high-severity buzzwords **without** code evidence, specifically:
- **Multiple distinct** severity claims (e.g. both `remote code execution` and `account takeover`) without any code block, stack trace, or PoC; **or**
- **Any** severity claim combined with a vague description (fewer than 2 technical terms) and no code evidence.

**Rationale:** Spam reports routinely pile on severity buzzwords to maximise urgency without providing evidence. A report mentioning both "RCE" and "full server takeover" and "privilege escalation" with no supporting code is a strong spam signal.

**Detected severity terms include:**
`critical vulnerability`, `remote code execution`, `RCE`, `arbitrary code execution`, `full system/server/database compromise`, `complete takeover`, `account takeover`, `authentication bypass`, `privilege escalation`, `zero-day`, `data breach`, `sensitive data exposure`, `unauthenticated access/RCE/SSRF/IDOR`, `SSRF`, `SQLi`, `XSS`, `IDOR`, `path traversal`, `hardcoded secret/credential`, `exposed API key`, etc.

---

### Score Examples

| Issue Type | Score | Signals Fired |
|---|---|---|
| Empty body | 1.00 | All 7 |
| Generic AI spam report | 0.71–1.00 | 5–7 |
| Short vague report | 0.71–0.86 | 5–6 |
| Borderline (missing repro + no code) | 0.43–0.57 | 3–4 |
| Legitimate XSS report with PoC | 0.00–0.29 | 0–2 |
| Detailed RCE report with steps | 0.00–0.14 | 0–1 |

---

## LLM Classifier

When `LLM_ENABLED=true`, BountyGuard calls the OpenAI Chat Completions API after the rule-based scorer to get a second opinion.

### How It Works

1. The issue title and body (truncated to 4,000 characters) are sent to the configured model.
2. A carefully structured system prompt instructs the model to respond **only** with a JSON object containing:
   - `spam_probability`: float in [0.0, 1.0]
   - `reasoning`: 2–4 sentence human-readable explanation
3. The response is parsed and returned as an `LLMResult`.
4. The LLM probability is combined with the rule score using `COMBINED_MODE`.

### Combining Scores

| `COMBINED_MODE` | Spam Decision |
|---|---|
| `any` (default) | Flag if **either** the rule score ≥ `SPAM_SCORE_THRESHOLD` **or** the LLM probability ≥ `LLM_SPAM_THRESHOLD` |
| `all` | Flag only if **both** exceed their respective thresholds (more conservative) |

When the LLM is disabled or encounters an error, the rule-based score is used exclusively and the decision is not blocked.

### Graceful Degradation

LLM errors (rate limits, timeouts, connection errors, malformed responses) are caught and logged. The triage pipeline continues with `LLMResult(skipped=True)` so a flaky LLM never blocks issue processing.

### Cost Considerations

- **Model:** `gpt-4o-mini` (default) is recommended for cost efficiency. A typical security issue (~500 tokens) costs approximately $0.00015 with `gpt-4o-mini`.
- **Truncation:** Issue bodies longer than 4,000 characters are automatically truncated to control token usage.
- **Temperature:** Always set to `0.0` for deterministic, reproducible classifications.

---

## Dashboard API

BountyGuard exposes a paginated JSON dashboard at `GET /dashboard`.

### Endpoint

```
GET /dashboard
```

### Query Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `repo` | string | `null` | Filter by repository full name (e.g. `owner/repo`). |
| `decision` | string | `null` | Filter by decision: `spam`, `legitimate`, or `uncertain`. |
| `limit` | integer | `50` | Page size (1–500). |
| `offset` | integer | `0` | Pagination offset. |

### Example Request

```bash
# All records
curl http://localhost:8000/dashboard

# Spam only in a specific repo
curl "http://localhost:8000/dashboard?repo=owner/myapp&decision=spam&limit=20"

# Page 2 of all records
curl "http://localhost:8000/dashboard?limit=50&offset=50"
```

### Example Response

```json
{
  "total": 3,
  "limit": 50,
  "offset": 0,
  "records": [
    {
      "id": 1,
      "repo_full_name": "owner/myapp",
      "issue_number": 42,
      "issue_title": "Critical RCE vulnerability",
      "issue_url": "https://github.com/owner/myapp/issues/42",
      "author_login": "badactor",
      "decision": "spam",
      "rule_score": 0.857143,
      "llm_probability": 0.0,
      "llm_skipped": true,
      "label_applied": "spam-suspected",
      "comment_posted": true,
      "reasoning": "Issue flagged as suspected spam. Rule score: 0.86 (threshold: 0.60). LLM classification: disabled. Fired signals: vague_description, missing_reproduction_steps, cve_template_detected, no_code_evidence, excessive_severity_claims, generic_greeting.",
      "triaged_at": "2024-01-15T10:05:32.123456+00:00",
      "updated_at": "2024-01-15T10:05:32.456789+00:00"
    }
  ]
}
```

---

## Development

### Project Structure

```
bounty_guard/
├── __init__.py          # Package init, version
├── app.py               # FastAPI application, webhook + dashboard endpoints
├── config.py            # Pydantic-settings configuration
├── github_client.py     # PyGithub wrapper (labels, comments, issue metadata)
├── llm_classifier.py    # OpenAI LLM second-opinion classifier
├── models.py            # Pydantic models + SQLite persistence layer
├── scorer.py            # Rule-based spam scoring rubric
├── triage.py            # Triage orchestrator
└── webhook_validator.py # HMAC-SHA256 signature verification

tests/
├── __init__.py
├── fixtures.py          # Shared test fixtures and sample data
├── test_app.py          # FastAPI endpoint integration tests
├── test_github_client.py
├── test_llm_classifier.py
├── test_models.py
├── test_scorer.py
├── test_triage.py
└── test_webhook_validator.py
```

### Adding a New Scoring Signal

1. Add a new `bool` field to `SpamScore` in `bounty_guard/models.py`.
2. Update `signal_fields` in `SpamScore.fired_signals`.
3. Update `_TOTAL_SIGNALS` in `bounty_guard/scorer.py`.
4. Implement the detection function (`_detect_*`) in `scorer.py`.
5. Call the new detector in `score_issue()` and include it in the `fired_count` sum.
6. Add tests in `tests/test_scorer.py`.

### Adjusting Thresholds Without Redeployment

BountyGuard reads thresholds from environment variables at startup. To adjust:

1. Update `SPAM_SCORE_THRESHOLD` and/or `LLM_SPAM_THRESHOLD` in your environment.
2. Restart the server.
3. Use the `retriage_issue` method (or a future admin endpoint) to reprocess previously triaged issues with the new thresholds.

---

## Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run a specific test file
pytest tests/test_scorer.py -v

# Run a specific test class or function
pytest tests/test_scorer.py::TestSuspiciouslyShort -v
pytest tests/test_triage.py::TestMakeDecision::test_rule_triggered_any_mode -v

# Run with coverage (requires pytest-cov)
pip install pytest-cov
pytest --cov=bounty_guard --cov-report=term-missing
```

### Test Environment

Tests do **not** require any real GitHub credentials or OpenAI API key. All external calls are mocked using `unittest.mock`. The SQLite database uses `:memory:` for full isolation between test runs.

Required environment variables are not needed for tests — the `settings` singleton gracefully falls back to `None` when environment variables are absent, and individual tests inject mock settings directly.

---

## Deployment

### Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir -e .

EXPOSE 8000

CMD ["bounty-guard"]
```

```bash
docker build -t bounty-guard .
docker run -p 8000:8000 --env-file .env bounty-guard
```

### Railway / Heroku / Render

1. Set all required environment variables in the platform's dashboard or CLI.
2. Set the start command to `bounty-guard` or `uvicorn bounty_guard.app:app --host 0.0.0.0 --port $PORT`.
3. For platforms that don't persist files, set `DATABASE_URL` to a path on a mounted volume, or adapt the persistence layer to use a managed PostgreSQL database.

### Production Recommendations

- **Reverse proxy:** Run behind Nginx or Caddy for TLS termination.
- **Process manager:** Use systemd, supervisord, or a container orchestrator to ensure automatic restarts.
- **Database backups:** The SQLite `bounty_guard.db` file should be included in your backup strategy.
- **Log aggregation:** Set `LOG_LEVEL=INFO` and forward logs to your observability platform.
- **Health checks:** Configure your load balancer to poll `GET /health` every 30 seconds.

---

## Security Considerations

### Webhook Signature Verification

Every incoming webhook request is verified using HMAC-SHA256 before any processing occurs:

```python
HMAC-SHA256(webhook_secret, raw_request_body)
```

- The raw body bytes are read **before** JSON parsing to ensure the signature covers the exact bytes GitHub signed.
- Comparison uses `hmac.compare_digest` (constant-time) to prevent timing-oracle attacks.
- Requests with a missing, malformed, or invalid `X-Hub-Signature-256` header receive a `403 Forbidden` response immediately.

### Secret Management

- Never commit `.env` files containing real secrets to version control.
- Use your platform's secret management system (AWS Secrets Manager, GitHub Actions secrets, Vault, etc.) in production.
- Rotate the `GITHUB_WEBHOOK_SECRET` and GitHub App private key periodically.
- The OpenAI API key is only required when `LLM_ENABLED=true`; keep it scoped to the minimum necessary permissions.

### GitHub App Permissions

BountyGuard requests the minimum permissions necessary:
- **Issues: Read & Write** — required to apply labels and post comments.
- **Metadata: Read-only** — required baseline for all GitHub Apps.

It does **not** request access to repository code, pull requests, secrets, or any other resource.

### Issue Body Handling

Issue bodies are treated as untrusted user input throughout the pipeline:
- The scorer applies only read-only regex matching — no code execution.
- Issue bodies sent to the LLM are truncated to 4,000 characters.
- The LLM prompt explicitly instructs the model to evaluate, not execute, the content.
- No issue body content is rendered as HTML or executed anywhere in the pipeline.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository and create a feature branch.
2. Write tests for any new functionality.
3. Ensure `pytest` passes with no failures.
4. Open a pull request with a clear description of the change.

For bug reports or feature requests, please open a GitHub issue.
