# BountyGuard 🛡️

**Stop AI-generated spam from drowning your bug bounty inbox.**

BountyGuard is a GitHub App that automatically triages incoming security issue reports on open-source repositories. It scores each report against a spam-detection rubric, labels suspicious submissions, and optionally holds them from maintainer notification — so your security program stays open without the noise.

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/your-org/bounty_guard.git
cd bounty_guard
pip install -e .
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your GitHub App credentials and webhook secret
```

```env
GITHUB_WEBHOOK_SECRET=your_webhook_secret
GITHUB_APP_ID=123456
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."
GITHUB_INSTALLATION_ID=78901234
```

### 3. Run the server

```bash
uvicorn bounty_guard.app:app --host 0.0.0.0 --port 8000
```

Point your GitHub App's webhook URL to `https://your-host/webhook`. That's it — BountyGuard will start triaging new security issues immediately.

---

## What It Does

BountyGuard listens for GitHub `issues` webhook events and runs every new report through a multi-signal spam-detection rubric. Suspicious reports are automatically labeled (e.g. `spam-suspected`) and can optionally be held from notifying maintainers. An optional OpenAI-powered classifier provides a second-opinion score with human-readable reasoning. A built-in dashboard API gives maintainers a paginated view of flagged vs. legitimate reports and supports retriaging issues after config changes.

---

## Features

- **Rule-based scoring rubric** — Detects vague descriptions, missing reproduction steps, copy-pasted CVE templates, absent code evidence, and unsupported severity claims, with a per-signal score breakdown.
- **Optional LLM second opinion** — Calls the OpenAI Chat Completions API for a spam probability score and human-readable reasoning when `LLM_ENABLED=true`. Failures are graceful and never block triage.
- **Automatic GitHub actions** — Applies configurable labels and posts templated clarification comments on flagged issues via the GitHub App installation API.
- **SQLite triage history** — Persists every triage decision so maintainers can review past outcomes, tune thresholds, and retriage issues without losing context.
- **Secure by default** — HMAC-SHA256 webhook signature verification on every request; all credentials loaded from environment variables with no hardcoded secrets.

---

## Usage Examples

### Health check

```bash
curl http://localhost:8000/health
# {"status": "ok"}
```

### Dashboard — view triage history

```bash
# All recent decisions
curl "http://localhost:8000/dashboard?limit=20&offset=0"

# Filter to spam-suspected only
curl "http://localhost:8000/dashboard?decision=SPAM&limit=10"

# Filter by repository
curl "http://localhost:8000/dashboard?repo=your-org/your-repo&limit=10"
```

```json
{
  "total": 42,
  "results": [
    {
      "repo": "your-org/your-repo",
      "issue_number": 87,
      "decision": "SPAM",
      "total_score": 0.71,
      "fired_signals": ["vague_description", "missing_reproduction_steps", "no_code_evidence", "generic_greeting", "cve_template_detected"],
      "llm_spam_probability": 0.88,
      "llm_reasoning": "The report uses a generic CVE template with no repository-specific details or proof-of-concept code.",
      "created_at": "2024-11-15T10:32:00Z"
    }
  ]
}
```

### Enabling the LLM classifier

```env
LLM_ENABLED=true
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini
```

### Tuning spam thresholds

```env
# Flag issues where rule score >= 0.57 (4 of 7 signals)
SPAM_SCORE_THRESHOLD=0.57

# Also flag if LLM probability exceeds this value
LLM_SPAM_THRESHOLD=0.75

# 'any': flag if either scorer triggers | 'all': require both
COMBINED_MODE=any

# Post a comment requesting clarification on flagged issues
HOLD_NOTIFICATION=true
```

---

## Project Structure

```
bounty_guard/
├── __init__.py            # Package init, version info
├── app.py                 # FastAPI entry point: /webhook, /health, /dashboard
├── config.py              # Settings from environment variables
├── github_client.py       # PyGithub wrapper: labels, comments, metadata
├── llm_classifier.py      # Optional OpenAI spam classifier
├── models.py              # Pydantic models + SQLite persistence layer
├── scorer.py              # Rule-based spam scoring rubric
├── triage.py              # Orchestrates scorer + LLM → GitHub actions
└── webhook_validator.py   # HMAC-SHA256 signature verification

tests/
├── fixtures.py            # Shared issue bodies and webhook payloads
├── test_app.py            # FastAPI endpoint integration tests
├── test_github_client.py  # GitHub client unit tests (mocked API)
├── test_llm_classifier.py # LLM classifier unit tests (mocked OpenAI)
├── test_models.py         # Pydantic model and SQLite persistence tests
├── test_scorer.py         # Rubric signal unit tests
├── test_triage.py         # Triage pipeline integration tests
└── test_webhook_validator.py  # HMAC verification unit tests

pyproject.toml
README.md
```

---

## Configuration

All configuration is driven by environment variables. A `.env` file is supported via `pydantic-settings`.

| Variable | Required | Default | Description |
|---|---|---|---|
| `GITHUB_WEBHOOK_SECRET` | ✅ | — | Shared secret for HMAC-SHA256 webhook verification |
| `GITHUB_APP_ID` | ✅ | — | Numeric GitHub App ID |
| `GITHUB_PRIVATE_KEY` | ✅ | — | PEM-encoded RSA private key (use `\n` for newlines) |
| `GITHUB_INSTALLATION_ID` | ❌ | _(auto)_ | Installation ID; resolved dynamically if omitted |
| `LLM_ENABLED` | ❌ | `false` | Enable OpenAI second-opinion classifier |
| `OPENAI_API_KEY` | ❌* | — | Required when `LLM_ENABLED=true` |
| `OPENAI_MODEL` | ❌ | `gpt-4o-mini` | OpenAI chat model name |
| `SPAM_SCORE_THRESHOLD` | ❌ | `0.57` | Rule-based score threshold to flag as spam |
| `LLM_SPAM_THRESHOLD` | ❌ | `0.75` | LLM probability threshold to flag as spam |
| `COMBINED_MODE` | ❌ | `any` | `any` = either signal flags; `all` = both required |
| `SPAM_LABEL` | ❌ | `spam-suspected` | GitHub label applied to flagged issues |
| `HOLD_NOTIFICATION` | ❌ | `false` | Post a comment requesting clarification on flagged issues |
| `APPLY_GITHUB_ACTIONS` | ❌ | `true` | Toggle all GitHub label/comment actions |
| `DATABASE_PATH` | ❌ | `bounty_guard.db` | SQLite database file path |

---

## Scoring Rubric

The rule-based scorer checks seven signals, each carrying equal weight. The total score is `signals_fired / 7`.

| Signal | What it detects |
|---|---|
| `vague_description` | Body lacks specific technical terms |
| `missing_reproduction_steps` | No reproduction / steps-to-reproduce section |
| `cve_template_detected` | Boilerplate CVE template text present |
| `no_code_evidence` | No code blocks, stack traces, or PoC fragments |
| `excessive_severity_claims` | High-severity buzzwords without technical evidence |
| `generic_greeting` | Body opens with an AI-typical generic greeting |
| `suspiciously_short` | Body is too short to contain a real report |

A score of `0.57` (4/7 signals) is the default threshold for flagging an issue as `SPAM`.

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

All tests use mocked GitHub and OpenAI clients — no credentials or network access required.

---

## License

MIT © BountyGuard Contributors

---

*Built with [Jitter](https://github.com/jitter-ai) - an AI agent that ships code daily.*
