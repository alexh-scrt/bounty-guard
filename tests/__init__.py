"""Test package for BountyGuard.

This package contains all unit and integration tests for the BountyGuard
application. Test modules are organised by the component they cover:

- test_scorer.py           - Rule-based spam scoring rubric signals.
- test_webhook_validator.py - HMAC-SHA256 signature verification.
- test_triage.py           - Triage orchestration pipeline.
- test_models.py           - Pydantic models and SQLite persistence.
- test_github_client.py    - GitHub API client wrapper.
- test_llm_classifier.py   - OpenAI LLM classifier.
- test_app.py              - FastAPI application endpoints.
- fixtures.py              - Shared test fixtures and sample data.
"""
