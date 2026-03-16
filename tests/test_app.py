"""Integration tests for the FastAPI application (bounty_guard.app).

Uses the HTTPX async test client to exercise the full request/response cycle.
All GitHub App credentials and webhook secrets are supplied via mock settings
so no real network calls are made.

Covers:
- GET /health returns 200 with correct body.
- POST /webhook with valid signature and 'ping' event.
- POST /webhook with valid 'issues' opened event triggers triage.
- POST /webhook with 'issues' non-triage action returns accepted=True.
- POST /webhook with missing signature returns 403.
- POST /webhook with invalid signature returns 403.
- POST /webhook with invalid JSON returns 400.
- POST /webhook for unsupported event type returns accepted=True.
- GET /dashboard returns paginated records.
- GET /dashboard with decision filter.
- GET /dashboard with repo filter.
- GET /dashboard with invalid decision filter returns 400.
- POST /webhook triage pipeline error returns 500.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient, ASGITransport

from bounty_guard.app import create_app
from bounty_guard.models import TriageDecision, TriageRepository, TriageResult, SpamScore, LLMResult
from bounty_guard.webhook_validator import compute_signature


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WEBHOOK_SECRET = "test-secret-key"
REPO_NAME = "owner/testrepo"
ISSUE_NUMBER = 42


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sign_payload(payload: bytes, secret: str = WEBHOOK_SECRET) -> str:
    return compute_signature(payload, secret)


def _make_issues_payload(
    action: str = "opened",
    issue_number: int = ISSUE_NUMBER,
    body: str = "Dear Security Team, critical RCE.",
    installation_id: int | None = 123,
) -> dict:
    payload: dict = {
        "action": action,
        "issue": {
            "number": issue_number,
            "title": "Critical vulnerability",
            "body": body,
            "html_url": f"https://github.com/{REPO_NAME}/issues/{issue_number}",
            "user": {"login": "attacker"},
        },
        "repository": {
            "full_name": REPO_NAME,
        },
    }
    if installation_id is not None:
        payload["installation"] = {"id": installation_id}
    return payload


def _make_mock_settings(
    webhook_secret: str = WEBHOOK_SECRET,
    github_app_id: int = 1,
    github_private_key: str = "fake-key",
    github_installation_id: int | None = 123,
    llm_enabled: bool = False,
    spam_label: str = "spam-suspected",
    spam_score_threshold: float = 0.6,
    llm_spam_threshold: float = 0.7,
    combined_mode: str = "any",
    hold_notification: bool = True,
    openai_api_key: str | None = None,
    openai_model: str = "gpt-4o-mini",
    database_url: str = ":memory:",
) -> MagicMock:
    s = MagicMock()
    s.github_webhook_secret = webhook_secret
    s.github_app_id = github_app_id
    s.github_private_key = github_private_key
    s.github_installation_id = github_installation_id
    s.llm_enabled = llm_enabled
    s.spam_label = spam_label
    s.spam_score_threshold = spam_score_threshold
    s.llm_spam_threshold = llm_spam_threshold
    s.combined_mode = combined_mode
    s.hold_notification = hold_notification
    s.openai_api_key = openai_api_key
    s.openai_model = openai_model
    s.database_url = database_url
    return s


def _make_triage_result(
    decision: TriageDecision = TriageDecision.SPAM,
) -> TriageResult:
    return TriageResult(
        decision=decision,
        spam_score=SpamScore(total_score=0.85),
        llm_result=LLMResult(skipped=True),
        rule_triggered=True,
        label_applied="spam-suspected",
        comment_posted=True,
        reasoning="Rule score exceeded threshold.",
    )


@pytest.fixture
def mock_settings():
    return _make_mock_settings()


@pytest.fixture
def in_memory_db():
    repo = TriageRepository(db_path=":memory:")
    repo.connect()
    yield repo
    repo.close()


@pytest.fixture
def app_with_mocks(mock_settings, in_memory_db):
    """Create the FastAPI app with mocked settings and in-memory DB."""
    _app = create_app()
    _app.state.settings = mock_settings
    _app.state.db_repo = in_memory_db
    return _app


# ---------------------------------------------------------------------------
# Tests: GET /health
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health_returns_200(self, app_with_mocks):
        async with AsyncClient(
            transport=ASGITransport(app=app_with_mocks), base_url="http://test"
        ) as client:
            response = await client.get("/health")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_health_body(self, app_with_mocks):
        async with AsyncClient(
            transport=ASGITransport(app=app_with_mocks), base_url="http://test"
        ) as client:
            response = await client.get("/health")
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data


# ---------------------------------------------------------------------------
# Tests: POST /webhook
# ---------------------------------------------------------------------------


class TestWebhookEndpoint:
    @pytest.mark.asyncio
    async def test_ping_event_accepted(self, app_with_mocks):
        payload = json.dumps({"zen": "Keep it simple.", "action": None}).encode()
        sig = _sign_payload(payload)
        async with AsyncClient(
            transport=ASGITransport(app=app_with_mocks), base_url="http://test"
        ) as client:
            response = await client.post(
                "/webhook",
                content=payload,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "ping",
                    "Content-Type": "application/json",
                },
            )
        assert response.status_code == 200
        data = response.json()
        assert data["accepted"] is True
        assert "Pong" in data["message"]

    @pytest.mark.asyncio
    async def test_missing_signature_returns_403(self, app_with_mocks):
        payload = json.dumps({"action": "opened"}).encode()
        async with AsyncClient(
            transport=ASGITransport(app=app_with_mocks), base_url="http://test"
        ) as client:
            response = await client.post(
                "/webhook",
                content=payload,
                headers={"X-GitHub-Event": "issues", "Content-Type": "application/json"},
            )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_invalid_signature_returns_403(self, app_with_mocks):
        payload = json.dumps({"action": "opened"}).encode()
        async with AsyncClient(
            transport=ASGITransport(app=app_with_mocks), base_url="http://test"
        ) as client:
            response = await client.post(
                "/webhook",
                content=payload,
                headers={
                    "X-Hub-Signature-256": "sha256=" + "0" * 64,
                    "X-GitHub-Event": "issues",
                    "Content-Type": "application/json",
                },
            )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_invalid_json_returns_400(self, app_with_mocks):
        payload = b"not valid json{"
        sig = _sign_payload(payload)
        async with AsyncClient(
            transport=ASGITransport(app=app_with_mocks), base_url="http://test"
        ) as client:
            response = await client.post(
                "/webhook",
                content=payload,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "issues",
                    "Content-Type": "application/json",
                },
            )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_unsupported_event_type_accepted(self, app_with_mocks):
        payload = json.dumps({"action": "created"}).encode()
        sig = _sign_payload(payload)
        async with AsyncClient(
            transport=ASGITransport(app=app_with_mocks), base_url="http://test"
        ) as client:
            response = await client.post(
                "/webhook",
                content=payload,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )
        assert response.status_code == 200
        data = response.json()
        assert data["accepted"] is True
        assert "not processed" in data["message"]

    @pytest.mark.asyncio
    async def test_issues_non_triage_action_accepted(self, app_with_mocks):
        payload = json.dumps({"action": "closed"}).encode()
        sig = _sign_payload(payload)
        async with AsyncClient(
            transport=ASGITransport(app=app_with_mocks), base_url="http://test"
        ) as client:
            response = await client.post(
                "/webhook",
                content=payload,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "issues",
                    "Content-Type": "application/json",
                },
            )
        assert response.status_code == 200
        data = response.json()
        assert data["accepted"] is True

    @pytest.mark.asyncio
    async def test_issues_opened_triggers_triage(self, app_with_mocks):
        """issues:opened event should trigger triage and return decision."""
        payload_dict = _make_issues_payload(action="opened")
        payload = json.dumps(payload_dict).encode()
        sig = _sign_payload(payload)

        mock_result = _make_triage_result(TriageDecision.SPAM)

        with patch(
            "bounty_guard.triage.TriageOrchestrator.triage_issue",
            return_value=mock_result,
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app_with_mocks), base_url="http://test"
            ) as client:
                response = await client.post(
                    "/webhook",
                    content=payload,
                    headers={
                        "X-Hub-Signature-256": sig,
                        "X-GitHub-Event": "issues",
                        "Content-Type": "application/json",
                    },
                )
        assert response.status_code == 200
        data = response.json()
        assert data["accepted"] is True
        assert data["decision"] == "spam"

    @pytest.mark.asyncio
    async def test_issues_reopened_triggers_triage(self, app_with_mocks):
        payload_dict = _make_issues_payload(action="reopened")
        payload = json.dumps(payload_dict).encode()
        sig = _sign_payload(payload)

        mock_result = _make_triage_result(TriageDecision.LEGITIMATE)

        with patch(
            "bounty_guard.triage.TriageOrchestrator.triage_issue",
            return_value=mock_result,
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app_with_mocks), base_url="http://test"
            ) as client:
                response = await client.post(
                    "/webhook",
                    content=payload,
                    headers={
                        "X-Hub-Signature-256": sig,
                        "X-GitHub-Event": "issues",
                        "Content-Type": "application/json",
                    },
                )
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "legitimate"

    @pytest.mark.asyncio
    async def test_triage_exception_returns_500(self, app_with_mocks):
        payload_dict = _make_issues_payload(action="opened")
        payload = json.dumps(payload_dict).encode()
        sig = _sign_payload(payload)

        with patch(
            "bounty_guard.triage.TriageOrchestrator.triage_issue",
            side_effect=RuntimeError("Database connection lost"),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app_with_mocks), base_url="http://test"
            ) as client:
                response = await client.post(
                    "/webhook",
                    content=payload,
                    headers={
                        "X-Hub-Signature-256": sig,
                        "X-GitHub-Event": "issues",
                        "Content-Type": "application/json",
                    },
                )
        assert response.status_code == 500

    @pytest.mark.asyncio
    async def test_payload_missing_repo_returns_not_accepted(self, app_with_mocks):
        # Payload missing 'repository' field.
        payload_dict = {
            "action": "opened",
            "issue": {"number": 1, "title": "Bug", "body": "test"},
        }
        payload = json.dumps(payload_dict).encode()
        sig = _sign_payload(payload)
        async with AsyncClient(
            transport=ASGITransport(app=app_with_mocks), base_url="http://test"
        ) as client:
            response = await client.post(
                "/webhook",
                content=payload,
                headers={
                    "X-Hub-Signature-256": sig,
                    "X-GitHub-Event": "issues",
                    "Content-Type": "application/json",
                },
            )
        assert response.status_code == 200
        data = response.json()
        assert data["accepted"] is False


# ---------------------------------------------------------------------------
# Tests: GET /dashboard
# ---------------------------------------------------------------------------


class TestDashboardEndpoint:
    def _insert_record(
        self,
        db_repo: TriageRepository,
        repo: str = "owner/repo",
        issue_number: int = 1,
        decision: TriageDecision = TriageDecision.SPAM,
    ):
        from bounty_guard.models import IssueRecord

        result = TriageResult(
            decision=decision,
            spam_score=SpamScore(total_score=0.7),
            llm_result=LLMResult(skipped=True),
            rule_triggered=True,
            reasoning="Test record.",
        )
        record = IssueRecord(
            repo_full_name=repo,
            issue_number=issue_number,
            issue_title="Test",
            issue_url="https://github.com/owner/repo/issues/1",
            author_login="user",
            triage_result=result,
        )
        db_repo.upsert(record)

    @pytest.mark.asyncio
    async def test_empty_dashboard(self, app_with_mocks):
        async with AsyncClient(
            transport=ASGITransport(app=app_with_mocks), base_url="http://test"
        ) as client:
            response = await client.get("/dashboard")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["records"] == []

    @pytest.mark.asyncio
    async def test_dashboard_returns_records(self, app_with_mocks, in_memory_db):
        self._insert_record(in_memory_db, issue_number=1)
        self._insert_record(in_memory_db, issue_number=2)
        async with AsyncClient(
            transport=ASGITransport(app=app_with_mocks), base_url="http://test"
        ) as client:
            response = await client.get("/dashboard")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert len(data["records"]) == 2

    @pytest.mark.asyncio
    async def test_dashboard_decision_filter(self, app_with_mocks, in_memory_db):
        self._insert_record(in_memory_db, issue_number=1, decision=TriageDecision.SPAM)
        self._insert_record(
            in_memory_db, issue_number=2, decision=TriageDecision.LEGITIMATE
        )
        async with AsyncClient(
            transport=ASGITransport(app=app_with_mocks), base_url="http://test"
        ) as client:
            response = await client.get("/dashboard?decision=spam")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["records"][0]["decision"] == "spam"

    @pytest.mark.asyncio
    async def test_dashboard_repo_filter(self, app_with_mocks, in_memory_db):
        self._insert_record(in_memory_db, repo="owner/alpha", issue_number=1)
        self._insert_record(in_memory_db, repo="owner/beta", issue_number=1)
        async with AsyncClient(
            transport=ASGITransport(app=app_with_mocks), base_url="http://test"
        ) as client:
            response = await client.get("/dashboard?repo=owner/alpha")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["records"][0]["repo_full_name"] == "owner/alpha"

    @pytest.mark.asyncio
    async def test_dashboard_invalid_decision_filter_400(self, app_with_mocks):
        async with AsyncClient(
            transport=ASGITransport(app=app_with_mocks), base_url="http://test"
        ) as client:
            response = await client.get("/dashboard?decision=invalid_decision")
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_dashboard_pagination(self, app_with_mocks, in_memory_db):
        for i in range(1, 6):
            self._insert_record(in_memory_db, issue_number=i)
        async with AsyncClient(
            transport=ASGITransport(app=app_with_mocks), base_url="http://test"
        ) as client:
            resp1 = await client.get("/dashboard?limit=3&offset=0")
            resp2 = await client.get("/dashboard?limit=3&offset=3")
        assert len(resp1.json()["records"]) == 3
        assert len(resp2.json()["records"]) == 2

    @pytest.mark.asyncio
    async def test_dashboard_record_fields(self, app_with_mocks, in_memory_db):
        self._insert_record(in_memory_db, issue_number=1)
        async with AsyncClient(
            transport=ASGITransport(app=app_with_mocks), base_url="http://test"
        ) as client:
            response = await client.get("/dashboard")
        record = response.json()["records"][0]
        assert "repo_full_name" in record
        assert "issue_number" in record
        assert "decision" in record
        assert "rule_score" in record
        assert "reasoning" in record
        assert "triaged_at" in record

    @pytest.mark.asyncio
    async def test_dashboard_no_db_returns_503(self, mock_settings):
        """When db_repo is None on app state, dashboard returns 503."""
        _app = create_app()
        _app.state.settings = mock_settings
        _app.state.db_repo = None
        async with AsyncClient(
            transport=ASGITransport(app=_app), base_url="http://test"
        ) as client:
            response = await client.get("/dashboard")
        assert response.status_code == 503
