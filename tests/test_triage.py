"""Integration tests for the triage pipeline (bounty_guard.triage).

All GitHub client calls and LLM classifier calls are mocked to isolate the
orchestration logic.  Tests verify:

- Rule-only spam detection (LLM disabled).
- LLM-triggered spam detection (rule below threshold, LLM above).
- combined_mode='all' requires both signals.
- combined_mode='any' flags when either signal fires.
- Legitimate issue is not flagged.
- Uncertain decision emitted for borderline scores.
- GitHub label is applied for spam decisions.
- GitHub comment is posted when hold_notification=True.
- GitHub actions are skipped when apply_github_actions=False.
- Database record is persisted after triage.
- GitHub client errors are swallowed (graceful degradation).
- retriage_issue removes existing label before re-running.
- _make_decision logic for all combined_mode/trigger combinations.
- _build_reasoning returns non-empty strings.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from bounty_guard.models import (
    LLMResult,
    SpamScore,
    TriageDecision,
    TriageRepository,
    TriageResult,
)
from bounty_guard.triage import (
    TriageOrchestrator,
    _build_reasoning,
    _make_decision,
    get_orchestrator,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

SPAM_BODY = """Dear Security Team,

I am writing to report a critical vulnerability.
Severity: Critical
Impact: Critical
Remediation: Please fix this.
Vulnerability type: Remote code execution

This allows complete system compromise and full server takeover.
Privilege escalation and account takeover are also possible.

Please fix immediately.
"""

LEGITIMATE_BODY = """
## Path Traversal in /api/upload

The filename parameter is not sanitised, allowing `../` sequences.

## Steps to Reproduce

1. Authenticate.
2. Send:

```http
POST /api/v1/upload HTTP/1.1
Content-Disposition: form-data; name="file"; filename="../../../etc/passwd"
```

3. Response contains `/etc/passwd` contents.

## Impact

Arbitrary file read via directory traversal (CWE-22).
"""


def _make_settings(
    rule_threshold: float = 0.6,
    llm_threshold: float = 0.7,
    combined_mode: str = "any",
    llm_enabled: bool = False,
    hold_notification: bool = True,
    spam_label: str = "spam-suspected",
    openai_api_key: str | None = None,
    openai_model: str = "gpt-4o-mini",
    github_app_id: int = 1,
    github_private_key: str = "fake-key",
    github_installation_id: int | None = 42,
    database_url: str = ":memory:",
) -> MagicMock:
    """Build a mock Settings object."""
    s = MagicMock()
    s.spam_score_threshold = rule_threshold
    s.llm_spam_threshold = llm_threshold
    s.combined_mode = combined_mode
    s.llm_enabled = llm_enabled
    s.hold_notification = hold_notification
    s.spam_label = spam_label
    s.openai_api_key = openai_api_key
    s.openai_model = openai_model
    s.github_app_id = github_app_id
    s.github_private_key = github_private_key
    s.github_installation_id = github_installation_id
    s.database_url = database_url
    return s


def _make_mock_github_client() -> MagicMock:
    """Build a mock GitHubClient."""
    client = MagicMock()
    client.apply_label.return_value = None
    client.post_spam_comment.return_value = "https://github.com/owner/repo/issues/1#issuecomment-1"
    client.remove_label.return_value = True
    return client


def _make_db_repo() -> TriageRepository:
    """Return a connected in-memory TriageRepository."""
    repo = TriageRepository(db_path=":memory:")
    repo.connect()
    return repo


# ---------------------------------------------------------------------------
# Tests: _make_decision
# ---------------------------------------------------------------------------


class TestMakeDecision:
    def _spam_score(self, total: float) -> SpamScore:
        return SpamScore(total_score=total)

    def _llm_result(self, prob: float, skipped: bool = False) -> LLMResult:
        return LLMResult(spam_probability=prob, skipped=skipped)

    def test_rule_triggered_any_mode(self):
        decision, rule_t, llm_t = _make_decision(
            spam_score=self._spam_score(0.7),
            llm_result=self._llm_result(0.0, skipped=True),
            rule_threshold=0.6,
            llm_threshold=0.7,
            combined_mode="any",
        )
        assert decision == TriageDecision.SPAM
        assert rule_t is True
        assert llm_t is False

    def test_llm_triggered_any_mode(self):
        decision, rule_t, llm_t = _make_decision(
            spam_score=self._spam_score(0.3),
            llm_result=self._llm_result(0.8),
            rule_threshold=0.6,
            llm_threshold=0.7,
            combined_mode="any",
        )
        assert decision == TriageDecision.SPAM
        assert rule_t is False
        assert llm_t is True

    def test_neither_triggered_legitimate(self):
        decision, rule_t, llm_t = _make_decision(
            spam_score=self._spam_score(0.2),
            llm_result=self._llm_result(0.1),
            rule_threshold=0.6,
            llm_threshold=0.7,
            combined_mode="any",
        )
        assert decision == TriageDecision.LEGITIMATE
        assert rule_t is False
        assert llm_t is False

    def test_all_mode_requires_both(self):
        # Rule exceeds threshold but LLM does not.
        decision, _, _ = _make_decision(
            spam_score=self._spam_score(0.8),
            llm_result=self._llm_result(0.3),
            rule_threshold=0.6,
            llm_threshold=0.7,
            combined_mode="all",
        )
        assert decision == TriageDecision.LEGITIMATE

    def test_all_mode_both_triggered_gives_spam(self):
        decision, rule_t, llm_t = _make_decision(
            spam_score=self._spam_score(0.8),
            llm_result=self._llm_result(0.9),
            rule_threshold=0.6,
            llm_threshold=0.7,
            combined_mode="all",
        )
        assert decision == TriageDecision.SPAM
        assert rule_t is True
        assert llm_t is True

    def test_all_mode_llm_disabled_falls_back_to_rule(self):
        decision, rule_t, llm_t = _make_decision(
            spam_score=self._spam_score(0.8),
            llm_result=self._llm_result(0.0, skipped=True),
            rule_threshold=0.6,
            llm_threshold=0.7,
            combined_mode="all",
        )
        assert decision == TriageDecision.SPAM
        assert rule_t is True
        assert llm_t is False

    def test_borderline_score_gives_uncertain(self):
        # score = 0.5, threshold = 0.6 -> near threshold (0.5 >= 0.45)
        decision, rule_t, llm_t = _make_decision(
            spam_score=self._spam_score(0.5),
            llm_result=self._llm_result(0.0, skipped=True),
            rule_threshold=0.6,
            llm_threshold=0.7,
            combined_mode="any",
        )
        assert decision == TriageDecision.UNCERTAIN
        assert rule_t is False

    def test_score_at_exact_threshold_is_spam(self):
        decision, rule_t, _ = _make_decision(
            spam_score=self._spam_score(0.6),
            llm_result=self._llm_result(0.0, skipped=True),
            rule_threshold=0.6,
            llm_threshold=0.7,
            combined_mode="any",
        )
        assert decision == TriageDecision.SPAM
        assert rule_t is True

    def test_llm_not_triggered_when_skipped(self):
        _, _, llm_t = _make_decision(
            spam_score=self._spam_score(0.1),
            llm_result=LLMResult(spam_probability=0.99, skipped=True),
            rule_threshold=0.6,
            llm_threshold=0.7,
            combined_mode="any",
        )
        assert llm_t is False


# ---------------------------------------------------------------------------
# Tests: _build_reasoning
# ---------------------------------------------------------------------------


class TestBuildReasoning:
    def _spam_score(self, total: float, **kwargs) -> SpamScore:
        return SpamScore(total_score=total, **kwargs)

    def test_spam_decision_includes_signals(self):
        score = self._spam_score(
            0.7, vague_description=True, no_code_evidence=True
        )
        llm = LLMResult(skipped=True)
        reasoning = _build_reasoning(
            decision=TriageDecision.SPAM,
            spam_score=score,
            llm_result=llm,
            rule_threshold=0.6,
            llm_threshold=0.7,
        )
        assert "spam" in reasoning.lower() or "flagged" in reasoning.lower()
        assert len(reasoning) > 0

    def test_legitimate_decision_mentions_score(self):
        score = self._spam_score(0.1)
        llm = LLMResult(skipped=True)
        reasoning = _build_reasoning(
            decision=TriageDecision.LEGITIMATE,
            spam_score=score,
            llm_result=llm,
            rule_threshold=0.6,
            llm_threshold=0.7,
        )
        assert "0.10" in reasoning or "legitimate" in reasoning.lower()

    def test_llm_info_included_when_not_skipped(self):
        score = self._spam_score(0.7)
        llm = LLMResult(spam_probability=0.85, skipped=False, model="gpt-4o-mini")
        reasoning = _build_reasoning(
            decision=TriageDecision.SPAM,
            spam_score=score,
            llm_result=llm,
            rule_threshold=0.6,
            llm_threshold=0.7,
        )
        assert "0.85" in reasoning

    def test_llm_disabled_info_included(self):
        score = self._spam_score(0.3)
        llm = LLMResult(skipped=True)
        reasoning = _build_reasoning(
            decision=TriageDecision.LEGITIMATE,
            spam_score=score,
            llm_result=llm,
            rule_threshold=0.6,
            llm_threshold=0.7,
        )
        assert "disabled" in reasoning.lower() or "LLM" in reasoning


# ---------------------------------------------------------------------------
# Tests: TriageOrchestrator.triage_issue
# ---------------------------------------------------------------------------


class TestTriageOrchestratorTriageIssue:
    def _make_orchestrator(
        self,
        settings=None,
        github_client=None,
        db_repo=None,
    ) -> TriageOrchestrator:
        if settings is None:
            settings = _make_settings()
        if db_repo is None:
            db_repo = _make_db_repo()
        return TriageOrchestrator(
            settings=settings,
            db_repo=db_repo,
            github_client=github_client,
        )

    def test_spam_issue_applies_label_and_comment(self):
        gh = _make_mock_github_client()
        orchestrator = self._make_orchestrator(
            settings=_make_settings(rule_threshold=0.3, hold_notification=True),
            github_client=gh,
        )
        result = orchestrator.triage_issue(
            repo_full_name="owner/repo",
            issue_number=1,
            issue_title="Critical bug",
            issue_body=SPAM_BODY,
        )
        assert result.decision == TriageDecision.SPAM
        assert result.rule_triggered is True
        gh.apply_label.assert_called_once()
        gh.post_spam_comment.assert_called_once()
        assert result.label_applied == "spam-suspected"
        assert result.comment_posted is True

    def test_legitimate_issue_no_github_actions(self):
        gh = _make_mock_github_client()
        orchestrator = self._make_orchestrator(
            settings=_make_settings(rule_threshold=0.6),
            github_client=gh,
        )
        result = orchestrator.triage_issue(
            repo_full_name="owner/repo",
            issue_number=2,
            issue_title="Path traversal",
            issue_body=LEGITIMATE_BODY,
        )
        assert result.decision == TriageDecision.LEGITIMATE
        gh.apply_label.assert_not_called()
        gh.post_spam_comment.assert_not_called()
        assert result.label_applied is None
        assert result.comment_posted is False

    def test_no_comment_when_hold_notification_false(self):
        gh = _make_mock_github_client()
        orchestrator = self._make_orchestrator(
            settings=_make_settings(
                rule_threshold=0.3,
                hold_notification=False,
            ),
            github_client=gh,
        )
        result = orchestrator.triage_issue(
            repo_full_name="owner/repo",
            issue_number=3,
            issue_body=SPAM_BODY,
        )
        # Label should still be applied but no comment.
        gh.apply_label.assert_called_once()
        gh.post_spam_comment.assert_not_called()
        assert result.comment_posted is False

    def test_no_github_actions_when_disabled(self):
        gh = _make_mock_github_client()
        orchestrator = self._make_orchestrator(
            settings=_make_settings(rule_threshold=0.3),
            github_client=gh,
        )
        result = orchestrator.triage_issue(
            repo_full_name="owner/repo",
            issue_number=4,
            issue_body=SPAM_BODY,
            apply_github_actions=False,
        )
        gh.apply_label.assert_not_called()
        gh.post_spam_comment.assert_not_called()
        assert result.label_applied is None
        assert result.comment_posted is False

    def test_result_persisted_to_database(self):
        db_repo = _make_db_repo()
        orchestrator = self._make_orchestrator(
            settings=_make_settings(rule_threshold=0.3),
            db_repo=db_repo,
        )
        orchestrator.triage_issue(
            repo_full_name="owner/persist-test",
            issue_number=99,
            issue_body=SPAM_BODY,
            apply_github_actions=False,
        )
        record = db_repo.get_by_repo_and_issue("owner/persist-test", 99)
        assert record is not None
        assert record.issue_number == 99
        assert record.triage_result.decision == TriageDecision.SPAM

    def test_github_label_error_is_swallowed(self):
        from bounty_guard.github_client import LabelError

        gh = _make_mock_github_client()
        gh.apply_label.side_effect = LabelError("GitHub API error")
        orchestrator = self._make_orchestrator(
            settings=_make_settings(rule_threshold=0.3),
            github_client=gh,
        )
        # Should not raise even though the GitHub API fails.
        result = orchestrator.triage_issue(
            repo_full_name="owner/repo",
            issue_number=5,
            issue_body=SPAM_BODY,
        )
        assert result.decision == TriageDecision.SPAM
        assert result.label_applied is None

    def test_github_comment_error_is_swallowed(self):
        from bounty_guard.github_client import CommentError

        gh = _make_mock_github_client()
        gh.post_spam_comment.side_effect = CommentError("GitHub API error")
        orchestrator = self._make_orchestrator(
            settings=_make_settings(rule_threshold=0.3, hold_notification=True),
            github_client=gh,
        )
        result = orchestrator.triage_issue(
            repo_full_name="owner/repo",
            issue_number=6,
            issue_body=SPAM_BODY,
        )
        # Label was applied but comment posting failed gracefully.
        assert result.label_applied == "spam-suspected"
        assert result.comment_posted is False

    def test_llm_result_included_in_triage_result(self):
        mock_llm_result = LLMResult(
            spam_probability=0.9,
            reasoning="Looks like AI spam.",
            model="gpt-4o-mini",
            skipped=False,
        )
        with patch(
            "bounty_guard.triage.classify_issue",
            return_value=mock_llm_result,
        ):
            orchestrator = self._make_orchestrator(
                settings=_make_settings(
                    rule_threshold=0.6,
                    llm_enabled=True,
                    llm_threshold=0.7,
                    combined_mode="any",
                    openai_api_key="sk-fake",
                ),
            )
            result = orchestrator.triage_issue(
                repo_full_name="owner/repo",
                issue_number=7,
                issue_body=LEGITIMATE_BODY,
                apply_github_actions=False,
            )
        assert result.llm_result.spam_probability == pytest.approx(0.9)
        assert result.llm_triggered is True

    def test_combined_mode_all_requires_both(self):
        mock_llm_result = LLMResult(
            spam_probability=0.2,
            skipped=False,
            model="gpt-4o-mini",
        )
        with patch(
            "bounty_guard.triage.classify_issue",
            return_value=mock_llm_result,
        ):
            orchestrator = self._make_orchestrator(
                settings=_make_settings(
                    rule_threshold=0.3,
                    llm_enabled=True,
                    llm_threshold=0.7,
                    combined_mode="all",
                    openai_api_key="sk-fake",
                ),
            )
            # SPAM_BODY will fire the rule (score > 0.3) but LLM gives 0.2 < 0.7.
            result = orchestrator.triage_issue(
                repo_full_name="owner/repo",
                issue_number=8,
                issue_body=SPAM_BODY,
                apply_github_actions=False,
            )
        # In 'all' mode, both must trigger; LLM didn't, so not SPAM.
        assert result.decision != TriageDecision.SPAM

    def test_result_contains_reasoning(self):
        orchestrator = self._make_orchestrator(
            settings=_make_settings(rule_threshold=0.3),
        )
        result = orchestrator.triage_issue(
            repo_full_name="owner/repo",
            issue_number=9,
            issue_body=SPAM_BODY,
            apply_github_actions=False,
        )
        assert len(result.reasoning) > 0

    def test_empty_body_scores_spam(self):
        orchestrator = self._make_orchestrator(
            settings=_make_settings(rule_threshold=0.6),
        )
        result = orchestrator.triage_issue(
            repo_full_name="owner/repo",
            issue_number=10,
            issue_body="",
            apply_github_actions=False,
        )
        assert result.decision == TriageDecision.SPAM
        assert result.spam_score.total_score == 1.0

    def test_triage_result_has_spam_score(self):
        orchestrator = self._make_orchestrator()
        result = orchestrator.triage_issue(
            repo_full_name="owner/repo",
            issue_number=11,
            issue_body=LEGITIMATE_BODY,
            apply_github_actions=False,
        )
        assert isinstance(result.spam_score, SpamScore)
        assert 0.0 <= result.spam_score.total_score <= 1.0

    def test_installation_id_passed_to_github_client(self):
        gh = _make_mock_github_client()
        orchestrator = self._make_orchestrator(
            settings=_make_settings(rule_threshold=0.3, hold_notification=False),
            github_client=gh,
        )
        orchestrator.triage_issue(
            repo_full_name="owner/repo",
            issue_number=12,
            issue_body=SPAM_BODY,
            installation_id=999,
        )
        gh.set_installation_id.assert_called_with(999)


# ---------------------------------------------------------------------------
# Tests: TriageOrchestrator.retriage_issue
# ---------------------------------------------------------------------------


class TestTriageOrchestratorRetriageIssue:
    def test_retriage_removes_label_first(self):
        gh = _make_mock_github_client()
        orchestrator = TriageOrchestrator(
            settings=_make_settings(rule_threshold=0.3, hold_notification=False),
            db_repo=_make_db_repo(),
            github_client=gh,
        )
        orchestrator.retriage_issue(
            repo_full_name="owner/repo",
            issue_number=1,
            issue_body=SPAM_BODY,
        )
        gh.remove_label.assert_called_once_with(
            repo_full_name="owner/repo",
            issue_number=1,
            label_name="spam-suspected",
        )

    def test_retriage_skips_label_removal_when_no_github_actions(self):
        gh = _make_mock_github_client()
        orchestrator = TriageOrchestrator(
            settings=_make_settings(rule_threshold=0.3),
            db_repo=_make_db_repo(),
            github_client=gh,
        )
        orchestrator.retriage_issue(
            repo_full_name="owner/repo",
            issue_number=2,
            issue_body=SPAM_BODY,
            apply_github_actions=False,
        )
        gh.remove_label.assert_not_called()

    def test_retriage_returns_triage_result(self):
        orchestrator = TriageOrchestrator(
            settings=_make_settings(rule_threshold=0.3),
            db_repo=_make_db_repo(),
        )
        result = orchestrator.retriage_issue(
            repo_full_name="owner/repo",
            issue_number=3,
            issue_body=SPAM_BODY,
            apply_github_actions=False,
        )
        assert isinstance(result, TriageResult)

    def test_retriage_swallows_remove_label_error(self):
        from bounty_guard.github_client import LabelError

        gh = _make_mock_github_client()
        gh.remove_label.side_effect = LabelError("Not found")
        orchestrator = TriageOrchestrator(
            settings=_make_settings(rule_threshold=0.3, hold_notification=False),
            db_repo=_make_db_repo(),
            github_client=gh,
        )
        # Should not raise.
        result = orchestrator.retriage_issue(
            repo_full_name="owner/repo",
            issue_number=4,
            issue_body=SPAM_BODY,
        )
        assert isinstance(result, TriageResult)


# ---------------------------------------------------------------------------
# Tests: get_orchestrator factory
# ---------------------------------------------------------------------------


class TestGetOrchestrator:
    def test_returns_orchestrator_instance(self):
        orchestrator = get_orchestrator()
        assert isinstance(orchestrator, TriageOrchestrator)

    def test_injected_db_repo_used(self):
        db_repo = _make_db_repo()
        orchestrator = get_orchestrator(db_repo=db_repo)
        assert orchestrator._db_repo is db_repo

    def test_injected_github_client_used(self):
        gh = _make_mock_github_client()
        orchestrator = get_orchestrator(github_client=gh)
        assert orchestrator._github_client is gh
