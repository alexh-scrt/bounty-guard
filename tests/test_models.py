"""Tests for bounty_guard.models - Pydantic models and SQLite persistence layer.

Covers:
- SpamScore: field defaults, clamp validator, fired_signals, signal_count.
- LLMResult: field defaults, clamp validator, skipped flag.
- TriageResult: construction with nested models, default llm_result.
- IssueRecord: construction, field constraints.
- TriageRepository: connect/close, upsert (insert + update), get, list,
  delete, count, context-manager protocol, error on unconnected access.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from bounty_guard.models import (
    IssueRecord,
    LLMResult,
    SpamScore,
    TriageDecision,
    TriageRepository,
    TriageResult,
    get_repository,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_spam_score(**kwargs) -> SpamScore:
    return SpamScore(**kwargs)


def _make_llm_result(**kwargs) -> LLMResult:
    return LLMResult(**kwargs)


def _make_triage_result(
    decision: TriageDecision = TriageDecision.LEGITIMATE,
    spam_score: SpamScore | None = None,
    **kwargs,
) -> TriageResult:
    if spam_score is None:
        spam_score = SpamScore()
    return TriageResult(decision=decision, spam_score=spam_score, **kwargs)


def _make_issue_record(
    repo: str = "owner/repo",
    issue_number: int = 1,
    decision: TriageDecision = TriageDecision.LEGITIMATE,
    **kwargs,
) -> IssueRecord:
    triage_result = _make_triage_result(decision=decision)
    return IssueRecord(
        repo_full_name=repo,
        issue_number=issue_number,
        issue_title="Test issue",
        issue_url="https://github.com/owner/repo/issues/1",
        author_login="octocat",
        triage_result=triage_result,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# SpamScore tests
# ---------------------------------------------------------------------------


class TestSpamScore:
    def test_defaults_all_false(self):
        score = SpamScore()
        assert score.vague_description is False
        assert score.missing_reproduction_steps is False
        assert score.cve_template_detected is False
        assert score.no_code_evidence is False
        assert score.excessive_severity_claims is False
        assert score.generic_greeting is False
        assert score.suspiciously_short is False
        assert score.total_score == 0.0

    def test_total_score_clamped_above_one(self):
        score = SpamScore(total_score=1.5)
        assert score.total_score == 1.0

    def test_total_score_clamped_below_zero(self):
        score = SpamScore(total_score=-0.5)
        assert score.total_score == 0.0

    def test_total_score_boundary_values(self):
        assert SpamScore(total_score=0.0).total_score == 0.0
        assert SpamScore(total_score=1.0).total_score == 1.0

    def test_fired_signals_empty_when_none_set(self):
        score = SpamScore()
        assert score.fired_signals == []

    def test_fired_signals_returns_true_fields(self):
        score = SpamScore(
            vague_description=True,
            no_code_evidence=True,
            suspiciously_short=True,
        )
        fired = score.fired_signals
        assert "vague_description" in fired
        assert "no_code_evidence" in fired
        assert "suspiciously_short" in fired
        assert "missing_reproduction_steps" not in fired

    def test_signal_count_matches_fired(self):
        score = SpamScore(
            vague_description=True,
            cve_template_detected=True,
        )
        assert score.signal_count == 2

    def test_signal_count_zero_default(self):
        assert SpamScore().signal_count == 0

    def test_all_signals_fired(self):
        score = SpamScore(
            vague_description=True,
            missing_reproduction_steps=True,
            cve_template_detected=True,
            no_code_evidence=True,
            excessive_severity_claims=True,
            generic_greeting=True,
            suspiciously_short=True,
        )
        assert score.signal_count == 7
        assert len(score.fired_signals) == 7


# ---------------------------------------------------------------------------
# LLMResult tests
# ---------------------------------------------------------------------------


class TestLLMResult:
    def test_defaults(self):
        result = LLMResult()
        assert result.spam_probability == 0.0
        assert result.reasoning == ""
        assert result.model == ""
        assert result.skipped is False
        assert result.error is None

    def test_skipped_flag(self):
        result = LLMResult(skipped=True)
        assert result.skipped is True

    def test_probability_clamped_above_one(self):
        result = LLMResult(spam_probability=2.0)
        assert result.spam_probability == 1.0

    def test_probability_clamped_below_zero(self):
        result = LLMResult(spam_probability=-1.0)
        assert result.spam_probability == 0.0

    def test_error_field(self):
        result = LLMResult(error="API timeout", skipped=True)
        assert result.error == "API timeout"

    def test_full_construction(self):
        result = LLMResult(
            spam_probability=0.85,
            reasoning="Missing repro steps and vague claims.",
            model="gpt-4o-mini",
        )
        assert result.spam_probability == 0.85
        assert "repro" in result.reasoning
        assert result.model == "gpt-4o-mini"


# ---------------------------------------------------------------------------
# TriageResult tests
# ---------------------------------------------------------------------------


class TestTriageResult:
    def test_basic_construction(self):
        score = SpamScore(vague_description=True, total_score=0.3)
        result = TriageResult(decision=TriageDecision.SPAM, spam_score=score)
        assert result.decision == TriageDecision.SPAM
        assert result.spam_score.vague_description is True

    def test_default_llm_result_is_skipped(self):
        result = _make_triage_result()
        assert result.llm_result.skipped is True

    def test_triaged_at_is_utc(self):
        result = _make_triage_result()
        assert result.triaged_at.tzinfo is not None

    def test_explicit_llm_result(self):
        llm = LLMResult(spam_probability=0.9, reasoning="Spam", model="gpt-4o")
        result = _make_triage_result(llm_result=llm)
        assert result.llm_result.spam_probability == 0.9
        assert result.llm_result.skipped is False

    def test_rule_and_llm_triggered_flags(self):
        result = _make_triage_result(
            decision=TriageDecision.SPAM,
            rule_triggered=True,
            llm_triggered=True,
        )
        assert result.rule_triggered is True
        assert result.llm_triggered is True

    def test_label_and_comment_defaults(self):
        result = _make_triage_result()
        assert result.label_applied is None
        assert result.comment_posted is False

    def test_reasoning_field(self):
        result = _make_triage_result(reasoning="Rule score 0.7 exceeded threshold.")
        assert "threshold" in result.reasoning

    def test_all_decisions_valid(self):
        for decision in TriageDecision:
            result = _make_triage_result(decision=decision)
            assert result.decision == decision


# ---------------------------------------------------------------------------
# IssueRecord tests
# ---------------------------------------------------------------------------


class TestIssueRecord:
    def test_basic_construction(self):
        record = _make_issue_record()
        assert record.repo_full_name == "owner/repo"
        assert record.issue_number == 1
        assert record.id is None

    def test_created_at_and_updated_at_defaults_are_utc(self):
        record = _make_issue_record()
        assert record.created_at.tzinfo is not None
        assert record.updated_at.tzinfo is not None

    def test_invalid_issue_number_raises(self):
        with pytest.raises(Exception):
            _make_issue_record(issue_number=0)

    def test_optional_id_field(self):
        record = _make_issue_record()
        assert record.id is None
        record_with_id = record.model_copy(update={"id": 42})
        assert record_with_id.id == 42

    def test_triage_result_embedded(self):
        record = _make_issue_record(decision=TriageDecision.SPAM)
        assert record.triage_result.decision == TriageDecision.SPAM


# ---------------------------------------------------------------------------
# TriageRepository tests
# ---------------------------------------------------------------------------


@pytest.fixture
def repo() -> TriageRepository:
    """Return a connected in-memory TriageRepository."""
    r = TriageRepository(db_path=":memory:")
    r.connect()
    yield r
    r.close()


class TestTriageRepository:
    def test_context_manager_connects_and_closes(self):
        with TriageRepository(db_path=":memory:") as r:
            assert r._conn is not None
        assert r._conn is None

    def test_upsert_inserts_new_record(self, repo):
        record = _make_issue_record(repo="acme/project", issue_number=10)
        saved = repo.upsert(record)
        assert saved.id is not None

    def test_upsert_updates_existing_record(self, repo):
        record = _make_issue_record(decision=TriageDecision.LEGITIMATE)
        saved = repo.upsert(record)
        assert saved.triage_result.decision == TriageDecision.LEGITIMATE

        updated_result = _make_triage_result(decision=TriageDecision.SPAM)
        updated_record = saved.model_copy(
            update={"triage_result": updated_result, "issue_title": "Updated"}
        )
        saved2 = repo.upsert(updated_record)
        assert saved2.id == saved.id
        assert saved2.triage_result.decision == TriageDecision.SPAM

    def test_get_by_repo_and_issue_returns_record(self, repo):
        record = _make_issue_record(repo="owner/test", issue_number=5)
        repo.upsert(record)
        fetched = repo.get_by_repo_and_issue("owner/test", 5)
        assert fetched is not None
        assert fetched.issue_number == 5

    def test_get_by_repo_and_issue_returns_none_when_missing(self, repo):
        result = repo.get_by_repo_and_issue("owner/missing", 999)
        assert result is None

    def test_get_by_id_returns_record(self, repo):
        record = _make_issue_record()
        saved = repo.upsert(record)
        fetched = repo.get_by_id(saved.id)
        assert fetched is not None
        assert fetched.id == saved.id

    def test_get_by_id_returns_none_for_missing(self, repo):
        assert repo.get_by_id(99999) is None

    def test_list_by_repo_returns_records(self, repo):
        for i in range(1, 4):
            repo.upsert(_make_issue_record(repo="org/repo", issue_number=i))
        records = repo.list_by_repo("org/repo")
        assert len(records) == 3

    def test_list_by_repo_filters_by_decision(self, repo):
        repo.upsert(
            _make_issue_record(
                repo="org/repo", issue_number=1, decision=TriageDecision.SPAM
            )
        )
        repo.upsert(
            _make_issue_record(
                repo="org/repo", issue_number=2, decision=TriageDecision.LEGITIMATE
            )
        )
        spam_records = repo.list_by_repo("org/repo", decision=TriageDecision.SPAM)
        assert len(spam_records) == 1
        assert spam_records[0].triage_result.decision == TriageDecision.SPAM

    def test_list_by_repo_pagination(self, repo):
        for i in range(1, 6):
            repo.upsert(_make_issue_record(repo="org/paginate", issue_number=i))
        page1 = repo.list_by_repo("org/paginate", limit=3, offset=0)
        page2 = repo.list_by_repo("org/paginate", limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 2
        ids1 = {r.id for r in page1}
        ids2 = {r.id for r in page2}
        assert ids1.isdisjoint(ids2)

    def test_list_all_returns_all_repos(self, repo):
        repo.upsert(_make_issue_record(repo="a/b", issue_number=1))
        repo.upsert(_make_issue_record(repo="c/d", issue_number=2))
        all_records = repo.list_all()
        assert len(all_records) == 2

    def test_list_all_filters_by_decision(self, repo):
        repo.upsert(
            _make_issue_record(
                repo="a/b", issue_number=1, decision=TriageDecision.SPAM
            )
        )
        repo.upsert(
            _make_issue_record(
                repo="c/d", issue_number=1, decision=TriageDecision.UNCERTAIN
            )
        )
        spam_only = repo.list_all(decision=TriageDecision.SPAM)
        assert len(spam_only) == 1

    def test_delete_by_repo_and_issue_returns_true(self, repo):
        record = _make_issue_record(repo="del/repo", issue_number=7)
        repo.upsert(record)
        deleted = repo.delete_by_repo_and_issue("del/repo", 7)
        assert deleted is True
        assert repo.get_by_repo_and_issue("del/repo", 7) is None

    def test_delete_by_repo_and_issue_returns_false_when_missing(self, repo):
        deleted = repo.delete_by_repo_and_issue("nonexistent/repo", 999)
        assert deleted is False

    def test_count_by_repo(self, repo):
        for i in range(1, 4):
            repo.upsert(_make_issue_record(repo="count/repo", issue_number=i))
        assert repo.count_by_repo("count/repo") == 3

    def test_count_by_repo_with_decision_filter(self, repo):
        repo.upsert(
            _make_issue_record(
                repo="count/repo2", issue_number=1, decision=TriageDecision.SPAM
            )
        )
        repo.upsert(
            _make_issue_record(
                repo="count/repo2", issue_number=2, decision=TriageDecision.SPAM
            )
        )
        repo.upsert(
            _make_issue_record(
                repo="count/repo2", issue_number=3, decision=TriageDecision.LEGITIMATE
            )
        )
        assert repo.count_by_repo("count/repo2", decision=TriageDecision.SPAM) == 2
        assert (
            repo.count_by_repo("count/repo2", decision=TriageDecision.LEGITIMATE) == 1
        )

    def test_count_all(self, repo):
        repo.upsert(_make_issue_record(repo="x/y", issue_number=1))
        repo.upsert(_make_issue_record(repo="x/z", issue_number=1))
        assert repo.count_all() == 2

    def test_count_all_with_decision_filter(self, repo):
        repo.upsert(
            _make_issue_record(
                repo="x/y", issue_number=1, decision=TriageDecision.UNCERTAIN
            )
        )
        repo.upsert(
            _make_issue_record(
                repo="x/z", issue_number=1, decision=TriageDecision.SPAM
            )
        )
        assert repo.count_all(decision=TriageDecision.UNCERTAIN) == 1

    def test_error_raised_when_not_connected(self):
        r = TriageRepository(db_path=":memory:")
        with pytest.raises(RuntimeError, match="not connected"):
            r.upsert(_make_issue_record())

    def test_double_connect_is_idempotent(self):
        r = TriageRepository(db_path=":memory:")
        r.connect()
        conn_first = r._conn
        r.connect()  # second call should be no-op
        assert r._conn is conn_first
        r.close()

    def test_roundtrip_serialisation_preserves_data(self, repo):
        spam_score = SpamScore(
            vague_description=True,
            missing_reproduction_steps=True,
            total_score=0.57,
        )
        llm_result = LLMResult(
            spam_probability=0.82,
            reasoning="Looks like generated text.",
            model="gpt-4o-mini",
        )
        triage_result = TriageResult(
            decision=TriageDecision.SPAM,
            spam_score=spam_score,
            llm_result=llm_result,
            rule_triggered=True,
            llm_triggered=True,
            label_applied="spam-suspected",
            comment_posted=True,
            reasoning="Both rule and LLM exceeded thresholds.",
        )
        record = IssueRecord(
            repo_full_name="security/test",
            issue_number=42,
            issue_title="Remote code execution via unsafe deserialisation",
            issue_url="https://github.com/security/test/issues/42",
            author_login="badactor",
            triage_result=triage_result,
        )
        saved = repo.upsert(record)
        fetched = repo.get_by_id(saved.id)

        assert fetched is not None
        assert fetched.repo_full_name == "security/test"
        assert fetched.issue_number == 42
        assert fetched.issue_title == "Remote code execution via unsafe deserialisation"
        assert fetched.author_login == "badactor"
        assert fetched.triage_result.decision == TriageDecision.SPAM
        assert fetched.triage_result.spam_score.vague_description is True
        assert fetched.triage_result.spam_score.total_score == pytest.approx(0.57)
        assert fetched.triage_result.llm_result.spam_probability == pytest.approx(0.82)
        assert fetched.triage_result.llm_result.model == "gpt-4o-mini"
        assert fetched.triage_result.rule_triggered is True
        assert fetched.triage_result.label_applied == "spam-suspected"
        assert fetched.triage_result.comment_posted is True


# ---------------------------------------------------------------------------
# get_repository factory tests
# ---------------------------------------------------------------------------


class TestGetRepository:
    def test_get_repository_in_memory(self):
        repo = get_repository(db_path=":memory:")
        assert repo._conn is not None
        repo.close()

    def test_get_repository_returns_connected_instance(self):
        repo = get_repository(db_path=":memory:")
        try:
            count = repo.count_all()
            assert count == 0
        finally:
            repo.close()
