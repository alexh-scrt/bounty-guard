"""Triage orchestrator for BountyGuard.

This module is the central coordination layer that combines the rule-based
scorer and optional LLM classifier results into a final :class:`TriageDecision`,
then triggers the appropriate GitHub actions (applying labels and posting
clarification comments) via the GitHub client.

Orchestration flow
------------------
1. Run the rule-based scorer on the issue body to produce a :class:`SpamScore`.
2. Optionally run the LLM classifier to produce an :class:`LLMResult`.
3. Combine the two scores using the configured ``combined_mode`` (``'any'`` or
   ``'all'``) to reach a :class:`TriageDecision`.
4. If the decision is ``SPAM`` (or ``UNCERTAIN`` based on config), apply the
   configured spam label and optionally post a comment via the GitHub client.
5. Persist the :class:`IssueRecord` to the SQLite database.
6. Return the :class:`TriageResult` to the caller.

Example usage::

    from bounty_guard.triage import TriageOrchestrator
    from bounty_guard.config import settings

    orchestrator = TriageOrchestrator(settings=settings)
    result = orchestrator.triage_issue(
        repo_full_name="owner/repo",
        issue_number=42,
        issue_title="Critical RCE in login",
        issue_body="Dear Security Team...",
        issue_url="https://github.com/owner/repo/issues/42",
        author_login="badactor",
        installation_id=12345,
    )
    print(result.decision)  # TriageDecision.SPAM
"""

from __future__ import annotations

import logging
from typing import Optional

from bounty_guard.models import (
    IssueRecord,
    LLMResult,
    SpamScore,
    TriageDecision,
    TriageRepository,
    TriageResult,
)
from bounty_guard.scorer import score_issue
from bounty_guard.llm_classifier import classify_issue
from bounty_guard.github_client import GitHubClient, GitHubClientError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Reasoning template
# ---------------------------------------------------------------------------

_REASONING_TEMPLATES = {
    TriageDecision.SPAM: (
        "Issue flagged as suspected spam. "
        "Rule score: {rule_score:.2f} (threshold: {rule_threshold:.2f}). "
        "{llm_info}"
        "Fired signals: {signals}."
    ),
    TriageDecision.LEGITIMATE: (
        "Issue appears to be a legitimate security report. "
        "Rule score: {rule_score:.2f} (threshold: {rule_threshold:.2f}). "
        "{llm_info}"
    ),
    TriageDecision.UNCERTAIN: (
        "Issue is borderline; human review recommended. "
        "Rule score: {rule_score:.2f} (threshold: {rule_threshold:.2f}). "
        "{llm_info}"
        "Fired signals: {signals}."
    ),
}


def _build_reasoning(
    decision: TriageDecision,
    spam_score: SpamScore,
    llm_result: LLMResult,
    rule_threshold: float,
    llm_threshold: float,
) -> str:
    """Build a human-readable reasoning string for the triage decision.

    Args:
        decision:       The final triage decision.
        spam_score:     Rule-based score breakdown.
        llm_result:     LLM classifier result (may be skipped).
        rule_threshold: Configured rule-based score threshold.
        llm_threshold:  Configured LLM probability threshold.

    Returns:
        A plain-English explanation suitable for inclusion in a GitHub comment.
    """
    if llm_result.skipped:
        llm_info = "LLM classification: disabled. "
    else:
        llm_info = (
            f"LLM score: {llm_result.spam_probability:.2f} "
            f"(threshold: {llm_threshold:.2f}). "
        )

    template = _REASONING_TEMPLATES.get(
        decision, _REASONING_TEMPLATES[TriageDecision.UNCERTAIN]
    )
    return template.format(
        rule_score=spam_score.total_score,
        rule_threshold=rule_threshold,
        llm_info=llm_info,
        signals=", ".join(spam_score.fired_signals) if spam_score.fired_signals else "none",
    )


# ---------------------------------------------------------------------------
# Decision logic
# ---------------------------------------------------------------------------


def _make_decision(
    spam_score: SpamScore,
    llm_result: LLMResult,
    rule_threshold: float,
    llm_threshold: float,
    combined_mode: str,
) -> tuple[TriageDecision, bool, bool]:
    """Derive the final :class:`TriageDecision` from rule and LLM scores.

    Args:
        spam_score:     Rule-based score breakdown.
        llm_result:     LLM classifier result.
        rule_threshold: Score threshold for rule-based spam detection.
        llm_threshold:  Probability threshold for LLM spam detection.
        combined_mode:  ``'any'`` to flag when either exceeds its threshold;
                        ``'all'`` to require both.

    Returns:
        A 3-tuple of ``(decision, rule_triggered, llm_triggered)``.
    """
    rule_triggered = spam_score.total_score >= rule_threshold
    llm_triggered = (
        not llm_result.skipped
        and llm_result.spam_probability >= llm_threshold
    )

    if combined_mode == "all":
        if llm_result.skipped:
            # When LLM is disabled, fall back to rule-only.
            is_spam = rule_triggered
        else:
            is_spam = rule_triggered and llm_triggered
    else:  # "any" (default)
        is_spam = rule_triggered or llm_triggered

    if is_spam:
        decision = TriageDecision.SPAM
    else:
        # Borderline: rule is close to threshold but did not exceed it.
        near_threshold = (
            spam_score.total_score >= rule_threshold * 0.75
            and spam_score.total_score < rule_threshold
        )
        if near_threshold:
            decision = TriageDecision.UNCERTAIN
        else:
            decision = TriageDecision.LEGITIMATE

    return decision, rule_triggered, llm_triggered


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class TriageOrchestrator:
    """Coordinates scoring, classification, GitHub actions, and persistence.

    The orchestrator is designed to be instantiated once per application
    lifecycle (or per request if settings change dynamically) and its
    :meth:`triage_issue` method called for each incoming issue.

    Args:
        settings:     Application settings instance.  When ``None``, the
                      module-level singleton from ``bounty_guard.config`` is
                      used.
        db_repo:      Optional pre-connected :class:`TriageRepository`.  When
                      ``None`` a new repository is opened from settings.
        github_client: Optional pre-configured :class:`GitHubClient`.  When
                       ``None`` the client is constructed from settings at
                       triage time using the installation_id from the webhook.
    """

    def __init__(
        self,
        settings=None,
        db_repo: Optional[TriageRepository] = None,
        github_client: Optional[GitHubClient] = None,
    ) -> None:
        """Initialise the orchestrator.

        Args:
            settings:      Settings instance or None to use global settings.
            db_repo:       Pre-connected TriageRepository or None.
            github_client: Pre-configured GitHubClient or None.
        """
        self._settings = settings
        self._db_repo = db_repo
        self._github_client = github_client

    def _get_settings(self):
        """Return the settings instance, falling back to the global singleton."""
        if self._settings is not None:
            return self._settings
        try:
            from bounty_guard.config import settings as _settings
            return _settings
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Could not load application settings. "
                "Ensure environment variables are configured."
            ) from exc

    def _get_db_repo(self) -> TriageRepository:
        """Return the database repository, creating one if not injected."""
        if self._db_repo is not None:
            return self._db_repo
        cfg = self._get_settings()
        db_path = cfg.database_url if cfg is not None else "bounty_guard.db"
        repo = TriageRepository(db_path=db_path)
        repo.connect()
        self._db_repo = repo
        return repo

    def _get_github_client(
        self, installation_id: Optional[int] = None
    ) -> Optional[GitHubClient]:
        """Return the GitHub client, constructing one if not injected.

        Args:
            installation_id: Installation ID extracted from the webhook payload.

        Returns:
            A configured :class:`GitHubClient`, or ``None`` if settings are
            unavailable.
        """
        if self._github_client is not None:
            if installation_id is not None:
                self._github_client.set_installation_id(installation_id)
            return self._github_client

        cfg = self._get_settings()
        if cfg is None:  # pragma: no cover
            return None

        iid = installation_id or cfg.github_installation_id
        from bounty_guard.github_client import GitHubClient as _GitHubClient

        client = _GitHubClient(
            app_id=cfg.github_app_id,
            private_key=cfg.github_private_key,
            installation_id=iid,
        )
        return client

    # ------------------------------------------------------------------
    # Core triage logic
    # ------------------------------------------------------------------

    def triage_issue(
        self,
        repo_full_name: str,
        issue_number: int,
        issue_title: str = "",
        issue_body: Optional[str] = None,
        issue_url: str = "",
        author_login: str = "",
        installation_id: Optional[int] = None,
        apply_github_actions: bool = True,
    ) -> TriageResult:
        """Perform a full triage pass on a single GitHub issue.

        Steps:
            1. Score the issue body with the rule-based rubric.
            2. Optionally classify with the LLM.
            3. Make a combined decision.
            4. Optionally apply a GitHub label and post a comment.
            5. Persist the result to the database.
            6. Return the :class:`TriageResult`.

        Args:
            repo_full_name:       Repository in ``owner/name`` format.
            issue_number:         GitHub issue number.
            issue_title:          Title of the issue.
            issue_body:           Raw Markdown body text of the issue.
            issue_url:            HTML URL of the issue on GitHub.
            author_login:         GitHub login of the issue author.
            installation_id:      GitHub App installation ID (from webhook).
            apply_github_actions: When ``True`` (default) applies label and
                                  posts comment for spam/uncertain issues.
                                  Set to ``False`` in tests or dry-run mode.

        Returns:
            The fully populated :class:`TriageResult`.
        """
        cfg = self._get_settings()
        rule_threshold: float = cfg.spam_score_threshold if cfg else 0.6
        llm_threshold: float = cfg.llm_spam_threshold if cfg else 0.7
        combined_mode: str = cfg.combined_mode if cfg else "any"
        spam_label: str = cfg.spam_label if cfg else "spam-suspected"
        hold_notification: bool = cfg.hold_notification if cfg else True
        llm_enabled: bool = cfg.llm_enabled if cfg else False
        openai_api_key: Optional[str] = cfg.openai_api_key if cfg else None
        openai_model: str = cfg.openai_model if cfg else "gpt-4o-mini"

        logger.info(
            "Triaging %s#%d (title=%r)",
            repo_full_name,
            issue_number,
            issue_title[:80] if issue_title else "",
        )

        # Step 1: Rule-based scoring.
        spam_score: SpamScore = score_issue(issue_body)
        logger.debug(
            "Rule score for %s#%d: %.3f (signals=%s)",
            repo_full_name,
            issue_number,
            spam_score.total_score,
            spam_score.fired_signals,
        )

        # Step 2: Optional LLM classification.
        llm_result: LLMResult = classify_issue(
            issue_body=issue_body,
            issue_title=issue_title,
            api_key=openai_api_key,
            model=openai_model,
            enabled=llm_enabled,
        )
        if not llm_result.skipped:
            logger.debug(
                "LLM score for %s#%d: %.3f",
                repo_full_name,
                issue_number,
                llm_result.spam_probability,
            )

        # Step 3: Combined decision.
        decision, rule_triggered, llm_triggered = _make_decision(
            spam_score=spam_score,
            llm_result=llm_result,
            rule_threshold=rule_threshold,
            llm_threshold=llm_threshold,
            combined_mode=combined_mode,
        )

        reasoning = _build_reasoning(
            decision=decision,
            spam_score=spam_score,
            llm_result=llm_result,
            rule_threshold=rule_threshold,
            llm_threshold=llm_threshold,
        )

        label_applied: Optional[str] = None
        comment_posted: bool = False

        # Step 4: GitHub actions (label + comment) for spam/uncertain.
        if apply_github_actions and decision in (
            TriageDecision.SPAM,
            TriageDecision.UNCERTAIN,
        ):
            gh_client = self._get_github_client(installation_id=installation_id)
            if gh_client is not None:
                try:
                    gh_client.apply_label(
                        repo_full_name=repo_full_name,
                        issue_number=issue_number,
                        label_name=spam_label,
                    )
                    label_applied = spam_label
                    logger.info(
                        "Applied label '%s' to %s#%d",
                        spam_label,
                        repo_full_name,
                        issue_number,
                    )
                except GitHubClientError as exc:
                    logger.warning(
                        "Failed to apply label to %s#%d: %s",
                        repo_full_name,
                        issue_number,
                        exc,
                    )

                if hold_notification:
                    try:
                        # Include LLM reasoning if available.
                        comment_reasoning = reasoning
                        if not llm_result.skipped and llm_result.reasoning:
                            comment_reasoning = (
                                f"{reasoning}\n\n"
                                f"**LLM analysis:** {llm_result.reasoning}"
                            )
                        gh_client.post_spam_comment(
                            repo_full_name=repo_full_name,
                            issue_number=issue_number,
                            reasoning=comment_reasoning,
                        )
                        comment_posted = True
                        logger.info(
                            "Posted clarification comment on %s#%d",
                            repo_full_name,
                            issue_number,
                        )
                    except GitHubClientError as exc:
                        logger.warning(
                            "Failed to post comment on %s#%d: %s",
                            repo_full_name,
                            issue_number,
                            exc,
                        )
            else:  # pragma: no cover
                logger.warning(
                    "No GitHub client available; skipping label/comment for %s#%d.",
                    repo_full_name,
                    issue_number,
                )

        # Build the final TriageResult.
        triage_result = TriageResult(
            decision=decision,
            spam_score=spam_score,
            llm_result=llm_result,
            rule_triggered=rule_triggered,
            llm_triggered=llm_triggered,
            label_applied=label_applied,
            comment_posted=comment_posted,
            reasoning=reasoning,
        )

        # Step 5: Persist.
        issue_record = IssueRecord(
            repo_full_name=repo_full_name,
            issue_number=issue_number,
            issue_title=issue_title,
            issue_url=issue_url,
            author_login=author_login,
            triage_result=triage_result,
        )
        try:
            db_repo = self._get_db_repo()
            db_repo.upsert(issue_record)
            logger.debug(
                "Persisted triage record for %s#%d",
                repo_full_name,
                issue_number,
            )
        except Exception as exc:
            logger.error(
                "Failed to persist triage record for %s#%d: %s",
                repo_full_name,
                issue_number,
                exc,
            )

        logger.info(
            "Triage complete for %s#%d: decision=%s rule_score=%.3f",
            repo_full_name,
            issue_number,
            decision.value,
            spam_score.total_score,
        )
        return triage_result

    def retriage_issue(
        self,
        repo_full_name: str,
        issue_number: int,
        issue_title: str = "",
        issue_body: Optional[str] = None,
        issue_url: str = "",
        author_login: str = "",
        installation_id: Optional[int] = None,
        apply_github_actions: bool = True,
    ) -> TriageResult:
        """Re-run triage on an issue, typically after threshold changes.

        This method removes any existing spam label before retriaging so that
        the outcome reflects the current configuration.

        Args:
            repo_full_name:       Repository in ``owner/name`` format.
            issue_number:         GitHub issue number.
            issue_title:          Title of the issue.
            issue_body:           Raw Markdown body text.
            issue_url:            HTML URL of the issue.
            author_login:         GitHub login of the issue author.
            installation_id:      GitHub App installation ID.
            apply_github_actions: When ``True``, apply GitHub labels/comments.

        Returns:
            The new :class:`TriageResult` after retriaging.
        """
        cfg = self._get_settings()
        spam_label: str = cfg.spam_label if cfg else "spam-suspected"

        # Remove existing spam label before retriaging.
        if apply_github_actions:
            gh_client = self._get_github_client(installation_id=installation_id)
            if gh_client is not None:
                try:
                    removed = gh_client.remove_label(
                        repo_full_name=repo_full_name,
                        issue_number=issue_number,
                        label_name=spam_label,
                    )
                    if removed:
                        logger.info(
                            "Removed '%s' label from %s#%d before retriage.",
                            spam_label,
                            repo_full_name,
                            issue_number,
                        )
                except GitHubClientError as exc:
                    logger.warning(
                        "Could not remove label before retriage for %s#%d: %s",
                        repo_full_name,
                        issue_number,
                        exc,
                    )

        return self.triage_issue(
            repo_full_name=repo_full_name,
            issue_number=issue_number,
            issue_title=issue_title,
            issue_body=issue_body,
            issue_url=issue_url,
            author_login=author_login,
            installation_id=installation_id,
            apply_github_actions=apply_github_actions,
        )


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------


def get_orchestrator(
    settings=None,
    db_repo: Optional[TriageRepository] = None,
    github_client: Optional[GitHubClient] = None,
) -> TriageOrchestrator:
    """Create and return a :class:`TriageOrchestrator`.

    This is a convenience factory that can be used with FastAPI's ``Depends``
    mechanism or called directly in tests with injected dependencies.

    Args:
        settings:      Settings instance override.  When ``None`` the global
                       singleton from ``bounty_guard.config`` is used.
        db_repo:       Pre-connected :class:`TriageRepository` override.
        github_client: Pre-configured :class:`GitHubClient` override.

    Returns:
        A :class:`TriageOrchestrator` instance.
    """
    return TriageOrchestrator(
        settings=settings,
        db_repo=db_repo,
        github_client=github_client,
    )
