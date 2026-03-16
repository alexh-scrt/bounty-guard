"""GitHub client wrapper for BountyGuard.

Provides a high-level interface over PyGithub for the specific actions
BountyGuard needs to perform on GitHub issues:

- Applying a label to an issue (creating the label in the repo if it does
  not already exist).
- Posting a templated comment requesting clarification on a flagged issue.
- Fetching basic issue metadata for display in the dashboard.
- Removing a previously applied spam label (for retriaging).

All methods are synchronous because PyGithub is a synchronous library.  The
FastAPI endpoint runs these calls in a thread-pool executor via
``asyncio.to_thread`` or ``run_in_executor`` to avoid blocking the event loop.

Authentication uses GitHub App installation tokens generated from the App ID
and PEM private key supplied in the application settings.  A new token is
fetched automatically when the current one expires.

Example usage::

    from bounty_guard.github_client import GitHubClient
    from bounty_guard.config import settings

    client = GitHubClient(
        app_id=settings.github_app_id,
        private_key=settings.github_private_key,
        installation_id=42,
    )
    client.apply_label(
        repo_full_name="owner/repo",
        issue_number=7,
        label_name="spam-suspected",
        label_color="e11d48",
    )
    client.post_spam_comment(
        repo_full_name="owner/repo",
        issue_number=7,
        reasoning="Rule score 0.86 exceeded threshold.",
    )
"""

from __future__ import annotations

import logging
from typing import Optional

from github import Auth, GithubIntegration, Github, GithubException
from github.Issue import Issue
from github.Repository import Repository

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default comment template
# ---------------------------------------------------------------------------

_SPAM_COMMENT_TEMPLATE = """\
<!-- bounty-guard: spam-suspected -->
## ⚠️ BountyGuard: This report has been flagged for review

Thank you for your submission. Our automated triage system has flagged this
issue as potentially lacking the detail needed for a security report.

**Reason:** {reasoning}

To help maintainers evaluate your report, please consider adding:

- [ ] **Clear reproduction steps** – numbered, step-by-step instructions
- [ ] **Proof-of-concept code or HTTP request/response samples**
- [ ] **Specific version and environment details**
- [ ] **Concrete impact assessment** with technical justification

If this is a genuine security report, please edit the issue with the
additional details above and a maintainer will review it promptly.

*This comment was posted automatically by [BountyGuard](https://github.com/apps/bounty-guard).*
"""

# Default colour for the spam label (red).
_DEFAULT_LABEL_COLOR = "e11d48"
_DEFAULT_LABEL_DESCRIPTION = "Suspected AI-generated or low-quality security report"


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class GitHubClientError(RuntimeError):
    """Raised when a GitHub API operation fails in an unrecoverable way.

    Wraps :class:`github.GithubException` with additional context.
    """


class LabelError(GitHubClientError):
    """Raised when creating or applying a label fails."""


class CommentError(GitHubClientError):
    """Raised when posting a comment fails."""


# ---------------------------------------------------------------------------
# Client implementation
# ---------------------------------------------------------------------------


class GitHubClient:
    """High-level GitHub client for BountyGuard issue actions.

    The client authenticates as a GitHub App installation using the App ID
    and PEM private key.  A :class:`github.Github` instance is created lazily
    on the first API call and cached for the lifetime of this object.

    Args:
        app_id:          Numeric GitHub App ID.
        private_key:     PEM-encoded RSA private key for the GitHub App.
        installation_id: GitHub App installation ID for the target account /
                         organisation.  Required for write operations.
        timeout:         HTTP request timeout in seconds (default: 30).
        retry:           Number of automatic retries on transient errors.
    """

    def __init__(
        self,
        app_id: int,
        private_key: str,
        installation_id: Optional[int] = None,
        timeout: int = 30,
        retry: int = 3,
    ) -> None:
        """Initialise the client without making any API calls.

        Args:
            app_id:          Numeric GitHub App ID.
            private_key:     PEM-encoded RSA private key.
            installation_id: Installation ID for the target account.
            timeout:         HTTP timeout in seconds.
            retry:           Retry count for transient failures.
        """
        self._app_id = app_id
        self._private_key = private_key
        self._installation_id = installation_id
        self._timeout = timeout
        self._retry = retry
        self._gh: Optional[Github] = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_github(self) -> Github:
        """Return a cached, authenticated :class:`github.Github` instance.

        On the first call this method creates a GitHub App auth token for the
        configured installation and constructs a :class:`~github.Github`
        instance.  Subsequent calls return the cached instance.

        Returns:
            An authenticated :class:`github.Github` instance.

        Raises:
            GitHubClientError: If authentication fails or installation_id is
                not set.
        """
        if self._gh is not None:
            return self._gh

        if self._installation_id is None:
            raise GitHubClientError(
                "installation_id is required for GitHub API operations.  "
                "Set GITHUB_INSTALLATION_ID in your environment or pass it "
                "explicitly to GitHubClient."
            )

        try:
            app_auth = Auth.AppAuth(
                app_id=self._app_id,
                private_key=self._private_key,
            )
            integration = GithubIntegration(auth=app_auth)
            install_auth = integration.get_access_token(self._installation_id)
            self._gh = Github(
                login_or_token=install_auth.token,
                timeout=self._timeout,
                retry=self._retry,
            )
            logger.debug(
                "GitHubClient authenticated for installation %s",
                self._installation_id,
            )
        except GithubException as exc:
            raise GitHubClientError(
                f"Failed to authenticate as GitHub App installation "
                f"{self._installation_id}: {exc.data}"
            ) from exc
        except Exception as exc:
            raise GitHubClientError(
                f"Unexpected error during GitHub App authentication: {exc}"
            ) from exc

        return self._gh

    def _get_repo(self, repo_full_name: str) -> Repository:
        """Fetch and return a :class:`~github.Repository.Repository` object.

        Args:
            repo_full_name: Repository in ``owner/name`` format.

        Returns:
            A :class:`~github.Repository.Repository` instance.

        Raises:
            GitHubClientError: If the repository cannot be fetched.
        """
        try:
            return self._get_github().get_repo(repo_full_name)
        except GithubException as exc:
            raise GitHubClientError(
                f"Failed to fetch repository '{repo_full_name}': {exc.data}"
            ) from exc

    def _get_issue(self, repo_full_name: str, issue_number: int) -> Issue:
        """Fetch and return a :class:`~github.Issue.Issue` object.

        Args:
            repo_full_name: Repository in ``owner/name`` format.
            issue_number:   GitHub issue number.

        Returns:
            A :class:`~github.Issue.Issue` instance.

        Raises:
            GitHubClientError: If the issue cannot be fetched.
        """
        try:
            repo = self._get_repo(repo_full_name)
            return repo.get_issue(number=issue_number)
        except GithubException as exc:
            raise GitHubClientError(
                f"Failed to fetch issue {repo_full_name}#{issue_number}: "
                f"{exc.data}"
            ) from exc

    # ------------------------------------------------------------------
    # Label management
    # ------------------------------------------------------------------

    def ensure_label_exists(
        self,
        repo_full_name: str,
        label_name: str,
        label_color: str = _DEFAULT_LABEL_COLOR,
        label_description: str = _DEFAULT_LABEL_DESCRIPTION,
    ) -> None:
        """Create the label in the repository if it does not already exist.

        This is idempotent: if the label already exists the method returns
        without making any changes.

        Args:
            repo_full_name:    Repository in ``owner/name`` format.
            label_name:        Name of the label to create.
            label_color:       Hex colour code without the leading ``#``
                               (default: ``e11d48`` / red).
            label_description: Short description shown in the GitHub UI.

        Raises:
            LabelError: If the label cannot be created due to a non-404 API
                error.
        """
        try:
            repo = self._get_repo(repo_full_name)
            # Try to fetch the existing label first.
            try:
                repo.get_label(label_name)
                logger.debug(
                    "Label '%s' already exists in %s", label_name, repo_full_name
                )
                return
            except GithubException as exc:
                if exc.status != 404:
                    raise
            # Label does not exist; create it.
            repo.create_label(
                name=label_name,
                color=label_color,
                description=label_description,
            )
            logger.info(
                "Created label '%s' in repository %s", label_name, repo_full_name
            )
        except GithubException as exc:
            raise LabelError(
                f"Failed to ensure label '{label_name}' exists in "
                f"'{repo_full_name}': {exc.data}"
            ) from exc

    def apply_label(
        self,
        repo_full_name: str,
        issue_number: int,
        label_name: str,
        label_color: str = _DEFAULT_LABEL_COLOR,
        label_description: str = _DEFAULT_LABEL_DESCRIPTION,
    ) -> None:
        """Apply a label to a GitHub issue, creating the label if necessary.

        This method first calls :meth:`ensure_label_exists` to guarantee the
        label exists in the repository, then adds it to the specified issue.
        If the label is already present on the issue the method is a no-op.

        Args:
            repo_full_name:    Repository in ``owner/name`` format.
            issue_number:      GitHub issue number.
            label_name:        Name of the label to apply.
            label_color:       Hex colour code for label creation (default:
                               ``e11d48``).
            label_description: Description used when creating the label.

        Raises:
            LabelError: If the label cannot be applied.
            GitHubClientError: If the issue cannot be fetched.
        """
        self.ensure_label_exists(
            repo_full_name=repo_full_name,
            label_name=label_name,
            label_color=label_color,
            label_description=label_description,
        )
        try:
            issue = self._get_issue(repo_full_name, issue_number)
            # Check if label is already on the issue.
            existing_labels = [lbl.name for lbl in issue.labels]
            if label_name in existing_labels:
                logger.debug(
                    "Label '%s' already present on %s#%d",
                    label_name,
                    repo_full_name,
                    issue_number,
                )
                return
            issue.add_to_labels(label_name)
            logger.info(
                "Applied label '%s' to %s#%d",
                label_name,
                repo_full_name,
                issue_number,
            )
        except GithubException as exc:
            raise LabelError(
                f"Failed to apply label '{label_name}' to "
                f"{repo_full_name}#{issue_number}: {exc.data}"
            ) from exc

    def remove_label(
        self,
        repo_full_name: str,
        issue_number: int,
        label_name: str,
    ) -> bool:
        """Remove a label from a GitHub issue if it is present.

        Args:
            repo_full_name: Repository in ``owner/name`` format.
            issue_number:   GitHub issue number.
            label_name:     Name of the label to remove.

        Returns:
            True if the label was present and removed; False if it was not
            present on the issue.

        Raises:
            LabelError: If the removal fails for a reason other than the
                label not being present.
            GitHubClientError: If the issue cannot be fetched.
        """
        try:
            issue = self._get_issue(repo_full_name, issue_number)
            existing_labels = [lbl.name for lbl in issue.labels]
            if label_name not in existing_labels:
                logger.debug(
                    "Label '%s' not present on %s#%d; nothing to remove.",
                    label_name,
                    repo_full_name,
                    issue_number,
                )
                return False
            issue.remove_from_labels(label_name)
            logger.info(
                "Removed label '%s' from %s#%d",
                label_name,
                repo_full_name,
                issue_number,
            )
            return True
        except GithubException as exc:
            raise LabelError(
                f"Failed to remove label '{label_name}' from "
                f"{repo_full_name}#{issue_number}: {exc.data}"
            ) from exc

    # ------------------------------------------------------------------
    # Comment management
    # ------------------------------------------------------------------

    def post_spam_comment(
        self,
        repo_full_name: str,
        issue_number: int,
        reasoning: str = "",
        comment_template: str = _SPAM_COMMENT_TEMPLATE,
    ) -> str:
        """Post a templated spam-flagging comment on the specified issue.

        The comment is formatted using *comment_template* with the *reasoning*
        string injected.  An HTML marker comment is included so that future
        runs can detect if a comment was already posted.

        Args:
            repo_full_name:   Repository in ``owner/name`` format.
            issue_number:     GitHub issue number.
            reasoning:        Human-readable explanation of why the issue was
                              flagged, included in the comment body.
            comment_template: Format string for the comment body.  Must
                              contain a ``{reasoning}`` placeholder.

        Returns:
            The HTML URL of the newly created comment.

        Raises:
            CommentError: If posting the comment fails.
            GitHubClientError: If the issue cannot be fetched.
        """
        try:
            issue = self._get_issue(repo_full_name, issue_number)
            body = comment_template.format(reasoning=reasoning or "Automated rubric check.")
            comment = issue.create_comment(body)
            logger.info(
                "Posted spam comment on %s#%d (comment id=%d)",
                repo_full_name,
                issue_number,
                comment.id,
            )
            return comment.html_url
        except GithubException as exc:
            raise CommentError(
                f"Failed to post comment on {repo_full_name}#{issue_number}: "
                f"{exc.data}"
            ) from exc

    def post_comment(
        self,
        repo_full_name: str,
        issue_number: int,
        body: str,
    ) -> str:
        """Post an arbitrary comment on a GitHub issue.

        Args:
            repo_full_name: Repository in ``owner/name`` format.
            issue_number:   GitHub issue number.
            body:           Markdown-formatted comment body.

        Returns:
            The HTML URL of the newly created comment.

        Raises:
            CommentError: If posting the comment fails.
            GitHubClientError: If the issue cannot be fetched.
        """
        try:
            issue = self._get_issue(repo_full_name, issue_number)
            comment = issue.create_comment(body)
            logger.info(
                "Posted comment on %s#%d (comment id=%d)",
                repo_full_name,
                issue_number,
                comment.id,
            )
            return comment.html_url
        except GithubException as exc:
            raise CommentError(
                f"Failed to post comment on {repo_full_name}#{issue_number}: "
                f"{exc.data}"
            ) from exc

    # ------------------------------------------------------------------
    # Issue metadata
    # ------------------------------------------------------------------

    def get_issue_metadata(
        self,
        repo_full_name: str,
        issue_number: int,
    ) -> dict:
        """Fetch basic metadata for an issue as a plain dictionary.

        Returns only the fields required by the triage pipeline and dashboard,
        avoiding the overhead of returning the full PyGithub object across
        module boundaries.

        Args:
            repo_full_name: Repository in ``owner/name`` format.
            issue_number:   GitHub issue number.

        Returns:
            A dictionary with the following keys:

            - ``number`` (int): Issue number.
            - ``title`` (str): Issue title.
            - ``body`` (str | None): Raw Markdown body text.
            - ``html_url`` (str): Issue HTML URL.
            - ``author_login`` (str): Login of the issue author.
            - ``state`` (str): ``"open"`` or ``"closed"``.
            - ``created_at`` (datetime): UTC creation datetime.
            - ``labels`` (list[str]): Names of labels currently on the issue.

        Raises:
            GitHubClientError: If the issue cannot be fetched.
        """
        issue = self._get_issue(repo_full_name, issue_number)
        return {
            "number": issue.number,
            "title": issue.title,
            "body": issue.body,
            "html_url": issue.html_url,
            "author_login": issue.user.login if issue.user else "",
            "state": issue.state,
            "created_at": issue.created_at,
            "labels": [lbl.name for lbl in issue.labels],
        }

    # ------------------------------------------------------------------
    # Installation resolution
    # ------------------------------------------------------------------

    def resolve_installation_id(
        self, repo_full_name: str
    ) -> int:
        """Resolve the installation ID for a repository using the App auth.

        Useful when *installation_id* is not known ahead of time and needs to
        be extracted from the webhook payload or resolved dynamically.

        This method authenticates as the GitHub App (not as an installation)
        and calls the Installations API.

        Args:
            repo_full_name: Repository in ``owner/name`` format
                            (e.g. ``"octocat/Hello-World"``).

        Returns:
            The numeric installation ID for the repository.

        Raises:
            GitHubClientError: If the installation cannot be resolved.
        """
        try:
            app_auth = Auth.AppAuth(
                app_id=self._app_id,
                private_key=self._private_key,
            )
            integration = GithubIntegration(auth=app_auth)
            installation = integration.get_repo_installation(
                *repo_full_name.split("/", 1)
            )
            installation_id = installation.id
            logger.debug(
                "Resolved installation ID %d for %s",
                installation_id,
                repo_full_name,
            )
            return installation_id
        except GithubException as exc:
            raise GitHubClientError(
                f"Failed to resolve installation ID for '{repo_full_name}': "
                f"{exc.data}"
            ) from exc

    def set_installation_id(self, installation_id: int) -> None:
        """Update the installation ID and invalidate the cached Github instance.

        Call this when the installation ID is determined from the webhook
        payload after the client has been constructed.

        Args:
            installation_id: New installation ID to use.
        """
        if self._installation_id != installation_id:
            self._installation_id = installation_id
            # Invalidate cached client so a new token is obtained.
            self._gh = None
            logger.debug(
                "GitHubClient installation_id updated to %d", installation_id
            )

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "GitHubClient":
        """Return self for use as a context manager."""
        return self

    def __exit__(
        self,
        exc_type: type | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None:
        """Close the underlying Github session if open."""
        if self._gh is not None:
            try:
                self._gh.close()
            except Exception:  # pragma: no cover
                pass
            finally:
                self._gh = None

    def __repr__(self) -> str:  # pragma: no cover
        """Return a developer-friendly representation."""
        return (
            f"GitHubClient("
            f"app_id={self._app_id}, "
            f"installation_id={self._installation_id})"
        )


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------


def get_github_client(
    installation_id: Optional[int] = None,
) -> GitHubClient:
    """Create a :class:`GitHubClient` from the application settings.

    The App ID and private key are read from the module-level
    :data:`bounty_guard.config.settings` singleton.  An *installation_id*
    override can be supplied (e.g. extracted from a webhook payload) to
    bypass the value in settings.

    Args:
        installation_id: Optional override for the GitHub App installation ID.
                         When ``None``, the value from settings is used.

    Returns:
        A configured :class:`GitHubClient` instance.

    Raises:
        ImportError: If ``bounty_guard.config`` cannot be imported.
        GitHubClientError: If the settings are incomplete.
    """
    from bounty_guard.config import settings  # local import to avoid circular deps

    iid = installation_id or (
        settings.github_installation_id if settings is not None else None
    )
    app_id = settings.github_app_id if settings is not None else 0
    private_key = settings.github_private_key if settings is not None else ""

    return GitHubClient(
        app_id=app_id,
        private_key=private_key,
        installation_id=iid,
    )
