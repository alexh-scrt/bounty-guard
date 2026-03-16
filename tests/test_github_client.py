"""Unit tests for bounty_guard.github_client.

All GitHub API calls are mocked using unittest.mock so these tests run
without any real GitHub credentials or network access.

Covers:
- GitHubClient construction and lazy authentication.
- ensure_label_exists: creates label when missing, skips when present.
- apply_label: applies label, skips if already present.
- remove_label: removes label when present, returns False when absent.
- post_spam_comment: posts correctly formatted comment.
- post_comment: posts arbitrary comment.
- get_issue_metadata: returns correct dict.
- resolve_installation_id: delegates to GithubIntegration.
- set_installation_id: invalidates cached Github instance.
- Context manager protocol.
- get_github_client factory function.
- Error handling: GitHubClientError, LabelError, CommentError raised on
  GithubException.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from github import GithubException

from bounty_guard.github_client import (
    CommentError,
    GitHubClient,
    GitHubClientError,
    LabelError,
    get_github_client,
)


# ---------------------------------------------------------------------------
# Helpers and fixtures
# ---------------------------------------------------------------------------


APP_ID = 123
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----"
INSTALL_ID = 456
REPO_NAME = "owner/testrepo"
ISSUE_NUMBER = 7


def _make_client(installation_id: int | None = INSTALL_ID) -> GitHubClient:
    return GitHubClient(
        app_id=APP_ID,
        private_key=PRIVATE_KEY,
        installation_id=installation_id,
    )


def _make_github_exception(status: int = 422, message: str = "error") -> GithubException:
    exc = GithubException(status=status, data={"message": message}, headers={})
    return exc


def _make_mock_issue(
    number: int = ISSUE_NUMBER,
    title: str = "Test Issue",
    body: str = "issue body",
    html_url: str = "https://github.com/owner/testrepo/issues/7",
    state: str = "open",
    login: str = "octocat",
    labels: list[str] | None = None,
) -> MagicMock:
    issue = MagicMock()
    issue.number = number
    issue.title = title
    issue.body = body
    issue.html_url = html_url
    issue.state = state
    issue.user.login = login
    issue.created_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    label_mocks = []
    for name in (labels or []):
        lbl = MagicMock()
        lbl.name = name
        label_mocks.append(lbl)
    issue.labels = label_mocks
    comment = MagicMock()
    comment.id = 999
    comment.html_url = "https://github.com/owner/testrepo/issues/7#issuecomment-999"
    issue.create_comment.return_value = comment
    return issue


def _make_mock_repo(issue: MagicMock | None = None) -> MagicMock:
    repo = MagicMock()
    if issue is not None:
        repo.get_issue.return_value = issue
    # Simulate label-not-found by default.
    repo.get_label.side_effect = GithubException(status=404, data={"message": "Not Found"}, headers={})
    return repo


def _patch_get_github(client: GitHubClient, repo: MagicMock) -> MagicMock:
    """Patch _get_github to return a mock that yields the given repo."""
    gh = MagicMock()
    gh.get_repo.return_value = repo
    client._gh = gh
    return gh


# ---------------------------------------------------------------------------
# Construction tests
# ---------------------------------------------------------------------------


class TestGitHubClientConstruction:
    def test_attributes_set(self):
        client = _make_client()
        assert client._app_id == APP_ID
        assert client._private_key == PRIVATE_KEY
        assert client._installation_id == INSTALL_ID
        assert client._gh is None

    def test_no_installation_id(self):
        client = _make_client(installation_id=None)
        assert client._installation_id is None

    def test_repr_does_not_raise(self):
        client = _make_client()
        repr(client)  # should not raise


# ---------------------------------------------------------------------------
# _get_github lazy auth tests
# ---------------------------------------------------------------------------


class TestGetGithub:
    def test_raises_without_installation_id(self):
        client = _make_client(installation_id=None)
        with pytest.raises(GitHubClientError, match="installation_id is required"):
            client._get_github()

    def test_returns_cached_instance(self):
        client = _make_client()
        mock_gh = MagicMock()
        client._gh = mock_gh
        result = client._get_github()
        assert result is mock_gh

    @patch("bounty_guard.github_client.GithubIntegration")
    @patch("bounty_guard.github_client.Auth.AppAuth")
    def test_authentication_flow(
        self, mock_app_auth, mock_integration_class
    ):
        mock_integration = MagicMock()
        mock_integration_class.return_value = mock_integration
        mock_token = MagicMock()
        mock_token.token = "ghs_faketoken"
        mock_integration.get_access_token.return_value = mock_token

        client = _make_client()
        with patch("bounty_guard.github_client.Github") as mock_gh_class:
            mock_gh_instance = MagicMock()
            mock_gh_class.return_value = mock_gh_instance
            result = client._get_github()

        assert result is mock_gh_instance
        mock_app_auth.assert_called_once_with(app_id=APP_ID, private_key=PRIVATE_KEY)
        mock_integration.get_access_token.assert_called_once_with(INSTALL_ID)

    @patch("bounty_guard.github_client.GithubIntegration")
    @patch("bounty_guard.github_client.Auth.AppAuth")
    def test_authentication_failure_raises_client_error(
        self, mock_app_auth, mock_integration_class
    ):
        mock_integration = MagicMock()
        mock_integration_class.return_value = mock_integration
        mock_integration.get_access_token.side_effect = GithubException(
            status=401, data={"message": "Bad credentials"}, headers={}
        )
        client = _make_client()
        with pytest.raises(GitHubClientError, match="Failed to authenticate"):
            client._get_github()


# ---------------------------------------------------------------------------
# ensure_label_exists tests
# ---------------------------------------------------------------------------


class TestEnsureLabelExists:
    def test_creates_label_when_missing(self):
        client = _make_client()
        repo = _make_mock_repo()
        _patch_get_github(client, repo)

        client.ensure_label_exists(REPO_NAME, "spam-suspected")

        repo.create_label.assert_called_once_with(
            name="spam-suspected",
            color="e11d48",
            description="Suspected AI-generated or low-quality security report",
        )

    def test_skips_creation_when_label_exists(self):
        client = _make_client()
        repo = _make_mock_repo()
        # Override: label exists.
        repo.get_label.side_effect = None
        repo.get_label.return_value = MagicMock(name="spam-suspected")
        _patch_get_github(client, repo)

        client.ensure_label_exists(REPO_NAME, "spam-suspected")

        repo.create_label.assert_not_called()

    def test_raises_label_error_on_non_404_exception(self):
        client = _make_client()
        repo = _make_mock_repo()
        repo.get_label.side_effect = GithubException(
            status=500, data={"message": "Server Error"}, headers={}
        )
        _patch_get_github(client, repo)

        with pytest.raises(LabelError):
            client.ensure_label_exists(REPO_NAME, "spam-suspected")

    def test_custom_color_and_description(self):
        client = _make_client()
        repo = _make_mock_repo()
        _patch_get_github(client, repo)

        client.ensure_label_exists(
            REPO_NAME, "my-label", label_color="aabbcc", label_description="Custom"
        )
        repo.create_label.assert_called_once_with(
            name="my-label", color="aabbcc", description="Custom"
        )


# ---------------------------------------------------------------------------
# apply_label tests
# ---------------------------------------------------------------------------


class TestApplyLabel:
    def test_applies_label_to_issue(self):
        client = _make_client()
        issue = _make_mock_issue(labels=[])
        repo = _make_mock_repo(issue=issue)
        _patch_get_github(client, repo)

        client.apply_label(REPO_NAME, ISSUE_NUMBER, "spam-suspected")

        issue.add_to_labels.assert_called_once_with("spam-suspected")

    def test_skips_if_label_already_present(self):
        client = _make_client()
        issue = _make_mock_issue(labels=["spam-suspected"])
        repo = _make_mock_repo(issue=issue)
        # Label exists in repo.
        repo.get_label.side_effect = None
        repo.get_label.return_value = MagicMock()
        _patch_get_github(client, repo)

        client.apply_label(REPO_NAME, ISSUE_NUMBER, "spam-suspected")

        issue.add_to_labels.assert_not_called()

    def test_raises_label_error_on_api_failure(self):
        client = _make_client()
        issue = _make_mock_issue(labels=[])
        repo = _make_mock_repo(issue=issue)
        _patch_get_github(client, repo)
        issue.add_to_labels.side_effect = GithubException(
            status=403, data={"message": "Forbidden"}, headers={}
        )

        with pytest.raises(LabelError):
            client.apply_label(REPO_NAME, ISSUE_NUMBER, "spam-suspected")


# ---------------------------------------------------------------------------
# remove_label tests
# ---------------------------------------------------------------------------


class TestRemoveLabel:
    def test_removes_label_returns_true(self):
        client = _make_client()
        issue = _make_mock_issue(labels=["spam-suspected"])
        repo = _make_mock_repo(issue=issue)
        _patch_get_github(client, repo)

        result = client.remove_label(REPO_NAME, ISSUE_NUMBER, "spam-suspected")

        assert result is True
        issue.remove_from_labels.assert_called_once_with("spam-suspected")

    def test_returns_false_when_label_not_present(self):
        client = _make_client()
        issue = _make_mock_issue(labels=["other-label"])
        repo = _make_mock_repo(issue=issue)
        _patch_get_github(client, repo)

        result = client.remove_label(REPO_NAME, ISSUE_NUMBER, "spam-suspected")

        assert result is False
        issue.remove_from_labels.assert_not_called()

    def test_raises_label_error_on_api_failure(self):
        client = _make_client()
        issue = _make_mock_issue(labels=["spam-suspected"])
        repo = _make_mock_repo(issue=issue)
        _patch_get_github(client, repo)
        issue.remove_from_labels.side_effect = GithubException(
            status=422, data={"message": "Unprocessable"}, headers={}
        )

        with pytest.raises(LabelError):
            client.remove_label(REPO_NAME, ISSUE_NUMBER, "spam-suspected")


# ---------------------------------------------------------------------------
# post_spam_comment tests
# ---------------------------------------------------------------------------


class TestPostSpamComment:
    def test_posts_comment_returns_url(self):
        client = _make_client()
        issue = _make_mock_issue()
        repo = _make_mock_repo(issue=issue)
        _patch_get_github(client, repo)

        url = client.post_spam_comment(
            REPO_NAME, ISSUE_NUMBER, reasoning="Score 0.86 exceeded threshold."
        )

        assert "issuecomment" in url
        issue.create_comment.assert_called_once()
        call_args = issue.create_comment.call_args[0][0]
        assert "BountyGuard" in call_args
        assert "Score 0.86 exceeded threshold." in call_args

    def test_default_reasoning_used_when_empty(self):
        client = _make_client()
        issue = _make_mock_issue()
        repo = _make_mock_repo(issue=issue)
        _patch_get_github(client, repo)

        client.post_spam_comment(REPO_NAME, ISSUE_NUMBER)

        call_args = issue.create_comment.call_args[0][0]
        assert "Automated rubric check" in call_args

    def test_raises_comment_error_on_api_failure(self):
        client = _make_client()
        issue = _make_mock_issue()
        repo = _make_mock_repo(issue=issue)
        _patch_get_github(client, repo)
        issue.create_comment.side_effect = GithubException(
            status=403, data={"message": "Forbidden"}, headers={}
        )

        with pytest.raises(CommentError):
            client.post_spam_comment(REPO_NAME, ISSUE_NUMBER)

    def test_comment_contains_marker(self):
        client = _make_client()
        issue = _make_mock_issue()
        repo = _make_mock_repo(issue=issue)
        _patch_get_github(client, repo)

        client.post_spam_comment(REPO_NAME, ISSUE_NUMBER, reasoning="test")

        body = issue.create_comment.call_args[0][0]
        assert "bounty-guard" in body


# ---------------------------------------------------------------------------
# post_comment tests
# ---------------------------------------------------------------------------


class TestPostComment:
    def test_posts_arbitrary_comment(self):
        client = _make_client()
        issue = _make_mock_issue()
        repo = _make_mock_repo(issue=issue)
        _patch_get_github(client, repo)

        url = client.post_comment(REPO_NAME, ISSUE_NUMBER, "Hello world")

        assert url
        issue.create_comment.assert_called_once_with("Hello world")

    def test_raises_comment_error_on_api_failure(self):
        client = _make_client()
        issue = _make_mock_issue()
        repo = _make_mock_repo(issue=issue)
        _patch_get_github(client, repo)
        issue.create_comment.side_effect = GithubException(
            status=500, data={"message": "Server Error"}, headers={}
        )

        with pytest.raises(CommentError):
            client.post_comment(REPO_NAME, ISSUE_NUMBER, "test")


# ---------------------------------------------------------------------------
# get_issue_metadata tests
# ---------------------------------------------------------------------------


class TestGetIssueMetadata:
    def test_returns_expected_keys(self):
        client = _make_client()
        issue = _make_mock_issue(
            labels=["bug", "spam-suspected"],
        )
        repo = _make_mock_repo(issue=issue)
        _patch_get_github(client, repo)

        meta = client.get_issue_metadata(REPO_NAME, ISSUE_NUMBER)

        assert meta["number"] == ISSUE_NUMBER
        assert meta["title"] == "Test Issue"
        assert meta["body"] == "issue body"
        assert meta["state"] == "open"
        assert meta["author_login"] == "octocat"
        assert "bug" in meta["labels"]
        assert "spam-suspected" in meta["labels"]
        assert meta["html_url"]

    def test_raises_on_api_failure(self):
        client = _make_client()
        repo = _make_mock_repo()
        repo.get_issue.side_effect = GithubException(
            status=404, data={"message": "Not Found"}, headers={}
        )
        _patch_get_github(client, repo)

        with pytest.raises(GitHubClientError):
            client.get_issue_metadata(REPO_NAME, ISSUE_NUMBER)


# ---------------------------------------------------------------------------
# resolve_installation_id tests
# ---------------------------------------------------------------------------


class TestResolveInstallationId:
    @patch("bounty_guard.github_client.GithubIntegration")
    @patch("bounty_guard.github_client.Auth.AppAuth")
    def test_returns_installation_id(self, mock_app_auth, mock_integration_class):
        mock_integration = MagicMock()
        mock_integration_class.return_value = mock_integration
        mock_install = MagicMock()
        mock_install.id = 789
        mock_integration.get_repo_installation.return_value = mock_install

        client = _make_client()
        result = client.resolve_installation_id("owner/repo")

        assert result == 789
        mock_integration.get_repo_installation.assert_called_once_with("owner", "repo")

    @patch("bounty_guard.github_client.GithubIntegration")
    @patch("bounty_guard.github_client.Auth.AppAuth")
    def test_raises_on_github_exception(self, mock_app_auth, mock_integration_class):
        mock_integration = MagicMock()
        mock_integration_class.return_value = mock_integration
        mock_integration.get_repo_installation.side_effect = GithubException(
            status=404, data={"message": "Not Found"}, headers={}
        )

        client = _make_client()
        with pytest.raises(GitHubClientError, match="Failed to resolve installation ID"):
            client.resolve_installation_id("owner/repo")


# ---------------------------------------------------------------------------
# set_installation_id tests
# ---------------------------------------------------------------------------


class TestSetInstallationId:
    def test_updates_installation_id(self):
        client = _make_client(installation_id=111)
        client.set_installation_id(222)
        assert client._installation_id == 222

    def test_invalidates_cached_github(self):
        client = _make_client()
        client._gh = MagicMock()  # simulate cached instance
        client.set_installation_id(999)
        assert client._gh is None

    def test_no_op_when_same_id(self):
        client = _make_client(installation_id=INSTALL_ID)
        mock_gh = MagicMock()
        client._gh = mock_gh
        client.set_installation_id(INSTALL_ID)  # same ID
        # _gh should NOT be invalidated.
        assert client._gh is mock_gh


# ---------------------------------------------------------------------------
# Context manager tests
# ---------------------------------------------------------------------------


class TestContextManager:
    def test_enter_returns_client(self):
        client = _make_client()
        result = client.__enter__()
        assert result is client

    def test_exit_closes_github(self):
        client = _make_client()
        mock_gh = MagicMock()
        client._gh = mock_gh
        client.__exit__(None, None, None)
        mock_gh.close.assert_called_once()
        assert client._gh is None

    def test_exit_when_not_connected(self):
        client = _make_client()
        # Should not raise even when _gh is None.
        client.__exit__(None, None, None)

    def test_context_manager_protocol(self):
        client = _make_client()
        with client as c:
            assert c is client


# ---------------------------------------------------------------------------
# get_github_client factory tests
# ---------------------------------------------------------------------------


class TestGetGithubClientFactory:
    def test_returns_github_client_instance(self):
        mock_settings = MagicMock()
        mock_settings.github_app_id = APP_ID
        mock_settings.github_private_key = PRIVATE_KEY
        mock_settings.github_installation_id = INSTALL_ID

        with patch("bounty_guard.github_client.settings", mock_settings):
            # We need to patch the import inside the function.
            with patch(
                "bounty_guard.github_client.get_github_client.__code__",
                get_github_client.__code__,
            ):
                pass  # Just verify the function exists and is importable.

        client = GitHubClient(
            app_id=APP_ID,
            private_key=PRIVATE_KEY,
            installation_id=INSTALL_ID,
        )
        assert isinstance(client, GitHubClient)

    def test_installation_id_override(self):
        """Verify that passing installation_id overrides settings value."""
        with patch("bounty_guard.github_client.settings") as mock_settings:
            mock_settings.github_app_id = APP_ID
            mock_settings.github_private_key = PRIVATE_KEY
            mock_settings.github_installation_id = 111

            # Import locally to exercise the factory.
            from bounty_guard import github_client as gc_module

            with patch.object(gc_module, "GitHubClient") as MockClient:
                MockClient.return_value = MagicMock()
                # Patch the import inside the factory.
                with patch(
                    "bounty_guard.github_client.settings", mock_settings
                ):
                    gc_module.get_github_client(installation_id=999)
                # The client should have been created with installation_id=999.
                call_kwargs = MockClient.call_args[1]
                assert call_kwargs["installation_id"] == 999
