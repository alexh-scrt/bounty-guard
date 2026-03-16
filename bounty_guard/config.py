"""Configuration module for BountyGuard.

Loads all runtime settings from environment variables using pydantic-settings.
Every module in the package should import the singleton `settings` object
rather than reading environment variables directly.

Required environment variables:
    GITHUB_WEBHOOK_SECRET: Shared secret for HMAC-SHA256 webhook verification.
    GITHUB_APP_ID:         Numeric GitHub App ID.
    GITHUB_PRIVATE_KEY:    PEM-encoded RSA private key for the GitHub App
                           (newlines may be represented as literal \\n).

Optional environment variables (with defaults documented on each field):
    GITHUB_INSTALLATION_ID: Installation ID override (resolved dynamically
                            when not provided).
    OPENAI_API_KEY:         Required only when LLM_ENABLED=true.
    OPENAI_MODEL:           OpenAI chat model name (default: gpt-4o-mini).
    LLM_ENABLED:            Enable the LLM second-opinion classifier
                            (default: false).
    SPAM_LABEL:             GitHub label applied to suspected spam issues
                            (default: spam-suspected).
    HOLD_NOTIFICATION:      If true, posts a comment instead of notifying
                            maintainers (default: true).
    SPAM_SCORE_THRESHOLD:   Minimum rule-based score to flag as spam
                            (default: 0.6, range 0.0-1.0).
    LLM_SPAM_THRESHOLD:     Minimum LLM probability to flag as spam
                            (default: 0.7, range 0.0-1.0).
    COMBINED_MODE:          How to combine rule and LLM scores: 'any' or 'all'
                            (default: any).
    DATABASE_URL:           SQLite database file path
                            (default: bounty_guard.db).
    LOG_LEVEL:              Logging level (default: INFO).
    HOST:                   Uvicorn bind host (default: 0.0.0.0).
    PORT:                   Uvicorn bind port (default: 8000).
"""

from __future__ import annotations

import textwrap
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide settings resolved from environment variables.

    All fields with defaults are optional; fields without defaults must be
    supplied via environment variables before the application starts.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------ #
    # GitHub App credentials                                               #
    # ------------------------------------------------------------------ #

    github_webhook_secret: str = Field(
        ...,
        description="Shared HMAC secret configured in the GitHub App settings.",
    )
    github_app_id: int = Field(
        ...,
        description="Numeric GitHub App ID shown on the App settings page.",
    )
    github_private_key: str = Field(
        ...,
        description=(
            "PEM-encoded RSA private key downloaded from GitHub App settings. "
            "Literal \\n sequences are automatically expanded to newlines."
        ),
    )
    github_installation_id: int | None = Field(
        default=None,
        description=(
            "Optional installation ID. When omitted the app resolves it "
            "dynamically from the webhook payload."
        ),
    )

    # ------------------------------------------------------------------ #
    # OpenAI / LLM settings                                               #
    # ------------------------------------------------------------------ #

    openai_api_key: str | None = Field(
        default=None,
        description="OpenAI API key. Required when llm_enabled=True.",
    )
    openai_model: str = Field(
        default="gpt-4o-mini",
        description="OpenAI chat completion model to use for classification.",
    )
    llm_enabled: bool = Field(
        default=False,
        description="Whether to invoke the LLM classifier for a second opinion.",
    )

    # ------------------------------------------------------------------ #
    # Triage behaviour                                                     #
    # ------------------------------------------------------------------ #

    spam_label: str = Field(
        default="spam-suspected",
        description="GitHub label applied to issues flagged as suspected spam.",
    )
    hold_notification: bool = Field(
        default=True,
        description=(
            "When True, posts a comment asking for clarification instead of "
            "immediately notifying maintainers."
        ),
    )
    spam_score_threshold: float = Field(
        default=0.6,
        ge=0.0,
        le=1.0,
        description="Rule-based score above which an issue is considered spam.",
    )
    llm_spam_threshold: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="LLM probability above which an issue is considered spam.",
    )
    combined_mode: Literal["any", "all"] = Field(
        default="any",
        description=(
            "How to combine rule-based and LLM verdicts: "
            "'any' flags if either exceeds threshold; "
            "'all' requires both to exceed their thresholds."
        ),
    )

    # ------------------------------------------------------------------ #
    # Persistence                                                          #
    # ------------------------------------------------------------------ #

    database_url: str = Field(
        default="bounty_guard.db",
        description="File path for the SQLite database used to store triage history.",
    )

    # ------------------------------------------------------------------ #
    # Server settings                                                      #
    # ------------------------------------------------------------------ #

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Python logging level for the application.",
    )
    host: str = Field(
        default="0.0.0.0",
        description="Host address Uvicorn should bind to.",
    )
    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="Port Uvicorn should listen on.",
    )

    # ------------------------------------------------------------------ #
    # Validators                                                           #
    # ------------------------------------------------------------------ #

    @field_validator("github_private_key", mode="before")
    @classmethod
    def expand_private_key_newlines(cls, value: str) -> str:
        """Replace literal \\n escape sequences with real newline characters.

        Many deployment platforms (e.g. Heroku, Railway) do not support
        multi-line environment variable values, so operators often encode
        the PEM key with literal \\n sequences.

        Args:
            value: Raw private key string from the environment.

        Returns:
            Private key string with \\n replaced by actual newline characters.
        """
        if value and "\\n" in value:
            value = value.replace("\\n", "\n")
        # Ensure the key is properly dedented in case it was indented in .env
        return textwrap.dedent(value).strip()

    @model_validator(mode="after")
    def validate_llm_requirements(self) -> "Settings":
        """Ensure OpenAI API key is present when LLM classification is enabled.

        Returns:
            The validated Settings instance.

        Raises:
            ValueError: When llm_enabled is True but openai_api_key is not set.
        """
        if self.llm_enabled and not self.openai_api_key:
            raise ValueError(
                "OPENAI_API_KEY must be set when LLM_ENABLED=true. "
                "Provide the key or set LLM_ENABLED=false to disable the LLM classifier."
            )
        return self

    # ------------------------------------------------------------------ #
    # Convenience helpers                                                  #
    # ------------------------------------------------------------------ #

    @property
    def webhook_secret_bytes(self) -> bytes:
        """Return the webhook secret encoded as UTF-8 bytes for HMAC operations.

        Returns:
            The webhook secret as a byte string.
        """
        return self.github_webhook_secret.encode("utf-8")

    def __repr__(self) -> str:  # pragma: no cover
        """Return a safe representation that masks sensitive fields."""
        return (
            f"Settings("
            f"github_app_id={self.github_app_id}, "
            f"llm_enabled={self.llm_enabled}, "
            f"spam_score_threshold={self.spam_score_threshold}, "
            f"combined_mode={self.combined_mode!r}, "
            f"port={self.port}"
            f")"
        )


def get_settings() -> Settings:
    """Construct and return a Settings instance from the current environment.

    This function is intended for use with FastAPI's ``Depends`` mechanism to
    allow settings to be overridden in tests::

        from fastapi import Depends
        from bounty_guard.config import get_settings, Settings

        def my_route(settings: Settings = Depends(get_settings)):
            ...

    Returns:
        A fully-validated Settings instance.

    Raises:
        pydantic_core.ValidationError: If required environment variables are
            missing or any value fails validation.
    """
    return Settings()  # type: ignore[call-arg]


# Module-level singleton used by all non-FastAPI code paths.
# Modules that need settings import this object directly::
#
#     from bounty_guard.config import settings
#
# During tests you can monkeypatch individual attributes or replace the object.
try:
    settings: Settings = Settings()  # type: ignore[call-arg]
except Exception:  # pragma: no cover
    # Allow the module to be imported even if env vars are not yet configured,
    # e.g. when running `pytest` with only partial configuration.  The
    # application startup will fail loudly if required vars are absent.
    settings = None  # type: ignore[assignment]
