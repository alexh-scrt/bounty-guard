"""Core data models and SQLite persistence layer for BountyGuard.

This module defines all Pydantic models used across the application as a stable
data contract, as well as the SQLite-backed repository for persisting triage
history so maintainers can review past decisions and retriage issues.

Data model hierarchy:
    SpamScore      - Per-signal breakdown from the rule-based scorer.
    LLMResult      - Probability and reasoning from the optional LLM classifier.
    TriageDecision - Enum representing the final triage outcome.
    TriageResult   - Combined final decision with all supporting evidence.
    IssueRecord    - Persistent record stored in SQLite per repo+issue.

Persistence:
    TriageRepository - Context-managed SQLite repository for CRUD on IssueRecord.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Generator, Optional

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class TriageDecision(str, Enum):
    """Possible outcomes of the triage pipeline for a single issue.

    Attributes:
        SPAM:       Issue has been flagged as suspected spam.
        LEGITIMATE: Issue appears to be a genuine security report.
        UNCERTAIN:  Scores are borderline; human review is recommended.
    """

    SPAM = "spam"
    LEGITIMATE = "legitimate"
    UNCERTAIN = "uncertain"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SpamScore(BaseModel):
    """Per-signal breakdown produced by the rule-based scorer.

    Each boolean signal contributes to the overall spam score.  The
    ``total_score`` field is a float in [0.0, 1.0] representing the fraction
    of signals that fired.

    Attributes:
        vague_description:         True when the issue body lacks specific
                                   technical detail.
        missing_reproduction_steps: True when no reproduction steps are
                                    provided.
        cve_template_detected:     True when boilerplate CVE template text
                                   is detected.
        no_code_evidence:          True when the body contains no code
                                   blocks, stack traces, or PoC fragments.
        excessive_severity_claims: True when the body makes unsupported
                                   high-severity claims without evidence.
        generic_greeting:          True when the body starts with a
                                   generic greeting typical of spam.
        suspiciously_short:        True when the body is too short to
                                   constitute a real security report.
        total_score:               Weighted fraction of signals that fired,
                                   in the range [0.0, 1.0].
    """

    vague_description: bool = Field(
        default=False,
        description="Issue body lacks specific technical detail.",
    )
    missing_reproduction_steps: bool = Field(
        default=False,
        description="No reproduction steps are present in the issue body.",
    )
    cve_template_detected: bool = Field(
        default=False,
        description="Boilerplate CVE template text was detected.",
    )
    no_code_evidence: bool = Field(
        default=False,
        description="No code blocks, stack traces, or PoC fragments found.",
    )
    excessive_severity_claims: bool = Field(
        default=False,
        description="Unsupported high-severity claims without evidence.",
    )
    generic_greeting: bool = Field(
        default=False,
        description="Body starts with a generic greeting typical of spam.",
    )
    suspiciously_short: bool = Field(
        default=False,
        description="Body is too short to be a genuine security report.",
    )
    total_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Weighted fraction of signals that fired (0.0 – 1.0).",
    )

    @field_validator("total_score", mode="before")
    @classmethod
    def clamp_total_score(cls, value: float) -> float:
        """Clamp total_score to [0.0, 1.0] before validation.

        Args:
            value: Raw score value.

        Returns:
            Score clamped to the [0.0, 1.0] range.
        """
        return max(0.0, min(1.0, float(value)))

    @property
    def fired_signals(self) -> list[str]:
        """Return the names of all signals that evaluated to True.

        Returns:
            List of field names whose boolean value is True.
        """
        signal_fields = [
            "vague_description",
            "missing_reproduction_steps",
            "cve_template_detected",
            "no_code_evidence",
            "excessive_severity_claims",
            "generic_greeting",
            "suspiciously_short",
        ]
        return [name for name in signal_fields if getattr(self, name)]

    @property
    def signal_count(self) -> int:
        """Return the number of signals that fired.

        Returns:
            Integer count of True boolean signal fields.
        """
        return len(self.fired_signals)


class LLMResult(BaseModel):
    """Result returned by the optional LLM-based classifier.

    Attributes:
        spam_probability: Float in [0.0, 1.0] where 1.0 means certainly spam.
        reasoning:        Human-readable explanation from the LLM.
        model:            Name of the model that produced this result.
        skipped:          True when LLM classification was disabled or failed.
        error:            Error message if classification failed.
    """

    spam_probability: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Probability that the issue is spam according to the LLM.",
    )
    reasoning: str = Field(
        default="",
        description="Human-readable explanation produced by the LLM.",
    )
    model: str = Field(
        default="",
        description="Name of the LLM model that produced this result.",
    )
    skipped: bool = Field(
        default=False,
        description="True when LLM classification was disabled or not invoked.",
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message when LLM classification encountered a failure.",
    )

    @field_validator("spam_probability", mode="before")
    @classmethod
    def clamp_probability(cls, value: float) -> float:
        """Clamp spam_probability to [0.0, 1.0].

        Args:
            value: Raw probability value.

        Returns:
            Probability clamped to the [0.0, 1.0] range.
        """
        return max(0.0, min(1.0, float(value)))


class TriageResult(BaseModel):
    """Combined triage outcome containing all supporting evidence.

    This is the primary output of the triage orchestrator and is persisted
    as part of each IssueRecord.

    Attributes:
        decision:         Final triage decision (spam / legitimate / uncertain).
        spam_score:       Rule-based per-signal breakdown.
        llm_result:       LLM classifier result (may be skipped).
        rule_triggered:   True when the rule-based score exceeded the threshold.
        llm_triggered:    True when the LLM probability exceeded the threshold.
        label_applied:    GitHub label string applied to the issue, if any.
        comment_posted:   True when a clarification comment was posted.
        reasoning:        Human-readable summary of why this decision was made.
        triaged_at:       UTC timestamp when triage was performed.
    """

    decision: TriageDecision = Field(
        ...,
        description="Final triage outcome for the issue.",
    )
    spam_score: SpamScore = Field(
        ...,
        description="Per-signal breakdown from the rule-based scorer.",
    )
    llm_result: LLMResult = Field(
        default_factory=lambda: LLMResult(skipped=True),
        description="Result from the LLM classifier, or a skipped placeholder.",
    )
    rule_triggered: bool = Field(
        default=False,
        description="True when the rule-based score exceeded its threshold.",
    )
    llm_triggered: bool = Field(
        default=False,
        description="True when the LLM probability exceeded its threshold.",
    )
    label_applied: Optional[str] = Field(
        default=None,
        description="GitHub label applied to the issue, if any.",
    )
    comment_posted: bool = Field(
        default=False,
        description="True when a clarification comment was posted on the issue.",
    )
    reasoning: str = Field(
        default="",
        description="Human-readable summary explaining the triage decision.",
    )
    triaged_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC datetime when the triage was performed.",
    )


class IssueRecord(BaseModel):
    """Persistent record for one triage decision stored in SQLite.

    A record is uniquely identified by (repo_full_name, issue_number).  When
    the same issue is retriaged the existing record is updated in-place.

    Attributes:
        id:             Auto-assigned integer primary key (None before insert).
        repo_full_name: GitHub repository in ``owner/name`` format.
        issue_number:   GitHub issue number within the repository.
        issue_title:    Title of the issue at the time of triage.
        issue_url:      HTML URL of the issue on GitHub.
        author_login:   GitHub login of the issue author.
        triage_result:  Full triage result including score breakdown.
        created_at:     UTC datetime when the record was first created.
        updated_at:     UTC datetime when the record was last updated.
    """

    id: Optional[int] = Field(
        default=None,
        description="Auto-assigned integer primary key.",
    )
    repo_full_name: str = Field(
        ...,
        description="Repository in 'owner/name' format.",
        examples=["octocat/Hello-World"],
    )
    issue_number: int = Field(
        ...,
        ge=1,
        description="GitHub issue number within the repository.",
    )
    issue_title: str = Field(
        default="",
        description="Title of the issue at the time of triage.",
    )
    issue_url: str = Field(
        default="",
        description="HTML URL of the issue on GitHub.",
    )
    author_login: str = Field(
        default="",
        description="GitHub login of the issue author.",
    )
    triage_result: TriageResult = Field(
        ...,
        description="Complete triage result including score breakdown and decision.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC datetime when this record was first created.",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC datetime when this record was last updated.",
    )


# ---------------------------------------------------------------------------
# SQLite persistence layer
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS triage_records (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_full_name   TEXT    NOT NULL,
    issue_number     INTEGER NOT NULL,
    issue_title      TEXT    NOT NULL DEFAULT '',
    issue_url        TEXT    NOT NULL DEFAULT '',
    author_login     TEXT    NOT NULL DEFAULT '',
    triage_result    TEXT    NOT NULL,
    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL,
    UNIQUE (repo_full_name, issue_number)
);
CREATE INDEX IF NOT EXISTS idx_repo_issue
    ON triage_records (repo_full_name, issue_number);
CREATE INDEX IF NOT EXISTS idx_repo_decision
    ON triage_records (repo_full_name, json_extract(triage_result, '$.decision'));
"""


class TriageRepository:
    """SQLite-backed repository for storing and querying IssueRecord objects.

    Usage as a context manager ensures the database connection is properly
    opened and closed::

        with TriageRepository("bounty_guard.db") as repo:
            repo.upsert(record)
            records = repo.list_by_repo("owner/repo")

    The repository can also be used without the context manager by calling
    :meth:`connect` and :meth:`close` explicitly.

    Args:
        db_path: File-system path for the SQLite database.  Pass ``:memory:``
                 for an in-memory database (useful for tests).
    """

    def __init__(self, db_path: str = "bounty_guard.db") -> None:
        """Initialise the repository without opening a connection.

        Args:
            db_path: Path to the SQLite database file.
        """
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Open the SQLite connection and create tables if they do not exist.

        This method is idempotent; calling it when already connected is safe.

        Raises:
            sqlite3.Error: If the database file cannot be opened or created.
        """
        if self._conn is not None:
            return
        db_path = self._db_path
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._apply_ddl()
        logger.debug("TriageRepository connected to %s", db_path)

    def close(self) -> None:
        """Close the SQLite connection if it is open."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None
            logger.debug("TriageRepository connection closed.")

    def __enter__(self) -> "TriageRepository":
        """Open the connection and return self for context-manager use."""
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None:
        """Close the connection on context-manager exit."""
        self.close()

    @contextmanager
    def _cursor(self) -> Generator[sqlite3.Cursor, None, None]:
        """Yield a cursor within an auto-commit/rollback transaction.

        Yields:
            An active sqlite3.Cursor.

        Raises:
            RuntimeError: If called before :meth:`connect`.
            sqlite3.Error: On database errors, after rolling back.
        """
        if self._conn is None:
            raise RuntimeError(
                "TriageRepository is not connected.  Call connect() or use as "
                "a context manager before performing database operations."
            )
        cursor = self._conn.cursor()
        try:
            yield cursor
            self._conn.commit()
        except sqlite3.Error:
            self._conn.rollback()
            raise
        finally:
            cursor.close()

    # ------------------------------------------------------------------
    # Schema management
    # ------------------------------------------------------------------

    def _apply_ddl(self) -> None:
        """Execute the DDL statements to create tables and indices."""
        assert self._conn is not None
        for statement in _DDL.strip().split(";"):
            statement = statement.strip()
            if statement:
                self._conn.execute(statement)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _record_to_row(record: IssueRecord) -> dict:
        """Convert an IssueRecord to a flat dict suitable for SQLite insertion.

        Args:
            record: The IssueRecord to serialise.

        Returns:
            Dictionary with string/int values matching the table columns.
        """
        now = datetime.now(timezone.utc).isoformat()
        return {
            "repo_full_name": record.repo_full_name,
            "issue_number": record.issue_number,
            "issue_title": record.issue_title,
            "issue_url": record.issue_url,
            "author_login": record.author_login,
            "triage_result": record.triage_result.model_dump_json(),
            "created_at": record.created_at.isoformat(),
            "updated_at": now,
        }

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> IssueRecord:
        """Reconstruct an IssueRecord from a SQLite row.

        Args:
            row: A sqlite3.Row fetched from the triage_records table.

        Returns:
            A fully populated IssueRecord instance.

        Raises:
            pydantic.ValidationError: If the stored JSON is malformed.
        """
        triage_result = TriageResult.model_validate_json(row["triage_result"])
        return IssueRecord(
            id=row["id"],
            repo_full_name=row["repo_full_name"],
            issue_number=row["issue_number"],
            issue_title=row["issue_title"],
            issue_url=row["issue_url"],
            author_login=row["author_login"],
            triage_result=triage_result,
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    # ------------------------------------------------------------------
    # CRUD operations
    # ------------------------------------------------------------------

    def upsert(self, record: IssueRecord) -> IssueRecord:
        """Insert or update an IssueRecord identified by (repo_full_name, issue_number).

        If a record for the same repo and issue number already exists it is
        updated in-place; otherwise a new row is inserted.  The record's
        ``id`` field is populated with the assigned primary key.

        Args:
            record: The IssueRecord to persist.

        Returns:
            The same record with its ``id`` field populated.

        Raises:
            RuntimeError: If the repository is not connected.
            sqlite3.Error: On database errors.
        """
        row = self._record_to_row(record)
        sql = """
            INSERT INTO triage_records
                (repo_full_name, issue_number, issue_title, issue_url,
                 author_login, triage_result, created_at, updated_at)
            VALUES
                (:repo_full_name, :issue_number, :issue_title, :issue_url,
                 :author_login, :triage_result, :created_at, :updated_at)
            ON CONFLICT (repo_full_name, issue_number) DO UPDATE SET
                issue_title    = excluded.issue_title,
                issue_url      = excluded.issue_url,
                author_login   = excluded.author_login,
                triage_result  = excluded.triage_result,
                updated_at     = excluded.updated_at
        """
        with self._cursor() as cur:
            cur.execute(sql, row)
            last_id = cur.lastrowid

        # Fetch the persisted row to get the canonical id (lastrowid is 0
        # on UPDATE in some SQLite versions).
        fetched = self.get_by_repo_and_issue(
            record.repo_full_name, record.issue_number
        )
        if fetched is not None:
            record = record.model_copy(update={"id": fetched.id})
        elif last_id:
            record = record.model_copy(update={"id": last_id})
        logger.debug(
            "Upserted IssueRecord id=%s for %s#%s",
            record.id,
            record.repo_full_name,
            record.issue_number,
        )
        return record

    def get_by_repo_and_issue(
        self, repo_full_name: str, issue_number: int
    ) -> Optional[IssueRecord]:
        """Fetch a single IssueRecord by repository and issue number.

        Args:
            repo_full_name: Repository in ``owner/name`` format.
            issue_number:   GitHub issue number.

        Returns:
            The matching IssueRecord, or None if not found.

        Raises:
            RuntimeError: If the repository is not connected.
        """
        sql = """
            SELECT * FROM triage_records
            WHERE repo_full_name = ? AND issue_number = ?
            LIMIT 1
        """
        with self._cursor() as cur:
            cur.execute(sql, (repo_full_name, issue_number))
            row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_record(row)

    def get_by_id(self, record_id: int) -> Optional[IssueRecord]:
        """Fetch a single IssueRecord by its primary key.

        Args:
            record_id: Integer primary key.

        Returns:
            The matching IssueRecord, or None if not found.

        Raises:
            RuntimeError: If the repository is not connected.
        """
        sql = "SELECT * FROM triage_records WHERE id = ? LIMIT 1"
        with self._cursor() as cur:
            cur.execute(sql, (record_id,))
            row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_record(row)

    def list_by_repo(
        self,
        repo_full_name: str,
        decision: Optional[TriageDecision] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[IssueRecord]:
        """List IssueRecords for a repository with optional decision filter.

        Args:
            repo_full_name: Repository in ``owner/name`` format.
            decision:       Optional filter; only records with this decision
                            are returned.  Pass None to return all.
            limit:          Maximum number of records to return (default 100).
            offset:         Number of records to skip for pagination.

        Returns:
            List of IssueRecord objects ordered by updated_at descending.

        Raises:
            RuntimeError: If the repository is not connected.
        """
        if decision is not None:
            sql = """
                SELECT * FROM triage_records
                WHERE repo_full_name = ?
                  AND json_extract(triage_result, '$.decision') = ?
                ORDER BY updated_at DESC
                LIMIT ? OFFSET ?
            """
            params: tuple = (repo_full_name, decision.value, limit, offset)
        else:
            sql = """
                SELECT * FROM triage_records
                WHERE repo_full_name = ?
                ORDER BY updated_at DESC
                LIMIT ? OFFSET ?
            """
            params = (repo_full_name, limit, offset)
        with self._cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return [self._row_to_record(row) for row in rows]

    def list_all(
        self,
        decision: Optional[TriageDecision] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[IssueRecord]:
        """List all IssueRecords across all repositories.

        Args:
            decision: Optional filter by triage decision.
            limit:    Maximum number of records to return.
            offset:   Number of records to skip for pagination.

        Returns:
            List of IssueRecord objects ordered by updated_at descending.

        Raises:
            RuntimeError: If the repository is not connected.
        """
        if decision is not None:
            sql = """
                SELECT * FROM triage_records
                WHERE json_extract(triage_result, '$.decision') = ?
                ORDER BY updated_at DESC
                LIMIT ? OFFSET ?
            """
            params = (decision.value, limit, offset)
        else:
            sql = """
                SELECT * FROM triage_records
                ORDER BY updated_at DESC
                LIMIT ? OFFSET ?
            """
            params = (limit, offset)
        with self._cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return [self._row_to_record(row) for row in rows]

    def delete_by_repo_and_issue(
        self, repo_full_name: str, issue_number: int
    ) -> bool:
        """Delete the record for a specific repository issue.

        Args:
            repo_full_name: Repository in ``owner/name`` format.
            issue_number:   GitHub issue number.

        Returns:
            True if a row was deleted, False if no matching row existed.

        Raises:
            RuntimeError: If the repository is not connected.
        """
        sql = """
            DELETE FROM triage_records
            WHERE repo_full_name = ? AND issue_number = ?
        """
        with self._cursor() as cur:
            cur.execute(sql, (repo_full_name, issue_number))
            deleted = cur.rowcount > 0
        logger.debug(
            "Deleted IssueRecord for %s#%s: %s",
            repo_full_name,
            issue_number,
            deleted,
        )
        return deleted

    def count_by_repo(
        self,
        repo_full_name: str,
        decision: Optional[TriageDecision] = None,
    ) -> int:
        """Count IssueRecords for a repository with optional decision filter.

        Args:
            repo_full_name: Repository in ``owner/name`` format.
            decision:       Optional filter by triage decision.

        Returns:
            Integer count of matching records.

        Raises:
            RuntimeError: If the repository is not connected.
        """
        if decision is not None:
            sql = """
                SELECT COUNT(*) FROM triage_records
                WHERE repo_full_name = ?
                  AND json_extract(triage_result, '$.decision') = ?
            """
            params = (repo_full_name, decision.value)
        else:
            sql = """
                SELECT COUNT(*) FROM triage_records
                WHERE repo_full_name = ?
            """
            params = (repo_full_name,)
        with self._cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
        return int(row[0]) if row else 0

    def count_all(self, decision: Optional[TriageDecision] = None) -> int:
        """Count all IssueRecords across all repositories.

        Args:
            decision: Optional filter by triage decision.

        Returns:
            Integer count of matching records.

        Raises:
            RuntimeError: If the repository is not connected.
        """
        if decision is not None:
            sql = """
                SELECT COUNT(*) FROM triage_records
                WHERE json_extract(triage_result, '$.decision') = ?
            """
            params = (decision.value,)
        else:
            sql = "SELECT COUNT(*) FROM triage_records"
            params = ()
        with self._cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
        return int(row[0]) if row else 0


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------


def get_repository(db_path: Optional[str] = None) -> TriageRepository:
    """Create and return a connected TriageRepository.

    If ``db_path`` is not provided the value is read from the application
    settings.  This function exists as a convenient injection point for tests
    that need to substitute an in-memory database.

    Args:
        db_path: Optional override for the database file path.  Pass
                 ``:memory:`` for an isolated in-memory database.

    Returns:
        A connected TriageRepository instance.
    """
    if db_path is None:
        try:
            from bounty_guard.config import settings as _settings

            db_path = _settings.database_url if _settings is not None else "bounty_guard.db"
        except Exception:
            db_path = "bounty_guard.db"
    repo = TriageRepository(db_path=db_path)
    repo.connect()
    return repo
