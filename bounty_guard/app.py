"""FastAPI application entry point for BountyGuard.

Exposes three HTTP endpoints:

- ``POST /webhook``  – Receives GitHub webhook events, validates the HMAC
  signature, and dispatches ``issues`` events to the triage pipeline.
- ``GET  /health``   – Simple liveness probe returning ``{"status": "ok"}``.
- ``GET  /dashboard`` – Paginated JSON view of triage history with optional
  filters for repository and decision type.

Startup / shutdown lifecycle:
    On startup a :class:`~bounty_guard.models.TriageRepository` is opened and
    stored on the application state.  On shutdown it is closed gracefully.

Authentication:
    All webhook deliveries are verified via HMAC-SHA256 using
    :func:`~bounty_guard.webhook_validator.verify_signature`.  Requests with
    missing or invalid signatures receive a 403 response.

Example startup::

    uvicorn bounty_guard.app:app --host 0.0.0.0 --port 8000

or via the CLI entry point::

    bounty-guard
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from bounty_guard.models import TriageDecision, TriageRepository
from bounty_guard.webhook_validator import SignatureError, verify_signature
from bounty_guard.triage import TriageOrchestrator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    """Response body for the health check endpoint."""

    status: str = Field(default="ok", description="Always 'ok' when the service is healthy.")
    version: str = Field(default="0.1.0", description="Application version.")


class WebhookResponse(BaseModel):
    """Response body returned after processing a webhook delivery."""

    accepted: bool = Field(description="True when the event was processed.")
    event: str = Field(description="The GitHub event type that was received.")
    action: Optional[str] = Field(default=None, description="The event action sub-type.")
    message: str = Field(default="", description="Human-readable status message.")
    decision: Optional[str] = Field(
        default=None,
        description="Triage decision when an issue was processed.",
    )


class DashboardRecord(BaseModel):
    """Slim projection of an IssueRecord for the dashboard endpoint."""

    id: Optional[int] = None
    repo_full_name: str
    issue_number: int
    issue_title: str
    issue_url: str
    author_login: str
    decision: str
    rule_score: float
    llm_probability: float
    llm_skipped: bool
    label_applied: Optional[str]
    comment_posted: bool
    reasoning: str
    triaged_at: str
    updated_at: str


class DashboardResponse(BaseModel):
    """Paginated response for the dashboard endpoint."""

    total: int = Field(description="Total number of matching records.")
    limit: int
    offset: int
    records: list[DashboardRecord]


# ---------------------------------------------------------------------------
# Application lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown.

    On startup:
        - Load settings.
        - Open the SQLite triage repository.
        - Log the configuration.

    On shutdown:
        - Close the SQLite repository gracefully.
    """
    # ---- Startup ----
    try:
        from bounty_guard.config import settings

        app.state.settings = settings
        db_path = settings.database_url if settings is not None else "bounty_guard.db"
    except Exception as exc:
        logger.warning(
            "Could not load settings during startup: %s. Using defaults.", exc
        )
        app.state.settings = None
        db_path = "bounty_guard.db"

    repo = TriageRepository(db_path=db_path)
    try:
        repo.connect()
        app.state.db_repo = repo
        logger.info("BountyGuard started. Database: %s", db_path)
    except Exception as exc:
        logger.error("Failed to open database at startup: %s", exc)
        app.state.db_repo = None

    yield

    # ---- Shutdown ----
    if getattr(app.state, "db_repo", None) is not None:
        try:
            app.state.db_repo.close()
            logger.info("BountyGuard shutdown complete. Database connection closed.")
        except Exception as exc:  # pragma: no cover
            logger.error("Error closing database on shutdown: %s", exc)


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """Construct and return the FastAPI application instance.

    Returns:
        A configured :class:`fastapi.FastAPI` instance with all routes
        registered and the lifespan context attached.
    """
    _app = FastAPI(
        title="BountyGuard",
        description=(
            "Automatic triage of security issue reports on GitHub repositories. "
            "Scores incoming reports against a spam-detection rubric and optionally "
            "uses an LLM for a second-opinion classification."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    # Register routes.
    _app.include_router(_health_router())
    _app.include_router(_webhook_router())
    _app.include_router(_dashboard_router())

    return _app


# ---------------------------------------------------------------------------
# Route factories
# ---------------------------------------------------------------------------


def _health_router():
    """Build and return the health-check router."""
    from fastapi import APIRouter

    router = APIRouter(tags=["health"])

    @router.get(
        "/health",
        response_model=HealthResponse,
        summary="Health check",
        description="Returns 200 OK when the service is running.",
    )
    async def health() -> HealthResponse:
        """Liveness probe for the BountyGuard service.

        Returns:
            A :class:`HealthResponse` with ``status='ok'``.
        """
        return HealthResponse(status="ok", version="0.1.0")

    return router


def _webhook_router():
    """Build and return the GitHub webhook router."""
    from fastapi import APIRouter

    router = APIRouter(tags=["webhook"])

    @router.post(
        "/webhook",
        response_model=WebhookResponse,
        summary="GitHub webhook receiver",
        description=(
            "Receives GitHub App webhook deliveries. Validates the HMAC-SHA256 "
            "signature and processes 'issues' events through the triage pipeline."
        ),
        status_code=200,
    )
    async def webhook(
        request: Request,
        x_hub_signature_256: Optional[str] = Header(
            default=None,
            alias="X-Hub-Signature-256",
            description="HMAC-SHA256 signature from GitHub.",
        ),
        x_github_event: Optional[str] = Header(
            default=None,
            alias="X-GitHub-Event",
            description="GitHub event type (e.g. 'issues', 'ping').",
        ),
        x_github_delivery: Optional[str] = Header(
            default=None,
            alias="X-GitHub-Delivery",
            description="Unique delivery ID from GitHub.",
        ),
    ) -> WebhookResponse:
        """Handle an incoming GitHub webhook delivery.

        Validates the HMAC-SHA256 signature, then routes the event:

        - ``ping``:   Acknowledges the webhook configuration.
        - ``issues``: Dispatches ``opened`` and ``reopened`` actions to the
                      triage pipeline.  Other actions are acknowledged but
                      not processed.
        - All other events are acknowledged with a no-op response.

        Args:
            request:               The raw FastAPI request.
            x_hub_signature_256:   Value of ``X-Hub-Signature-256`` header.
            x_github_event:        Value of ``X-GitHub-Event`` header.
            x_github_delivery:     Value of ``X-GitHub-Delivery`` header.

        Returns:
            A :class:`WebhookResponse` describing the outcome.

        Raises:
            HTTPException 403: When the signature is missing or invalid.
            HTTPException 400: When the payload cannot be parsed as JSON.
        """
        # Read raw body before any parsing so we can verify the signature.
        raw_body = await request.body()

        # Signature verification.
        settings = getattr(request.app.state, "settings", None)
        if settings is None:
            logger.error("Settings not available; cannot verify webhook signature.")
            raise HTTPException(
                status_code=503,
                detail="Service not fully initialised; settings unavailable.",
            )

        try:
            verify_signature(
                payload=raw_body,
                secret=settings.github_webhook_secret,
                signature_header=x_hub_signature_256 or "",
            )
        except SignatureError as exc:
            logger.warning(
                "Webhook signature verification failed (delivery=%s): %s",
                x_github_delivery,
                exc,
            )
            raise HTTPException(status_code=403, detail=str(exc)) from exc

        # Parse JSON payload.
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            logger.warning("Invalid JSON payload: %s", exc)
            raise HTTPException(
                status_code=400, detail=f"Invalid JSON payload: {exc}"
            ) from exc

        event_type = x_github_event or "unknown"
        action = payload.get("action") if isinstance(payload, dict) else None

        logger.info(
            "Received webhook event=%s action=%s delivery=%s",
            event_type,
            action,
            x_github_delivery,
        )

        # Handle ping events (sent when a webhook is first configured).
        if event_type == "ping":
            return WebhookResponse(
                accepted=True,
                event=event_type,
                action=action,
                message="Pong! Webhook is configured correctly.",
            )

        # Only process 'issues' events.
        if event_type != "issues":
            return WebhookResponse(
                accepted=True,
                event=event_type,
                action=action,
                message=f"Event type '{event_type}' is not processed by BountyGuard.",
            )

        # Only process 'opened' and 'reopened' actions.
        if action not in ("opened", "reopened"):
            return WebhookResponse(
                accepted=True,
                event=event_type,
                action=action,
                message=f"Action '{action}' is not triaged by BountyGuard.",
            )

        # Extract issue data from the payload.
        issue_data = payload.get("issue", {})
        repo_data = payload.get("repository", {})
        installation_data = payload.get("installation", {})

        repo_full_name: str = repo_data.get("full_name", "")
        issue_number: int = int(issue_data.get("number", 0))
        issue_title: str = issue_data.get("title", "")
        issue_body: Optional[str] = issue_data.get("body") or ""
        issue_url: str = issue_data.get("html_url", "")
        author_login: str = (
            issue_data.get("user", {}).get("login", "")
            if isinstance(issue_data.get("user"), dict)
            else ""
        )
        installation_id: Optional[int] = (
            int(installation_data["id"])
            if installation_data.get("id")
            else None
        )

        if not repo_full_name or not issue_number:
            logger.warning(
                "Webhook payload missing repo or issue number. Skipping triage."
            )
            return WebhookResponse(
                accepted=False,
                event=event_type,
                action=action,
                message="Payload missing repository or issue information.",
            )

        # Run triage in a thread to avoid blocking the event loop.
        db_repo = getattr(request.app.state, "db_repo", None)
        orchestrator = TriageOrchestrator(
            settings=settings,
            db_repo=db_repo,
        )

        try:
            triage_result = await asyncio.to_thread(
                orchestrator.triage_issue,
                repo_full_name=repo_full_name,
                issue_number=issue_number,
                issue_title=issue_title,
                issue_body=issue_body,
                issue_url=issue_url,
                author_login=author_login,
                installation_id=installation_id,
            )
        except Exception as exc:
            logger.exception(
                "Triage failed for %s#%d: %s",
                repo_full_name,
                issue_number,
                exc,
            )
            raise HTTPException(
                status_code=500,
                detail=f"Triage pipeline error: {exc}",
            ) from exc

        return WebhookResponse(
            accepted=True,
            event=event_type,
            action=action,
            message=(
                f"Triage complete for {repo_full_name}#{issue_number}: "
                f"{triage_result.decision.value}."
            ),
            decision=triage_result.decision.value,
        )

    return router


def _dashboard_router():
    """Build and return the dashboard router."""
    from fastapi import APIRouter

    router = APIRouter(tags=["dashboard"])

    @router.get(
        "/dashboard",
        response_model=DashboardResponse,
        summary="Triage history dashboard",
        description=(
            "Returns paginated triage history records. Optionally filter by "
            "repository full name and/or triage decision."
        ),
    )
    async def dashboard(
        request: Request,
        repo: Optional[str] = Query(
            default=None,
            description="Filter by repository full name (e.g. 'owner/repo').",
        ),
        decision: Optional[str] = Query(
            default=None,
            description="Filter by triage decision: 'spam', 'legitimate', or 'uncertain'.",
        ),
        limit: int = Query(
            default=50,
            ge=1,
            le=500,
            description="Maximum number of records to return (1-500).",
        ),
        offset: int = Query(
            default=0,
            ge=0,
            description="Number of records to skip for pagination.",
        ),
    ) -> DashboardResponse:
        """Return paginated triage history from the database.

        Args:
            request:  The FastAPI request (used to access app state).
            repo:     Optional repository filter (``owner/name`` format).
            decision: Optional decision filter.
            limit:    Page size (1–500).
            offset:   Pagination offset.

        Returns:
            A :class:`DashboardResponse` with the matching records.

        Raises:
            HTTPException 400: If the decision filter value is invalid.
            HTTPException 503: If the database is not available.
        """
        db_repo: Optional[TriageRepository] = getattr(
            request.app.state, "db_repo", None
        )
        if db_repo is None:
            raise HTTPException(
                status_code=503,
                detail="Database not available.",
            )

        # Resolve optional decision filter.
        decision_filter: Optional[TriageDecision] = None
        if decision is not None:
            try:
                decision_filter = TriageDecision(decision.lower())
            except ValueError:
                valid = [d.value for d in TriageDecision]
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Invalid decision filter '{decision}'. "
                        f"Valid values: {valid}."
                    ),
                )

        # Query the database.
        try:
            if repo:
                records = await asyncio.to_thread(
                    db_repo.list_by_repo,
                    repo,
                    decision_filter,
                    limit,
                    offset,
                )
                total = await asyncio.to_thread(
                    db_repo.count_by_repo,
                    repo,
                    decision_filter,
                )
            else:
                records = await asyncio.to_thread(
                    db_repo.list_all,
                    decision_filter,
                    limit,
                    offset,
                )
                total = await asyncio.to_thread(
                    db_repo.count_all,
                    decision_filter,
                )
        except Exception as exc:
            logger.error("Dashboard query failed: %s", exc)
            raise HTTPException(
                status_code=500,
                detail=f"Database query error: {exc}",
            ) from exc

        dashboard_records = [
            DashboardRecord(
                id=r.id,
                repo_full_name=r.repo_full_name,
                issue_number=r.issue_number,
                issue_title=r.issue_title,
                issue_url=r.issue_url,
                author_login=r.author_login,
                decision=r.triage_result.decision.value,
                rule_score=r.triage_result.spam_score.total_score,
                llm_probability=r.triage_result.llm_result.spam_probability,
                llm_skipped=r.triage_result.llm_result.skipped,
                label_applied=r.triage_result.label_applied,
                comment_posted=r.triage_result.comment_posted,
                reasoning=r.triage_result.reasoning,
                triaged_at=r.triage_result.triaged_at.isoformat(),
                updated_at=r.updated_at.isoformat(),
            )
            for r in records
        ]

        return DashboardResponse(
            total=total,
            limit=limit,
            offset=offset,
            records=dashboard_records,
        )

    return router


# ---------------------------------------------------------------------------
# Module-level app instance
# ---------------------------------------------------------------------------

# The module-level ``app`` object is imported by Uvicorn.
app: FastAPI = create_app()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:  # pragma: no cover
    """Start the Uvicorn server using settings from the environment.

    This function is registered as the ``bounty-guard`` console script in
    ``pyproject.toml``.
    """
    import uvicorn

    try:
        from bounty_guard.config import settings

        host = settings.host if settings is not None else "0.0.0.0"
        port = settings.port if settings is not None else 8000
        log_level = settings.log_level.lower() if settings is not None else "info"
    except Exception:
        host = "0.0.0.0"
        port = 8000
        log_level = "info"

    uvicorn.run(
        "bounty_guard.app:app",
        host=host,
        port=port,
        log_level=log_level,
        reload=False,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
