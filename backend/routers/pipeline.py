"""
Core scanning pipeline router — routers/pipeline.py

Exposes the primary endpoint the React frontend calls to trigger a
vulnerability scan + autonomous remediation job:

    POST /pipeline/scan  →  HTTP 202 Accepted  (immediate)

Execution flow
--------------
1. Receive the scan request payload (file path + raw source code).
2. Run the StaticScannerInterface synchronously to flag vulnerability
   categories and compute an initial business risk score.
3. Open a request-scoped async DB session, create a new AuditLedger row
   with status=PENDING, commit, then close the session.
4. Enqueue the long-running AutonomousSecurityOrchestrator.execute_remediation
   call as a FastAPI BackgroundTask — the endpoint returns HTTP 202 before
   the Antigravity reasoning loop begins.
5. The background task opens its own independent AsyncSession via the
   session_factory so it is entirely isolated from the request session
   that was already closed in step 3. This prevents connection pool
   exhaustion regardless of how long the agent runs.
"""

import uuid
import logging
from typing import Annotated, Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config.database import get_db, AsyncSessionLocal
from backend.models.audit_ledger import AuditLedger, PatchStatus
from backend.services.scanner import StaticScannerInterface
from backend.services.agent_orchestrator import AutonomousSecurityOrchestrator

logger = logging.getLogger("reposhield.pipeline")

router = APIRouter(prefix="/pipeline", tags=["Scanning Pipeline"])

# Shared scanner instance — stateless, safe to reuse across requests
_scanner = StaticScannerInterface()


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """
    Payload the frontend sends to initiate a vulnerability scan + remediation job.
    """
    file_path: str = Field(
        ...,
        min_length=1,
        max_length=1024,
        description="Repository-relative path of the file to scan.",
        examples=["app/auth.py"],
    )
    source_code: str = Field(
        ...,
        min_length=1,
        description="Raw source code content of the file to analyse.",
    )
    test_command: str = Field(
        default="pytest tests/",
        description="Shell command to run the test suite inside the agent sandbox.",
        examples=["pytest tests/test_auth.py -v"],
    )
    user_id: Optional[str] = Field(
        default=None,
        description="UUID of the requesting user. Used to link the AuditLedger record.",
        examples=["f47ac10b-58cc-4372-a567-0e02b2c3d479"],
    )

    model_config = {"json_schema_extra": {"example": {
        "file_path":    "app/auth.py",
        "source_code":  "query = 'SELECT * FROM users WHERE id = ' + user_id",
        "test_command": "pytest tests/test_auth.py -v",
        "user_id":      "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    }}}


class ScanAcceptedResponse(BaseModel):
    """
    Immediate HTTP 202 response that unblocks the frontend while the
    Antigravity agent reasoning loop runs in the background.
    """
    job_id:               str        = Field(..., description="UUID of the newly created scan job.")
    status:               str        = Field(..., description="Current job status.")
    file_path:            str        = Field(..., description="File path submitted for analysis.")
    initial_findings:     int        = Field(..., description="Number of static-analysis findings detected before agent run.")
    has_critical:         bool       = Field(..., description="True if at least one CRITICAL finding was detected.")
    business_risk_score:  float      = Field(..., description="Initial risk score derived from static scan findings.")
    scan_summary:         dict       = Field(..., description="Per-severity finding counts from the static scanner.")
    message:              str        = Field(..., description="Human-readable status message for the frontend.")


# ---------------------------------------------------------------------------
# Background task — fully isolated DB session
# ---------------------------------------------------------------------------

async def _run_agent_in_background(
    job_id:       str,
    file_path:    str,
    source_code:  str,
    test_command: str,
    scan_result:  dict[str, Any],
) -> None:
    """
    Standalone coroutine executed by FastAPI BackgroundTasks.

    Opens its own AsyncSession via AsyncSessionLocal (the factory) so it is
    completely decoupled from the request-scoped session that was already
    committed and closed before this task begins. This guarantees:
      - No connection pool exhaustion (two live sessions never overlap).
      - No 'session already closed' errors inside the orchestrator.
    """
    logger.info(f"Background remediation task started for job_id={job_id}")

    # Build a concise prompt from the static scanner's top finding
    top_finding: dict = {}
    if scan_result.get("findings"):
        top_finding = scan_result["findings"][0]

    prompt: str = (
        f"The static scanner flagged the file '{file_path}' with "
        f"{scan_result['total_findings']} vulnerability finding(s). "
        f"Top finding: category={top_finding.get('category', 'UNKNOWN')}, "
        f"message={top_finding.get('message', 'No details')}. "
        f"Rewrite the affected code to remediate all findings and ensure tests pass."
    )

    # Open an independent session for the entire background lifecycle
    async with AsyncSessionLocal() as bg_session:
        try:
            orchestrator = AutonomousSecurityOrchestrator(
                db=bg_session,
                session_factory=AsyncSessionLocal,
            )
            result = await orchestrator.execute_remediation(
                job_id=job_id,
                prompt=prompt,
                test_command=test_command,
            )
            logger.info(f"Remediation complete for job_id={job_id}. Result: {result}")

        except Exception as exc:
            logger.error(
                f"Background remediation failed for job_id={job_id}: {exc}",
                exc_info=True,
            )
            # The orchestrator already handles final DB status writes internally;
            # this outer catch is a safety net for unexpected failures.


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/scan",
    response_model=ScanAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger a vulnerability scan and autonomous remediation job",
    description=(
        "Runs the static scanner immediately, creates an AuditLedger job record, "
        "then enqueues the Antigravity agent remediation loop as a background task. "
        "Returns HTTP 202 with the initial job state so the frontend is never blocked."
    ),
)
async def trigger_scan(
    body:             ScanRequest,
    background_tasks: BackgroundTasks,
    db:               Annotated[AsyncSession, Depends(get_db)],
) -> ScanAcceptedResponse:
    """
    POST /pipeline/scan

    Step-by-step
    ------------
    1. Run StaticScannerInterface.scan() to classify vulnerabilities and
       derive an initial business risk score.
    2. Create a new AuditLedger row (status=PENDING) in the request-scoped
       session, commit, then allow get_db to close the session.
    3. Register the Antigravity orchestrator as a BackgroundTask — it will
       open its own isolated session via AsyncSessionLocal.
    4. Return HTTP 202 immediately with the job ID and initial scan summary.
    """

    # -----------------------------------------------------------------
    # 1. Static scan — CPU-light enough to run inline (< 5 000 lines)
    # -----------------------------------------------------------------
    scan_result: dict[str, Any] = await _scanner.scan(
        file_path=body.file_path,
        source_code=body.source_code,
    )

    logger.info(
        f"Static scan complete for '{body.file_path}': "
        f"{scan_result['total_findings']} findings "
        f"(critical={scan_result['has_critical']})"
    )

    # -----------------------------------------------------------------
    # 2. Derive initial business risk score from severity distribution
    #    CRITICAL=0.95, HIGH=0.75, MEDIUM=0.50, LOW=0.25, none=0.10
    # -----------------------------------------------------------------
    summary: dict = scan_result.get("summary", {})
    if summary.get("CRITICAL", 0) > 0:
        risk_score: float = 0.95
    elif summary.get("HIGH", 0) > 0:
        risk_score = 0.75
    elif summary.get("MEDIUM", 0) > 0:
        risk_score = 0.50
    elif summary.get("LOW", 0) > 0:
        risk_score = 0.25
    else:
        risk_score = 0.10

    # -----------------------------------------------------------------
    # 3. Create AuditLedger record in the request-scoped session
    # -----------------------------------------------------------------
    job_id: str = str(uuid.uuid4())

    ledger_row = AuditLedger(
        id=job_id,
        user_id=body.user_id or "anonymous",
        target_file_path=body.file_path,
        business_risk_score=risk_score,
        patch_status=PatchStatus.PENDING,
        model_armor_blocked=0,
        self_healing_count=0,
        pull_request_url=None,
    )
    db.add(ledger_row)

    try:
        await db.flush()
        await db.commit()
        logger.info(f"AuditLedger job created: job_id={job_id} status=PENDING")
    except Exception as exc:
        await db.rollback()
        logger.error(f"Failed to persist AuditLedger row for job {job_id}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create the scan job record. Please retry.",
        ) from exc

    # -----------------------------------------------------------------
    # 4. Enqueue agent orchestration as a background task.
    #    The request-scoped `db` is committed and will be closed by
    #    get_db's finally block. The background task receives its own
    #    fresh session via AsyncSessionLocal — zero shared state.
    # -----------------------------------------------------------------
    background_tasks.add_task(
        _run_agent_in_background,
        job_id=job_id,
        file_path=body.file_path,
        source_code=body.source_code,
        test_command=body.test_command,
        scan_result=scan_result,
    )

    logger.info(
        f"Scan job {job_id} enqueued as background task. "
        f"Returning HTTP 202 to client."
    )

    # -----------------------------------------------------------------
    # 5. Return HTTP 202 immediately — frontend is never blocked
    # -----------------------------------------------------------------
    return ScanAcceptedResponse(
        job_id=job_id,
        status=PatchStatus.PENDING.value,
        file_path=body.file_path,
        initial_findings=scan_result["total_findings"],
        has_critical=scan_result["has_critical"],
        business_risk_score=risk_score,
        scan_summary=summary,
        message=(
            f"Scan job accepted. The Antigravity remediation agent is running "
            f"in the background. Poll /pipeline/job/{job_id} for live status."
        ),
    )


# ---------------------------------------------------------------------------
# Job status polling endpoint (used by frontend to track background progress)
# ---------------------------------------------------------------------------

class JobStatusResponse(BaseModel):
    job_id:              str
    status:              str
    file_path:           str
    business_risk_score: float
    model_armor_blocked: int
    self_healing_count:  int
    pull_request_url:    Optional[str]


@router.get(
    "/job/{job_id}",
    response_model=JobStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Poll the live status of a running scan job",
    description="Returns the current AuditLedger record for the given job ID.",
)
async def get_job_status(
    job_id: str,
    db:     Annotated[AsyncSession, Depends(get_db)],
) -> JobStatusResponse:
    """
    GET /pipeline/job/{job_id}

    Fetches the live AuditLedger row so the React frontend can poll for
    status transitions (PENDING → IN_PROGRESS → PATCHED / FAILED).
    """
    from sqlalchemy import select
    from backend.models.audit_ledger import AuditLedger

    stmt = select(AuditLedger).where(AuditLedger.id == job_id)
    result = await db.execute(stmt)
    row: AuditLedger | None = result.scalar_one_or_none()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan job found with ID '{job_id}'.",
        )

    return JobStatusResponse(
        job_id=row.id,
        status=row.patch_status.value,
        file_path=row.target_file_path,
        business_risk_score=row.business_risk_score,
        model_armor_blocked=row.model_armor_blocked,
        self_healing_count=row.self_healing_count,
        pull_request_url=row.pull_request_url,
    )
