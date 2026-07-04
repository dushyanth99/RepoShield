"""
Core scanning pipeline router — routers/pipeline.py

POST /api/v1/jobs/scan   →  HTTP 202 Accepted  (immediate response)
GET  /api/v1/jobs/{id}   →  live job status poll

Execution flow
--------------
1. Receive scan payload (file path + source code).
2. Run StaticScannerInterface inline to classify vulnerabilities.
3. Create VulnerabilityJob row (status=PENDING) in the request session, commit, close.
4. Enqueue ShieldAgentOrchestrator.execute_remediation as a BackgroundTask.
5. Return HTTP 202 immediately — frontend is never blocked.
6. Background task opens its OWN isolated AsyncSession → zero session sharing.
"""

import uuid
import logging
from typing import Annotated, Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from config.database import get_db, AsyncSessionLocal
from models.audit import VulnerabilityJob, PatchStatusEnum
from services.shield_agent import ShieldAgentOrchestrator
from services.scanner import StaticScannerInterface

logger = logging.getLogger("reposhield.pipeline")

router = APIRouter(prefix="/api/v1/jobs", tags=["Pipeline"])

_scanner = StaticScannerInterface()   # stateless — safe to share across requests


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    file_path:    str = Field(..., min_length=1, max_length=1024,
                              description="Repository-relative path of the file to scan.",
                              examples=["app/auth.py"])
    source_code:  str = Field(..., min_length=1,
                              description="Raw source code content of the file.")
    test_command: str = Field(default="pytest tests/",
                              description="Shell command to validate the patch inside the agent sandbox.",
                              examples=["pytest tests/test_auth.py -v"])
    user_id: Optional[str] = Field(default=None,
                                   description="UUID of the requesting user.",
                                   examples=["f47ac10b-58cc-4372-a567-0e02b2c3d479"])

    model_config = {"json_schema_extra": {"example": {
        "file_path":    "app/auth.py",
        "source_code":  "query = 'SELECT * FROM users WHERE id = ' + user_id",
        "test_command": "pytest tests/test_auth.py -v",
        "user_id":      "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    }}}


class ScanAcceptedResponse(BaseModel):
    job_id:              str   = Field(..., description="UUID of the newly created scan job.")
    status:              str   = Field(..., description="Initial job status.")
    file_path:           str   = Field(..., description="File submitted for analysis.")
    initial_findings:    int   = Field(..., description="Static-analysis finding count.")
    has_critical:        bool  = Field(..., description="True if ≥1 CRITICAL finding detected.")
    business_risk_score: float = Field(..., description="Initial risk score from static scan.")
    scan_summary:        dict  = Field(..., description="Per-severity finding counts.")
    message:             str   = Field(..., description="Human-readable status for the frontend.")


class JobStatusResponse(BaseModel):
    job_id:              str
    status:              str
    file_path:           str
    business_risk_score: float
    model_armor_blocked: int
    self_healing_count:  int
    pull_request_url:    Optional[str]


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
    Executed by FastAPI BackgroundTasks after HTTP 202 is returned.

    ShieldAgentOrchestrator is initialised with only a session_factory.
    It opens all DB sessions internally and independently — zero shared
    state with the already-closed request session.
    """
    logger.info(
        "Background remediation task started",
        extra={"job_id": job_id, "file_path": file_path},
    )

    orchestrator = ShieldAgentOrchestrator(db_session_factory=AsyncSessionLocal)

    try:
        result = await orchestrator.execute_remediation_pipeline(
            job_id=job_id,
            file_path=file_path,
            raw_source_code=source_code,
            test_command=test_command,
        )
        logger.info(
            "Background remediation completed",
            extra={"job_id": job_id, "result_preview": str(result)[:100]},
        )
    except Exception as exc:
        # The orchestrator already wrote FAILED to the DB and logged the
        # structured traceback. This outer catch prevents unhandled exceptions
        # from silently disappearing inside FastAPI's background task runner.
        logger.error(
            "Background task caught re-raised orchestrator exception",
            extra={"job_id": job_id, "error": str(exc)},
        )


# ---------------------------------------------------------------------------
# POST /api/v1/jobs/scan
# ---------------------------------------------------------------------------

@router.post(
    "/scan",
    response_model=ScanAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger a vulnerability scan and autonomous remediation job",
    description=(
        "Runs the static scanner immediately, creates a VulnerabilityJob record, "
        "then enqueues the ShieldAgentOrchestrator as a background task. "
        "Returns HTTP 202 with the initial job state — frontend never blocked."
    ),
)
async def trigger_scan(
    body:             ScanRequest,
    background_tasks: BackgroundTasks,
    db:               Annotated[AsyncSession, Depends(get_db)],
) -> ScanAcceptedResponse:
    # 1. Static scan
    scan_result: dict[str, Any] = await _scanner.scan(
        file_path=body.file_path,
        source_code=body.source_code,
    )
    logger.info(
        f"Static scan: '{body.file_path}' → "
        f"{scan_result['total_findings']} findings (critical={scan_result['has_critical']})"
    )

    # 2. Derive initial risk score from severity distribution
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

    # 3. Persist VulnerabilityJob (PENDING) in the request-scoped session
    job_id: str = str(uuid.uuid4())
    job_row = VulnerabilityJob(
        id=job_id,
        user_id=body.user_id or "anonymous",
        target_file_path=body.file_path,
        business_risk_score=risk_score,
        patch_status=PatchStatusEnum.PENDING,
        model_armor_blocked=0,
        self_healing_count=0,
        pull_request_url=None,
    )
    db.add(job_row)

    try:
        await db.flush()
        await db.commit()
        logger.info(f"VulnerabilityJob created: job_id={job_id} status=PENDING")
    except Exception as exc:
        await db.rollback()
        logger.error(f"Failed to create VulnerabilityJob {job_id}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create the scan job record. Please retry.",
        ) from exc

    # 4. Enqueue orchestrator — isolated session, opened inside _run_agent_in_background
    background_tasks.add_task(
        _run_agent_in_background,
        job_id=job_id,
        file_path=body.file_path,
        source_code=body.source_code,
        test_command=body.test_command,
        scan_result=scan_result,
    )
    logger.info(f"Job {job_id} enqueued. Returning HTTP 202.")

    # 5. Return 202 immediately
    return ScanAcceptedResponse(
        job_id=job_id,
        status=PatchStatusEnum.PENDING.value,
        file_path=body.file_path,
        initial_findings=scan_result["total_findings"],
        has_critical=scan_result["has_critical"],
        business_risk_score=risk_score,
        scan_summary=summary,
        message=(
            f"Scan job accepted. ShieldAgentOrchestrator is running in the background. "
            f"Poll /api/v1/jobs/{job_id} for live status."
        ),
    )


# ---------------------------------------------------------------------------
# GET /api/v1/jobs/{job_id}
# ---------------------------------------------------------------------------

@router.get(
    "/{job_id}",
    response_model=JobStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Poll the live status of a running scan job",
)
async def get_job_status(
    job_id: str,
    db:     Annotated[AsyncSession, Depends(get_db)],
) -> JobStatusResponse:
    stmt   = select(VulnerabilityJob).where(VulnerabilityJob.id == job_id)
    result = await db.execute(stmt)
    row: VulnerabilityJob | None = result.scalar_one_or_none()

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
