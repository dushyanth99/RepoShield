"""
Core scanning pipeline router — routers/pipeline.py

POST /api/v1/jobs/scan   →  HTTP 200 (secure) or HTTP 202 Accepted (vulnerable)
GET  /api/v1/jobs/{id}   →  live job status poll

Execution flow
--------------
1. Receive repo URL from the frontend.
2. Run StaticScannerInterface.scan_github_repo to shallow-clone and AST-scan
   every .py file for hardcoded secrets and injection vulnerabilities.
3. If the repo is clean → return HTTP 200 immediately.
4. If a vulnerability is found:
   a. Create a VulnerabilityJob row (status=PENDING) and commit.
   b. Enqueue ShieldAgentOrchestrator.execute_remediation as a BackgroundTask
      with the dynamically discovered file_path and raw_code.
   c. Return HTTP 202 Accepted — frontend is never blocked.
5. Background task opens its OWN isolated AsyncSession → zero session sharing.
"""

import uuid
import logging
import asyncio
from typing import Annotated, Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status, Request
from sse_starlette.sse import EventSourceResponse
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from config.database import get_db, AsyncSessionLocal
from config.security import verify_github_webhook, get_current_user
from models.audit import VulnerabilityJob, PatchStatusEnum
from models.user import Repository
from services.shield_agent import ShieldAgentOrchestrator
from services.scanner import StaticScannerInterface

logger = logging.getLogger("reposhield.pipeline")

router = APIRouter(prefix="/api/v1/jobs", tags=["Pipeline"])

_scanner = StaticScannerInterface()   # stateless — safe to share across requests


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class ManualScanRequest(BaseModel):
    repository_id: str = Field(..., description="UUID of the repository to scan.")
    test_command: str = Field(default="pytest tests/", description="Shell command to validate the patch.")

    model_config = {"json_schema_extra": {"example": {
        "repository_id": "b3f3b9c0-5f3a-4a2e-8a2a-7e3e9d3d3a2e",
        "test_command": "pytest tests/test_auth.py -v",
    }}}

class ScanSecureResponse(BaseModel):
    status:  str = Field(..., description="Scan result status.")
    message: str = Field(..., description="Human-readable summary.")

class ScanAcceptedResponse(BaseModel):
    job_id:              str   = Field(..., description="UUID of the newly created scan job.")
    status:              str   = Field(..., description="Initial job status.")
    file_path:           str   = Field(..., description="Vulnerable file discovered by the scanner.")
    category:            str   = Field(..., description="Vulnerability category (e.g. HARDCODED_SECRET).")
    business_risk_score: float = Field(..., description="Business risk score from static scan.")
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
) -> None:
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
        logger.error(
            "Background task caught re-raised orchestrator exception",
            extra={"job_id": job_id, "error": str(exc)},
        )

# ---------------------------------------------------------------------------
# POST /api/v1/jobs/scan/manual (Route A: Client-to-Server)
# ---------------------------------------------------------------------------
@router.post(
    "/scan/manual",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Manually trigger a scan using a JWT",
)
async def trigger_scan_manual(
    body:             ManualScanRequest,
    background_tasks: BackgroundTasks,
    db:               Annotated[AsyncSession, Depends(get_db)],
    user_id:          str = Depends(get_current_user),
):
    repo = await db.get(Repository, body.repository_id)
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    if repo.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to scan this repository")

    scan_result = await _scanner.scan_github_repo(repo.github_repo_url)

    if scan_result.get("status") == "error":
        raise HTTPException(status_code=422, detail=f"Scan failed: {scan_result.get('message')}")

    if scan_result["status"] == "secure":
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=ScanSecureResponse(
                status="secure",
                message=f"No vulnerabilities detected in {repo.github_repo_url}.",
            ).model_dump(),
        )

    file_path = scan_result["file_path"]
    raw_code = scan_result["raw_code"]
    category = scan_result["category"]
    business_impact = scan_result["business_impact"]

    job_id = str(uuid.uuid4())
    job_row = VulnerabilityJob(
        id=job_id,
        user_id=user_id,
        repository_id=repo.id,
        target_file_path=file_path,
        business_risk_score=business_impact,
        patch_status=PatchStatusEnum.PENDING,
        model_armor_blocked=0,
        self_healing_count=0,
        pull_request_url=None,
    )
    db.add(job_row)
    await db.commit()

    background_tasks.add_task(
        _run_agent_in_background,
        job_id=job_id,
        file_path=file_path,
        source_code=raw_code,
        test_command=body.test_command,
    )

    return ScanAcceptedResponse(
        job_id=job_id,
        status=PatchStatusEnum.PENDING.value,
        file_path=file_path,
        category=category,
        business_risk_score=business_impact,
        message=f"Vulnerability ({category}) detected. Remediation enqueued.",
    )

# ---------------------------------------------------------------------------
# POST /api/v1/webhooks/github (Route B: Server-to-Server)
# ---------------------------------------------------------------------------
@router.post(
    "/webhooks/github",
    status_code=status.HTTP_202_ACCEPTED,
    summary="GitHub Webhook ingress",
)
async def github_webhook(
    request:          Request,
    background_tasks: BackgroundTasks,
    db:               Annotated[AsyncSession, Depends(get_db)],
    _hmac:            None = Depends(verify_github_webhook),
):
    payload = await request.json()
    repo_data = payload.get("repository", {})
    repo_url = repo_data.get("html_url")

    if not repo_url:
        return JSONResponse(status_code=200, content={"message": "No repository URL in payload"})

    result = await db.execute(select(Repository).where(Repository.github_repo_url == repo_url))
    repo = result.scalars().first()
    if not repo:
        return JSONResponse(status_code=200, content={"message": "Repository not registered"})

    scan_result = await _scanner.scan_github_repo(repo_url)

    if scan_result.get("status") == "error":
        raise HTTPException(status_code=422, detail="Scan failed")

    if scan_result["status"] == "secure":
        return JSONResponse(status_code=200, content={"message": "Clean"})

    job_id = str(uuid.uuid4())
    job_row = VulnerabilityJob(
        id=job_id,
        user_id=repo.user_id,
        repository_id=repo.id,
        target_file_path=scan_result["file_path"],
        business_risk_score=scan_result["business_impact"],
        patch_status=PatchStatusEnum.PENDING,
        model_armor_blocked=0,
        self_healing_count=0,
        pull_request_url=None,
    )
    db.add(job_row)
    await db.commit()

    background_tasks.add_task(
        _run_agent_in_background,
        job_id=job_id,
        file_path=scan_result["file_path"],
        source_code=scan_result["raw_code"],
        test_command="pytest tests/",
    )

    return JSONResponse(status_code=202, content={"message": "Accepted"})


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


# ---------------------------------------------------------------------------
# GET /api/v1/jobs/{job_id}/stream
# ---------------------------------------------------------------------------

@router.get(
    "/{job_id}/stream",
    summary="Stream live job status updates via SSE",
)
async def stream_job_status(job_id: str):
    async def event_generator():
        while True:
            async with AsyncSessionLocal() as session:
                stmt = select(VulnerabilityJob).where(VulnerabilityJob.id == job_id)
                result = await session.execute(stmt)
                row = result.scalar_one_or_none()
                
                if row is None:
                    yield {"event": "error", "data": '{"detail": "Job not found"}'}
                    break
                    
                data = JobStatusResponse(
                    job_id=row.id,
                    status=row.patch_status.value,
                    file_path=row.target_file_path,
                    business_risk_score=row.business_risk_score,
                    model_armor_blocked=row.model_armor_blocked,
                    self_healing_count=row.self_healing_count,
                    pull_request_url=row.pull_request_url,
                ).model_dump_json()
                
                yield {"event": "message", "data": data}
                
                if row.patch_status.value in [PatchStatusEnum.VERIFIED.value, PatchStatusEnum.FAILED.value, PatchStatusEnum.MANUAL_REVIEW_REQUIRED.value]:
                    break
            
            await asyncio.sleep(2)

    return EventSourceResponse(event_generator())
