"""
Pipeline router stub — routers/pipeline.py

Placeholder module for the core vulnerability scanning pipeline endpoints.
Wires into the AutonomousSecurityOrchestrator to trigger agent runs,
poll job status, and retrieve audit ledger records.
Replace stubs with real implementations before production deployment.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/pipeline", tags=["Scanning Pipeline"])


@router.get("/health", summary="Pipeline router health check")
async def pipeline_health() -> dict:
    """Liveness probe for the scanning pipeline sub-module."""
    return {"status": "ok", "module": "pipeline"}
