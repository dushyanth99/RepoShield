"""
Authentication router stub — routers/auth.py

Placeholder module for user registration, login, token refresh, and
GitHub OAuth callback endpoints. Replace stubs with real implementations
before production deployment.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get("/health", summary="Auth router health check")
async def auth_health() -> dict:
    """Liveness probe for the authentication sub-module."""
    return {"status": "ok", "module": "auth"}
