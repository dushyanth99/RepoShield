"""
RepoShield — FastAPI Application Entrypoint
main.py

Bootstraps the ASGI application, mounts CORS middleware, registers routers,
and fires a clean startup lifecycle banner.

Run locally (from the backend/ directory):
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config.database import engine
from routers.auth import router as auth_router
from routers.pipeline import router as pipeline_router


# ---------------------------------------------------------------------------
# Lifespan — startup / shutdown
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    """
    Startup: validate the async DB connection pool is live.
    Shutdown: drain all pooled connections gracefully.
    """
    import sqlalchemy

    print("========================================")
    print("🚀 RepoShield Core Engine Initialized")
    print("========================================")
    print("   Stack  : FastAPI · SQLAlchemy 2.0 · Antigravity SDK")
    print("   Security: Google Cloud Model Armor")
    print("========================================")

    try:
        async with engine.connect() as probe:
            await probe.execute(sqlalchemy.text("SELECT 1"))
        print("✅ Database connection pool ACTIVE\n")
    except Exception as exc:
        print(f"⚠️  Database connection failed: {exc}")
        print("   Proceeding without a verified DB pool — check DATABASE_URL.\n")

    yield  # application runs here

    print("\n🔻 Shutting down — draining database connection pool...")
    await engine.dispose()
    print("✅ Shutdown complete.\n")


# ---------------------------------------------------------------------------
# Application instance
# ---------------------------------------------------------------------------
app = FastAPI(
    title="RepoShield Core API",
    version="1.0.0",
    description=(
        "Autonomous vulnerability detection and self-healing remediation "
        "powered by Google Antigravity SDK and Model Armor."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# CORS — permissive for hackathon / ngrok demo
# Tighten allow_origins to an explicit list before production deployment.
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(auth_router)      # /auth/*          — user authentication
app.include_router(pipeline_router)  # /api/v1/jobs/*   — scanning pipeline


# ---------------------------------------------------------------------------
# Root health probe
# ---------------------------------------------------------------------------
@app.get("/", tags=["Health"], summary="Root liveness check")
async def root() -> dict[str, str]:
    return {
        "service": "RepoShield Core API",
        "version": "1.0.0",
        "status":  "operational",
    }
