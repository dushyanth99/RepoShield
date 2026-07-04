"""
RepoShield — FastAPI Application Entrypoint
main.py

Boot sequence (order is critical):
  1. setup_production_logging()  — must run first, before any other import
                                   fires a log call
  2. FastAPI app + CORS
  3. Limiter + RateLimitExceeded handler (Deficit 5)
  4. Router registration
  5. Lifespan DB probe

Run locally (from the backend/ directory):
    python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

# ── Step 1: Activate JSON logging BEFORE any other module-level logger fires ──
from config.logging_config import setup_production_logging
setup_production_logging()

# ── All other imports come AFTER logging is initialised ───────────────────────
import logging
import sqlalchemy
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from config.database import engine
from routers.auth import limiter, router as auth_router
from routers.pipeline import router as pipeline_router

logger = logging.getLogger("reposhield.main")


# ---------------------------------------------------------------------------
# Lifespan — startup / shutdown
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    """
    Startup: probe the async DB connection pool.
    Shutdown: drain all pooled connections gracefully.
    """
    logger.info("RepoShield Core Engine starting up")

    print("========================================")
    print("[*] RepoShield Core Engine Initialized")
    print("========================================")
    print("   Stack   : FastAPI . SQLAlchemy 2.0 . Antigravity SDK")
    print("   Security : Google Cloud Model Armor . slowapi rate limiting")
    print("   Logging  : Structured JSON (cloud-ready)")
    print("========================================")

    try:
        async with engine.connect() as probe:
            await probe.execute(sqlalchemy.text("SELECT 1"))
        print("[OK] Database connection pool ACTIVE\n")
        logger.info("Database connection pool probed successfully")
    except Exception as exc:
        print(f"[WARN] Database connection failed: {exc}")
        logger.warning(
            "Database probe failed -- proceeding without verified pool",
            extra={"error": str(exc)},
        )

    yield  # ─── application serves requests here ───

    logger.info("Shutting down -- draining database connection pool")
    print("\n[>>] Shutting down -- draining database connection pool...")
    await engine.dispose()
    print("[OK] Shutdown complete.\n")
    logger.info("Engine disposed. Shutdown complete.")


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
# Rate Limiter (Deficit 5 fix)
# Attaches the slowapi limiter to app.state so the @limiter.limit() decorator
# on routers can find it. The exception handler converts 429 limit-exceeded
# events into proper JSON responses instead of raw 500 errors.
#
# This setup also handles requests routed through ngrok / reverse proxies
# because slowapi's get_remote_address reads X-Forwarded-For automatically
# when the standard ASGI scope is populated by the proxy.
# ---------------------------------------------------------------------------
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

logger.info("slowapi rate limiter mounted")


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(auth_router)      # /auth/*         — authentication
app.include_router(pipeline_router)  # /api/v1/jobs/*  — scan pipeline

logger.info(
    "Routers registered",
    extra={"routers": ["/auth", "/api/v1/jobs"]},
)


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
