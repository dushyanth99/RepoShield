"""
RepoShield — FastAPI Application Entrypoint.

Bootstraps the ASGI application, mounts middleware, registers all routing
sub-modules, and fires a lifecycle startup handler that validates the async
database connection pool.

Run locally:
    uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

Expose over ngrok for hackathon demo:
    ngrok http 8000
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config.database import engine
from backend.routers import auth, pipeline
from backend.routers.security import router as security_router

# ---------------------------------------------------------------------------
# ASCII Banner
# ---------------------------------------------------------------------------
BANNER: str = r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    ██████╗ ███████╗██████╗  ██████╗ ███████╗██╗  ██╗        ║
║    ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔════╝██║  ██║        ║
║    ██████╔╝█████╗  ██████╔╝██║   ██║███████╗███████║        ║
║    ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║╚════██║██╔══██║        ║
║    ██║  ██║███████╗██║     ╚██████╔╝███████║██║  ██║        ║
║    ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚══════╝╚═╝  ╚═╝        ║
║                    ███████╗██╗  ██╗██╗███████╗██╗     ██████╗║
║                    ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
║                    ███████╗███████║██║█████╗  ██║     ██║  ██║
║                    ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
║                    ███████║██║  ██║██║███████╗███████╗██████╔╝
║                    ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ ║
║                                                              ║
║   🛡  Autonomous Vulnerability Remediation Platform          ║
║   ⚡  FastAPI  ·  SQLAlchemy 2.0  ·  Antigravity SDK         ║
║   🔒  Secured by Google Cloud Model Armor                    ║
╚══════════════════════════════════════════════════════════════╝
"""


# ---------------------------------------------------------------------------
# Lifespan — startup / shutdown lifecycle handler
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manages application-level startup and graceful shutdown.

    On startup:
      - Prints the branded ASCII banner to the terminal.
      - Fires a connectivity check against the async DB engine to confirm
        the connection pool is live before accepting any traffic.
        Uses pool_pre_ping so a recycled idle connection is never returned.

    On shutdown:
      - Disposes the async engine, draining all pooled connections cleanly.
    """
    # --- Startup ---
    print(BANNER)
    print("  ► Initialising async database connection pool...")

    try:
        async with engine.connect() as probe:
            await probe.execute(__import__("sqlalchemy").text("SELECT 1"))
        print("  ✓ Database connection pool is ACTIVE and healthy.\n")
    except Exception as exc:
        print(f"  ✗ Database connection failed on startup: {exc}\n")
        print("  ⚠  Proceeding without a verified DB connection — check DATABASE_URL.\n")

    print("  ► All routers mounted. RepoShield API is ready to accept requests.\n")

    yield  # Application runs here

    # --- Shutdown ---
    print("\n  ► Shutting down — disposing async database engine...")
    await engine.dispose()
    print("  ✓ Database connection pool drained. Goodbye.\n")


# ---------------------------------------------------------------------------
# FastAPI Application Instance
# ---------------------------------------------------------------------------
app: FastAPI = FastAPI(
    title="RepoShield API",
    description=(
        "Autonomous vulnerability detection and self-healing pipeline "
        "powered by Google Antigravity SDK and Model Armor."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# CORS Middleware
# Permissive configuration required during hackathon presentation because the
# React frontend is served over dynamic ngrok tunnels whose origins change on
# every tunnel restart. Tighten allow_origins to an explicit list before
# moving to a production environment.
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # Permit all origins (ngrok-safe for demo)
    allow_credentials=True,
    allow_methods=["*"],       # Permit all HTTP methods
    allow_headers=["*"],       # Permit all request headers
    expose_headers=["*"],      # Expose all response headers to the browser
)


# ---------------------------------------------------------------------------
# Router Registration
# ---------------------------------------------------------------------------
app.include_router(auth.router)          # /auth/*      — user authentication
app.include_router(pipeline.router)      # /pipeline/*  — scanning pipeline
app.include_router(security_router)      # /security/*  — agent job results


# ---------------------------------------------------------------------------
# Root health probe
# ---------------------------------------------------------------------------
@app.get("/", tags=["Health"], summary="Root health check")
async def root() -> dict[str, str]:
    """Simple liveness probe. Returns API name and version."""
    return {
        "service": "RepoShield API",
        "version": "0.1.0",
        "status": "operational",
    }
