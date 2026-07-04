"""
Database configuration for RepoShield backend.
Uses SQLAlchemy 2.0 async engine with aiomysql driver.
DATABASE_URL is sourced from the validated Pydantic settings singleton.
"""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

# ---------------------------------------------------------------------------
# Connection URL — sourced from validated Pydantic settings
# Set DATABASE_URL in your .env file.
# Example: mysql+aiomysql://user:password@localhost:3306/reposhield
# ---------------------------------------------------------------------------
from config.settings import settings

DATABASE_URL: str = settings.database_url

# ---------------------------------------------------------------------------
# Async Engine
# pool_size=20      : base connections kept open at all times
# max_overflow=10   : extra connections allowed beyond pool_size
# pool_recycle=3600 : recycle connections after 1 hour to prevent stale
#                     idle connections dropped by MySQL's wait_timeout —
#                     especially important for long-running async AI loops
# pool_pre_ping=True: issues a cheap "SELECT 1" before handing out a
#                     connection so dropped idle connections are detected
#                     and replaced automatically
# ---------------------------------------------------------------------------
engine: AsyncEngine = create_async_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=10,
    pool_recycle=3600,
    pool_pre_ping=True,
    echo=False,
)

# ---------------------------------------------------------------------------
# Session factory
# expire_on_commit=False keeps ORM objects usable after commit without
# triggering lazy-load errors in an async context.
# ---------------------------------------------------------------------------
AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# ---------------------------------------------------------------------------
# Declarative Base – shared by all models
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Yield an async database session and guarantee it is closed after the
    request — even if an exception is raised mid-request.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
