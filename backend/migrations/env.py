"""
Async Alembic environment — migrations/env.py

Replaces the default sync-only Alembic template with a fully async-compatible
migration runner using SQLAlchemy's async_engine_from_config and NullPool.

NullPool is critical here: Alembic migrations run outside the application
lifespan, so we NEVER want pooled connections to persist between migration
steps. Each migration step gets a fresh connection.

Usage
-----
From backend/ directory:
    # Generate a new revision after model changes:
    python -m alembic revision --autogenerate -m "add xyz column"

    # Apply all pending migrations:
    python -m alembic upgrade head

    # Roll back one revision:
    python -m alembic downgrade -1
"""

import asyncio
import logging
import sys
import os
from logging.config import fileConfig
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure the backend/ directory is on sys.path so that relative imports
# like `from config.settings import settings` and `import models.audit`
# resolve correctly regardless of which directory alembic is invoked from.
# ---------------------------------------------------------------------------
BACKEND_DIR = Path(__file__).resolve().parent.parent  # .../backend/
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# -----------------------------------------------------------------------
# Load application models so Alembic can detect schema changes via
# autogenerate (Base.metadata captures all mapped tables).
# Import ALL models here, even if you don't use them directly.
# -----------------------------------------------------------------------
from config.database import Base
from config.settings import settings

# Explicitly import every model module so their table definitions are
# registered on Base.metadata before autogenerate runs.
import models.audit   # noqa: F401
import models.user    # noqa: F401

# -----------------------------------------------------------------------
# Alembic Config object (provides access to values in alembic.ini)
# -----------------------------------------------------------------------
config = context.config

# Wire Python logging to Alembic's logging configuration block in alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

alembic_logger = logging.getLogger("alembic.env")

# -----------------------------------------------------------------------
# Target metadata — Alembic diffs against this to produce migrations
# -----------------------------------------------------------------------
target_metadata = Base.metadata


# -----------------------------------------------------------------------
# Offline mode: generate SQL scripts without a live DB connection.
# Useful for review, DBA approval workflows, and CI pipelines.
# -----------------------------------------------------------------------
def run_migrations_offline() -> None:
    """
    Emit raw SQL instead of running against a live database.

    Useful when you want to review or hand-off the migration SQL to a DBA
    before applying it, or in environments where DB access is restricted.
    """
    url = settings.database_url
    alembic_logger.info("Running offline migrations against: %s", url)

    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,           # detect column type changes
        compare_server_default=True, # detect default value changes
    )

    with context.begin_transaction():
        context.run_migrations()


# -----------------------------------------------------------------------
# Online mode: run migrations against a live async DB connection.
# -----------------------------------------------------------------------
def do_run_migrations(connection) -> None:
    """Synchronous inner function required by connection.run_sync()."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """
    Connect via async engine and execute pending migrations.

    NullPool is intentional: Alembic is a one-shot CLI tool. Pooled
    connections would hold resources open indefinitely between migration
    steps, which is unnecessary and potentially dangerous.
    """
    configuration = dict(config.get_section(config.config_ini_section) or {})
    # Override the URL from Pydantic settings — ignores whatever is in alembic.ini
    configuration["sqlalchemy.url"] = settings.database_url

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    alembic_logger.info("Running online async migrations.")

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()
    alembic_logger.info("Async migration engine disposed.")


# -----------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------
if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
