# =============================================================================
# RepoShield Core API — Multi-Stage Rootless Dockerfile
# =============================================================================
#
# Stage 1 (builder): Install Python wheels into the build user's local
#   site-packages. The full compiler toolchain is available here but stays
#   out of the final image.
#
# Stage 2 (runner): Minimal runtime image. Copies only the installed wheels
#   and application source. Runs as a non-privileged user (UID 10001).
#   No build tools, no root. Attack surface is minimal.
#
# Build & run:
#   docker build -t reposhield-api:latest .
#   docker run -p 8000:8000 --env-file .env reposhield-api:latest
# =============================================================================

# ─────────────────────────────────────────────────────────────
# Stage 1: Build Dependencies
# ─────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

LABEL stage="builder"

WORKDIR /app

# Install native compile toolchain required by some Python wheels
# (e.g. mysqlclient, cryptography). Purge the apt cache immediately to keep
# the layer thin — these tools will NOT be present in the final image.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libssl-dev \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to exploit Docker layer caching — the pip install
# layer is only invalidated when requirements.txt changes.
COPY requirements.txt .

# Install wheels into the build-user's local path.
# --no-cache-dir keeps the layer lean; --user avoids writing to system site-packages.
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --user -r requirements.txt


# ─────────────────────────────────────────────────────────────
# Stage 2: Final Runtime Executable
# ─────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runner

LABEL maintainer="RepoShield Engineering <eng@reposhield.io>" \
      version="1.0.0" \
      description="RepoShield autonomous vulnerability remediation API"

WORKDIR /app

# Create a non-privileged runtime system user and group.
# UID/GID 10001 is above the reserved system range, avoiding privilege
# escalation vectors.
RUN groupadd --gid 10001 appgroup && \
    useradd  --uid 10001 \
             --gid appgroup \
             --no-create-home \
             --shell /sbin/nologin \
             appuser

# Copy installed wheel artifacts from the builder layer.
# The builder installed to /root/.local — copy to the runtime user's home.
COPY --from=builder /root/.local /home/appuser/.local

# Copy application source files.
# .dockerignore should exclude: .git, __pycache__, *.pyc, .env, tmp/, tests/
COPY . .

# Transfer ownership of the application directory to the runtime user.
RUN chown -R appuser:appgroup /app

# Drop to the non-root user for all subsequent operations.
USER appuser

# Ensure the user-local pip packages are on PATH.
ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1

# Port the API listens on (must match ENTRYPOINT --port).
EXPOSE 8000

# Health check — Docker Swarm / Kubernetes liveness probe.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')"

# 4 Uvicorn workers for production parallelism.
# Override --workers via ENTRYPOINT args or a CMD override in docker-compose.
ENTRYPOINT ["python", "-m", "uvicorn", "main:app", \
            "--host", "0.0.0.0", \
            "--port", "8000", \
            "--workers", "4", \
            "--access-log"]
