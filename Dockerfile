# =============================================================================
# CleanCare Solutions — Backend Dockerfile
# Multi-stage build: keeps production image lean and secret-free
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: builder — install dependencies into a venv
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

# System dependencies required by python-magic and cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy only requirements first — layer caches if requirements unchanged
COPY requirements.txt .

RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: production image
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS production

# libmagic runtime dependency
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user — principle of least privilege
RUN groupadd -r cleancare && useradd -r -g cleancare -d /app -s /sbin/nologin cleancare

WORKDIR /app

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Copy application source
COPY --chown=cleancare:cleancare . .

# Private uploads directory (mounted as volume in production)
RUN mkdir -p /private/uploads && chown -R cleancare:cleancare /private

USER cleancare

EXPOSE 8000

# Uvicorn in production: no --reload, multiple workers via env var
CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "127.0.0.1", \
     "--access-log", \
     "--no-server-header"]
