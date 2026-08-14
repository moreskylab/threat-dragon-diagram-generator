# ==============================================================================
# Dragon-GPT Cloud Native Dockerfile
# Multi-stage, minimal, secure non-root container image with Graphviz support
# ==============================================================================

# --- Stage 1: Build & Dependencies ---
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install uv for fast, reliable dependency installation
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy dependency definition
COPY pyproject.toml README.md ./

# Install dependencies into a dedicated virtualenv
RUN uv venv /opt/venv && \
    . /opt/venv/bin/activate && \
    uv pip install --no-cache .

# --- Stage 2: Runtime Image ---
FROM python:3.12-slim-bookworm AS runner

LABEL org.opencontainers.image.title="Dragon-GPT Cloud Native Platform" \
      org.opencontainers.image.description="Cloud-native automated threat modeling for OWASP Threat Dragon diagrams using LLMs" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.authors="DevSecOps & Platform Security Team" \
      org.opencontainers.image.source="https://github.com/moreskylab/threat-dragon-diagram-generator"

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    PORT=8000 \
    HOST=0.0.0.0 \
    ENV=production

# Install runtime OS dependencies: Graphviz for diagram rendering, curl for healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    graphviz \
    fonts-freefont-ttf \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy virtualenv from builder stage
COPY --from=builder /opt/venv /opt/venv

# Create non-root user and group for security
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/bash -m appuser

# Copy application source code
COPY --chown=appuser:appgroup api/ ./api/
COPY --chown=appuser:appgroup utils/ ./utils/
COPY --chown=appuser:appgroup diagram/ ./diagram/
COPY --chown=appuser:appgroup web/ ./web/
COPY --chown=appuser:appgroup main.py generate.py ./

# Create writable temp directory for diagram generation
RUN mkdir -p /app/diagram/generated && chown -R appuser:appgroup /app

# Switch to non-root user
USER 10001:10001

EXPOSE 8000

# Cloud-native container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/healthz || exit 1

# Launch FastAPI Uvicorn Server
CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
