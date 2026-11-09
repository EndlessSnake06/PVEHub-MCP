# syntax=docker/dockerfile:1
#
# PVEHub-MCP — multi-stage image.
#
# Build:  docker build -t pvehub-mcp:0.1.0 .
# Run:    docker compose up -d --build
#
# Both base images publish linux/amd64 and linux/arm64 variants; nothing in this
# file is architecture-specific. The build stage installs the project with uv
# (frozen lockfile, no dev extras, non-editable) into /app/.venv; the runtime
# stage only receives that venv, the sources and a non-root user.

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

# uv binary from the official multi-arch image, pinned by version.
COPY --from=ghcr.io/astral-sh/uv:0.12.23 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0 \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

# Dependency layer first: source edits do not invalidate the resolved wheels.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-dev --no-editable --no-install-project

# Project layer: install pvehub_mcp itself (non-editable) and prove the entrypoint.
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable \
    && /app/.venv/bin/pvehub-mcp --version

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ARG PVEHUB_UID=10001

LABEL org.opencontainers.image.title="PVEHub-MCP" \
      org.opencontainers.image.description="MCP server for Proxmox VE and Proxmox Backup Server" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/EndlessSnake06/PVEHub-MCP"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:${PATH}" \
    HOME=/data \
    PVEHUB_CONFIG_FILE=/config/config.yaml

# python:3.12-slim already ships ca-certificates; no extra packages are needed.

# Non-root runtime user (UID/GID 10001). No login shell, no home directory writes.
RUN groupadd --gid "${PVEHUB_UID}" pvehub \
    && useradd --uid "${PVEHUB_UID}" --gid "${PVEHUB_UID}" \
       --home-dir /app --no-create-home --shell /usr/sbin/nologin pvehub

WORKDIR /app
COPY --from=builder --chown=root:root /app/.venv /app/.venv
COPY --chown=root:root src /app/src

# Only /data is writable (named volume). /config and /ssh are mounted read-only.
RUN mkdir -p /data /config /ssh \
    && chown pvehub:pvehub /data \
    && chmod 0700 /data

USER 10001:10001

EXPOSE 8080

# Liveness (/health) is unauthenticated and minimal: it only reports that the
# process is running ({"status": "ok"}), never version or tool count.
# Readiness (/ready) is authenticated (same bearer as /mcp) and returns 503
# while any capability discovery is degraded; the container healthcheck
# probes /ready with the token from the container environment, so a dead or
# degraded backend turns the container "unhealthy" (issues #23, #24).
# stdio deployments have no HTTP listener, so this check stays "unhealthy"
# there — that is expected and harmless (see docs/CONFIGURATION.md).
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import os,sys,urllib.request as u; t=os.environ.get('PVEHUB_MCP_AUTH_TOKEN',''); h={'Authorization':'Bearer '+t} if t else {}; sys.exit(0 if u.urlopen(u.Request('http://127.0.0.1:8080/ready', headers=h), timeout=4).status==200 else 1)"]

ENTRYPOINT ["pvehub-mcp"]
