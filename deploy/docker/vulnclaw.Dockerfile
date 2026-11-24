# syntax=docker/dockerfile:1
# ==============================================================================
# ALLINAGENT — VulnClaw Defensive On-Demand Security Worker Container
# Base: python:3.12-slim-bookworm (Multi-Stage)
# Upstream Pin: Netw0rkNoob/VulnClaw @ 0b34878f84b089b21fcf85ecd445315f14df0672 (v0.4.1)
# Security: non-root `vulnclaw` (uid:gid 10002:10002, /usr/sbin/nologin),
#           no sudo, no Docker socket, minimal defensive wheels only.
# ==============================================================================

FROM python:3.12-slim-bookworm AS builder

ARG VULNCLAW_UPSTREAM_REPO=https://github.com/Netw0rkNoob/VulnClaw.git
ARG VULNCLAW_UPSTREAM_SHA=0b34878f84b089b21fcf85ecd445315f14df0672

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/opt/vulnclaw-venv/bin:/usr/local/bin:/usr/bin:/bin" \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      git \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/vulnclaw-venv

WORKDIR /opt/allinagent

COPY components/vulnclaw /opt/allinagent/components/vulnclaw

RUN --mount=type=bind,source=.,target=/ctx,readonly \
    set -eux; \
    if [ -d "/ctx/config" ]; then \
      mkdir -p /opt/allinagent/config; \
      cp -a /ctx/config/. /opt/allinagent/config/; \
    fi; \
    find /opt/allinagent -type f \( -name "*.py" -o -name "*.txt" -o -name "*.yaml" -o -name "*.yml" \) \
      -exec sed -i 's/\r$//' {} +; \
    mkdir -p /opt/allinagent/vendor /opt/vulnclaw-config; \
    python /opt/allinagent/components/vulnclaw/bootstrap_vulnclaw.py \
      --target-dir /opt/allinagent/vendor/vulnclaw \
      --venv-dir /opt/vulnclaw-venv \
      --config-dir /opt/vulnclaw-config \
      --requirements /opt/allinagent/components/vulnclaw/requirements-defensive.txt \
      --prune; \
    pip uninstall -y pip setuptools wheel; \
    find /opt/vulnclaw-venv /opt/allinagent /opt/vulnclaw-config -type d -name "__pycache__" -exec rm -rf {} +; \
    rm -rf /root/.cache /tmp/*

# ------------------------------------------------------------------------------
# Stage 2: Air-Gapped Locked-Down Runtime (uid:gid 10002:10002, nologin)
# ------------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.source="https://github.com/Vistapra/ALLINAGENT"
LABEL org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/opt/vulnclaw-venv/bin:/usr/local/bin:/usr/bin:/bin" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONMALLOC=malloc \
    MALLOC_ARENA_MAX=2 \
    ALLINAGENT_DOCKER=1 \
    VULNCLAW_DEFENSIVE_ONLY=1 \
    VULNCLAW_BIND_HOST=0.0.0.0 \
    VULNCLAW_HOST=0.0.0.0 \
    VULNCLAW_PORT=8660 \
    AUTHORIZED_WORKSPACES=/workspaces:/var/lib/allinagent/workspaces \
    VULNCLAW_CONFIG_DIR=/opt/vulnclaw-config \
    VULNCLAW_SOURCE_DIR=/opt/allinagent/vendor/vulnclaw \
    VULNCLAW_DATA_DIR=/var/lib/vulnclaw \
    VULNCLAW_WORKSPACES_DIR=/workspaces

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10002 vulnclaw \
    && useradd --uid 10002 --gid 10002 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin vulnclaw \
    && mkdir -p /var/lib/vulnclaw /workspaces /var/lib/allinagent/workspaces \
    && chown 10002:10002 /var/lib/vulnclaw

COPY --from=builder --chown=root:root /opt/vulnclaw-venv /opt/vulnclaw-venv
COPY --from=builder --chown=root:root /opt/allinagent /opt/allinagent
COPY --from=builder --chown=10002:10002 /opt/vulnclaw-config /opt/vulnclaw-config

WORKDIR /opt/allinagent
USER 10002:10002
EXPOSE 8660

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/opt/vulnclaw-venv/bin/python", "/opt/allinagent/components/vulnclaw/vulnclaw_worker.py", "health", "--probe-http"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/opt/vulnclaw-venv/bin/python", "/opt/allinagent/components/vulnclaw/vulnclaw_worker.py", "serve"]
