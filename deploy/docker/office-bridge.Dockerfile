# syntax=docker/dockerfile:1
# ==============================================================================
# ALLINAGENT — Unified Office Bridge & Realtime Event Bus Container
# Base: node:24-bookworm-slim (Multi-Stage, optional Chromium build arg)
# Components: apps/office-bridge + apps/control-center + /usr/local/bin/hermes
# User: non-root `node` (uid:gid 1000:1000) | PID 1: tini | Port: 3210
# ==============================================================================

FROM node:24-bookworm-slim AS builder

ENV NODE_ENV=production \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false

WORKDIR /opt/allinagent/apps/office-bridge

COPY apps/office-bridge/package*.json ./
RUN if [ -f package-lock.json ]; then \
      npm ci --omit=dev; \
    else \
      npm install --omit=dev; \
    fi \
    && npm cache clean --force \
    && rm -rf /root/.npm /tmp/*

COPY apps/office-bridge /opt/allinagent/apps/office-bridge
COPY apps/control-center /opt/allinagent/apps/control-center
COPY components/hermes/hermes-cli-shim.mjs /stage/hermes-cli-shim.mjs

RUN --mount=type=bind,source=.,target=/ctx,readonly \
    set -eux; \
    for dir in config agents skills skill-registry scripts; do \
      if [ -d "/ctx/${dir}" ]; then \
        mkdir -p "/opt/allinagent/${dir}"; \
        cp -a "/ctx/${dir}/." "/opt/allinagent/${dir}/"; \
      fi; \
    done; \
    if [ ! -e "/opt/allinagent/office-bridge" ]; then \
      ln -s /opt/allinagent/apps/office-bridge /opt/allinagent/office-bridge; \
    fi; \
    if [ ! -e "/opt/allinagent/integration" ]; then \
      ln -s /opt/allinagent/apps/control-center/integration /opt/allinagent/integration; \
    fi; \
    find /opt/allinagent /stage -type f \( -name "*.js" -o -name "*.mjs" -o -name "*.py" -o -name "*.sh" \) \
      -exec sed -i 's/\r$//' {} +; \
    chmod 0755 /stage/hermes-cli-shim.mjs

# ------------------------------------------------------------------------------
# Stage 2: Minimal Hardened Production Runtime (+ optional headless Chromium)
# ------------------------------------------------------------------------------
FROM node:24-bookworm-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/Vistapra/ALLINAGENT"
LABEL org.opencontainers.image.licenses="MIT"

ARG INSTALL_CHROMIUM=false

ENV DEBIAN_FRONTEND=noninteractive \
    NODE_ENV=production \
    NODE_OPTIONS="--max-old-space-size=112" \
    MALLOC_ARENA_MAX=2 \
    ALLINAGENT_DOCKER=1 \
    OFFICE_BRIDGE_ALLOW_DOCKER_NETWORK=1 \
    OFFICE_BRIDGE_ALLOW_CONTAINER_BIND=1 \
    ALLINAGENT_ROOT=/opt/allinagent \
    ALLINAGENT_SECRETS_DIR=/var/lib/allinagent/secrets \
    ALLINAGENT_WORKSPACE_ROOT=/var/lib/allinagent/workspaces \
    ALLINAGENT_REPORTS_ROOT=/var/lib/allinagent/reports \
    PYTHONPATH="/opt/allinagent/apps/control-center:/opt/allinagent" \
    OFFICE_BRIDGE_HOST=0.0.0.0 \
    OFFICE_BRIDGE_PORT=3210 \
    PAPERCLIP_BASE_URL=http://paperclip:3100 \
    PAPERCLIP_URL=http://paperclip:3100 \
    HERMES_REMOTE_EXEC_URL=http://hermes:8650 \
    HERMES_EXEC_URL=http://hermes:8650 \
    VULNCLAW_WORKER_URL=http://vulnclaw:8660 \
    HERMES_HOME=/var/lib/allinagent/hermes \
    OFFICE_DATA_DIR=/var/lib/allinagent/office-data

RUN set -eux; \
    apt-get update; \
    EXTRA_PKGS=""; \
    if [ "${INSTALL_CHROMIUM}" = "true" ]; then \
      EXTRA_PKGS="chromium fonts-liberation"; \
    fi; \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      python3 \
      tini \
      ${EXTRA_PKGS}; \
    rm -rf /var/lib/apt/lists/*; \
    git config --system --add safe.directory '*'; \
    mkdir -p /var/lib/allinagent/office-data \
             /var/lib/allinagent/data \
             /var/lib/allinagent/secrets \
             /var/lib/allinagent/workspaces \
             /var/lib/allinagent/reports \
             /var/lib/allinagent/hermes \
             /var/lib/allinagent/logs; \
    chown -R node:node /var/lib/allinagent

COPY --from=builder --chown=node:node /opt/allinagent /opt/allinagent
COPY --from=builder /stage/hermes-cli-shim.mjs /usr/local/bin/hermes

RUN chmod 0755 /usr/local/bin/hermes

WORKDIR /opt/allinagent/apps/office-bridge
USER node
EXPOSE 3210

HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3210/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "server.js"]
