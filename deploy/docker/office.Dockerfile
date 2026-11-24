# syntax=docker/dockerfile:1
# ==============================================================================
# ALLINAGENT — Hermes3D & 2D Pixel Virtual Office Production Container
# Base: node:24-bookworm-slim (Multi-Stage)
# Build: npm ci && npm run build && npm prune --omit=dev && rm -rf .next/cache
# User: non-root `node` (uid:gid 1000:1000) | PID 1: tini | Port: 3200
# ==============================================================================

FROM node:24-bookworm-slim AS builder

ENV NEXT_TELEMETRY_DISABLED=1 \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    NODE_OPTIONS="--max-old-space-size=1536"

WORKDIR /opt/allinagent/apps/hermes3d

COPY apps/hermes3d/package*.json ./
RUN if [ -f package-lock.json ]; then \
      npm ci; \
    else \
      npm install; \
    fi

COPY apps/hermes3d /opt/allinagent/apps/hermes3d

RUN NODE_ENV=production npm run build \
    && npm prune --omit=dev \
    && rm -rf .next/cache /root/.npm /tmp/* \
    && find /opt/allinagent/apps/hermes3d/server -type f -name "*.js" -exec sed -i 's/\r$//' {} +

# ------------------------------------------------------------------------------
# Stage 2: Minimal Hardened Production Runtime (Pure ESM next.config.mjs)
# ------------------------------------------------------------------------------
FROM node:24-bookworm-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/Vistapra/ALLINAGENT"
LABEL org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    NODE_OPTIONS="--max-old-space-size=128" \
    MALLOC_ARENA_MAX=2 \
    ALLINAGENT_DOCKER=1 \
    ALLINAGENT_ROOT=/opt/allinagent \
    AUTHORIZED_WORKSPACES=/var/lib/allinagent/workspaces \
    ALLINAGENT_WORKSPACE_ROOT=/var/lib/allinagent/workspaces \
    ALLINAGENT_SECRETS_DIR=/var/lib/allinagent/secrets \
    HOST=0.0.0.0 \
    PORT=3200 \
    OFFICE_BRIDGE_HTTP_URL=http://office-bridge:3210 \
    OFFICE_BRIDGE_WS_URL=ws://office-bridge:3210 \
    HERMES_STATE_DIR=/var/lib/allinagent/studio-state \
    UNIFIED_COMPANY_GOVERNANCE=1 \
    CUSTOM_RUNTIME_ALLOWLIST="office-bridge:3210,127.0.0.1:3210,localhost:3210"

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      tini \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p \
      /opt/allinagent/apps/hermes3d \
      /var/lib/allinagent/studio-state \
      /var/lib/allinagent/secrets \
      /var/lib/allinagent/workspaces \
    && chown -R node:node /opt/allinagent /var/lib/allinagent

WORKDIR /opt/allinagent/apps/hermes3d

COPY --from=builder --chown=node:node /opt/allinagent/apps/hermes3d/.next ./.next
COPY --from=builder --chown=node:node /opt/allinagent/apps/hermes3d/public ./public
COPY --from=builder --chown=node:node /opt/allinagent/apps/hermes3d/server ./server
COPY --from=builder --chown=node:node /opt/allinagent/apps/hermes3d/node_modules ./node_modules
COPY --from=builder --chown=node:node /opt/allinagent/apps/hermes3d/package.json ./package.json
COPY --from=builder --chown=node:node /opt/allinagent/apps/hermes3d/next.config.mjs ./next.config.mjs

USER node
EXPOSE 3200

HEALTHCHECK --interval=20s --timeout=5s --start-period=25s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3200/api/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "server/index.js"]
