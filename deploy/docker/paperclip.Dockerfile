# syntax=docker/dockerfile:1
# ==============================================================================
# ALLINAGENT — Paperclip Control Plane Production Container
# Base: node:24-bookworm-slim (Multi-Stage)
# Package: paperclipai@2026.1117.0 (--omit=dev --no-optional, zero embedded-pg)
# Patches: prune-paperclip-bloat.mjs + apply-paperclip-patches.mjs + hermes shim
# User: non-root `node` (uid:gid 1000:1000) | PID 1: tini | Port: 3100
# ==============================================================================

FROM node:24-bookworm-slim AS builder

ARG PAPERCLIP_VERSION=2026.1117.0

ENV NODE_ENV=production \
    PAPERCLIP_APP_DIR=/opt/paperclip \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false

WORKDIR /opt/paperclip

RUN printf '{\n  "name": "allinagent-paperclip-runtime",\n  "private": true,\n  "version": "1.0.0"\n}\n' > package.json \
    && (npm install --omit=dev "paperclipai@${PAPERCLIP_VERSION}" || npm install --omit=dev --ignore-scripts "paperclipai@${PAPERCLIP_VERSION}") \
    && npm cache clean --force \
    && rm -rf /root/.npm /tmp/*

COPY components/paperclip /opt/allinagent/components/paperclip
COPY components/hermes/hermes-cli-shim.mjs /stage/hermes-cli-shim.mjs

RUN --mount=type=bind,source=.,target=/ctx,readonly \
    set -eux; \
    if [ -d "/ctx/patches" ]; then \
      mkdir -p /opt/allinagent/patches; \
      cp -a /ctx/patches/. /opt/allinagent/patches/; \
    fi; \
    if [ -d "/ctx/config" ]; then \
      mkdir -p /opt/allinagent/config; \
      cp -a /ctx/config/. /opt/allinagent/config/; \
    fi; \
    find /opt/allinagent /stage -type f \( -name "*.mjs" -o -name "*.js" -o -name "*.patch" \) \
      -exec sed -i 's/\r$//' {} +; \
    chmod 0755 /stage/hermes-cli-shim.mjs \
      /opt/allinagent/components/paperclip/paperclip-server-entry.mjs; \
    node /opt/allinagent/components/paperclip/prune-paperclip-bloat.mjs --node-modules /opt/paperclip/node_modules --prune-embedded-postgres; \
    node /opt/allinagent/components/paperclip/apply-paperclip-patches.mjs /opt/paperclip; \
    rm -rf /root/.npm /tmp/*

# ------------------------------------------------------------------------------
# Stage 2: Minimal Hardened Production Runtime
# ------------------------------------------------------------------------------
FROM node:24-bookworm-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/Vistapra/ALLINAGENT"
LABEL org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    NODE_ENV=production \
    NODE_OPTIONS="--max-old-space-size=480" \
    MALLOC_ARENA_MAX=2 \
    ALLINAGENT_DOCKER=1 \
    ALLINAGENT_ROOT=/opt/allinagent \
    PAPERCLIP_APP_DIR=/opt/paperclip \
    PAPERCLIP_HOME=/var/lib/allinagent/paperclip \
    PAPERCLIP_DEPLOYMENT_MODE=local_trusted \
    PAPERCLIP_ALLOWED_HOSTNAMES=paperclip,allinagent-paperclip,localhost,127.0.0.1,host.docker.internal \
    ALLINAGENT_WORKSPACE_ROOT=/var/lib/allinagent/workspaces \
    ALLINAGENT_REPORTS_ROOT=/var/lib/allinagent/reports \
    ALLINAGENT_SECRETS_DIR=/var/lib/allinagent/secrets \
    HERMES_REMOTE_EXEC_URL=http://hermes:8650 \
    HERMES_EXEC_URL=http://hermes:8650 \
    HOST=0.0.0.0 \
    PORT=3100

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      tini \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/allinagent/paperclip \
                /var/lib/allinagent/workspaces \
                /var/lib/allinagent/reports \
                /var/lib/allinagent/hermes/profiles \
                /var/lib/allinagent/secrets \
    && chown -R node:node /var/lib/allinagent

COPY --from=builder --chown=node:node /opt/paperclip /opt/paperclip
COPY --from=builder --chown=node:node /opt/allinagent /opt/allinagent
COPY --from=builder /stage/hermes-cli-shim.mjs /usr/local/bin/hermes

RUN chmod 0755 /usr/local/bin/hermes

WORKDIR /opt/paperclip
USER node
EXPOSE 3100

HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
  CMD curl -fsS http://127.0.0.1:3100/api/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "/opt/allinagent/components/paperclip/paperclip-server-entry.mjs"]
