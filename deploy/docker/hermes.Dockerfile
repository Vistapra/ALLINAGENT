# syntax=docker/dockerfile:1
# ==============================================================================
# ALLINAGENT — Shared Hermes Execution Daemon & Telegram Control Runtime
# Base: Debian Bookworm Slim + uv + CPython 3.14 + Pinned NousResearch/hermes-agent
# Upstream Pin: eb49b8920a25ffa7bb2fadf548fe819221ca79d7 + 0001-error-classifier-integrator.patch
# License Gate: Permissive PDF/Doc stack ONLY (NO pymupdf AGPL, NO marker-pdf GPL)
# User: non-root `allinagent` (uid:gid 10001:10001) | PID 1: tini | Port: 8650
# ==============================================================================

FROM debian:bookworm-slim AS builder

ARG HERMES_UPSTREAM_REPO=https://github.com/NousResearch/hermes-agent.git
ARG HERMES_UPSTREAM_SHA=eb49b8920a25ffa7bb2fadf548fe819221ca79d7

ENV DEBIAN_FRONTEND=noninteractive \
    UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      patch \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.6.6 /uv /uvx /usr/local/bin/

# Install standalone CPython 3.14 and create isolated virtual environment
RUN uv python install 3.14 && \
    uv venv --python 3.14 /opt/hermes-venv

WORKDIR /opt/allinagent

# Copy core Hermes & Control Center components
COPY components/hermes /opt/allinagent/components/hermes
COPY apps/control-center /opt/allinagent/apps/control-center

# Copy shared manifests, patches, agent role specs, and skill definitions from context
RUN --mount=type=bind,source=.,target=/ctx,readonly \
    set -eux; \
    for dir in config patches agents skills skill-registry scripts; do \
      if [ -d "/ctx/${dir}" ]; then \
        mkdir -p "/opt/allinagent/${dir}"; \
        cp -a "/ctx/${dir}/." "/opt/allinagent/${dir}/"; \
      fi; \
    done; \
    if [ -d "/opt/allinagent/components/hermes/patches" ] && [ ! -d "/opt/allinagent/patches" ]; then \
      mkdir -p /opt/allinagent/patches; \
      cp -a /opt/allinagent/components/hermes/patches/. /opt/allinagent/patches/; \
    fi; \
    if [ -d "/opt/allinagent/components/hermes/agents" ] && [ ! -d "/opt/allinagent/agents" ]; then \
      mkdir -p /opt/allinagent/agents; \
      cp -a /opt/allinagent/components/hermes/agents/. /opt/allinagent/agents/; \
    fi; \
    if [ -d "/opt/allinagent/components/hermes/skills" ] && [ ! -d "/opt/allinagent/skills" ]; then \
      mkdir -p /opt/allinagent/skills; \
      cp -a /opt/allinagent/components/hermes/skills/. /opt/allinagent/skills/; \
    fi; \
    if [ ! -e "/opt/allinagent/integration" ]; then \
      ln -s /opt/allinagent/apps/control-center/integration /opt/allinagent/integration; \
    fi; \
    find /opt/allinagent -type f \( -name "*.sh" -o -name "*.py" -o -name "*.mjs" -o -name "*.patch" \) \
      -exec sed -i 's/\r$//' {} +; \
    chmod 0755 /opt/allinagent/components/hermes/entrypoint.sh

# Bootstrap pinned hermes-agent source, verify commit SHA, apply patch, and strip bloat
RUN set -eux; \
    mkdir -p /opt/allinagent/vendor/hermes-agent; \
    cd /opt/allinagent/vendor/hermes-agent; \
    git init; \
    git remote add origin "${HERMES_UPSTREAM_REPO}"; \
    git fetch --depth 1 origin "${HERMES_UPSTREAM_SHA}"; \
    git checkout --detach FETCH_HEAD; \
    ACTUAL_SHA="$(git rev-parse HEAD)"; \
    test "${ACTUAL_SHA}" = "${HERMES_UPSTREAM_SHA}"; \
    PATCH_FILE=""; \
    for cand in \
      /opt/allinagent/components/hermes/patches/hermes-agent/0001-error-classifier-integrator.patch \
      /opt/allinagent/patches/hermes-agent/0001-error-classifier-integrator.patch; do \
      if [ -f "${cand}" ]; then PATCH_FILE="${cand}"; break; fi; \
    done; \
    if ! grep -q "model_not_available_for_integrator" agent/error_classifier.py; then \
      if [ -n "${PATCH_FILE}" ]; then \
        patch -p1 --forward < "${PATCH_FILE}"; \
      else \
        /opt/hermes-venv/bin/python -c 'from pathlib import Path; p = Path("agent/error_classifier.py"); s = p.read_text(encoding="utf-8"); needle = "\"no endpoints found that support tool use\","; assert needle in s, "anchor missing"; p.write_text(s.replace(needle, needle + "\n    \"model_not_available_for_integrator\",", 1), encoding="utf-8")'; \
      fi; \
    fi; \
    grep -q "model_not_available_for_integrator" agent/error_classifier.py; \
    rm -rf .git apps/desktop website tests evals nix benchmarks docs

# Install hermes-agent + permissive messaging & document stack; enforce strict AGPL/GPL exclusion
RUN set -eux; \
    cd /opt/allinagent/vendor/hermes-agent; \
    /opt/hermes-venv/bin/python -c 'from pathlib import Path; import re; p = Path("pyproject.toml"); t = p.read_text(encoding="utf-8"); t = re.sub(r"(?i)^\s*\"?(?:pymupdf|marker-pdf)[^\"\n]*\"?,?\s*$", "", t, flags=re.M); p.write_text(t, encoding="utf-8")'; \
    if ! uv pip install --python /opt/hermes-venv/bin/python --no-cache "/opt/allinagent/vendor/hermes-agent[messaging,documents,documents-pdf]"; then \
      uv pip install --python /opt/hermes-venv/bin/python --no-cache "/opt/allinagent/vendor/hermes-agent"; \
    fi; \
    uv pip install --python /opt/hermes-venv/bin/python --no-cache \
      python-telegram-bot \
      python-docx \
      reportlab \
      pypdf \
      pdfplumber; \
    if [ -f /opt/allinagent/apps/control-center/requirements.txt ]; then \
      uv pip install --python /opt/hermes-venv/bin/python --no-cache \
        -r /opt/allinagent/apps/control-center/requirements.txt; \
    fi; \
    /opt/hermes-venv/bin/python -c 'import importlib.metadata as md; pkgs = {d.metadata["Name"].lower() for d in md.distributions() if d.metadata.get("Name")}; forbidden = pkgs & {"pymupdf", "marker-pdf"}; assert not forbidden, f"Forbidden copyleft packages detected: {forbidden}"; required = {"python-telegram-bot", "python-docx", "reportlab", "pypdf", "pdfplumber"}; missing = required - pkgs; assert not missing, f"Missing required packages: {missing}"'; \
    find /opt/hermes-venv /opt/python /opt/allinagent -type d -name "__pycache__" -exec rm -rf {} +; \
    rm -rf /root/.cache /tmp/*

# ------------------------------------------------------------------------------
# Stage 2: Minimal Hardened Production Runtime (Zero build caches / Zero uv)
# ------------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/Vistapra/ALLINAGENT"
LABEL org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/opt/hermes-venv/bin:/usr/local/bin:/usr/bin:/bin" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONMALLOC=malloc \
    MALLOC_ARENA_MAX=2 \
    ALLINAGENT_DOCKER=1 \
    ALLINAGENT_ROOT=/opt/allinagent \
    PYTHONPATH="/opt/allinagent/apps/control-center:/opt/allinagent:/opt/allinagent/vendor/hermes-agent" \
    HERMES_SOURCE_DIR=/opt/allinagent/vendor/hermes-agent \
    HERMES_HOME=/var/lib/allinagent/hermes \
    HERMES_DATA_ROOT=/var/lib/allinagent/hermes \
    HERMES_PROFILES_ROOT=/var/lib/allinagent/hermes/profiles \
    ALLINAGENT_WORKSPACE_ROOT=/var/lib/allinagent/workspaces \
    ALLINAGENT_REPORTS_ROOT=/var/lib/allinagent/reports \
    ALLINAGENT_SECRETS_DIR=/var/lib/allinagent/secrets \
    HERMES_EXEC_HOST=0.0.0.0 \
    HERMES_EXEC_PORT=8650 \
    HEAVY_WORKER_CONCURRENCY=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      tini \
      tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 allinagent \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/allinagent --shell /bin/bash allinagent \
    && mkdir -p \
      /var/lib/allinagent/hermes \
      /var/lib/allinagent/hermes/profiles \
      /var/lib/allinagent/workspaces \
      /var/lib/allinagent/reports \
      /var/lib/allinagent/data \
      /var/lib/allinagent/secrets \
    && chown -R 10001:10001 /var/lib/allinagent /home/allinagent

COPY --from=builder --chown=10001:10001 /opt/python /opt/python
COPY --from=builder --chown=10001:10001 /opt/hermes-venv /opt/hermes-venv
COPY --from=builder --chown=10001:10001 /opt/allinagent /opt/allinagent

RUN printf '#!/bin/sh\nexec /opt/hermes-venv/bin/python -m hermes_cli.main "$@"\n' > /usr/local/bin/hermes \
    && chmod 0755 /usr/local/bin/hermes

WORKDIR /opt/allinagent
USER 10001:10001
EXPOSE 8650

HEALTHCHECK --interval=20s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8650/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/opt/allinagent/components/hermes/entrypoint.sh"]
