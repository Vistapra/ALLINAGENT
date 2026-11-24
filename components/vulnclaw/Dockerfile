# syntax=docker/dockerfile:1
# ALLINAGENT Phase 10 — VulnClaw Lightweight On-Demand Defensive Worker Image
# Idle RSS: < 25 MB | Ephemeral child subprocess per scan | Zero heavy ML/browser packages

FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/components/vulnclaw
COPY requirements-defensive.txt vulnclaw.defensive.yaml bootstrap_vulnclaw.py __init__.py ./

RUN python -m venv /opt/vulnclaw-venv && \
    python bootstrap_vulnclaw.py \
        --target-dir /opt/vulnclaw-src \
        --venv-dir /opt/vulnclaw-venv \
        --config-dir /opt/vulnclaw-config \
        --prune


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    PATH="/opt/vulnclaw-venv/bin:${PATH}" \
    VULNCLAW_SOURCE_DIR=/opt/vulnclaw-src \
    VULNCLAW_CONFIG_DIR=/opt/vulnclaw-config \
    VULNCLAW_BIND_HOST=0.0.0.0 \
    VULNCLAW_HOST=0.0.0.0 \
    VULNCLAW_PORT=8660 \
    AUTHORIZED_WORKSPACES=/workspaces

RUN groupadd --gid 10002 vulnclaw && \
    useradd --uid 10002 --gid 10002 --create-home --shell /usr/sbin/nologin vulnclaw && \
    mkdir -p /workspaces /tmp/vulnclaw-work && \
    chown -R 10002:10002 /tmp/vulnclaw-work

COPY --from=builder /opt/vulnclaw-venv /opt/vulnclaw-venv
COPY --from=builder /opt/vulnclaw-src /opt/vulnclaw-src
COPY --from=builder /opt/vulnclaw-config /opt/vulnclaw-config
COPY __init__.py vulnclaw_worker.py vulnclaw.defensive.yaml /opt/allinagent/components/vulnclaw/

USER 10002:10002
WORKDIR /opt/allinagent/components/vulnclaw

EXPOSE 8660

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/opt/vulnclaw-venv/bin/python", "/opt/allinagent/components/vulnclaw/vulnclaw_worker.py", "health", "--probe-http"]

CMD ["/opt/vulnclaw-venv/bin/python", "/opt/allinagent/components/vulnclaw/vulnclaw_worker.py", "serve"]
