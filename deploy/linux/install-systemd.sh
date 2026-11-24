#!/usr/bin/env bash
# ==============================================================================
# ALLINAGENT — Idempotent Linux Systemd Installer (`install-systemd.sh`)
# Installs and enables:
#   1. allinagent.service             (boot autostart of Docker Compose stack)
#   2. allinagent-maintenance.service (resource-capped coordinated updater)
#   3. allinagent-maintenance.timer   (daily 03:00 in configured TIMEZONE)
# ==============================================================================
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "[install-systemd] Error: must be executed as root (use sudo)." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${INSTALL_ROOT}/.env"
SYSTEMD_DIR="/etc/systemd/system"

TIMEZONE_VAL="UTC"
if [ -f "${ENV_FILE}" ]; then
  EXTRACTED_TZ="$(grep -E '^TIMEZONE=' "${ENV_FILE}" | tail -n 1 | cut -d'=' -f2- | tr -d '"\r ' || true)"
  if [ -n "${EXTRACTED_TZ}" ]; then
    TIMEZONE_VAL="${EXTRACTED_TZ}"
  fi
fi

chmod 0755 "${INSTALL_ROOT}/allinagent"

sed "s|/opt/allinagent|${INSTALL_ROOT}|g" \
  "${SCRIPT_DIR}/allinagent.service" > "${SYSTEMD_DIR}/allinagent.service"

sed "s|/opt/allinagent|${INSTALL_ROOT}|g" \
  "${SCRIPT_DIR}/allinagent-maintenance.service" > "${SYSTEMD_DIR}/allinagent-maintenance.service"

sed "s|03:00:00 UTC|03:00:00 ${TIMEZONE_VAL}|g" \
  "${SCRIPT_DIR}/allinagent-maintenance.timer" > "${SYSTEMD_DIR}/allinagent-maintenance.timer"

chmod 0644 \
  "${SYSTEMD_DIR}/allinagent.service" \
  "${SYSTEMD_DIR}/allinagent-maintenance.service" \
  "${SYSTEMD_DIR}/allinagent-maintenance.timer"

systemctl daemon-reload
systemctl enable allinagent.service
systemctl enable --now allinagent-maintenance.timer

if [ "${ALLINAGENT_START_NOW:-1}" = "1" ] && [ -f "${ENV_FILE}" ]; then
  systemctl start allinagent.service
fi

echo "[install-systemd] Installed and enabled ALLINAGENT systemd units:"
echo "  - Root Directory : ${INSTALL_ROOT}"
echo "  - Timer Schedule : *-*-* 03:00:00 ${TIMEZONE_VAL} (Persistent=true)"
systemctl list-timers --no-pager allinagent-maintenance.timer || true
