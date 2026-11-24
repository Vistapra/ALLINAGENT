#!/usr/bin/env bash
# ==============================================================================
# ALLINAGENT — Safe Nginx Vhost Installer (`install-nginx.sh`)
# Renders `nginx-allinagent.conf.template`, validates via `nginx -t`, and reloads
# Nginx cleanly without risking existing host sites.
# ==============================================================================
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "[install-nginx] Error: must run as root (sudo)." >&2
  exit 1
fi

if [ $# -lt 1 ] && [ -z "${ALLINAGENT_DOMAIN:-}" ]; then
  echo "Usage: sudo $0 <domain> [tls_cert_path] [tls_key_path]" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ALLINAGENT_DOMAIN="${1:-${ALLINAGENT_DOMAIN}}"
export ALLINAGENT_OFFICE_PORT="${ALLINAGENT_OFFICE_PORT:-8200}"
export ALLINAGENT_BRIDGE_PORT="${ALLINAGENT_BRIDGE_PORT:-8202}"
export ALLINAGENT_TLS_CERT="${2:-${ALLINAGENT_TLS_CERT:-/etc/letsencrypt/live/${ALLINAGENT_DOMAIN}/fullchain.pem}}"
export ALLINAGENT_TLS_KEY="${3:-${ALLINAGENT_TLS_KEY:-/etc/letsencrypt/live/${ALLINAGENT_DOMAIN}/privkey.pem}}"

AVAIL_PATH="/etc/nginx/sites-available/allinagent.conf"
ENABLED_PATH="/etc/nginx/sites-enabled/allinagent.conf"
TMP_PATH="$(mktemp /tmp/nginx-allinagent.XXXXXX.conf)"

envsubst '${ALLINAGENT_DOMAIN} ${ALLINAGENT_OFFICE_PORT} ${ALLINAGENT_BRIDGE_PORT} ${ALLINAGENT_TLS_CERT} ${ALLINAGENT_TLS_KEY}' \
  < "${SCRIPT_DIR}/nginx-allinagent.conf.template" > "${TMP_PATH}"

BACKUP_PATH=""
if [ -f "${AVAIL_PATH}" ]; then
  BACKUP_PATH="${AVAIL_PATH}.bak.$(date +%s)"
  cp -a "${AVAIL_PATH}" "${BACKUP_PATH}"
fi

install -m 0644 "${TMP_PATH}" "${AVAIL_PATH}"
rm -f "${TMP_PATH}"
ln -sfn "${AVAIL_PATH}" "${ENABLED_PATH}"

if ! nginx -t; then
  echo "[install-nginx] nginx -t failed; rolling back vhost change..." >&2
  rm -f "${ENABLED_PATH}"
  if [ -n "${BACKUP_PATH}" ] && [ -f "${BACKUP_PATH}" ]; then
    mv "${BACKUP_PATH}" "${AVAIL_PATH}"
    ln -sfn "${AVAIL_PATH}" "${ENABLED_PATH}"
  else
    rm -f "${AVAIL_PATH}"
  fi
  exit 1
fi

rm -f "${BACKUP_PATH}" 2>/dev/null || true
systemctl reload nginx
echo "[install-nginx] Enabled https://${ALLINAGENT_DOMAIN}/office -> 127.0.0.1:${ALLINAGENT_OFFICE_PORT}"
