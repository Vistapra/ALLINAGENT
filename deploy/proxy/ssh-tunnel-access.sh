#!/usr/bin/env bash
# ==============================================================================
# ALLINAGENT — Zero-Domain Encrypted SSH Loopback Tunnel (`ssh-tunnel-access.sh`)
# Forwards remote loopback ports (8200, 8201, 8202) exclusively to local 127.0.0.1.
# ==============================================================================
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <ssh_user@server_host> [ssh_port]" >&2
  echo "Example: $0 ubuntu@203.0.113.10 22" >&2
  exit 1
fi

REMOTE_TARGET="$1"
SSH_PORT="${2:-22}"
LOCAL_OFFICE_PORT="${ALLINAGENT_LOCAL_OFFICE_PORT:-8200}"
LOCAL_PAPERCLIP_PORT="${ALLINAGENT_LOCAL_PAPERCLIP_PORT:-8201}"
LOCAL_BRIDGE_PORT="${ALLINAGENT_LOCAL_BRIDGE_PORT:-8202}"
REMOTE_OFFICE_PORT="${ALLINAGENT_OFFICE_PORT:-8200}"
REMOTE_PAPERCLIP_PORT="${ALLINAGENT_PAPERCLIP_PORT:-8201}"
REMOTE_BRIDGE_PORT="${ALLINAGENT_BRIDGE_PORT:-8202}"

echo "======================================================================"
echo " ALLINAGENT Secure SSH Loopback Tunnel"
echo "   Remote Host         : ${REMOTE_TARGET} (port ${SSH_PORT})"
echo "   3D & 2D Office URL  : http://127.0.0.1:${LOCAL_OFFICE_PORT}/office"
echo "   Paperclip API       : http://127.0.0.1:${LOCAL_PAPERCLIP_PORT}/api/health"
echo "   Office Bridge       : http://127.0.0.1:${LOCAL_BRIDGE_PORT}/health"
echo " Press Ctrl+C to close tunnel."
echo "======================================================================"

exec ssh -N \
  -p "${SSH_PORT}" \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -L "127.0.0.1:${LOCAL_OFFICE_PORT}:127.0.0.1:${REMOTE_OFFICE_PORT}" \
  -L "127.0.0.1:${LOCAL_PAPERCLIP_PORT}:127.0.0.1:${REMOTE_PAPERCLIP_PORT}" \
  -L "127.0.0.1:${LOCAL_BRIDGE_PORT}:127.0.0.1:${REMOTE_BRIDGE_PORT}" \
  "${REMOTE_TARGET}"
