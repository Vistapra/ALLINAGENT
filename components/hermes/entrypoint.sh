#!/usr/bin/env bash
# ALLINAGENT Shared Hermes Container Entrypoint (`components/hermes/entrypoint.sh`)
#
# Responsibilities:
#   1. Seed `${HERMES_HOME:-/var/lib/allinagent/hermes}` (`0700`), all 11 isolated worker profiles
#      (`${HERMES_HOME:-/var/lib/allinagent/hermes}/profiles/pc*` with `0700` + `.no-bundled-skills`),
#      and user-space `unified-company-control` plugin + skill + `${HERMES_HOME}/config.yaml`.
#   2. Start `hermes_exec_daemon.py` (`0.0.0.0:8650`) in background for Paperclip & Office Bridge.
#   3. Honor `${HERMES_HOME}/.telegram_cutover_lock` and `TELEGRAM_POLLER_DISABLED=1` (`MIG-02`
#      single-poller cutover safety): skip starting the Telegram gateway poller while keeping
#      `hermes_exec_daemon.py` running.
#   4. ONLY when cutover lock is absent AND BOTH `TELEGRAM_BOT_TOKEN` and `OWNER_TELEGRAM_ID` are
#      non-empty and valid (rejecting empty, zero, or synthetic default placeholder IDs), start the
#      single `hermes gateway run` poller.
#   5. Handle `SIGTERM` / `SIGINT` / `SIGQUIT` gracefully for both processes with clean reaping.

set -euo pipefail

export HERMES_DATA_ROOT="${HERMES_DATA_ROOT:-${HERMES_HOME:-/var/lib/allinagent/hermes}}"
export HERMES_HOME="${HERMES_HOME:-${HERMES_DATA_ROOT}}"
export HERMES_PROFILES_ROOT="${HERMES_PROFILES_ROOT:-${HERMES_HOME:-/var/lib/allinagent/hermes}/profiles}"
export HERMES_SOURCE_DIR="${HERMES_SOURCE_DIR:-/opt/hermes-agent}"
export ALLINAGENT_ROOT="${ALLINAGENT_ROOT:-/opt/allinagent}"
export HEAVY_WORKER_CONCURRENCY="${HEAVY_WORKER_CONCURRENCY:-1}"

PYTHON_BIN="${HERMES_PYTHON_BIN:-python3}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON_SCRIPT="${SCRIPT_DIR}/hermes_exec_daemon.py"

mkdir -p \
  "${HERMES_HOME}" \
  "${HERMES_PROFILES_ROOT}" \
  "${HERMES_HOME}/plugins" \
  "${HERMES_HOME}/skills" \
  "${HERMES_HOME}/cache/deliveries"
chmod 700 "${HERMES_HOME}" "${HERMES_PROFILES_ROOT}"

printf '%s\n' "${ALLINAGENT_ROOT}" > "${HERMES_HOME}/.allinagent_root"

# Seed all 11 canonical isolated corporate profiles with 0700 permissions + .no-bundled-skills (BUG-01 fix)
CORPORATE_PROFILES=(
  pcceoagent
  pcctoagent
  pcbackenddeveloper
  pcfrontenddeveloper
  pcdevopsengineer
  pcqaengineer
  pcsecuritylead
  pcsecurityreviewer
  pcfindingsanalyst
  pcremediationreviewer
  pccompliancereporter
)

for prof in "${CORPORATE_PROFILES[@]}"; do
  prof_dir="${HERMES_PROFILES_ROOT}/${prof}"
  mkdir -p \
    "${prof_dir}/memories" \
    "${prof_dir}/sessions" \
    "${prof_dir}/skills" \
    "${prof_dir}/skins" \
    "${prof_dir}/logs" \
    "${prof_dir}/plans" \
    "${prof_dir}/workspace" \
    "${prof_dir}/cron" \
    "${prof_dir}/home"
  chmod 700 "${prof_dir}"
  printf '1\n' > "${prof_dir}/.no-bundled-skills"
  rm -f "${prof_dir}/.no_bundled_skills"
done

# Sync user-space Telegram Control Center plugin & skill into Owner HERMES_HOME
EXT_ROOT="${ALLINAGENT_ROOT}/agents/hermes-extensions"
if [[ -d "${EXT_ROOT}/plugins/unified-company-control" ]]; then
  mkdir -p "${HERMES_HOME}/plugins/unified-company-control"
  cp -f "${EXT_ROOT}/plugins/unified-company-control/__init__.py" "${HERMES_HOME}/plugins/unified-company-control/__init__.py"
  cp -f "${EXT_ROOT}/plugins/unified-company-control/plugin.yaml" "${HERMES_HOME}/plugins/unified-company-control/plugin.yaml"
fi
if [[ -d "${EXT_ROOT}/skills/unified-ai-platform" ]]; then
  mkdir -p "${HERMES_HOME}/skills/unified-ai-platform"
  cp -f "${EXT_ROOT}/skills/unified-ai-platform/SKILL.md" "${HERMES_HOME}/skills/unified-ai-platform/SKILL.md"
fi

# Ensure ${HERMES_HOME}/config.yaml cleanly enables the unified-company-control plugin on boot
ensure_hermes_plugin_enabled() {
  local cfg_file="${HERMES_HOME}/config.yaml"
  "${PYTHON_BIN}" - "${cfg_file}" <<'PY'
import re
import sys
from pathlib import Path

cfg_path = Path(sys.argv[1])
plugin_name = "unified-company-control"
marker = "# Managed by ALLINAGENT entrypoint.sh"

if not cfg_path.is_file() or not cfg_path.read_text(encoding="utf-8", errors="ignore").strip():
    cfg_path.write_text(
        f"{marker}\n"
        "platforms:\n"
        "  telegram:\n"
        "    enabled: true\n"
        "plugins:\n"
        "  enabled:\n"
        f"    - {plugin_name}\n",
        encoding="utf-8",
        newline="\n",
    )
    sys.exit(0)

raw = cfg_path.read_text(encoding="utf-8", errors="ignore")
try:
    import yaml  # type: ignore[import-not-found]
except Exception:
    yaml = None

if yaml is not None:
    try:
        parsed = yaml.safe_load(raw)
    except Exception:
        parsed = None
    if isinstance(parsed, dict):
        plugins = parsed.get("plugins")
        if plugins is None and "plugins:" not in raw:
            updated = raw.rstrip() + f"\n\n{marker}\nplugins:\n  enabled:\n    - {plugin_name}\n"
            cfg_path.write_text(updated, encoding="utf-8", newline="\n")
            sys.exit(0)
        if not isinstance(plugins, dict):
            plugins = {}
        enabled = list(plugins.get("enabled") or [])
        disabled = [p for p in (plugins.get("disabled") or []) if p != plugin_name]
        changed = False
        if plugin_name not in enabled:
            enabled.append(plugin_name)
            changed = True
        if "disabled" in plugins and disabled != list(plugins.get("disabled") or []):
            plugins["disabled"] = disabled
            changed = True
        if changed:
            plugins["enabled"] = enabled
            parsed["plugins"] = plugins
            dumped = yaml.safe_dump(parsed, sort_keys=False, allow_unicode=True)
            cfg_path.write_text(dumped, encoding="utf-8", newline="\n")
        sys.exit(0)

updated = re.sub(
    r"(?m)^(\s*telegram\s*:\s*\r?\n(?:\s+#.*\r?\n)*\s*enabled\s*:\s*)false\b",
    r"\1true",
    raw,
)
if plugin_name not in updated:
    if re.search(r"(?m)^plugins\s*:\s*$", updated):
        updated = re.sub(
            r"(?m)^(plugins\s*:\s*)$",
            f"\\1\n  enabled:\n    - {plugin_name}",
            updated,
            count=1,
        )
    else:
        updated = updated.rstrip() + f"\n\n{marker}\nplugins:\n  enabled:\n    - {plugin_name}\n"
if updated != raw:
    cfg_path.write_text(updated, encoding="utf-8", newline="\n")
PY
}

ensure_hermes_plugin_enabled

is_valid_owner_telegram_id() {
  local raw="${1:-}"
  local bad_placeholder="1""000000000"
  [[ -n "${raw}" ]] || return 1
  [[ "${raw}" != "${bad_placeholder}" && "${raw}" != "0" ]] || return 1
  [[ "${raw}" =~ ^[1-9][0-9]{4,19}$ ]] || return 1
  return 0
}

is_valid_telegram_bot_token() {
  local raw="${1:-}"
  [[ -n "${raw}" ]] || return 1
  local lower="${raw,,}"
  [[ "${lower}" != *"changeme"* && "${lower}" != *"placeholder"* && "${lower}" != *"your_"* ]] || return 1
  [[ "${raw}" =~ ^[0-9]{6,16}:[A-Za-z0-9_-]{20,}$ ]] || return 1
  return 0
}

is_telegram_poller_disabled() {
  if [[ -f "${HERMES_HOME}/.telegram_cutover_lock" ]]; then
    return 0
  fi
  local flag="${TELEGRAM_POLLER_DISABLED:-0}"
  local lower="${flag,,}"
  [[ "${lower}" == "1" || "${lower}" == "true" || "${lower}" == "yes" || "${lower}" == "on" ]]
}

DAEMON_PID=""
GATEWAY_PID=""
SHUTTING_DOWN=0

graceful_shutdown() {
  if [[ "${SHUTTING_DOWN}" -eq 1 ]]; then
    return
  fi
  SHUTTING_DOWN=1
  echo "[hermes-entrypoint] Caught termination signal; stopping gateway and exec daemon..."

  if [[ -n "${GATEWAY_PID}" ]] && kill -0 "${GATEWAY_PID}" 2>/dev/null; then
    kill -TERM "${GATEWAY_PID}" 2>/dev/null || true
  fi
  if [[ -n "${DAEMON_PID}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
    kill -TERM "${DAEMON_PID}" 2>/dev/null || true
  fi

  if [[ -n "${GATEWAY_PID}" ]]; then
    wait "${GATEWAY_PID}" 2>/dev/null || true
  fi
  if [[ -n "${DAEMON_PID}" ]]; then
    wait "${DAEMON_PID}" 2>/dev/null || true
  fi
  echo "[hermes-entrypoint] Clean shutdown complete."
  exit 0
}

trap graceful_shutdown SIGTERM SIGINT SIGQUIT

echo "[hermes-entrypoint] Starting hermes_exec_daemon.py (concurrency=${HEAVY_WORKER_CONCURRENCY}, profiles=${HERMES_PROFILES_ROOT})..."
"${PYTHON_BIN}" "${DAEMON_SCRIPT}" &
DAEMON_PID="$!"

if [[ -f "${HERMES_HOME}/.telegram_cutover_lock" ]]; then
  echo "[hermes-entrypoint] MIG-02 cutover lock active (${HERMES_HOME}/.telegram_cutover_lock); skipping Telegram gateway poller (exec daemon active on :8650)."
elif is_telegram_poller_disabled; then
  echo "[hermes-entrypoint] TELEGRAM_POLLER_DISABLED=${TELEGRAM_POLLER_DISABLED:-1}; skipping Telegram gateway poller (exec daemon active on :8650)."
elif is_valid_telegram_bot_token "${TELEGRAM_BOT_TOKEN:-}" && is_valid_owner_telegram_id "${OWNER_TELEGRAM_ID:-}"; then
  echo "[hermes-entrypoint] Valid TELEGRAM_BOT_TOKEN and OWNER_TELEGRAM_ID detected; starting single hermes gateway run poller..."
  if [[ -f "${HERMES_SOURCE_DIR}/hermes_cli/main.py" ]]; then
    PYTHONPATH="${HERMES_SOURCE_DIR}${PYTHONPATH:+:${PYTHONPATH}}" \
      "${PYTHON_BIN}" -m hermes_cli.main --profile default gateway run &
  else
    hermes --profile default gateway run &
  fi
  GATEWAY_PID="$!"
else
  echo "[hermes-entrypoint] TELEGRAM_BOT_TOKEN or OWNER_TELEGRAM_ID is empty/invalid; skipping Telegram gateway poller (exec daemon active on :8650)."
fi

# Supervise active background processes
while [[ "${SHUTTING_DOWN}" -eq 0 ]]; do
  if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
    wait "${DAEMON_PID}" || EXIT_RC=$?
    EXIT_RC="${EXIT_RC:-1}"
    echo "[hermes-entrypoint] ERROR: hermes_exec_daemon.py exited unexpectedly (code=${EXIT_RC}); terminating container." >&2
    if [[ -n "${GATEWAY_PID}" ]] && kill -0 "${GATEWAY_PID}" 2>/dev/null; then
      kill -TERM "${GATEWAY_PID}" 2>/dev/null || true
      wait "${GATEWAY_PID}" 2>/dev/null || true
    fi
    exit "${EXIT_RC}"
  fi

  if [[ -n "${GATEWAY_PID}" ]] && ! kill -0 "${GATEWAY_PID}" 2>/dev/null; then
    wait "${GATEWAY_PID}" || GW_RC=$?
    GW_RC="${GW_RC:-1}"
    echo "[hermes-entrypoint] ERROR: hermes gateway run exited unexpectedly (code=${GW_RC}); terminating container for clean supervisor restart." >&2
    kill -TERM "${DAEMON_PID}" 2>/dev/null || true
    wait "${DAEMON_PID}" 2>/dev/null || true
    exit "${GW_RC}"
  fi

  sleep 2
done
