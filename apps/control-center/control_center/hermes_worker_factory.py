#!/usr/bin/env python3
"""Cross-platform isolated Hermes named profile provisioner for Paperclip worker roles.

Key guarantees:
- Writes `.no-bundled-skills` (HYPHENS — fixing BUG-01) so Hermes never copies 60+ bundled
  hub skills into isolated worker profiles.
- Branches cleanly between Windows (`icacls.exe`) and POSIX (`os.chmod(..., 0o700)` / `0o600`).
- Explicitly strips `TELEGRAM_BOT_TOKEN` (and gateway/messaging bot credentials) from worker
  profile `.env` files so worker processes can never hijack or conflict with the single
  Telegram Gateway poller.
- Generates 100% OS-neutral `config.yaml`, `SOUL.md`, and `AGENTS.md` using dynamic LLM
  provider/model settings.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from control_center.paths import (
    ALLINAGENT_ROOT,
    DEFAULT_LLM_MODEL,
    HERMES_EXE,
    HERMES_HOME_ROOT,
    IS_WINDOWS,
    LLM_BASE_URL,
    LLM_PROVIDER,
    PAPERCLIP_API_URL,
    PROFILES_ROOT,
    SECRETS_DIR,
    WORKERS_DIR,
)

SECRET_WORKER_ENV: Path = SECRETS_DIR / "worker-llm.env"

STRIPPED_WORKER_ENV_PREFIXES = (
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_",
    "DISCORD_",
    "SLACK_",
    "WHATSAPP_",
    "SIGNAL_",
    "HERMES_GATEWAY_",
)

PASSTHROUGH_WORKER_LLM_ENV_KEYS = (
    "CUSTOM_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "LLM_BASE_URL",
    "DEFAULT_LLM_MODEL",
    "LLM_MODEL",
)


def to_profile_id(role_slug: str) -> str:
    clean = re.sub(r"[^a-z0-9]", "", role_slug.lower())
    if not clean.startswith("pc"):
        clean = "pc" + clean
    return clean[:24]


_to_profile_id = to_profile_id  # Backward-compatible alias


def _resolve_windows_current_sid() -> str | None:
    """Resolve current Windows user SID cleanly via `whoami /user /fo csv /nh`."""
    try:
        proc = subprocess.run(
            ["whoami.exe", "/user", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            rows = list(csv.reader(io.StringIO(proc.stdout.strip())))
            if rows and len(rows[0]) >= 2 and rows[0][1].startswith("S-1-"):
                return rows[0][1].strip()
    except OSError:
        pass
    return None


def lock_worker_profile_permissions(hermes_home: Path, env_dst: Path | None = None) -> str:
    """Apply OS-appropriate private directory (`0700`) and `.env` (`0600`) ACLs."""
    if IS_WINDOWS:
        sid = _resolve_windows_current_sid()
        if sid:
            subprocess.run(
                [
                    "icacls.exe",
                    str(hermes_home),
                    "/inheritance:r",
                    "/grant:r",
                    f"*{sid}:(OI)(CI)F",
                    "*S-1-5-18:(OI)(CI)F",
                    "*S-1-5-32-544:(OI)(CI)F",
                ],
                capture_output=True,
                timeout=15,
                check=False,
            )
            return "windows_icacls"
        return "windows_default"

    os.chmod(hermes_home, 0o700)
    if env_dst is not None and env_dst.exists():
        os.chmod(env_dst, 0o600)
    return "posix_chmod_0700_0600"


def filter_worker_env_lines(lines: list[str]) -> list[str]:
    """Strip `TELEGRAM_BOT_TOKEN` and gateway/chat bot tokens from worker `.env` lines."""
    cleaned: list[str] = []
    for raw_ln in lines:
        stripped = raw_ln.strip()
        if not stripped or stripped.startswith("#"):
            cleaned.append(raw_ln)
            continue
        if "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip().upper()
        if any(key == p or key.startswith(p) for p in STRIPPED_WORKER_ENV_PREFIXES):
            continue
        cleaned.append(stripped)
    return cleaned


def _write_sanitized_worker_env(env_dst: Path, secret_worker_env: Path = SECRET_WORKER_ENV) -> None:
    existing_pc_key = ""
    if env_dst.is_file():
        for line in env_dst.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.strip().startswith("PAPERCLIP_API_KEY="):
                existing_pc_key = line.strip()
                break

    source_lines: list[str] = []
    if secret_worker_env.is_file():
        source_lines = secret_worker_env.read_text(encoding="utf-8", errors="ignore").splitlines()
    else:
        for env_k in PASSTHROUGH_WORKER_LLM_ENV_KEYS:
            val = os.environ.get(env_k, "").strip()
            if val:
                source_lines.append(f"{env_k}={val}")

    filtered = [ln for ln in filter_worker_env_lines(source_lines) if not ln.strip().startswith("PAPERCLIP_API_KEY=")]
    if existing_pc_key:
        filtered.append(existing_pc_key)

    env_dst.write_text(("\n".join(filtered).strip() + "\n") if filtered else "", encoding="utf-8")
    if not IS_WINDOWS:
        os.chmod(env_dst, 0o600)


def _find_paperclip_task_bridge_skill() -> Path | None:
    explicit = os.environ.get("PAPERCLIP_TASK_BRIDGE_DIR", "").strip()
    candidates = [
        Path(explicit) if explicit else None,
        ALLINAGENT_ROOT / "skills" / "bundled" / "paperclip-task-bridge",
        ALLINAGENT_ROOT / "agents" / "hermes-extensions" / "skills" / "paperclip-task-bridge",
        ALLINAGENT_ROOT / "paperclip" / "packages" / "adapters" / "hermes" / "skills" / "paperclip-task-bridge",
    ]
    for cand in candidates:
        if cand and cand.is_dir() and (cand / "SKILL.md").is_file():
            return cand
    return None


def provision_worker_home(
    role_slug: str,
    *,
    role_title: str,
    authorized_workspace: str | Path,
    allowed_toolsets: list[str],
    extra_soul_rules: str = "",
    profiles_root: Path | None = None,
    workers_root: Path | None = None,
    company_name: str = "Unified AI Engineering & Operations",
) -> dict[str, str]:
    profile_id = to_profile_id(role_slug)
    prof_root = (profiles_root or PROFILES_ROOT).resolve()
    wrk_root = (workers_root or WORKERS_DIR).resolve()
    hermes_home = prof_root / profile_id
    role_meta_dir = wrk_root / role_slug

    for sub in ("memories", "sessions", "skills", "plugins", "logs", "plans", "workspace", "cron", "home"):
        (hermes_home / sub).mkdir(parents=True, exist_ok=True)
    role_meta_dir.mkdir(parents=True, exist_ok=True)

    # Preserve custom plugins installed in `<hermes_home>/plugins/` or already enabled in `config.yaml`.
    existing_enabled_plugins: list[str] = []
    existing_disabled_plugins: list[str] = []
    cfg_path = hermes_home / "config.yaml"
    if cfg_path.is_file():
        try:
            import yaml  # type: ignore[import-not-found]
            parsed_cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8", errors="ignore")) or {}
            if isinstance(parsed_cfg, dict) and isinstance(parsed_cfg.get("plugins"), dict):
                existing_enabled_plugins = [str(x) for x in (parsed_cfg["plugins"].get("enabled") or []) if str(x).strip()]
                existing_disabled_plugins = [str(x) for x in (parsed_cfg["plugins"].get("disabled") or []) if str(x).strip()]
        except Exception:
            pass
    plugins_dir = hermes_home / "plugins"
    if plugins_dir.is_dir():
        for entry in sorted(plugins_dir.iterdir()):
            if entry.is_dir() and ((entry / "plugin.yaml").is_file() or (entry / "__init__.py").is_file()):
                if entry.name not in existing_enabled_plugins:
                    existing_enabled_plugins.append(entry.name)

    # BUG-01 FIX: Hermes checks `.no-bundled-skills` (HYPHENS), not `.no_bundled_skills`.
    (hermes_home / ".no_bundled_skills").unlink(missing_ok=True)
    (hermes_home / ".no-bundled-skills").write_text("1\n", encoding="utf-8")

    env_dst = hermes_home / ".env"
    _write_sanitized_worker_env(env_dst)
    acl_mode = lock_worker_profile_permissions(hermes_home, env_dst)

    model_name = (os.environ.get("DEFAULT_LLM_MODEL") or os.environ.get("LLM_MODEL") or DEFAULT_LLM_MODEL).strip()
    base_url = (os.environ.get("LLM_BASE_URL") or LLM_BASE_URL).strip()
    provider_name = (os.environ.get("LLM_PROVIDER") or LLM_PROVIDER).strip()
    if provider_name == "auto":
        yaml_provider = "custom" if base_url and "api.openai.com" not in base_url else "openai"
    else:
        yaml_provider = provider_name

    ws_norm = Path(authorized_workspace).as_posix()
    config_yaml = f"""model:
  default: {model_name}
  provider: {yaml_provider}
  base_url: {base_url}
openrouter_base_url: {base_url}
providers:
  custom:
    base_url: {base_url}
    key_env: CUSTOM_API_KEY
_config_version: 54
updates:
  pre_update_backup: "off"
curator:
  backup:
    enabled: false
skills:
  ledger: false
terminal:
  backend: local
  home_mode: real
  persistent_shell: false
  timeout: 180
  client_env_passthrough:
    - PAPERCLIP_API_URL
    - PAPERCLIP_RUN_ID
    - PAPERCLIP_TASK_ID
    - PAPERCLIP_AGENT_ID
    - PAPERCLIP_COMPANY_ID
    - PAPERCLIP_WAKE_REASON
    - PAPERCLIP_WAKE_COMMENT_ID
  env_passthrough:
    - PAPERCLIP_API_KEY
code_execution:
  mode: project
network:
  force_ipv4: true
computer_use:
  cua_telemetry: false
  autostart: false
  no_overlay: true
approvals:
  mode: smart
  timeout: 60
  cron_mode: deny
  single_query_mode: deny
  unattended_mode: deny
"""
    if existing_enabled_plugins or existing_disabled_plugins:
        plugins_lines = ["plugins:"]
        if existing_enabled_plugins:
            plugins_lines.append("  enabled:")
            for p_name in existing_enabled_plugins:
                plugins_lines.append(f"    - {p_name}")
        if existing_disabled_plugins:
            plugins_lines.append("  disabled:")
            for p_name in existing_disabled_plugins:
                plugins_lines.append(f"    - {p_name}")
        config_yaml = config_yaml + "\n".join(plugins_lines) + "\n"
    (hermes_home / "config.yaml").write_text(config_yaml, encoding="utf-8")

    py_cmd = "python" if IS_WINDOWS else "python3"
    soul_md = f"""# Role Identity: {role_title} (`{role_slug}` / profile `{profile_id}`)
- Organization: **{company_name}** (Paperclip-orchestrated).
- Authorized workspace boundary: `{ws_norm}`.
- Permitted toolsets: `{", ".join(allowed_toolsets)}`.
- Cross-platform Paperclip API helper (portable Python `urllib.request` snippet for updating assigned issues when `terminal` toolset is enabled):
  ```bash
  {py_cmd} -c "import json, os, urllib.request; api=os.environ.get('PAPERCLIP_API_URL','{PAPERCLIP_API_URL}').rstrip('/'); api=api if api.endswith('/api') else api+'/api'; tid=os.environ['PAPERCLIP_TASK_ID']; data=json.dumps({{'status':'done','comment':'Completed and verified.'}}).encode(); req=urllib.request.Request(api+'/issues/'+tid, data=data, method='PATCH', headers={{'Authorization':'Bearer '+os.environ['PAPERCLIP_API_KEY'],'X-Paperclip-Run-Id':os.environ.get('PAPERCLIP_RUN_ID',''),'Content-Type':'application/json'}}); urllib.request.urlopen(req, timeout=15).read()"
  ```
- Prohibited actions:
  1. Never read or modify the Gateway/Owner root profile (`{HERMES_HOME_ROOT.as_posix()}` root `.env`, `state.db`, `memories/`) or `{SECRETS_DIR.as_posix()}`.
  2. Never access or modify folders outside `{ws_norm}` unless explicitly listed in the assigned task scope.
  3. Never attempt privilege escalation (`sudo`, `su`, `doas`, or Windows UAC), alter host init/systemd/container/firewall settings, run offensive network scans, or self-escalate permissions.
  4. Never output or store API keys, tokens, `.env` contents, or passwords in comments, files, reports, or memory.
{extra_soul_rules}
""".strip() + "\n"

    (hermes_home / "SOUL.md").write_text(soul_md, encoding="utf-8")
    (role_meta_dir / "AGENTS.md").write_text(soul_md, encoding="utf-8")

    mem_file = hermes_home / "memories" / "MEMORY.md"
    if not mem_file.exists():
        mem_file.write_text(f"# Isolated Role Memory — {role_title}\n", encoding="utf-8")

    bridge_src = _find_paperclip_task_bridge_skill()
    if bridge_src is not None:
        bridge_dst = hermes_home / "skills" / "paperclip-task-bridge"
        if bridge_dst.exists():
            shutil.rmtree(bridge_dst)
        shutil.copytree(bridge_src, bridge_dst)

    manifest = {
        "role_slug": role_slug,
        "profile_id": profile_id,
        "role_title": role_title,
        "hermes_home": str(hermes_home),
        "instructions_file": str(role_meta_dir / "AGENTS.md"),
        "hermes_exe": HERMES_EXE,
        "authorized_workspace": str(Path(authorized_workspace)),
        "toolsets": ",".join(allowed_toolsets),
        "permissions_mode": acl_mode,
        "no_bundled_skills_marker": str(hermes_home / ".no-bundled-skills"),
    }
    (role_meta_dir / "role-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def bind_agent_paperclip_key(hermes_home: str | Path, pc: object, agent_id: str, role_slug: str) -> None:
    """Mint (once) and bind an agent-scoped Paperclip API key into the isolated profile `.env`."""
    home = Path(hermes_home)
    env_file = home / ".env"
    marker = home / ".paperclip_key_meta.json"
    txt = env_file.read_text(encoding="utf-8", errors="ignore") if env_file.exists() else ""
    if marker.exists() and "PAPERCLIP_API_KEY=" in txt:
        try:
            meta = json.loads(marker.read_text(encoding="utf-8"))
            if meta.get("agent_id") == agent_id:
                return
        except Exception:
            pass
    created = pc.create_agent_key(agent_id, {"name": f"{role_slug}-profile-key"})  # type: ignore[attr-defined]
    token = str(created.get("token") or "").strip()
    if not token:
        raise RuntimeError(f"Paperclip create_agent_key for {agent_id} did not return a token")
    lines = [
        ln for ln in filter_worker_env_lines(txt.splitlines())
        if not ln.strip().startswith("PAPERCLIP_API_KEY=")
    ]
    lines.append(f"PAPERCLIP_API_KEY={token}")
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    marker.write_text(
        json.dumps({"agent_id": agent_id, "key_id": created.get("id"), "role_slug": role_slug}, indent=2),
        encoding="utf-8",
    )
    if not IS_WINDOWS:
        os.chmod(env_file, 0o600)
        os.chmod(marker, 0o600)
