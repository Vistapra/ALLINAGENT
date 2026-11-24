#!/usr/bin/env python3
"""ALLINAGENT — Unified One-Command Installer, Operations & Safe Update CLI.

Zero third-party dependencies (Python 3.10+ standard library only).
Supports Linux (Ubuntu/Debian systemd + Docker Compose v2), macOS, and Windows.

Subcommands:
  setup    Preflight, .env wizard (--yes), CSPRNG 0600 secrets, pull/build, DB init,
           11-agent org provisioning, Sentry-gated skills, health gate & summary
  up       Create and start containers in background (auto-seeds missing .env secrets)
  down     Stop and remove containers (preserves bind-mounted persistent data)
  start    Start existing stopped containers
  stop     Gracefully stop running containers
  status   Show container runtime state, ports, and resource budget
  health   Probe all 6 internal/loopback service health endpoints
  logs     Stream or tail container logs
  doctor   Run deep SRE environment, security, port, and cgroup diagnostics
  update   Release-aware digest check, active-work deferral, DB backup & auto-rollback
  version  Print ALLINAGENT CLI & pinned component versions
"""
from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import getpass
import gzip
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CLI_VERSION = "1.0.0"
DEFAULT_GITHUB_REPO = "Vistapra/ALLINAGENT"
DEFAULT_IMAGE_NAMESPACE = "vistapra"
SERVICES_ALL = ("postgres", "vulnclaw", "hermes", "paperclip", "office-bridge", "office")
CUSTOM_IMAGE_SERVICES = ("vulnclaw", "hermes", "paperclip", "office-bridge", "office")

REQUIRED_AUTO_SECRETS = (
    "POSTGRES_PASSWORD",
    "ALLINAGENT_INTERNAL_TOKEN",
    "OFFICE_BRIDGE_TOKEN",
    "STUDIO_ACCESS_TOKEN",
    "BETTER_AUTH_SECRET",
    "PAPERCLIP_AGENT_JWT_SECRET",
    "PAPERCLIP_TOOL_ACTION_SIGNING_SECRET",
)

UPSTREAM_PINS = {
    "hermes_agent_commit": "eb49b8920a25ffa7bb2fadf548fe819221ca79d7",
    "paperclip_npm": "2026.1117.0",
    "vulnclaw_commit": "0b34878f84b089b21fcf85ecd445315f14df0672",
    "vulnclaw_tag": "v0.4.1",
    "postgres_image": "postgres:16-alpine",
}

REPO_ROOT = Path(os.environ.get("ALLINAGENT_ROOT") or Path(__file__).resolve().parents[1]).resolve()
COMPOSE_BASE = REPO_ROOT / "compose.yaml"
COMPOSE_PROD = REPO_ROOT / "compose.production.yaml"


# ------------------------------------------------------------------------------
# Utility & Cross-Platform System Helpers
# ------------------------------------------------------------------------------


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def mask_secret(val: str) -> str:
    if not val:
        return "<unset>"
    clean = val.strip()
    if len(clean) <= 10:
        return "****"
    digest = hashlib.sha256(clean.encode("utf-8")).hexdigest()[:8]
    return f"{clean[:4]}...{clean[-4:]} (sha256:{digest})"


def parse_dotenv(path: Path) -> dict[str, str]:
    env_map: dict[str, str] = {}
    if not path.is_file():
        return env_map
    raw = path.read_text(encoding="utf-8-sig")
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, val = stripped.split("=", 1)
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and ((val[0] == val[-1] == '"') or (val[0] == val[-1] == "'")):
            val = val[1:-1]
        if key:
            env_map[key] = val
    return env_map


def write_secure_file(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise
    if os.name != "nt":
        os.chmod(tmp_path, mode)
    tmp_path.replace(path)
    if os.name != "nt":
        os.chmod(path, mode)


def detect_memory_mib() -> dict[str, float]:
    sys_name = platform.system()
    if sys_name == "Linux" and Path("/proc/meminfo").is_file():
        info: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                info[parts[0].rstrip(":")] = int(parts[1])
        total_mib = info.get("MemTotal", 0) / 1024.0
        avail_mib = info.get("MemAvailable", info.get("MemFree", 0)) / 1024.0
        return {"total_mib": round(total_mib, 2), "available_mib": round(avail_mib, 2)}

    if sys_name == "Windows":
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        mem = MEMORYSTATUSEX()
        mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):  # type: ignore[attr-defined]
            return {
                "total_mib": round(mem.ullTotalPhys / (1024 * 1024), 2),
                "available_mib": round(mem.ullAvailPhys / (1024 * 1024), 2),
            }

    if sys_name == "Darwin":
        res = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, check=False)
        if res.returncode == 0 and res.stdout.strip().isdigit():
            total_mib = int(res.stdout.strip()) / (1024 * 1024)
            return {"total_mib": round(total_mib, 2), "available_mib": round(total_mib * 0.5, 2)}

    return {"total_mib": 8192.0, "available_mib": 4096.0}


def detect_timezone() -> str:
    env_tz = os.environ.get("TIMEZONE") or os.environ.get("TZ")
    if env_tz and env_tz.strip():
        return env_tz.strip()
    tz_file = Path("/etc/timezone")
    if tz_file.is_file():
        val = tz_file.read_text(encoding="utf-8").strip()
        if val:
            return val
    localtime = Path("/etc/localtime")
    if localtime.is_symlink():
        target = str(localtime.resolve())
        marker = "/zoneinfo/"
        if marker in target:
            return target.split(marker, 1)[1]
    return "UTC"


def is_tcp_port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.4)
        return sock.connect_ex((host, port)) != 0


def http_get_json(url: str, timeout: float = 5.0, headers: dict[str, str] | None = None) -> tuple[int, Any]:
    req = urllib.request.Request(url, headers=headers or {"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, {"raw": raw[:300]}
    except urllib.error.HTTPError as exc:
        return exc.code, {"error": f"HTTP {exc.code}"}
    except Exception as exc:
        return 0, {"error": str(exc)}


def resolve_effective_env(env_file: Path) -> dict[str, str]:
    merged = parse_dotenv(env_file)
    for k, v in os.environ.items():
        if v != "":
            merged[k] = v
    return merged


def resolve_port_from_env(env_map: dict[str, str], primary_key: str, legacy_key: str, default: int) -> int:
    raw = (env_map.get(primary_key) or env_map.get(legacy_key) or str(default)).strip()
    try:
        port = int(raw)
        return port if port > 0 else default
    except ValueError:
        return default


def resolve_data_dir(env_map: dict[str, str], override: str | None = None) -> Path:
    raw = override or env_map.get("ALLINAGENT_DATA_DIR")
    if raw:
        p = Path(raw)
        return p if p.is_absolute() else (REPO_ROOT / p).resolve()
    if os.name != "nt" and str(REPO_ROOT).startswith("/opt/allinagent"):
        return Path("/opt/allinagent/data")
    return (REPO_ROOT / "data").resolve()


def should_use_production_compose(
    args: argparse.Namespace,
    env_map: dict[str, str],
    *,
    auto_low_ram: bool = False,
) -> bool:
    if getattr(args, "local", False):
        return False
    if getattr(args, "production", False):
        return True
    profile = env_map.get("ALLINAGENT_PROFILE", "").strip().lower()
    if profile == "local":
        return False
    if profile == "production":
        return True
    if os.name != "nt" and str(REPO_ROOT).startswith("/opt/allinagent"):
        return True
    if auto_low_ram and detect_memory_mib()["total_mib"] <= 8500.0:
        return True
    return False


def build_compose_cmd(env_file: Path, production: bool, sub_args: list[str]) -> list[str]:
    cmd = ["docker", "compose", "--project-directory", str(REPO_ROOT)]
    if env_file.is_file():
        cmd.extend(["--env-file", str(env_file)])
    cmd.extend(["-f", str(COMPOSE_BASE)])
    if production and COMPOSE_PROD.is_file():
        cmd.extend(["-f", str(COMPOSE_PROD)])
    cmd.extend(sub_args)
    return cmd


def run_cmd(
    cmd: list[str],
    *,
    env: dict[str, str] | None = None,
    capture: bool = False,
    check: bool = True,
    cwd: Path = REPO_ROOT,
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=merged_env,
        text=True,
        capture_output=capture,
        check=check,
    )


# ------------------------------------------------------------------------------
# Preflight & System Diagnostics
# ------------------------------------------------------------------------------


def collect_preflight(env_file: Path, production: bool) -> dict[str, Any]:
    env_map = resolve_effective_env(env_file)
    mem = detect_memory_mib()
    disk = shutil.disk_usage(str(REPO_ROOT))
    disk_free_gib = round(disk.free / (1024**3), 2)
    disk_total_gib = round(disk.total / (1024**3), 2)
    cpus = os.cpu_count() or 1
    arch = platform.machine()
    sys_name = platform.system()

    docker_ok = False
    docker_version = ""
    compose_v2_ok = False
    compose_version = ""

    if shutil.which("docker"):
        d_info = run_cmd(["docker", "info", "--format", "{{.ServerVersion}}"], capture=True, check=False)
        if d_info.returncode == 0 and d_info.stdout.strip():
            docker_ok = True
            docker_version = d_info.stdout.strip()
        c_ver = run_cmd(["docker", "compose", "version", "--short"], capture=True, check=False)
        if c_ver.returncode == 0 and c_ver.stdout.strip():
            compose_v2_ok = True
            compose_version = c_ver.stdout.strip()

    office_port = resolve_port_from_env(env_map, "OFFICE_PORT", "ALLINAGENT_OFFICE_PORT", 8200)
    paperclip_port = resolve_port_from_env(env_map, "PAPERCLIP_PORT", "ALLINAGENT_PAPERCLIP_PORT", 8201)
    bridge_port = resolve_port_from_env(env_map, "OFFICE_BRIDGE_PORT", "ALLINAGENT_BRIDGE_PORT", 8202)

    ports_status = {
        "office": {"port": office_port, "free_on_loopback": is_tcp_port_free("127.0.0.1", office_port)},
        "paperclip": {"port": paperclip_port, "free_on_loopback": is_tcp_port_free("127.0.0.1", paperclip_port)},
        "office_bridge": {"port": bridge_port, "free_on_loopback": is_tcp_port_free("127.0.0.1", bridge_port)},
    }

    issues: list[str] = []
    warnings: list[str] = []

    if not docker_ok:
        issues.append("Docker Engine is not reachable (`docker info` failed).")
    if not compose_v2_ok:
        issues.append("Docker Compose v2 plugin (`docker compose`) is missing. Standalone v1 `docker-compose` is unsupported.")
    if cpus < 2:
        warnings.append(f"Detected {cpus} vCPU (< 2 vCPUs recommended).")
    if mem["total_mib"] < 3500:
        issues.append(f"Insufficient physical RAM ({mem['total_mib']} MiB < 3,500 MiB minimum).")
    elif production and mem["available_mib"] < 1600:
        warnings.append(f"Low currently available RAM ({mem['available_mib']} MiB); strict 1,536 MiB cgroup caps required.")
    if disk_free_gib < 6.0:
        issues.append(f"Insufficient free disk space ({disk_free_gib} GiB < 6.0 GiB minimum).")
    elif production and disk_free_gib < 24.0:
        warnings.append(f"Free disk ({disk_free_gib} GiB) is below the 24.0 GiB multi-tenant VPS safety floor.")

    return {
        "ok": len(issues) == 0,
        "timestamp": utc_now_iso(),
        "os": sys_name,
        "arch": arch,
        "cpus": cpus,
        "memory_mib": mem,
        "disk_gib": {"total": disk_total_gib, "free": disk_free_gib},
        "docker": {"ok": docker_ok, "server_version": docker_version},
        "compose_v2": {"ok": compose_v2_ok, "version": compose_version},
        "production_profile": production,
        "ports": ports_status,
        "issues": issues,
        "warnings": warnings,
    }


# ------------------------------------------------------------------------------
# Secrets, Directories & First-Run `.env` Provisioning
# ------------------------------------------------------------------------------


def chown_if_root(path: Path, uid: int, gid: int, mode: int | None = None) -> None:
    if os.name == "nt":
        return
    if mode is not None:
        os.chmod(path, mode)
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid) and geteuid() == 0:
        os.chown(path, uid, gid)


def scaffold_data_directories(data_dir: Path, workspaces_dir: Path) -> None:
    layout = [
        (data_dir, 0, 0, 0o755),
        (data_dir / "postgres", 70, 70, 0o700),
        (data_dir / "paperclip", 1000, 1000, 0o750),
        (data_dir / "hermes", 10001, 10001, 0o750),
        (data_dir / "hermes" / "profiles", 10001, 10001, 0o750),
        (data_dir / "reports", 10001, 1000, 0o775),
        (data_dir / "office-data", 1000, 1000, 0o750),
        (data_dir / "studio-state" / "hermes3d", 1000, 1000, 0o750),
        (data_dir / "vulnclaw", 10002, 10002, 0o750),
        (data_dir / "secrets", 0, 0, 0o755),
        (data_dir / "office-secrets", 1000, 1000, 0o750),
        (data_dir / "maintenance", 0, 0, 0o750),
        (data_dir / "backups", 0, 0, 0o700),
        (data_dir / "logs", 1000, 1000, 0o750),
        (workspaces_dir, 10001, 1000, 0o775),
    ]
    for folder, uid, gid, mode in layout:
        folder.mkdir(parents=True, exist_ok=True)
        chown_if_root(folder, uid, gid, mode)


def prompt_value(label: str, default: str, non_interactive: bool, secret: bool = False) -> str:
    if non_interactive or not sys.stdin.isatty():
        return default
    if secret:
        hint = mask_secret(default) if default else "<YOUR_PROVIDER_API_KEY>"
        entered = getpass.getpass(f"  {label} [{hint}]: ").strip()
        return entered if entered else default
    entered = input(f"  {label} [{default}]: ").strip()
    return entered if entered else default


def is_valid_secret_value(val: str) -> bool:
    clean = val.strip()
    if len(clean) < 24:
        return False
    lower = clean.lower()
    if "replace" in lower or "changeme" in lower or "placeholder" in lower or clean.startswith("<"):
        return False
    return True


def has_all_required_secrets(env_file: Path) -> bool:
    if not env_file.is_file():
        return False
    env_map = resolve_effective_env(env_file)
    return all(is_valid_secret_value(env_map.get(k, "")) for k in REQUIRED_AUTO_SECRETS)


def provision_env_and_secrets(
    env_file: Path,
    *,
    non_interactive: bool,
    production: bool,
    rotate_secrets: bool = False,
    data_dir_override: str | None = None,
) -> dict[str, Any]:
    existing = parse_dotenv(env_file)
    example = parse_dotenv(REPO_ROOT / ".env.example")

    def cur(key: str, fallback: str = "") -> str:
        val = os.environ.get(key) or existing.get(key) or example.get(key) or fallback
        return val.strip()

    default_profile = "production" if production else "local"
    default_data_dir = str(resolve_data_dir(existing, data_dir_override))
    default_workspaces = cur("ALLINAGENT_WORKSPACES_DIR", str(Path(default_data_dir) / "workspaces"))

    if not non_interactive and sys.stdin.isatty():
        print("\n[ALLINAGENT Wizard] Configure core deployment parameters (press Enter for defaults):")

    llm_base_url = prompt_value("LLM Base URL (OpenAI-compatible)", cur("LLM_BASE_URL", "https://api.openai.com/v1"), non_interactive)
    llm_model = prompt_value("Default LLM Model", cur("LLM_MODEL", "gpt-4o-mini"), non_interactive)

    raw_api_key = cur("CUSTOM_API_KEY", "")
    denylisted_api_placeholders = {
        "<YOUR_PROVIDER_API_KEY>",
        "sk-" + "placeholder",
        "sk-" + "replace-with-your-api-key",
    }
    if raw_api_key in denylisted_api_placeholders:
        raw_api_key = ""
    custom_api_key = prompt_value(
        "LLM Provider API Key (<YOUR_PROVIDER_API_KEY>, masked)",
        raw_api_key,
        non_interactive,
        secret=True,
    )

    telegram_token = prompt_value("Telegram Bot Token (optional, masked)", cur("TELEGRAM_BOT_TOKEN", ""), non_interactive, secret=True)

    raw_owner_tg = cur("OWNER_TELEGRAM_ID", "")
    dummy_tg_id = "1" + ("0" * 9)
    if raw_owner_tg == dummy_tg_id or raw_owner_tg.startswith("<"):
        raw_owner_tg = ""
    owner_tg_id = prompt_value("Owner Telegram Numeric ID (optional)", raw_owner_tg, non_interactive)

    tg_username = prompt_value("Telegram Bot Username (optional)", cur("TELEGRAM_BOT_USERNAME", ""), non_interactive)
    timezone_str = prompt_value("Maintenance Timezone (IANA)", cur("TIMEZONE", detect_timezone()), non_interactive)

    office_port = prompt_value("Loopback Web Office Port", cur("OFFICE_PORT", cur("ALLINAGENT_OFFICE_PORT", "8200")), non_interactive)
    paperclip_port = prompt_value("Loopback Paperclip API Port", cur("PAPERCLIP_PORT", cur("ALLINAGENT_PAPERCLIP_PORT", "8201")), non_interactive)
    bridge_port = prompt_value("Loopback Office Bridge Port", cur("OFFICE_BRIDGE_PORT", cur("ALLINAGENT_BRIDGE_PORT", "8202")), non_interactive)

    def ensure_secret(key: str, prefix: str = "", nbytes: int = 32, fallback_key: str = "") -> str:
        val = existing.get(key, "").strip()
        if not val and fallback_key:
            val = existing.get(fallback_key, "").strip()
        if not rotate_secrets and is_valid_secret_value(val):
            return val
        return f"{prefix}{secrets.token_hex(nbytes)}"

    pg_user = cur("POSTGRES_USER", "paperclip")
    pg_db = cur("POSTGRES_DB", "paperclip")
    pg_password = ensure_secret("POSTGRES_PASSWORD", nbytes=24)
    internal_token = ensure_secret(
        "ALLINAGENT_INTERNAL_TOKEN",
        prefix="ia_tok_",
        nbytes=32,
        fallback_key="HERMES_EXEC_SHARED_SECRET",
    )
    studio_token = ensure_secret("STUDIO_ACCESS_TOKEN", prefix="st_tok_", nbytes=24)
    bridge_token = ensure_secret("OFFICE_BRIDGE_TOKEN", prefix="ob_tok_", nbytes=32)
    better_auth = ensure_secret("BETTER_AUTH_SECRET", nbytes=32)
    agent_jwt = ensure_secret("PAPERCLIP_AGENT_JWT_SECRET", nbytes=32)
    action_sig = ensure_secret("PAPERCLIP_TOOL_ACTION_SIGNING_SECRET", nbytes=32)

    registry = cur("ALLINAGENT_REGISTRY", "ghcr.io")
    raw_namespace = cur("ALLINAGENT_IMAGE_NAMESPACE", DEFAULT_IMAGE_NAMESPACE)
    namespace = DEFAULT_IMAGE_NAMESPACE if raw_namespace in ("", "allinagent") else raw_namespace
    version_tag = cur("ALLINAGENT_VERSION", "latest")
    raw_repo = cur("ALLINAGENT_GITHUB_REPO", DEFAULT_GITHUB_REPO)
    gh_repo = DEFAULT_GITHUB_REPO if raw_repo in ("", "allinagent/allinagent") else raw_repo

    data_dir = Path(default_data_dir).resolve()
    workspaces_dir = Path(default_workspaces).resolve()
    scaffold_data_directories(data_dir, workspaces_dir)

    env_lines = [
        "# ==============================================================================",
        "# ALLINAGENT — Runtime Environment (.env)",
        "# Permissions: chmod 0600 (owner-only). Never commit this file to Git.",
        "# ==============================================================================",
        f"ALLINAGENT_PROFILE={default_profile}",
        f"ALLINAGENT_REGISTRY={registry}",
        f"ALLINAGENT_IMAGE_NAMESPACE={namespace}",
        f"ALLINAGENT_VERSION={version_tag}",
        f"ALLINAGENT_GITHUB_REPO={gh_repo}",
        f"ALLINAGENT_DATA_DIR={data_dir.as_posix() if os.name != 'nt' else str(data_dir)}",
        f"ALLINAGENT_WORKSPACES_DIR={workspaces_dir.as_posix() if os.name != 'nt' else str(workspaces_dir)}",
        f"TIMEZONE={timezone_str}",
        "",
        "# Loopback-Only Host Ports (127.0.0.1)",
        f"OFFICE_PORT={office_port}",
        f"PAPERCLIP_PORT={paperclip_port}",
        f"OFFICE_BRIDGE_PORT={bridge_port}",
        f"ALLINAGENT_OFFICE_PORT={office_port}",
        f"ALLINAGENT_PAPERCLIP_PORT={paperclip_port}",
        f"ALLINAGENT_BRIDGE_PORT={bridge_port}",
        "",
        "# LLM Provider Configuration",
        f"LLM_BASE_URL={llm_base_url}",
        f"LLM_MODEL={llm_model}",
        f"CUSTOM_API_KEY={custom_api_key}",
        "",
        "# Optional Telegram Control Center",
        f"TELEGRAM_BOT_TOKEN={telegram_token}",
        f"OWNER_TELEGRAM_ID={owner_tg_id}",
        f"TELEGRAM_BOT_USERNAME={tg_username}",
        "UNIFIED_COMPANY_GOVERNANCE=1",
        "HEAVY_WORKER_CONCURRENCY=1",
        "",
        "# CSPRNG Internal Platform Secrets",
        f"POSTGRES_USER={pg_user}",
        f"POSTGRES_DB={pg_db}",
        f"POSTGRES_PASSWORD={pg_password}",
        f"ALLINAGENT_INTERNAL_TOKEN={internal_token}",
        f"HERMES_EXEC_SHARED_SECRET={internal_token}",
        f"VULNCLAW_SCAN_TOKEN={internal_token}",
        f"STUDIO_ACCESS_TOKEN={studio_token}",
        f"OFFICE_BRIDGE_TOKEN={bridge_token}",
        f"BETTER_AUTH_SECRET={better_auth}",
        f"PAPERCLIP_AGENT_JWT_SECRET={agent_jwt}",
        f"PAPERCLIP_TOOL_ACTION_SIGNING_SECRET={action_sig}",
        "",
    ]
    write_secure_file(env_file, "\n".join(env_lines), mode=0o600)

    # Scoped secret files for non-root containers (zero secrets mounted into vulnclaw;
    # paperclip-auth.env is NEVER mounted into office!)
    secrets_dir = data_dir / "secrets"
    office_secrets_dir = data_dir / "office-secrets"
    ob_auth_path = secrets_dir / "office-bridge-auth.json"
    office_only_auth_path = office_secrets_dir / "office-bridge-auth.json"
    ob_auth_payload = {
        "createdAt": utc_now_iso(),
        "token": bridge_token,
        "bridgeToken": bridge_token,
        "studioAccessToken": studio_token,
        "allowedOwnerId": owner_tg_id,
    }
    serialized_ob_auth = json.dumps(ob_auth_payload, indent=2) + "\n"
    write_secure_file(ob_auth_path, serialized_ob_auth, mode=0o600)
    chown_if_root(ob_auth_path, 1000, 1000, 0o600)
    write_secure_file(office_only_auth_path, serialized_ob_auth, mode=0o600)
    chown_if_root(office_only_auth_path, 1000, 1000, 0o600)

    pc_auth_path = secrets_dir / "paperclip-auth.env"
    write_secure_file(
        pc_auth_path,
        "\n".join(
            [
                f"BETTER_AUTH_SECRET={better_auth}",
                f"PAPERCLIP_AGENT_JWT_SECRET={agent_jwt}",
                f"PAPERCLIP_TOOL_ACTION_SIGNING_SECRET={action_sig}",
                "",
            ]
        ),
        mode=0o600,
    )
    chown_if_root(pc_auth_path, 1000, 1000, 0o600)

    worker_llm_path = secrets_dir / "worker-llm.env"
    write_secure_file(
        worker_llm_path,
        "\n".join(
            [
                f"OPENAI_BASE_URL={llm_base_url}",
                f"LLM_MODEL={llm_model}",
                f"CUSTOM_API_KEY={custom_api_key}",
                f"OPENAI_API_KEY={custom_api_key}",
                "",
            ]
        ),
        mode=0o600,
    )
    chown_if_root(worker_llm_path, 10001, 10001, 0o600)

    # Seed Studio settings inside studio-state
    studio_settings_path = data_dir / "studio-state" / "hermes3d" / "settings.json"
    studio_settings = {
        "version": 1,
        "gateway": {
            "url": "ws://office-bridge:3210/ws",
            "token": bridge_token,
            "adapterType": "hermes",
            "profiles": {
                "hermes": {
                    "url": "ws://office-bridge:3210/ws",
                    "token": bridge_token,
                }
            },
        },
        "office": {"title": "ALLINAGENT AUTONOMOUS AI COMPANY"},
        "focused": {},
    }
    write_secure_file(studio_settings_path, json.dumps(studio_settings, indent=2) + "\n", mode=0o600)
    chown_if_root(studio_settings_path, 1000, 1000, 0o600)

    # Render defensive VulnClaw config (zero secrets)
    vc_tpl_path = REPO_ROOT / "config" / "vulnclaw.defensive.yaml"
    vc_dst_path = data_dir / "vulnclaw" / "config.yaml"
    if vc_tpl_path.is_file():
        rendered = (
            vc_tpl_path.read_text(encoding="utf-8")
            .replace("${LLM_MODEL}", llm_model)
            .replace("${LLM_BASE_URL}", llm_base_url)
        )
    else:
        rendered = (
            "# ALLINAGENT VulnClaw Defensive Policy\n"
            "mode: defensive_static_only\n"
            "allow_network_egress: false\n"
            "allow_exploitation: false\n"
        )
    write_secure_file(vc_dst_path, rendered, mode=0o640)
    chown_if_root(vc_dst_path, 10002, 10002, 0o640)

    return {
        "env_file": str(env_file),
        "data_dir": str(data_dir),
        "workspaces_dir": str(workspaces_dir),
        "office_port": int(office_port),
        "paperclip_port": int(paperclip_port),
        "bridge_port": int(bridge_port),
        "studio_token_path": str(ob_auth_path),
        "studio_token_masked": mask_secret(studio_token),
    }


# ------------------------------------------------------------------------------
# Health Probing & Service Readiness
# ------------------------------------------------------------------------------


def collect_health_report(env_file: Path, production: bool) -> dict[str, Any]:
    env_map = resolve_effective_env(env_file)
    data_dir = resolve_data_dir(env_map)
    office_port = resolve_port_from_env(env_map, "OFFICE_PORT", "ALLINAGENT_OFFICE_PORT", 8200)
    paperclip_port = resolve_port_from_env(env_map, "PAPERCLIP_PORT", "ALLINAGENT_PAPERCLIP_PORT", 8201)
    bridge_port = resolve_port_from_env(env_map, "OFFICE_BRIDGE_PORT", "ALLINAGENT_BRIDGE_PORT", 8202)

    containers: dict[str, Any] = {}
    ps_cmd = build_compose_cmd(env_file, production, ["ps", "--format", "json"])
    ps_res = run_cmd(ps_cmd, capture=True, check=False)
    if ps_res.returncode == 0 and ps_res.stdout.strip():
        raw_out = ps_res.stdout.strip()
        rows: list[dict[str, Any]] = []
        if raw_out.startswith("["):
            try:
                rows = json.loads(raw_out)
            except json.JSONDecodeError:
                rows = []
        else:
            for ln in raw_out.splitlines():
                ln = ln.strip()
                if ln.startswith("{"):
                    try:
                        rows.append(json.loads(ln))
                    except json.JSONDecodeError:
                        pass
        for row in rows:
            svc = row.get("Service") or row.get("Name") or "unknown"
            containers[svc] = {
                "name": row.get("Name"),
                "state": row.get("State"),
                "health": row.get("Health") or "",
                "status": row.get("Status") or "",
            }

    office_code, office_body = http_get_json(f"http://127.0.0.1:{office_port}/api/health", timeout=4.0)
    pc_code, pc_body = http_get_json(f"http://127.0.0.1:{paperclip_port}/api/health", timeout=4.0)
    br_code, br_body = http_get_json(f"http://127.0.0.1:{bridge_port}/health", timeout=4.0)

    def internal_ok(svc: str) -> bool:
        c = containers.get(svc)
        if not c or c.get("state") != "running":
            return False
        if c.get("health") == "healthy":
            return True
        if svc == "postgres":
            r = run_cmd(
                build_compose_cmd(env_file, production, ["exec", "-T", "postgres", "pg_isready", "-U", env_map.get("POSTGRES_USER", "paperclip")]),
                capture=True,
                check=False,
            )
            return r.returncode == 0
        if svc == "hermes":
            r = run_cmd(
                build_compose_cmd(env_file, production, ["exec", "-T", "hermes", "curl", "-fsS", "http://127.0.0.1:8650/health"]),
                capture=True,
                check=False,
            )
            return r.returncode == 0
        if svc == "vulnclaw":
            r = run_cmd(
                build_compose_cmd(
                    env_file,
                    production,
                    [
                        "exec",
                        "-T",
                        "vulnclaw",
                        "/opt/vulnclaw-venv/bin/python",
                        "/opt/allinagent/components/vulnclaw/vulnclaw_worker.py",
                        "health",
                        "--probe-http",
                    ],
                ),
                capture=True,
                check=False,
            )
            return r.returncode == 0
        return False

    checks = {
        "postgres": {"ok": internal_ok("postgres"), "exposure": "internal-only (allinagent_data)"},
        "hermes": {"ok": internal_ok("hermes"), "exposure": "internal-only (:8650)"},
        "vulnclaw": {"ok": internal_ok("vulnclaw"), "exposure": "internal-only (:8660, air-gapped)"},
        "paperclip": {"ok": pc_code == 200, "http_status": pc_code, "url": f"http://127.0.0.1:{paperclip_port}/api/health", "detail": pc_body},
        "office-bridge": {"ok": br_code == 200, "http_status": br_code, "url": f"http://127.0.0.1:{bridge_port}/health", "detail": br_body},
        "office": {"ok": office_code == 200, "http_status": office_code, "url": f"http://127.0.0.1:{office_port}/api/health", "detail": office_body},
    }

    overall_ok = all(item["ok"] for item in checks.values())
    report = {
        "ok": overall_ok,
        "timestamp": utc_now_iso(),
        "production_profile": production,
        "services": checks,
        "containers": containers,
    }

    if data_dir.is_dir():
        try:
            snap_path = data_dir / "last-health-snapshot.json"
            write_secure_file(snap_path, json.dumps(report, indent=2) + "\n", mode=0o644)
        except OSError:
            pass

    return report


def wait_for_healthy(env_file: Path, production: bool, timeout_sec: int = 90) -> tuple[bool, dict[str, Any]]:
    deadline = time.monotonic() + timeout_sec
    last_report: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last_report = collect_health_report(env_file, production)
        if last_report.get("ok"):
            return True, last_report
        time.sleep(3.0)
    return False, last_report


# ------------------------------------------------------------------------------
# Constrained Image Pull / Build Engine
# ------------------------------------------------------------------------------


def pull_or_build_images(env_file: Path, production: bool, force_build: bool = False) -> None:
    env_map = resolve_effective_env(env_file)
    mem = detect_memory_mib()
    low_ram_host = mem["total_mib"] <= 9000.0

    if not force_build:
        print("[ALLINAGENT] Pulling prebuilt images (postgres + GHCR release images)...")
        pull_res = run_cmd(build_compose_cmd(env_file, production, ["pull"]), check=False)
        if pull_res.returncode == 0:
            return
        print("[ALLINAGENT] Notice: Prebuilt GHCR tags not yet cached/published; falling back to local multi-stage build.")

    # Always pull postgres:16-alpine cleanly
    run_cmd(build_compose_cmd(env_file, production, ["pull", "postgres"]), check=True)

    registry = env_map.get("ALLINAGENT_REGISTRY", "ghcr.io")
    namespace = env_map.get("ALLINAGENT_IMAGE_NAMESPACE", DEFAULT_IMAGE_NAMESPACE)
    version_tag = env_map.get("ALLINAGENT_VERSION", "latest")

    for svc in CUSTOM_IMAGE_SERVICES:
        dockerfile = REPO_ROOT / "deploy" / "docker" / f"{svc}.Dockerfile"
        image_tag = f"{registry}/{namespace}/allinagent-{svc}:{version_tag}"
        print(f"[ALLINAGENT] Building `{svc}` -> {image_tag} (low_ram_cap={low_ram_host})...")
        if low_ram_host:
            cmd = [
                "docker",
                "buildx",
                "build",
                "--load",
                "--memory=1280m",
                "--cpus=1.0",
                "-f",
                str(dockerfile),
                "-t",
                image_tag,
                str(REPO_ROOT),
            ]
            res = run_cmd(cmd, check=False)
            if res.returncode != 0:
                run_cmd(
                    ["docker", "build", "--memory=1280m", "-f", str(dockerfile), "-t", image_tag, str(REPO_ROOT)],
                    check=True,
                )
        else:
            run_cmd(build_compose_cmd(env_file, production, ["build", svc]), check=True)


# ------------------------------------------------------------------------------
# Post-Boot 11-Agent Provisioning & Sentry-Gated Skill Installation
# ------------------------------------------------------------------------------


def provision_organization_and_skills(
    env_file: Path,
    production: bool,
    *,
    skip_provision: bool = False,
    skip_skills: bool = False,
    strict: bool = True,
) -> dict[str, Any]:
    results: dict[str, Any] = {
        "org_provisioned": False,
        "skills_installed": False,
        "errors": [],
    }

    if not skip_provision:
        print("[ALLINAGENT] Provisioning 11-agent organizational hierarchy in Paperclip...")
        found_org_script = False
        for script_path in (
            "/opt/allinagent/apps/control-center/control_center/org_provisioner.py",
            "/opt/allinagent/scripts/bootstrap_and_verify_paperclip.py",
        ):
            chk = run_cmd(
                build_compose_cmd(env_file, production, ["exec", "-T", "hermes", "test", "-f", script_path]),
                capture=True,
                check=False,
            )
            if chk.returncode == 0:
                found_org_script = True
                res = run_cmd(
                    build_compose_cmd(
                        env_file,
                        production,
                        ["exec", "-T", "hermes", "/opt/hermes-venv/bin/python", script_path],
                    ),
                    capture=True,
                    check=False,
                )
                results["org_provisioned"] = res.returncode == 0
                results["org_script"] = script_path
                if res.returncode != 0:
                    err_detail = (res.stderr or res.stdout or "").strip()[-800:]
                    msg = f"11-agent organization provisioning failed ({script_path}, exit={res.returncode}): {err_detail}"
                    print(f"[FAIL] {msg}", file=sys.stderr)
                    results["errors"].append(msg)
                    if strict:
                        raise RuntimeError(msg)
                break
        if not found_org_script:
            msg = "No organization provisioner script found inside `hermes` container."
            print(f"[FAIL] {msg}", file=sys.stderr)
            results["errors"].append(msg)
            if strict:
                raise RuntimeError(msg)

    if not skip_skills:
        print("[ALLINAGENT] Running Sentry-gated skill manifest verification & role skill installation...")
        found_skills_script = False
        for cmd_args in (
            [
                "/opt/hermes-venv/bin/python",
                "/opt/allinagent/apps/control-center/control_center/agent_skills_manager.py",
                "install",
                "--agent",
                "all",
                "--hermes-home",
                "/var/lib/allinagent/hermes",
            ],
            [
                "/opt/hermes-venv/bin/python",
                "/opt/allinagent/skills/install_agent_skills.py",
                "--hermes-home",
                "/var/lib/allinagent/hermes",
            ],
        ):
            chk = run_cmd(
                build_compose_cmd(env_file, production, ["exec", "-T", "hermes", "test", "-f", cmd_args[1]]),
                capture=True,
                check=False,
            )
            if chk.returncode == 0:
                found_skills_script = True
                res = run_cmd(
                    build_compose_cmd(env_file, production, ["exec", "-T", "hermes", *cmd_args]),
                    capture=True,
                    check=False,
                )
                results["skills_installed"] = res.returncode == 0
                results["skills_script"] = cmd_args[1]
                if res.returncode != 0:
                    err_detail = (res.stderr or res.stdout or "").strip()[-800:]
                    msg = f"Role skill installation failed ({cmd_args[1]}, exit={res.returncode}): {err_detail}"
                    print(f"[FAIL] {msg}", file=sys.stderr)
                    results["errors"].append(msg)
                    if strict:
                        raise RuntimeError(msg)
                break
        if not found_skills_script:
            msg = "No skill installation script found inside `hermes` container."
            print(f"[FAIL] {msg}", file=sys.stderr)
            results["errors"].append(msg)
            if strict:
                raise RuntimeError(msg)

    return results


# ------------------------------------------------------------------------------
# Subcommand Implementations
# ------------------------------------------------------------------------------


def cmd_setup(args: argparse.Namespace) -> int:
    env_file = Path(args.env_file).resolve()
    existing_env = resolve_effective_env(env_file)
    production = should_use_production_compose(args, existing_env, auto_low_ram=True)

    print("======================================================================")
    print(f" ALLINAGENT v{CLI_VERSION} — One-Command Setup & Production Provisioner")
    print("======================================================================")

    preflight = collect_preflight(env_file, production)
    print(
        f"[1/6] Preflight: OS={preflight['os']}/{preflight['arch']}, "
        f"CPU={preflight['cpus']} vCPU, RAM={preflight['memory_mib']['total_mib']} MiB "
        f"(avail {preflight['memory_mib']['available_mib']} MiB), Disk Free={preflight['disk_gib']['free']} GiB"
    )
    for warn in preflight["warnings"]:
        print(f"  [WARN] {warn}")
    if not preflight["ok"]:
        if args.config_only:
            for err in preflight["issues"]:
                print(f"  [WARN] (config-only) {err}")
        else:
            for err in preflight["issues"]:
                print(f"  [FAIL] {err}", file=sys.stderr)
            return 1

    provisioned = provision_env_and_secrets(
        env_file,
        non_interactive=args.yes,
        production=production,
        rotate_secrets=args.rotate_secrets,
        data_dir_override=args.data_dir,
    )
    print(f"[2/6] Secrets & configuration ready (`0600`): {provisioned['env_file']}")

    if args.config_only:
        print("[ALLINAGENT] `--config-only` requested; skipping Docker container launch.")
        return 0

    if not args.skip_pull:
        print("[3/6] Preparing container images...")
        pull_or_build_images(env_file, production, force_build=args.build)
    else:
        print("[3/6] Skipped image pull/build (`--skip-pull`).")

    print("[4/6] Starting PostgreSQL 16 (`allinagent_data` internal network)...")
    run_cmd(build_compose_cmd(env_file, production, ["up", "-d", "postgres"]), check=True)
    for _ in range(30):
        pg_chk = run_cmd(
            build_compose_cmd(env_file, production, ["exec", "-T", "postgres", "pg_isready", "-U", "paperclip"]),
            capture=True,
            check=False,
        )
        if pg_chk.returncode == 0:
            break
        time.sleep(2.0)

    print("[5/6] Launching ALLINAGENT stack (hermes, vulnclaw, paperclip, office-bridge, office)...")
    run_cmd(build_compose_cmd(env_file, production, ["up", "-d", "--remove-orphans"]), check=True)

    healthy, report = wait_for_healthy(env_file, production, timeout_sec=args.health_timeout)
    if not healthy:
        print("[FAIL] Stack did not pass health checks within timeout:", file=sys.stderr)
        print(json.dumps(report, indent=2), file=sys.stderr)
        return 1

    try:
        org_info = provision_organization_and_skills(
            env_file,
            production,
            skip_provision=args.skip_provision,
            skip_skills=args.skip_skills,
            strict=True,
        )
    except RuntimeError as exc:
        print(f"[FAIL] Post-boot provisioning failed: {exc}", file=sys.stderr)
        return 1

    print("\n======================================================================")
    print(" [6/6] ALLINAGENT SETUP COMPLETE & VERIFIED HEALTHY")
    print("======================================================================")
    print(f"  3D & 2D Virtual Office : http://127.0.0.1:{provisioned['office_port']}/office")
    print(f"  Paperclip Control API  : http://127.0.0.1:{provisioned['paperclip_port']}/api/health")
    print(f"  Unified Office Bridge  : http://127.0.0.1:{provisioned['bridge_port']}/health")
    print(f"  Persistent Data Root   : {provisioned['data_dir']}")
    print(f"  Studio Login Token     : {provisioned['studio_token_masked']} (see STUDIO_ACCESS_TOKEN in {provisioned['env_file']})")
    print(f"  11-Agent Provisioning  : {org_info}")
    print("  Remote SSH Tunnel Tip  : ./deploy/proxy/ssh-tunnel-access.sh user@your-server-ip")
    print("======================================================================")
    return 0


def cmd_up(args: argparse.Namespace) -> int:
    env_file = Path(args.env_file).resolve()
    effective_env = resolve_effective_env(env_file)
    production = should_use_production_compose(args, effective_env)
    if not has_all_required_secrets(env_file):
        provision_env_and_secrets(
            env_file,
            non_interactive=True,
            production=production,
        )
        print(f"[ALLINAGENT] Auto-provisioned missing CSPRNG secrets (`0600`) in {env_file}")
    else:
        data_dir = resolve_data_dir(effective_env)
        workspaces_dir = Path(effective_env.get("ALLINAGENT_WORKSPACES_DIR") or str(data_dir / "workspaces")).resolve()
        scaffold_data_directories(data_dir, workspaces_dir)
    extra = ["up", "-d", "--remove-orphans"]
    if args.build:
        pull_or_build_images(env_file, production, force_build=True)
    return run_cmd(build_compose_cmd(env_file, production, extra), check=False).returncode


def cmd_down(args: argparse.Namespace) -> int:
    env_file = Path(args.env_file).resolve()
    production = should_use_production_compose(args, resolve_effective_env(env_file))
    return run_cmd(build_compose_cmd(env_file, production, ["down", "--remove-orphans"]), check=False).returncode


def cmd_start(args: argparse.Namespace) -> int:
    env_file = Path(args.env_file).resolve()
    production = should_use_production_compose(args, resolve_effective_env(env_file))
    return run_cmd(build_compose_cmd(env_file, production, ["start"]), check=False).returncode


def cmd_stop(args: argparse.Namespace) -> int:
    env_file = Path(args.env_file).resolve()
    production = should_use_production_compose(args, resolve_effective_env(env_file))
    return run_cmd(build_compose_cmd(env_file, production, ["stop"]), check=False).returncode


def cmd_status(args: argparse.Namespace) -> int:
    env_file = Path(args.env_file).resolve()
    env_map = resolve_effective_env(env_file)
    production = should_use_production_compose(args, env_map)
    data_dir = resolve_data_dir(env_map)
    maint_state_file = data_dir / "maintenance" / "state.json"
    maint_state = {}
    if maint_state_file.is_file():
        try:
            maint_state = json.loads(maint_state_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            maint_state = {}

    if args.json:
        report = collect_health_report(env_file, production)
        report["maintenance"] = maint_state
        print(json.dumps(report, indent=2))
        return 0

    run_cmd(build_compose_cmd(env_file, production, ["ps"]), check=False)
    if maint_state:
        print(f"\nMaintenance State: {maint_state.get('state', 'IDLE')} (last_run_at={maint_state.get('last_run_at')})")
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    env_file = Path(args.env_file).resolve()
    production = should_use_production_compose(args, resolve_effective_env(env_file))
    report = collect_health_report(env_file, production)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        verdict = "HEALTHY" if report["ok"] else "DEGRADED / UNHEALTHY"
        print(f"[ALLINAGENT Health] Overall: {verdict} ({report['timestamp']})")
        for svc, info in report["services"].items():
            mark = "PASS" if info["ok"] else "FAIL"
            target = info.get("url") or info.get("exposure", "")
            print(f"  - {svc:14s}: [{mark}] {target}")
    return 0 if report["ok"] else 1


def cmd_logs(args: argparse.Namespace) -> int:
    env_file = Path(args.env_file).resolve()
    production = should_use_production_compose(args, resolve_effective_env(env_file))
    sub = ["logs", "--tail", str(args.tail)]
    if args.follow:
        sub.append("-f")
    if args.services:
        sub.extend(args.services)
    return run_cmd(build_compose_cmd(env_file, production, sub), check=False).returncode


def cmd_doctor(args: argparse.Namespace) -> int:
    env_file = Path(args.env_file).resolve()
    env_map = resolve_effective_env(env_file)
    production = should_use_production_compose(args, env_map)
    preflight = collect_preflight(env_file, production)
    data_dir = resolve_data_dir(env_map)

    checks: list[dict[str, Any]] = []
    checks.append(
        {
            "check": "compose_files_present",
            "ok": COMPOSE_BASE.is_file() and COMPOSE_PROD.is_file(),
            "detail": f"compose.yaml={COMPOSE_BASE.is_file()}, compose.production.yaml={COMPOSE_PROD.is_file()}",
        }
    )

    env_exists = env_file.is_file()
    env_mode_ok = True
    env_mode_str = "n/a"
    if env_exists and os.name != "nt":
        mode_bits = stat.S_IMODE(env_file.stat().st_mode)
        env_mode_str = oct(mode_bits)
        env_mode_ok = (mode_bits & 0o077) == 0
    checks.append(
        {
            "check": "env_file_permissions",
            "ok": env_exists and env_mode_ok,
            "detail": f"exists={env_exists}, mode={env_mode_str}",
        }
    )

    missing_secrets = [k for k in REQUIRED_AUTO_SECRETS if len(env_map.get(k, "").strip()) < 16]
    checks.append(
        {
            "check": "csprng_secrets_configured",
            "ok": len(missing_secrets) == 0,
            "detail": "all present" if not missing_secrets else f"missing_or_weak={missing_secrets}",
        }
    )

    # Verify zero wildcard 0.0.0.0 port bindings in compose.production.yaml
    prod_raw = COMPOSE_PROD.read_text(encoding="utf-8") if COMPOSE_PROD.is_file() else ""
    wildcard_ports = re.findall(r'^\s*-\s*["\']?(?:0\.0\.0\.0:|\d+:)', prod_raw, flags=re.M)
    checks.append(
        {
            "check": "loopback_only_ports",
            "ok": len(wildcard_ports) == 0,
            "detail": "127.0.0.1 exclusively" if not wildcard_ports else f"wildcard_bindings={wildcard_ports}",
        }
    )

    maint_lock = data_dir / "maintenance" / "maintenance.lock"
    stale_lock = False
    if maint_lock.is_file():
        age_sec = time.time() - maint_lock.stat().st_mtime
        stale_lock = age_sec > 5400
    checks.append(
        {
            "check": "maintenance_lock_clean",
            "ok": not stale_lock,
            "detail": f"present={maint_lock.is_file()}, stale={stale_lock}",
        }
    )

    overall_ok = preflight["ok"] and all(c["ok"] for c in checks)
    payload = {
        "ok": overall_ok,
        "timestamp": utc_now_iso(),
        "preflight": preflight,
        "security_and_config_checks": checks,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"[ALLINAGENT Doctor] Verdict: {'PASS' if overall_ok else 'NEEDS ATTENTION'}")
        print(
            f"  - Host Profile : {preflight['os']} {preflight['arch']} | {preflight['cpus']} vCPU | "
            f"{preflight['memory_mib']['total_mib']} MiB RAM | {preflight['disk_gib']['free']} GiB free disk"
        )
        print(
            f"  - Docker Stack : Engine={preflight['docker']['server_version'] or 'missing'} | "
            f"Compose v2={preflight['compose_v2']['version'] or 'missing'}"
        )
        for item in checks:
            print(f"  - {item['check']:28s}: [{'PASS' if item['ok'] else 'FAIL'}] ({item['detail']})")
        for issue in preflight["issues"]:
            print(f"  - [ISSUE] {issue}")
        for warn in preflight["warnings"]:
            print(f"  - [WARN]  {warn}")
    return 0 if overall_ok else 1


# ------------------------------------------------------------------------------
# Coordinated Safe Update (`update`) with Active-Work Deferral & Auto-Rollback
# ------------------------------------------------------------------------------


def detect_active_agent_work(env_map: dict[str, str]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    paperclip_port = resolve_port_from_env(env_map, "PAPERCLIP_PORT", "ALLINAGENT_PAPERCLIP_PORT", 8201)
    bridge_port = resolve_port_from_env(env_map, "OFFICE_BRIDGE_PORT", "ALLINAGENT_BRIDGE_PORT", 8202)

    code, br_state = http_get_json(f"http://127.0.0.1:{bridge_port}/health", timeout=3.0)
    if code == 200 and isinstance(br_state, dict):
        active_runs = int(br_state.get("active_runs") or 0)
        if active_runs > 0:
            reasons.append(f"office_bridge_active_runs:{active_runs}")

    c_code, companies = http_get_json(f"http://127.0.0.1:{paperclip_port}/api/companies", timeout=3.0)
    if c_code == 200 and isinstance(companies, list) and companies:
        comp_id = companies[0].get("id")
        if comp_id:
            r_code, runs = http_get_json(
                f"http://127.0.0.1:{paperclip_port}/api/companies/{comp_id}/heartbeat-runs",
                timeout=3.0,
            )
            if r_code == 200 and isinstance(runs, list):
                live = [r for r in runs if r.get("status") in ("queued", "running")]
                if live:
                    reasons.append(f"paperclip_live_runs:{len(live)}")

    return (len(reasons) > 0, reasons)


def fetch_latest_release_manifest(repo: str, manifest_path: str | None = None) -> dict[str, Any] | None:
    if manifest_path:
        p = Path(manifest_path)
        if p.is_file():
            return json.loads(p.read_text(encoding="utf-8"))
    code, release = http_get_json(f"https://api.github.com/repos/{repo}/releases/latest", timeout=8.0)
    if code != 200 or not isinstance(release, dict):
        return None
    for asset in release.get("assets") or []:
        if asset.get("name") == "release-manifest.json" and asset.get("browser_download_url"):
            m_code, m_body = http_get_json(asset["browser_download_url"], timeout=8.0)
            if m_code == 200 and isinstance(m_body, dict):
                return m_body
    tag = str(release.get("tag_name") or "").lstrip("v")
    return {"version": tag, "tag": release.get("tag_name"), "images": {}} if tag else None


def update_env_key(env_file: Path, key: str, new_value: str) -> None:
    if not env_file.is_file():
        return
    lines = env_file.read_text(encoding="utf-8").splitlines()
    replaced = False
    out_lines: list[str] = []
    for ln in lines:
        if ln.strip().startswith(f"{key}="):
            out_lines.append(f"{key}={new_value}")
            replaced = True
        else:
            out_lines.append(ln)
    if not replaced:
        out_lines.append(f"{key}={new_value}")
    write_secure_file(env_file, "\n".join(out_lines) + "\n", mode=0o600)


def backup_postgres_database(env_file: Path, production: bool, data_dir: Path, pg_user: str, pg_db: str) -> Path | None:
    backups_dir = data_dir / "backups"
    backups_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_file = backups_dir / f"paperclip-pre-update-{stamp}.sql.gz"
    tmp_file = backups_dir / f".paperclip-pre-update-{stamp}.sql.gz.tmp.{os.getpid()}"
    cmd = build_compose_cmd(env_file, production, ["exec", "-T", "postgres", "pg_dump", "-U", pg_user, "-d", pg_db])

    bytes_written = 0
    fd = os.open(str(tmp_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as raw_fh:
            with subprocess.Popen(
                cmd,
                cwd=str(REPO_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc:
                assert proc.stdout is not None
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw_fh, mtime=0) as gz:
                    while True:
                        chunk = proc.stdout.read(65536)
                        if not chunk:
                            break
                        bytes_written += len(chunk)
                        gz.write(chunk)
                _, _stderr = proc.communicate()
                if proc.returncode != 0 or bytes_written == 0:
                    tmp_file.unlink(missing_ok=True)
                    return None
        if os.name != "nt":
            os.chmod(tmp_file, 0o600)
        tmp_file.replace(out_file)
        if os.name != "nt":
            os.chmod(out_file, 0o600)
    except Exception:
        tmp_file.unlink(missing_ok=True)
        return None

    # Retain only the 7 most recent backups to protect disk floor
    existing = sorted(backups_dir.glob("paperclip-pre-update-*.sql.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in existing[7:]:
        old.unlink(missing_ok=True)
    return out_file


def snapshot_current_images(env_file: Path, production: bool) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for svc in CUSTOM_IMAGE_SERVICES:
        cid_res = run_cmd(build_compose_cmd(env_file, production, ["ps", "-q", svc]), capture=True, check=False)
        cid = cid_res.stdout.strip()
        if not cid:
            continue
        img_res = run_cmd(["docker", "inspect", "--format", "{{.Image}}", cid], capture=True, check=False)
        img_id = img_res.stdout.strip()
        if img_id:
            snapshot[svc] = img_id
            run_cmd(["docker", "tag", img_id, f"allinagent-rollback/{svc}:previous"], check=False)
    return snapshot


def rollback_to_previous_images(
    env_file: Path,
    production: bool,
    previous_version: str,
    snapshot: dict[str, str],
    registry: str,
    namespace: str,
) -> bool:
    print("[ROLLBACK] Restoring previous known-good container images...", file=sys.stderr)
    update_env_key(env_file, "ALLINAGENT_VERSION", previous_version)
    for svc, img_id in snapshot.items():
        target_ref = f"{registry}/{namespace}/allinagent-{svc}:{previous_version}"
        run_cmd(["docker", "tag", img_id, target_ref], check=False)
    up_res = run_cmd(build_compose_cmd(env_file, production, ["up", "-d", "--remove-orphans"]), check=False)
    if up_res.returncode != 0:
        return False
    ok, _ = wait_for_healthy(env_file, production, timeout_sec=60)
    return ok


def cmd_update(args: argparse.Namespace) -> int:
    env_file = Path(args.env_file).resolve()
    env_map = resolve_effective_env(env_file)
    production = should_use_production_compose(args, env_map)
    data_dir = resolve_data_dir(env_map)
    maint_dir = data_dir / "maintenance"
    maint_dir.mkdir(parents=True, exist_ok=True)
    lock_path = maint_dir / "maintenance.lock"
    state_path = maint_dir / "state.json"

    state: dict[str, Any] = {}
    if state_path.is_file():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            state = {}
    quarantined: dict[str, Any] = state.get("quarantined_candidates") or {}

    def save_maint_state(status_str: str, note: str = "", extra: dict[str, Any] | None = None) -> None:
        state.update(
            {
                "state": status_str,
                "last_run_at": utc_now_iso(),
                "last_note": note,
                "quarantined_candidates": quarantined,
            }
        )
        if extra:
            state.update(extra)
        write_secure_file(state_path, json.dumps(state, indent=2) + "\n", mode=0o644)

    # 1. Respect active maintenance.lock (< 90 minutes old)
    if lock_path.is_file():
        lock_age = time.time() - lock_path.stat().st_mtime
        if lock_age < 5400 and not args.force:
            msg = f"Active maintenance.lock held ({int(lock_age)}s old); deferring update."
            print(f"[ALLINAGENT Update] DEFERRED: {msg}")
            save_maint_state("DEFERRED", msg)
            return 0
        lock_path.unlink(missing_ok=True)

    # 2. Check active agent runs before disrupting containers
    if not args.force:
        busy, reasons = detect_active_agent_work(env_map)
        if busy:
            msg = f"Active agent executions detected ({', '.join(reasons)}); deferring update cleanly."
            print(f"[ALLINAGENT Update] DEFERRED: {msg}")
            save_maint_state("DEFERRED", msg)
            return 0

    # 3. Release-aware digest / tag check
    repo = args.repo or env_map.get("ALLINAGENT_GITHUB_REPO", DEFAULT_GITHUB_REPO)
    current_version = env_map.get("ALLINAGENT_VERSION", "latest")
    manifest = fetch_latest_release_manifest(repo, args.manifest)
    target_version = args.target_tag or (manifest.get("version") if manifest else None) or current_version

    if target_version in quarantined and not args.force:
        msg = f"Candidate `{target_version}` is quarantined due to prior failed post-update healthcheck."
        print(f"[ALLINAGENT Update] SKIPPED: {msg}")
        save_maint_state("NEEDS_ATTENTION", msg)
        return 0

    if args.check_only:
        payload = {
            "current_version": current_version,
            "target_version": target_version,
            "update_available": target_version != current_version or bool(manifest),
            "manifest": manifest,
        }
        print(json.dumps(payload, indent=2))
        return 0

    # Acquire atomic maintenance lock
    write_secure_file(
        lock_path,
        json.dumps({"pid": os.getpid(), "started_at": utc_now_iso(), "target_version": target_version}) + "\n",
        mode=0o600,
    )

    registry = env_map.get("ALLINAGENT_REGISTRY", "ghcr.io")
    namespace = env_map.get("ALLINAGENT_IMAGE_NAMESPACE", DEFAULT_IMAGE_NAMESPACE)

    try:
        save_maint_state("PRECHECK", f"Snapshotting running images (current={current_version}, target={target_version})")
        snapshot = snapshot_current_images(env_file, production)
        write_secure_file(
            maint_dir / "rollback-snapshot.json",
            json.dumps({"previous_version": current_version, "images": snapshot, "created_at": utc_now_iso()}, indent=2) + "\n",
            mode=0o600,
        )

        backup_file = backup_postgres_database(
            env_file,
            production,
            data_dir,
            env_map.get("POSTGRES_USER", "paperclip"),
            env_map.get("POSTGRES_DB", "paperclip"),
        )
        if backup_file:
            print(f"[ALLINAGENT Update] Pre-update PostgreSQL backup saved: {backup_file}")

        save_maint_state("UPDATING", f"Pulling target version {target_version}")
        update_env_key(env_file, "ALLINAGENT_VERSION", target_version)

        pull_res = run_cmd(build_compose_cmd(env_file, production, ["pull"]), check=False)
        if pull_res.returncode != 0:
            print("[FAIL] Image pull failed; restoring previous version setting.", file=sys.stderr)
            update_env_key(env_file, "ALLINAGENT_VERSION", current_version)
            save_maint_state("FAILED", f"Image pull failed for {target_version}")
            return 1

        up_res = run_cmd(build_compose_cmd(env_file, production, ["up", "-d", "--remove-orphans"]), check=False)
        save_maint_state("POST_UPDATE_TEST", "Verifying post-update service health")
        healthy, report = wait_for_healthy(env_file, production, timeout_sec=args.health_timeout)

        if up_res.returncode != 0 or not healthy:
            quarantined[target_version] = {"failed_at": utc_now_iso(), "health_report": report}
            rb_ok = rollback_to_previous_images(env_file, production, current_version, snapshot, registry, namespace)
            save_maint_state(
                "FAILED",
                f"Post-update healthcheck failed for {target_version}; automatic rollback_ok={rb_ok}",
                {"last_rollback_at": utc_now_iso(), "rollback_succeeded": rb_ok},
            )
            print(f"[ROLLBACK] Candidate `{target_version}` quarantined; rollback_succeeded={rb_ok}.", file=sys.stderr)
            return 1

        # Safe cleanup of dangling images belonging only to replaced layers (never volumes)
        run_cmd(["docker", "image", "prune", "-f"], check=False)
        save_maint_state("READY", f"Successfully updated and verified `{target_version}`")
        print(f"[ALLINAGENT Update] Update to `{target_version}` completed and verified HEALTHY.")
        return 0
    finally:
        lock_path.unlink(missing_ok=True)


def cmd_version(args: argparse.Namespace) -> int:
    payload = {
        "product": "ALLINAGENT",
        "cli_version": CLI_VERSION,
        "github_repo": DEFAULT_GITHUB_REPO,
        "image_namespace": DEFAULT_IMAGE_NAMESPACE,
        "upstream_pins": UPSTREAM_PINS,
        "python_runtime": sys.version.split()[0],
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"ALLINAGENT CLI v{CLI_VERSION}")
        for k, v in UPSTREAM_PINS.items():
            print(f"  - {k}: {v}")
    return 0


# ------------------------------------------------------------------------------
# Argument Parser Entrypoint
# ------------------------------------------------------------------------------


def _attach_shared_subparser_flags(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--env-file",
        default=argparse.SUPPRESS,
        help="Path to .env configuration file",
    )
    sub_mode = subparser.add_mutually_exclusive_group()
    sub_mode.add_argument(
        "--production",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Force 2-vCPU / 8-GB production compose profile",
    )
    sub_mode.add_argument(
        "--local",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Force local compose profile without production caps",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="allinagent",
        description="ALLINAGENT — One-Command Installer, Operations & Coordinated Safe Update CLI",
    )
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env"), help="Path to .env configuration file")
    mode_grp = parser.add_mutually_exclusive_group()
    mode_grp.add_argument("--production", action="store_true", help="Force 2-vCPU / 8-GB production compose profile")
    mode_grp.add_argument("--local", action="store_true", help="Force local compose profile without production caps")

    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_setup = sub.add_parser("setup", help="Run preflight, .env wizard, CSPRNG secrets, DB init, org & skill setup")
    _attach_shared_subparser_flags(p_setup)
    p_setup.add_argument("-y", "--yes", action="store_true", help="Non-interactive mode using defaults / env vars")
    p_setup.add_argument("--build", action="store_true", help="Build Docker images locally (RAM-capped on <=8GB hosts)")
    p_setup.add_argument("--skip-pull", action="store_true", help="Skip pulling/building container images")
    p_setup.add_argument("--skip-provision", action="store_true", help="Skip 11-agent org provisioning step")
    p_setup.add_argument("--skip-skills", action="store_true", help="Skip role-specific GitHub skill installation")
    p_setup.add_argument("--rotate-secrets", action="store_true", help="Regenerate internal CSPRNG platform secrets")
    p_setup.add_argument("--config-only", action="store_true", help="Generate .env, secrets, and directories only")
    p_setup.add_argument("--data-dir", default=None, help="Override persistent host bind-mount directory")
    p_setup.add_argument("--health-timeout", type=int, default=90, help="Seconds to wait for container healthchecks")
    p_setup.set_defaults(func=cmd_setup)

    p_up = sub.add_parser("up", help="Start ALLINAGENT Docker stack in background")
    _attach_shared_subparser_flags(p_up)
    p_up.add_argument("--build", action="store_true", help="Rebuild images before starting")
    p_up.set_defaults(func=cmd_up)

    p_down = sub.add_parser("down", help="Stop and remove ALLINAGENT containers (preserves bind-mounted data)")
    _attach_shared_subparser_flags(p_down)
    p_down.set_defaults(func=cmd_down)

    p_start = sub.add_parser("start", help="Start existing stopped ALLINAGENT containers")
    _attach_shared_subparser_flags(p_start)
    p_start.set_defaults(func=cmd_start)

    p_stop = sub.add_parser("stop", help="Gracefully stop running ALLINAGENT containers")
    _attach_shared_subparser_flags(p_stop)
    p_stop.set_defaults(func=cmd_stop)

    p_status = sub.add_parser("status", help="Display container status and maintenance state")
    _attach_shared_subparser_flags(p_status)
    p_status.add_argument("--json", action="store_true", help="Emit JSON output")
    p_status.set_defaults(func=cmd_status)

    p_health = sub.add_parser("health", help="Probe all 6 ALLINAGENT service health endpoints")
    _attach_shared_subparser_flags(p_health)
    p_health.add_argument("--json", action="store_true", help="Emit JSON output")
    p_health.set_defaults(func=cmd_health)

    p_logs = sub.add_parser("logs", help="View or follow ALLINAGENT service logs")
    _attach_shared_subparser_flags(p_logs)
    p_logs.add_argument("services", nargs="*", help="Optional service names (e.g. hermes paperclip office)")
    p_logs.add_argument("-f", "--follow", action="store_true", help="Stream logs continuously")
    p_logs.add_argument("--tail", type=int, default=100, help="Number of lines from end of logs")
    p_logs.set_defaults(func=cmd_logs)

    p_doc = sub.add_parser("doctor", help="Run comprehensive SRE, security, port, and cgroup diagnostics")
    _attach_shared_subparser_flags(p_doc)
    p_doc.add_argument("--json", action="store_true", help="Emit JSON output")
    p_doc.set_defaults(func=cmd_doctor)

    p_upd = sub.add_parser("update", help="Safe release-aware update with active-work deferral & auto-rollback")
    _attach_shared_subparser_flags(p_upd)
    p_upd.add_argument("-y", "--yes", action="store_true", help="Non-interactive confirmation")
    p_upd.add_argument("--scheduled-maintenance", action="store_true", help="Triggered by daily 03:00 systemd timer")
    p_upd.add_argument("--check-only", action="store_true", help="Check remote release manifest without updating")
    p_upd.add_argument("--force", action="store_true", help="Bypass active-work deferral or candidate quarantine")
    p_upd.add_argument("--target-tag", default=None, help="Explicit image version tag to deploy")
    p_upd.add_argument("--manifest", default=None, help="Path to local release-manifest.json")
    p_upd.add_argument("--repo", default=None, help="GitHub owner/repo for release manifest checks")
    p_upd.add_argument("--health-timeout", type=int, default=90, help="Seconds to wait before triggering auto-rollback")
    p_upd.set_defaults(func=cmd_update)

    p_ver = sub.add_parser("version", help="Display ALLINAGENT CLI and upstream component versions")
    _attach_shared_subparser_flags(p_ver)
    p_ver.add_argument("--json", action="store_true", help="Emit JSON output")
    p_ver.set_defaults(func=cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "production", False) and getattr(args, "local", False):
        parser.error("argument --local: not allowed with argument --production")
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
