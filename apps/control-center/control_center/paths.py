#!/usr/bin/env python3
"""Cross-platform path, runtime executable, and service URL resolver for ALLINAGENT.

Enforces fail-closed Owner Telegram authorization (never falling back to dummy IDs),
eliminates Windows-specific hardcoded paths, and supports both Linux Docker/systemd
production deployments and local multi-OS development environments.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

IS_WINDOWS: bool = os.name == "nt"
IS_POSIX: bool = not IS_WINDOWS


def _resolve_allinagent_root() -> Path:
    for env_key in ("ALLINAGENT_ROOT", "ALLAGENT_ROOT", "PLATFORM_ROOT"):
        raw = os.environ.get(env_key, "").strip()
        if raw:
            return Path(raw).expanduser().resolve()
    # apps/control-center/control_center/paths.py -> parents[3] == ALLINAGENT root
    return Path(__file__).resolve().parents[3]


ALLINAGENT_ROOT: Path = _resolve_allinagent_root()
PLATFORM_ROOT: Path = ALLINAGENT_ROOT  # Legacy compatibility alias


def _load_root_dotenv_defaults(root: Path) -> None:
    """Populate unset environment variables from `<ALLINAGENT_ROOT>/.env` without logging values."""
    if os.environ.get("ALLINAGENT_SKIP_DOTENV") == "1":
        return
    env_file = root / ".env"
    if not env_file.is_file():
        return
    try:
        for line in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, val = stripped.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
    except OSError:
        pass


_load_root_dotenv_defaults(ALLINAGENT_ROOT)


def venv_python_path(venv_dir: str | Path) -> Path:
    """Return the cross-platform Python interpreter inside a virtual environment."""
    base = Path(venv_dir)
    return base / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")


def _is_docker_mode() -> bool:
    if os.environ.get("ALLINAGENT_DOCKER", "").strip() == "1":
        return True
    if IS_POSIX and (Path("/.dockerenv").exists() or Path("/var/lib/allinagent/hermes").exists()):
        return True
    return False


def _resolve_hermes_home_root() -> Path:
    for env_key in ("HERMES_HOME_ROOT", "HERMES_HOME"):
        raw = os.environ.get(env_key, "").strip()
        if raw:
            return Path(raw).expanduser().resolve()
    if IS_POSIX and Path("/var/lib/allinagent/hermes").exists():
        return Path("/var/lib/allinagent/hermes").resolve()
    if IS_POSIX and Path("/data/hermes").exists():
        return Path("/data/hermes").resolve()
    return (ALLINAGENT_ROOT / "data" / "hermes").resolve()


def resolve_data_dir() -> Path:
    raw = os.environ.get("ALLINAGENT_DATA_DIR", "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    if IS_POSIX and (Path("/var/lib/allinagent/hermes").exists() or _is_docker_mode()):
        return Path("/var/lib/allinagent").resolve()
    return (ALLINAGENT_ROOT / "data").expanduser().resolve()


def resolve_config_dir() -> Path:
    raw = os.environ.get("ALLINAGENT_CONFIG_DIR", "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return (ALLINAGENT_ROOT / "config").expanduser().resolve()


def resolve_secrets_dir() -> Path:
    for env_key in ("ALLINAGENT_SECRETS_DIR", "SECRETS_DIR"):
        raw = os.environ.get(env_key, "").strip()
        if raw:
            return Path(raw).expanduser().resolve()
    if IS_POSIX and (Path("/var/lib/allinagent/secrets").exists() or _is_docker_mode()):
        return Path("/var/lib/allinagent/secrets").resolve()
    return (resolve_config_dir() / "secrets").expanduser().resolve()


def resolve_workspaces_dir() -> Path:
    for env_key in ("ALLINAGENT_WORKSPACE_ROOT", "ALLINAGENT_WORKSPACES_DIR"):
        raw = os.environ.get(env_key, "").strip()
        if raw:
            return Path(raw).expanduser().resolve()
    if IS_POSIX and (Path("/var/lib/allinagent/workspaces").exists() or _is_docker_mode()):
        return Path("/var/lib/allinagent/workspaces").resolve()
    return (ALLINAGENT_ROOT / "workspaces").expanduser().resolve()


def resolve_reports_dir() -> Path:
    for env_key in ("ALLINAGENT_REPORTS_ROOT", "ALLINAGENT_REPORTS_DIR"):
        raw = os.environ.get(env_key, "").strip()
        if raw:
            return Path(raw).expanduser().resolve()
    if IS_POSIX and (Path("/var/lib/allinagent/reports").exists() or _is_docker_mode()):
        return Path("/var/lib/allinagent/reports").resolve()
    return (resolve_data_dir() / "reports").expanduser().resolve()


HERMES_HOME_ROOT: Path = _resolve_hermes_home_root()
HERMES_HOME: Path = HERMES_HOME_ROOT  # Legacy compatibility alias
PROFILES_ROOT: Path = Path(
    os.environ.get("HERMES_PROFILES_ROOT") or (HERMES_HOME_ROOT / "profiles")
).expanduser().resolve()

DATA_DIR: Path = resolve_data_dir()
CONFIG_DIR: Path = resolve_config_dir()
SECRETS_DIR: Path = resolve_secrets_dir()
WORKERS_DIR: Path = Path(os.environ.get("ALLINAGENT_WORKERS_DIR") or (DATA_DIR / "workers")).expanduser().resolve()
WORKSPACES_DIR: Path = resolve_workspaces_dir()
WORKSPACE_ROOT: Path = WORKSPACES_DIR
REPORTS_DIR: Path = resolve_reports_dir()
REPORTS_ROOT: Path = REPORTS_DIR
LOGS_DIR: Path = Path(os.environ.get("ALLINAGENT_LOGS_DIR") or (DATA_DIR / "logs")).expanduser().resolve()


def resolve_roster_json_path() -> Path:
    explicit = os.environ.get("ALLINAGENT_ROSTER_PATH", "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()
    if os.environ.get("HERMES_HOME_ROOT", "").strip() or os.environ.get("HERMES_HOME", "").strip() or _is_docker_mode():
        return (_resolve_hermes_home_root() / "organization-roster.json").resolve()
    return (resolve_data_dir() / "organization-roster.json").resolve()


def resolve_roster_read_paths(primary: Path | None = None) -> list[Path]:
    candidates = [
        primary or resolve_roster_json_path(),
        _resolve_hermes_home_root() / "organization-roster.json",
        resolve_data_dir() / "organization-roster.json",
        resolve_secrets_dir() / "organization-roster.json",
        resolve_config_dir() / "organization-roster.json",
    ]
    unique: list[Path] = []
    seen: set[str] = set()
    for cand in candidates:
        key = str(cand).lower() if IS_WINDOWS else str(cand)
        if key not in seen:
            seen.add(key)
            unique.append(cand)
    return unique


ROSTER_JSON_PATH: Path = resolve_roster_json_path()

SKILL_SOURCE_DIR: Path = (ALLINAGENT_ROOT / "skills").resolve()
SKILL_MANIFESTS_DIR: Path = (SKILL_SOURCE_DIR / "manifests").resolve()
SKILL_POLICIES_DIR: Path = (SKILL_SOURCE_DIR / "policies").resolve()
SKILL_REGISTRY_DIR: Path = Path(
    os.environ.get("SKILL_REGISTRY_DIR") or (DATA_DIR / "skill-registry")
).expanduser().resolve()

HERMES_REPO: Path = Path(
    os.environ.get("HERMES_REPO")
    or os.environ.get("HERMES_SOURCE_DIR")
    or (ALLINAGENT_ROOT / "runtime" / "hermes-agent")
).expanduser().resolve()
HERMES_UPDATER_DIR: Path = Path(
    os.environ.get("HERMES_UPDATER_DIR") or (DATA_DIR / "hermes-updater")
).expanduser().resolve()

# --- Service Base URLs ---
PAPERCLIP_BASE_URL: str = (
    os.environ.get("PAPERCLIP_BASE_URL")
    or os.environ.get("PAPERCLIP_URL")
    or ("http://paperclip:3100" if _is_docker_mode() else "http://127.0.0.1:3100")
).strip().rstrip("/")
PAPERCLIP_API_URL: str = (
    os.environ.get("PAPERCLIP_API_URL") or f"{PAPERCLIP_BASE_URL}/api"
).strip().rstrip("/")
OFFICE_BRIDGE_URL: str = (
    os.environ.get("OFFICE_BRIDGE_URL")
    or os.environ.get("OFFICE_BRIDGE_HTTP_URL")
    or ("http://office-bridge:3210" if _is_docker_mode() else "http://127.0.0.1:3210")
).strip().rstrip("/")
OFFICE_BRIDGE_HTTP_URL: str = OFFICE_BRIDGE_URL
HERMES3D_URL: str = (
    os.environ.get("HERMES3D_URL")
    or os.environ.get("HERMES3D_BASE_URL")
    or ("http://office:3200" if _is_docker_mode() else "http://127.0.0.1:3200")
).strip().rstrip("/")
VULNCLAW_WORKER_URL: str = (
    os.environ.get("VULNCLAW_WORKER_URL") or ""
).strip().rstrip("/")

# --- Fail-Closed Owner Authorization ---
_DISALLOWED_PLACEHOLDER_IDS = frozenset({
    "",
    "0",
    "1" + ("0" * 9),
    "123456789",
    "1234567890",
    "changeme",
    "your_telegram_id",
    "none",
    "null",
})


def resolve_owner_telegram_id(raw_value: str | None = None) -> str:
    """Validate and normalize OWNER_TELEGRAM_ID; returns '' when unset or invalid (fail-closed)."""
    cand = str(raw_value if raw_value is not None else os.environ.get("OWNER_TELEGRAM_ID", "")).strip()
    if cand.lower() in _DISALLOWED_PLACEHOLDER_IDS:
        return ""
    if not cand.isdigit() or int(cand) <= 0:
        return ""
    return cand


OWNER_TELEGRAM_ID: str = resolve_owner_telegram_id()
AUTHORIZED_OWNER_ID: str = OWNER_TELEGRAM_ID  # Legacy compatibility alias


def require_owner_telegram_id() -> str:
    """Return validated OWNER_TELEGRAM_ID or raise PermissionError (fail-closed)."""
    current = resolve_owner_telegram_id()
    if not current:
        raise PermissionError(
            "OWNER_TELEGRAM_ID is unconfigured or invalid (fail-closed security policy). "
            "Configure a valid numeric Telegram user ID in OWNER_TELEGRAM_ID."
        )
    return current


def is_owner_authorized(caller_id: str | int | None) -> bool:
    """Fail-closed check that caller_id matches a valid configured OWNER_TELEGRAM_ID."""
    expected = resolve_owner_telegram_id()
    if not expected:
        return False
    probe = str(caller_id if caller_id is not None else "").strip()
    return bool(probe) and probe.isdigit() and probe == expected


# --- Dynamic LLM & Runtime Binaries ---
DEFAULT_LLM_MODEL: str = (
    os.environ.get("DEFAULT_LLM_MODEL")
    or os.environ.get("LLM_MODEL")
    or "gpt-4o-mini"
).strip()
LLM_MODEL: str = DEFAULT_LLM_MODEL  # Legacy compatibility alias
LLM_BASE_URL: str = (
    os.environ.get("LLM_BASE_URL") or "https://api.openai.com/v1"
).strip()
LLM_PROVIDER: str = (
    os.environ.get("LLM_PROVIDER") or "auto"
).strip()


def _resolve_hermes_exe() -> str:
    explicit = os.environ.get("HERMES_EXE", "").strip()
    if explicit:
        return explicit
    found = shutil.which("hermes")
    if found:
        return found
    cand = HERMES_HOME_ROOT / ("bin/hermes.exe" if IS_WINDOWS else "bin/hermes")
    return str(cand)


def _abspath_preserve_symlink(candidate: str | Path) -> Path:
    """Return normalized `os.path.abspath` without dereferencing virtualenv `bin/python` symlinks."""
    return Path(os.path.abspath(os.path.expanduser(str(candidate))))


def resolve_hermes_python_bin(raw_override: str | Path | None = None) -> Path:
    """Resolve the Hermes/runtime Python executable while preserving venv symlink paths."""
    explicit = str(raw_override if raw_override is not None else os.environ.get("HERMES_PYTHON_BIN", "")).strip()
    if explicit:
        return _abspath_preserve_symlink(explicit)
    if IS_POSIX:
        docker_venv_py = venv_python_path("/opt/hermes-venv")
        if docker_venv_py.is_symlink() or docker_venv_py.exists():
            return _abspath_preserve_symlink(docker_venv_py)
    return _abspath_preserve_symlink(sys.executable)


def _resolve_venv_or_sys_python(
    env_key: str,
    default_venv_subdir: str,
    *,
    docker_venv_dir: str | None = None,
    fallback_env_keys: tuple[str, ...] = (),
) -> Path:
    for key in (env_key, *fallback_env_keys):
        explicit = os.environ.get(key, "").strip()
        if explicit:
            return _abspath_preserve_symlink(explicit)
    if IS_POSIX and docker_venv_dir:
        docker_cand = venv_python_path(docker_venv_dir)
        if docker_cand.is_symlink() or docker_cand.exists():
            return _abspath_preserve_symlink(docker_cand)
    cand = venv_python_path(ALLINAGENT_ROOT / "runtime" / default_venv_subdir)
    if cand.is_symlink() or cand.exists():
        return _abspath_preserve_symlink(cand)
    return resolve_hermes_python_bin()


HERMES_EXE: str = _resolve_hermes_exe()
HERMES_PYTHON_BIN: Path = resolve_hermes_python_bin()
PYTHON_EXE: str = str(HERMES_PYTHON_BIN)
SKILL_VENV_PYTHON: Path = _resolve_venv_or_sys_python(
    "SKILL_VENV_PYTHON",
    "skill-tools-venv",
    docker_venv_dir="/opt/hermes-venv",
    fallback_env_keys=("HERMES_PYTHON_BIN",),
)
VULNCLAW_VENV_PYTHON: Path = _resolve_venv_or_sys_python(
    "VULNCLAW_VENV_PYTHON",
    "vulnclaw-venv",
    docker_venv_dir="/opt/vulnclaw-venv",
)
SKILL_NODE_TOOLS_DIR: Path = Path(
    os.environ.get("SKILL_NODE_TOOLS_DIR") or (ALLINAGENT_ROOT / "runtime" / "skill-node-tools")
).expanduser().resolve()
