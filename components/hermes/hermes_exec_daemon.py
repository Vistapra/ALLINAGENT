#!/usr/bin/env python3
"""ALLINAGENT Shared Hermes Execution & Health Daemon (`0.0.0.0:8650`).

Provides an authenticated internal HTTP bridge so `allinagent-paperclip` and
`allinagent-office-bridge` execute all 11 corporate Hermes workers inside a single
shared Python/Hermes container without duplicating Python runtimes across Node containers.

Key Guarantees:
  1. Constant-time `X-Internal-Exec-Token` authentication (`ALLINAGENT_INTERNAL_TOKEN`), fail-closed.
  2. Global `asyncio.Semaphore(HEAVY_WORKER_CONCURRENCY)` (default `1`) preventing concurrent LLM
     worker RAM/CPU spikes on a 2-vCPU / 8-GB VPS while queuing bursts cleanly in FIFO order.
  3. Non-LLM CLI metadata probes (`--version`, `-V`, `--help`, `-h`) bypass the heavy worker queue
     so Paperclip adapter health checks (`10s` timeout) respond in <200ms even under active load.
  4. Strict allowlist of the 11 corporate profiles (`pcceoagent` .. `pccompliancereporter`),
     enforcing `HERMES_HOME=/var/lib/allinagent/hermes/profiles/<profile>`, `0o700` directory permissions,
     and `.no-bundled-skills` (hyphenated — fixing `BUG-01`).
  5. Explicit secret stripping (`TELEGRAM_BOT_TOKEN`, `OWNER_TELEGRAM_ID`, `ALLINAGENT_INTERNAL_TOKEN`,
     `HERMES_EXEC_SHARED_SECRET`, `PAPERCLIP_AGENT_JWT_SECRET`, `PAPERCLIP_TOOL_ACTION_SIGNING_SECRET`,
     `DATABASE_URL`, etc.) and strict 8-key `PAPERCLIP_*` worker env allowlist.
  6. Safe cross-container `--query-file` payload materialization (`0o600` temp file + guaranteed unlink).
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import mimetypes
import os
import re
import shutil
import signal
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=os.environ.get("HERMES_EXEC_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] hermes-exec-daemon: %(message)s",
)
logger = logging.getLogger("hermes_exec_daemon")

ALLOWED_PROFILES: tuple[str, ...] = (
    "pcceoagent",
    "pcctoagent",
    "pcbackenddeveloper",
    "pcfrontenddeveloper",
    "pcdevopsengineer",
    "pcqaengineer",
    "pcsecuritylead",
    "pcsecurityreviewer",
    "pcfindingsanalyst",
    "pcremediationreviewer",
    "pccompliancereporter",
)
ALLOWED_PROFILES_SET: frozenset[str] = frozenset(ALLOWED_PROFILES)

PROFILE_SUBDIRS: tuple[str, ...] = (
    "memories",
    "sessions",
    "skills",
    "skins",
    "logs",
    "plans",
    "workspace",
    "cron",
    "home",
)

NO_BUNDLED_SKILLS_MARKER = ".no-bundled-skills"
LEGACY_UNDERSCORE_MARKER = ".no_bundled_skills"

# Secrets and control vars that MUST NEVER enter any child worker environment.
FORBIDDEN_WORKER_ENV_KEYS: frozenset[str] = frozenset({
    "TELEGRAM_BOT_TOKEN",
    "OWNER_TELEGRAM_ID",
    "ALLINAGENT_INTERNAL_TOKEN",
    "HERMES_EXEC_SHARED_SECRET",
    "OFFICE_BRIDGE_TOKEN",
    "OFFICE_BRIDGE_AUTH_TOKEN",
    "PAPERCLIP_BOARD_API_KEY",
    "PAPERCLIP_AGENT_JWT_SECRET",
    "PAPERCLIP_TOOL_ACTION_SIGNING_SECRET",
    "PAPERCLIP_WAKE_PAYLOAD_JSON",
    "DATABASE_URL",
    "POSTGRES_PASSWORD",
    "POSTGRES_USER",
    "HERMES_REMOTE_EXEC_URL",
    "HERMES_EXEC_URL",
    "STUDIO_ACCESS_PASSWORD",
    "BETTER_AUTH_SECRET",
})

# Explicit allowlist of 8 safe worker keys permitted across the PAPERCLIP_* namespace.
SAFE_PAPERCLIP_WORKER_ENV_KEYS: frozenset[str] = frozenset({
    "PAPERCLIP_API_URL",
    "PAPERCLIP_API_KEY",
    "PAPERCLIP_RUN_ID",
    "PAPERCLIP_TASK_ID",
    "PAPERCLIP_AGENT_ID",
    "PAPERCLIP_COMPANY_ID",
    "PAPERCLIP_WAKE_REASON",
    "PAPERCLIP_WAKE_COMMENT_ID",
})

# Base daemon environment keys permitted to pass into child workers (OS + LLM provider keys).
BASE_PASSTHROUGH_ENV_KEYS: frozenset[str] = frozenset({
    "PATH",
    "LANG",
    "LC_ALL",
    "TZ",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "COMSPEC",
    "PATHEXT",
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALLINAGENT_ROOT",
    "ALLINAGENT_WORKSPACE_ROOT",
    "ALLINAGENT_REPORTS_ROOT",
    "SKILL_TOOLS_PYTHON",
    "SKILL_NODE_TOOLS_DIR",
    "CHROMIUM_BIN",
    "PLAYWRIGHT_BROWSERS_PATH",
    # LLM inference credentials & endpoints configured for workers
    "CUSTOM_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "ANTHROPIC_API_KEY",
    "NOUS_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "ZAI_API_KEY",
    "DEEPSEEK_API_KEY",
    "GROQ_API_KEY",
    "KIMI_API_KEY",
    "MINIMAX_API_KEY",
    "XAI_API_KEY",
    "LLM_BASE_URL",
    "LLM_MODEL",
    "OPENAI_BASE_URL",
})

SAFE_CLIENT_HERMES_KEYS: frozenset[str] = frozenset({
    "HERMES_EPHEMERAL_SYSTEM_PROMPT",
    "HERMES_QUIET",
    "HERMES_MODEL",
    "HERMES_PROVIDER",
    "HERMES_MAX_TURNS",
    "HERMES_TOOLSETS",
    "HERMES_INSTALL_ROOT",
})

LIGHTWEIGHT_PROBE_ARGS: frozenset[tuple[str, ...]] = frozenset({
    ("--version",),
    ("-V",),
    ("--help",),
    ("-h",),
    ("version",),
    ("chat", "--help"),
    ("chat", "-h"),
})

MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024  # 8 MiB ceiling for large --query-file prompts
DEFAULT_WORKER_TIMEOUT_SEC = 300
MAX_WORKER_TIMEOUT_SEC = 900


DEFAULT_HERMES_HOME = "/var/lib/allinagent/hermes"

_DISALLOWED_PLACEHOLDER_OWNER_IDS: frozenset[str] = frozenset({
    "",
    "0",
    "1" + ("0" * 9),
    "123456789",
    "1234567890",
    "changeme",
    "your_telegram_id",
    "none",
    "null",
    "unset",
    "undefined",
})

_DAEMON_REDACT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bsk-(?:ant-|or-v1-|proj-)?[A-Za-z0-9_-]{12,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b"), "[REDACTED_TELEGRAM_TOKEN]"),
    (re.compile(r"\b(?:ob_tok|st_tok|pcp)_[A-Za-z0-9_-]{8,}\b"), "[REDACTED_INTERNAL_TOKEN]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{12,}"), r"\1[REDACTED_BEARER]"),
)

_ALLOWED_TELEGRAM_DOC_EXTENSIONS: frozenset[str] = frozenset({
    ".pdf",
    ".docx",
    ".md",
    ".json",
    ".txt",
    ".sarif",
    ".csv",
})


def _sanitize_daemon_text(text: str, extra_secret: str = "") -> str:
    out = str(text or "")
    if extra_secret and extra_secret in out:
        out = out.replace(extra_secret, "[REDACTED_SECRET]")
    for rx, repl in _DAEMON_REDACT_PATTERNS:
        out = rx.sub(repl, out)
    return out


def resolve_valid_owner_telegram_id(raw_value: str | None = None) -> str:
    cand = str(raw_value if raw_value is not None else os.environ.get("OWNER_TELEGRAM_ID", "")).strip()
    if cand.lower() in _DISALLOWED_PLACEHOLDER_OWNER_IDS:
        return ""
    if not cand.isdigit() or int(cand) <= 0:
        return ""
    return cand


def resolve_platform_cli_script() -> Path:
    explicit_root = os.environ.get("ALLINAGENT_ROOT", "").strip()
    candidates = [
        Path(explicit_root) / "apps" / "control-center" / "control_center" / "platform_cli.py"
        if explicit_root
        else None,
        Path("/opt/allinagent/apps/control-center/control_center/platform_cli.py"),
        Path(__file__).resolve().parents[2] / "apps" / "control-center" / "control_center" / "platform_cli.py",
    ]
    for cand in candidates:
        if cand is not None and cand.is_file():
            return cand.resolve()
    return Path("/opt/allinagent/apps/control-center/control_center/platform_cli.py")


def _resolve_authorized_attachment_roots() -> list[Path]:
    explicit_root = Path(
        os.environ.get("ALLINAGENT_ROOT", "").strip()
        or str(Path(__file__).resolve().parents[2])
    ).expanduser()
    raw_candidates = [
        os.environ.get("ALLINAGENT_REPORTS_ROOT", "").strip(),
        os.environ.get("ALLINAGENT_REPORTS_DIR", "").strip(),
        os.environ.get("ALLINAGENT_WORKSPACE_ROOT", "").strip(),
        os.environ.get("ALLINAGENT_WORKSPACES_DIR", "").strip(),
        "/var/lib/allinagent/reports" if os.name != "nt" else "",
        "/var/lib/allinagent/workspaces" if os.name != "nt" else "",
        str(explicit_root / "data" / "reports"),
        str(explicit_root / "reports"),
        str(explicit_root / "workspaces"),
    ]
    roots: list[Path] = []
    seen: set[str] = set()
    for raw in raw_candidates:
        if not raw:
            continue
        rp = Path(raw).expanduser().resolve()
        key = str(rp).lower() if os.name == "nt" else str(rp)
        if key not in seen:
            seen.add(key)
            roots.append(rp)
    return roots


def validate_telegram_attachment_path(raw_path: str) -> Path:
    cleaned = str(raw_path or "").strip()
    if not cleaned or "\x00" in cleaned:
        raise ValueError("Invalid attachment path.")
    slash_norm = cleaned.replace("\\", "/")
    segments = [s for s in slash_norm.split("/") if s]
    if ".." in segments or slash_norm == "~" or slash_norm.startswith("~/"):
        raise PermissionError("Path traversal or home-relative attachment path is forbidden.")
    for seg in segments:
        if seg.lower() in {".ssh", ".gnupg", ".aws", ".kube", "secrets", ".certs"}:
            raise PermissionError(f"Protected directory '{seg}' is forbidden.")

    roots = _resolve_authorized_attachment_roots()
    if not roots:
        raise PermissionError("No authorized report/workspace roots configured.")

    cand = Path(cleaned)
    if not cand.is_absolute():
        matched_cand = next((r / cand for r in roots if (r / cand).exists()), roots[0] / cand)
        cand = matched_cand

    if cand.is_symlink():
        raise PermissionError("Symlink attachments are forbidden.")

    resolved = cand.resolve()
    low_name = resolved.name.lower()
    if (
        low_name == ".env"
        or low_name.startswith(".env.")
        or "secret" in low_name
        or "auth.json" in low_name
        or ".local." in low_name
        or low_name.endswith((".local", ".pem", ".key", ".pfx", ".p12"))
        or low_name.startswith(("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"))
    ):
        raise PermissionError("Refusing to transmit protected credential file via Telegram.")

    if not any(resolved == root or resolved.is_relative_to(root) for root in roots):
        raise PermissionError("Attachment path is outside ALLINAGENT_REPORTS_ROOT / ALLINAGENT_WORKSPACE_ROOT.")

    if resolved.suffix.lower() not in _ALLOWED_TELEGRAM_DOC_EXTENSIONS:
        raise ValueError(f"Unsupported attachment extension '{resolved.suffix}'.")

    if not resolved.is_file():
        raise FileNotFoundError("Requested attachment file does not exist.")

    if resolved.stat().st_size > 45 * 1024 * 1024:
        raise ValueError("Attachment exceeds 45 MiB Telegram upload ceiling.")

    return resolved


def _deliver_telegram_sync(
    *,
    api_base: str,
    bot_token: str,
    owner_id: str,
    message_text: str,
    attachment_path: Path | None,
    caption: str,
) -> dict[str, Any]:
    safe_msg = _sanitize_daemon_text(message_text, bot_token)[:3900]
    safe_caption = _sanitize_daemon_text(caption, bot_token)[:950]
    message_id: Any = None
    document_message_id: Any = None

    if attachment_path is not None:
        # Send standalone text first only if both message_text and an explicit separate caption were supplied
        effective_caption = safe_caption or safe_msg[:950]
        if safe_msg and safe_caption:
            msg_req = urllib.request.Request(
                f"{api_base}/bot{bot_token}/sendMessage",
                data=json.dumps(
                    {
                        "chat_id": owner_id,
                        "text": safe_msg,
                        "disable_web_page_preview": True,
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(msg_req, timeout=15) as resp:
                m_body = json.loads(resp.read().decode("utf-8", errors="replace"))
                message_id = (m_body.get("result") or {}).get("message_id")

        boundary = f"----ALLINAGENTBoundary{uuid.uuid4().hex}"
        mime_type = mimetypes.guess_type(attachment_path.name)[0] or "application/octet-stream"
        parts: list[bytes] = [
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="chat_id"\r\n\r\n'
                f"{owner_id}\r\n"
            ).encode("utf-8")
        ]
        if effective_caption:
            parts.append(
                (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="caption"\r\n\r\n'
                    f"{effective_caption}\r\n"
                ).encode("utf-8")
            )
        parts.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="document"; filename="{attachment_path.name}"\r\n'
                f"Content-Type: {mime_type}\r\n\r\n"
            ).encode("utf-8")
            + attachment_path.read_bytes()
            + b"\r\n"
        )
        parts.append(f"--{boundary}--\r\n".encode("utf-8"))
        doc_req = urllib.request.Request(
            f"{api_base}/bot{bot_token}/sendDocument",
            data=b"".join(parts),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        with urllib.request.urlopen(doc_req, timeout=30) as resp:
            d_body = json.loads(resp.read().decode("utf-8", errors="replace"))
            ok = bool(d_body.get("ok"))
            document_message_id = (d_body.get("result") or {}).get("message_id")
            return {
                "ok": True,
                "delivered": ok,
                "message_id": document_message_id or message_id,
                "document_sent": ok,
            }

    msg_req = urllib.request.Request(
        f"{api_base}/bot{bot_token}/sendMessage",
        data=json.dumps(
            {
                "chat_id": owner_id,
                "text": safe_msg,
                "disable_web_page_preview": True,
            }
        ).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(msg_req, timeout=15) as resp:
        body = json.loads(resp.read().decode("utf-8", errors="replace"))
        ok = bool(body.get("ok"))
        return {
            "ok": True,
            "delivered": ok,
            "message_id": (body.get("result") or {}).get("message_id"),
        }


def get_profiles_root() -> Path:
    raw = os.environ.get("HERMES_PROFILES_ROOT", "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    hermes_home = os.environ.get("HERMES_HOME", DEFAULT_HERMES_HOME).strip() or DEFAULT_HERMES_HOME
    return Path(os.path.join(hermes_home, "profiles")).expanduser().resolve()


def resolve_hermes_invocation() -> list[str]:
    """Resolve the underlying real Python/Hermes invocation inside the Hermes container."""
    explicit_bin = os.environ.get("HERMES_REAL_BIN", "").strip()
    if explicit_bin and Path(explicit_bin).exists():
        return [explicit_bin]

    source_dir = os.environ.get("HERMES_SOURCE_DIR", "/opt/hermes-agent").strip()
    if source_dir and (Path(source_dir) / "hermes_cli" / "main.py").is_file():
        return [sys.executable, "-m", "hermes_cli.main"]

    which_hermes = shutil.which("hermes")
    if which_hermes:
        return [which_hermes]

    return [sys.executable, "-m", "hermes_cli.main"]


def is_lightweight_probe(argv: list[str]) -> bool:
    return tuple(argv) in LIGHTWEIGHT_PROBE_ARGS


def extract_and_strip_profile_args(argv: list[str]) -> tuple[str | None, list[str]]:
    """Extract `-p <profile>` / `--profile <profile>` / `--profile=<profile>` and return stripped argv."""
    found_profile: str | None = None
    cleaned: list[str] = []
    i = 0
    while i < len(argv):
        tok = str(argv[i])
        if tok in ("-p", "--profile") and i + 1 < len(argv):
            if found_profile is None:
                found_profile = str(argv[i + 1]).strip()
            i += 2
            continue
        if tok.startswith("--profile="):
            if found_profile is None:
                found_profile = tok.split("=", 1)[1].strip()
            i += 1
            continue
        cleaned.append(tok)
        i += 1
    return found_profile, cleaned


def extract_profile_from_hermes_home(raw_home: str) -> str | None:
    norm = raw_home.strip().replace("\\", "/").rstrip("/")
    if not norm:
        return None
    parts = [p for p in norm.split("/") if p]
    if len(parts) >= 2 and parts[-2] == "profiles":
        return parts[-1]
    return None


def resolve_validated_profile(
    payload: dict[str, Any],
    argv_profile: str | None,
    client_env: dict[str, Any],
) -> str:
    """Resolve and strictly validate the worker profile against ALLOWED_PROFILES."""
    candidates = [
        str(payload.get("profile") or "").strip(),
        str(argv_profile or "").strip(),
        str(client_env.get("HERMES_PROFILE") or "").strip(),
        extract_profile_from_hermes_home(str(client_env.get("HERMES_HOME") or "")) or "",
    ]
    profile = next((c for c in candidates if c), "")
    if not profile:
        raise ValueError(
            "Missing corporate worker profile. Expected one of: " + ", ".join(ALLOWED_PROFILES)
        )
    if not re.fullmatch(r"pc[a-z0-9]{2,30}", profile) or profile not in ALLOWED_PROFILES_SET:
        raise ValueError(
            f"Unauthorized or invalid Hermes worker profile {profile!r}. "
            f"Allowed profiles: {', '.join(ALLOWED_PROFILES)}"
        )
    return profile


def prepare_isolated_profile_home(profile: str, profiles_root: Path | None = None) -> Path:
    """Ensure `<HERMES_PROFILES_ROOT>/<profile>` exists with `0o700` mode and `.no-bundled-skills`."""
    if profile not in ALLOWED_PROFILES_SET:
        raise ValueError(f"Profile {profile!r} is not in ALLOWED_PROFILES")
    root = (profiles_root or get_profiles_root()).resolve()
    root.mkdir(parents=True, exist_ok=True)

    profile_home = (root / profile).resolve()
    if profile_home.parent != root:
        raise ValueError(f"Path traversal rejected for profile {profile!r}")

    profile_home.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(profile_home, 0o700)
    except OSError:
        pass

    for sub in PROFILE_SUBDIRS:
        sub_dir = profile_home / sub
        sub_dir.mkdir(parents=True, exist_ok=True)

    # Fix BUG-01: Hermes checks `.no-bundled-skills` (HYPHENS), not `.no_bundled_skills`.
    marker = profile_home / NO_BUNDLED_SKILLS_MARKER
    if not marker.is_file():
        marker.write_text("1\n", encoding="utf-8", newline="\n")
    legacy_marker = profile_home / LEGACY_UNDERSCORE_MARKER
    if legacy_marker.exists():
        try:
            legacy_marker.unlink()
        except OSError:
            pass

    return profile_home


def build_sanitized_worker_env(
    profile_home: Path,
    client_env: dict[str, Any],
) -> dict[str, str]:
    """Construct a clean child environment isolated to `profile_home` with zero Telegram/daemon secrets."""
    env: dict[str, str] = {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "TERM": "dumb",
        "NO_COLOR": "1",
    }

    for k, v in os.environ.items():
        if k in FORBIDDEN_WORKER_ENV_KEYS:
            continue
        if k in BASE_PASSTHROUGH_ENV_KEYS or k.startswith("UV_"):
            env[k] = v

    source_dir = os.environ.get("HERMES_SOURCE_DIR", "/opt/hermes-agent").strip()
    if source_dir and Path(source_dir).is_dir():
        existing_py = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{source_dir}{os.pathsep}{existing_py}" if existing_py else source_dir

    if isinstance(client_env, dict):
        for raw_k, raw_v in client_env.items():
            if not isinstance(raw_k, str) or raw_v is None:
                continue
            k = raw_k.strip()
            if not k or k in FORBIDDEN_WORKER_ENV_KEYS:
                continue
            val = str(raw_v)
            if "\x00" in k or "\x00" in val:
                continue
            if k in SAFE_PAPERCLIP_WORKER_ENV_KEYS:
                env[k] = val
            elif k in SAFE_CLIENT_HERMES_KEYS:
                env[k] = val

    # Authoritative isolation overrides — client can NEVER override these.
    env["HERMES_HOME"] = str(profile_home)
    env["HOME"] = str(profile_home / "home")

    # Final defensive sweep to guarantee forbidden tokens are absent.
    for forbidden in FORBIDDEN_WORKER_ENV_KEYS:
        env.pop(forbidden, None)

    return env


def rewrite_query_file_args(argv: list[str], query_file_content: str | None) -> tuple[list[str], Path | None]:
    """If `--query-file` is used or `query_file_content` is supplied, materialize a `0o600` temp file."""
    has_qfile_flag = any(tok == "--query-file" or tok.startswith("--query-file=") for tok in argv)
    if query_file_content is None and not has_qfile_flag:
        return list(argv), None

    if query_file_content is None:
        raise ValueError("--query-file flag present in argv without query_file_content payload")
    if not str(query_file_content).strip():
        raise ValueError("--query-file content is empty")

    fd, tmp_name = tempfile.mkstemp(prefix="allinagent-hermes-query-", suffix=".txt")
    tmp_path = Path(tmp_name)
    try:
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(str(query_file_content))
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

    rewritten: list[str] = []
    replaced = False
    i = 0
    while i < len(argv):
        tok = str(argv[i])
        if tok == "--query-file":
            rewritten.extend(["--query-file", str(tmp_path)])
            replaced = True
            i += 2 if i + 1 < len(argv) else 1
            continue
        if tok.startswith("--query-file="):
            rewritten.extend(["--query-file", str(tmp_path)])
            replaced = True
            i += 1
            continue
        rewritten.append(tok)
        i += 1

    if not replaced:
        rewritten.extend(["--query-file", str(tmp_path)])

    return rewritten, tmp_path


def resolve_safe_cwd(requested_cwd: str | None, profile_home: Path) -> Path:
    fallback = profile_home / "workspace"
    fallback.mkdir(parents=True, exist_ok=True)
    if not requested_cwd or requested_cwd.strip() in ("", "."):
        return fallback

    candidate = Path(requested_cwd.strip())
    if not candidate.is_absolute() or not candidate.is_dir():
        return fallback

    resolved = candidate.resolve()
    forbidden_prefixes = [
        Path("/etc"),
        Path("/proc"),
        Path("/sys"),
        Path("/root/.ssh"),
        get_profiles_root().parent.resolve(),
    ]
    for fp in forbidden_prefixes:
        try:
            if resolved == fp or (fp != get_profiles_root().parent.resolve() and fp in resolved.parents):
                return fallback
        except OSError:
            return fallback

    # Allow inside profile's own workspace, or any non-hermes-root directory (e.g. /data/workspaces, /opt/allinagent/workspaces)
    hermes_root = get_profiles_root().parent.resolve()
    if hermes_root in resolved.parents and profile_home not in (resolved, *resolved.parents):
        return fallback

    return resolved


async def terminate_process_tree(proc: asyncio.subprocess.Process, grace_sec: float = 5.0) -> None:
    if proc.returncode is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(proc.pid, signal.SIGTERM)
        else:
            proc.terminate()
    except ProcessLookupError:
        return
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass

    try:
        await asyncio.wait_for(proc.wait(), timeout=grace_sec)
        return
    except asyncio.TimeoutError:
        pass

    try:
        if os.name != "nt":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        await asyncio.wait_for(proc.wait(), timeout=2.0)
    except Exception:
        pass


class HermesExecDaemon:
    def __init__(self) -> None:
        self.max_concurrency = max(1, int(os.environ.get("HEAVY_WORKER_CONCURRENCY", "1")))
        self.max_queue_size = max(1, int(os.environ.get("MAX_WORKER_QUEUE_SIZE", "32")))
        self.heavy_semaphore = asyncio.Semaphore(self.max_concurrency)
        self.probe_semaphore = asyncio.Semaphore(4)
        self.active_workers = 0
        self.queued_workers = 0
        self.total_completed = 0
        self.started_at = time.time()
        self._active_procs: set[asyncio.subprocess.Process] = set()

    def _verify_auth(self, headers: dict[str, str]) -> tuple[bool, int, str]:
        expected = (
            os.environ.get("ALLINAGENT_INTERNAL_TOKEN", "").strip()
            or os.environ.get("HERMES_EXEC_SHARED_SECRET", "").strip()
        )
        if not expected:
            return (
                False,
                503,
                "ALLINAGENT_INTERNAL_TOKEN (or HERMES_EXEC_SHARED_SECRET) is not configured on hermes-exec-daemon (fail-closed)",
            )

        provided = (
            headers.get("x-internal-exec-token", "").strip()
            or headers.get("x-hermes-exec-secret", "").strip()
            or headers.get("x-allinagent-internal-token", "").strip()
        )
        if not provided:
            auth_hdr = headers.get("authorization", "").strip()
            if auth_hdr.lower().startswith("bearer "):
                provided = auth_hdr[7:].strip()

        if not provided or not hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")):
            return False, 401, "Unauthorized: invalid or missing X-Internal-Exec-Token"
        return True, 200, ""

    def health_payload(self) -> dict[str, Any]:
        return {
            "ok": True,
            "service": "hermes-exec-daemon",
            "status": "healthy",
            "uptime_sec": int(max(0.0, time.time() - self.started_at)),
            "max_concurrency": self.max_concurrency,
            "active_workers": self.active_workers,
            "queued_workers": self.queued_workers,
            "max_queue_size": self.max_queue_size,
            "total_completed": self.total_completed,
            "profiles_root": str(get_profiles_root()),
            "allowed_profiles": list(ALLOWED_PROFILES),
        }

    async def _spawn_and_collect(
        self,
        cmd: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout_sec: float,
    ) -> tuple[int, str, str, bool]:
        popen_kwargs: dict[str, Any] = {}
        if os.name != "nt":
            popen_kwargs["start_new_session"] = True

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd),
            env=env,
            **popen_kwargs,
        )
        self._active_procs.add(proc)
        timed_out = False
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
        except asyncio.TimeoutError:
            timed_out = True
            await terminate_process_tree(proc)
            stdout_bytes = b""
            stderr_bytes = f"[hermes-exec-daemon] Worker timed out after {int(timeout_sec)}s\n".encode("utf-8")
        except asyncio.CancelledError:
            await terminate_process_tree(proc)
            raise
        finally:
            self._active_procs.discard(proc)

        exit_code = proc.returncode if proc.returncode is not None else (124 if timed_out else 1)
        if timed_out and exit_code == 0:
            exit_code = 124
        return (
            int(exit_code),
            stdout_bytes.decode("utf-8", errors="replace"),
            stderr_bytes.decode("utf-8", errors="replace"),
            timed_out,
        )

    async def execute_request(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        t0 = time.monotonic()
        raw_argv = payload.get("argv")
        if not isinstance(raw_argv, list) or not all(isinstance(x, (str, int, float)) for x in raw_argv):
            return 400, {
                "ok": False,
                "error": "Field 'argv' must be a list of strings",
                "exit_code": 2,
                "stdout": "",
                "stderr": "Error: invalid argv payload\n",
                "duration_ms": 0,
            }

        argv = [str(x) for x in raw_argv]
        if any("\x00" in x for x in argv):
            return 400, {
                "ok": False,
                "error": "Null byte in argv rejected",
                "exit_code": 2,
                "stdout": "",
                "stderr": "Error: invalid character in argv\n",
                "duration_ms": 0,
            }

        # Prevent remote callers from spawning long-lived daemons via the worker RPC bridge.
        if len(argv) >= 2 and argv[0] == "gateway" and argv[1] in ("run", "start", "install"):
            return 403, {
                "ok": False,
                "error": "Gateway lifecycle commands are forbidden on worker exec endpoint",
                "exit_code": 77,
                "stdout": "",
                "stderr": "Error: gateway commands cannot be invoked via worker exec daemon\n",
                "duration_ms": 0,
            }

        base_cmd = resolve_hermes_invocation()

        # Fast-path: non-LLM metadata probe (`--version`, `--help`) bypasses heavy LLM worker semaphore.
        if is_lightweight_probe(argv):
            probe_dir = Path(tempfile.gettempdir()) / "allinagent-hermes-probe"
            probe_dir.mkdir(parents=True, exist_ok=True)
            (probe_dir / "home").mkdir(parents=True, exist_ok=True)
            probe_env = build_sanitized_worker_env(probe_dir, {})
            async with self.probe_semaphore:
                rc, out, err, timed_out = await self._spawn_and_collect(
                    [*base_cmd, *argv],
                    cwd=probe_dir,
                    env=probe_env,
                    timeout_sec=15.0,
                )
            duration_ms = int(round((time.monotonic() - t0) * 1000))
            return 200, {
                "ok": rc == 0,
                "exit_code": rc,
                "stdout": out,
                "stderr": err,
                "duration_ms": duration_ms,
                "timed_out": timed_out,
                "profile": None,
            }

        client_env = payload.get("env") if isinstance(payload.get("env"), dict) else {}
        argv_profile, stripped_argv = extract_and_strip_profile_args(argv)
        try:
            profile = resolve_validated_profile(payload, argv_profile, client_env)
            profile_home = prepare_isolated_profile_home(profile)
        except ValueError as exc:
            duration_ms = int(round((time.monotonic() - t0) * 1000))
            return 400, {
                "ok": False,
                "error": str(exc),
                "exit_code": 2,
                "stdout": "",
                "stderr": f"Error: {exc}\n",
                "duration_ms": duration_ms,
            }

        if self.queued_workers >= self.max_queue_size:
            duration_ms = int(round((time.monotonic() - t0) * 1000))
            return 429, {
                "ok": False,
                "error": f"Worker queue full ({self.queued_workers}/{self.max_queue_size})",
                "exit_code": 75,
                "stdout": "",
                "stderr": "Error: Hermes worker queue at capacity; retry shortly.\n",
                "duration_ms": duration_ms,
            }

        raw_timeout = payload.get("timeout_sec")
        try:
            timeout_sec = float(raw_timeout) if raw_timeout is not None else float(DEFAULT_WORKER_TIMEOUT_SEC)
        except (TypeError, ValueError):
            timeout_sec = float(DEFAULT_WORKER_TIMEOUT_SEC)
        timeout_sec = max(5.0, min(timeout_sec, float(MAX_WORKER_TIMEOUT_SEC)))

        temp_query_file: Path | None = None
        try:
            q_content = payload.get("query_file_content")
            if q_content is not None and not isinstance(q_content, str):
                q_content = str(q_content)
            final_argv, temp_query_file = rewrite_query_file_args(stripped_argv, q_content)
        except ValueError as exc:
            duration_ms = int(round((time.monotonic() - t0) * 1000))
            return 400, {
                "ok": False,
                "error": str(exc),
                "exit_code": 2,
                "stdout": "",
                "stderr": f"Error: {exc}\n",
                "duration_ms": duration_ms,
            }

        child_env = build_sanitized_worker_env(profile_home, client_env)
        child_cwd = resolve_safe_cwd(
            str(payload.get("cwd") or "") if payload.get("cwd") is not None else None,
            profile_home,
        )

        try:
            self.queued_workers += 1
            logger.info(
                "Queued worker profile=%s (queued=%d, active=%d/%d)",
                profile,
                self.queued_workers,
                self.active_workers,
                self.max_concurrency,
            )
            try:
                await self.heavy_semaphore.acquire()
            finally:
                self.queued_workers = max(0, self.queued_workers - 1)

            self.active_workers += 1
            try:
                logger.info(
                    "Starting worker profile=%s timeout=%ds cwd=%s",
                    profile,
                    int(timeout_sec),
                    child_cwd,
                )
                rc, out, err, timed_out = await self._spawn_and_collect(
                    [*base_cmd, *final_argv],
                    cwd=child_cwd,
                    env=child_env,
                    timeout_sec=timeout_sec,
                )
                self.total_completed += 1
            finally:
                self.active_workers = max(0, self.active_workers - 1)
                self.heavy_semaphore.release()
        finally:
            if temp_query_file is not None:
                temp_query_file.unlink(missing_ok=True)

        duration_ms = int(round((time.monotonic() - t0) * 1000))
        logger.info(
            "Finished worker profile=%s exit_code=%d timed_out=%s duration_ms=%d",
            profile,
            rc,
            timed_out,
            duration_ms,
        )
        return 200, {
            "ok": rc == 0 and not timed_out,
            "exit_code": rc,
            "stdout": out,
            "stderr": err,
            "duration_ms": duration_ms,
            "timed_out": timed_out,
            "profile": profile,
        }

    async def execute_cli_request(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        raw_args = payload.get("args")
        if (
            not isinstance(raw_args, list)
            or len(raw_args) > 64
            or not all(isinstance(x, (str, int, float)) for x in raw_args)
        ):
            return 400, {
                "ok": False,
                "error": "Field 'args' must be a list of at most 64 strings",
                "exit_code": 2,
                "stdout": "",
                "stderr": "Error: invalid args payload\n",
                "parsed": None,
            }

        str_args = [str(x) for x in raw_args]
        if any("\x00" in x for x in str_args):
            return 400, {
                "ok": False,
                "error": "Null byte in args rejected",
                "exit_code": 2,
                "stdout": "",
                "stderr": "Error: null byte in args\n",
                "parsed": None,
            }

        cli_script = resolve_platform_cli_script()
        if not cli_script.is_file():
            return 404, {
                "ok": False,
                "error": f"Allowlisted CLI script not found at {cli_script}",
                "exit_code": 127,
                "stdout": "",
                "stderr": "Error: platform_cli.py not found\n",
                "parsed": None,
            }

        raw_timeout = payload.get("timeout_sec")
        try:
            timeout_sec = float(raw_timeout) if raw_timeout is not None else 45.0
        except (TypeError, ValueError):
            timeout_sec = 45.0
        timeout_sec = max(3.0, min(timeout_sec, 120.0))

        pkg_root = cli_script.parents[1]
        repo_root = cli_script.parents[3]
        cli_env = dict(os.environ)
        cli_env["PYTHONDONTWRITEBYTECODE"] = "1"
        cli_env["PYTHONUTF8"] = "1"
        existing_py = cli_env.get("PYTHONPATH", "")
        prepend_py = f"{pkg_root}{os.pathsep}{repo_root}"
        cli_env["PYTHONPATH"] = f"{prepend_py}{os.pathsep}{existing_py}" if existing_py else prepend_py

        async with self.probe_semaphore:
            rc, out, err, timed_out = await self._spawn_and_collect(
                [sys.executable, "-B", str(cli_script), *str_args],
                cwd=repo_root if repo_root.is_dir() else cli_script.parent,
                env=cli_env,
                timeout_sec=timeout_sec,
            )

        safe_out = _sanitize_daemon_text(out)
        safe_err = _sanitize_daemon_text(err)
        parsed: Any = None
        trimmed = safe_out.strip()
        if trimmed:
            try:
                parsed = json.loads(trimmed)
            except json.JSONDecodeError:
                first_brace = trimmed.find("{")
                if first_brace >= 0:
                    try:
                        parsed = json.loads(trimmed[first_brace:])
                    except json.JSONDecodeError:
                        parsed = None

        return 200, {
            "ok": rc == 0 and not timed_out,
            "exit_code": rc,
            "stdout": safe_out,
            "stderr": safe_err,
            "parsed": parsed,
        }

    async def handle_telegram_notify(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        msg_text = str(payload.get("text") or payload.get("message") or "").strip()
        doc_raw = str(payload.get("document_path") or payload.get("file_path") or "").strip()
        caption = str(payload.get("caption") or "").strip()

        if not msg_text and not doc_raw:
            return 400, {
                "ok": False,
                "delivered": False,
                "error": "Either 'text'/'message' or 'document_path'/'file_path' is required.",
            }

        validated_doc: Path | None = None
        if doc_raw:
            try:
                validated_doc = validate_telegram_attachment_path(doc_raw)
            except PermissionError as exc:
                return 403, {"ok": False, "delivered": False, "error": _sanitize_daemon_text(str(exc))}
            except FileNotFoundError as exc:
                return 404, {"ok": False, "delivered": False, "error": _sanitize_daemon_text(str(exc))}
            except ValueError as exc:
                return 400, {"ok": False, "delivered": False, "error": _sanitize_daemon_text(str(exc))}

        bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        owner_id = resolve_valid_owner_telegram_id()
        if not bot_token or not owner_id:
            return 200, {
                "ok": True,
                "delivered": False,
                "reason": "telegram_not_configured",
            }

        api_base = (
            os.environ.get("TELEGRAM_API_BASE_URL", "https://api.telegram.org").strip().rstrip("/")
            or "https://api.telegram.org"
        )
        try:
            res = await asyncio.to_thread(
                _deliver_telegram_sync,
                api_base=api_base,
                bot_token=bot_token,
                owner_id=owner_id,
                message_text=msg_text,
                attachment_path=validated_doc,
                caption=caption,
            )
            return 200, res
        except Exception as exc:
            safe_reason = _sanitize_daemon_text(str(exc), bot_token)[:180]
            return 200, {
                "ok": True,
                "delivered": False,
                "reason": safe_reason or "telegram_delivery_failed",
            }

    async def shutdown(self) -> None:
        procs = list(self._active_procs)
        if procs:
            logger.info("Terminating %d active worker subprocess(es)...", len(procs))
            await asyncio.gather(*(terminate_process_tree(p) for p in procs), return_exceptions=True)


HTTP_STATUS_TEXT: dict[int, str] = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    413: "Payload Too Large",
    429: "Too Many Requests",
    500: "Internal Server Error",
    503: "Service Unavailable",
}


async def _write_json_response(
    writer: asyncio.StreamWriter,
    status_code: int,
    body_obj: dict[str, Any],
) -> None:
    payload = json.dumps(body_obj, ensure_ascii=False).encode("utf-8")
    reason = HTTP_STATUS_TEXT.get(status_code, "OK")
    head = (
        f"HTTP/1.1 {status_code} {reason}\r\n"
        f"Content-Type: application/json; charset=utf-8\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii")
    writer.write(head + payload)
    await writer.drain()


async def handle_http_client(
    daemon: HermesExecDaemon,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    try:
        req_line_bytes = await asyncio.wait_for(reader.readline(), timeout=15.0)
        if not req_line_bytes:
            return
        req_line = req_line_bytes.decode("latin-1", errors="replace").strip()
        parts = req_line.split(" ")
        if len(parts) < 2:
            await _write_json_response(writer, 400, {"ok": False, "error": "Malformed HTTP request line"})
            return
        method = parts[0].upper()
        raw_target = parts[1].split("?", 1)[0]

        headers: dict[str, str] = {}
        while True:
            hdr_line = await asyncio.wait_for(reader.readline(), timeout=15.0)
            if not hdr_line or hdr_line in (b"\r\n", b"\n"):
                break
            decoded = hdr_line.decode("latin-1", errors="replace").strip()
            if ":" in decoded:
                k, v = decoded.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        if method == "GET" and raw_target in ("/health", "/healthz", "/v1/health"):
            await _write_json_response(writer, 200, daemon.health_payload())
            return

        if raw_target not in ("/v1/exec", "/exec", "/api/cli", "/api/telegram/notify"):
            await _write_json_response(writer, 404, {"ok": False, "error": f"Unknown route: {raw_target}"})
            return

        if method != "POST":
            await _write_json_response(writer, 405, {"ok": False, "error": "Method not allowed; use POST"})
            return

        auth_ok, auth_code, auth_err = daemon._verify_auth(headers)
        if not auth_ok:
            await _write_json_response(
                writer,
                auth_code,
                {"ok": False, "error": auth_err, "exit_code": 77, "stdout": "", "stderr": auth_err + "\n", "duration_ms": 0},
            )
            return

        content_len = int(headers.get("content-length", "0") or "0")
        if content_len < 0 or content_len > MAX_REQUEST_BODY_BYTES:
            await _write_json_response(writer, 413, {"ok": False, "error": "Request payload exceeds 8 MiB limit"})
            return

        raw_body = await asyncio.wait_for(reader.readexactly(content_len), timeout=30.0) if content_len > 0 else b"{}"
        try:
            payload = json.loads(raw_body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("JSON body must be an object")
        except Exception as exc:
            await _write_json_response(writer, 400, {"ok": False, "error": f"Invalid JSON payload: {exc}"})
            return

        if raw_target == "/api/cli":
            status_code, resp_body = await daemon.execute_cli_request(payload)
        elif raw_target == "/api/telegram/notify":
            status_code, resp_body = await daemon.handle_telegram_notify(payload)
        else:
            status_code, resp_body = await daemon.execute_request(payload)
        await _write_json_response(writer, status_code, resp_body)
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as exc:
        logger.exception("Unhandled error in hermes-exec-daemon HTTP handler: %s", exc)
        try:
            await _write_json_response(
                writer,
                500,
                {"ok": False, "error": "Internal daemon error", "exit_code": 1, "stdout": "", "stderr": "Internal daemon error\n", "duration_ms": 0},
            )
        except Exception:
            pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def run_server(host: str, port: int) -> int:
    daemon = HermesExecDaemon()
    # Pre-seed all 11 isolated profile homes on daemon boot
    profiles_root = get_profiles_root()
    for prof in ALLOWED_PROFILES:
        prepare_isolated_profile_home(prof, profiles_root)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig_name in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try:
                loop.add_signal_handler(sig, stop_event.set)
            except NotImplementedError:
                # Windows ProactorEventLoop fallback
                signal.signal(sig, lambda *_: loop.call_soon_threadsafe(stop_event.set))

    server = await asyncio.start_server(
        lambda r, w: handle_http_client(daemon, r, w),
        host=host,
        port=port,
    )
    addrs = ", ".join(str(s.getsockname()) for s in (server.sockets or []))
    logger.info(
        "Listening on %s (HEAVY_WORKER_CONCURRENCY=%d, profiles_root=%s)",
        addrs,
        daemon.max_concurrency,
        profiles_root,
    )

    try:
        await stop_event.wait()
    finally:
        logger.info("Shutting down hermes-exec-daemon...")
        server.close()
        await server.wait_closed()
        await daemon.shutdown()
    return 0


def main() -> int:
    host = os.environ.get("HERMES_EXEC_HOST", "0.0.0.0").strip() or "0.0.0.0"
    port = int(os.environ.get("HERMES_EXEC_PORT", "8650"))
    return asyncio.run(run_server(host, port))


if __name__ == "__main__":
    sys.exit(main())
