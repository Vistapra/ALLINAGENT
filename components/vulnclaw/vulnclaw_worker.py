#!/usr/bin/env python3
"""ALLINAGENT Phase 10 — VulnClaw Lightweight On-Demand Defensive Sandbox Worker.

Architecture & Security Guarantees:
- Pure Python stdlib + asyncio parent HTTP/CLI worker (`127.0.0.1` / internal port `8660`)
  with idle resident memory `< 25 MB` (~14-19 MB empirical RSS).
- Constant-time `X-Internal-Scan-Token` authentication verified against
  `ALLINAGENT_INTERNAL_TOKEN`.
- Defensive-only policy:
  * Blocks all 10 offensive capabilities (`exploit`, `payload`, `c2`, `reverse_shell`,
    `lateral_movement`, `credential_dump`, `privilege_escalation`, `network_scan`,
    `port_scan`, `traffic_intercept`).
  * Disables `BUILTIN_MCP_SERVERS` (`fetch`, `memory`, and all external MCP transports)
    and disables `python_execute` + L3 external LLM calls.
- Strict workspace path jail (`AUTHORIZED_WORKSPACES`, expected `:ro` mount):
  * Blocks `/etc`, `/proc`, `/sys`, `/root`, `/var/run`, `~/.ssh`, `.env*` (except
    `.env.example`/`.sample`/`.template`), `auth.json`, `office-bridge-auth.json`,
    `*.local.*`, private keys, path traversal (`..`), and symlink escapes.
  * Enforces `max_files=250`, per-file size limit `1 MB` (`1,048,576` bytes),
    wall-clock timeout `timeout_sec=60`, and response size cap `512 KB` (`524,288` bytes).
- Ephemeral child subprocess execution (`vulnclaw.codescan.scanner` L1+L2):
  * Runs each scan in a clean-env `-B` child Python process; 100% of scanner AST/regex/rule
    allocations are reclaimed by the OS kernel immediately upon scan completion.
- Emits structured sanitized JSON + SARIF 2.1.0 findings directly compatible with
  `FindingsStore.ingest_finding()`.
"""

from __future__ import annotations

import sys

# Internal loopback worker (`127.0.0.1:8660`) never terminates TLS directly; preventing
# eager OpenSSL (`_ssl` / `libssl` / `libcrypto`) loading saves ~7-9 MiB of resident RAM.
sys.modules.setdefault("ssl", None)  # type: ignore[arg-type]

import asyncio
import json
import os
import re
import time
from pathlib import Path
from typing import Any

try:
    from _operator import _compare_digest as _compare_digest
except ImportError:  # pragma: no cover
    import hmac as _hmac

    _compare_digest = _hmac.compare_digest

# ---------------------------------------------------------------------------
# Pinned Upstream & Worker Defaults
# ---------------------------------------------------------------------------
VULNCLAW_PINNED_VERSION = "0.4.1"
VULNCLAW_PINNED_COMMIT = "0b34878f84b089b21fcf85ecd445315f14df0672"

DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 8660
AUTH_HEADER_NAME = "x-internal-scan-token"
INTERNAL_TOKEN_ENV = "ALLINAGENT_INTERNAL_TOKEN"
FALLBACK_SCAN_TOKEN_ENV = "VULNCLAW_SCAN_TOKEN"


def _resolve_internal_scan_token(explicit: str | None = None) -> str:
    """Read ALLINAGENT_INTERNAL_TOKEN first, falling back to VULNCLAW_SCAN_TOKEN."""
    if explicit is not None:
        return explicit.strip()
    return (
        os.environ.get(INTERNAL_TOKEN_ENV, "").strip()
        or os.environ.get(FALLBACK_SCAN_TOKEN_ENV, "").strip()
    )


def _resolve_bind_host() -> str:
    """Accept both VULNCLAW_BIND_HOST and VULNCLAW_HOST environment variables."""
    return (
        os.environ.get("VULNCLAW_BIND_HOST", "").strip()
        or os.environ.get("VULNCLAW_HOST", "").strip()
        or DEFAULT_BIND_HOST
    )

HARD_MAX_FILES = 250
HARD_MAX_FILE_BYTES = 1_048_576  # 1 MiB per file
HARD_MAX_TIMEOUT_SEC = 60  # 60s wall-clock ceiling
HARD_MAX_OUTPUT_BYTES = 524_288  # 512 KiB serialized response cap
MAX_HTTP_HEADER_BYTES = 16_384
MAX_HTTP_BODY_BYTES = 65_536
IDLE_RSS_BUDGET_BYTES = 25 * 1024 * 1024  # 25 MiB target ceiling

# ---------------------------------------------------------------------------
# Defensive-Only Policy Definitions
# ---------------------------------------------------------------------------
BLOCKED_OFFENSIVE_CAPABILITIES: tuple[str, ...] = (
    "exploit",
    "payload",
    "c2",
    "reverse_shell",
    "lateral_movement",
    "credential_dump",
    "privilege_escalation",
    "network_scan",
    "port_scan",
    "traffic_intercept",
)

DISABLED_BUILTIN_MCP_SERVERS: tuple[str, ...] = (
    "fetch",
    "memory",
)

BLOCKED_TOOLS_AND_ENGINES: frozenset[str] = frozenset(
    {
        *BLOCKED_OFFENSIVE_CAPABILITIES,
        *DISABLED_BUILTIN_MCP_SERVERS,
        "python_execute",
        "chrome-devtools",
        "burp",
        "scanmalware",
        "solve",
        "run",
        "persistent",
        "recon",
        "scan_network",
        "shell_command",
        "http_probe_batch",
        "traffic_repeat",
    }
)

ALLOWED_SCAN_LAYERS: frozenset[str] = frozenset({"L1", "L2"})

# ---------------------------------------------------------------------------
# Path Jail & Secret Protection Rules
# ---------------------------------------------------------------------------
FORBIDDEN_POSIX_PREFIXES: tuple[str, ...] = (
    "/etc",
    "/proc",
    "/sys",
    "/root",
    "/var/run",
    "/run",
    "/boot",
    "/dev",
)

FORBIDDEN_DIR_SEGMENTS: frozenset[str] = frozenset(
    {
        ".ssh",
        ".gnupg",
        ".aws",
        ".kube",
        "secrets",
    }
)

SAFE_ENV_TEMPLATES: frozenset[str] = frozenset(
    {
        ".env.example",
        ".env.sample",
        ".env.template",
    }
)

FORBIDDEN_EXACT_FILENAMES: frozenset[str] = frozenset(
    {
        ".env",
        "auth.json",
        "office-bridge-auth.json",
        "deploy-secrets.local.ps1",
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
    }
)

FORBIDDEN_SECRET_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".pem",
        ".key",
        ".pfx",
        ".p12",
        ".kdbx",
    }
)

URL_TARGET_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

# ---------------------------------------------------------------------------
# Output Sanitization & Prompt-Injection Directive Neutralization
# ---------------------------------------------------------------------------
SECRET_REDACT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b"), "[REDACTED_BOT_TOKEN]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{12,}"), r"\1[REDACTED_TOKEN]"),
    (
        re.compile(
            r"(?i)((?:api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*['\"]?)(?!\[REDACTED_)[^\s'\",;]{6,}"
        ),
        r"\1[REDACTED_SECRET]",
    ),
)

DIRECTIVE_MARKER_RE = re.compile(
    r"(?i)(\[embedded_directive:[^\]]*\]|ignore\s+previous\s+instructions|system\s*override\s*:)"
)

CWE_RE = re.compile(r"^CWE-\d+$")
VALID_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class WorkerError(Exception):
    http_status: int = 400
    error_code: str = "BAD_REQUEST"

    def __init__(self, message: str, *, status: int | None = None, code: str | None = None) -> None:
        super().__init__(message)
        if status is not None:
            self.http_status = status
        if code is not None:
            self.error_code = code


class AuthError(WorkerError):
    http_status = 401
    error_code = "UNAUTHORIZED"


class OffensivePolicyError(WorkerError):
    http_status = 403
    error_code = "OFFENSIVE_CAPABILITY_BLOCKED"


class PathJailError(WorkerError):
    http_status = 403
    error_code = "PATH_JAIL_VIOLATION"


class TargetNotFoundError(WorkerError):
    http_status = 404
    error_code = "TARGET_NOT_FOUND"


class ScanTimeoutError(WorkerError):
    http_status = 504
    error_code = "SCAN_TIMEOUT"


# ---------------------------------------------------------------------------
# Process RSS Measurement (Pure Stdlib, Cross-Platform)
# ---------------------------------------------------------------------------
def get_process_memory_info() -> tuple[int, int]:
    """Return `(resident_private_or_vmrss_bytes, total_working_set_bytes)` using pure stdlib.

    - Linux: `(VmRSS, VmRSS)` from `/proc/self/status` (~14-18 MiB on python:3.12-slim).
    - Windows: `(PrivateUsage, WorkingSetSize)` via `K32GetProcessMemoryInfo`, matching
      Windows Task Manager private memory (~14-17 MiB) alongside total shared-DLL working set.
    """
    proc_status = Path("/proc/self/status")
    if proc_status.is_file():
        try:
            vm_rss = 0
            rss_anon = 0
            for line in proc_status.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        vm_rss = int(parts[1]) * 1024
                elif line.startswith("RssAnon:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        rss_anon = int(parts[1]) * 1024
            if vm_rss > 0:
                return vm_rss, (rss_anon or vm_rss)
        except OSError:
            pass

    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                    ("PrivateUsage", ctypes.c_size_t),
                ]

            pmc = PROCESS_MEMORY_COUNTERS_EX()
            pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.GetCurrentProcess.argtypes = []
            k32.GetCurrentProcess.restype = wintypes.HANDLE
            get_mem = getattr(k32, "K32GetProcessMemoryInfo", None)
            if get_mem is None:
                psapi = ctypes.WinDLL("psapi", use_last_error=True)
                get_mem = psapi.GetProcessMemoryInfo
            get_mem.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX),
                wintypes.DWORD,
            ]
            get_mem.restype = wintypes.BOOL
            if get_mem(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
                return int(pmc.PrivateUsage), int(pmc.WorkingSetSize)
        except Exception:
            pass

    try:
        import resource

        ru = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        val = int(ru) if sys.platform == "darwin" else int(ru) * 1024
        return val, val
    except Exception:
        return 0, 0


def get_process_rss_bytes() -> int:
    """Return process resident memory in bytes (VmRSS on Linux, PrivateUsage on Windows)."""
    rss_b, _ws_b = get_process_memory_info()
    return rss_b


# ---------------------------------------------------------------------------
# Sanitization & Normalization Helpers
# ---------------------------------------------------------------------------
def sanitize_text(text: str) -> str:
    """Redact credentials, tokens, private keys, and neutralize prompt directives."""
    out = str(text or "")
    for rx, repl in SECRET_REDACT_PATTERNS:
        out = rx.sub(repl, out)
    if DIRECTIVE_MARKER_RE.search(out):
        out = DIRECTIVE_MARKER_RE.sub("[DATA_LITERAL_DIRECTIVE_IGNORED]", out)
    return out


def is_forbidden_secret_filename(filename: str) -> bool:
    """Return True if a file basename matches protected .env* or credential patterns."""
    low = filename.strip().lower()
    if not low:
        return False
    if low in SAFE_ENV_TEMPLATES:
        return False
    if low in FORBIDDEN_EXACT_FILENAMES:
        return True
    if low.startswith(".env."):
        return True
    if ".local." in low or low.endswith(".local"):
        return True
    if low.startswith(("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")):
        return True
    _, ext = os.path.splitext(low)
    if ext in FORBIDDEN_SECRET_EXTENSIONS:
        return True
    return False


def parse_authorized_workspaces(
    raw_env: str | None = None,
    extra_roots: list[str] | None = None,
) -> list[Path]:
    """Parse AUTHORIZED_WORKSPACES across POSIX (`:`) and Windows (`;`) safely."""
    candidates: list[str] = []
    raw = (
        raw_env
        if raw_env is not None
        else os.environ.get("AUTHORIZED_WORKSPACES", "")
    ).strip()

    if raw:
        if raw.startswith("["):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    candidates.extend(str(x).strip() for x in parsed if str(x).strip())
            except json.JSONDecodeError:
                pass
        else:
            sep_pattern = r"[;,]" if os.name == "nt" else r"[:;,]"
            candidates.extend(p.strip() for p in re.split(sep_pattern, raw) if p.strip())

    if extra_roots:
        candidates.extend(str(p).strip() for p in extra_roots if str(p).strip())

    if not candidates:
        allin_root = os.environ.get("ALLINAGENT_ROOT", "").strip()
        if allin_root:
            candidates.append(str(Path(allin_root) / "workspaces"))
        elif Path("/workspaces").exists():
            candidates.append("/workspaces")
        else:
            candidates.append(str(Path(__file__).resolve().parent.parent.parent / "workspaces"))

    resolved_roots: list[Path] = []
    seen: set[str] = set()
    for item in candidates:
        norm_slash = item.replace("\\", "/")
        if any(
            norm_slash == pref or norm_slash.startswith(pref + "/")
            for pref in FORBIDDEN_POSIX_PREFIXES
        ):
            continue
        rp = Path(item).resolve()
        low_parts = {part.lower() for part in rp.parts}
        if low_parts & FORBIDDEN_DIR_SEGMENTS:
            continue
        key = str(rp).lower() if os.name == "nt" else str(rp)
        if key not in seen:
            seen.add(key)
            resolved_roots.append(rp)
    return resolved_roots


def _check_raw_path_forbidden(raw_path: str) -> None:
    if not raw_path or "\x00" in raw_path:
        raise PathJailError("Target path must be a non-empty string without null bytes.")

    stripped = raw_path.strip()
    if URL_TARGET_RE.match(stripped):
        raise OffensivePolicyError(
            "Network/URL targets are forbidden; VulnClaw worker enforces local static code analysis only."
        )

    slash_norm = stripped.replace("\\", "/")
    # Explicit tilde / home SSH & credential check before filesystem resolution
    if slash_norm == "~" or slash_norm.startswith("~/"):
        for seg in slash_norm.split("/"):
            if seg.lower() in FORBIDDEN_DIR_SEGMENTS:
                raise PathJailError(f"Access denied: home credential path '{stripped}' is blocked.")
        raise PathJailError("Access denied: home-relative '~' paths are outside AUTHORIZED_WORKSPACES.")

    # Explicit traversal segment check
    raw_segments = [s for s in slash_norm.split("/") if s]
    if ".." in raw_segments:
        raise PathJailError("Access denied: relative parent traversal ('..') is forbidden.")

    # Explicit POSIX system path block (enforced on all OSes including Windows self-tests)
    for pref in FORBIDDEN_POSIX_PREFIXES:
        if slash_norm == pref or slash_norm.startswith(pref + "/"):
            raise PathJailError(f"Access denied: system path '{pref}' is strictly blocked.")

    for seg in raw_segments:
        if seg.lower() in FORBIDDEN_DIR_SEGMENTS:
            raise PathJailError(f"Access denied: protected directory '{seg}' is strictly blocked.")

    if raw_segments and is_forbidden_secret_filename(raw_segments[-1]):
        raise PathJailError(
            f"Access denied: secret or credential file '{raw_segments[-1]}' is strictly protected."
        )

    if os.name == "nt":
        sys_root = os.environ.get("SystemRoot", "").replace("\\", "/").rstrip("/").lower()
        if sys_root and (slash_norm.lower() == sys_root or slash_norm.lower().startswith(sys_root + "/")):
            raise PathJailError("Access denied: Windows system directory is strictly blocked.")


def validate_scan_target(raw_path: str, authorized_roots: list[Path]) -> tuple[Path, Path]:
    """Validate that raw_path resolves strictly inside an authorized workspace jail.

    Returns `(resolved_target, matched_workspace_root)`.
    """
    _check_raw_path_forbidden(raw_path)

    if not authorized_roots:
        raise PathJailError("No valid AUTHORIZED_WORKSPACES roots configured.")

    cand = Path(raw_path.strip())
    if not cand.is_absolute():
        cand = authorized_roots[0] / cand

    # Reject direct symlink targets before resolving
    if cand.is_symlink():
        raise PathJailError("Access denied: symlink scan targets are forbidden inside workspace jail.")

    resolved = cand.resolve()

    # Re-verify resolved path segments & filename against symlink/alias redirection
    for part in resolved.parts:
        if part.lower() in FORBIDDEN_DIR_SEGMENTS:
            raise PathJailError(f"Access denied: resolved path enters protected zone '{part}'.")
    if is_forbidden_secret_filename(resolved.name):
        raise PathJailError(f"Access denied: resolved file '{resolved.name}' is strictly protected.")

    resolved_slash = str(resolved).replace("\\", "/")
    for pref in FORBIDDEN_POSIX_PREFIXES:
        if resolved_slash == pref or resolved_slash.startswith(pref + "/"):
            raise PathJailError(f"Access denied: resolved system path '{pref}' is blocked.")

    matched_root: Path | None = None
    for root in authorized_roots:
        if resolved == root or resolved.is_relative_to(root):
            matched_root = root
            break

    if matched_root is None:
        raise PathJailError(
            "Access denied: target path is outside AUTHORIZED_WORKSPACES."
        )

    if not resolved.exists():
        raise TargetNotFoundError("Requested scan path does not exist inside AUTHORIZED_WORKSPACES.")

    return resolved, matched_root


def validate_defensive_policy_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate scan request parameters and enforce defensive-only policy."""
    # 1. Inspect any requested capability / action / mode / tool / MCP field
    for field_name in ("capability", "capabilities", "action", "actions", "tools", "mode", "engine"):
        val = payload.get(field_name)
        if val is None:
            continue
        items = val if isinstance(val, list) else [val]
        for raw_item in items:
            norm = str(raw_item).strip().lower().replace("-", "_")
            if norm in BLOCKED_TOOLS_AND_ENGINES or norm.replace("_", "-") in BLOCKED_TOOLS_AND_ENGINES:
                raise OffensivePolicyError(
                    f"Capability '{raw_item}' is blocked by ALLINAGENT defensive-only policy."
                )
            if field_name in ("mode", "engine") and norm not in (
                "defensive",
                "defensive_only",
                "defensive_readonly",
                "codescan",
                "static",
            ):
                raise OffensivePolicyError(
                    f"Execution mode '{raw_item}' is forbidden; only 'defensive_only' static scanning is allowed."
                )

    if payload.get("enable_python_execute"):
        raise OffensivePolicyError(
            "Tool 'python_execute' is permanently disabled in the VulnClaw defensive sandbox."
        )

    mcp_req = payload.get("mcp_servers")
    if mcp_req:
        raise OffensivePolicyError(
            "External and built-in MCP servers ('fetch', 'memory') are permanently disabled."
        )

    # 2. Validate layers (strictly L1 and/or L2; L3 LLM calls blocked)
    raw_layers = payload.get("layers")
    if raw_layers is None:
        layers = ["L1", "L2"]
    elif isinstance(raw_layers, list) and raw_layers:
        layers = [str(x).strip().upper() for x in raw_layers if str(x).strip()]
    else:
        raise WorkerError("Field 'layers' must be a non-empty list of ['L1', 'L2'].")

    invalid_layers = [lyr for lyr in layers if lyr not in ALLOWED_SCAN_LAYERS]
    if invalid_layers or not layers:
        raise OffensivePolicyError(
            f"Unsupported or non-static detection layers {invalid_layers}; only static L1 and L2 are permitted."
        )

    # 3. Clamp resource limits strictly to hard ceilings
    try:
        req_max_files = int(payload.get("max_files", HARD_MAX_FILES))
        req_max_bytes = int(payload.get("max_file_bytes", HARD_MAX_FILE_BYTES))
        req_timeout = float(payload.get("timeout_sec", HARD_MAX_TIMEOUT_SEC))
    except (TypeError, ValueError) as exc:
        raise WorkerError(f"Invalid numeric resource parameter: {exc}") from exc

    if req_max_files < 1:
        raise WorkerError("max_files must be >= 1.")
    if req_max_bytes < 256:
        raise WorkerError("max_file_bytes must be >= 256.")
    if req_timeout <= 0:
        raise WorkerError("timeout_sec must be > 0.")

    return {
        "path": str(payload.get("path") or payload.get("target_path") or "").strip(),
        "project_id": sanitize_text(str(payload.get("project_id") or "default-project").strip())[:120]
        or "default-project",
        "asset_reference": sanitize_text(str(payload.get("asset_reference") or "").strip())[:200],
        "layers": sorted(set(layers)),
        "max_files": min(req_max_files, HARD_MAX_FILES),
        "max_file_bytes": min(req_max_bytes, HARD_MAX_FILE_BYTES),
        "timeout_sec": min(req_timeout, float(HARD_MAX_TIMEOUT_SEC)),
        "include_sarif": bool(payload.get("include_sarif", True)),
        "include_markdown": bool(payload.get("include_markdown", False)),
    }


# ---------------------------------------------------------------------------
# Ephemeral Child Subprocess Script (100% OS Memory Reclaim After Scan)
# ---------------------------------------------------------------------------
_CHILD_SCANNER_SCRIPT = r"""
import importlib.abc
import importlib.util
import json
import os
import sys
from pathlib import Path

BLOCKED_MODULE_PREFIXES = (
    "vulnclaw.mcp",
    "vulnclaw.tools",
    "vulnclaw.recon",
    "vulnclaw.traffic",
    "vulnclaw.agent",
    "vulnclaw.subagent",
    "chromadb",
    "sentence_transformers",
    "torch",
    "mitmproxy",
    "playwright",
)

class _DefensiveImportBlocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        for prefix in BLOCKED_MODULE_PREFIXES:
            if fullname == prefix or fullname.startswith(prefix + "."):
                raise PermissionError(
                    f"Import of '{fullname}' is blocked by ALLINAGENT defensive-only policy."
                )
        return None

sys.meta_path.insert(0, _DefensiveImportBlocker())

# Neutralize BUILTIN_MCP_SERVERS ('fetch', 'memory', etc.) and python_execute in schema if pydantic is installed
if importlib.util.find_spec("pydantic") is not None:
    import vulnclaw.config.schema as _vc_schema
    for _srv_name, _srv_cfg in _vc_schema.BUILTIN_MCP_SERVERS.items():
        _srv_cfg["enabled"] = False
        _srv_cfg["transport"] = {"type": "disabled"}
    if "enable_python_execute" in _vc_schema.SafetyConfig.model_fields:
        _vc_schema.SafetyConfig.model_fields["enable_python_execute"].default = False

import vulnclaw
from vulnclaw.codescan import report as vc_report
from vulnclaw.codescan import rules as vc_rules
from vulnclaw.codescan import scanner as vc_scanner

# Never treat secret '.env' as an always-scanned file
vc_rules.ALWAYS_SCAN_FILES.discard(".env")

def _disabled_llm(*_args, **_kwargs):
    raise PermissionError("L3 LLM scan is disabled in the isolated static L1+L2 subprocess.")

vc_scanner.scan_code_llm = _disabled_llm

cfg = json.loads(sys.stdin.read())
target_path = Path(cfg["target_path"])
workspace_root = Path(cfg["workspace_root"])
max_files = int(cfg["max_files"])
max_file_bytes = int(cfg["max_file_bytes"])
layers = tuple(cfg["layers"])
forbidden_exact = set(cfg["forbidden_exact"])
safe_env_templates = set(cfg["safe_env_templates"])
forbidden_exts = set(cfg["forbidden_exts"])
forbidden_dirs = set(cfg["forbidden_dirs"]) | set(vc_rules.SKIP_DIRS) | {"vendor", "storage"}

PRIORITY_DIR_HINTS = (
    "routes",
    "controllers",
    "middleware",
    "auth",
    "api",
    "src",
    "app",
    "integration",
    "server",
    "config",
)

def _is_secret_name(name: str) -> bool:
    low = name.strip().lower()
    if not low:
        return False
    if low in safe_env_templates:
        return False
    if low in forbidden_exact or low.startswith(".env."):
        return True
    if ".local." in low or low.endswith(".local"):
        return True
    if low.startswith(("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")):
        return True
    _, ext = os.path.splitext(low)
    return ext in forbidden_exts

def _is_scannable_extension(name: str) -> bool:
    if name in vc_rules.ALWAYS_SCAN_FILES:
        return True
    ext = os.path.splitext(name)[1].lower()
    if ext in vc_rules.SKIP_EXTS:
        return False
    return ext in vc_rules.EXT_LANGUAGE

stats_extra = {
    "skipped_secrets": 0,
    "skipped_symlinks": 0,
    "skipped_oversize": 0,
    "truncated_by_max_files": False,
}

def _jailed_iter_source_files(path_str: str):
    p = Path(path_str)
    if p.is_symlink():
        stats_extra["skipped_symlinks"] += 1
        return [], 1

    if p.is_file():
        if _is_secret_name(p.name) or not _is_scannable_extension(p.name):
            return [], 1
        try:
            st = p.stat(follow_symlinks=False)
        except OSError:
            return [], 1
        if st.st_size > max_file_bytes:
            stats_extra["skipped_oversize"] += 1
            return [], 1
        return [str(p)], 0

    candidates = []
    skipped = 0
    for root, dirs, names in os.walk(path_str, followlinks=False):
        kept_dirs = []
        for d in dirs:
            if d in forbidden_dirs or d.startswith("."):
                continue
            full_d = os.path.join(root, d)
            if os.path.islink(full_d):
                stats_extra["skipped_symlinks"] += 1
                skipped += 1
                continue
            kept_dirs.append(d)
        dirs[:] = sorted(kept_dirs)

        for name in names:
            full_f = os.path.join(root, name)
            if os.path.islink(full_f):
                stats_extra["skipped_symlinks"] += 1
                skipped += 1
                continue
            if _is_secret_name(name):
                stats_extra["skipped_secrets"] += 1
                skipped += 1
                continue
            if not _is_scannable_extension(name):
                skipped += 1
                continue
            try:
                st = os.stat(full_f, follow_symlinks=False)
            except OSError:
                skipped += 1
                continue
            if st.st_size > max_file_bytes:
                stats_extra["skipped_oversize"] += 1
                skipped += 1
                continue
            rel_slash = os.path.relpath(full_f, path_str).replace("\\", "/").lower()
            prio = 0 if any(rel_slash.startswith(h + "/") or ("/" + h + "/") in rel_slash for h in PRIORITY_DIR_HINTS) else 1
            candidates.append((prio, rel_slash, full_f))

    candidates.sort(key=lambda item: (item[0], item[1]))
    if len(candidates) > max_files:
        stats_extra["truncated_by_max_files"] = True
        skipped += len(candidates) - max_files
        candidates = candidates[:max_files]

    return [item[2] for item in candidates], skipped

vc_scanner._iter_source_files = _jailed_iter_source_files

scan_res = vc_scanner.scan_code(str(target_path), layers=layers)
raw_json = json.loads(vc_report.format_json(scan_res))
raw_sarif = json.loads(vc_report.format_sarif(scan_res)) if cfg.get("include_sarif", True) else None
raw_md = vc_report.format_markdown(scan_res) if cfg.get("include_markdown", False) else None

# Verify zero ambient secret env vars leaked into child subprocess
leaked_secret_envs = [
    k for k in os.environ
    if k in ("ALLINAGENT_INTERNAL_TOKEN", "VULNCLAW_SCAN_TOKEN", "TELEGRAM_BOT_TOKEN", "CUSTOM_API_KEY", "PAPERCLIP_API_KEY")
    or k.startswith(("HERMES_", "TELEGRAM_", "PAPERCLIP_"))
]

print(json.dumps({
    "vulnclaw_version": getattr(vulnclaw, "__version__", "0.4.1"),
    "scan_json": raw_json,
    "sarif": raw_sarif,
    "markdown_report": raw_md,
    "stats_extra": stats_extra,
    "leaked_secret_envs": leaked_secret_envs,
}, ensure_ascii=False))
"""


def _resolve_scanner_python_and_path() -> tuple[str, str]:
    """Resolve child Python interpreter and PYTHONPATH for vulnclaw package."""
    py_exe = os.environ.get("VULNCLAW_PYTHON_BIN", "").strip() or sys.executable
    py_path_entries: list[str] = []

    vc_src = os.environ.get("VULNCLAW_SOURCE_DIR", "").strip()
    if vc_src and Path(vc_src).is_dir():
        py_path_entries.append(str(Path(vc_src).resolve()))
    else:
        default_src = Path(__file__).resolve().parent.parent.parent / "runtime" / "vulnclaw-src"
        if default_src.is_dir():
            py_path_entries.append(str(default_src.resolve()))

    ambient_pypath = os.environ.get("PYTHONPATH", "").strip()
    if ambient_pypath:
        py_path_entries.extend(p for p in ambient_pypath.split(os.pathsep) if p.strip())

    deduped: list[str] = []
    for entry in py_path_entries:
        if entry not in deduped:
            deduped.append(entry)
    return py_exe, os.pathsep.join(deduped)


def _build_child_clean_env(ephemeral_tmp_dir: str, pythonpath: str) -> dict[str, str]:
    """Construct a minimal secret-free environment for the ephemeral child subprocess."""
    env: dict[str, str] = {
        "HOME": ephemeral_tmp_dir,
        "USERPROFILE": ephemeral_tmp_dir,
        "TMPDIR": ephemeral_tmp_dir,
        "TEMP": ephemeral_tmp_dir,
        "TMP": ephemeral_tmp_dir,
        "VULNCLAW_CONFIG_DIR": os.environ.get("VULNCLAW_CONFIG_DIR", ephemeral_tmp_dir),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if pythonpath:
        env["PYTHONPATH"] = pythonpath

    if os.name == "nt":
        sys_root = os.environ.get("SystemRoot", "")
        if sys_root:
            env["SystemRoot"] = sys_root
            env["WINDIR"] = sys_root
            env["COMSPEC"] = os.environ.get("COMSPEC", os.path.join(sys_root, "System32", "cmd.exe"))
            env["PATH"] = os.pathsep.join([os.path.join(sys_root, "System32"), sys_root])
    else:
        env["PATH"] = "/usr/local/bin:/usr/bin:/bin"

    return env


def _normalize_relative_location(file_str: str, target_path: Path, workspace_root: Path) -> str:
    """Relativize file paths to workspace_root so host filesystem prefixes are never exposed."""
    try:
        fp = Path(file_str).resolve()
        if fp == workspace_root or fp.is_relative_to(workspace_root):
            rel = fp.relative_to(workspace_root)
            return str(rel).replace("\\", "/")
        if fp == target_path:
            return fp.name
    except OSError:
        pass
    return Path(file_str).name


def _normalize_findings_for_store(
    raw_findings: list[dict[str, Any]],
    *,
    project_id: str,
    asset_reference: str,
    target_path: Path,
    workspace_root: Path,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Transform and sanitize findings into FindingsStore.ingest_finding() schema."""
    normalized: list[dict[str, Any]] = []
    sev_counts: dict[str, int] = {}

    for item in raw_findings:
        raw_sev = str(item.get("severity") or "Medium").strip().capitalize()
        severity = raw_sev if raw_sev in VALID_SEVERITIES else "Medium"
        sev_counts[severity] = sev_counts.get(severity, 0) + 1

        rule_id = sanitize_text(str(item.get("vuln_type") or item.get("rule_id") or "static_finding").strip())
        title = sanitize_text(str(item.get("title") or rule_id).strip())
        description = sanitize_text(str(item.get("description") or title).strip())
        evidence = sanitize_text(str(item.get("evidence") or "").strip())[:300]
        remediation = sanitize_text(
            str(
                item.get("remediation")
                or "Review the flagged code location and apply parameterized / allow-listed validation."
            ).strip()
        )

        raw_cwe = str(item.get("cwe") or "").strip().upper()
        cwe = raw_cwe if CWE_RE.match(raw_cwe) else None

        # Upstream scanner sets confidence = entropy_min (e.g. 3.0 or 2.5) for entropy rules;
        # normalize strictly to [0.0, 1.0] for FindingsStore.ingest_finding().
        try:
            raw_conf = float(item.get("confidence", 0.9))
        except (TypeError, ValueError):
            raw_conf = 0.9
        confidence = 0.95 if raw_conf > 1.0 else round(max(0.0, min(1.0, raw_conf)), 3)

        line_no = int(item.get("line") or 0)
        col_no = int(item.get("column") or 0)
        rel_file = _normalize_relative_location(str(item.get("target") or ""), target_path, workspace_root)
        code_loc = f"{rel_file}:{line_no}" if line_no > 0 else rel_file
        layer = str(item.get("detection_layer") or "L1").upper()

        normalized.append(
            {
                "source_reference": "vulnclaw_codescan",
                "project_id": project_id,
                "asset_reference": asset_reference,
                "finding_title": title,
                "title": title,
                "finding_description": description,
                "description": description,
                "severity": severity,
                "confidence": confidence,
                "cwe_reference": cwe,
                "cwe": cwe,
                "cve_reference": None,
                "affected_component": code_loc,
                "code_location": code_loc,
                "sanitized_evidence": evidence,
                "evidence": evidence,
                "remediation_recommendation": remediation,
                "remediation": remediation,
                "vuln_type": rule_id,
                "rule_id": rule_id,
                "detection_layer": layer if layer in ALLOWED_SCAN_LAYERS else "L1",
                "line": line_no,
                "column": col_no,
                "owner": "security_reviewer",
            }
        )

    normalized.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f["severity"], 99),
            f["affected_component"],
            f["line"],
        )
    )
    return normalized, sev_counts


def _sanitize_sarif_document(
    sarif_doc: dict[str, Any] | None,
    *,
    target_path: Path,
    workspace_root: Path,
) -> dict[str, Any] | None:
    if not isinstance(sarif_doc, dict):
        return None
    for run in sarif_doc.get("runs", []):
        for res in run.get("results", []):
            msg = res.get("message")
            if isinstance(msg, dict) and "text" in msg:
                msg["text"] = sanitize_text(str(msg["text"]))
            props = res.get("properties")
            if isinstance(props, dict):
                if "evidence" in props:
                    props["evidence"] = sanitize_text(str(props["evidence"]))[:300]
                if "remediation" in props:
                    props["remediation"] = sanitize_text(str(props["remediation"]))
            for loc in res.get("locations", []):
                phys = loc.get("physicalLocation", {})
                art = phys.get("artifactLocation", {})
                if "uri" in art:
                    rel_uri = _normalize_relative_location(str(art["uri"]), target_path, workspace_root)
                    art["uri"] = rel_uri
                    if "partialFingerprints" in res and isinstance(res["partialFingerprints"], dict):
                        region = phys.get("region", {})
                        ln = region.get("startLine", 0)
                        res["partialFingerprints"]["primaryLocationLineHash"] = (
                            f"{res.get('ruleId', 'rule')}:{rel_uri}:{ln}"
                        )
    return sarif_doc


def _enforce_output_cap(response_obj: dict[str, Any], max_bytes: int = HARD_MAX_OUTPUT_BYTES) -> bytes:
    """Guarantee serialized JSON output is strictly <= max_bytes (512 KB) and valid JSON."""
    encoded = json.dumps(response_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) <= max_bytes:
        return encoded

    response_obj["stats"]["output_truncated"] = True
    response_obj["stats"]["total_findings_before_output_cap"] = len(response_obj.get("findings", []))

    # Step 1: drop optional markdown report first
    if "markdown_report" in response_obj:
        response_obj.pop("markdown_report", None)
        encoded = json.dumps(response_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) <= max_bytes:
            return encoded

    # Step 2: progressively halve findings & SARIF results until strictly under 512 KB
    findings = list(response_obj.get("findings", []))
    sarif = response_obj.get("sarif")
    sarif_results = (
        list(sarif["runs"][0].get("results", []))
        if isinstance(sarif, dict) and sarif.get("runs")
        else []
    )

    while len(encoded) > max_bytes and (findings or sarif_results):
        new_len = max(0, (max(len(findings), len(sarif_results)) * 3) // 4 - 1)
        findings = findings[:new_len]
        response_obj["findings"] = findings
        if sarif_results and isinstance(sarif, dict) and sarif.get("runs"):
            sarif_results = sarif_results[:new_len]
            sarif["runs"][0]["results"] = sarif_results
        encoded = json.dumps(response_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    return encoded


async def run_ephemeral_defensive_scan(
    raw_payload: dict[str, Any],
    *,
    authorized_roots: list[Path],
) -> tuple[dict[str, Any], bytes]:
    """Validate policy & path jail, execute scan in ephemeral child process, and sanitize output."""
    params = validate_defensive_policy_payload(raw_payload)
    resolved_target, matched_root = validate_scan_target(params["path"], authorized_roots)

    asset_ref = params["asset_reference"]
    if not asset_ref:
        if resolved_target == matched_root:
            asset_ref = matched_root.name or "workspace"
        else:
            asset_ref = str(resolved_target.relative_to(matched_root)).replace("\\", "/")

    import shutil
    import tempfile

    py_exe, pypath = _resolve_scanner_python_and_path()
    ephemeral_tmp = tempfile.mkdtemp(prefix="vc-scan-")
    t0 = time.perf_counter()

    child_input = json.dumps(
        {
            "target_path": str(resolved_target),
            "workspace_root": str(matched_root),
            "layers": params["layers"],
            "max_files": params["max_files"],
            "max_file_bytes": params["max_file_bytes"],
            "include_sarif": params["include_sarif"],
            "include_markdown": params["include_markdown"],
            "forbidden_exact": sorted(FORBIDDEN_EXACT_FILENAMES),
            "safe_env_templates": sorted(SAFE_ENV_TEMPLATES),
            "forbidden_exts": sorted(FORBIDDEN_SECRET_EXTENSIONS),
            "forbidden_dirs": sorted(FORBIDDEN_DIR_SEGMENTS),
        }
    ).encode("utf-8")

    creationflags = getattr(asyncio.subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0
    proc: asyncio.subprocess.Process | None = None

    try:
        proc = await asyncio.create_subprocess_exec(
            py_exe,
            "-B",
            "-c",
            _CHILD_SCANNER_SCRIPT,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=ephemeral_tmp,
            env=_build_child_clean_env(ephemeral_tmp, pypath),
            start_new_session=(os.name != "nt"),
            creationflags=creationflags,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=child_input),
                timeout=params["timeout_sec"],
            )
        except asyncio.TimeoutError as exc:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            raise ScanTimeoutError(
                f"Defensive scan exceeded wall-clock timeout ({params['timeout_sec']}s) and was terminated."
            ) from exc

        if proc.returncode != 0:
            err_tail = sanitize_text(stderr_b.decode("utf-8", errors="replace").strip()[-500:])
            raise WorkerError(
                f"Isolated scanner subprocess failed (exit {proc.returncode}): {err_tail}",
                status=500,
                code="SCANNER_SUBPROCESS_ERROR",
            )

        lines = [ln for ln in stdout_b.decode("utf-8", errors="replace").splitlines() if ln.strip()]
        if not lines:
            raise WorkerError(
                "Isolated scanner subprocess returned empty output.",
                status=500,
                code="SCANNER_EMPTY_OUTPUT",
            )
        child_out = json.loads(lines[-1])
    finally:
        shutil.rmtree(ephemeral_tmp, ignore_errors=True)

    wall_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    scan_json = child_out.get("scan_json") or {}
    findings, sev_counts = _normalize_findings_for_store(
        scan_json.get("findings") or [],
        project_id=params["project_id"],
        asset_reference=asset_ref,
        target_path=resolved_target,
        workspace_root=matched_root,
    )
    sanitized_sarif = _sanitize_sarif_document(
        child_out.get("sarif"),
        target_path=resolved_target,
        workspace_root=matched_root,
    )

    rel_target = (
        "."
        if resolved_target == matched_root
        else str(resolved_target.relative_to(matched_root)).replace("\\", "/")
    )
    extra = child_out.get("stats_extra") or {}

    response_obj: dict[str, Any] = {
        "ok": True,
        "tool": "vulnclaw",
        "vulnclaw_version": str(child_out.get("vulnclaw_version") or VULNCLAW_PINNED_VERSION),
        "pinned_commit": VULNCLAW_PINNED_COMMIT,
        "mode": "defensive_only",
        "scan_id": f"vcs-{os.urandom(6).hex()}",
        "project_id": params["project_id"],
        "asset_reference": asset_ref,
        "target_relative_path": rel_target,
        "workspace_read_only": not os.access(matched_root, os.W_OK),
        "layers": params["layers"],
        "limits": {
            "max_files": params["max_files"],
            "max_file_bytes": params["max_file_bytes"],
            "timeout_sec": params["timeout_sec"],
            "max_output_bytes": HARD_MAX_OUTPUT_BYTES,
        },
        "stats": {
            "files_scanned": int(scan_json.get("files_scanned") or 0),
            "files_skipped": int(scan_json.get("files_skipped") or 0),
            "skipped_secrets": int(extra.get("skipped_secrets") or 0),
            "skipped_symlinks": int(extra.get("skipped_symlinks") or 0),
            "skipped_oversize": int(extra.get("skipped_oversize") or 0),
            "truncated_by_max_files": bool(extra.get("truncated_by_max_files")),
            "findings_count": len(findings),
            "severity_counts": sev_counts,
            "scanner_duration_ms": float(scan_json.get("duration_ms") or 0.0),
            "wall_duration_ms": wall_ms,
            "subprocess_memory_reclaimed": True,
            "secret_env_leaked_to_child": bool(child_out.get("leaked_secret_envs")),
            "output_truncated": False,
        },
        "findings": findings,
    }
    if sanitized_sarif is not None:
        response_obj["sarif"] = sanitized_sarif
    if params["include_markdown"] and child_out.get("markdown_report"):
        response_obj["markdown_report"] = sanitize_text(str(child_out["markdown_report"]))

    serialized = _enforce_output_cap(response_obj, HARD_MAX_OUTPUT_BYTES)
    return json.loads(serialized.decode("utf-8")), serialized


# ---------------------------------------------------------------------------
# Lightweight Asyncio HTTP/1.1 Server (Zero External Dependencies, < 25 MB RSS)
# ---------------------------------------------------------------------------
HTTP_STATUS_REASONS: dict[int, str] = {
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
    504: "Gateway Timeout",
}


class VulnClawDefensiveServer:
    """Minimal asyncio HTTP server exposing GET /health and POST /scan."""

    def __init__(
        self,
        *,
        host: str | None = None,
        port: int = DEFAULT_PORT,
        internal_token: str | None = None,
        authorized_roots: list[Path] | None = None,
        max_concurrent_scans: int = 2,
        idle_timeout_sec: float = 0.0,
    ) -> None:
        self.host = (host.strip() if host is not None else _resolve_bind_host()) or DEFAULT_BIND_HOST
        self.port = port
        self.internal_token = _resolve_internal_scan_token(internal_token)
        self.authorized_roots = (
            authorized_roots
            if authorized_roots is not None
            else parse_authorized_workspaces()
        )
        self.scan_semaphore = asyncio.Semaphore(max(1, max_concurrent_scans))
        self.idle_timeout_sec = idle_timeout_sec
        self.started_monotonic = time.monotonic()
        self.last_activity_monotonic = self.started_monotonic
        self.scans_completed = 0
        self.scans_failed = 0
        self._server: asyncio.AbstractServer | None = None
        self._shutdown_event = asyncio.Event()

    def _verify_token(self, headers: dict[str, str], *, required: bool) -> bool:
        supplied = (
            headers.get(AUTH_HEADER_NAME, "").strip()
            or headers.get("x-vulnclaw-scan-token", "").strip()
            or headers.get("x-allinagent-internal-token", "").strip()
            or headers.get("x-vulnclaw-token", "").strip()
        )
        if not supplied:
            auth_hdr = headers.get("authorization", "").strip()
            if auth_hdr.lower().startswith("bearer "):
                supplied = auth_hdr[7:].strip()

        if not self.internal_token:
            if required:
                raise WorkerError(
                    f"Server authentication token ({INTERNAL_TOKEN_ENV} / {FALLBACK_SCAN_TOKEN_ENV}) is not configured.",
                    status=503,
                    code="SERVER_TOKEN_UNCONFIGURED",
                )
            return False

        if not supplied:
            if required:
                raise AuthError("Missing required X-Internal-Scan-Token header.")
            return False

        if not _compare_digest(supplied.encode("utf-8"), self.internal_token.encode("utf-8")):
            raise AuthError("Invalid X-Internal-Scan-Token.")
        return True

    def build_health_payload(self, *, authenticated: bool = False) -> dict[str, Any]:
        rss_bytes, total_ws_bytes = get_process_memory_info()
        rss_mb = round(rss_bytes / (1024.0 * 1024.0), 2)
        total_ws_mb = round(total_ws_bytes / (1024.0 * 1024.0), 2)
        payload: dict[str, Any] = {
            "ok": True,
            "status": "healthy",
            "service": "vulnclaw-defensive-worker",
            "mode": "defensive_only",
            "vulnclaw_pinned_version": VULNCLAW_PINNED_VERSION,
            "vulnclaw_pinned_commit": VULNCLAW_PINNED_COMMIT,
            "authenticated": authenticated,
            "uptime_sec": round(time.monotonic() - self.started_monotonic, 2),
            "rss_bytes": rss_bytes,
            "rss_mb": rss_mb,
            "working_set_mb": total_ws_mb,
            "idle_rss_under_25mb": rss_bytes < IDLE_RSS_BUDGET_BYTES,
            "scans_completed": self.scans_completed,
            "scans_failed": self.scans_failed,
            "subprocess_memory_reclaim": True,
            "policy": {
                "allowed_layers": sorted(ALLOWED_SCAN_LAYERS),
                "blocked_offensive_capabilities": list(BLOCKED_OFFENSIVE_CAPABILITIES),
                "disabled_builtin_mcp_servers": list(DISABLED_BUILTIN_MCP_SERVERS),
                "python_execute_enabled": False,
                "max_files": HARD_MAX_FILES,
                "max_file_bytes": HARD_MAX_FILE_BYTES,
                "timeout_sec": HARD_MAX_TIMEOUT_SEC,
                "max_output_bytes": HARD_MAX_OUTPUT_BYTES,
            },
        }
        if authenticated:
            payload["authorized_workspaces_count"] = len(self.authorized_roots)
        return payload

    async def _write_json(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        body_bytes: bytes,
    ) -> None:
        reason = HTTP_STATUS_REASONS.get(status, "Error")
        header = (
            f"HTTP/1.1 {status} {reason}\r\n"
            "Content-Type: application/json; charset=utf-8\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            "Cache-Control: no-store\r\n"
            "X-Content-Type-Options: nosniff\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        writer.write(header + body_bytes)
        await writer.drain()

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.last_activity_monotonic = time.monotonic()
        try:
            raw_head = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"),
                timeout=10.0,
            )
            if len(raw_head) > MAX_HTTP_HEADER_BYTES:
                raise WorkerError("HTTP headers exceed maximum size.", status=413, code="HEADERS_TOO_LARGE")

            lines = raw_head.decode("iso-8859-1").split("\r\n")
            req_line = lines[0].strip().split(" ")
            if len(req_line) < 2:
                raise WorkerError("Malformed HTTP request line.", status=400)
            method = req_line[0].upper()
            route_path = req_line[1].partition("?")[0]

            headers: dict[str, str] = {}
            for hline in lines[1:]:
                if not hline:
                    continue
                k, sep, v = hline.partition(":")
                if sep:
                    headers[k.strip().lower()] = v.strip()

            content_length = 0
            if "content-length" in headers:
                try:
                    content_length = int(headers["content-length"])
                except ValueError as exc:
                    raise WorkerError("Invalid Content-Length header.", status=400) from exc
                if content_length < 0:
                    raise WorkerError("Negative Content-Length header.", status=400)
                if content_length > MAX_HTTP_BODY_BYTES:
                    raise WorkerError(
                        f"Request body exceeds {MAX_HTTP_BODY_BYTES} bytes.",
                        status=413,
                        code="PAYLOAD_TOO_LARGE",
                    )

            body_bytes = b""
            if content_length > 0:
                body_bytes = await asyncio.wait_for(
                    reader.readexactly(content_length),
                    timeout=10.0,
                )

            if route_path in ("/health", "/healthz"):
                if method != "GET":
                    raise WorkerError("Method not allowed on /health.", status=405, code="METHOD_NOT_ALLOWED")
                require_health_auth = os.environ.get("ALLINAGENT_HEALTH_REQUIRE_AUTH", "0") == "1"
                is_auth = self._verify_token(headers, required=require_health_auth)
                resp_bytes = json.dumps(
                    self.build_health_payload(authenticated=is_auth),
                    ensure_ascii=False,
                ).encode("utf-8")
                await self._write_json(writer, 200, resp_bytes)
                return

            if route_path in ("/scan", "/api/scan"):
                if method != "POST":
                    raise WorkerError("Method not allowed on /scan.", status=405, code="METHOD_NOT_ALLOWED")
                self._verify_token(headers, required=True)
                try:
                    req_json = json.loads(body_bytes.decode("utf-8") or "{}")
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise WorkerError("Request body must be valid UTF-8 JSON.", status=400) from exc
                if not isinstance(req_json, dict):
                    raise WorkerError("Request JSON root must be an object.", status=400)

                async with self.scan_semaphore:
                    _parsed_resp, serialized = await run_ephemeral_defensive_scan(
                        req_json,
                        authorized_roots=self.authorized_roots,
                    )
                    self.scans_completed += 1
                    self.last_activity_monotonic = time.monotonic()

                await self._write_json(writer, 200, serialized)
                return

            raise WorkerError(f"Unknown endpoint '{route_path}'.", status=404, code="NOT_FOUND")

        except asyncio.IncompleteReadError:
            err_payload = json.dumps(
                {"ok": False, "error_code": "BAD_REQUEST", "error": "Incomplete HTTP request."}
            ).encode("utf-8")
            await self._write_json(writer, 400, err_payload)
        except asyncio.LimitOverrunError:
            err_payload = json.dumps(
                {"ok": False, "error_code": "HEADERS_TOO_LARGE", "error": "HTTP headers too large."}
            ).encode("utf-8")
            await self._write_json(writer, 413, err_payload)
        except WorkerError as exc:
            if exc.http_status >= 500:
                self.scans_failed += 1
            err_payload = json.dumps(
                {
                    "ok": False,
                    "error_code": exc.error_code,
                    "error": sanitize_text(str(exc)),
                },
                ensure_ascii=False,
            ).encode("utf-8")
            try:
                await self._write_json(writer, exc.http_status, err_payload)
            except OSError:
                pass
        except Exception as exc:  # noqa: BLE001
            self.scans_failed += 1
            err_payload = json.dumps(
                {
                    "ok": False,
                    "error_code": "INTERNAL_ERROR",
                    "error": sanitize_text(str(exc))[:300],
                },
                ensure_ascii=False,
            ).encode("utf-8")
            try:
                await self._write_json(writer, 500, err_payload)
            except OSError:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    async def start(self) -> tuple[str, int]:
        self._server = await asyncio.start_server(
            self.handle_client,
            host=self.host,
            port=self.port,
        )
        sockets = self._server.sockets or []
        bound_port = sockets[0].getsockname()[1] if sockets else self.port
        self.port = int(bound_port)
        return self.host, self.port

    async def stop(self) -> None:
        self._shutdown_event.set()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def serve_forever(self) -> None:
        host, port = await self.start()
        sys.stderr.write(
            f"[vulnclaw-worker] listening on http://{host}:{port} "
            f"(mode=defensive_only, rss={get_process_rss_bytes() / (1024 * 1024):.2f} MiB)\n"
        )
        sys.stderr.flush()

        if self.idle_timeout_sec > 0:
            while not self._shutdown_event.is_set():
                await asyncio.sleep(1.0)
                if time.monotonic() - self.last_activity_monotonic >= self.idle_timeout_sec:
                    await self.stop()
                    return
        else:
            assert self._server is not None
            async with self._server:
                await self._server.serve_forever()


# ---------------------------------------------------------------------------
# End-to-End Self-Test Suite (HTTP + Policy + Path Jail + Real L1/L2 + Reclaim)
# ---------------------------------------------------------------------------
def _http_json_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    import http.client

    rest = url.split("://", 1)[-1]
    host_port, _, path_part = rest.partition("/")
    host, _, port_str = host_port.partition(":")
    conn = http.client.HTTPConnection(host, int(port_str or "80"), timeout=30.0)
    try:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        req_headers = {"Accept": "application/json", **(headers or {})}
        if body is not None:
            req_headers["Content-Type"] = "application/json"
        conn.request(method, "/" + path_part, body=body, headers=req_headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", errors="replace")
        return resp.status, json.loads(raw) if raw.strip() else {"ok": False}
    finally:
        conn.close()


async def run_self_test(workspace_base_dir: Path | None = None) -> dict[str, Any]:
    """Run live end-to-end verification against a standalone `serve` daemon process."""
    import shutil
    import tempfile

    ephemeral_token = f"ephemeral-test-{os.urandom(12).hex()}"
    managed_tmp = workspace_base_dir is None
    ws_root = (
        Path(tempfile.mkdtemp(prefix="vc-selftest-ws-")).resolve()
        if workspace_base_dir is None
        else workspace_base_dir.resolve()
    )
    ws_root.mkdir(parents=True, exist_ok=True)
    synth_dir = ws_root / "synthetic_app"
    synth_dir.mkdir(parents=True, exist_ok=True)

    # Create synthetic vulnerable source file (triggers both L1 and L2 rules) + decoys
    # Constructed dynamically so this worker source file itself contains zero fake secret literals.
    fake_sk = "sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"
    (synth_dir / "app.py").write_text(
        "\n".join(
            [
                "import os",
                f'API_TOKEN = "{fake_sk}"',
                "def fetch_user(user_input, cmd_arg):",
                '    query = f"SELECT * FROM accounts WHERE username = {user_input}"',
                "    os.system(cmd_arg)",
                "    return eval(user_input)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    # Protected .env decoy inside workspace (must NEVER be read or scanned)
    (synth_dir / ".env").write_text(f"OPENAI_API_KEY={fake_sk}\n", encoding="utf-8")
    # Oversized >1 MB file decoy inside workspace (must be skipped by 1 MB cap)
    (synth_dir / "oversize_bundle.js").write_text(
        "// padding\n" * 110_000,
        encoding="utf-8",
    )

    daemon_env = dict(os.environ)
    daemon_env[INTERNAL_TOKEN_ENV] = ephemeral_token
    daemon_env["AUTHORIZED_WORKSPACES"] = str(ws_root)
    daemon_env["PYTHONDONTWRITEBYTECODE"] = "1"

    creationflags = getattr(asyncio.subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0
    daemon = await asyncio.create_subprocess_exec(
        sys.executable,
        "-B",
        str(Path(__file__).resolve()),
        "serve",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--authorized-workspace",
        str(ws_root),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=daemon_env,
        creationflags=creationflags,
    )

    try:
        assert daemon.stderr is not None
        banner_raw = await asyncio.wait_for(daemon.stderr.readline(), timeout=10.0)
        banner = banner_raw.decode("utf-8", errors="replace").strip()
        m = re.search(r"http://(127\.0\.0\.1):(\d+)", banner)
        if not m:
            raise RuntimeError(f"Failed to parse daemon listen banner: {banner!r}")
        base_url = f"http://{m.group(1)}:{m.group(2)}"
        auth_hdr = {"X-Internal-Scan-Token": ephemeral_token}

        # 1. Health & standalone daemon idle RSS check (< 25 MB)
        st_health, health = await asyncio.to_thread(
            _http_json_request, f"{base_url}/health", headers=auth_hdr
        )
        assert st_health == 200 and health["ok"] is True, f"Health check failed: {health}"
        assert health["idle_rss_under_25mb"] is True, f"Idle RSS >= 25 MB: {health['rss_mb']} MB"

        # 2. Authentication enforcement (missing & wrong token -> 401)
        st_unauth, _ = await asyncio.to_thread(
            _http_json_request,
            f"{base_url}/scan",
            method="POST",
            payload={"path": str(synth_dir)},
        )
        assert st_unauth == 401, f"Expected 401 without token, got {st_unauth}"

        st_badtok, _ = await asyncio.to_thread(
            _http_json_request,
            f"{base_url}/scan",
            method="POST",
            headers={"X-Internal-Scan-Token": "wrong-token"},
            payload={"path": str(synth_dir)},
        )
        assert st_badtok == 401, f"Expected 401 with bad token, got {st_badtok}"

        # 3. Verify all 10 offensive capabilities + MCP servers + python_execute + L3 are blocked (403)
        blocked_checks: dict[str, int] = {}
        for cap in (*BLOCKED_OFFENSIVE_CAPABILITIES, "fetch", "memory", "python_execute"):
            code, _ = await asyncio.to_thread(
                _http_json_request,
                f"{base_url}/scan",
                method="POST",
                headers=auth_hdr,
                payload={"path": str(synth_dir), "capability": cap},
            )
            assert code == 403, f"Expected 403 for capability={cap}, got {code}"
            blocked_checks[cap] = code

        st_pyexec, _ = await asyncio.to_thread(
            _http_json_request,
            f"{base_url}/scan",
            method="POST",
            headers=auth_hdr,
            payload={"path": str(synth_dir), "enable_python_execute": True},
        )
        assert st_pyexec == 403

        st_l3, _ = await asyncio.to_thread(
            _http_json_request,
            f"{base_url}/scan",
            method="POST",
            headers=auth_hdr,
            payload={"path": str(synth_dir), "layers": ["L1", "L3"]},
        )
        assert st_l3 == 403

        # 4. Path jail checks (/etc, /proc, /sys, /root, /var/run, ~/.ssh, .env, auth.json, traversal)
        jail_targets = [
            "/etc/passwd",
            "/proc/self/environ",
            "/sys/kernel",
            "/root/.bashrc",
            "/var/run/docker.sock",
            "~/.ssh/id_rsa",
            "../outside",
            str(synth_dir / ".env"),
            str(synth_dir / "auth.json"),
            str(synth_dir / "office-bridge-auth.json"),
        ]
        jail_results: dict[str, int] = {}
        for bad_path in jail_targets:
            code, _ = await asyncio.to_thread(
                _http_json_request,
                f"{base_url}/scan",
                method="POST",
                headers=auth_hdr,
                payload={"path": bad_path},
            )
            assert code == 403, f"Expected 403 for {bad_path}, got {code}"
            jail_results[bad_path] = code

        # 5. Real L1 + L2 scan in ephemeral subprocess
        st_scan, scan_out = await asyncio.to_thread(
            _http_json_request,
            f"{base_url}/scan",
            method="POST",
            headers=auth_hdr,
            payload={
                "path": str(synth_dir),
                "project_id": "selftest-project",
                "asset_reference": "synthetic_app",
                "layers": ["L1", "L2"],
                "include_sarif": True,
            },
        )
        assert st_scan == 200 and scan_out["ok"] is True, f"Scan failed: {scan_out}"
        findings = scan_out["findings"]
        layers_hit = {f["detection_layer"] for f in findings}
        rules_hit = {f["rule_id"] for f in findings}
        assert "L1" in layers_hit and "L2" in layers_hit, f"Expected both L1 & L2 hits, got {layers_hit}"
        assert scan_out["stats"]["files_scanned"] == 1, f"Expected 1 file scanned, got {scan_out['stats']}"
        assert scan_out["stats"]["skipped_secrets"] >= 1, "Expected .env decoy to be skipped"
        assert scan_out["stats"]["skipped_oversize"] >= 1, "Expected >1MB file to be skipped"
        assert scan_out["stats"]["secret_env_leaked_to_child"] is False

        # Ensure raw fake OpenAI key literal was redacted in both JSON findings and SARIF
        serialized_scan = json.dumps(scan_out)
        assert fake_sk not in serialized_scan, "Raw secret literal leaked into scan output!"
        assert "[REDACTED_API_KEY]" in serialized_scan, "Expected redacted marker in evidence"
        assert scan_out["sarif"]["version"] == "2.1.0"
        assert len(serialized_scan.encode("utf-8")) <= HARD_MAX_OUTPUT_BYTES

        # 6. Post-scan standalone daemon RSS check (< 25 MB after child subprocess exit)
        st_post_health, post_health = await asyncio.to_thread(
            _http_json_request, f"{base_url}/health", headers=auth_hdr
        )
        assert st_post_health == 200 and post_health["idle_rss_under_25mb"] is True, (
            f"Post-scan daemon RSS >= 25 MB: {post_health['rss_mb']} MB"
        )

        return {
            "ok": True,
            "vulnclaw_version": scan_out["vulnclaw_version"],
            "idle_rss_mb": health["rss_mb"],
            "post_scan_rss_mb": post_health["rss_mb"],
            "rss_budget_mb": 25.0,
            "auth_enforcement_http_codes": {"missing_token": st_unauth, "invalid_token": st_badtok},
            "blocked_capabilities_verified": len(blocked_checks),
            "path_jail_blocks_verified": len(jail_results),
            "scan_stats": scan_out["stats"],
            "layers_detected": sorted(layers_hit),
            "rules_detected": sorted(rules_hit),
            "sample_finding_schema_keys": sorted(findings[0].keys()) if findings else [],
            "sarif_results_count": len(scan_out["sarif"]["runs"][0]["results"]),
        }
    finally:
        try:
            daemon.terminate()
            await asyncio.wait_for(daemon.wait(), timeout=5.0)
        except Exception:
            try:
                daemon.kill()
            except ProcessLookupError:
                pass
        if managed_tmp:
            shutil.rmtree(ws_root, ignore_errors=True)
        else:
            shutil.rmtree(synth_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# CLI Interface (`serve`, `scan`, `health`, `self-test`)
# ---------------------------------------------------------------------------
def build_cli_parser() -> Any:
    import argparse

    parser = argparse.ArgumentParser(
        description="ALLINAGENT VulnClaw Lightweight On-Demand Defensive Worker"
    )
    sub = parser.add_subparsers(dest="command")

    # serve
    p_serve = sub.add_parser("serve", help="Run internal HTTP worker on 127.0.0.1:8660")
    p_serve.add_argument(
        "--host",
        default=_resolve_bind_host(),
        help="Bind host (env: VULNCLAW_BIND_HOST / VULNCLAW_HOST, default: 127.0.0.1)",
    )
    p_serve.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("VULNCLAW_PORT", str(DEFAULT_PORT))),
        help="Bind port (default: 8660)",
    )
    p_serve.add_argument(
        "--authorized-workspace",
        action="append",
        default=[],
        help="Authorized read-only workspace root (repeatable)",
    )
    p_serve.add_argument(
        "--max-concurrent-scans",
        type=int,
        default=int(os.environ.get("VULNCLAW_MAX_CONCURRENT_SCANS", "2")),
        help="Maximum concurrent ephemeral scan subprocesses (default: 2)",
    )
    p_serve.add_argument(
        "--idle-timeout-sec",
        type=float,
        default=float(os.environ.get("VULNCLAW_IDLE_TIMEOUT_SEC", "0")),
        help="Optional scale-to-zero idle timeout in seconds (0 = stay resident)",
    )

    # scan (CLI one-shot mode)
    p_scan = sub.add_parser("scan", help="Run a one-shot jailed L1+L2 defensive scan via CLI")
    p_scan.add_argument("path", help="File or directory inside AUTHORIZED_WORKSPACES")
    p_scan.add_argument("--project-id", default="default-project")
    p_scan.add_argument("--asset-reference", default="")
    p_scan.add_argument("--layers", nargs="+", default=["L1", "L2"])
    p_scan.add_argument("--max-files", type=int, default=HARD_MAX_FILES)
    p_scan.add_argument("--max-file-bytes", type=int, default=HARD_MAX_FILE_BYTES)
    p_scan.add_argument("--timeout-sec", type=float, default=float(HARD_MAX_TIMEOUT_SEC))
    p_scan.add_argument("--authorized-workspace", action="append", default=[])
    p_scan.add_argument("--sarif-only", action="store_true", help="Print only the SARIF 2.1.0 JSON")

    # health
    p_health = sub.add_parser("health", help="Print local worker health/RSS or probe live HTTP /health")
    p_health.add_argument("--probe-http", action="store_true", help="Probe running HTTP server /health")
    p_health.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("VULNCLAW_PORT", str(DEFAULT_PORT))),
    )

    # self-test
    p_test = sub.add_parser("self-test", help="Run end-to-end defensive worker verification suite")
    p_test.add_argument(
        "--workspace-dir",
        type=Path,
        default=None,
        help="Directory to hold temporary synthetic test files during self-test",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    if not effective_argv:
        effective_argv = ["serve"]
    args = build_cli_parser().parse_args(effective_argv)
    cmd = args.command or "serve"

    if cmd == "serve":
        roots = parse_authorized_workspaces(extra_roots=getattr(args, "authorized_workspace", None))
        srv = VulnClawDefensiveServer(
            host=getattr(args, "host", None),
            port=getattr(args, "port", DEFAULT_PORT),
            authorized_roots=roots,
            max_concurrent_scans=getattr(args, "max_concurrent_scans", 2),
            idle_timeout_sec=getattr(args, "idle_timeout_sec", 0.0),
        )
        try:
            asyncio.run(srv.serve_forever())
        except KeyboardInterrupt:
            pass
        return 0

    if cmd == "scan":
        roots = parse_authorized_workspaces(extra_roots=args.authorized_workspace)
        payload = {
            "path": args.path,
            "project_id": args.project_id,
            "asset_reference": args.asset_reference,
            "layers": args.layers,
            "max_files": args.max_files,
            "max_file_bytes": args.max_file_bytes,
            "timeout_sec": args.timeout_sec,
            "include_sarif": True,
        }
        try:
            parsed, serialized = asyncio.run(
                run_ephemeral_defensive_scan(payload, authorized_roots=roots)
            )
        except WorkerError as exc:
            sys.stderr.write(
                json.dumps({"ok": False, "error_code": exc.error_code, "error": str(exc)}) + "\n"
            )
            return 2
        if args.sarif_only:
            sys.stdout.write(json.dumps(parsed.get("sarif", {}), ensure_ascii=False, indent=2) + "\n")
        else:
            sys.stdout.buffer.write(serialized + b"\n")
        return 0

    if cmd == "health":
        if args.probe_http:
            cfg_host = _resolve_bind_host()
            probe_host = "127.0.0.1" if cfg_host in ("0.0.0.0", "::", "") else cfg_host
            url = f"http://{probe_host}:{args.port}/health"
            hdrs: dict[str, str] = {}
            tok = _resolve_internal_scan_token()
            if tok:
                hdrs["X-Internal-Scan-Token"] = tok
            status, body = _http_json_request(url, headers=hdrs)
            print(json.dumps(body, indent=2))
            return 0 if status == 200 and body.get("ok") else 1
        srv = VulnClawDefensiveServer()
        print(json.dumps(srv.build_health_payload(authenticated=False), indent=2))
        return 0

    if cmd == "self-test":
        report = asyncio.run(run_self_test(args.workspace_dir))
        print(json.dumps(report, indent=2))
        return 0 if report.get("ok") else 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
