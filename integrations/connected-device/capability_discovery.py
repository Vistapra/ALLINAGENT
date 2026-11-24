#!/usr/bin/env python3
"""ALLINAGENT Phase 16 — Honest Runtime Capability Discovery & Workspace Boundary Guard.

Distinguishes two strictly separated execution planes:
  1. `server_workspace`:
     - Linux/POSIX terminal, Git, coding, build, test, source code analysis, headless Chromium
       (`playwright` / `/usr/bin/chromium`), and optional virtual Xvfb desktop (`DISPLAY`),
       jailed strictly to `AUTHORIZED_WORKSPACES` (default `/workspaces`).
     - Operates 100% independently whether or not any remote Windows device is paired or online.
  2. `windows_connected_device`:
     - Optional paired remote Windows runner (`CONNECTED_WINDOWS_DEVICE_URL` + HMAC-SHA256
       `CONNECTED_DEVICE_SHARED_SECRET`).
     - Reports `device_online` / `device_offline`, `interactive_desktop_available`,
       `authorized_windows_roots`, and `capability_not_supported` with zero false claims:
       an Ubuntu/Linux server NEVER claims direct access to a remote PC's `C:\\` or `D:\\` drive
       without an explicitly paired and online runner!
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

WINDOWS_DRIVE_PATH_RE = re.compile(r"^(?:[A-Za-z]:(?:[\\/]|$)|\\\\[^\\/]+[\\/][^\\/]+)")
SENSITIVE_FILENAME_RE = re.compile(
    r"^(\.env(\..+)?|auth\.json|office-bridge-auth\.json|.*\.local\..*|.*credentials.*|id_rsa|id_ed25519|.*\.pem|.*\.key|\.git-credentials)$",
    re.IGNORECASE,
)
MIN_SHARED_SECRET_LEN = 32
PLACEHOLDER_SECRET_MARKERS = ("replace", "example", "changeme", "placeholder", "your_secret", "00000000")
PRIVATE_TUNNEL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
)


def is_explicit_private_or_tunnel_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(ip_obj in net for net in PRIVATE_TUNNEL_NETWORKS)

CHROMIUM_CANDIDATE_PATHS = (
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/snap/bin/chromium",
)


def compute_body_sha256(body: bytes) -> str:
    return hashlib.sha256(body or b"").hexdigest()


def sign_device_request(
    shared_secret: str,
    *,
    method: str,
    path_with_query: str,
    body: bytes = b"",
    timestamp: Optional[str] = None,
    nonce: Optional[str] = None,
) -> dict[str, str]:
    """Generate HMAC-SHA256 authentication headers with timestamp & replay nonce."""
    ts = timestamp if timestamp is not None else f"{time.time():.3f}"
    nc = nonce if nonce is not None else secrets.token_hex(16)
    body_hash = compute_body_sha256(body)
    canonical = f"{ts}.{nc}.{method.upper()}.{path_with_query}.{body_hash}".encode("utf-8")
    sig = hmac.new(shared_secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return {
        "X-AllInAgent-Timestamp": ts,
        "X-AllInAgent-Nonce": nc,
        "X-AllInAgent-Signature": sig,
    }


def _is_valid_shared_secret(secret: str) -> bool:
    clean = str(secret or "").strip()
    if len(clean) < MIN_SHARED_SECRET_LEN:
        return False
    lowered = clean.lower()
    return not any(marker in lowered for marker in PLACEHOLDER_SECRET_MARKERS)


def validate_connected_device_url(raw_url: str) -> dict[str, Any]:
    """Ensure `CONNECTED_WINDOWS_DEVICE_URL` uses loopback/private tunnel HTTP or HTTPS."""
    clean = str(raw_url or "").strip()
    if not clean:
        return {"ok": False, "code": "EMPTY_URL", "error": "CONNECTED_WINDOWS_DEVICE_URL is empty."}
    try:
        parsed = urllib.parse.urlparse(clean)
    except Exception as exc:
        return {"ok": False, "code": "INVALID_URL", "error": f"Invalid URL: {exc}"}

    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return {"ok": False, "code": "UNSUPPORTED_SCHEME", "error": "URL scheme must be http or https."}
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return {"ok": False, "code": "MISSING_HOST", "error": "URL hostname is missing."}
    if parsed.username or parsed.password:
        return {"ok": False, "code": "CREDENTIALS_IN_URL_FORBIDDEN", "error": "Do not embed secrets in URL."}

    if scheme == "http":
        if host != "localhost":
            try:
                ip_obj = ipaddress.ip_address(host)
            except ValueError:
                return {
                    "ok": False,
                    "code": "INSECURE_HTTP_NON_TUNNEL_HOST",
                    "error": "Plain HTTP is restricted to loopback (127.0.0.1/::1) or private WireGuard/Tailscale/RFC1918 tunnel IPs; use HTTPS or SSH tunnel.",
                }
            is_private_or_tunnel = ip_obj.is_loopback or is_explicit_private_or_tunnel_ip(ip_obj)
            if not is_private_or_tunnel or ip_obj.is_unspecified:
                return {
                    "ok": False,
                    "code": "PUBLIC_HTTP_FORBIDDEN",
                    "error": f"Refusing unencrypted HTTP connection to non-private IP '{host}'.",
                }

    normalized_base = f"{scheme}://{parsed.netloc}".rstrip("/")
    return {"ok": True, "base_url": normalized_base, "host": host, "port": parsed.port, "scheme": scheme}


def _detect_is_container() -> bool:
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
        return True
    cg = Path("/proc/1/cgroup")
    if cg.is_file():
        try:
            txt = cg.read_text(encoding="utf-8", errors="ignore")
            if any(k in txt for k in ("docker", "containerd", "kubepods", "lxc")):
                return True
        except OSError:
            pass
    return False


def _detect_host_os(override: Optional[str] = None) -> str:
    if override:
        return override.strip().lower()
    sys_name = platform.system().lower()
    if sys_name in {"linux", "darwin", "windows"}:
        return sys_name
    return "windows" if os.name == "nt" else "posix"


def parse_authorized_workspaces(
    env: Optional[Mapping[str, str]] = None,
    *,
    host_os: Optional[str] = None,
) -> list[str]:
    """Parse `AUTHORIZED_WORKSPACES` (defaulting to `/workspaces` on Linux/POSIX)."""
    env_map = env if env is not None else os.environ
    effective_os = _detect_host_os(host_os)
    raw = str(env_map.get("AUTHORIZED_WORKSPACES") or "").strip()
    if not raw:
        if effective_os != "windows":
            return ["/workspaces"]
        # Local Windows fallback only when running server_workspace directly on Windows dev host
        root_fallback = Path(env_map.get("ALLINAGENT_ROOT") or Path(__file__).resolve().parents[2]) / "workspaces"
        return [str(root_fallback.resolve())]

    # Split on comma or semicolon (avoid splitting Windows `C:\` on `:`!)
    parts = [p.strip() for p in re.split(r"[,;]+", raw) if p.strip()]
    if not parts:
        return ["/workspaces"] if effective_os != "windows" else [str((Path.cwd() / "workspaces").resolve())]
    return parts


def is_windows_drive_or_unc_path(raw_path: str) -> bool:
    return bool(WINDOWS_DRIVE_PATH_RE.match(str(raw_path or "").strip()))


def validate_server_workspace_path(
    candidate_path: str,
    *,
    authorized_workspaces: Optional[Iterable[str]] = None,
    host_os: Optional[str] = None,
) -> dict[str, Any]:
    """Validate that `candidate_path` stays strictly inside `AUTHORIZED_WORKSPACES` and is not a secret."""
    effective_os = _detect_host_os(host_os)
    raw = str(candidate_path or "").strip().strip('"').strip("'")
    if not raw:
        return {"ok": False, "code": "EMPTY_WORKSPACE_PATH", "error": "Workspace path cannot be empty."}
    if "\x00" in raw:
        return {"ok": False, "code": "NULL_BYTE_FORBIDDEN", "error": "Null byte in path is forbidden."}

    roots = list(authorized_workspaces) if authorized_workspaces is not None else parse_authorized_workspaces(host_os=effective_os)
    has_windows_style_authorized_root = any(is_windows_drive_or_unc_path(r) for r in roots)

    if effective_os != "windows" and is_windows_drive_or_unc_path(raw) and not has_windows_style_authorized_root:
        return {
            "ok": False,
            "code": "WINDOWS_DRIVE_ON_POSIX_FORBIDDEN",
            "capability_not_supported_on_server": True,
            "error": (
                f"Linux/POSIX server cannot directly read Windows path '{raw}'. "
                "Pair and start windows_runner_agent to access authorized remote Windows folders."
            ),
        }

    resolved_roots: list[Path] = []
    for r in roots:
        try:
            resolved_roots.append(Path(os.path.realpath(os.path.abspath(r))))
        except OSError:
            continue

    if not resolved_roots:
        return {"ok": False, "code": "NO_AUTHORIZED_WORKSPACES", "error": "No AUTHORIZED_WORKSPACES configured."}

    try:
        real_target = Path(os.path.realpath(os.path.abspath(raw)))
    except OSError as exc:
        return {"ok": False, "code": "PATH_RESOLUTION_FAILED", "error": f"Failed to resolve path: {exc}"}

    if SENSITIVE_FILENAME_RE.match(real_target.name):
        return {
            "ok": False,
            "code": "SENSITIVE_SECRET_FILE_BLOCKED",
            "error": f"Access to sensitive file '{real_target.name}' is strictly forbidden.",
        }

    lowered_parts = {p.lower() for p in real_target.parts}
    if ".ssh" in lowered_parts or ".gnupg" in lowered_parts:
        return {
            "ok": False,
            "code": "SENSITIVE_DIRECTORY_BLOCKED",
            "error": "Access to SSH/GPG key directories is strictly forbidden.",
        }

    inside_any = False
    matched_root: Optional[Path] = None
    for root_path in resolved_roots:
        try:
            real_target.relative_to(root_path)
            inside_any = True
            matched_root = root_path
            break
        except ValueError:
            continue

    if not inside_any:
        return {
            "ok": False,
            "code": "OUTSIDE_AUTHORIZED_WORKSPACES",
            "error": (
                f"Path '{real_target}' is outside AUTHORIZED_WORKSPACES "
                f"({[str(r) for r in resolved_roots]})."
            ),
        }

    return {
        "ok": True,
        "resolved_path": str(real_target),
        "matched_workspace_root": str(matched_root),
    }


def _detect_headless_chromium(env: Mapping[str, str]) -> dict[str, Any]:
    playwright_installed = importlib.util.find_spec("playwright") is not None
    explicit_bin = str(env.get("CHROMIUM_PATH") or env.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH") or "").strip()
    found_bin: Optional[str] = None
    if explicit_bin and Path(explicit_bin).is_file():
        found_bin = explicit_bin
    if not found_bin:
        for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "msedge"):
            which_path = shutil.which(name)
            if which_path:
                found_bin = which_path
                break
    if not found_bin:
        for cand in CHROMIUM_CANDIDATE_PATHS:
            if Path(cand).is_file():
                found_bin = cand
                break
    return {
        "available": bool(playwright_installed or found_bin),
        "playwright_python_installed": playwright_installed,
        "chromium_binary": found_bin,
    }


def _detect_virtual_xvfb_desktop(env: Mapping[str, str], host_os: str) -> dict[str, Any]:
    if host_os == "windows":
        return {"available": False, "display": None, "xvfb_binary": None, "note": "POSIX Xvfb applies to Linux hosts/containers."}
    display_val = str(env.get("DISPLAY") or "").strip() or None
    xvfb_bin = shutil.which("Xvfb") or shutil.which("xvfb-run")
    x11_socket_present = False
    if display_val and display_val.startswith(":"):
        disp_num = display_val[1:].split(".", 1)[0]
        if disp_num.isdigit():
            x11_socket_present = Path(f"/tmp/.X11-unix/X{disp_num}").exists()
    return {
        "available": bool((display_val and x11_socket_present) or xvfb_bin),
        "display": display_val,
        "x11_socket_active": x11_socket_present,
        "xvfb_binary": xvfb_bin,
    }


def detect_server_workspace_capabilities(
    env: Optional[Mapping[str, str]] = None,
    *,
    host_os: Optional[str] = None,
) -> dict[str, Any]:
    env_map = env if env is not None else os.environ
    effective_os = _detect_host_os(host_os)
    workspaces = parse_authorized_workspaces(env_map, host_os=effective_os)

    shell_bin = shutil.which("bash") or shutil.which("sh")
    git_bin = shutil.which("git")
    node_bin = shutil.which("node")
    npm_bin = shutil.which("npm")
    python_bin = sys.executable or shutil.which("python3") or shutil.which("python")

    return {
        "plane": "server_workspace",
        "available": True,
        "independent_of_connected_device": True,
        "host_os": effective_os,
        "is_container": _detect_is_container() if host_os is None else False,
        "authorized_workspaces": workspaces,
        "jailed_to_authorized_workspaces": True,
        "windows_drive_direct_access": effective_os == "windows",
        "capabilities": {
            "posix_terminal": {
                "available": bool(shell_bin) or effective_os != "windows",
                "shell": shell_bin,
            },
            "git": {
                "available": bool(git_bin),
                "binary": git_bin,
            },
            "coding": {"available": True},
            "build": {
                "available": True,
                "toolchains": {
                    "python": python_bin,
                    "node": node_bin,
                    "npm": npm_bin,
                },
            },
            "test": {"available": True},
            "source_analysis": {"available": True},
            "headless_chromium": _detect_headless_chromium(env_map),
            "virtual_xvfb_desktop": _detect_virtual_xvfb_desktop(env_map, effective_os),
        },
    }


def invoke_connected_windows_runner(
    *,
    base_url: str,
    shared_secret: str,
    method: str = "GET",
    path: str = "/v1/capabilities",
    payload: Optional[dict[str, Any]] = None,
    timeout: float = 3.0,
    opener: Optional[Callable[..., Any]] = None,
) -> dict[str, Any]:
    """Perform an HMAC-SHA256 authenticated request to a paired `windows_runner_agent`."""
    url_check = validate_connected_device_url(base_url)
    if not url_check["ok"]:
        return {"ok": False, "code": url_check["code"], "error": url_check["error"]}
    if not _is_valid_shared_secret(shared_secret):
        return {
            "ok": False,
            "code": "INVALID_SHARED_SECRET",
            "error": f"CONNECTED_DEVICE_SHARED_SECRET must be >= {MIN_SHARED_SECRET_LEN} non-placeholder characters.",
        }

    clean_path = "/" + path.lstrip("/")
    body_bytes = json.dumps(payload).encode("utf-8") if payload is not None else b""
    sig_headers = sign_device_request(
        shared_secret.strip(),
        method=method.upper(),
        path_with_query=clean_path,
        body=body_bytes,
    )
    headers = {
        **sig_headers,
        "Accept": "application/json",
    }
    if payload is not None:
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        f"{url_check['base_url']}{clean_path}",
        data=body_bytes if method.upper() != "GET" else None,
        headers=headers,
        method=method.upper(),
    )
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
            return {"ok": False, "code": "INVALID_RUNNER_RESPONSE", "error": "Non-object JSON from runner."}
    except urllib.error.HTTPError as http_err:
        err_body = ""
        try:
            err_body = http_err.read().decode("utf-8", errors="replace")
            parsed_err = json.loads(err_body)
            if isinstance(parsed_err, dict):
                return {
                    "ok": False,
                    "http_status": http_err.code,
                    "code": parsed_err.get("code") or f"HTTP_{http_err.code}",
                    "error": parsed_err.get("error") or f"Runner HTTP {http_err.code}",
                }
        except Exception:
            pass
        finally:
            try:
                http_err.close()
            except Exception:
                pass
        return {"ok": False, "http_status": http_err.code, "code": f"HTTP_{http_err.code}", "error": err_body[:200] or str(http_err)}
    except Exception as exc:
        return {"ok": False, "code": "RUNNER_UNREACHABLE", "error": f"Windows runner unreachable: {exc}"}


def detect_windows_connected_device(
    env: Optional[Mapping[str, str]] = None,
    *,
    probe_timeout: float = 3.0,
    opener: Optional[Callable[..., Any]] = None,
) -> dict[str, Any]:
    """Probe the optional paired `windows_connected_device` and report its honest runtime state."""
    env_map = env if env is not None else os.environ
    raw_url = str(env_map.get("CONNECTED_WINDOWS_DEVICE_URL") or "").strip()
    raw_secret = str(env_map.get("CONNECTED_DEVICE_SHARED_SECRET") or "").strip()

    if not raw_url and not raw_secret:
        return {
            "plane": "windows_connected_device",
            "configured": False,
            "paired": False,
            "state": "unpaired",
            "device_online": False,
            "device_offline": True,
            "interactive_desktop_available": False,
            "authorized_windows_roots": [],
            "capability_not_supported": True,
            "supported_operations": [],
            "endpoint_url": None,
            "status_reason": (
                "No Windows device paired (CONNECTED_WINDOWS_DEVICE_URL unset). "
                "Server workspace features remain 100% active; remote Windows C:/D: drives and Windows GUI are capability_not_supported."
            ),
        }

    url_check = validate_connected_device_url(raw_url)
    if not url_check["ok"]:
        return {
            "plane": "windows_connected_device",
            "configured": True,
            "paired": False,
            "state": "configuration_error",
            "device_online": False,
            "device_offline": True,
            "interactive_desktop_available": False,
            "authorized_windows_roots": [],
            "capability_not_supported": True,
            "supported_operations": [],
            "endpoint_url": None,
            "error_code": url_check["code"],
            "status_reason": url_check["error"],
        }

    if not _is_valid_shared_secret(raw_secret):
        return {
            "plane": "windows_connected_device",
            "configured": True,
            "paired": False,
            "state": "configuration_error",
            "device_online": False,
            "device_offline": True,
            "interactive_desktop_available": False,
            "authorized_windows_roots": [],
            "capability_not_supported": True,
            "supported_operations": [],
            "endpoint_url": url_check["base_url"],
            "error_code": "INVALID_SHARED_SECRET",
            "status_reason": (
                f"CONNECTED_DEVICE_SHARED_SECRET is missing, placeholder, or shorter than {MIN_SHARED_SECRET_LEN} characters."
            ),
        }

    probe = invoke_connected_windows_runner(
        base_url=url_check["base_url"],
        shared_secret=raw_secret,
        method="GET",
        path="/v1/capabilities",
        timeout=probe_timeout,
        opener=opener,
    )
    if not probe.get("ok"):
        return {
            "plane": "windows_connected_device",
            "configured": True,
            "paired": True,
            "state": "device_offline",
            "device_online": False,
            "device_offline": True,
            "interactive_desktop_available": False,
            "authorized_windows_roots": [],
            "capability_not_supported": False,
            "supported_operations": [],
            "endpoint_url": url_check["base_url"],
            "error_code": probe.get("code") or "DEVICE_OFFLINE",
            "status_reason": f"Paired Windows runner is offline or unreachable ({probe.get('code')}: {probe.get('error')}).",
        }

    roots = [str(r) for r in (probe.get("authorized_windows_roots") or []) if isinstance(r, str) and r.strip()]
    ops = [str(o) for o in (probe.get("supported_operations") or []) if isinstance(o, str)]
    desktop_ok = bool(probe.get("interactive_desktop_available", False))
    return {
        "plane": "windows_connected_device",
        "configured": True,
        "paired": True,
        "state": "device_online",
        "device_online": True,
        "device_offline": False,
        "interactive_desktop_available": desktop_ok,
        "authorized_windows_roots": roots,
        "capability_not_supported": False,
        "supported_operations": ops,
        "endpoint_url": url_check["base_url"],
        "status_reason": "Paired Windows runner is online and authenticated via HMAC-SHA256.",
    }


def detect_capability_matrix(
    env: Optional[Mapping[str, str]] = None,
    *,
    host_os: Optional[str] = None,
    probe_timeout: float = 3.0,
    opener: Optional[Callable[..., Any]] = None,
) -> dict[str, Any]:
    """Build the unified capability matrix across `server_workspace` and `windows_connected_device`."""
    server_plane = detect_server_workspace_capabilities(env=env, host_os=host_os)
    win_plane = detect_windows_connected_device(env=env, probe_timeout=probe_timeout, opener=opener)
    return {
        "schema_version": "1.0.0",
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "server_features_independent": True,
        "server_workspace": server_plane,
        "windows_connected_device": win_plane,
    }


def _windows_path_under_authorized_roots(candidate_win_path: str, authorized_roots: Iterable[str]) -> bool:
    def _norm_win(p: str) -> str:
        cleaned = re.sub(r"[\\/]+", "\\\\", p.strip().strip('"').strip("'")).rstrip("\\")
        return cleaned.lower()

    cand = _norm_win(candidate_win_path)
    if not cand or ".." in cand.split("\\"):
        return False
    base_name = cand.rsplit("\\", 1)[-1]
    if SENSITIVE_FILENAME_RE.match(base_name):
        return False
    for root in authorized_roots:
        norm_r = _norm_win(root)
        if not norm_r:
            continue
        if cand == norm_r or cand.startswith(norm_r + "\\"):
            return True
    return False


def resolve_capability_request(
    action: str,
    *,
    target_path: str = "",
    matrix: Optional[dict[str, Any]] = None,
    env: Optional[Mapping[str, str]] = None,
    host_os: Optional[str] = None,
) -> dict[str, Any]:
    """Route an action/path honestly to `server_workspace` or `windows_connected_device` without false claims."""
    mat = matrix or detect_capability_matrix(env=env, host_os=host_os)
    srv = mat["server_workspace"]
    win = mat["windows_connected_device"]
    srv_os = srv["host_os"]
    norm_action = str(action or "").strip().lower()
    clean_path = str(target_path or "").strip()

    windows_only_actions = {"windows_interactive_desktop", "windows_gui_screenshot", "windows_native_app"}
    matches_local_server_workspace = False
    if clean_path and srv["authorized_workspaces"]:
        cand_check = validate_server_workspace_path(
            clean_path,
            authorized_workspaces=srv["authorized_workspaces"],
            host_os=srv_os,
        )
        if cand_check["ok"] or cand_check.get("code") == "SENSITIVE_SECRET_FILE_BLOCKED":
            matches_local_server_workspace = True

    requires_windows_runner = norm_action in windows_only_actions or (
        bool(clean_path)
        and srv_os != "windows"
        and is_windows_drive_or_unc_path(clean_path)
        and not matches_local_server_workspace
    )

    if requires_windows_runner:
        if not win["paired"]:
            return {
                "allowed": False,
                "plane": "windows_connected_device",
                "status": "capability_not_supported",
                "reason": (
                    "Requested Windows desktop/drive capability is not supported on an unpaired server. "
                    "All server_workspace capabilities (/workspaces) remain available."
                ),
            }
        if not win["device_online"]:
            return {
                "allowed": False,
                "plane": "windows_connected_device",
                "status": "device_offline",
                "reason": win["status_reason"],
            }
        if norm_action in {"windows_interactive_desktop", "windows_gui_screenshot"} and not win["interactive_desktop_available"]:
            return {
                "allowed": False,
                "plane": "windows_connected_device",
                "status": "capability_not_supported",
                "reason": "Paired Windows runner is online, but interactive desktop capture is disabled or unavailable.",
            }
        if clean_path and not _windows_path_under_authorized_roots(clean_path, win["authorized_windows_roots"]):
            return {
                "allowed": False,
                "plane": "windows_connected_device",
                "status": "forbidden_windows_root",
                "reason": (
                    f"Windows path '{clean_path}' is outside AUTHORIZED_WINDOWS_ROOTS "
                    f"({win['authorized_windows_roots']}) or targets a protected secret file."
                ),
            }
        return {
            "allowed": True,
            "plane": "windows_connected_device",
            "status": "device_online",
            "reason": "Authorized on online paired Windows runner.",
        }

    # Server workspace plane
    if clean_path:
        path_check = validate_server_workspace_path(
            clean_path,
            authorized_workspaces=srv["authorized_workspaces"],
            host_os=srv_os,
        )
        if not path_check["ok"]:
            return {
                "allowed": False,
                "plane": "server_workspace",
                "status": "forbidden_workspace_path",
                "code": path_check["code"],
                "reason": path_check["error"],
            }

    if norm_action == "headless_chromium" and not srv["capabilities"]["headless_chromium"]["available"]:
        return {
            "allowed": False,
            "plane": "server_workspace",
            "status": "capability_not_supported",
            "reason": "Headless Chromium / Playwright is not installed in this server environment.",
        }
    if norm_action == "virtual_xvfb_desktop" and not srv["capabilities"]["virtual_xvfb_desktop"]["available"]:
        return {
            "allowed": False,
            "plane": "server_workspace",
            "status": "capability_not_supported",
            "reason": "Virtual Xvfb desktop (DISPLAY) is not installed or active on this server.",
        }

    return {
        "allowed": True,
        "plane": "server_workspace",
        "status": "supported",
        "reason": "Supported natively inside server_workspace.",
    }


def run_self_checks() -> dict[str, Any]:
    """Run deterministic self-checks verifying Linux server jail, unpaired/offline/online Windows honesty."""
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: Any = "") -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": str(detail)[:240]})
        if not passed:
            raise AssertionError(f"Self-check failed [{name}]: {detail}")

    with tempfile.TemporaryDirectory(prefix="allinagent-ws-test-") as tmp:
        ws_dir = Path(tmp) / "workspaces"
        proj_dir = ws_dir / "sample-project"
        proj_dir.mkdir(parents=True)
        (proj_dir / "README.md").write_text("# Sample\n", encoding="utf-8")
        (proj_dir / ".env").write_text("DUMMY=1\n", encoding="utf-8")

        # 1. Linux server unpaired matrix: 100% server features work, C:\ honestly rejected!
        unpaired_env = {"AUTHORIZED_WORKSPACES": str(ws_dir)}
        mat_unpaired = detect_capability_matrix(env=unpaired_env, host_os="linux")
        record(
            "unpaired_server_workspace_available",
            mat_unpaired["server_workspace"]["available"] is True
            and mat_unpaired["windows_connected_device"]["paired"] is False
            and mat_unpaired["windows_connected_device"]["capability_not_supported"] is True,
        )

        srv_git_req = resolve_capability_request(
            "git",
            target_path=str(proj_dir),
            matrix=mat_unpaired,
        )
        record("server_git_works_when_windows_unpaired", srv_git_req["allowed"] is True and srv_git_req["plane"] == "server_workspace")

        win_drive_unpaired = resolve_capability_request(
            "source_analysis",
            target_path=r"C:\Projects\DemoApp",
            matrix=mat_unpaired,
        )
        record(
            "ubuntu_server_never_claims_c_drive_when_unpaired",
            win_drive_unpaired["allowed"] is False and win_drive_unpaired["status"] == "capability_not_supported",
            win_drive_unpaired,
        )

        # 2. Workspace jail & .env secret protection
        outside_req = resolve_capability_request(
            "source_analysis",
            target_path="/etc/passwd",
            matrix=mat_unpaired,
        )
        record("outside_workspace_jailed", outside_req["allowed"] is False and outside_req["status"] == "forbidden_workspace_path")

        env_file_req = resolve_capability_request(
            "source_analysis",
            target_path=str(proj_dir / ".env"),
            matrix=mat_unpaired,
        )
        record("workspace_dotenv_blocked", env_file_req["allowed"] is False and env_file_req["code"] == "SENSITIVE_SECRET_FILE_BLOCKED")

        # 3. Paired but offline Windows runner -> reports device_offline honestly while server works!
        valid_secret = secrets.token_hex(32)
        offline_env = {
            "AUTHORIZED_WORKSPACES": str(ws_dir),
            "CONNECTED_WINDOWS_DEVICE_URL": "http://127.0.0.1:9",  # discard/closed port
            "CONNECTED_DEVICE_SHARED_SECRET": valid_secret,
        }
        mat_offline = detect_capability_matrix(env=offline_env, host_os="linux", probe_timeout=0.4)
        record(
            "paired_offline_reported_honestly",
            mat_offline["windows_connected_device"]["paired"] is True
            and mat_offline["windows_connected_device"]["device_offline"] is True
            and mat_offline["windows_connected_device"]["device_online"] is False
            and mat_offline["server_workspace"]["available"] is True,
        )
        win_drive_offline = resolve_capability_request(
            "source_analysis",
            target_path=r"D:\Projects\ClientApp",
            matrix=mat_offline,
        )
        record(
            "c_or_d_drive_reports_device_offline_when_runner_down",
            win_drive_offline["allowed"] is False and win_drive_offline["status"] == "device_offline",
        )

        # 4. Public unencrypted HTTP URL rejected
        bad_url_check = validate_connected_device_url("http://203.0.113.55:8670")
        record("public_http_runner_url_rejected", not bad_url_check["ok"] and bad_url_check["code"] == "PUBLIC_HTTP_FORBIDDEN")

    return {"ok": True, "total_checks": len(checks), "checks": checks}


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capability_discovery.py",
        description="Detect server_workspace and optional windows_connected_device runtime capabilities.",
    )
    parser.add_argument("--detect", action="store_true", help="Detect full capability matrix.")
    parser.add_argument("--check-action", default="", help="Check routing & support for a specific action.")
    parser.add_argument("--target-path", default="", help="Optional target path to validate with --check-action.")
    parser.add_argument("--self-check", action="store_true", help="Run deterministic unit self-checks.")
    parser.add_argument("--json", action="store_true", help="Output JSON.")
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.self_check:
        res = run_self_checks()
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"[PASS] capability_discovery self-checks passed ({res['total_checks']}/{res['total_checks']}).")
        return 0

    if args.check_action:
        verdict = resolve_capability_request(args.check_action, target_path=args.target_path)
        if args.json:
            print(json.dumps(verdict, indent=2))
        else:
            print(f"[{verdict['status'].upper()}] plane={verdict['plane']} allowed={verdict['allowed']} — {verdict['reason']}")
        return 0 if verdict["allowed"] else 1

    matrix = detect_capability_matrix()
    if args.json or args.detect:
        print(json.dumps(matrix, indent=2))
    else:
        print(json.dumps(matrix, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
