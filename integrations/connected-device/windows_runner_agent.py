#!/usr/bin/env python3
"""ALLINAGENT Phase 16 — Optional Paired Windows Runner Agent (`windows_runner_agent.py`).

A lightweight, zero-dependency stdlib agent that a Windows user can explicitly pair and bind
to a loopback / SSH-tunneled (`127.0.0.1:8670`) or private WireGuard/Tailscale interface.

Security Invariants (Non-Negotiable):
  1. NEVER binds to `0.0.0.0`, `::`, or any public internet IP (`PUBLIC_WILDCARD_BIND_FORBIDDEN`).
  2. NEVER runs as permanent Administrator / root (`PERMANENT_ADMIN_FORBIDDEN`).
  3. NEVER exposes arbitrary shell/command execution (`RCE_ENDPOINT_FORBIDDEN`).
  4. Every `/v1/*` request requires HMAC-SHA256 signature + bounded timestamp skew (`<= 60s`)
     + cryptographic nonce replay protection (`401` / `409`).
  5. Every filesystem operation is jailed strictly inside explicit `AUTHORIZED_WINDOWS_ROOTS`
     with canonical `realpath` symlink/junction escape detection and secret-file blocking.
"""

from __future__ import annotations

import argparse
import ctypes
import hmac
import http.server
import ipaddress
import json
import os
import re
import secrets
import socketserver
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from capability_discovery import (  # noqa: E402
    MIN_SHARED_SECRET_LEN,
    PLACEHOLDER_SECRET_MARKERS,
    SENSITIVE_FILENAME_RE,
    compute_body_sha256,
    detect_capability_matrix,
    invoke_connected_windows_runner,
    is_explicit_private_or_tunnel_ip,
    resolve_capability_request,
    sign_device_request,
)

DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 8670
MAX_READ_BYTES = 256 * 1024  # 256 KiB cap per file read
MAX_REQUEST_BODY_BYTES = 64 * 1024  # 64 KiB cap on inbound JSON request bodies
NONCE_FORMAT_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")

FORBIDDEN_DIR_SEGMENTS = frozenset(
    {
        "windows",
        "system32",
        "program files",
        "program files (x86)",
        "programdata",
        "appdata",
        "$recycle.bin",
        "system volume information",
        ".ssh",
        ".gnupg",
        "secrets",
    }
)


def is_elevated_admin() -> bool:
    """Detect whether the current process is running with permanent Administrator / root privileges."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid):
        return int(geteuid()) == 0
    return False


def enforce_least_privilege(*, is_admin_fn: Optional[Callable[[], bool]] = None) -> None:
    """Refuse permanent Administrator / root execution."""
    check_fn = is_admin_fn or is_elevated_admin
    if check_fn():
        raise PermissionError(
            "PERMANENT_ADMIN_FORBIDDEN: windows_runner_agent must run under a standard non-elevated user account."
        )


def validate_private_bind_host(host: str, *, allow_private_tunnel_ip: bool = False) -> str:
    """Validate bind address, strictly rejecting `0.0.0.0`, `::`, `*`, or any public IP."""
    clean = str(host or "").strip().lower()
    if not clean or clean in {"0.0.0.0", "::", "[::]", "*"}:
        raise ValueError(
            f"PUBLIC_WILDCARD_BIND_FORBIDDEN: Refusing to bind windows_runner_agent to wildcard '{host}'."
        )
    if clean == "localhost":
        return "127.0.0.1"

    stripped = clean.strip("[]")
    try:
        ip_obj = ipaddress.ip_address(stripped)
    except ValueError as exc:
        raise ValueError(
            f"INVALID_BIND_ADDRESS: '{host}' is not a valid IP literal (use 127.0.0.1 or a private tunnel IP)."
        ) from exc

    if ip_obj.is_unspecified or ip_obj.is_multicast or ip_obj.is_link_local:
        raise ValueError(
            f"PUBLIC_WILDCARD_BIND_FORBIDDEN: Bind address '{host}' is unspecified, link-local, or multicast."
        )

    if ip_obj.is_loopback:
        return str(ip_obj)

    is_private_tunnel = is_explicit_private_or_tunnel_ip(ip_obj)
    if is_private_tunnel and allow_private_tunnel_ip:
        return str(ip_obj)

    if is_private_tunnel and not allow_private_tunnel_ip:
        raise ValueError(
            f"LOOPBACK_ONLY_BY_DEFAULT: '{host}' is a private/tunnel IP; pass --allow-private-tunnel-ip "
            "explicitly if binding directly to a WireGuard/Tailscale interface instead of SSH loopback."
        )

    raise ValueError(f"PUBLIC_WILDCARD_BIND_FORBIDDEN: Refusing to bind to public IP '{host}'.")


def _is_bare_filesystem_root(path_obj: Path) -> bool:
    resolved = path_obj.resolve()
    return resolved == resolved.anchor or str(resolved).rstrip("\\/") in {"", resolved.drive}


class HmacReplayGuard:
    """Thread-safe HMAC-SHA256 request authenticator with timestamp skew & nonce replay protection."""

    def __init__(self, shared_secret: str, *, max_skew_seconds: float = 60.0) -> None:
        clean = str(shared_secret or "").strip()
        if len(clean) < MIN_SHARED_SECRET_LEN or any(m in clean.lower() for m in PLACEHOLDER_SECRET_MARKERS):
            raise ValueError(
                f"INVALID_SHARED_SECRET: CONNECTED_DEVICE_SHARED_SECRET must be >= {MIN_SHARED_SECRET_LEN} random characters."
            )
        self._secret_bytes = clean.encode("utf-8")
        self._max_skew = float(max_skew_seconds)
        self._nonce_ttl = (2.0 * self._max_skew) + 15.0
        self._seen_nonces: dict[str, float] = {}
        self._lock = threading.Lock()

    def verify(
        self,
        *,
        method: str,
        path_with_query: str,
        body: bytes,
        timestamp_header: str,
        nonce_header: str,
        signature_header: str,
        now_epoch: Optional[float] = None,
    ) -> dict[str, Any]:
        ts_str = str(timestamp_header or "").strip()
        nonce = str(nonce_header or "").strip()
        sig = str(signature_header or "").strip().lower()

        if not ts_str or not nonce or not sig:
            return {
                "ok": False,
                "status": 401,
                "code": "MISSING_AUTH_HEADERS",
                "error": "Missing X-AllInAgent-Timestamp, X-AllInAgent-Nonce, or X-AllInAgent-Signature.",
            }

        try:
            ts_val = float(ts_str)
        except ValueError:
            return {
                "ok": False,
                "status": 401,
                "code": "INVALID_TIMESTAMP",
                "error": "X-AllInAgent-Timestamp must be Unix epoch seconds.",
            }

        now = float(now_epoch if now_epoch is not None else time.time())
        if abs(now - ts_val) > self._max_skew:
            return {
                "ok": False,
                "status": 401,
                "code": "TIMESTAMP_SKEW_EXCEEDED",
                "error": f"Request timestamp skew exceeds {int(self._max_skew)}s replay window.",
            }

        if not NONCE_FORMAT_RE.match(nonce):
            return {
                "ok": False,
                "status": 401,
                "code": "INVALID_NONCE_FORMAT",
                "error": "X-AllInAgent-Nonce must be 16..128 URL-safe characters.",
            }

        body_hash = compute_body_sha256(body)
        canonical = f"{ts_str}.{nonce}.{method.upper()}.{path_with_query}.{body_hash}".encode("utf-8")
        expected_sig = hmac.new(self._secret_bytes, canonical, "sha256").hexdigest().lower()

        if not hmac.compare_digest(sig, expected_sig):
            return {
                "ok": False,
                "status": 401,
                "code": "INVALID_HMAC_SIGNATURE",
                "error": "HMAC-SHA256 signature verification failed.",
            }

        with self._lock:
            # Prune expired nonces
            cutoff = now - self._nonce_ttl
            expired_keys = [k for k, seen_at in self._seen_nonces.items() if seen_at < cutoff]
            for k in expired_keys:
                self._seen_nonces.pop(k, None)

            if nonce in self._seen_nonces:
                return {
                    "ok": False,
                    "status": 409,
                    "code": "REPLAY_DETECTED",
                    "error": "Replayed X-AllInAgent-Nonce rejected.",
                }
            self._seen_nonces[nonce] = now

        return {"ok": True}


class AuthorizedWindowsRootsJail:
    """Canonical realpath & secret-aware allowlist jail for `AUTHORIZED_WINDOWS_ROOTS`."""

    def __init__(self, roots: Iterable[str]) -> None:
        resolved_roots: list[Path] = []
        for raw in roots:
            s = str(raw or "").strip().strip('"').strip("'")
            if not s:
                continue
            cand = Path(os.path.realpath(os.path.abspath(s)))
            if not cand.exists() or not cand.is_dir():
                raise ValueError(f"INVALID_AUTHORIZED_ROOT: Directory does not exist: '{s}'")
            if _is_bare_filesystem_root(cand):
                raise ValueError(
                    f"BARE_DRIVE_ROOT_FORBIDDEN: Refusing bare filesystem root '{cand}'; specify explicit project folders."
                )
            lowered_parts = {p.lower() for p in cand.parts}
            # Note: allow temp dirs during unit tests only when candidate itself isn't pointing at secrets/ssh;
            # block system roots (`windows`, `system32`, `program files`, `.ssh`, `secrets`).
            if lowered_parts & {"windows", "system32", "program files", "program files (x86)", ".ssh", ".gnupg", "secrets"}:
                raise ValueError(f"PROTECTED_SYSTEM_ROOT_FORBIDDEN: '{cand}' cannot be added to AUTHORIZED_WINDOWS_ROOTS.")
            resolved_roots.append(cand)

        if not resolved_roots:
            raise ValueError("EMPTY_AUTHORIZED_ROOTS: At least one explicit directory in AUTHORIZED_WINDOWS_ROOTS is required.")
        self._roots = resolved_roots

    @property
    def roots(self) -> list[str]:
        return [str(r) for r in self._roots]

    def validate_path(self, candidate: str, *, allow_file: bool = True) -> dict[str, Any]:
        raw = str(candidate or "").strip().strip('"').strip("'")
        if not raw:
            return {"ok": False, "status": 400, "code": "EMPTY_PATH", "error": "Target path cannot be empty."}
        if "\x00" in raw:
            return {"ok": False, "status": 400, "code": "NULL_BYTE_PATH", "error": "Null byte in path is forbidden."}

        try:
            nominal = Path(os.path.abspath(raw))
            real = Path(os.path.realpath(str(nominal)))
        except OSError as exc:
            return {"ok": False, "status": 403, "code": "PATH_RESOLVE_ERROR", "error": str(exc)}

        if SENSITIVE_FILENAME_RE.match(nominal.name) or SENSITIVE_FILENAME_RE.match(real.name):
            return {
                "ok": False,
                "status": 403,
                "code": "SENSITIVE_SECRET_FILE_BLOCKED",
                "error": f"Access to secret/credential file '{real.name}' is strictly blocked.",
            }

        matched_root: Optional[Path] = None
        for root in self._roots:
            try:
                real.relative_to(root)
                matched_root = root
                break
            except ValueError:
                continue

        if matched_root is None:
            return {
                "ok": False,
                "status": 403,
                "code": "OUTSIDE_AUTHORIZED_WINDOWS_ROOTS",
                "error": f"Path is outside AUTHORIZED_WINDOWS_ROOTS ({self.roots}).",
            }

        rel_segments = {seg.lower() for seg in real.relative_to(matched_root).parts}
        if rel_segments & FORBIDDEN_DIR_SEGMENTS:
            return {
                "ok": False,
                "status": 403,
                "code": "PROTECTED_SUBDIRECTORY_BLOCKED",
                "error": "Path traverses into a protected subdirectory (.ssh, secrets, system).",
            }

        if not real.exists():
            return {"ok": False, "status": 404, "code": "PATH_NOT_FOUND", "error": "Requested path does not exist."}

        if not allow_file and not real.is_dir():
            return {"ok": False, "status": 400, "code": "NOT_A_DIRECTORY", "error": "Expected a directory path."}

        return {"ok": True, "resolved": real, "matched_root": matched_root}


def detect_interactive_windows_desktop(*, enabled_by_config: bool = False) -> bool:
    """Detect whether interactive desktop GUI operations are both opted-in and attached to an interactive session."""
    if not enabled_by_config:
        return False
    if os.name != "nt":
        return False
    try:
        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        w_px = int(user32.GetSystemMetrics(0))
        h_px = int(user32.GetSystemMetrics(1))
        return w_px > 0 and h_px > 0
    except Exception:
        return False


class _ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = False


def create_runner_http_server(
    *,
    bind_host: str = DEFAULT_BIND_HOST,
    bind_port: int = DEFAULT_BIND_PORT,
    shared_secret: str,
    authorized_roots: Iterable[str],
    allow_private_tunnel_ip: bool = False,
    enable_interactive_desktop: bool = False,
    max_skew_seconds: float = 60.0,
    is_admin_fn: Optional[Callable[[], bool]] = None,
) -> _ThreadedHTTPServer:
    """Construct a hardened `windows_runner_agent` HTTP server instance."""
    enforce_least_privilege(is_admin_fn=is_admin_fn)
    validated_host = validate_private_bind_host(bind_host, allow_private_tunnel_ip=allow_private_tunnel_ip)
    auth_guard = HmacReplayGuard(shared_secret, max_skew_seconds=max_skew_seconds)
    root_jail = AuthorizedWindowsRootsJail(authorized_roots)

    class RunnerRequestHandler(http.server.BaseHTTPRequestHandler):
        server_version = "ALLINAGENTWindowsRunner/1.0"

        def log_message(self, format_str: str, *args: Any) -> None:
            # Suppress default stderr access logging to avoid leaking query parameters
            return

        def _send_json(self, status: int, obj: dict[str, Any]) -> None:
            payload = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def _authenticate(self, body: bytes) -> bool:
            verdict = auth_guard.verify(
                method=self.command,
                path_with_query=self.path,
                body=body,
                timestamp_header=self.headers.get("X-AllInAgent-Timestamp", ""),
                nonce_header=self.headers.get("X-AllInAgent-Nonce", ""),
                signature_header=self.headers.get("X-AllInAgent-Signature", ""),
            )
            if not verdict["ok"]:
                self._send_json(verdict["status"], {"ok": False, "code": verdict["code"], "error": verdict["error"]})
                return False
            return True

        def _read_bounded_body(self) -> Optional[bytes]:
            raw_len = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_len)
            except ValueError:
                self._send_json(400, {"ok": False, "code": "INVALID_CONTENT_LENGTH", "error": "Invalid Content-Length."})
                return None
            if length < 0 or length > MAX_REQUEST_BODY_BYTES:
                self._send_json(413, {"ok": False, "code": "PAYLOAD_TOO_LARGE", "error": "Request body exceeds 64 KiB limit."})
                return None
            return self.rfile.read(length) if length > 0 else b""

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "service": "allinagent-windows-runner",
                        "hmac_auth_required": True,
                    },
                )
                return

            if not self._authenticate(b""):
                return

            if self.path == "/v1/capabilities":
                desktop_ok = detect_interactive_windows_desktop(enabled_by_config=enable_interactive_desktop)
                ops = ["fs.list", "fs.stat", "fs.read"]
                if desktop_ok:
                    ops.append("desktop.status")
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "device_online": True,
                        "elevated_admin": False,
                        "interactive_desktop_available": desktop_ok,
                        "authorized_windows_roots": root_jail.roots,
                        "supported_operations": ops,
                    },
                )
                return

            self._send_json(404, {"ok": False, "code": "ENDPOINT_NOT_FOUND", "error": "Unknown GET endpoint."})

        def do_POST(self) -> None:  # noqa: N802
            body = self._read_bounded_body()
            if body is None:
                return
            if not self._authenticate(body):
                return

            if any(self.path.startswith(p) for p in ("/v1/exec", "/v1/shell", "/v1/cmd", "/v1/powershell")):
                self._send_json(
                    403,
                    {
                        "ok": False,
                        "code": "RCE_ENDPOINT_FORBIDDEN",
                        "error": "Arbitrary shell/command execution is prohibited by security design.",
                    },
                )
                return

            try:
                data = json.loads(body.decode("utf-8")) if body else {}
                if not isinstance(data, dict):
                    raise ValueError("Body must be a JSON object.")
            except Exception as exc:
                self._send_json(400, {"ok": False, "code": "INVALID_JSON", "error": str(exc)})
                return

            if self.path == "/v1/fs/stat":
                check = root_jail.validate_path(str(data.get("path") or ""), allow_file=True)
                if not check["ok"]:
                    self._send_json(check["status"], {"ok": False, "code": check["code"], "error": check["error"]})
                    return
                resolved: Path = check["resolved"]
                st = resolved.stat()
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "path": str(resolved),
                        "is_dir": resolved.is_dir(),
                        "is_file": resolved.is_file(),
                        "size_bytes": st.st_size,
                        "mtime_epoch": st.st_mtime,
                    },
                )
                return

            if self.path == "/v1/fs/list":
                check = root_jail.validate_path(str(data.get("path") or ""), allow_file=False)
                if not check["ok"]:
                    self._send_json(check["status"], {"ok": False, "code": check["code"], "error": check["error"]})
                    return
                resolved_dir: Path = check["resolved"]
                dirs: list[str] = []
                files: list[dict[str, Any]] = []
                for entry in sorted(resolved_dir.iterdir(), key=lambda x: x.name.lower()):
                    if SENSITIVE_FILENAME_RE.match(entry.name) or entry.name.lower() in FORBIDDEN_DIR_SEGMENTS:
                        continue
                    sub_check = root_jail.validate_path(str(entry), allow_file=True)
                    if not sub_check["ok"]:
                        continue
                    if entry.is_dir():
                        dirs.append(entry.name)
                    elif entry.is_file():
                        files.append({"name": entry.name, "size_bytes": entry.stat().st_size})
                    if len(dirs) + len(files) >= 200:
                        break
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "path": str(resolved_dir),
                        "directories": dirs,
                        "files": files,
                    },
                )
                return

            if self.path == "/v1/fs/read":
                check = root_jail.validate_path(str(data.get("path") or ""), allow_file=True)
                if not check["ok"]:
                    self._send_json(check["status"], {"ok": False, "code": check["code"], "error": check["error"]})
                    return
                resolved_file: Path = check["resolved"]
                if not resolved_file.is_file():
                    self._send_json(400, {"ok": False, "code": "NOT_A_FILE", "error": "Target is a directory, not a file."})
                    return
                max_bytes = min(MAX_READ_BYTES, max(1, int(data.get("max_bytes") or MAX_READ_BYTES)))
                with resolved_file.open("rb") as fh:
                    chunk = fh.read(max_bytes)
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "path": str(resolved_file),
                        "bytes_read": len(chunk),
                        "truncated": resolved_file.stat().st_size > len(chunk),
                        "content": chunk.decode("utf-8", errors="replace"),
                    },
                )
                return

            if self.path == "/v1/desktop/status":
                desktop_ok = detect_interactive_windows_desktop(enabled_by_config=enable_interactive_desktop)
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "interactive_desktop_available": desktop_ok,
                    },
                )
                return

            self._send_json(404, {"ok": False, "code": "ENDPOINT_NOT_FOUND", "error": "Unknown POST endpoint."})

    return _ThreadedHTTPServer((validated_host, int(bind_port)), RunnerRequestHandler)


def parse_roots_from_env_or_args(cli_roots: Optional[list[str]] = None) -> list[str]:
    if cli_roots:
        return [r.strip() for r in cli_roots if r.strip()]
    raw = (os.environ.get("AUTHORIZED_WINDOWS_ROOTS") or "").strip()
    if not raw:
        return []
    return [p.strip() for p in re.split(r"[;,]+", raw) if p.strip()]


def generate_pairing_template() -> dict[str, Any]:
    """Generate fresh pairing configuration instructions (with ephemeral random secret)."""
    fresh_secret = secrets.token_hex(32)
    return {
        "bind_default": f"{DEFAULT_BIND_HOST}:{DEFAULT_BIND_PORT}",
        "ssh_reverse_tunnel_example": (
            f"ssh -N -o ExitOnForwardFailure=yes -R 127.0.0.1:{DEFAULT_BIND_PORT}:127.0.0.1:{DEFAULT_BIND_PORT} "
            "ubuntu@your-allinagent-server.example"
        ),
        "server_env": {
            "CONNECTED_WINDOWS_DEVICE_URL": f"http://127.0.0.1:{DEFAULT_BIND_PORT}",
            "CONNECTED_DEVICE_SHARED_SECRET": fresh_secret,
        },
        "windows_runner_env": {
            "CONNECTED_DEVICE_SHARED_SECRET": fresh_secret,
            "AUTHORIZED_WINDOWS_ROOTS": r"D:\Projects;C:\Workspaces",
        },
    }


def run_self_checks() -> dict[str, Any]:
    """Run comprehensive security & live loopback integration tests in isolated temp directories."""
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: Any = "") -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": str(detail)[:240]})
        if not passed:
            raise AssertionError(f"Self-check failed [{name}]: {detail}")

    # 1. Wildcard & public IP bind rejection
    for bad_host in ("0.0.0.0", "::", "*", "198.51.100.42"):
        rejected = False
        try:
            validate_private_bind_host(bad_host, allow_private_tunnel_ip=True)
        except ValueError:
            rejected = True
        record(f"reject_public_or_wildcard_bind:{bad_host}", rejected)

    record("allow_loopback_bind", validate_private_bind_host("127.0.0.1") == "127.0.0.1")
    record(
        "allow_tailscale_cgnat_only_when_opted_in",
        validate_private_bind_host("100.94.10.20", allow_private_tunnel_ip=True) == "100.94.10.20",
    )

    # 2. Permanent admin privilege rejection
    admin_blocked = False
    try:
        enforce_least_privilege(is_admin_fn=lambda: True)
    except PermissionError:
        admin_blocked = True
    record("permanent_admin_privilege_rejected", admin_blocked)

    # 3. Live loopback server + HMAC + replay + AUTHORIZED_WINDOWS_ROOTS jail + capability_discovery E2E
    with tempfile.TemporaryDirectory(prefix="allinagent-winrunner-test-") as tmp:
        tmp_path = Path(tmp)
        allowed_proj = tmp_path / "AllowedProject"
        outside_proj = tmp_path / "OutsideSecretArea"
        allowed_proj.mkdir()
        outside_proj.mkdir()
        (allowed_proj / "app.py").write_text("print('hello allinagent')\n", encoding="utf-8")
        (allowed_proj / ".env").write_text("DO_NOT_READ=1\n", encoding="utf-8")
        (outside_proj / "private.txt").write_text("outside\n", encoding="utf-8")

        shared_secret = secrets.token_hex(32)
        httpd = create_runner_http_server(
            bind_host="127.0.0.1",
            bind_port=0,  # OS-assigned ephemeral loopback port
            shared_secret=shared_secret,
            authorized_roots=[str(allowed_proj)],
            enable_interactive_desktop=False,
            is_admin_fn=lambda: False,
        )
        port = httpd.server_address[1]
        base_url = f"http://127.0.0.1:{port}"
        srv_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        srv_thread.start()

        try:
            # 3a. Capability discovery sees device_online + exact authorized_windows_roots
            env_online = {
                "AUTHORIZED_WORKSPACES": str(allowed_proj),
                "CONNECTED_WINDOWS_DEVICE_URL": base_url,
                "CONNECTED_DEVICE_SHARED_SECRET": shared_secret,
            }
            mat = detect_capability_matrix(env=env_online, host_os="linux")
            win_state = mat["windows_connected_device"]
            record(
                "live_paired_runner_reports_device_online",
                win_state["paired"] is True
                and win_state["device_online"] is True
                and len(win_state["authorized_windows_roots"]) == 1,
                win_state,
            )

            # 3b. Validated file list & read inside AUTHORIZED_WINDOWS_ROOTS (and .env hidden from list!)
            list_res = invoke_connected_windows_runner(
                base_url=base_url,
                shared_secret=shared_secret,
                method="POST",
                path="/v1/fs/list",
                payload={"path": str(allowed_proj)},
            )
            listed_names = [f["name"] for f in list_res.get("files", [])]
            record("fs_list_returns_safe_files_and_hides_dotenv", list_res["ok"] and "app.py" in listed_names and ".env" not in listed_names)

            read_res = invoke_connected_windows_runner(
                base_url=base_url,
                shared_secret=shared_secret,
                method="POST",
                path="/v1/fs/read",
                payload={"path": str(allowed_proj / "app.py")},
            )
            record("fs_read_inside_allowed_root_succeeds", read_res["ok"] and "hello allinagent" in read_res["content"])

            # 3c. Secret .env read blocked (403)
            env_read = invoke_connected_windows_runner(
                base_url=base_url,
                shared_secret=shared_secret,
                method="POST",
                path="/v1/fs/read",
                payload={"path": str(allowed_proj / ".env")},
            )
            record("fs_read_dotenv_blocked_403", not env_read["ok"] and env_read.get("http_status") == 403)

            # 3d. Path outside AUTHORIZED_WINDOWS_ROOTS blocked (403)
            outside_read = invoke_connected_windows_runner(
                base_url=base_url,
                shared_secret=shared_secret,
                method="POST",
                path="/v1/fs/read",
                payload={"path": str(outside_proj / "private.txt")},
            )
            record("fs_read_outside_root_blocked_403", not outside_read["ok"] and outside_read.get("http_status") == 403)

            # 3e. Arbitrary RCE endpoint blocked (403)
            rce_attempt = invoke_connected_windows_runner(
                base_url=base_url,
                shared_secret=shared_secret,
                method="POST",
                path="/v1/exec",
                payload={"cmd": "whoami"},
            )
            record("rce_endpoint_blocked_403", not rce_attempt["ok"] and rce_attempt.get("code") == "RCE_ENDPOINT_FORBIDDEN")

            # 3f. Wrong HMAC secret rejected (401)
            bad_hmac = invoke_connected_windows_runner(
                base_url=base_url,
                shared_secret="f" * 64,
                method="GET",
                path="/v1/capabilities",
            )
            record("invalid_hmac_rejected_401", not bad_hmac["ok"] and bad_hmac.get("http_status") == 401)

            # 3g. Replay attack rejected (409) & stale timestamp rejected (401)
            guard = HmacReplayGuard(shared_secret, max_skew_seconds=60.0)
            now_ts = f"{time.time():.3f}"
            fixed_nonce = secrets.token_hex(16)
            hdrs = sign_device_request(
                shared_secret,
                method="GET",
                path_with_query="/v1/capabilities",
                body=b"",
                timestamp=now_ts,
                nonce=fixed_nonce,
            )
            first_ok = guard.verify(
                method="GET",
                path_with_query="/v1/capabilities",
                body=b"",
                timestamp_header=hdrs["X-AllInAgent-Timestamp"],
                nonce_header=hdrs["X-AllInAgent-Nonce"],
                signature_header=hdrs["X-AllInAgent-Signature"],
            )
            replay_res = guard.verify(
                method="GET",
                path_with_query="/v1/capabilities",
                body=b"",
                timestamp_header=hdrs["X-AllInAgent-Timestamp"],
                nonce_header=hdrs["X-AllInAgent-Nonce"],
                signature_header=hdrs["X-AllInAgent-Signature"],
            )
            record("replay_nonce_rejected_409", first_ok["ok"] and not replay_res["ok"] and replay_res["status"] == 409)

            old_ts = f"{time.time() - 3600:.3f}"
            stale_nonce = secrets.token_hex(16)
            stale_hdrs = sign_device_request(
                shared_secret,
                method="GET",
                path_with_query="/v1/capabilities",
                body=b"",
                timestamp=old_ts,
                nonce=stale_nonce,
            )
            stale_res = guard.verify(
                method="GET",
                path_with_query="/v1/capabilities",
                body=b"",
                timestamp_header=stale_hdrs["X-AllInAgent-Timestamp"],
                nonce_header=stale_hdrs["X-AllInAgent-Nonce"],
                signature_header=stale_hdrs["X-AllInAgent-Signature"],
            )
            record("stale_timestamp_rejected_401", not stale_res["ok"] and stale_res["status"] == 401)

            # 3h. resolve_capability_request routes authorized Windows root when online
            fake_win_mat = {
                **mat,
                "windows_connected_device": {
                    **win_state,
                    "authorized_windows_roots": [r"D:\AllowedWorkspace"],
                },
            }
            allowed_win_req = resolve_capability_request(
                "source_analysis",
                target_path=r"D:\AllowedWorkspace\ServiceA",
                matrix=fake_win_mat,
            )
            forbidden_win_req = resolve_capability_request(
                "source_analysis",
                target_path=r"C:\Windows\System32",
                matrix=fake_win_mat,
            )
            record(
                "online_windows_routing_enforces_authorized_roots",
                allowed_win_req["allowed"] is True and forbidden_win_req["allowed"] is False,
            )
        finally:
            httpd.shutdown()
            httpd.server_close()

    return {"ok": True, "total_checks": len(checks), "checks": checks}


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="windows_runner_agent.py",
        description="Optional paired Windows workspace runner bound strictly to loopback/private tunnel.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--serve", action="store_true", help="Start HMAC-authenticated Windows runner HTTP agent.")
    mode.add_argument("--generate-pairing-config", action="store_true", help="Print fresh pairing secret & SSH tunnel instructions.")
    mode.add_argument("--self-check", action="store_true", help="Run built-in security & integration self-checks.")

    parser.add_argument("--bind", default=DEFAULT_BIND_HOST, help="Bind IP (default 127.0.0.1; never 0.0.0.0).")
    parser.add_argument("--port", type=int, default=DEFAULT_BIND_PORT, help=f"Bind TCP port (default {DEFAULT_BIND_PORT}).")
    parser.add_argument(
        "--allow-private-tunnel-ip",
        action="store_true",
        help="Allow binding directly to a private WireGuard/Tailscale/RFC1918 interface IP.",
    )
    parser.add_argument(
        "--root",
        action="append",
        dest="roots",
        default=[],
        help="Explicit directory to add to AUTHORIZED_WINDOWS_ROOTS (repeatable).",
    )
    parser.add_argument(
        "--enable-interactive-desktop",
        action="store_true",
        help="Opt-in to advertise interactive desktop availability when running in an active user session.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.self_check:
        res = run_self_checks()
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"[PASS] windows_runner_agent self-checks passed ({res['total_checks']}/{res['total_checks']}).")
        return 0

    if args.generate_pairing_config:
        tpl = generate_pairing_template()
        print(json.dumps(tpl, indent=2))
        return 0

    if args.serve:
        secret = (os.environ.get("CONNECTED_DEVICE_SHARED_SECRET") or "").strip()
        roots = parse_roots_from_env_or_args(args.roots)
        try:
            server = create_runner_http_server(
                bind_host=args.bind,
                bind_port=args.port,
                shared_secret=secret,
                authorized_roots=roots,
                allow_private_tunnel_ip=bool(args.allow_private_tunnel_ip),
                enable_interactive_desktop=bool(args.enable_interactive_desktop),
            )
        except (ValueError, PermissionError) as exc:
            print(f"[SECURITY_REFUSED] {exc}", file=sys.stderr)
            return 2

        host_bound, port_bound = server.server_address[:2]
        print(
            f"[OK] allinagent-windows-runner listening on http://{host_bound}:{port_bound} "
            f"(HMAC-SHA256 active, roots={len(roots)}, admin=False)"
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
