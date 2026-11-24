#!/usr/bin/env python3
"""Decrypt, verify, and restore an ALLINAGENT private state bundle on Ubuntu 24.04 VPS.

Safety, Security & Continuity Guarantees:
  1. Authenticates & decrypts the `.aiaenc` bundle (`AES-256-GCM` + `PBKDF2-HMAC-SHA256` >= 600k
     iterations + header AAD) strictly inside OS temp storage (`0700`), rejecting tampered
     headers/ciphertexts, tar-slip path traversal, and any path inside a Git repository worktree
     via `assert_outside_git_repo(path)`.
  2. Verifies every extracted file's SHA-256 digest and byte size against `manifest.json` and runs
     `PRAGMA integrity_check` on all staged SQLite databases.
  3. Enforces quiescent target service checks via `compose.yaml` and acquires exclusive
     `<state-root>/maintenance/maintenance.lock` atomically (`O_CREAT | O_EXCL`, `0600`) prior to
     mutating state.
  4. Enforces the Single-Poller Telegram Cutover Guard (`MIG-02`): supports creating and clearing
     `<target-hermes-root>/.telegram_cutover_lock` (honored by `components/hermes/entrypoint.sh`)
     so the target Hermes Gateway never polls Telegram concurrently with an active source poller.
  5. Restores WAL-clean SQLite databases (`state.db` root + 11 `pc*` profiles, `findings.db`,
     `workflow-ledger.db`), Paperclip `master.key`, `organization-roster.json`, `office-data`
     stores, and Paperclip PostgreSQL dump under `/var/lib/allinagent/{hermes,reports,secrets,...}`
     with `0700` directory / `0600` file permissions.
  6. Rewrites legacy host paths inside Paperclip `agents.adapter_config` to
     `/var/lib/allinagent/hermes/profiles/pc*`, `/var/lib/allinagent/reports`, and `/workspaces`
     while preserving the Company UUID and all 11 Agent UUIDs 100% intact.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import io
import json
import os
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BUNDLE_MAGIC = b"AIASTATE"
BUNDLE_VERSION = 1
MIN_PBKDF2_ITERATIONS = 600_000
KEY_BYTES = 32

CANONICAL_11_PROFILES: dict[str, str] = {
    "ceo_agent": "pcceoagent",
    "cto_agent": "pcctoagent",
    "backend_developer": "pcbackenddeveloper",
    "frontend_developer": "pcfrontenddeveloper",
    "devops_engineer": "pcdevopsengineer",
    "qa_engineer": "pcqaengineer",
    "security_lead": "pcsecuritylead",
    "security_reviewer": "pcsecurityreviewer",
    "findings_analyst": "pcfindingsanalyst",
    "remediation_reviewer": "pcremediationreviewer",
    "compliance_reporter": "pccompliancereporter",
}

AGENT_NAME_TO_SLUG: dict[str, str] = {
    "CEO Agent": "ceo_agent",
    "CTO Agent": "cto_agent",
    "Backend Developer": "backend_developer",
    "Frontend Developer": "frontend_developer",
    "DevOps Engineer": "devops_engineer",
    "QA Engineer": "qa_engineer",
    "Security Lead": "security_lead",
    "Security Reviewer": "security_reviewer",
    "Findings Analyst": "findings_analyst",
    "Remediation Reviewer": "remediation_reviewer",
    "Report & Compliance Agent": "compliance_reporter",
}

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Generic host-path matchers (zero hardcoded personal usernames, drive roots, or folder names)
WIN_HERMES_PROFILE_RE = re.compile(
    r"(?i)^(?:\\\\\?\\)?[A-Za-z]:[\\/]+(?:[^\\/]+[\\/]+)*hermes[\\/]+profiles[\\/]+(pc[a-z0-9_-]+)(?:[\\/]+(.*))?$"
)
POSIX_HERMES_PROFILE_RE = re.compile(
    r"^(?:/home/[^/]+|/Users/[^/]+|~|/data)/(?:\.?hermes)/profiles/(pc[a-z0-9_-]+)(?:/(.*))?$"
)
PLATFORM_HERMES_PROFILE_RE = re.compile(
    r"(?i)^.*?[\\/]+profiles[\\/]+(pc[a-z0-9_-]+)(?:[\\/]+(.*))?$"
)
WIN_HERMES_ROOT_RE = re.compile(
    r"(?i)^(?:\\\\\?\\)?[A-Za-z]:[\\/]+(?:[^\\/]+[\\/]+)*hermes(?:[\\/]+(.*))?$"
)
LEGACY_WORKSPACES_RE = re.compile(
    r"(?i)^(?:(?:\\\\\?\\)?[A-Za-z]:[\\/]+[^\\/]+[\\/]+|\$\{[A-Z0-9_]+_ROOT\}[\\/]+|/opt/[a-z0-9_-]+/)workspaces(?:[\\/]+(.*))?$"
)
LEGACY_REPORTS_RE = re.compile(
    r"(?i)^(?:(?:\\\\\?\\)?[A-Za-z]:[\\/]+[^\\/]+[\\/]+|\$\{[A-Z0-9_]+_ROOT\}[\\/]+|/opt/[a-z0-9_-]+/)reports(?:[\\/]+(.*))?$"
)
LEGACY_WORKERS_INSTRUCTIONS_RE = re.compile(
    r"(?i)^(?:(?:\\\\\?\\)?[A-Za-z]:[\\/]+[^\\/]+[\\/]+|\$\{[A-Z0-9_]+_ROOT\}[\\/]+)workers[\\/]+([a-z0-9_-]+)[\\/]+AGENTS\.md$"
)
WINDOWS_DRIVE_PREFIX_RE = re.compile(r"^(?:\\\\\?\\)?[A-Za-z]:[\\/]")


@dataclass(frozen=True)
class TargetPathConfig:
    target_root: str = "/opt/allinagent"
    state_root: str = "/var/lib/allinagent"
    hermes_root: str = "/var/lib/allinagent/hermes"
    workspaces_root: str = "/workspaces"
    reports_root: str = "/var/lib/allinagent/reports"
    secrets_root: str = "/var/lib/allinagent/secrets"
    hermes_command: str = "hermes"
    paperclip_api_url: str = "http://paperclip:3100/api"
    preserve_paperclip_api_url: bool = False


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def enforce_permissions(path: Path, *, is_dir: bool, uid_gid: tuple[int, int] | None = None) -> None:
    mode = 0o700 if is_dir else 0o600
    try:
        os.chmod(path, mode)
    except OSError:
        pass
    if uid_gid is not None and hasattr(os, "chown"):
        try:
            os.chown(path, uid_gid[0], uid_gid[1])  # type: ignore[attr-defined]
        except OSError:
            pass


def parse_chown_spec(spec: str | None) -> tuple[int, int] | None:
    if not spec:
        return None
    parts = spec.strip().split(":", 1)
    if len(parts) != 2:
        raise ValueError("--chown must be formatted as '<uid>:<gid>' (integer IDs).")
    return (int(parts[0]), int(parts[1]))


def resolve_system_temp_dir() -> Path:
    if os.name == "nt":
        raw = os.environ.get("TEMP") or os.environ.get("TMP") or tempfile.gettempdir()
    else:
        raw = os.environ.get("TMPDIR") or "/tmp"
    resolved = Path(raw).expanduser().resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def assert_outside_git_repo(
    path: Path | str,
    *,
    extra_forbidden_roots: list[Path] | None = None,
) -> Path:
    """Ensure encrypted state bundles, staging dirs, and unpacked files NEVER touch a Git worktree."""
    resolved = Path(path).expanduser().resolve()
    repo_root = Path(__file__).resolve().parents[2].resolve()
    sys_temp = resolve_system_temp_dir()
    user_home = Path.home().resolve()

    forbidden = [repo_root, *(extra_forbidden_roots or [])]
    for root in forbidden:
        r_norm = root.resolve()
        if resolved == r_norm or r_norm in resolved.parents:
            raise PermissionError(
                f"Security policy violation: path '{resolved}' is inside repository tree '{r_norm}'. "
                "Encrypted state bundles and unpacked runtime state MUST reside outside any Git repository."
            )

    in_sys_temp = resolved == sys_temp or sys_temp in resolved.parents
    for ancestor in (resolved, *resolved.parents):
        # Stop walking above the OS temp root when a user home directory tracks dotfiles via .git
        if in_sys_temp and ancestor in sys_temp.parents:
            break
        if ancestor == user_home:
            continue
        if (ancestor / ".git").exists():
            raise PermissionError(
                f"Security policy violation: path '{resolved}' is inside Git working tree '{ancestor}'."
            )
    return resolved


def resolve_compose_file(target_root: Path, explicit_compose: str | None = None) -> Path:
    if explicit_compose and explicit_compose.strip():
        return Path(explicit_compose).expanduser().resolve()
    for candidate_name in ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"):
        cand = target_root / candidate_name
        if cand.is_file():
            return cand
    return target_root / "compose.yaml"


def _dynamic_windows_legacy_prefixes() -> tuple[str | None, str | None]:
    """Build optional Windows legacy root & Hermes appdata prefixes dynamically from environment."""
    legacy_root = (os.environ.get("ALLINAGENT_LEGACY_ROOT") or "").strip().rstrip("\\/") or None
    local_appdata = (os.environ.get("LOCALAPPDATA") or "").strip().rstrip("\\/")
    legacy_hermes = os.path.join(local_appdata, "hermes") if local_appdata else None
    return legacy_root, legacy_hermes


def resolve_passphrase(args: argparse.Namespace) -> str:
    if args.passphrase_file:
        return Path(args.passphrase_file).expanduser().resolve().read_text(encoding="utf-8").splitlines()[0].strip()
    if args.passphrase_env and os.environ.get(args.passphrase_env):
        return os.environ[args.passphrase_env].strip()
    return getpass.getpass("Enter migration bundle decryption passphrase: ").strip()


def decrypt_and_verify_bundle(bundle_path: Path, passphrase: str) -> tuple[dict[str, Any], bytes]:
    assert_outside_git_repo(bundle_path)
    if not bundle_path.is_file():
        raise FileNotFoundError(f"Encrypted migration bundle not found: {bundle_path}")

    raw = bundle_path.read_bytes()
    min_prefix = len(BUNDLE_MAGIC) + 5
    if len(raw) < min_prefix + 32:
        raise ValueError("Bundle is truncated or not a valid ALLINAGENT encrypted archive.")
    if raw[: len(BUNDLE_MAGIC)] != BUNDLE_MAGIC:
        raise ValueError("Bundle magic header mismatch (expected 'AIASTATE').")

    version, header_len = struct.unpack(">BI", raw[len(BUNDLE_MAGIC) : min_prefix])
    if version != BUNDLE_VERSION:
        raise ValueError(f"Unsupported bundle version: {version}")
    header_end = min_prefix + header_len
    if header_end >= len(raw):
        raise ValueError("Corrupted bundle header length.")

    aad = raw[:header_end]
    ciphertext = raw[header_end:]
    header_obj = json.loads(raw[min_prefix:header_end].decode("utf-8"))

    iterations = int(header_obj.get("kdf_iterations", 0))
    if iterations < MIN_PBKDF2_ITERATIONS:
        raise ValueError(
            f"Refusing weak KDF iteration count ({iterations} < {MIN_PBKDF2_ITERATIONS})."
        )
    if header_obj.get("cipher") != "AES-256-GCM" or header_obj.get("kdf") != "PBKDF2-HMAC-SHA256":
        raise ValueError("Unsupported cipher or KDF algorithm in bundle header.")

    salt = base64.b64decode(header_obj["salt_b64"])
    nonce = base64.b64decode(header_obj["nonce_b64"])

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    aesgcm = AESGCM(key)
    try:
        plaintext_tar_gz = aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise PermissionError(
            "AES-256-GCM authentication failed: wrong passphrase or tampered bundle/header."
        ) from exc

    actual_sha = hashlib.sha256(plaintext_tar_gz).hexdigest()
    if actual_sha != header_obj.get("payload_sha256"):
        raise ValueError("Decrypted payload SHA-256 digest mismatch.")
    return header_obj, plaintext_tar_gz


def safe_extract_tar_gz(tar_gz_bytes: bytes, dest_dir: Path) -> None:
    dest_resolved = assert_outside_git_repo(dest_dir)
    with tarfile.open(fileobj=io.BytesIO(tar_gz_bytes), mode="r:gz") as tf:
        for member in tf.getmembers():
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise PermissionError(f"Refusing unsafe non-regular tar entry: {member.name}")
            if member.name.startswith("/") or member.name.startswith("\\") or ".." in Path(member.name).parts:
                raise PermissionError(f"Refusing tar path traversal entry: {member.name}")
            target_path = (dest_resolved / member.name).resolve()
            if target_path != dest_resolved and dest_resolved not in target_path.parents:
                raise PermissionError(f"Tar entry escapes staging root: {member.name}")
            if member.isdir():
                target_path.mkdir(parents=True, exist_ok=True)
                enforce_permissions(target_path, is_dir=True)
            elif member.isfile():
                target_path.parent.mkdir(parents=True, exist_ok=True)
                enforce_permissions(target_path.parent, is_dir=True)
                extracted = tf.extractfile(member)
                if extracted is None:
                    raise RuntimeError(f"Failed to read tar member: {member.name}")
                target_path.write_bytes(extracted.read())
                enforce_permissions(target_path, is_dir=False)


def verify_staged_payload(payload_dir: Path) -> dict[str, Any]:
    manifest_path = payload_dir / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError("Extracted bundle is missing manifest.json.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    for art in manifest.get("artifacts", []):
        rel = str(art["archive_path"])
        staged_file = (payload_dir / rel).resolve()
        if payload_dir.resolve() not in staged_file.parents:
            raise PermissionError(f"Manifest artifact path escapes staging root: {rel}")
        if not staged_file.is_file():
            raise FileNotFoundError(f"Missing expected artifact in bundle: {rel}")
        actual_size = staged_file.stat().st_size
        if actual_size != int(art["size_bytes"]):
            raise ValueError(
                f"Size mismatch for '{rel}': expected {art['size_bytes']}, got {actual_size}"
            )
        actual_sha = sha256_file(staged_file)
        if actual_sha != art["sha256"]:
            raise ValueError(
                f"SHA-256 mismatch for '{rel}': expected {art['sha256']}, got {actual_sha}"
            )
        if art.get("category") == "sqlite":
            conn = sqlite3.connect(str(staged_file), timeout=15.0)
            try:
                ic = conn.execute("PRAGMA integrity_check;").fetchone()
                if not ic or str(ic[0]).lower() != "ok":
                    raise RuntimeError(f"Staged SQLite integrity_check failed on '{rel}': {ic}")
            finally:
                conn.close()

    # Validate Company UUID + all 11 Agent UUIDs in manifest
    continuity = manifest.get("identity_continuity") or {}
    cid = str(continuity.get("company_id") or "")
    if not UUID_RE.match(cid):
        raise ValueError(f"Invalid company_id in manifest: '{cid}'")
    uuids_by_slug = continuity.get("agent_uuids_by_slug") or {}
    for slug in CANONICAL_11_PROFILES:
        uid = str(uuids_by_slug.get(slug) or "")
        if not UUID_RE.match(uid):
            raise ValueError(f"Manifest missing valid Agent UUID for role '{slug}'.")
    if len(set(uuids_by_slug.values())) != 11:
        raise ValueError("Manifest contains duplicate Agent UUIDs.")

    return manifest


def _is_tcp_port_open(host: str, port: int, timeout_s: float = 0.5) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout_s)
        return sock.connect_ex((host, port)) == 0


def verify_quiescent_services(
    state_root: Path,
    *,
    compose_file: Path,
    skip_check: bool = False,
) -> None:
    maint_dir = state_root / "maintenance"
    lock_file = maint_dir / "maintenance.lock"
    if lock_file.exists():
        raise RuntimeError(
            f"Active maintenance.lock detected at '{lock_file}'. "
            "Wait for active maintenance to complete or verify services are stopped before restoring."
        )

    state_file = maint_dir / "state.json"
    if state_file.is_file():
        try:
            st = json.loads(state_file.read_text(encoding="utf-8-sig"))
            if st.get("state") in {"DRAINING", "PRECHECK", "UPDATING", "POST_UPDATE_TEST"}:
                raise RuntimeError(
                    f"Maintenance coordinator is currently in active state '{st.get('state')}'."
                )
        except json.JSONDecodeError:
            pass

    if skip_check:
        return

    active_ports = [
        f"127.0.0.1:{port}"
        for port in (3100, 3200, 3210, 8650)
        if _is_tcp_port_open("127.0.0.1", port)
    ]
    if active_ports:
        raise RuntimeError(
            f"Target application services are still listening on {active_ports}. "
            "Stop application containers/units (keep only postgres running if needed) before state restore."
        )

    if compose_file.is_file() and shutil.which("docker"):
        proc = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "ps", "--services", "--status", "running"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if proc.returncode == 0:
            running_svcs = [
                s.strip()
                for s in proc.stdout.splitlines()
                if s.strip() and s.strip() not in {"postgres", "db"}
            ]
            if running_svcs:
                raise RuntimeError(
                    f"Target Docker Compose services in '{compose_file.name}' must be stopped before restore: {running_svcs}"
                )


class MaintenanceLockGuard:
    """Atomic exclusive `maintenance.lock` manager (`O_CREAT | O_EXCL`, mode `0600`)."""

    def __init__(self, state_root: Path) -> None:
        self.maint_dir = assert_outside_git_repo(state_root / "maintenance")
        self.lock_path = self.maint_dir / "maintenance.lock"
        self._acquired = False

    def __enter__(self) -> Path:
        self.maint_dir.mkdir(parents=True, exist_ok=True)
        enforce_permissions(self.maint_dir, is_dir=True)
        try:
            fd = os.open(str(self.lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise RuntimeError(
                f"Cannot acquire '{self.lock_path}': another maintenance or migration process holds the lock."
            ) from exc
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "holder": "import_private_state",
                    "pid": os.getpid(),
                    "phase": "MIGRATION_RESTORE",
                    "acquired_at_utc": utc_now_iso(),
                },
                fh,
                indent=2,
            )
        enforce_permissions(self.lock_path, is_dir=False)
        self._acquired = True
        return self.lock_path

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._acquired:
            self.lock_path.unlink(missing_ok=True)


def set_telegram_cutover_lock(
    *,
    target_hermes_root: Path,
    state_root: Path,
    locked: bool,
    source_poller_active: bool = False,
    uid_gid: tuple[int, int] | None = None,
    reason: str = "",
) -> dict[str, Any]:
    """Create or clear `<target-hermes-root>/.telegram_cutover_lock` for safe single-poller cutover."""
    assert_outside_git_repo(target_hermes_root)
    assert_outside_git_repo(state_root)

    if not locked and source_poller_active:
        raise RuntimeError(
            "Single-Poller Telegram Cutover Guard: source host Telegram Gateway poller is still active! "
            "Stop the source host's Hermes gateway poller service/task before clearing .telegram_cutover_lock."
        )

    target_hermes_root.mkdir(parents=True, exist_ok=True)
    enforce_permissions(target_hermes_root, is_dir=True, uid_gid=uid_gid)
    cutover_lock_file = target_hermes_root / ".telegram_cutover_lock"
    cutover_audit_file = state_root / "maintenance" / "telegram-cutover.json"
    cutover_audit_file.parent.mkdir(parents=True, exist_ok=True)
    enforce_permissions(cutover_audit_file.parent, is_dir=True, uid_gid=uid_gid)

    if locked:
        lock_payload = {
            "cutover_approved": False,
            "gateway_startup_blocked": True,
            "created_at_utc": utc_now_iso(),
            "reason": reason
            or (
                "Target state in single-poller standby mode. Confirm the source host Telegram poller "
                "is stopped, then clear .telegram_cutover_lock via --clear-telegram-cutover or --cutover-telegram."
            ),
        }
        cutover_lock_file.write_text(json.dumps(lock_payload, indent=2) + "\n", encoding="utf-8")
        enforce_permissions(cutover_lock_file, is_dir=False, uid_gid=uid_gid)
        return {
            "cutover_approved": False,
            "gateway_startup_allowed": False,
            "lock_file": str(cutover_lock_file),
            "lock_present": True,
        }

    if cutover_lock_file.exists():
        cutover_lock_file.unlink(missing_ok=True)

    audit_payload = {
        "cutover_approved": True,
        "gateway_startup_allowed": True,
        "cutover_at_utc": utc_now_iso(),
    }
    cutover_audit_file.write_text(json.dumps(audit_payload, indent=2) + "\n", encoding="utf-8")
    enforce_permissions(cutover_audit_file, is_dir=False, uid_gid=uid_gid)
    return {
        "cutover_approved": True,
        "gateway_startup_allowed": True,
        "audit_file": str(cutover_audit_file),
        "lock_present": False,
    }


def enforce_single_poller_telegram_cutover(
    *,
    manifest: dict[str, Any],
    target_root: Path,
    state_root: Path,
    target_hermes_root: Path,
    cutover_telegram: bool,
    start_gateway: bool,
    source_poller_active: bool,
    uid_gid: tuple[int, int] | None,
) -> dict[str, Any]:
    """Prevent simultaneous Telegram `getUpdates` polling between source host and target VPS."""
    has_root_gateway_state = any(
        a.get("archive_path") == "hermes/state.db" for a in manifest.get("artifacts", [])
    )
    # Metadata-only stat check (never reads .env contents)
    has_target_env = (
        (target_root / ".env").is_file() and (target_root / ".env").stat().st_size > 0
    ) or (
        (target_hermes_root / ".env").is_file() and (target_hermes_root / ".env").stat().st_size > 0
    )
    live_token_scope = has_root_gateway_state or has_target_env

    if source_poller_active:
        raise RuntimeError(
            "Single-Poller Telegram Cutover Guard: source host Telegram Gateway poller is still active! "
            "Stop the source host's Hermes gateway poller service/task before cutting over."
        )

    if start_gateway and live_token_scope and not cutover_telegram:
        raise RuntimeError(
            "Single-Poller Telegram Cutover Guard: refusing to start Hermes Gateway with live Telegram "
            "state/token until source poller is confirmed stopped and '--cutover-telegram' is passed."
        )

    should_lock = bool(live_token_scope and not cutover_telegram)
    return set_telegram_cutover_lock(
        target_hermes_root=target_hermes_root,
        state_root=state_root,
        locked=should_lock,
        source_poller_active=source_poller_active,
        uid_gid=uid_gid,
    )


def rewrite_single_path_string(
    raw_value: str,
    *,
    fallback_profile_id: str | None,
    target_cfg: TargetPathConfig,
) -> str:
    val = raw_value.strip()
    if not val:
        return raw_value

    legacy_root, legacy_hermes = _dynamic_windows_legacy_prefixes()
    val_norm = val.replace("\\", "/")

    if legacy_hermes:
        lh_norm = legacy_hermes.replace("\\", "/").rstrip("/")
        if val_norm.lower() == lh_norm.lower() or val_norm.lower().startswith(lh_norm.lower() + "/"):
            suffix = val_norm[len(lh_norm) :].lstrip("/")
            base = target_cfg.hermes_root.rstrip("/")
            return f"{base}/{suffix}" if suffix else base

    if legacy_root:
        lr_norm = legacy_root.replace("\\", "/").rstrip("/")
        if val_norm.lower() == lr_norm.lower() or val_norm.lower().startswith(lr_norm.lower() + "/"):
            suffix = val_norm[len(lr_norm) :].lstrip("/")
            if suffix.lower() == "workspaces" or suffix.lower().startswith("workspaces/"):
                rest = suffix[len("workspaces") :].lstrip("/")
                base = target_cfg.workspaces_root.rstrip("/")
                return f"{base}/{rest}" if rest else base
            if suffix.lower() == "reports" or suffix.lower().startswith("reports/"):
                rest = suffix[len("reports") :].lstrip("/")
                base = target_cfg.reports_root.rstrip("/")
                return f"{base}/{rest}" if rest else base
            base = target_cfg.target_root.rstrip("/")
            return f"{base}/{suffix}" if suffix else base

    for rx in (WIN_HERMES_PROFILE_RE, POSIX_HERMES_PROFILE_RE):
        m = rx.match(val)
        if m:
            prof = m.group(1).lower()
            rest = (m.group(2) or "").replace("\\", "/").strip("/")
            base = f"{target_cfg.hermes_root.rstrip('/')}/profiles/{prof}"
            return f"{base}/{rest}" if rest else base

    m_workers = LEGACY_WORKERS_INSTRUCTIONS_RE.match(val)
    if m_workers:
        slug = m_workers.group(1).lower()
        prof = CANONICAL_11_PROFILES.get(slug) or fallback_profile_id or f"pc{re.sub(r'[^a-z0-9]', '', slug)}"
        return f"{target_cfg.hermes_root.rstrip('/')}/profiles/{prof}/AGENTS.md"

    m_ws = LEGACY_WORKSPACES_RE.match(val)
    if m_ws:
        rest = (m_ws.group(1) or "").replace("\\", "/").strip("/")
        base = target_cfg.workspaces_root.rstrip("/")
        return f"{base}/{rest}" if rest else base

    m_rep = LEGACY_REPORTS_RE.match(val)
    if m_rep:
        rest = (m_rep.group(1) or "").replace("\\", "/").strip("/")
        base = target_cfg.reports_root.rstrip("/")
        return f"{base}/{rest}" if rest else base

    m_hroot = WIN_HERMES_ROOT_RE.match(val)
    if m_hroot:
        rest = (m_hroot.group(1) or "").replace("\\", "/").strip("/")
        base = target_cfg.hermes_root.rstrip("/")
        return f"{base}/{rest}" if rest else base

    m_any_prof = PLATFORM_HERMES_PROFILE_RE.match(val)
    if m_any_prof and WINDOWS_DRIVE_PREFIX_RE.match(val):
        prof = m_any_prof.group(1).lower()
        rest = (m_any_prof.group(2) or "").replace("\\", "/").strip("/")
        base = f"{target_cfg.hermes_root.rstrip('/')}/profiles/{prof}"
        return f"{base}/{rest}" if rest else base

    if WINDOWS_DRIVE_PREFIX_RE.match(val):
        lower = val.lower()
        if lower.endswith(("hermes.exe", "hermes.cmd", "\\hermes", "/hermes")):
            return target_cfg.hermes_command
        return target_cfg.workspaces_root.rstrip("/")

    return raw_value


def rewrite_adapter_config_paths(
    adapter_config: dict[str, Any],
    *,
    role_slug: str | None,
    profile_id: str | None,
    target_cfg: TargetPathConfig,
) -> dict[str, Any]:
    resolved_prof = profile_id or (CANONICAL_11_PROFILES.get(role_slug or "") if role_slug else None)

    def _walk(node: Any, key_name: str = "") -> Any:
        if isinstance(node, dict):
            return {k: _walk(v, k) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(item, key_name) for item in node]
        if isinstance(node, str):
            if key_name == "hermesCommand":
                if WINDOWS_DRIVE_PREFIX_RE.match(node) or node.lower().endswith((".exe", ".cmd", ".bat")):
                    return target_cfg.hermes_command
                return node
            if key_name == "paperclipApiUrl" and not target_cfg.preserve_paperclip_api_url:
                return target_cfg.paperclip_api_url
            if key_name == "HERMES_HOME":
                rewritten = rewrite_single_path_string(
                    node, fallback_profile_id=resolved_prof, target_cfg=target_cfg
                )
                if resolved_prof and not rewritten.startswith(f"{target_cfg.hermes_root.rstrip('/')}/profiles/"):
                    return f"{target_cfg.hermes_root.rstrip('/')}/profiles/{resolved_prof}"
                return rewritten
            if key_name == "cwd":
                return rewrite_single_path_string(
                    node, fallback_profile_id=resolved_prof, target_cfg=target_cfg
                )
            if key_name == "instructionsFilePath":
                rewritten = rewrite_single_path_string(
                    node, fallback_profile_id=resolved_prof, target_cfg=target_cfg
                )
                if resolved_prof and WINDOWS_DRIVE_PREFIX_RE.match(rewritten):
                    return f"{target_cfg.hermes_root.rstrip('/')}/profiles/{resolved_prof}/AGENTS.md"
                return rewritten
            return rewrite_single_path_string(
                node, fallback_profile_id=resolved_prof, target_cfg=target_cfg
            )
        return node

    updated = _walk(dict(adapter_config))
    if resolved_prof:
        env_map = dict(updated.get("env") or {})
        env_map["HERMES_HOME"] = f"{target_cfg.hermes_root.rstrip('/')}/profiles/{resolved_prof}"
        updated["env"] = env_map
    return updated


def scrub_legacy_paths_in_markdown(text: str, target_cfg: TargetPathConfig) -> str:
    out = text
    legacy_root, legacy_hermes = _dynamic_windows_legacy_prefixes()
    if legacy_hermes:
        escaped_lh = re.escape(legacy_hermes).replace(r"\\", r"[\\/]+")
        out = re.sub(
            rf"(?i){escaped_lh}[\\/]+profiles[\\/]+(pc[a-z0-9_-]+)",
            lambda m: f"{target_cfg.hermes_root.rstrip('/')}/profiles/{m.group(1).lower()}",
            out,
        )
        out = re.sub(rf"(?i){escaped_lh}", lambda _m: target_cfg.hermes_root.rstrip("/"), out)

    if legacy_root:
        escaped_lr = re.escape(legacy_root).replace(r"\\", r"[\\/]+")
        out = re.sub(
            rf"(?i){escaped_lr}[\\/]+workspaces\b",
            lambda _m: target_cfg.workspaces_root.rstrip("/"),
            out,
        )
        out = re.sub(
            rf"(?i){escaped_lr}[\\/]+reports\b",
            lambda _m: target_cfg.reports_root.rstrip("/"),
            out,
        )
        out = re.sub(rf"(?i){escaped_lr}", lambda _m: target_cfg.target_root.rstrip("/"), out)

    out = re.sub(
        r"(?i)(?:\\\\\?\\)?[A-Za-z]:[\\/]+(?:[^\\/\s`'\"<>|]+[\\/]+)*hermes[\\/]+profiles[\\/]+(pc[a-z0-9_-]+)",
        lambda m: f"{target_cfg.hermes_root.rstrip('/')}/profiles/{m.group(1).lower()}",
        out,
    )
    out = re.sub(
        r"(?i)(?:\\\\\?\\)?[A-Za-z]:[\\/]+(?:[^\\/\s`'\"<>|]+[\\/]+)*hermes\b",
        lambda _m: target_cfg.hermes_root.rstrip("/"),
        out,
    )
    out = re.sub(
        r"(?i)(?:\\\\\?\\)?[A-Za-z]:[\\/]+[^\\/\s`'\"<>|]+[\\/]+workspaces\b",
        lambda _m: target_cfg.workspaces_root.rstrip("/"),
        out,
    )
    out = re.sub(
        r"(?i)(?:\\\\\?\\)?[A-Za-z]:[\\/]+[^\\/\s`'\"<>|]+[\\/]+reports\b",
        lambda _m: target_cfg.reports_root.rstrip("/"),
        out,
    )
    return out


def restore_sqlite_clean(
    staged_db: Path,
    target_db: Path,
    *,
    uid_gid: tuple[int, int] | None,
) -> dict[str, Any]:
    assert_outside_git_repo(target_db)
    target_db.parent.mkdir(parents=True, exist_ok=True)
    enforce_permissions(target_db.parent, is_dir=True, uid_gid=uid_gid)

    # Remove stale WAL/SHM files BEFORE writing restored DB so stale frames never replay
    for suffix in ("-wal", "-shm", "-journal"):
        stale = Path(str(target_db) + suffix)
        if stale.exists():
            stale.unlink(missing_ok=True)

    tmp_dst = target_db.with_suffix(target_db.suffix + ".restore_tmp")
    if tmp_dst.exists():
        tmp_dst.unlink(missing_ok=True)

    src_conn = sqlite3.connect(str(staged_db), timeout=30.0)
    dst_conn = sqlite3.connect(str(tmp_dst), timeout=30.0)
    try:
        src_conn.backup(dst_conn, pages=250, sleep=0.01)
        dst_conn.execute("PRAGMA journal_mode=WAL;")
        dst_conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        ic = dst_conn.execute("PRAGMA integrity_check;").fetchone()
        if not ic or str(ic[0]).lower() != "ok":
            raise RuntimeError(f"Post-restore integrity_check failed for '{target_db}': {ic}")
    finally:
        src_conn.close()
        dst_conn.close()

    for suffix in ("-wal", "-shm", "-journal"):
        tmp_side = Path(str(tmp_dst) + suffix)
        if tmp_side.exists():
            tmp_side.unlink(missing_ok=True)

    enforce_permissions(tmp_dst, is_dir=False, uid_gid=uid_gid)
    os.replace(tmp_dst, target_db)
    enforce_permissions(target_db, is_dir=False, uid_gid=uid_gid)
    return {
        "target_path": str(target_db),
        "integrity_check": "ok",
        "size_bytes": target_db.stat().st_size,
    }


def _run_psql_command(
    sql: str,
    *,
    postgres_mode: str,
    database_url: str | None,
    compose_file: Path,
    postgres_service: str,
    postgres_user: str,
    postgres_db: str,
    tuples_only: bool = False,
) -> str:
    extra_flags = ["-v", "ON_ERROR_STOP=1"]
    if tuples_only:
        extra_flags.extend(["-t", "-A"])

    if postgres_mode == "psql" or (postgres_mode == "auto" and database_url and shutil.which("psql")):
        if not database_url:
            raise ValueError("--database-url is required when using direct psql mode.")
        cmd = ["psql", *extra_flags, database_url]
    elif postgres_mode in {"docker", "auto"} and compose_file.is_file() and shutil.which("docker"):
        cmd = [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "exec",
            "-T",
            postgres_service,
            "psql",
            *extra_flags,
            "-U",
            postgres_user,
            "-d",
            postgres_db,
        ]
    elif shutil.which("psql") and database_url:
        cmd = ["psql", *extra_flags, database_url]
    else:
        raise RuntimeError(
            f"Neither host 'psql' (with --database-url) nor 'docker compose -f {compose_file.name} exec postgres psql' is available. "
            "Use --postgres-mode=sql-stage only in offline test environments."
        )

    proc = subprocess.run(
        cmd,
        input=sql,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=240,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"psql execution failed (exit {proc.returncode}): {proc.stderr.strip()[:500]}")
    return proc.stdout


def assert_no_legacy_paths_in_adapter_config(agent_id: str, cfg: dict[str, Any]) -> None:
    serialized = json.dumps(cfg)
    if re.search(r"(?i)[A-Za-z]:\\\\|[A-Za-z]:/", serialized):
        raise AssertionError(
            f"Legacy Windows drive path remained in adapter_config for agent {agent_id}: {serialized}"
        )


def restore_and_rewrite_postgres(
    *,
    payload_dir: Path,
    manifest: dict[str, Any],
    compose_file: Path,
    paperclip_instance_root: Path,
    target_cfg: TargetPathConfig,
    postgres_mode: str,
    database_url: str | None,
    postgres_service: str,
    postgres_user: str,
    postgres_db: str,
    uid_gid: tuple[int, int] | None,
) -> dict[str, Any]:
    staged_sql_path = payload_dir / "paperclip" / "paperclip_dump.sql"
    sql_text = staged_sql_path.read_text(encoding="utf-8")
    continuity = manifest["identity_continuity"]
    expected_company_id = continuity["company_id"]
    expected_uuids: dict[str, str] = continuity["agent_uuids_by_slug"]
    uuid_to_slug = {uid.lower(): slug for slug, uid in expected_uuids.items()}

    if postgres_mode == "sql-stage":
        assert_outside_git_repo(paperclip_instance_root)
        rewritten_sql = scrub_legacy_paths_in_markdown(sql_text, target_cfg)
        restored_sql_dst = paperclip_instance_root / "data" / "backups" / "migrated_paperclip_dump.sql"
        restored_sql_dst.parent.mkdir(parents=True, exist_ok=True)
        enforce_permissions(restored_sql_dst.parent, is_dir=True, uid_gid=uid_gid)
        restored_sql_dst.write_text(rewritten_sql, encoding="utf-8")
        enforce_permissions(restored_sql_dst, is_dir=False, uid_gid=uid_gid)

        rewritten_agents_summary: list[dict[str, Any]] = []
        snap_src = payload_dir / "paperclip" / "agents-adapter-snapshot.json"
        if snap_src.is_file():
            rows = json.loads(snap_src.read_text(encoding="utf-8"))
            updated_rows = []
            found_uuids: set[str] = set()
            for row in rows:
                ag_id = str(row["id"])
                if str(row.get("company_id", expected_company_id)).lower() != expected_company_id.lower():
                    raise ValueError(f"Agent {ag_id} company_id mismatch against manifest.")
                meta = row.get("metadata") or {}
                slug = (
                    uuid_to_slug.get(ag_id.lower())
                    or meta.get("role_slug")
                    or AGENT_NAME_TO_SLUG.get(str(row.get("name", "")))
                )
                prof = meta.get("hermes_profile") or (CANONICAL_11_PROFILES.get(slug or ""))
                new_cfg = rewrite_adapter_config_paths(
                    row.get("adapter_config") or {},
                    role_slug=slug,
                    profile_id=prof,
                    target_cfg=target_cfg,
                )
                assert_no_legacy_paths_in_adapter_config(ag_id, new_cfg)
                found_uuids.add(ag_id.lower())
                updated_row = {**row, "adapter_config": new_cfg}
                updated_rows.append(updated_row)
                rewritten_agents_summary.append(
                    {
                        "id": ag_id,
                        "role_slug": slug,
                        "hermes_home": (new_cfg.get("env") or {}).get("HERMES_HOME"),
                        "cwd": new_cfg.get("cwd"),
                        "instructionsFilePath": new_cfg.get("instructionsFilePath"),
                    }
                )
            expected_set = {u.lower() for u in expected_uuids.values()}
            if not expected_set.issubset(found_uuids):
                missing = sorted(expected_set - found_uuids)
                raise RuntimeError(f"Missing canonical Agent UUIDs in snapshot verification: {missing}")

            snap_dst = paperclip_instance_root / "agents-adapter-migrated.json"
            snap_dst.write_text(json.dumps(updated_rows, indent=2) + "\n", encoding="utf-8")
            enforce_permissions(snap_dst, is_dir=False, uid_gid=uid_gid)

        return {
            "mode": "sql-stage",
            "company_id_verified": expected_company_id,
            "preserved_agent_uuids": len(expected_uuids),
            "rewritten_agents": rewritten_agents_summary,
            "staged_sql_path": str(restored_sql_dst),
        }

    # 1. Restore full Paperclip logical SQL dump
    _run_psql_command(
        sql_text,
        postgres_mode=postgres_mode,
        database_url=database_url,
        compose_file=compose_file,
        postgres_service=postgres_service,
        postgres_user=postgres_user,
        postgres_db=postgres_db,
    )

    # 2. Fetch restored agents & verify Company UUID + 11 Agent UUIDs
    query_json = (
        "SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json)::text FROM ("
        "SELECT id::text AS id, company_id::text AS company_id, name, role, "
        "adapter_config, COALESCE(metadata, '{}'::jsonb) AS metadata FROM public.agents"
        ") t;"
    )
    raw_out = _run_psql_command(
        query_json,
        postgres_mode=postgres_mode,
        database_url=database_url,
        compose_file=compose_file,
        postgres_service=postgres_service,
        postgres_user=postgres_user,
        postgres_db=postgres_db,
        tuples_only=True,
    ).strip()
    agent_rows: list[dict[str, Any]] = json.loads(raw_out or "[]")

    found_uuids = {str(r["id"]).lower() for r in agent_rows}
    expected_uuid_set = {u.lower() for u in expected_uuids.values()}
    if not expected_uuid_set.issubset(found_uuids):
        missing = sorted(expected_uuid_set - found_uuids)
        raise RuntimeError(f"PostgreSQL restore missing expected Agent UUIDs: {missing}")

    # 3. Rewrite adapter_config JSONB in-place while preserving exact Agent UUIDs
    update_statements = ["BEGIN;"]
    rewritten_agents_summary = []
    for row in agent_rows:
        ag_id = str(row["id"])
        if not UUID_RE.match(ag_id):
            raise ValueError(f"Unexpected non-UUID agent id in database: {ag_id}")
        meta = row.get("metadata") or {}
        slug = (
            uuid_to_slug.get(ag_id.lower())
            or meta.get("role_slug")
            or AGENT_NAME_TO_SLUG.get(str(row.get("name", "")))
        )
        prof = meta.get("hermes_profile") or (CANONICAL_11_PROFILES.get(slug or ""))
        new_cfg = rewrite_adapter_config_paths(
            row.get("adapter_config") or {},
            role_slug=slug,
            profile_id=prof,
            target_cfg=target_cfg,
        )
        assert_no_legacy_paths_in_adapter_config(ag_id, new_cfg)
        cfg_json = json.dumps(new_cfg, separators=(",", ":"))
        tag = f"aia_cfg_{ag_id.replace('-', '')}"
        update_statements.append(
            f"UPDATE public.agents SET adapter_config = ${tag}${cfg_json}${tag}$::jsonb "
            f"WHERE id = '{ag_id}'::uuid;"
        )
        rewritten_agents_summary.append(
            {
                "id": ag_id,
                "role_slug": slug,
                "hermes_home": (new_cfg.get("env") or {}).get("HERMES_HOME"),
                "cwd": new_cfg.get("cwd"),
                "instructionsFilePath": new_cfg.get("instructionsFilePath"),
            }
        )
    update_statements.append("COMMIT;")

    _run_psql_command(
        "\n".join(update_statements),
        postgres_mode=postgres_mode,
        database_url=database_url,
        compose_file=compose_file,
        postgres_service=postgres_service,
        postgres_user=postgres_user,
        postgres_db=postgres_db,
    )

    return {
        "mode": "live_psql",
        "company_id_verified": expected_company_id,
        "preserved_agent_uuids": len(expected_uuids),
        "rewritten_agents": rewritten_agents_summary,
    }


def _resolve_target_state_root(target_root: Path, explicit_state_root: str | None) -> Path:
    if explicit_state_root and explicit_state_root.strip():
        return Path(explicit_state_root).expanduser().resolve()
    env_state = (os.environ.get("ALLINAGENT_STATE_DIR") or "").strip()
    if env_state:
        return Path(env_state).expanduser().resolve()
    if target_root.as_posix() == "/opt/allinagent" or (target_root / ".git").exists():
        return Path("/var/lib/allinagent").resolve()
    return target_root.resolve()


def run_import(args: argparse.Namespace) -> dict[str, Any]:
    target_root = Path(args.target_root).expanduser().resolve()
    state_root = _resolve_target_state_root(target_root, args.target_state_root)
    compose_file = resolve_compose_file(target_root, args.compose_file)

    target_hermes_root = (
        Path(args.target_hermes_root).expanduser().resolve()
        if args.target_hermes_root
        else (state_root / "hermes").resolve()
    )
    target_reports_root = (
        Path(args.target_reports_root).expanduser().resolve()
        if args.target_reports_root
        else (state_root / "reports").resolve()
    )
    target_secrets_root = (
        Path(args.target_secrets_root).expanduser().resolve()
        if args.target_secrets_root
        else (state_root / "secrets").resolve()
    )
    target_workspaces_root = Path(args.target_workspaces_root).expanduser().resolve()
    paperclip_home = (
        Path(args.paperclip_home).expanduser().resolve()
        if args.paperclip_home
        else (state_root / "paperclip").resolve()
    )
    office_data_dst_root = (
        Path(args.target_office_data_root).expanduser().resolve()
        if args.target_office_data_root
        else (state_root / "office-data").resolve()
    )
    paperclip_instance_root = paperclip_home / "instances" / args.paperclip_instance
    uid_gid = parse_chown_spec(args.chown)

    # Standalone .telegram_cutover_lock management mode (no --bundle required)
    if not args.bundle and (args.lock_telegram_cutover or args.clear_telegram_cutover):
        if args.lock_telegram_cutover and args.clear_telegram_cutover:
            raise ValueError("Cannot pass both --lock-telegram-cutover and --clear-telegram-cutover simultaneously.")
        cutover_res = set_telegram_cutover_lock(
            target_hermes_root=target_hermes_root,
            state_root=state_root,
            locked=bool(args.lock_telegram_cutover),
            source_poller_active=bool(args.source_poller_active),
            uid_gid=uid_gid,
        )
        return {
            "ok": True,
            "mode": "telegram_cutover_lock_updated",
            "target_hermes_root": str(target_hermes_root),
            "telegram_cutover": cutover_res,
        }

    if not args.bundle:
        raise ValueError("--bundle is required unless --lock-telegram-cutover or --clear-telegram-cutover is specified.")

    bundle_path = assert_outside_git_repo(Path(args.bundle))
    if not args.dry_run:
        for writable_dir in (
            state_root,
            target_hermes_root,
            target_reports_root,
            target_secrets_root,
            paperclip_instance_root,
            office_data_dst_root,
        ):
            assert_outside_git_repo(writable_dir)

    target_cfg = TargetPathConfig(
        target_root=target_root.as_posix(),
        state_root=state_root.as_posix(),
        hermes_root=target_hermes_root.as_posix(),
        workspaces_root=target_workspaces_root.as_posix(),
        reports_root=target_reports_root.as_posix(),
        secrets_root=target_secrets_root.as_posix(),
        hermes_command=args.target_hermes_command,
        paperclip_api_url=args.target_paperclip_api_url,
        preserve_paperclip_api_url=args.preserve_local_api_url,
    )

    passphrase = resolve_passphrase(args)
    header_obj, tar_gz_bytes = decrypt_and_verify_bundle(bundle_path, passphrase)

    temp_root = assert_outside_git_repo(resolve_system_temp_dir())
    stage_root = assert_outside_git_repo(
        Path(tempfile.mkdtemp(prefix="allinagent-mig-import-", dir=str(temp_root)))
    )
    enforce_permissions(stage_root, is_dir=True)
    payload_dir = stage_root / "payload"
    payload_dir.mkdir(parents=True, exist_ok=True)
    enforce_permissions(payload_dir, is_dir=True)

    try:
        safe_extract_tar_gz(tar_gz_bytes, payload_dir)
        manifest = verify_staged_payload(payload_dir)

        if args.dry_run:
            return {
                "ok": True,
                "mode": "dry_run",
                "compose_file": str(compose_file),
                "bundle_header": {
                    "cipher": header_obj["cipher"],
                    "kdf": header_obj["kdf"],
                    "kdf_iterations": header_obj["kdf_iterations"],
                },
                "target_paths": {
                    "state_root": str(state_root),
                    "hermes_root": str(target_hermes_root),
                    "reports_root": str(target_reports_root),
                    "secrets_root": str(target_secrets_root),
                },
                "manifest_consistency": manifest["consistency_summary"],
                "identity_continuity": manifest["identity_continuity"],
            }

        # 1. Verify quiescent services & pre-check Telegram cutover guard BEFORE touching target state
        verify_quiescent_services(
            state_root,
            compose_file=compose_file,
            skip_check=args.skip_quiescence_check,
        )

        effective_cutover = bool((args.cutover_telegram or args.clear_telegram_cutover) and not args.lock_telegram_cutover)
        if args.source_poller_active:
            raise RuntimeError(
                "Single-Poller Telegram Cutover Guard: source Telegram poller reported active."
            )
        has_root_gateway_state = any(
            a.get("archive_path") == "hermes/state.db" for a in manifest.get("artifacts", [])
        )
        if args.start_gateway and has_root_gateway_state and not effective_cutover:
            raise RuntimeError(
                "Single-Poller Telegram Cutover Guard: refusing --start-gateway with live Telegram "
                "gateway state unless --cutover-telegram is explicitly passed after stopping source poller."
            )

        with MaintenanceLockGuard(state_root):
            target_reports_root.mkdir(parents=True, exist_ok=True)
            enforce_permissions(target_reports_root, is_dir=True, uid_gid=uid_gid)
            target_secrets_root.mkdir(parents=True, exist_ok=True)
            enforce_permissions(target_secrets_root, is_dir=True, uid_gid=uid_gid)

            if args.lock_telegram_cutover:
                cutover_status = set_telegram_cutover_lock(
                    target_hermes_root=target_hermes_root,
                    state_root=state_root,
                    locked=True,
                    source_poller_active=args.source_poller_active,
                    uid_gid=uid_gid,
                )
            else:
                cutover_status = enforce_single_poller_telegram_cutover(
                    manifest=manifest,
                    target_root=target_root,
                    state_root=state_root,
                    target_hermes_root=target_hermes_root,
                    cutover_telegram=effective_cutover,
                    start_gateway=args.start_gateway,
                    source_poller_active=args.source_poller_active,
                    uid_gid=uid_gid,
                )

            restored_sqlite: list[dict[str, Any]] = []

            # 2. Restore Hermes root state.db + continuity files
            staged_root_db = payload_dir / "hermes" / "state.db"
            if staged_root_db.is_file():
                restored_sqlite.append(
                    restore_sqlite_clean(
                        staged_root_db,
                        target_hermes_root / "state.db",
                        uid_gid=uid_gid,
                    )
                )
            for rel_mem in ("SOUL.md", "memories/MEMORY.md", "memories/USER.md"):
                src_m = payload_dir / "hermes" / rel_mem
                if src_m.is_file():
                    dst_m = assert_outside_git_repo(target_hermes_root / rel_mem)
                    dst_m.parent.mkdir(parents=True, exist_ok=True)
                    enforce_permissions(dst_m.parent, is_dir=True, uid_gid=uid_gid)
                    scrubbed = scrub_legacy_paths_in_markdown(
                        src_m.read_text(encoding="utf-8", errors="replace"), target_cfg
                    )
                    dst_m.write_text(scrubbed, encoding="utf-8")
                    enforce_permissions(dst_m, is_dir=False, uid_gid=uid_gid)

            # 3. Restore all 11 pc* worker profile directories & state.db snapshots
            staged_profiles_root = payload_dir / "hermes" / "profiles"
            for _slug, prof_id in CANONICAL_11_PROFILES.items():
                dst_prof = assert_outside_git_repo(target_hermes_root / "profiles" / prof_id)
                for sub in ("memories", "sessions", "skills", "skins", "logs", "plans", "workspace", "cron", "home"):
                    sub_dir = dst_prof / sub
                    sub_dir.mkdir(parents=True, exist_ok=True)
                    enforce_permissions(sub_dir, is_dir=True, uid_gid=uid_gid)
                (dst_prof / ".no-bundled-skills").write_text("1\n", encoding="utf-8")
                enforce_permissions(dst_prof / ".no-bundled-skills", is_dir=False, uid_gid=uid_gid)
                enforce_permissions(dst_prof, is_dir=True, uid_gid=uid_gid)

            if staged_profiles_root.is_dir():
                for prof_dir in sorted(staged_profiles_root.iterdir()):
                    if not prof_dir.is_dir():
                        continue
                    prof_id = prof_dir.name
                    dst_prof = assert_outside_git_repo(target_hermes_root / "profiles" / prof_id)
                    dst_prof.mkdir(parents=True, exist_ok=True)
                    enforce_permissions(dst_prof, is_dir=True, uid_gid=uid_gid)

                    staged_prof_db = prof_dir / "state.db"
                    if staged_prof_db.is_file():
                        restored_sqlite.append(
                            restore_sqlite_clean(
                                staged_prof_db,
                                dst_prof / "state.db",
                                uid_gid=uid_gid,
                            )
                        )

                    for item in sorted(prof_dir.rglob("*")):
                        if not item.is_file() or item.name in ("state.db", ".no_bundled_skills"):
                            continue
                        rel_p = item.relative_to(prof_dir)
                        dst_item = assert_outside_git_repo(dst_prof / rel_p)
                        dst_item.parent.mkdir(parents=True, exist_ok=True)
                        enforce_permissions(dst_item.parent, is_dir=True, uid_gid=uid_gid)
                        if item.suffix.lower() == ".md":
                            content = scrub_legacy_paths_in_markdown(
                                item.read_text(encoding="utf-8", errors="replace"), target_cfg
                            )
                            dst_item.write_text(content, encoding="utf-8")
                        else:
                            dst_item.write_bytes(item.read_bytes())
                        enforce_permissions(dst_item, is_dir=False, uid_gid=uid_gid)

                    (dst_prof / ".no-bundled-skills").write_text("1\n", encoding="utf-8")
                    enforce_permissions(dst_prof / ".no-bundled-skills", is_dir=False, uid_gid=uid_gid)
                    (dst_prof / ".no_bundled_skills").unlink(missing_ok=True)

                    if not (dst_prof / "AGENTS.md").is_file() and (dst_prof / "SOUL.md").is_file():
                        (dst_prof / "AGENTS.md").write_bytes((dst_prof / "SOUL.md").read_bytes())
                        enforce_permissions(dst_prof / "AGENTS.md", is_dir=False, uid_gid=uid_gid)

            # 4. Restore findings.db & workflow-ledger.db under state_root
            staged_findings = payload_dir / "platform-data" / "findings" / "findings.db"
            if staged_findings.is_file():
                restored_sqlite.append(
                    restore_sqlite_clean(
                        staged_findings,
                        state_root / "findings" / "findings.db",
                        uid_gid=uid_gid,
                    )
                )

            staged_workflow = payload_dir / "platform-data" / "workflow-ledger.db"
            if staged_workflow.is_file():
                restored_sqlite.append(
                    restore_sqlite_clean(
                        staged_workflow,
                        state_root / "workflow-ledger.db",
                        uid_gid=uid_gid,
                    )
                )

            # 5. Restore Paperclip master.key & organization-roster.json into secrets & instance dirs
            staged_master_key = payload_dir / "paperclip" / "secrets" / "master.key"
            master_key_bytes = staged_master_key.read_bytes()
            for dst_mk in (
                paperclip_instance_root / "secrets" / "master.key",
                target_secrets_root / "paperclip-master.key",
            ):
                assert_outside_git_repo(dst_mk)
                dst_mk.parent.mkdir(parents=True, exist_ok=True)
                enforce_permissions(dst_mk.parent, is_dir=True, uid_gid=uid_gid)
                dst_mk.write_bytes(master_key_bytes)
                enforce_permissions(dst_mk, is_dir=False, uid_gid=uid_gid)

            staged_roster = payload_dir / "paperclip" / "organization-roster.json"
            roster_bytes = staged_roster.read_bytes()
            roster_targets = [
                target_secrets_root / "organization-roster.json",
                state_root / "config" / "organization-roster.json",
            ]
            for dst_roster in roster_targets:
                assert_outside_git_repo(dst_roster)
                dst_roster.parent.mkdir(parents=True, exist_ok=True)
                enforce_permissions(dst_roster.parent, is_dir=True, uid_gid=uid_gid)
                dst_roster.write_bytes(roster_bytes)
                enforce_permissions(dst_roster, is_dir=False, uid_gid=uid_gid)

            # 6. Restore office-data continuity stores & normalize target-folders.json paths
            staged_office_dir = payload_dir / "office-data"
            restored_office_files = 0
            if staged_office_dir.is_dir():
                for src_off in sorted(staged_office_dir.rglob("*")):
                    if not src_off.is_file():
                        continue
                    rel_off = src_off.relative_to(staged_office_dir)
                    dst_off = assert_outside_git_repo(office_data_dst_root / rel_off)
                    dst_off.parent.mkdir(parents=True, exist_ok=True)
                    enforce_permissions(dst_off.parent, is_dir=True, uid_gid=uid_gid)
                    if rel_off.as_posix() == "target-folders.json":
                        tf_obj = json.loads(src_off.read_text(encoding="utf-8-sig"))
                        active_raw = tf_obj.get("active_folder")
                        tf_obj["active_folder"] = (
                            rewrite_single_path_string(
                                str(active_raw), fallback_profile_id=None, target_cfg=target_cfg
                            )
                            if active_raw
                            else f"{target_cfg.workspaces_root.rstrip('/')}/sample-project"
                        )
                        pinned = [
                            rewrite_single_path_string(
                                str(p), fallback_profile_id=None, target_cfg=target_cfg
                            )
                            for p in (tf_obj.get("pinned_paths") or [])
                            if p
                        ]
                        if target_cfg.workspaces_root not in pinned:
                            pinned.insert(0, target_cfg.workspaces_root)
                        tf_obj["pinned_paths"] = list(dict.fromkeys(pinned))
                        dst_off.write_text(json.dumps(tf_obj, indent=2) + "\n", encoding="utf-8")
                    else:
                        dst_off.write_bytes(src_off.read_bytes())
                    enforce_permissions(dst_off, is_dir=False, uid_gid=uid_gid)
                    restored_office_files += 1

            # 7. Restore Paperclip PostgreSQL dump & rewrite legacy paths in agents.adapter_config
            pg_restore_report = restore_and_rewrite_postgres(
                payload_dir=payload_dir,
                manifest=manifest,
                compose_file=compose_file,
                paperclip_instance_root=paperclip_instance_root,
                target_cfg=target_cfg,
                postgres_mode=args.postgres_mode,
                database_url=args.database_url,
                postgres_service=args.postgres_service,
                postgres_user=args.postgres_user,
                postgres_db=args.postgres_db,
                uid_gid=uid_gid,
            )

            return {
                "ok": True,
                "mode": "restored",
                "target_root": str(target_root),
                "compose_file": str(compose_file),
                "target_state_root": str(state_root),
                "target_hermes_root": str(target_hermes_root),
                "target_reports_root": str(target_reports_root),
                "target_secrets_root": str(target_secrets_root),
                "target_workspaces_root": str(target_workspaces_root),
                "telegram_cutover": cutover_status,
                "sqlite_restored_count": len(restored_sqlite),
                "office_data_restored_count": restored_office_files,
                "postgres_restore": pg_restore_report,
            }
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Decrypt, verify, and restore ALLINAGENT private production state onto Ubuntu 24.04 VPS."
    )
    parser.add_argument(
        "--bundle",
        default=None,
        help="Path to the AES-256-GCM encrypted .aiaenc migration bundle (must reside outside any Git repository).",
    )
    parser.add_argument(
        "--target-root",
        default="/opt/allinagent",
        help="Target ALLINAGENT Compose project root on VPS (default: /opt/allinagent).",
    )
    parser.add_argument(
        "--compose-file",
        default=None,
        help="Explicit compose.yaml path (default: <target-root>/compose.yaml).",
    )
    parser.add_argument(
        "--target-state-root",
        default=None,
        help="External mutable state root outside Git worktree (default: /var/lib/allinagent).",
    )
    parser.add_argument(
        "--target-hermes-root",
        default=None,
        help="Target Hermes data volume root (default: /var/lib/allinagent/hermes).",
    )
    parser.add_argument(
        "--target-reports-root",
        default=None,
        help="Target reports volume root (default: /var/lib/allinagent/reports).",
    )
    parser.add_argument(
        "--target-secrets-root",
        default=None,
        help="Target secrets volume root (default: /var/lib/allinagent/secrets).",
    )
    parser.add_argument(
        "--target-office-data-root",
        default=None,
        help="Target office-data volume root (default: /var/lib/allinagent/office-data).",
    )
    parser.add_argument(
        "--target-workspaces-root",
        default="/workspaces",
        help="Target authorized workspaces mount root inside containers (default: /workspaces).",
    )
    parser.add_argument(
        "--target-hermes-command",
        default="hermes",
        help="Target Linux Hermes CLI command for Paperclip agents.adapter_config (default: hermes).",
    )
    parser.add_argument(
        "--target-paperclip-api-url",
        default="http://paperclip:3100/api",
        help="Target Paperclip API URL injected into agents.adapter_config.",
    )
    parser.add_argument(
        "--preserve-local-api-url",
        action="store_true",
        help="Preserve existing paperclipApiUrl (e.g. http://127.0.0.1:3100/api) when sharing network namespace.",
    )
    parser.add_argument(
        "--paperclip-home",
        default=None,
        help="Target Paperclip home directory (default: /var/lib/allinagent/paperclip).",
    )
    parser.add_argument(
        "--paperclip-instance",
        default="default",
        help="Target Paperclip instance ID (default: default).",
    )
    parser.add_argument(
        "--postgres-mode",
        choices=("auto", "psql", "docker", "sql-stage"),
        default="auto",
        help="PostgreSQL restore driver: auto (psql or docker compose exec), psql, docker, or sql-stage.",
    )
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Target PostgreSQL connection string when using host psql.",
    )
    parser.add_argument(
        "--postgres-service",
        default="postgres",
        help="Docker Compose PostgreSQL service name (default: postgres).",
    )
    parser.add_argument(
        "--postgres-user",
        default="paperclip",
        help="PostgreSQL username for docker compose exec psql (default: paperclip).",
    )
    parser.add_argument(
        "--postgres-db",
        default="paperclip",
        help="PostgreSQL database name for docker compose exec psql (default: paperclip).",
    )
    parser.add_argument(
        "--passphrase-env",
        default="ALLINAGENT_MIGRATION_PASSPHRASE",
        help="Environment variable holding the decryption passphrase.",
    )
    parser.add_argument(
        "--passphrase-file",
        default=None,
        help="Path to a 0600 file containing the decryption passphrase.",
    )
    parser.add_argument(
        "--cutover-telegram",
        action="store_true",
        help="Confirm source host Telegram poller is stopped, clear .telegram_cutover_lock, and authorize target polling.",
    )
    parser.add_argument(
        "--lock-telegram-cutover",
        action="store_true",
        help="Create <target-hermes-root>/.telegram_cutover_lock so target Hermes skips Telegram polling while keeping exec daemon active.",
    )
    parser.add_argument(
        "--clear-telegram-cutover",
        action="store_true",
        help="Remove <target-hermes-root>/.telegram_cutover_lock after confirming the source Telegram poller is stopped.",
    )
    parser.add_argument(
        "--start-gateway",
        action="store_true",
        help="Request immediate Gateway activation (requires --cutover-telegram when live state is present).",
    )
    parser.add_argument(
        "--source-poller-active",
        action="store_true",
        help="Signal that a remote preflight check detected an active source Telegram poller (causes abort).",
    )
    parser.add_argument(
        "--skip-quiescence-check",
        action="store_true",
        help="Skip host port/container quiescence probe (isolated test harnesses only).",
    )
    parser.add_argument(
        "--chown",
        default=None,
        help="Optional POSIX '<uid>:<gid>' ownership applied alongside 0700/0600 permissions.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Decrypt and validate bundle integrity in /tmp without writing to target directories.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        result = run_import(args)
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 2 if "Cutover Guard" in str(exc) else 1


if __name__ == "__main__":
    raise SystemExit(main())
