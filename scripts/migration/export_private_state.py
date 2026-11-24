#!/usr/bin/env python3
"""Export operational ALLINAGENT / legacy host state into an AES-256-GCM encrypted bundle.

Security & Integrity Guarantees:
  1. Stages ALL intermediate artifacts exclusively in OS temporary storage (`$TEMP` / `/tmp`)
     with `0700` directory and `0600` file permissions — NEVER inside any Git working tree.
  2. Performs online WAL-safe snapshots of all SQLite databases (`state.db` root + all 11 `pc*`
     worker profiles, `findings.db`, and `workflow-ledger.db`) using `sqlite3.Connection.backup()`,
     normalizing snapshots to single-file journal mode (`DELETE`) with `PRAGMA integrity_check`
     (NEVER raw-copying dirty `-wal` or `-shm` files).
  3. Exports Paperclip PostgreSQL logical dump (`pg_dump --no-owner --no-acl` or
     `paperclipai db:backup`) + `master.key` + `organization-roster.json`, recording the
     canonical Company UUID and all 11 Agent UUIDs in the signed/authenticated manifest.
  4. Exports `office-data` continuity stores (`meetings.json`, `standup-store.json`,
     `chat-history/*.json`, `analytics-budgets.json`, `company-layout.json`, and related stores).
  5. Encrypts the compressed archive using `AESGCM` (256-bit key, 96-bit CSPRNG nonce, header AAD)
     derived via `PBKDF2HMAC` (SHA-256, 600,000 iterations, 256-bit CSPRNG salt).
  6. Supports `--dry-run` consistency verification without writing a persistent output file.
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
import sqlite3
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BUNDLE_MAGIC = b"AIASTATE"
BUNDLE_VERSION = 1
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 32
NONCE_BYTES = 12
KEY_BYTES = 32
MIN_PASSPHRASE_LENGTH = 12

CANONICAL_11_PROFILES: tuple[tuple[str, str], ...] = (
    ("ceo_agent", "pcceoagent"),
    ("cto_agent", "pcctoagent"),
    ("backend_developer", "pcbackenddeveloper"),
    ("frontend_developer", "pcfrontenddeveloper"),
    ("devops_engineer", "pcdevopsengineer"),
    ("qa_engineer", "pcqaengineer"),
    ("security_lead", "pcsecuritylead"),
    ("security_reviewer", "pcsecurityreviewer"),
    ("findings_analyst", "pcfindingsanalyst"),
    ("remediation_reviewer", "pcremediationreviewer"),
    ("compliance_reporter", "pccompliancereporter"),
)

OFFICE_DATA_CONTINUITY_CANDIDATES: tuple[str, ...] = (
    "meetings.json",
    "event-history/meetings.json",
    "event-history/notified-completions.json",
    "standup-store.json",
    "studio-state/hermes3d/standup-store.json",
    "company-layout.json",
    "studio-state/hermes3d/company-layout.json",
    "analytics-budgets.json",
    "target-folders.json",
    "telegram-control-state.json",
)

PROFILE_CONTINUITY_RELPATHS: tuple[str, ...] = (
    "SOUL.md",
    "AGENTS.md",
    ".no-bundled-skills",
    ".no_bundled_skills",
    ".paperclip_key_meta.json",
    "memories/MEMORY.md",
    "memories/USER.md",
)

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def enforce_private_permissions(path: Path, *, is_dir: bool = False) -> None:
    mode = 0o700 if is_dir else 0o600
    try:
        os.chmod(path, mode)
    except OSError:
        pass
    if os.name == "nt" and is_dir:
        username = os.environ.get("USERNAME", "").strip()
        if username:
            subprocess.run(
                [
                    "icacls.exe",
                    str(path),
                    "/inheritance:r",
                    "/grant:r",
                    f"{username}:(OI)(CI)F",
                    "*S-1-5-18:(OI)(CI)F",
                    "*S-1-5-32-544:(OI)(CI)F",
                ],
                capture_output=True,
                check=False,
            )


def resolve_system_temp_dir() -> Path:
    if os.name == "nt":
        raw = os.environ.get("TEMP") or os.environ.get("TMP") or tempfile.gettempdir()
    else:
        raw = os.environ.get("TMPDIR") or "/tmp"
    resolved = Path(raw).expanduser().resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def assert_outside_git_repo(
    candidate: Path | str,
    *,
    extra_forbidden_roots: list[Path] | None = None,
) -> Path:
    resolved = Path(candidate).expanduser().resolve()
    repo_root = Path(__file__).resolve().parents[2].resolve()
    sys_temp = resolve_system_temp_dir()
    user_home = Path.home().resolve()

    forbidden = [repo_root, *(extra_forbidden_roots or [])]
    for root in forbidden:
        r_norm = root.resolve()
        if resolved == r_norm or r_norm in resolved.parents:
            raise PermissionError(
                f"Security policy violation: path '{resolved}' is inside repository/platform tree '{r_norm}'. "
                "Migration staging and encrypted bundles MUST reside in $TEMP / /tmp or external storage."
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


def resolve_passphrase(args: argparse.Namespace, *, required: bool = True) -> str:
    if args.passphrase_file:
        pfile = Path(args.passphrase_file).expanduser().resolve()
        secret = pfile.read_text(encoding="utf-8").splitlines()[0].strip()
    elif args.passphrase_env and os.environ.get(args.passphrase_env):
        secret = os.environ[args.passphrase_env].strip()
    elif not required:
        return ""
    else:
        first = getpass.getpass("Enter migration bundle encryption passphrase (min 12 chars): ").strip()
        second = getpass.getpass("Confirm migration bundle encryption passphrase: ").strip()
        if first != second:
            raise ValueError("Passphrase confirmation did not match.")
        secret = first

    if required and len(secret) < MIN_PASSPHRASE_LENGTH:
        raise ValueError(
            f"Migration passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters long."
        )
    return secret


def derive_aes256_key(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    if iterations < PBKDF2_ITERATIONS:
        raise ValueError(f"PBKDF2 iteration count ({iterations}) is below minimum {PBKDF2_ITERATIONS}.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_tar_gz_bundle(plaintext_tar_gz: bytes, passphrase: str, output_path: Path) -> dict[str, Any]:
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = derive_aes256_key(passphrase, salt, PBKDF2_ITERATIONS)
    payload_sha256 = hashlib.sha256(plaintext_tar_gz).hexdigest()

    header_obj = {
        "cipher": "AES-256-GCM",
        "created_at_utc": utc_now_iso(),
        "kdf": "PBKDF2-HMAC-SHA256",
        "kdf_iterations": PBKDF2_ITERATIONS,
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "payload_sha256": payload_sha256,
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "version": BUNDLE_VERSION,
    }
    header_bytes = json.dumps(header_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    prefix = BUNDLE_MAGIC + struct.pack(">BI", BUNDLE_VERSION, len(header_bytes))
    aad = prefix + header_bytes

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_tar_gz, aad)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_out = output_path.with_suffix(output_path.suffix + ".part")
    try:
        fd = os.open(
            str(tmp_out),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(fd, "wb") as fh:
            fh.write(aad)
            fh.write(ciphertext)
            fh.flush()
            os.fsync(fh.fileno())
        enforce_private_permissions(tmp_out, is_dir=False)
        os.replace(tmp_out, output_path)
        enforce_private_permissions(output_path, is_dir=False)
    finally:
        if tmp_out.exists():
            tmp_out.unlink(missing_ok=True)

    bundle_sha256 = sha256_file(output_path)
    sidecar = output_path.with_suffix(output_path.suffix + ".sha256")
    sidecar.write_text(f"{bundle_sha256}  {output_path.name}\n", encoding="utf-8")
    enforce_private_permissions(sidecar, is_dir=False)

    return {
        "bundle_path": str(output_path),
        "bundle_sha256": bundle_sha256,
        "bundle_size_bytes": output_path.stat().st_size,
        "payload_sha256": payload_sha256,
        "kdf_iterations": PBKDF2_ITERATIONS,
        "sidecar_sha256_path": str(sidecar),
    }


def snapshot_sqlite_online(src_db: Path, dst_db: Path, *, archive_relpath: str) -> dict[str, Any]:
    """Perform an online WAL-safe SQLite snapshot via `sqlite3.Connection.backup()`."""
    if not src_db.is_file():
        raise FileNotFoundError(f"SQLite source database not found: {src_db}")

    dst_db.parent.mkdir(parents=True, exist_ok=True)
    enforce_private_permissions(dst_db.parent, is_dir=True)

    src_conn = sqlite3.connect(str(src_db), timeout=30.0)
    dst_conn = sqlite3.connect(str(dst_db), timeout=30.0)
    try:
        src_conn.backup(dst_conn, pages=250, sleep=0.02)
    finally:
        src_conn.close()

    table_counts: dict[str, int] = {}
    try:
        # Normalize snapshot into a clean single-file DB with zero -wal/-shm sidecars
        dst_conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        dst_conn.execute("PRAGMA journal_mode=DELETE;")
        dst_conn.commit()

        ic_rows = dst_conn.execute("PRAGMA integrity_check;").fetchall()
        ic_verdict = ic_rows[0][0] if len(ic_rows) == 1 else "; ".join(str(r[0]) for r in ic_rows)
        if ic_verdict.lower() != "ok":
            raise RuntimeError(
                f"SQLite PRAGMA integrity_check failed for '{archive_relpath}': {ic_verdict}"
            )

        tables = [
            str(r[0])
            for r in dst_conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ]
        for tbl in tables:
            safe_ident = tbl.replace('"', '""')
            cnt_row = dst_conn.execute(f'SELECT COUNT(*) FROM "{safe_ident}"').fetchone()
            table_counts[tbl] = int(cnt_row[0]) if cnt_row else 0
    finally:
        dst_conn.close()

    # Ensure zero residual WAL/SHM sidecars exist in staging
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(dst_db) + suffix)
        if sidecar.exists():
            sidecar.unlink(missing_ok=True)

    enforce_private_permissions(dst_db, is_dir=False)
    return {
        "archive_path": archive_relpath,
        "category": "sqlite",
        "integrity_check": "ok",
        "sha256": sha256_file(dst_db),
        "size_bytes": dst_db.stat().st_size,
        "table_row_counts": table_counts,
        "total_rows": sum(table_counts.values()),
    }


def stage_regular_file(
    src: Path,
    dst: Path,
    *,
    archive_relpath: str,
    category: str,
    validate_json: bool = False,
) -> dict[str, Any]:
    dst.parent.mkdir(parents=True, exist_ok=True)
    enforce_private_permissions(dst.parent, is_dir=True)
    raw = src.read_bytes()
    if validate_json:
        text = raw.decode("utf-8-sig")
        json.loads(text)
    dst.write_bytes(raw)
    enforce_private_permissions(dst, is_dir=False)
    return {
        "archive_path": archive_relpath,
        "category": category,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    }


def resolve_default_source_root() -> str:
    for env_key in ("ALLINAGENT_SOURCE_ROOT", "ALLINAGENT_LEGACY_ROOT", "ALLINAGENT_ROOT"):
        val = os.environ.get(env_key, "").strip()
        if val:
            return val
    return os.getcwd()


def resolve_default_hermes_home(platform_root: Path) -> Path:
    if os.environ.get("HERMES_HOME"):
        return Path(os.environ["HERMES_HOME"]).expanduser().resolve()
    local_appdata = os.environ.get("LOCALAPPDATA", "").strip()
    if os.name == "nt" and local_appdata:
        cand = Path(local_appdata) / "hermes"
        if cand.exists():
            return cand.resolve()
    var_hermes = Path("/var/lib/allinagent/hermes")
    if var_hermes.exists():
        return var_hermes.resolve()
    dot_hermes = Path.home() / ".hermes"
    if dot_hermes.exists():
        return dot_hermes.resolve()
    return (platform_root / "data" / "hermes-home").resolve()


def resolve_paperclip_connection_url(paperclip_instance_root: Path, explicit_url: str | None) -> str:
    if explicit_url and explicit_url.strip():
        return explicit_url.strip()
    if os.environ.get("DATABASE_URL"):
        return os.environ["DATABASE_URL"].strip()
    cfg_path = paperclip_instance_root / "config.json"
    port = 54329
    if cfg_path.is_file():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
            db_cfg = cfg.get("database") or {}
            if db_cfg.get("mode") == "postgres" and db_cfg.get("connectionString"):
                return str(db_cfg["connectionString"]).strip()
            if db_cfg.get("embeddedPostgresPort"):
                port = int(db_cfg["embeddedPostgresPort"])
        except Exception:
            pass
    return f"postgres://paperclip:paperclip@127.0.0.1:{port}/paperclip"


def discover_pg_dump_binary(platform_root: Path, explicit_bin: str | None) -> str | None:
    if explicit_bin:
        return explicit_bin
    found = shutil.which("pg_dump")
    if found:
        return found
    embedded_root = platform_root / "runtime" / "paperclip-app" / "node_modules" / "@embedded-postgres"
    if embedded_root.is_dir():
        exe_name = "pg_dump.exe" if os.name == "nt" else "pg_dump"
        for pkg_dir in sorted(embedded_root.iterdir()):
            cand = pkg_dir / "native" / "bin" / exe_name
            if cand.is_file():
                return str(cand)
    return None


def export_paperclip_postgres_dump(
    *,
    platform_root: Path,
    paperclip_instance_root: Path,
    stage_dir: Path,
    explicit_dump_file: str | None,
    explicit_pg_dump_bin: str | None,
    explicit_db_url: str | None,
    paperclip_cli_bin: str | None,
) -> dict[str, Any]:
    archive_rel = "paperclip/paperclip_dump.sql"
    dst_sql = stage_dir / archive_rel
    dst_sql.parent.mkdir(parents=True, exist_ok=True)
    enforce_private_permissions(dst_sql.parent, is_dir=True)

    if explicit_dump_file:
        src_dump = Path(explicit_dump_file).expanduser().resolve()
        if not src_dump.is_file() or src_dump.stat().st_size == 0:
            raise FileNotFoundError(f"Explicit PostgreSQL dump file missing or empty: {src_dump}")
        meta = stage_regular_file(src_dump, dst_sql, archive_relpath=archive_rel, category="postgres")
        meta["export_method"] = "explicit_dump_file"
        return meta

    conn_url = resolve_paperclip_connection_url(paperclip_instance_root, explicit_db_url)
    pg_dump_bin = discover_pg_dump_binary(platform_root, explicit_pg_dump_bin)

    if pg_dump_bin:
        cmd = [
            pg_dump_bin,
            "--no-owner",
            "--no-acl",
            "--clean",
            "--if-exists",
            "--encoding=UTF8",
            f"--dbname={conn_url}",
            f"--file={dst_sql}",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
        if proc.returncode == 0 and dst_sql.is_file() and dst_sql.stat().st_size > 0:
            enforce_private_permissions(dst_sql, is_dir=False)
            return {
                "archive_path": archive_rel,
                "category": "postgres",
                "export_method": "pg_dump",
                "sha256": sha256_file(dst_sql),
                "size_bytes": dst_sql.stat().st_size,
            }
        err_detail = (proc.stderr or proc.stdout or "").strip()[:400]
    else:
        err_detail = "pg_dump binary not found on PATH or embedded-postgres"

    # Fallback: `paperclipai db:backup --dir <tmp_backup_dir> --json`
    cli_bin = paperclip_cli_bin or shutil.which("paperclipai")
    if not cli_bin:
        cand_cmd = platform_root / "runtime" / "bin" / ("paperclipai.cmd" if os.name == "nt" else "paperclipai")
        if cand_cmd.is_file():
            cli_bin = str(cand_cmd)

    if cli_bin:
        backup_tmp = stage_dir / "_paperclip_cli_backup"
        backup_tmp.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            [cli_bin, "db:backup", "--dir", str(backup_tmp), "--json"],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        if proc.returncode == 0:
            sql_candidates = sorted(
                backup_tmp.rglob("*.sql*"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if sql_candidates:
                chosen = sql_candidates[0]
                if chosen.name.endswith(".gz"):
                    import gzip

                    with gzip.open(chosen, "rb") as gfh:
                        dst_sql.write_bytes(gfh.read())
                else:
                    shutil.copyfile(chosen, dst_sql)
                shutil.rmtree(backup_tmp, ignore_errors=True)
                enforce_private_permissions(dst_sql, is_dir=False)
                return {
                    "archive_path": archive_rel,
                    "category": "postgres",
                    "export_method": "paperclipai_db_backup",
                    "sha256": sha256_file(dst_sql),
                    "size_bytes": dst_sql.stat().st_size,
                }
        shutil.rmtree(backup_tmp, ignore_errors=True)

    raise RuntimeError(
        f"Failed to create Paperclip PostgreSQL logical backup ({err_detail}). "
        "Ensure Paperclip Postgres is running or pass --pg-dump-file."
    )


def parse_identity_continuity(roster_path: Path) -> dict[str, Any]:
    if not roster_path.is_file():
        raise FileNotFoundError(f"Required organization-roster.json not found at: {roster_path}")
    roster = json.loads(roster_path.read_text(encoding="utf-8-sig"))
    company_id = str(roster.get("company_id") or "").strip()
    if not UUID_RE.match(company_id):
        raise ValueError(f"organization-roster.json has invalid or missing company_id UUID: '{company_id}'")

    agents_obj = roster.get("agents")
    if not isinstance(agents_obj, dict):
        raise ValueError("organization-roster.json 'agents' field must be an object keyed by role_slug.")

    agent_uuids_by_slug: dict[str, str] = {}
    missing_slugs: list[str] = []
    for role_slug, _profile_id in CANONICAL_11_PROFILES:
        entry = agents_obj.get(role_slug)
        ag_id = str((entry or {}).get("id") or "").strip()
        if not UUID_RE.match(ag_id):
            missing_slugs.append(role_slug)
        else:
            agent_uuids_by_slug[role_slug] = ag_id

    if missing_slugs:
        raise ValueError(
            f"organization-roster.json is missing valid UUIDs for canonical agent roles: {missing_slugs}"
        )
    if len(set(agent_uuids_by_slug.values())) != 11:
        raise ValueError("organization-roster.json contains duplicate Agent UUIDs across the 11 roles.")

    return {
        "company_id": company_id,
        "company_name": str(roster.get("company_name") or "Unified AI Engineering & Operations"),
        "agent_count": len(agent_uuids_by_slug),
        "agent_uuids_by_slug": agent_uuids_by_slug,
        "canonical_profiles": {slug: prof for slug, prof in CANONICAL_11_PROFILES},
    }


def create_deterministic_tar_gz(stage_payload_dir: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT) as tf:
        for file_path in sorted(stage_payload_dir.rglob("*")):
            if file_path.is_symlink():
                continue
            rel = file_path.relative_to(stage_payload_dir).as_posix()
            ti = tarfile.TarInfo(name=rel)
            st = file_path.stat()
            if file_path.is_dir():
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o700
                ti.mtime = int(st.st_mtime)
                tf.addfile(ti)
            elif file_path.is_file():
                ti.type = tarfile.REGTYPE
                ti.size = st.st_size
                ti.mode = 0o600
                ti.mtime = int(st.st_mtime)
                with file_path.open("rb") as fh:
                    tf.addfile(ti, fh)
    return buf.getvalue()


def run_export(args: argparse.Namespace) -> dict[str, Any]:
    source_root = Path(args.source_root).expanduser().resolve()
    hermes_home = (
        Path(args.hermes_home).expanduser().resolve()
        if args.hermes_home
        else resolve_default_hermes_home(source_root)
    )
    paperclip_home = (
        Path(args.paperclip_home).expanduser().resolve()
        if args.paperclip_home
        else (source_root / "data" / "paperclip").resolve()
    )
    paperclip_instance_root = paperclip_home / "instances" / args.paperclip_instance

    temp_root = resolve_system_temp_dir()
    assert_outside_git_repo(temp_root)

    ts_slug = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else (temp_root / f"allinagent-private-state-{ts_slug}.aiaenc")
    )
    assert_outside_git_repo(output_path)

    passphrase = resolve_passphrase(args, required=not args.dry_run)

    stage_root = Path(tempfile.mkdtemp(prefix="allinagent-mig-export-", dir=str(temp_root)))
    enforce_private_permissions(stage_root, is_dir=True)
    assert_outside_git_repo(stage_root)
    payload_dir = stage_root / "payload"
    payload_dir.mkdir(parents=True, exist_ok=True)
    enforce_private_permissions(payload_dir, is_dir=True)

    artifacts: list[dict[str, Any]] = []
    warnings: list[str] = []

    try:
        # 1. Verify & stage organization-roster.json (Company UUID + 11 Agent UUIDs)
        roster_src = source_root / "config" / "organization-roster.json"
        identity_continuity = parse_identity_continuity(roster_src)
        artifacts.append(
            stage_regular_file(
                roster_src,
                payload_dir / "paperclip" / "organization-roster.json",
                archive_relpath="paperclip/organization-roster.json",
                category="roster",
                validate_json=True,
            )
        )

        # 2. Stage Paperclip master.key
        master_key_candidates = [
            paperclip_instance_root / "secrets" / "master.key",
            paperclip_instance_root / "master.key",
        ]
        master_key_src = next((p for p in master_key_candidates if p.is_file()), None)
        if master_key_src is None or master_key_src.stat().st_size == 0:
            raise FileNotFoundError(
                f"Paperclip master.key not found or empty under '{paperclip_instance_root}/secrets/master.key'."
            )
        artifacts.append(
            stage_regular_file(
                master_key_src,
                payload_dir / "paperclip" / "secrets" / "master.key",
                archive_relpath="paperclip/secrets/master.key",
                category="paperclip_key",
            )
        )

        # 3. Export Paperclip PostgreSQL logical dump (--no-owner --no-acl or paperclipai db:backup)
        pg_artifact = export_paperclip_postgres_dump(
            platform_root=source_root,
            paperclip_instance_root=paperclip_instance_root,
            stage_dir=payload_dir,
            explicit_dump_file=args.pg_dump_file,
            explicit_pg_dump_bin=args.pg_dump_bin,
            explicit_db_url=args.database_url,
            paperclip_cli_bin=args.paperclip_cli_bin,
        )
        artifacts.append(pg_artifact)

        # Optional structured agents rows companion if provided/present for offline verification
        agents_export_src = paperclip_instance_root / "agents-adapter-snapshot.json"
        if args.agents_json_file:
            agents_export_src = Path(args.agents_json_file).expanduser().resolve()
        if agents_export_src.is_file():
            artifacts.append(
                stage_regular_file(
                    agents_export_src,
                    payload_dir / "paperclip" / "agents-adapter-snapshot.json",
                    archive_relpath="paperclip/agents-adapter-snapshot.json",
                    category="paperclip_agents_meta",
                    validate_json=True,
                )
            )

        # 4. Online WAL-safe SQLite backups: root state.db + 11 pc* profiles
        root_state_db = hermes_home / "state.db"
        if root_state_db.is_file():
            artifacts.append(
                snapshot_sqlite_online(
                    root_state_db,
                    payload_dir / "hermes" / "state.db",
                    archive_relpath="hermes/state.db",
                )
            )
        elif args.allow_missing_optional_dbs:
            warnings.append(f"Root Hermes state.db not present at {root_state_db}")
        else:
            raise FileNotFoundError(f"Root Hermes state.db not found at: {root_state_db}")

        for rel_mem in ("SOUL.md", "memories/MEMORY.md", "memories/USER.md"):
            cand_mem = hermes_home / rel_mem
            if cand_mem.is_file():
                artifacts.append(
                    stage_regular_file(
                        cand_mem,
                        payload_dir / "hermes" / rel_mem,
                        archive_relpath=f"hermes/{rel_mem}",
                        category="hermes_continuity",
                    )
                )

        profiles_dir = hermes_home / "profiles"
        exported_profiles: list[str] = []
        canonical_profile_ids = {prof for _slug, prof in CANONICAL_11_PROFILES}
        extra_profile_ids: list[str] = []
        if profiles_dir.is_dir():
            for child in sorted(profiles_dir.iterdir()):
                if (
                    child.is_dir()
                    and not child.is_symlink()
                    and child.name.startswith("pc")
                    and child.name not in canonical_profile_ids
                ):
                    extra_profile_ids.append(child.name)

        all_profile_ids = [prof for _slug, prof in CANONICAL_11_PROFILES] + extra_profile_ids
        for prof_id in all_profile_ids:
            prof_root = profiles_dir / prof_id
            prof_db = prof_root / "state.db"
            if prof_db.is_file():
                artifacts.append(
                    snapshot_sqlite_online(
                        prof_db,
                        payload_dir / "hermes" / "profiles" / prof_id / "state.db",
                        archive_relpath=f"hermes/profiles/{prof_id}/state.db",
                    )
                )
                exported_profiles.append(prof_id)
            elif prof_id in canonical_profile_ids:
                if args.allow_missing_optional_dbs:
                    warnings.append(f"Profile {prof_id} has no state.db yet (standby/uninitialized).")
                else:
                    raise FileNotFoundError(
                        f"Canonical worker profile SQLite DB missing: {prof_db} "
                        "(pass --allow-missing-optional-dbs if standby workers have not run yet)."
                    )

            if prof_root.is_dir() and not prof_root.is_symlink():
                for rel_item in PROFILE_CONTINUITY_RELPATHS:
                    src_item = prof_root / rel_item
                    if src_item.is_file() and not src_item.is_symlink():
                        artifacts.append(
                            stage_regular_file(
                                src_item,
                                payload_dir / "hermes" / "profiles" / prof_id / rel_item,
                                archive_relpath=f"hermes/profiles/{prof_id}/{rel_item}",
                                category="hermes_profile_continuity",
                                validate_json=rel_item.endswith(".json"),
                            )
                        )

        # 5. Online WAL-safe SQLite backups: findings.db & workflow-ledger.db
        findings_db = source_root / "data" / "findings" / "findings.db"
        if findings_db.is_file():
            artifacts.append(
                snapshot_sqlite_online(
                    findings_db,
                    payload_dir / "platform-data" / "findings" / "findings.db",
                    archive_relpath="platform-data/findings/findings.db",
                )
            )
        elif not args.allow_missing_optional_dbs:
            raise FileNotFoundError(f"Required findings.db not found at: {findings_db}")

        workflow_db = source_root / "data" / "workflow-ledger.db"
        if workflow_db.is_file():
            artifacts.append(
                snapshot_sqlite_online(
                    workflow_db,
                    payload_dir / "platform-data" / "workflow-ledger.db",
                    archive_relpath="platform-data/workflow-ledger.db",
                )
            )
        elif not args.allow_missing_optional_dbs:
            raise FileNotFoundError(f"Required workflow-ledger.db not found at: {workflow_db}")

        # 6. Export office-data continuity stores
        office_data_root = source_root / "office-data"
        seen_office_rel: set[str] = set()
        if office_data_root.is_dir():
            for rel_cand in OFFICE_DATA_CONTINUITY_CANDIDATES:
                src_file = office_data_root / rel_cand
                if src_file.is_file() and not src_file.is_symlink():
                    seen_office_rel.add(rel_cand)
                    artifacts.append(
                        stage_regular_file(
                            src_file,
                            payload_dir / "office-data" / rel_cand,
                            archive_relpath=f"office-data/{rel_cand}",
                            category="office_data",
                            validate_json=True,
                        )
                    )
            chat_dir = office_data_root / "chat-history"
            if chat_dir.is_dir() and not chat_dir.is_symlink():
                for chat_file in sorted(chat_dir.glob("*.json")):
                    if chat_file.is_file() and not chat_file.is_symlink():
                        rel_chat = f"chat-history/{chat_file.name}"
                        seen_office_rel.add(rel_chat)
                        artifacts.append(
                            stage_regular_file(
                                chat_file,
                                payload_dir / "office-data" / rel_chat,
                                archive_relpath=f"office-data/{rel_chat}",
                                category="office_data",
                                validate_json=True,
                            )
                        )

        sqlite_artifacts = [a for a in artifacts if a["category"] == "sqlite"]
        manifest = {
            "schema_version": "1.0.0",
            "bundle_type": "allinagent-private-production-state",
            "created_at_utc": utc_now_iso(),
            "source_os": sys.platform,
            "encryption": {
                "cipher": "AES-256-GCM",
                "kdf": "PBKDF2-HMAC-SHA256",
                "kdf_iterations": PBKDF2_ITERATIONS,
            },
            "identity_continuity": {
                **identity_continuity,
                "exported_sqlite_profile_ids": exported_profiles,
            },
            "consistency_summary": {
                "total_artifacts": len(artifacts),
                "sqlite_databases_verified": len(sqlite_artifacts),
                "all_sqlite_integrity_ok": all(a.get("integrity_check") == "ok" for a in sqlite_artifacts),
                "total_sqlite_rows": sum(int(a.get("total_rows", 0)) for a in sqlite_artifacts),
                "office_data_files": len([a for a in artifacts if a["category"] == "office_data"]),
                "warnings": warnings,
            },
            "artifacts": artifacts,
        }

        manifest_path = payload_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        enforce_private_permissions(manifest_path, is_dir=False)

        if args.dry_run:
            return {
                "ok": True,
                "mode": "dry_run",
                "staged_strictly_in_temp": str(stage_root),
                "consistency_summary": manifest["consistency_summary"],
                "identity_continuity": {
                    "company_id": identity_continuity["company_id"],
                    "agent_count": identity_continuity["agent_count"],
                    "agent_uuids_by_slug": identity_continuity["agent_uuids_by_slug"],
                },
                "sqlite_reports": sqlite_artifacts,
            }

        tar_gz_bytes = create_deterministic_tar_gz(payload_dir)
        enc_meta = encrypt_tar_gz_bundle(tar_gz_bytes, passphrase, output_path)
        return {
            "ok": True,
            "mode": "encrypted_export",
            **enc_meta,
            "consistency_summary": manifest["consistency_summary"],
            "identity_continuity": {
                "company_id": identity_continuity["company_id"],
                "agent_count": identity_continuity["agent_count"],
            },
        }
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export ALLINAGENT private operational state into an AES-256-GCM encrypted bundle in $TEMP / /tmp."
    )
    parser.add_argument(
        "--source-root",
        default=resolve_default_source_root(),
        help="Root directory of the existing platform installation (or set ALLINAGENT_LEGACY_ROOT).",
    )
    parser.add_argument(
        "--hermes-home",
        default=None,
        help="Explicit Hermes root directory containing state.db and profiles/pc*.",
    )
    parser.add_argument(
        "--paperclip-home",
        default=None,
        help="Explicit Paperclip home directory (defaults to <source-root>/data/paperclip).",
    )
    parser.add_argument(
        "--paperclip-instance",
        default="default",
        help="Paperclip instance ID (default: 'default').",
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="PostgreSQL connection string override for pg_dump.",
    )
    parser.add_argument(
        "--pg-dump-bin",
        default=None,
        help="Explicit path to pg_dump executable.",
    )
    parser.add_argument(
        "--pg-dump-file",
        default=None,
        help="Pre-generated pg_dump --no-owner --no-acl SQL file to embed.",
    )
    parser.add_argument(
        "--paperclip-cli-bin",
        default=None,
        help="Explicit path to paperclipai CLI executable for fallback backup.",
    )
    parser.add_argument(
        "--agents-json-file",
        default=None,
        help="Optional JSON export of Paperclip agents rows for offline adapter_config verification.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output .aiaenc bundle path (MUST be outside any Git repository; defaults to $TEMP / /tmp).",
    )
    parser.add_argument(
        "--passphrase-env",
        default="ALLINAGENT_MIGRATION_PASSPHRASE",
        help="Environment variable holding the encryption passphrase.",
    )
    parser.add_argument(
        "--passphrase-file",
        default=None,
        help="Path to a 0600 file containing the encryption passphrase.",
    )
    parser.add_argument(
        "--allow-missing-optional-dbs",
        action="store_true",
        help="Allow standby pc* profiles that have not yet created a state.db file.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run online SQLite backups, PRAGMA integrity_check, and row-count verification in temp storage without writing an output bundle.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        result = run_export(args)
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
