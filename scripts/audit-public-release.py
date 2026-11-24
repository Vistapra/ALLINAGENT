#!/usr/bin/env python3
"""ALLINAGENT Public Release Security, Privacy & Hygiene Gate.

Fail-closed release auditor that verifies a candidate repository tree contains:
  1. Zero secrets, API keys, bot tokens, PEM private keys, or internal runtime
     tokens (`ob_tok_*`, `st_tok_*`, `pcp_*`).
  2. Zero hardcoded Windows user paths, legacy platform paths, or placeholder
     owner Telegram IDs; fail-closed blank credentials in `.env.example`.
  3. Zero tracked runtime data, `.env` files, `node_modules/`, virtualenvs,
     databases, SQL dumps, native Windows binaries, or Commons-Clause skill blobs
     in `git ls-files`.
  4. Clean working tree when `--strict-clean-tree` is enabled.
  5. Optional zero-plaintext private identifier matching via salted/unsalted
     SHA-256 hash blocklists (`ALLINAGENT_PRIVATE_HASH_FILE`) or an external
     untracked file (`ALLINAGENT_PRIVATE_BLOCKLIST_FILE`).

Safety Guarantee: Secret files (`.env`, `.env.*` except `.env.example`,
`auth.json`, `office-bridge-auth.json`, `*.local*`, private keys) are NEVER
opened, read, or printed. Any matched token in scanned source files is redacted.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

MAX_SINGLE_FILE_BYTES = 5 * 1024 * 1024
MAX_REPO_TOTAL_BYTES = 50 * 1024 * 1024
TEXT_SCAN_MAX_BYTES = 2 * 1024 * 1024

BINARY_EXTENSIONS = frozenset({
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".gif",
    ".ico",
    ".glb",
    ".gltf",
    ".bin",
    ".hdr",
    ".exr",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".wasm",
    ".mp3",
    ".ogg",
    ".wav",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
})

SKIP_WALK_DIRS = frozenset({
    ".git",
    "node_modules",
    ".pnpm-store",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".turbo",
    "dist",
    "out",
    "coverage",
    "data",
    "office-data",
    "logs",
    "reports",
    "skill-registry",
    "runtime",
    "vendor-cache",
    ".upstream-cache",
    ".certs",
})

FORBIDDEN_GIT_PREFIXES = (
    "node_modules/",
    ".venv/",
    "venv/",
    "__pycache__/",
    ".next/",
    ".turbo/",
    "dist/",
    "config/secrets/",
    "data/",
    "office-data/",
    "logs/",
    "reports/",
    "skill-registry/",
    "skills/upstream/",
    "skills/staging/",
    "skills/reviewed/",
    "skills/quarantine/",
    "skills/agents/",
    "skills/cache/",
    "hermes-agent/",
    "paperclip/",
    "vulnclaw/",
)

FORBIDDEN_GIT_GLOBS = (
    "*/node_modules/*",
    "*/.venv/*",
    "*/*venv*/*",
    "*venv*/*",
    "*/__pycache__/*",
    "*/.next/*",
    "*/dist/*",
    "*.tsbuildinfo",
    "*-worktrees/*",
    "*/*-worktrees/*",
    "*.local",
    "*.local.*",
    "auth.json",
    "*/auth.json",
    "office-bridge-auth.json",
    "*/office-bridge-auth.json",
    "config/organization-roster.json",
    "*secret*.json",
    "*token*.json",
    "*credentials*.json",
    "*.db",
    "*.db-wal",
    "*.db-shm",
    "*.db-journal",
    "*.sqlite",
    "*.sqlite3",
    "*.sql",
    "*.sql.gz",
    "*.dump",
    "*.exe",
    "*.dll",
    "*.pyd",
    "*.pem",
    "*.key",
    "*.pfx",
    ".certs/*",
    "*/.certs/*",
)

# Constructed via modular expressions so this file contains zero literal matches
# against its own scan rules.
CONTENT_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "SEC-001",
        "API key literal (sk-* / sk-ant-* / sk-or-*)",
        re.compile(r"\bsk-(?:ant-|or-v1-|proj-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "SEC-002",
        "Telegram Bot API token",
        re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{34,}\b"),
    ),
    (
        "SEC-003",
        "GitHub personal/OAuth/app access token",
        re.compile(r"\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    ),
    (
        "SEC-004",
        "Cloud / SaaS credential token (AWS AKIA, Google AIza, Slack xox*, HuggingFace hf_*)",
        re.compile(r"\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{12,}|hf_[A-Za-z0-9]{30,})\b"),
    ),
    (
        "SEC-005",
        "PEM / OpenSSH private key block header",
        re.compile("-----BEGIN " + r"(?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    ),
    (
        "SEC-006",
        "ALLINAGENT internal runtime token (ob_tok_* / st_tok_* / pcp_*)",
        re.compile(r"\b(?:ob_tok|st_tok|pcp)_[A-Za-z0-9_-]{8,}\b"),
    ),
    (
        "SEC-007",
        "Database URI with embedded non-template secret",
        re.compile(r"postgres(?:ql)?://[^:\s/]+:(?!paperclip@|\$\{|<|CHANGE_ME)[^@\s'\"`]{8,}@"),
    ),
    (
        "PORT-001",
        "Hardcoded Windows user profile path",
        re.compile(r"\b[A-Za-z]:(?:\\{1,2}|/)[Uu]sers(?:\\{1,2}|/)[A-Za-z0-9._-]{2,}"),
    ),
    (
        "PORT-002",
        "Hardcoded legacy platform or staging directory path",
        re.compile(
            r"\b[A-Za-z]:(?:\\{1,2}|/)(?:" + "AI-Agent-" + "Platform|" + "All" + "Agent" + r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        "PORT-003",
        "Hardcoded Windows AppData or Laragon host path",
        re.compile(r"(?:\b[A-Za-z]:(?:\\{1,2}|/)laragon\b|AppData(?:\\{1,2}|/)(?:Local|Roaming)(?:\\{1,2}|/)hermes)", re.IGNORECASE),
    ),
    (
        "AUTH-001",
        "Hardcoded placeholder 10-digit Telegram owner ID (must be blank / fail-closed)",
        re.compile(r"(?<![0-9])1" + r"0{9}(?![0-9])"),
    ),
)

TOKENIZER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}")

# Zero-plaintext SHA-256 token denylist for private owner, host, network, domain,
# legacy application, account, and bot identifiers (lowercase UTF-8 token digests).
BUILTIN_PRIVATE_TOKEN_SHA256: frozenset[str] = frozenset({
    "08a179227d9c68bbdede429d383f97f93c73b69647406987b272fce18f7ff9be",
    "185e74a1474798e4be09aaf2130f0e350a2b78a16573eb26f23792e6bb6bf5f4",
    "1d45d68b2e297251998990dc9da08c96aca5e19298d40bb02bdc3c380d82a0e4",
    "2208acdf2c2564d05d35529d9b9a561e6b1705e585329f58740ea8cfe4546995",
    "2f0a4c78d4727cc641f98665ef1143e08a1026983813dcfbfa85475d362edf1d",
    "313627408d0a3513e1f1d0066455ed931f6f3a3fcd59f6b3ea7577ade2965d57",
    "3a9384ee39939e7a3ef9e0a7b7875a11f2b7fda3f54ecaa166ada565d230ffda",
    "3e86bd83c112ce496d06939faec7e61fe51806c36923cdda555b7484064c0695",
    "3ffde61ef9db38690aba64a00188acf27f70556df73276b4001640197ce97655",
    "4df2f2b0800cf8c38b997812f0fc634850d4727950f05d1e394284a9847908d0",
    "527bc96e01d06a60a1157700059ea2d66906584a2f760f87c6e371a4bf5dc252",
    "588bcd17f48ccd22e0cf763073346bc1e1f94afa01e6bce7213e5c3c122f7178",
    "64ab4569dedb9c706c40fb1cd0bafed6ad78a216db765e873606b1c40f786db3",
    "771ab64b478683ecd9975f32704c0f2f9c615835386dd89ab03de6165db68b94",
    "7f40f1f25ba18e9633bec380834bbb1b3b950ba9ada2fe8b395e6bff0df58563",
    "826a46808d86325690847a653c27aab3a4cd3a2ac01efa69780d5a82f50bdde3",
    "8ef177fd3ff2c31b2b140d839b5b491e067fc71651424847a1c1603cd9103ed0",
    "92ff7111d6747b3609938da71c1f055f4246251365c8f7ed53065ff4cb9049a3",
    "969ff7f01ff4cf091c87c316dbb675c9a4b56c5679ccc0869a4ef5dde5239a19",
    "9f5e148bf6148658299ed4493da14a2292056c04ae7ea9637cc7a40c67603e66",
    "a0c36ba427871f949d71cc44fa6b085705e39da0d0c1d7689224269f0cf6b90d",
    "bea569aa7870ac91c841c341364be480851e86ea4a158ed16636aca9ad3736ee",
    "c9fae3e2294a58b5e3af301e53c6590bed7168317d386a69b517e995054eaa8f",
    "cb38434edba87892b8f61a6dc8bb513d440008bddaa0de0af8d8257943fa4d1c",
    "cc7a932d6650cf29adbab5ca53d596f128e90cd12c30b9fb1eebd04fcff463cf",
    "dc9370369642919ebeee3b9f0661aaa53a12a27c559255305a6ac7c31f326e43",
    "e3dc0fd25e92ef02e2c93496d73b8f3e447589e53a0e35715345bd08f9aedb17",
    "ea119d79c592ded758ea8a50fd85928d1481e63bbab039632ecc1fb0f042262b",
    "ebd8f80e1fd8e067dcc4157ffca179d90ec650694cde9959731217740dddf0bf",
    "fda528f46d9d106a7635c41dc2c8784548a85c44bb9be7ee9f265206ae00131a",
    "ff293b546aff2717334760b1b47f22cf62f6d202514370343e1f29acaa2183ec",
})


@dataclass
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int
    description: str
    redacted_snippet: str


def _redact_match(val: str) -> str:
    s = val.strip()
    if len(s) <= 8:
        return "[REDACTED]"
    return f"{s[:4]}...[REDACTED len={len(s)}]"


def _is_secret_filename(rel_posix: str) -> bool:
    name = Path(rel_posix).name.lower()
    parts_lower = [p.lower() for p in Path(rel_posix).parts]
    if "secrets" in parts_lower or ".certs" in parts_lower:
        return True
    if name == ".env":
        return True
    if name.startswith(".env.") and not name.endswith(".example"):
        return True
    if name in {"auth.json", "office-bridge-auth.json", "organization-roster.json"}:
        return True
    if ".local." in name or name.endswith(".local"):
        return True
    if name.endswith((".pem", ".key", ".pfx", ".p12")):
        return True
    if any(fnmatch.fnmatch(name, pat) for pat in ("*secret*.json", "*token*.json", "*credentials*.json")):
        return True
    return False


def _is_forbidden_tracked_path(rel_posix: str) -> str | None:
    if _is_secret_filename(rel_posix):
        return "Secret/credential file tracked in Git"
    for prefix in FORBIDDEN_GIT_PREFIXES:
        if rel_posix.startswith(prefix):
            return f"Forbidden runtime/dependency/monolithic directory prefix '{prefix}'"
    if rel_posix.startswith("workspaces/"):
        if rel_posix != "workspaces/README.md" and not rel_posix.startswith("workspaces/sample-project/"):
            return "Workspace file outside allowed workspaces/README.md and workspaces/sample-project/**"
    for glob_pat in FORBIDDEN_GIT_GLOBS:
        if glob_pat == "*.sql" and rel_posix.startswith("tests/fixtures/"):
            continue
        if fnmatch.fnmatch(rel_posix, glob_pat) or fnmatch.fnmatch(Path(rel_posix).name, glob_pat):
            return f"Matches forbidden tracked artifact pattern '{glob_pat}'"
    return None


@dataclass
class PrivateMatcher:
    literal_terms: list[str]
    custom_regexes: list[re.Pattern[str]]
    unsalted_sha256: set[str]
    salted_sha256: list[tuple[str, str]]

    @property
    def active(self) -> bool:
        return bool(self.literal_terms or self.custom_regexes or self.unsalted_sha256 or self.salted_sha256)

    def scan_line(self, line: str) -> tuple[str, str] | None:
        low = line.lower()
        for term in self.literal_terms:
            if term in low:
                return ("PRIV-BLK-001", "Matched external private blocklist term")
        for rx in self.custom_regexes:
            if rx.search(line):
                return ("PRIV-BLK-002", "Matched external private blocklist regex")
        if self.unsalted_sha256 or self.salted_sha256:
            candidates: set[str] = set()
            for raw_tok in TOKENIZER_RE.findall(line):
                cleaned = raw_tok.strip(".,;:()[]{}<>'\"/\\").lower()
                if len(cleaned) >= 3:
                    candidates.add(cleaned)
                    for sub in re.split(r"[:/@\\]", cleaned):
                        if len(sub) >= 3:
                            candidates.add(sub)
                    for part in re.split(r"[:/@\\._-]+", cleaned):
                        if len(part) >= 4:
                            candidates.add(part)
            for cand in candidates:
                if self.unsalted_sha256:
                    digest = hashlib.sha256(cand.encode("utf-8")).hexdigest()
                    if digest in self.unsalted_sha256:
                        return ("PRIV-HASH-001", "Matched SHA-256 private identifier hash")
                for salt, expected_hex in self.salted_sha256:
                    d1 = hashlib.sha256(f"{salt}:{cand}".encode("utf-8")).hexdigest()
                    d2 = hashlib.sha256(f"{salt}{cand}".encode("utf-8")).hexdigest()
                    if d1 == expected_hex or d2 == expected_hex:
                        return ("PRIV-HASH-002", "Matched salted SHA-256 private identifier hash")
        return None


def load_private_matcher(
    blocklist_file: Path | None = None,
    hash_file: Path | None = None,
    *,
    include_builtin_hashes: bool = True,
) -> PrivateMatcher:
    literals: list[str] = []
    regexes: list[re.Pattern[str]] = []
    unsalted: set[str] = set(BUILTIN_PRIVATE_TOKEN_SHA256) if include_builtin_hashes else set()
    salted: list[tuple[str, str]] = []

    blk_path = blocklist_file or (
        Path(os.environ["ALLINAGENT_PRIVATE_BLOCKLIST_FILE"])
        if os.environ.get("ALLINAGENT_PRIVATE_BLOCKLIST_FILE")
        else None
    )
    if blk_path and blk_path.is_file():
        for raw in blk_path.read_text(encoding="utf-8").splitlines():
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            if entry.startswith("regex:"):
                regexes.append(re.compile(entry[6:], re.IGNORECASE))
            elif entry.startswith("sha256:"):
                _parse_hash_entry(entry, unsalted, salted)
            else:
                literals.append(entry.lower())

    h_path = hash_file or (
        Path(os.environ["ALLINAGENT_PRIVATE_HASH_FILE"])
        if os.environ.get("ALLINAGENT_PRIVATE_HASH_FILE")
        else None
    )
    if h_path and h_path.is_file():
        for raw in h_path.read_text(encoding="utf-8").splitlines():
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            _parse_hash_entry(entry, unsalted, salted)

    return PrivateMatcher(literals, regexes, unsalted, salted)


def _parse_hash_entry(entry: str, unsalted: set[str], salted: list[tuple[str, str]]) -> None:
    if re.fullmatch(r"[0-9a-fA-F]{64}", entry):
        unsalted.add(entry.lower())
        return
    if entry.startswith("sha256:"):
        rest = entry[7:]
        if re.fullmatch(r"[0-9a-fA-F]{64}", rest):
            unsalted.add(rest.lower())
        elif ":" in rest:
            salt, hex_digest = rest.rsplit(":", 1)
            if salt and re.fullmatch(r"[0-9a-fA-F]{64}", hex_digest):
                salted.append((salt, hex_digest.lower()))


def _git_ls_files(repo_root: Path) -> list[str] | None:
    if not (repo_root / ".git").exists():
        return None
    proc = subprocess.run(
        ["git", "--no-optional-locks", "-C", str(repo_root), "ls-files", "-z"],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    raw = proc.stdout.decode("utf-8", errors="replace")
    return [p for p in raw.split("\0") if p]


def _git_dirty_entries(repo_root: Path) -> list[str] | None:
    if not (repo_root / ".git").exists():
        return None
    proc = subprocess.run(
        ["git", "--no-optional-locks", "-C", str(repo_root), "status", "--porcelain", "--untracked-files=normal"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        return ["git status --porcelain failed"]
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


def _collect_walk_candidates(repo_root: Path) -> list[str]:
    candidates: list[str] = []
    for cur_root, dirs, files in os.walk(repo_root, topdown=True, followlinks=False):
        cur_path = Path(cur_root)
        rel_parts = cur_path.relative_to(repo_root).parts if cur_path != repo_root else ()
        filtered_dirs: list[str] = []
        for d in sorted(dirs):
            if d in SKIP_WALK_DIRS or "venv" in d.lower() or d.endswith("-worktrees"):
                continue
            if len(rel_parts) >= 1 and rel_parts[0] == "workspaces" and d != "sample-project":
                continue
            if len(rel_parts) >= 1 and rel_parts[0] == "skills" and d in {
                "upstream",
                "staging",
                "reviewed",
                "quarantine",
                "agents",
                "cache",
            }:
                continue
            filtered_dirs.append(d)
        dirs[:] = filtered_dirs

        for fname in sorted(files):
            rel_posix = (cur_path / fname).relative_to(repo_root).as_posix()
            if rel_posix == "sbom.cdx.json":
                continue
            candidates.append(rel_posix)
    return candidates


def _audit_env_example(repo_root: Path, findings: list[Finding]) -> None:
    env_ex = repo_root / ".env.example"
    if not env_ex.is_file():
        findings.append(
            Finding("CFG-001", "HIGH", ".env.example", 0, "Missing required .env.example template", "")
        )
        return
    must_be_blank = {
        "OWNER_TELEGRAM_ID",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_BOT_HANDLE",
        "CUSTOM_API_KEY",
        "POSTGRES_PASSWORD",
    }
    seen_keys: set[str] = set()
    for lineno, line in enumerate(env_ex.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, val = stripped.split("=", 1)
        key = key.strip()
        val = val.strip().strip("'\"")
        seen_keys.add(key)
        if key in must_be_blank and val != "":
            findings.append(
                Finding(
                    "CFG-002",
                    "CRITICAL",
                    ".env.example",
                    lineno,
                    f"{key} in .env.example must be blank (fail-closed default)",
                    f"{key}=[NON_EMPTY]",
                )
            )
    for req_key in sorted(must_be_blank):
        if req_key not in seen_keys:
            findings.append(
                Finding(
                    "CFG-003",
                    "HIGH",
                    ".env.example",
                    0,
                    f"Missing required fail-closed key {req_key}= in .env.example",
                    "",
                )
            )


def _audit_required_governance_files(repo_root: Path, findings: list[Finding]) -> None:
    for req_rel in ("LICENSE", "THIRD-PARTY-NOTICES.md", "LICENSE-INVENTORY.json", "components.lock.json"):
        p = repo_root / req_rel
        if not p.is_file():
            findings.append(
                Finding("GOV-001", "HIGH", req_rel, 0, f"Required governance/supply-chain file '{req_rel}' is missing", "")
            )

    lock_path = repo_root / "components.lock.json"
    if lock_path.is_file():
        try:
            lock_data = json.loads(lock_path.read_text(encoding="utf-8"))
            for cid, cinfo in (lock_data.get("components") or {}).items():
                commit = str(cinfo.get("commit") or cinfo.get("base_commit") or "")
                if not re.fullmatch(r"[0-9a-f]{40}", commit):
                    findings.append(
                        Finding(
                            "GOV-002",
                            "HIGH",
                            "components.lock.json",
                            0,
                            f"Component '{cid}' must be pinned to an exact 40-char commit SHA",
                            commit[:16],
                        )
                    )
        except Exception as exc:
            findings.append(
                Finding("GOV-003", "CRITICAL", "components.lock.json", 0, f"Invalid JSON: {exc}", "")
            )


def audit_repository(
    repo_root: Path,
    *,
    strict_clean_tree: bool = False,
    matcher: PrivateMatcher | None = None,
    require_governance_files: bool = True,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    findings: list[Finding] = []
    private_matcher = matcher if matcher is not None else load_private_matcher()

    tracked = _git_ls_files(repo_root)
    has_git = tracked is not None

    if strict_clean_tree:
        if not has_git:
            findings.append(
                Finding(
                    "GIT-001",
                    "CRITICAL",
                    ".git",
                    0,
                    "--strict-clean-tree requires an initialized Git repository",
                    "",
                )
            )
        else:
            dirty = _git_dirty_entries(repo_root) or []
            for entry in dirty[:25]:
                # Never echo secret filenames' contents; only report status + path
                findings.append(
                    Finding(
                        "GIT-002",
                        "HIGH",
                        entry[3:].strip(),
                        0,
                        "Dirty or untracked working-tree entry under --strict-clean-tree",
                        entry[:2].strip(),
                    )
                )

    candidate_paths: set[str] = set(_collect_walk_candidates(repo_root))
    if tracked is not None:
        for rel_posix in tracked:
            candidate_paths.add(rel_posix)
            reason = _is_forbidden_tracked_path(rel_posix)
            if reason:
                findings.append(
                    Finding("HYG-001", "CRITICAL", rel_posix, 0, reason, "[TRACKED_IN_GIT]")
                )

    if require_governance_files:
        _audit_env_example(repo_root, findings)
        _audit_required_governance_files(repo_root, findings)

    total_bytes = 0
    files_scanned = 0
    secret_files_skipped_unopened = 0

    for rel_posix in sorted(candidate_paths):
        if _is_secret_filename(rel_posix):
            secret_files_skipped_unopened += 1
            if tracked is None:
                # Flag secret files sitting inside untracked source subtrees (other than root .env ignored by git)
                if rel_posix not in {".env"} and not rel_posix.startswith("config/secrets/"):
                    reason = _is_forbidden_tracked_path(rel_posix)
                    if reason:
                        findings.append(
                            Finding("HYG-002", "HIGH", rel_posix, 0, reason, "[UNOPENED_SECRET_FILE]")
                        )
            continue

        fpath = repo_root / rel_posix
        if not fpath.is_file() or fpath.is_symlink():
            continue

        size = fpath.stat().st_size
        total_bytes += size
        if size > MAX_SINGLE_FILE_BYTES:
            findings.append(
                Finding(
                    "SIZE-001",
                    "HIGH",
                    rel_posix,
                    0,
                    f"Single file size {size} B exceeds {MAX_SINGLE_FILE_BYTES} B limit",
                    f"{size} B",
                )
            )

        ext = fpath.suffix.lower()
        if ext in BINARY_EXTENSIONS or size > TEXT_SCAN_MAX_BYTES:
            continue

        raw_bytes = fpath.read_bytes()
        if b"\x00" in raw_bytes[:4096]:
            continue

        text = raw_bytes.decode("utf-8", errors="replace")
        files_scanned += 1

        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule_id, desc, pattern in CONTENT_RULES:
                m = pattern.search(line)
                if m:
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            severity="CRITICAL" if rule_id.startswith(("SEC-", "AUTH-")) else "HIGH",
                            file=rel_posix,
                            line=lineno,
                            description=desc,
                            redacted_snippet=_redact_match(m.group(0)),
                        )
                    )
            if private_matcher.active:
                pm = private_matcher.scan_line(line)
                if pm:
                    findings.append(
                        Finding(
                            rule_id=pm[0],
                            severity="CRITICAL",
                            file=rel_posix,
                            line=lineno,
                            description=pm[1],
                            redacted_snippet="[REDACTED_PRIVATE_IDENTIFIER]",
                        )
                    )

    if total_bytes > MAX_REPO_TOTAL_BYTES:
        findings.append(
            Finding(
                "SIZE-002",
                "HIGH",
                ".",
                0,
                f"Total repository source footprint {total_bytes} B exceeds {MAX_REPO_TOTAL_BYTES} B cap",
                f"{total_bytes} B",
            )
        )

    return {
        "ok": len(findings) == 0,
        "repo_root": str(repo_root),
        "git_initialized": has_git,
        "tracked_files_count": len(tracked) if tracked is not None else None,
        "files_content_scanned": files_scanned,
        "secret_files_skipped_unopened": secret_files_skipped_unopened,
        "total_candidate_bytes": total_bytes,
        "findings_count": len(findings),
        "findings": [asdict(f) for f in findings],
    }


def run_self_test() -> int:
    """Synthetic positive & negative verification suite (zero real identifiers)."""
    assert len(BUILTIN_PRIVATE_TOKEN_SHA256) >= 30, "Built-in SHA-256 private token set is incomplete"
    assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in BUILTIN_PRIVATE_TOKEN_SHA256), (
        "Invalid digest format in BUILTIN_PRIVATE_TOKEN_SHA256"
    )
    default_matcher = load_private_matcher()
    assert default_matcher.active and BUILTIN_PRIVATE_TOKEN_SHA256.issubset(default_matcher.unsalted_sha256)
    with tempfile.TemporaryDirectory(prefix="allinagent-audit-selftest-") as tmp:
        root = Path(tmp) / "dirty_repo"
        root.mkdir(parents=True)

        # Build synthetic test tokens dynamically at runtime
        fake_sk = "sk-" + ("A1b2C3d4" * 4)
        fake_bot = "1234567890:" + ("Z9y8X7w6V5u4" * 3)
        fake_ob = "ob_" + "tok_" + ("f0e1d2c3" * 2)
        fake_st = "st_" + "tok_" + ("a9b8c7d6" * 2)
        fake_pcp = "pcp_" + ("11223344" * 2)
        fake_pem = "-----BEGIN " + "RSA PRIVATE KEY-----"
        fake_win_user = "C:" + "\\" + "Users" + "\\" + "SyntheticAccount" + "\\" + "config.json"
        fake_legacy_single = "D:" + "\\" + "AI-Agent-" + "Platform" + "\\" + "server.js"
        fake_legacy_double = "D:" + "\\\\" + "AI-Agent-" + "Platform" + "\\\\" + "server.js"
        fake_tg_id = "1" + ("0" * 9)

        synthetic_priv_plain = "synthetic-internal-corp-host.invalid"
        synthetic_salted_plain = "synthetic-owner-handle-xyz987"
        salt = "selftest_salt_01"
        unsalted_hash = hashlib.sha256(synthetic_priv_plain.encode("utf-8")).hexdigest()
        salted_hash = hashlib.sha256(f"{salt}:{synthetic_salted_plain}".encode("utf-8")).hexdigest()

        hash_file = Path(tmp) / "hashes.txt"
        hash_file.write_text(f"sha256:{unsalted_hash}\nsha256:{salt}:{salted_hash}\n", encoding="utf-8")

        (root / ".env.example").write_text(
            f"OWNER_TELEGRAM_ID={fake_tg_id}\nTELEGRAM_BOT_TOKEN=\nTELEGRAM_BOT_HANDLE=\nCUSTOM_API_KEY=\nPOSTGRES_PASSWORD=\n",
            encoding="utf-8",
        )
        (root / "leak_sample.py").write_text(
            "\n".join([
                f"k1 = '{fake_sk}'",
                f"k2 = '{fake_bot}'",
                f"k3 = '{fake_ob}'",
                f"k4 = '{fake_st}'",
                f"k5 = '{fake_pcp}'",
                f"k6 = '{fake_pem}'",
                f"p1 = r'{fake_win_user}'",
                f"p2 = r'{fake_legacy_single}'",
                f"p3 = '{fake_legacy_double}'",
                f"h1 = '{synthetic_priv_plain}'",
                f"h2 = '{synthetic_salted_plain}'",
            ]) + "\n",
            encoding="utf-8",
        )

        matcher = load_private_matcher(hash_file=hash_file)
        dirty_report = audit_repository(root, strict_clean_tree=True, matcher=matcher)
        triggered_rules = {f["rule_id"] for f in dirty_report["findings"]}

        expected_rules = {
            "GIT-001",
            "CFG-002",
            "GOV-001",
            "SEC-001",
            "SEC-002",
            "SEC-005",
            "SEC-006",
            "PORT-001",
            "PORT-002",
            "AUTH-001",
            "PRIV-HASH-001",
            "PRIV-HASH-002",
        }
        missing = expected_rules - triggered_rules
        assert not missing, f"Self-test missed expected rules: {sorted(missing)}"

        # Verify redaction never echoes synthetic secrets in output JSON
        serialized = json.dumps(dirty_report)
        assert fake_sk not in serialized, "Full API key leaked into report!"
        assert synthetic_priv_plain not in serialized, "Hashed private identifier leaked into report!"

        # Build a clean mini Git repository and verify 100% PASS including --strict-clean-tree
        clean = Path(tmp) / "clean_repo"
        clean.mkdir(parents=True)
        (clean / ".env.example").write_text(
            "OWNER_TELEGRAM_ID=\nTELEGRAM_BOT_TOKEN=\nTELEGRAM_BOT_HANDLE=\nCUSTOM_API_KEY=\nPOSTGRES_PASSWORD=\n",
            encoding="utf-8",
        )
        (clean / "LICENSE").write_text("MIT License\n", encoding="utf-8")
        (clean / "THIRD-PARTY-NOTICES.md").write_text("# Notices\n", encoding="utf-8")
        (clean / "LICENSE-INVENTORY.json").write_text("{}\n", encoding="utf-8")
        (clean / "components.lock.json").write_text(
            json.dumps({"components": {"vulnclaw": {"commit": "0b34878f84b089b21fcf85ecd445315f14df0672"}}}) + "\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "init", "-q", str(clean)], check=True)
        subprocess.run(["git", "-C", str(clean), "config", "user.email", "ci@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(clean), "config", "user.name", "CI"], check=True)
        subprocess.run(["git", "-C", str(clean), "add", "."], check=True)
        subprocess.run(["git", "-C", str(clean), "commit", "-q", "-m", "init"], check=True)

        clean_report = audit_repository(clean, strict_clean_tree=True, matcher=matcher)
        assert clean_report["ok"] is True, f"Clean repo failed self-test: {clean_report}"

        # Force-add a forbidden artifact in Git and verify `git ls-files` catches HYG-001
        (clean / "office-bridge-auth.json").write_text('{"token":"redacted"}\n', encoding="utf-8")
        subprocess.run(["git", "-C", str(clean), "add", "-f", "office-bridge-auth.json"], check=True)
        hyg_report = audit_repository(clean, strict_clean_tree=False, matcher=matcher)
        hyg_rules = {f["rule_id"] for f in hyg_report["findings"]}
        assert "HYG-001" in hyg_rules, f"git ls-files secret detection failed: {hyg_report}"
        assert hyg_report["secret_files_skipped_unopened"] >= 1

    print(
        json.dumps(
            {
                "self_test": "PASSED",
                "verified_rules": sorted(expected_rules | {"HYG-001"}),
                "redaction_verified": True,
                "strict_clean_tree_verified": True,
            },
            indent=2,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit ALLINAGENT repository for safe public GitHub release.")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repository root directory to audit.",
    )
    parser.add_argument(
        "--strict-clean-tree",
        action="store_true",
        help="Require an initialized Git repository with zero uncommitted or untracked files.",
    )
    parser.add_argument(
        "--blocklist-file",
        type=Path,
        default=None,
        help="Optional external private blocklist file (or set ALLINAGENT_PRIVATE_BLOCKLIST_FILE).",
    )
    parser.add_argument(
        "--hash-blocklist-file",
        type=Path,
        default=None,
        help="Optional SHA-256 / salted-SHA-256 hash blocklist file (or set ALLINAGENT_PRIVATE_HASH_FILE).",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in synthetic security & redaction self-test suite and exit.",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    matcher = load_private_matcher(args.blocklist_file, args.hash_blocklist_file)
    report = audit_repository(
        args.root,
        strict_clean_tree=args.strict_clean_tree,
        matcher=matcher,
    )
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
