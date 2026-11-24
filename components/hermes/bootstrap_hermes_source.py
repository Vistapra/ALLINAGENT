#!/usr/bin/env python3
"""Deterministic Hermes Agent upstream checkout, idempotent patch applicator, and stamp writer.

Fetches `NousResearch/hermes-agent` at exact commit `eb49b8920a25ffa7bb2fadf548fe819221ca79d7`,
applies `patches/hermes-agent/0001-error-classifier-integrator.patch` idempotently, writes
canonical `install-stamp.json` (`schemaVersion: 2`, `baseVersion: "0.23.3"`), and strips
non-runtime directories plus `.git` bloat so `hermes --version` and all 11 worker profiles run
from a single lean shared runtime (< 75 MiB).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import py_compile
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

UPSTREAM_REPO = "https://github.com/NousResearch/hermes-agent.git"
PINNED_COMMIT = "eb49b8920a25ffa7bb2fadf548fe819221ca79d7"
PINNED_COMMIT_DATE = 1795460746  # 2026-11-23T19:05:46Z
PINNED_BASE_VERSION = "0.23.3"
PINNED_DISTANCE = 100
STAMP_SCHEMA_VERSION = 2

PATCH_SENTINEL = '"model_not_available_for_integrator",'
PATCH_ANCHOR = '"no such model", "unknown model", "unsupported model", "no endpoints found that support tool use",'

NON_RUNTIME_BLOAT_DIRS = (
    "apps/desktop",
    "website",
    "tests",
    "evals",
    "nix",
    ".github",
)


def _default_allinagent_root() -> Path:
    env_root = os.environ.get("ALLINAGENT_ROOT", "").strip()
    if env_root:
        return Path(env_root).expanduser().resolve()
    return Path(__file__).resolve().parents[2]


def _default_patch_path() -> Path:
    env_patch = os.environ.get("HERMES_PATCH_PATH", "").strip()
    if env_patch:
        return Path(env_patch).expanduser().resolve()
    return _default_allinagent_root() / "patches" / "hermes-agent" / "0001-error-classifier-integrator.patch"


def _rmtree_force(target: Path) -> None:
    if not target.exists() and not target.is_symlink():
        return

    def _onerror(func: Any, path_str: str, _exc_info: Any) -> None:
        try:
            os.chmod(path_str, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            func(path_str)
        except OSError:
            pass

    if target.is_symlink() or target.is_file():
        target.unlink(missing_ok=True)
    else:
        shutil.rmtree(target, onerror=_onerror)


def _run_git(args: list[str], cwd: Path, *, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed (exit {proc.returncode}): {(proc.stderr or proc.stdout).strip()}"
        )
    return proc


def _is_already_stamped_at_commit(dest: Path, commit: str) -> bool:
    stamp_file = dest / "install-stamp.json"
    classifier = dest / "agent" / "error_classifier.py"
    if not (stamp_file.is_file() and classifier.is_file()):
        return False
    try:
        stamp = json.loads(stamp_file.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return False
    return str(stamp.get("commit") or "").strip() == commit


def fetch_pinned_checkout(dest: Path, repo_url: str, commit: str, *, force: bool = False) -> None:
    if not force and _is_already_stamped_at_commit(dest, commit):
        print(f"[bootstrap-hermes] Existing stamped tree at {dest} already matches {commit[:12]}; skipping fetch.")
        return

    dest.mkdir(parents=True, exist_ok=True)
    git_dir = dest / ".git"
    if not git_dir.exists():
        # Clean partial/unstamped files before initializing fresh shallow fetch
        for child in list(dest.iterdir()):
            _rmtree_force(child)
        _run_git(["init"], cwd=dest)

    remotes = _run_git(["remote"], cwd=dest, check=False).stdout.splitlines()
    if "origin" in [r.strip() for r in remotes]:
        _run_git(["remote", "set-url", "origin", repo_url], cwd=dest)
    else:
        _run_git(["remote", "add", "origin", repo_url], cwd=dest)

    head_proc = _run_git(["rev-parse", "HEAD"], cwd=dest, check=False)
    current_head = (head_proc.stdout or "").strip()
    if current_head != commit:
        print(f"[bootstrap-hermes] Shallow-fetching {repo_url} @ {commit}...")
        fetch_proc = _run_git(
            ["fetch", "--depth", "1", "--no-tags", "origin", commit],
            cwd=dest,
            check=False,
            timeout=600,
        )
        if fetch_proc.returncode != 0:
            print("[bootstrap-hermes] Shallow SHA fetch unsupported by mirror; falling back to branch fetch...")
            _run_git(["fetch", "--no-tags", "origin", "main"], cwd=dest, timeout=600)
            _run_git(["checkout", "--force", commit], cwd=dest)
        else:
            _run_git(["checkout", "--force", "FETCH_HEAD"], cwd=dest)

    verified = (_run_git(["rev-parse", "HEAD"], cwd=dest).stdout or "").strip()
    if verified != commit:
        raise RuntimeError(f"Expected HEAD {commit}, got {verified!r}")
    print(f"[bootstrap-hermes] Verified exact upstream HEAD {verified}.")


def apply_error_classifier_patch(dest: Path, patch_file: Path) -> bool:
    """Apply `0001-error-classifier-integrator.patch` idempotently.

    Returns True if the file was modified during this call, False if already applied.
    """
    target_file = dest / "agent" / "error_classifier.py"
    if not target_file.is_file():
        raise FileNotFoundError(f"Target file missing: {target_file}")
    if not patch_file.is_file():
        raise FileNotFoundError(f"Patch file missing: {patch_file}")

    current_text = target_file.read_text(encoding="utf-8")
    if PATCH_SENTINEL in current_text:
        py_compile.compile(str(target_file), doraise=True)
        print("[bootstrap-hermes] Patch 0001-error-classifier-integrator.patch already applied (idempotent).")
        return False

    applied_via_git = False
    if shutil.which("git") is not None:
        rev_check = _run_git(
            ["apply", "--reverse", "--check", "--ignore-space-change", str(patch_file)],
            cwd=dest,
            check=False,
        )
        if rev_check.returncode == 0:
            py_compile.compile(str(target_file), doraise=True)
            print("[bootstrap-hermes] Patch verified via reverse git-apply check (idempotent).")
            return False

        fwd_check = _run_git(
            ["apply", "--check", "--ignore-space-change", str(patch_file)],
            cwd=dest,
            check=False,
        )
        if fwd_check.returncode == 0:
            _run_git(["apply", "--ignore-space-change", str(patch_file)], cwd=dest, check=True)
            applied_via_git = True

    if not applied_via_git:
        if PATCH_ANCHOR not in current_text:
            raise RuntimeError(
                f"Cannot apply patch to {target_file}: anchor pattern not found in _MODEL_NOT_FOUND_PATTERNS."
            )
        replacement = f"{PATCH_ANCHOR}\n    {PATCH_SENTINEL}"
        updated_text = current_text.replace(PATCH_ANCHOR, replacement, 1)
        target_file.write_text(updated_text.replace("\r\n", "\n"), encoding="utf-8", newline="\n")

    verified_text = target_file.read_text(encoding="utf-8")
    if PATCH_SENTINEL not in verified_text:
        raise RuntimeError("Post-patch verification failed: sentinel missing from agent/error_classifier.py")

    py_compile.compile(str(target_file), doraise=True)
    print("[bootstrap-hermes] Applied and syntax-verified 0001-error-classifier-integrator.patch.")
    return True


def write_hermes_install_stamp(
    dest: Path,
    *,
    commit: str = PINNED_COMMIT,
    base_version: str = PINNED_BASE_VERSION,
    distance: int = PINNED_DISTANCE,
    commit_date: int = PINNED_COMMIT_DATE,
    branch: str = "main",
    source: str = "docker",
    distribution: str | None = "docker",
    update_mechanism: str = "external",
) -> Path:
    """Write canonical schema v2 `install-stamp.json` consumed by `hermes_cli/version_info.py`."""
    if not commit or len(commit) != 40 or set(commit) == {"0"}:
        raise ValueError(f"Invalid 40-char commit SHA for install-stamp.json: {commit!r}")
    if update_mechanism not in ("self", "app-installer", "electron-updater", "external", "microsoft-store"):
        raise ValueError(f"Unsupported updateMechanism: {update_mechanism!r}")

    dist_val: str | None = distribution if distribution in ("docker", "nix", "desktop-app") else None
    display_version = f"{base_version}+{distance}" if distance and distance > 0 else base_version

    stamp: dict[str, Any] = {
        "schemaVersion": STAMP_SCHEMA_VERSION,
        "commit": commit,
        "commitDate": int(commit_date),
        "branch": branch,
        "builtAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "dirty": False,
        "source": source,
        "distribution": dist_val,
        "updateMechanism": update_mechanism,
        "baseVersion": base_version,
        "displayVersion": display_version,
        "distance": int(distance) if distance is not None else 0,
        "payload": "bootstrap",
        "tag": None,
    }

    stamp_path = dest / "install-stamp.json"
    stamp_path.write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(
        f"[bootstrap-hermes] Wrote {stamp_path} "
        f"(baseVersion={base_version}, displayVersion={display_version}, commit={commit[:12]})."
    )
    return stamp_path


def strip_non_runtime_bloat(dest: Path, *, strip_git: bool = True, strip_nonruntime: bool = True) -> list[str]:
    removed: list[str] = []
    if strip_nonruntime:
        for rel in NON_RUNTIME_BLOAT_DIRS:
            candidate = dest / rel
            if candidate.exists() or candidate.is_symlink():
                _rmtree_force(candidate)
                removed.append(rel)
    if strip_git:
        git_dir = dest / ".git"
        if git_dir.exists() or git_dir.is_symlink():
            _rmtree_force(git_dir)
            removed.append(".git")
    if removed:
        print(f"[bootstrap-hermes] Stripped non-runtime bloat: {', '.join(removed)}")
    return removed


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bootstrap pinned Hermes Agent source, patch, and install stamp.")
    parser.add_argument(
        "--dest",
        default=os.environ.get("HERMES_SOURCE_DIR", "/opt/hermes-agent"),
        help="Destination directory for Hermes Agent runtime source (default: /opt/hermes-agent).",
    )
    parser.add_argument(
        "--repo",
        default=os.environ.get("HERMES_GIT_URL", UPSTREAM_REPO),
        help=f"Upstream Git URL (default: {UPSTREAM_REPO}).",
    )
    parser.add_argument(
        "--commit",
        default=os.environ.get("HERMES_COMMIT", PINNED_COMMIT),
        help=f"Exact 40-char commit SHA to checkout (default: {PINNED_COMMIT}).",
    )
    parser.add_argument(
        "--base-version",
        default=os.environ.get("HERMES_BASE_VERSION", PINNED_BASE_VERSION),
        help=f"Semantic baseVersion recorded in install-stamp.json (default: {PINNED_BASE_VERSION}).",
    )
    parser.add_argument(
        "--distance",
        type=int,
        default=int(os.environ.get("HERMES_COMMIT_DISTANCE", str(PINNED_DISTANCE))),
        help=f"Commit distance from baseVersion tag (default: {PINNED_DISTANCE}).",
    )
    parser.add_argument(
        "--commit-date",
        type=int,
        default=int(os.environ.get("HERMES_COMMIT_DATE", str(PINNED_COMMIT_DATE))),
        help=f"Unix epoch timestamp for pinned commit (default: {PINNED_COMMIT_DATE}).",
    )
    parser.add_argument(
        "--patch",
        type=Path,
        default=_default_patch_path(),
        help="Path to 0001-error-classifier-integrator.patch.",
    )
    parser.add_argument(
        "--distribution",
        choices=("docker", "nix", "desktop-app", "none"),
        default="docker",
        help="Package distribution recorded in install-stamp.json (default: docker).",
    )
    parser.add_argument(
        "--update-mechanism",
        choices=("external", "self"),
        default="external",
        help="Update steward recorded in install-stamp.json (default: external).",
    )
    parser.add_argument(
        "--local-only",
        action="store_true",
        help="Apply patch and write install-stamp.json on an already populated --dest without git network fetch.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force fresh git fetch even if install-stamp.json already matches --commit.",
    )
    parser.add_argument(
        "--keep-git",
        action="store_true",
        help="Retain .git directory instead of stripping ~551 MiB git object bloat.",
    )
    parser.add_argument(
        "--keep-nonruntime",
        action="store_true",
        help="Retain non-runtime directories (apps/desktop, website, tests, evals, nix).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    dest = Path(args.dest).expanduser().resolve()
    patch_file = Path(args.patch).expanduser().resolve()

    if not args.local_only:
        fetch_pinned_checkout(dest, args.repo, args.commit, force=args.force)

    apply_error_classifier_patch(dest, patch_file)
    write_hermes_install_stamp(
        dest,
        commit=args.commit,
        base_version=args.base_version,
        distance=args.distance,
        commit_date=args.commit_date,
        source="docker" if args.distribution == "docker" else "local",
        distribution=None if args.distribution == "none" else args.distribution,
        update_mechanism=args.update_mechanism,
    )
    strip_non_runtime_bloat(
        dest,
        strip_git=not args.keep_git,
        strip_nonruntime=not args.keep_nonruntime,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
