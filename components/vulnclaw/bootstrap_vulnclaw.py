#!/usr/bin/env python3
"""Reproducible Bootstrapper & Supply-Chain Verifier for VulnClaw v0.4.1 (Phase 10).

Responsibilities:
1. Shallow-clones `https://github.com/Netw0rkNoob/VulnClaw.git` at exact commit
   `0b34878f84b089b21fcf85ecd445315f14df0672` (`v0.4.1`).
2. Verifies MIT `LICENSE`, `pyproject.toml` version/license metadata, and exact
   LF-normalized SHA-256 checksums of all core entrypoints and static-scan modules.
3. Prunes non-defensive upstream subtrees (Rust `tui/`, Vite `frontend/`, `assets/`,
   `tests/`, `demo/`, `.github/`) when requested.
4. Installs ONLY the minimal pure-Python defensive core dependencies from
   `requirements-defensive.txt` plus `vulnclaw` with `--no-deps`, completely excluding
   `[kb]` (`chromadb`), `[rerank]` (`sentence-transformers`/PyTorch), `[traffic]`
   (`mitmproxy`, `playwright`), `[web]`, `[pdf]`, and offensive sandbox libraries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

UPSTREAM_REPO_URL = "https://github.com/Netw0rkNoob/VulnClaw.git"
PINNED_COMMIT_SHA = "0b34878f84b089b21fcf85ecd445315f14df0672"
PINNED_VERSION = "0.4.1"
EXPECTED_LICENSE_SPDX = "MIT"

# Exact Git blob / LF-normalized SHA-256 checksums for VulnClaw v0.4.1
# (0b34878f84b089b21fcf85ecd445315f14df0672). Normalizing CRLF -> LF ensures
# identical verification across Linux containers and Windows core.autocrlf checkouts.
EXPECTED_LF_SHA256: dict[str, str] = {
    "LICENSE": "798df5f8d0f84b2e5805c53b2ecdaa75e182fee606199e996cfb1bd98e75f84b",
    "pyproject.toml": "23ef5239db489cdeaaa2ec5822ddaee6983af7ef84e26df67bc4f281fc2d8791",
    "vulnclaw/__init__.py": "66c0da0603d198818067bff0bb4c18d2604930d126cfae347e3f3b20c7cc5e71",
    "vulnclaw/cli/main.py": "8c1a5661d3df1cd2c4f28eaeb87dab1e588fffbd7ff44973d1b716a9cec8b3e9",
    "vulnclaw/config/schema.py": "45c6752ff912287985f186b01977f86e74c13ff1a7035a786784ff241a9796ee",
    "vulnclaw/codescan/scanner.py": "49162b2f455da4c5fa1d1b627a30aa12aff7274b3b5b6fc00d32369f31c8d6db",
    "vulnclaw/codescan/rules.py": "f7715a5dfb46bed9fbcc24d10c6794d437fffecada7c167fa7320c743e91a080",
    "vulnclaw/codescan/report.py": "c079faeafce72399bc6c170611cdd01812bd44b07cc273d93d7ea0a574d073fd",
}

EXPECTED_DEFENSIVE_PACKAGES: tuple[str, ...] = (
    "pydantic>=2.0",
    "pydantic-settings>=2.0",
    "pyyaml>=6.0",
    "httpx>=0.27",
    "openai>=1.66",
    "typer>=0.12",
    "rich>=13.7",
    "toml>=0.10",
    "jsonschema>=4.20",
)

FORBIDDEN_HEAVY_MODULES: tuple[str, ...] = (
    "chromadb",
    "sentence_transformers",
    "torch",
    "mitmproxy",
    "playwright",
    "reportlab",
)

PRUNABLE_NON_DEFENSIVE_TREES: tuple[str, ...] = (
    "frontend",
    "tui",
    "assets",
    "tests",
    "demo",
    ".github",
)

COMPONENT_DIR = Path(__file__).resolve().parent
DEFAULT_REQUIREMENTS_PATH = COMPONENT_DIR / "requirements-defensive.txt"
DEFAULT_DEFENSIVE_CONFIG_TEMPLATE = COMPONENT_DIR / "vulnclaw.defensive.yaml"


class BootstrapVerificationError(RuntimeError):
    """Raised when upstream commit, license, or file checksum verification fails."""


def _default_allinagent_root() -> Path:
    env_root = os.environ.get("ALLINAGENT_ROOT", "").strip()
    if env_root:
        return Path(env_root).resolve()
    return COMPONENT_DIR.parent.parent.resolve()


def compute_lf_sha256(file_path: Path) -> str:
    """Compute SHA-256 over LF-normalized file bytes for cross-OS determinism."""
    raw = file_path.read_bytes()
    normalized = raw.replace(b"\r\n", b"\n")
    return hashlib.sha256(normalized).hexdigest()


def _rmtree_force(target: Path) -> None:
    if not target.exists():
        return

    def _onerror(func: Any, path_str: str, _exc_info: Any) -> None:
        try:
            os.chmod(path_str, stat.S_IWRITE | stat.S_IREAD)
            func(path_str)
        except OSError:
            pass

    shutil.rmtree(target, onerror=_onerror)


def _run_cmd(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout_sec: int = 300,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_sec,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[-800:]
        raise RuntimeError(f"Command {args!r} exited with code {proc.returncode}: {detail}")
    return proc


def verify_requirements_manifest(req_path: Path = DEFAULT_REQUIREMENTS_PATH) -> list[str]:
    """Ensure requirements-defensive.txt strictly contains only approved lightweight packages."""
    if not req_path.is_file():
        raise BootstrapVerificationError(f"Missing defensive requirements file: {req_path}")
    specs: list[str] = []
    for raw_line in req_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        lower = line.lower().replace("-", "_")
        for forbidden in FORBIDDEN_HEAVY_MODULES:
            if lower.startswith(forbidden):
                raise BootstrapVerificationError(
                    f"Forbidden heavy dependency {line!r} found in {req_path}"
                )
        specs.append(line)
    if tuple(specs) != EXPECTED_DEFENSIVE_PACKAGES:
        raise BootstrapVerificationError(
            f"Defensive requirements mismatch. Expected {list(EXPECTED_DEFENSIVE_PACKAGES)}, got {specs}"
        )
    return specs


def clone_pinned_vulnclaw(
    target_dir: Path,
    *,
    repo_url: str = UPSTREAM_REPO_URL,
    commit_sha: str = PINNED_COMMIT_SHA,
    force_reclone: bool = False,
) -> dict[str, Any]:
    """Reproducibly shallow-fetch exact upstream commit into target_dir."""
    if target_dir.exists():
        if force_reclone:
            _rmtree_force(target_dir)
        elif (target_dir / "vulnclaw" / "__init__.py").is_file():
            # Existing checkout present; caller will run full checksum verification.
            return {"action": "reused_existing", "target_dir": str(target_dir)}
        elif any(target_dir.iterdir()):
            raise BootstrapVerificationError(
                f"Target directory {target_dir} is non-empty and not a valid VulnClaw tree "
                "(pass --force-reclone to replace)."
            )

    target_dir.mkdir(parents=True, exist_ok=True)
    git_env = dict(os.environ)
    git_env["GIT_TERMINAL_PROMPT"] = "0"

    _run_cmd(["git", "init", "--quiet"], cwd=target_dir, env=git_env)
    _run_cmd(["git", "remote", "add", "origin", repo_url], cwd=target_dir, env=git_env)
    _run_cmd(
        ["git", "fetch", "--quiet", "--depth", "1", "origin", commit_sha],
        cwd=target_dir,
        timeout_sec=300,
        env=git_env,
    )
    _run_cmd(
        ["git", "-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", "FETCH_HEAD"],
        cwd=target_dir,
        env=git_env,
    )
    head = _run_cmd(["git", "rev-parse", "HEAD"], cwd=target_dir, env=git_env).stdout.strip()
    if head != commit_sha:
        raise BootstrapVerificationError(
            f"Git HEAD mismatch after checkout: expected {commit_sha}, got {head}"
        )
    return {"action": "cloned_shallow", "commit": head, "target_dir": str(target_dir)}


def verify_vulnclaw_checkout(target_dir: Path) -> dict[str, Any]:
    """Verify MIT license, version metadata, optional git HEAD, and all 8 file SHA-256s."""
    if not target_dir.is_dir():
        raise BootstrapVerificationError(f"VulnClaw checkout directory does not exist: {target_dir}")

    git_dir = target_dir / ".git"
    verified_git_head: str | None = None
    if git_dir.is_dir():
        head = _run_cmd(
            ["git", "--no-optional-locks", "rev-parse", "HEAD"],
            cwd=target_dir,
        ).stdout.strip()
        if head != PINNED_COMMIT_SHA:
            raise BootstrapVerificationError(
                f"VulnClaw git HEAD mismatch: expected {PINNED_COMMIT_SHA}, got {head}"
            )
        verified_git_head = head

    # 1. Verify LICENSE exists and is MIT
    license_path = target_dir / "LICENSE"
    if not license_path.is_file():
        raise BootstrapVerificationError(f"Missing LICENSE file in {target_dir}")
    license_text = license_path.read_text(encoding="utf-8", errors="strict")
    if "MIT License" not in license_text or "Permission is hereby granted, free of charge" not in license_text:
        raise BootstrapVerificationError("LICENSE file does not contain expected MIT License text")

    # 2. Verify pyproject.toml declares vulnclaw v0.4.1 under MIT
    pyproject_path = target_dir / "pyproject.toml"
    if not pyproject_path.is_file():
        raise BootstrapVerificationError(f"Missing pyproject.toml in {target_dir}")
    pyproject_text = pyproject_path.read_text(encoding="utf-8", errors="strict")
    if f'version = "{PINNED_VERSION}"' not in pyproject_text:
        raise BootstrapVerificationError(
            f"pyproject.toml does not match pinned version {PINNED_VERSION}"
        )
    if 'license = { text = "MIT" }' not in pyproject_text:
        raise BootstrapVerificationError("pyproject.toml does not declare MIT license")

    # 3. Verify all 8 LF-normalized SHA-256 entrypoint and scanner checksums
    verified_checksums: dict[str, str] = {}
    for rel_path, expected_sha in EXPECTED_LF_SHA256.items():
        fpath = target_dir / rel_path
        if not fpath.is_file():
            raise BootstrapVerificationError(f"Expected upstream file missing: {rel_path}")
        actual_sha = compute_lf_sha256(fpath)
        if actual_sha != expected_sha:
            raise BootstrapVerificationError(
                f"SHA-256 mismatch for {rel_path}: expected {expected_sha}, got {actual_sha}"
            )
        verified_checksums[rel_path] = actual_sha

    return {
        "verified": True,
        "upstream_repo": UPSTREAM_REPO_URL,
        "pinned_commit": PINNED_COMMIT_SHA,
        "git_head_checked": verified_git_head,
        "version": PINNED_VERSION,
        "license": EXPECTED_LICENSE_SPDX,
        "checksums_lf_sha256": verified_checksums,
    }


def prune_non_defensive_subtrees(target_dir: Path, *, drop_git_metadata: bool = True) -> list[str]:
    """Remove Rust TUI, Vite frontend, tests, demo, and screenshots from runtime image."""
    removed: list[str] = []
    for rel in PRUNABLE_NON_DEFENSIVE_TREES:
        sub = target_dir / rel
        if sub.exists():
            _rmtree_force(sub)
            removed.append(rel)
    if drop_git_metadata and (target_dir / ".git").exists():
        _rmtree_force(target_dir / ".git")
        removed.append(".git")
    return removed


def _resolve_venv_python(venv_dir: Path | None) -> Path:
    if venv_dir is None:
        return Path(sys.executable).resolve()
    if not venv_dir.exists():
        _run_cmd([sys.executable, "-m", "venv", str(venv_dir)])
    if os.name == "nt":
        cand = venv_dir / "Scripts" / "python.exe"
    else:
        cand = venv_dir / "bin" / "python"
    if not cand.is_file():
        raise BootstrapVerificationError(f"Virtualenv Python binary not found at {cand}")
    return cand


def install_defensive_dependencies(
    target_dir: Path,
    *,
    python_bin: Path,
    req_path: Path = DEFAULT_REQUIREMENTS_PATH,
    use_uv: bool = False,
) -> dict[str, Any]:
    """Install ONLY requirements-defensive.txt + vulnclaw (--no-deps), then verify no bloat."""
    specs = verify_requirements_manifest(req_path)

    if use_uv and shutil.which("uv"):
        _run_cmd(
            ["uv", "pip", "install", "--python", str(python_bin), "--no-cache", "-r", str(req_path)],
            timeout_sec=600,
        )
    else:
        _run_cmd(
            [
                str(python_bin),
                "-m",
                "pip",
                "install",
                "--no-cache-dir",
                "--disable-pip-version-check",
                "-r",
                str(req_path),
            ],
            timeout_sec=600,
        )

    # Link vulnclaw source tree via site-packages .pth so zero extra wheel/build-backend
    # dependencies (hatchling, mcp, lxml, pycryptodome, beautifulsoup4) are ever pulled.
    site_pkg_raw = _run_cmd(
        [
            str(python_bin),
            "-c",
            "import site; paths = [p for p in site.getsitepackages() if 'site-packages' in p] or site.getsitepackages(); print(paths[0])",
        ]
    ).stdout.strip()
    site_pkg = Path(site_pkg_raw)
    pth_file = site_pkg / "vulnclaw_defensive.pth"
    pth_file.write_text(f"{target_dir.resolve()}\n", encoding="utf-8")

    # Verify vulnclaw imports cleanly AND none of the forbidden heavy modules exist
    audit_code = (
        "import importlib.util, json, vulnclaw; "
        "from vulnclaw.codescan.scanner import scan_code; "
        f"forbidden = {list(FORBIDDEN_HEAVY_MODULES)!r}; "
        "present = [m for m in forbidden if importlib.util.find_spec(m) is not None]; "
        "print(json.dumps({'vulnclaw_version': vulnclaw.__version__, 'forbidden_present': present}))"
    )
    audit_out = json.loads(_run_cmd([str(python_bin), "-c", audit_code]).stdout.strip())
    if audit_out.get("vulnclaw_version") != PINNED_VERSION:
        raise BootstrapVerificationError(
            f"Installed vulnclaw version mismatch: {audit_out.get('vulnclaw_version')}"
        )
    if audit_out.get("forbidden_present"):
        raise BootstrapVerificationError(
            f"Forbidden heavy packages detected in target environment: {audit_out['forbidden_present']}"
        )

    return {
        "installed_requirements": specs,
        "pth_link": str(pth_file),
        "vulnclaw_version": audit_out["vulnclaw_version"],
        "forbidden_heavy_modules_present": audit_out["forbidden_present"],
    }


def seed_defensive_config(config_dir: Path) -> Path:
    """Write isolated zero-secret defensive config.yaml into config_dir."""
    config_dir.mkdir(parents=True, exist_ok=True)
    dest = config_dir / "config.yaml"
    shutil.copyfile(DEFAULT_DEFENSIVE_CONFIG_TEMPLATE, dest)
    return dest


def build_arg_parser() -> argparse.ArgumentParser:
    default_root = _default_allinagent_root()
    default_src = Path(
        os.environ.get("VULNCLAW_SOURCE_DIR", "")
        or str(default_root / "runtime" / "vulnclaw-src")
    )
    parser = argparse.ArgumentParser(
        description="Reproducibly bootstrap & verify VulnClaw v0.4.1 defensive core."
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=default_src,
        help="Destination directory for pinned VulnClaw source checkout.",
    )
    parser.add_argument(
        "--venv-dir",
        type=Path,
        default=None,
        help="Optional Python virtualenv directory (omit to install into current Python).",
    )
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=None,
        help="Optional isolated VULNCLAW_CONFIG_DIR to seed with vulnclaw.defensive.yaml.",
    )
    parser.add_argument(
        "--requirements",
        type=Path,
        default=DEFAULT_REQUIREMENTS_PATH,
        help="Path to requirements-defensive.txt.",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify existing checkout checksums, MIT license, and manifest without cloning or installing.",
    )
    parser.add_argument(
        "--skip-pip",
        action="store_true",
        help="Clone and verify source checksums without installing pip dependencies.",
    )
    parser.add_argument(
        "--prune",
        action="store_true",
        default=False,
        help="Remove Rust TUI, Vite frontend, tests, assets, and .git after checksum verification.",
    )
    parser.add_argument(
        "--force-reclone",
        action="store_true",
        help="Delete existing --target-dir before shallow cloning.",
    )
    parser.add_argument(
        "--use-uv",
        action="store_true",
        help="Prefer `uv pip install` when uv is available on PATH.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    target_dir = args.target_dir.resolve()
    req_path = args.requirements.resolve()

    manifest_specs = verify_requirements_manifest(req_path)

    if args.verify_only:
        verification = verify_vulnclaw_checkout(target_dir)
        summary = {
            "ok": True,
            "mode": "verify_only",
            "requirements_verified": manifest_specs,
            "verification": verification,
        }
        print(json.dumps(summary, indent=2))
        return 0

    clone_info = clone_pinned_vulnclaw(
        target_dir,
        force_reclone=args.force_reclone,
    )
    verification = verify_vulnclaw_checkout(target_dir)

    pruned: list[str] = []
    if args.prune:
        pruned = prune_non_defensive_subtrees(target_dir, drop_git_metadata=True)

    install_info: dict[str, Any] | None = None
    if not args.skip_pip:
        py_bin = _resolve_venv_python(args.venv_dir.resolve() if args.venv_dir else None)
        install_info = install_defensive_dependencies(
            target_dir,
            python_bin=py_bin,
            req_path=req_path,
            use_uv=args.use_uv,
        )

    seeded_cfg: str | None = None
    if args.config_dir is not None:
        seeded_cfg = str(seed_defensive_config(args.config_dir.resolve()))

    summary = {
        "ok": True,
        "mode": "bootstrap",
        "clone": clone_info,
        "verification": verification,
        "pruned_subtrees": pruned,
        "install": install_info,
        "seeded_defensive_config": seeded_cfg,
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
