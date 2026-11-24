#!/usr/bin/env python3
"""ALLINAGENT Cross-Platform CI & Security Automated Test Runner.

Usage:
    python tests/run_ci_suite.py
    python tests/run_ci_suite.py --json-out data/reports/ci-suite-results.json

Runs cleanly on Linux and Windows with zero secret-file reads and zero working-tree pollution.
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import io
import json
import os
import platform
import py_compile
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

os.environ.setdefault("ALLINAGENT_SKIP_DOTENV", "1")
os.environ.setdefault("OFFICE_BRIDGE_LOAD_DOTENV", "0")
os.environ.setdefault("NODE_ENV", "test")

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
CONTROL_CENTER_PKG_ROOT = REPO_ROOT / "apps" / "control-center"

for path_entry in (str(REPO_ROOT), str(CONTROL_CENTER_PKG_ROOT)):
    if path_entry not in sys.path:
        sys.path.insert(0, path_entry)

SUITE_MODULES: tuple[tuple[str, Path], ...] = (
    ("unit.manifests_and_locks", TESTS_DIR / "unit" / "test_manifests_and_locks.py"),
    ("unit.security_and_portability", TESTS_DIR / "unit" / "test_security_and_portability.py"),
    ("contract.telegram_and_bridge", TESTS_DIR / "contract" / "test_telegram_and_bridge_contracts.py"),
)


def run_syntax_compile_stage() -> dict[str, Any]:
    """Compile all test files and first-party Python modules into a temporary directory via py_compile."""
    t0 = time.perf_counter()
    target_globs = [
        TESTS_DIR / "run_ci_suite.py",
        *sorted((TESTS_DIR / "unit").glob("*.py")),
        *sorted((TESTS_DIR / "contract").glob("*.py")),
        *sorted((TESTS_DIR / "e2e").glob("*.py")),
        *sorted((REPO_ROOT / "apps" / "control-center" / "control_center").glob("*.py")),
        *sorted((REPO_ROOT / "integrations").rglob("*.py")),
        *sorted((REPO_ROOT / "components").rglob("*.py")),
        *sorted((REPO_ROOT / "scripts").rglob("*.py")),
    ]
    seen: set[Path] = set()
    files_to_check: list[Path] = []
    for p in target_globs:
        if p.is_file() and "__pycache__" not in p.parts:
            rp = p.resolve()
            if rp not in seen:
                seen.add(rp)
                files_to_check.append(rp)

    errors: list[str] = []
    with tempfile.TemporaryDirectory() as tmp_pyc_dir:
        for idx, py_file in enumerate(files_to_check):
            out_pyc = Path(tmp_pyc_dir) / f"compiled_{idx}.pyc"
            try:
                py_compile.compile(str(py_file), cfile=str(out_pyc), doraise=True)
            except py_compile.PyCompileError as exc:
                errors.append(f"{py_file.relative_to(REPO_ROOT).as_posix()}: {exc.msg}")

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return {
        "stage": "syntax.py_compile",
        "passed": len(errors) == 0,
        "tests_run": len(files_to_check),
        "failures": len(errors),
        "errors": 0,
        "skipped": 0,
        "duration_ms": elapsed_ms,
        "details": errors,
    }


def run_unittest_module(stage_name: str, module_path: Path, *, verbose: bool = False, failfast: bool = False) -> dict[str, Any]:
    t0 = time.perf_counter()
    spec = importlib.util.spec_from_file_location(stage_name.replace(".", "_"), str(module_path))
    if spec is None or spec.loader is None:
        return {
            "stage": stage_name,
            "passed": False,
            "tests_run": 0,
            "failures": 0,
            "errors": 1,
            "skipped": 0,
            "duration_ms": 0.0,
            "details": [f"Unable to load {module_path}"],
        }

    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)

    suite = unittest.defaultTestLoader.loadTestsFromModule(mod)
    buf = io.StringIO()
    runner = unittest.TextTestRunner(
        stream=sys.stdout if verbose else buf,
        verbosity=2 if verbose else 1,
        failfast=failfast,
    )
    res = runner.run(suite)
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    problem_lines = [
        f"{tc.id()}: {trace.strip().splitlines()[-1]}"
        for tc, trace in (list(res.failures) + list(res.errors))
    ]
    return {
        "stage": stage_name,
        "file": module_path.relative_to(REPO_ROOT).as_posix(),
        "passed": res.wasSuccessful(),
        "tests_run": res.testsRun,
        "failures": len(res.failures),
        "errors": len(res.errors),
        "skipped": len(res.skipped),
        "duration_ms": elapsed_ms,
        "details": problem_lines,
    }


def run_e2e_stage(args: argparse.Namespace) -> dict[str, Any]:
    t0 = time.perf_counter()
    e2e_script = TESTS_DIR / "e2e" / "run_live_acceptance.py"
    cmd = [sys.executable, str(e2e_script)]
    if args.live:
        cmd.extend([
            "--live",
            "--base-office-url", args.base_office_url,
            "--base-paperclip-url", args.base_paperclip_url,
            "--base-bridge-url", args.base_bridge_url,
        ])
    else:
        cmd.append("--verify-plan")

    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env={**os.environ, "ALLINAGENT_SKIP_DOTENV": "1", "OFFICE_BRIDGE_LOAD_DOTENV": "0"},
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180 if args.live else 25,
        check=False,
    )
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    passed = proc.returncode == 0
    details = [] if passed else [(proc.stderr or proc.stdout).strip()[:300]]
    return {
        "stage": "e2e.live_acceptance" if args.live else "e2e.plan_readiness",
        "file": e2e_script.relative_to(REPO_ROOT).as_posix(),
        "passed": passed,
        "tests_run": 6 if args.live else 1,
        "failures": 0 if passed else 1,
        "errors": 0,
        "skipped": 0,
        "duration_ms": elapsed_ms,
        "details": details,
    }


def detect_node_version() -> str:
    node_bin = shutil.which("node")
    if not node_bin:
        return "not_installed"
    proc = subprocess.run([node_bin, "--version"], capture_output=True, text=True, timeout=5, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ALLINAGENT Cross-Platform CI & Security Test Suite")
    parser.add_argument("-v", "--verbose", action="store_true", help="Stream verbose per-test output")
    parser.add_argument("--failfast", action="store_true", help="Stop on first failing test")
    parser.add_argument("--json-out", default=None, help="Write structured CI JSON summary to path")
    parser.add_argument("--live", action="store_true", help="Also execute live E2E acceptance against running stack")
    parser.add_argument("--base-office-url", default=os.environ.get("BASE_OFFICE_URL", "http://127.0.0.1:8200"))
    parser.add_argument("--base-paperclip-url", default=os.environ.get("BASE_PAPERCLIP_URL", "http://127.0.0.1:8201"))
    parser.add_argument("--base-bridge-url", default=os.environ.get("BASE_BRIDGE_URL", "http://127.0.0.1:8202"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    t_suite_start = time.perf_counter()

    stages: list[dict[str, Any]] = []
    stages.append(run_syntax_compile_stage())

    for stage_name, mod_path in SUITE_MODULES:
        if args.failfast and not stages[-1]["passed"]:
            break
        stages.append(run_unittest_module(stage_name, mod_path, verbose=args.verbose, failfast=args.failfast))

    if not (args.failfast and not stages[-1]["passed"]):
        stages.append(run_e2e_stage(args))

    total_ms = round((time.perf_counter() - t_suite_start) * 1000.0, 2)
    overall_passed = all(s["passed"] for s in stages)
    total_tests = sum(int(s["tests_run"]) for s in stages)
    total_failures = sum(int(s["failures"]) + int(s["errors"]) for s in stages)

    summary = {
        "product": "ALLINAGENT",
        "suite": "cross_platform_ci_and_security",
        "executed_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "environment": {
            "os": platform.system(),
            "release": platform.release(),
            "arch": platform.machine(),
            "python": platform.python_version(),
            "node": detect_node_version(),
        },
        "overall_status": "PASS" if overall_passed else "FAIL",
        "total_checks": total_tests,
        "total_failures": total_failures,
        "total_duration_ms": total_ms,
        "stages": stages,
    }

    print("=" * 74)
    print(
        f" ALLINAGENT CI & Security Suite | OS={summary['environment']['os']} "
        f"| Py={summary['environment']['python']} | Node={summary['environment']['node']}"
    )
    print("=" * 74)
    for st in stages:
        badge = "PASS" if st["passed"] else "FAIL"
        print(
            f"  [{badge}] {st['stage']:34s} | checks={st['tests_run']:3d} | "
            f"fail={st['failures'] + st['errors']:2d} | {st['duration_ms']:7.1f} ms"
        )
        for detail in st.get("details") or []:
            print(f"         -> {detail}")
    print("-" * 74)
    print(
        f"  VERDICT: {summary['overall_status']} | Total Checks={total_tests} | "
        f"Failures={total_failures} | Duration={total_ms:.1f} ms"
    )
    print("=" * 74)

    if args.json_out:
        out_p = Path(args.json_out).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    return 0 if overall_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
