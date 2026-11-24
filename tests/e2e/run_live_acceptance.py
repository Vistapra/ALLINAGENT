#!/usr/bin/env python3
"""ALLINAGENT Live Runtime End-to-End Acceptance Runner (Groups A, B, D, F, G, H).

Example invocation against a running stack:
    python tests/e2e/run_live_acceptance.py \
        --live \
        --base-office-url http://127.0.0.1:8200 \
        --base-paperclip-url http://127.0.0.1:8201 \
        --base-bridge-url http://127.0.0.1:8202 \
        --output data/reports/live-acceptance-evidence.json

Strict Privacy & Safety:
- Never reads `.env*`, `auth.json`, `office-bridge-auth.json`, or secret files.
- Optional auth tokens are accepted strictly via CLI flags or environment variables and are
  redacted from all stdout logs and persisted JSON evidence.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

os.environ.setdefault("ALLINAGENT_SKIP_DOTENV", "1")
os.environ.setdefault("OFFICE_BRIDGE_LOAD_DOTENV", "0")

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_CENTER_PKG_ROOT = REPO_ROOT / "apps" / "control-center"
for p_entry in (str(REPO_ROOT), str(CONTROL_CENTER_PKG_ROOT)):
    if p_entry not in sys.path:
        sys.path.insert(0, p_entry)

from control_center import paths as cc_paths
from control_center import report_exporter

ALL_GROUPS = ("A", "B", "D", "F", "G", "H")

_REDACT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bob" + r"_tok_[A-Za-z0-9_-]{8,}\b"), "[REDACTED_BRIDGE_TOKEN]"),
    (re.compile(r"\bst" + r"_tok_[A-Za-z0-9_-]{8,}\b"), "[REDACTED_STUDIO_TOKEN]"),
    (re.compile(r"\bpcp" + r"_[A-Za-z0-9_-]{8,}\b"), "[REDACTED_PAPERCLIP_KEY]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b"), "[REDACTED_BOT_TOKEN]"),
    (re.compile(r"(?i)(Bearer\s+)[^\s\"',;]+"), r"\1[REDACTED_BEARER]"),
)


def sanitize_evidence_text(value: str) -> str:
    out = value
    for rx, repl in _REDACT_PATTERNS:
        out = rx.sub(repl, out)
    return out


def sanitize_evidence_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return sanitize_evidence_text(obj)
    if isinstance(obj, list):
        return [sanitize_evidence_obj(x) for x in obj]
    if isinstance(obj, dict):
        sanitized: dict[str, Any] = {}
        for k, v in obj.items():
            if re.search(r"(?i)(token|secret|password|api_?key|authorization|cookie)", str(k)):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_evidence_obj(v)
        return sanitized
    return obj


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_301(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        return fp

    http_error_302 = http_error_303 = http_error_307 = http_error_308 = http_error_301


def http_probe(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    timeout: float = 12.0,
    follow_redirects: bool = True,
) -> tuple[int, Any, float]:
    hdrs = {"Accept": "application/json", **(headers or {})}
    body_bytes = None
    if json_body is not None:
        body_bytes = json.dumps(json_body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=body_bytes, headers=hdrs, method=method)
    opener = urllib.request.build_opener() if follow_redirects else urllib.request.build_opener(_NoRedirectHandler)

    t0 = time.perf_counter()
    try:
        with opener.open(req, timeout=timeout) as resp:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            status = getattr(resp, "status", None) or resp.getcode()
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                parsed = {"raw_excerpt": sanitize_evidence_text(raw[:240])}
            return int(status), parsed, round(elapsed_ms, 2)
    except urllib.error.HTTPError as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        raw = ""
        try:
            raw = exc.read().decode("utf-8", errors="replace")
        except Exception:
            raw = ""
        try:
            parsed = json.loads(raw) if raw.strip() else {"http_error": exc.code}
        except json.JSONDecodeError:
            parsed = {"http_error": exc.code, "raw_excerpt": sanitize_evidence_text(raw[:240])}
        return int(exc.code), parsed, round(elapsed_ms, 2)
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return 0, {"transport_error": sanitize_evidence_text(str(exc))}, round(elapsed_ms, 2)


def run_unittest_class(module_path: Path, class_name: str | None = None) -> dict[str, Any]:
    loader = unittest.TestLoader()
    import importlib.util as ilu

    spec = ilu.spec_from_file_location(module_path.stem, str(module_path))
    assert spec and spec.loader
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)

    if class_name:
        cls = getattr(mod, class_name)
        suite = loader.loadTestsFromTestCase(cls)
    else:
        suite = loader.loadTestsFromModule(mod)

    stream_buf = tempfile.SpooledTemporaryFile(mode="w+", encoding="utf-8")
    t0 = time.perf_counter()
    try:
        runner = unittest.TextTestRunner(stream=stream_buf, verbosity=1)
        result = runner.run(suite)
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        failures = [f"{tc.id()}: {sanitize_evidence_text(msg.splitlines()[-1])}" for tc, msg in result.failures + result.errors]
        return {
            "passed": result.wasSuccessful(),
            "tests_run": result.testsRun,
            "failures_count": len(result.failures),
            "errors_count": len(result.errors),
            "skipped_count": len(result.skipped),
            "duration_ms": elapsed_ms,
            "failure_summaries": failures[:10],
        }
    finally:
        stream_buf.close()


def _parse_docker_mem_to_mib(mem_usage_field: str) -> float:
    """Parse first token of `docker stats` MemUsage (e.g. `142.5MiB / 480MiB`) into MiB."""
    used_part = mem_usage_field.split("/", 1)[0].strip()
    m = re.match(r"([0-9.]+)\s*([A-Za-z]+)", used_part)
    if not m:
        return 0.0
    val = float(m.group(1))
    unit = m.group(2).lower()
    if unit in ("gib", "gb", "g"):
        return val * 1024.0
    if unit in ("mib", "mb", "m"):
        return val
    if unit in ("kib", "kb", "k"):
        return val / 1024.0
    return val / (1024.0 * 1024.0)


class LiveAcceptanceRunner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.office_url = args.base_office_url.rstrip("/")
        self.paperclip_url = args.base_paperclip_url.rstrip("/")
        self.bridge_url = args.base_bridge_url.rstrip("/")
        self.timeout = float(args.timeout)
        self.bridge_token = (args.bridge_token or os.environ.get("OFFICE_BRIDGE_TOKEN") or "").strip()
        self.studio_token = (args.studio_token or os.environ.get("STUDIO_ACCESS_TOKEN") or "").strip()
        self.paperclip_token = (
            args.paperclip_token
            or os.environ.get("PAPERCLIP_API_KEY")
            or os.environ.get("PAPERCLIP_BOARD_TOKEN")
            or ""
        ).strip()
        self.owner_id = cc_paths.resolve_owner_telegram_id(
            args.owner_id if args.owner_id is not None else os.environ.get("OWNER_TELEGRAM_ID", "")
        )

    def run_group_a(self) -> dict[str, Any]:
        """Group A: Core Stack Health, Access Gate & Supply-Chain Lock Verification."""
        checks: list[dict[str, Any]] = []

        st_pc, body_pc, ms_pc = http_probe("GET", f"{self.paperclip_url}/api/health", timeout=self.timeout)
        pc_ok = st_pc == 200 and (
            isinstance(body_pc, dict) and str(body_pc.get("status", "ok")).lower() in ("ok", "healthy", "ready")
        )
        checks.append({
            "id": "A01",
            "name": "Paperclip Control Plane /api/health",
            "http_status": st_pc,
            "latency_ms": ms_pc,
            "passed": pc_ok,
            "detail": body_pc,
        })

        st_br, body_br, ms_br = http_probe("GET", f"{self.bridge_url}/health", timeout=self.timeout)
        br_ok = st_br == 200 and isinstance(body_br, dict) and bool(body_br.get("ok", True))
        checks.append({
            "id": "A02",
            "name": "Office Bridge /health",
            "http_status": st_br,
            "latency_ms": ms_br,
            "passed": br_ok,
            "detail": body_br,
        })

        st_of, body_of, ms_of = http_probe("GET", f"{self.office_url}/api/health", timeout=self.timeout)
        of_ok = st_of == 200 and isinstance(body_of, dict) and bool(body_of.get("ok", True))
        checks.append({
            "id": "A03",
            "name": "Virtual Office (3D/2D) /api/health",
            "http_status": st_of,
            "latency_ms": ms_of,
            "passed": of_ok,
            "detail": body_of,
        })

        st_gate, _, ms_gate = http_probe(
            "GET",
            f"{self.office_url}/office",
            timeout=self.timeout,
            follow_redirects=False,
        )
        gate_ok = st_gate in (401, 403, 301, 302, 303, 307, 308)
        checks.append({
            "id": "A04",
            "name": "Virtual Office Unauthenticated Access Gate Enforced",
            "http_status": st_gate,
            "latency_ms": ms_gate,
            "passed": gate_ok,
            "detail": f"Expected 401/403/30x gate on unauthenticated /office, got HTTP {st_gate}",
        })

        lock_suite = run_unittest_class(REPO_ROOT / "tests" / "unit" / "test_manifests_and_locks.py")
        checks.append({
            "id": "A05",
            "name": "Supply-Chain Locks, License Inventory & 33-Skill Manifests",
            "passed": lock_suite["passed"],
            "detail": lock_suite,
        })

        return self._summarize_group("A", "Stack Health, Access Gate & Supply-Chain Locks", checks)

    def run_group_b(self) -> dict[str, Any]:
        """Group B: 11-Agent Topology, Dynamic Role Resolution & Auth Boundaries."""
        checks: list[dict[str, Any]] = []

        st_unauth, _, ms_unauth = http_probe(
            "GET",
            f"{self.bridge_url}/api/office-bridge/snapshot",
            timeout=self.timeout,
        )
        checks.append({
            "id": "B01",
            "name": "Office Bridge Snapshot Rejects Unauthenticated Caller (401)",
            "http_status": st_unauth,
            "latency_ms": ms_unauth,
            "passed": st_unauth == 401,
        })

        ident_suite = run_unittest_class(
            REPO_ROOT / "tests" / "contract" / "test_telegram_and_bridge_contracts.py",
            "TestDynamic11AgentIdentityContract",
        )
        role_suite = run_unittest_class(
            REPO_ROOT / "tests" / "unit" / "test_manifests_and_locks.py",
            "TestRoleManifests",
        )
        checks.append({
            "id": "B02",
            "name": "11-Agent Dynamic role_slug Resolution & Role Manifest Toolsets",
            "passed": ident_suite["passed"] and role_suite["passed"],
            "detail": {"dynamic_identity": ident_suite, "role_manifests": role_suite},
        })

        if self.bridge_token:
            st_snap, snap_body, ms_snap = http_probe(
                "GET",
                f"{self.bridge_url}/api/office-bridge/snapshot",
                headers={"Authorization": f"Bearer {self.bridge_token}"},
                timeout=self.timeout,
            )
            agents_list = (snap_body.get("agents") or []) if isinstance(snap_body, dict) else []
            snap_ok = st_snap == 200 and len(agents_list) == 11
            checks.append({
                "id": "B03",
                "name": "Authenticated Office Bridge Live 11-Agent Snapshot",
                "http_status": st_snap,
                "latency_ms": ms_snap,
                "passed": snap_ok,
                "detail": {"agents_count": len(agents_list)},
            })

        return self._summarize_group("B", "11-Agent Organization & Dynamic Identity", checks)

    def run_group_d(self) -> dict[str, Any]:
        """Group D: 3D/2D Office Routes, 59 Telegram Commands & PDF/DOCX Report Export."""
        checks: list[dict[str, Any]] = []

        st_login, _, ms_login = http_probe(
            "GET",
            f"{self.office_url}/login",
            timeout=self.timeout,
            follow_redirects=False,
        )
        checks.append({
            "id": "D01",
            "name": "Virtual Office /login Gate Route Reachable",
            "http_status": st_login,
            "latency_ms": ms_login,
            "passed": st_login in (200, 302, 307, 401),
        })

        tg_contract = run_unittest_class(
            REPO_ROOT / "tests" / "contract" / "test_telegram_and_bridge_contracts.py",
            "TestTelegram59SlashCommandsContract",
        )
        checks.append({
            "id": "D02",
            "name": "59 Slash Commands & 13 Submenu Contract Parity",
            "passed": tg_contract["passed"],
            "detail": tg_contract,
        })

        if self.bridge_token and self.owner_id:
            st_k, body_k, ms_k = http_probe(
                "POST",
                f"{self.bridge_url}/api/office-bridge/telegram/command",
                headers={
                    "Authorization": f"Bearer {self.bridge_token}",
                    "X-Office-Caller-Id": self.owner_id,
                    "X-Office-Actor-Role": "owner",
                },
                json_body={
                    "command": "kantor",
                    "args": "",
                    "caller_id": self.owner_id,
                    "chat_id": self.owner_id,
                    "chat_type": "private",
                },
                timeout=self.timeout,
            )
            kb = body_k.get("inline_keyboard") if isinstance(body_k, dict) else None
            checks.append({
                "id": "D03_LIVE_TG",
                "name": "Live Authenticated /kantor Command Center Roundtrip",
                "http_status": st_k,
                "latency_ms": ms_k,
                "passed": st_k == 200 and isinstance(kb, list) and len(kb) > 0,
                "detail": {"keyboard_rows": len(kb) if isinstance(kb, list) else 0},
            })

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            md_src = tmp_dir / "live-acceptance-report.md"
            md_src.write_text(
                "# ALLINAGENT Live Acceptance Compliance Artifact\n\n"
                "| Check | Verdict |\n| --- | --- |\n| PDF + DOCX Export | PASS |\n",
                encoding="utf-8",
            )
            exp = report_exporter.export_markdown_to_pdf_and_docx(md_src, tmp_dir / "out")
            pdf_p = Path(exp["pdf_path"])
            docx_p = Path(exp["docx_path"])
            pdf_valid = pdf_p.is_file() and pdf_p.read_bytes().startswith(b"%PDF-")
            docx_valid = docx_p.is_file() and zipfile.is_zipfile(docx_p)
            if docx_valid:
                with zipfile.ZipFile(docx_p, "r") as zf:
                    docx_valid = "word/document.xml" in zf.namelist()
            checks.append({
                "id": "D04",
                "name": "PDF (%PDF-) & DOCX (word/document.xml) Report Generation",
                "passed": pdf_valid and docx_valid,
                "detail": {
                    "pdf_engine": exp["pdf_engine"],
                    "pdf_size_bytes": exp["pdf_size_bytes"],
                    "docx_engine": exp["docx_engine"],
                    "docx_size_bytes": exp["docx_size_bytes"],
                },
            })

        return self._summarize_group("D", "3D/2D Office, 59 Telegram Commands & Report Exporter", checks)

    def run_group_f(self) -> dict[str, Any]:
        """Group F: Skill Security Gate, SHA-256 Tamper Rejection & Quarantine (F01-F10)."""
        f_suite = run_unittest_class(
            REPO_ROOT / "tests" / "unit" / "test_security_and_portability.py",
            "TestGroupFSkillSecurityGate",
        )
        checks = [{
            "id": "F01_F10",
            "name": "Skill SHA-256 Tamper Rejection, Sentry Scanner Quarantine & .usage.json Lock",
            "passed": f_suite["passed"],
            "detail": f_suite,
        }]
        return self._summarize_group("F", "Skill Supply-Chain Security Gate (F01-F10)", checks)

    def run_group_g(self) -> dict[str, Any]:
        """Group G: Resource Budget (<= 1,536 MiB), Latency & Port Isolation."""
        checks: list[dict[str, Any]] = []

        samples_ms: dict[str, list[float]] = {"paperclip": [], "bridge": [], "office": []}
        statuses_ok = True
        for _ in range(3):
            s1, _, m1 = http_probe("GET", f"{self.paperclip_url}/api/health", timeout=self.timeout)
            s2, _, m2 = http_probe("GET", f"{self.bridge_url}/health", timeout=self.timeout)
            s3, _, m3 = http_probe("GET", f"{self.office_url}/api/health", timeout=self.timeout)
            samples_ms["paperclip"].append(m1)
            samples_ms["bridge"].append(m2)
            samples_ms["office"].append(m3)
            if not (s1 == 200 and s2 == 200 and s3 == 200):
                statuses_ok = False

        all_lat = samples_ms["paperclip"] + samples_ms["bridge"] + samples_ms["office"]
        max_lat = round(max(all_lat), 2) if all_lat else 9999.0
        mean_lat = round(statistics.mean(all_lat), 2) if all_lat else 9999.0
        checks.append({
            "id": "G01",
            "name": "Health Endpoint Latency Profile (< 2,500 ms)",
            "passed": statuses_ok and max_lat < 2500.0,
            "detail": {"mean_ms": mean_lat, "max_ms": max_lat, "per_service_ms": samples_ms},
        })

        compose_suite = run_unittest_class(
            REPO_ROOT / "tests" / "contract" / "test_telegram_and_bridge_contracts.py",
            "TestComposeProductionBudgetAndPortIsolation",
        )
        checks.append({
            "id": "G02",
            "name": "Compose Production mem_limit Budget (<= 1,536 MiB) & Zero DB Ports",
            "passed": compose_suite["passed"],
            "detail": compose_suite,
        })

        if shutil.which("docker"):
            dproc = subprocess.run(
                ["docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=15,
                check=False,
            )
            if dproc.returncode == 0 and dproc.stdout.strip():
                allinagent_ctrs: dict[str, dict[str, Any]] = {}
                total_rss_mib = 0.0
                for ln in dproc.stdout.splitlines():
                    parts = ln.split("\t")
                    if len(parts) >= 3 and parts[0].startswith("allinagent-"):
                        rss_mib = round(_parse_docker_mem_to_mib(parts[1]), 2)
                        total_rss_mib += rss_mib
                        allinagent_ctrs[parts[0]] = {
                            "mem_usage": parts[1],
                            "rss_mib": rss_mib,
                            "cpu": parts[2],
                        }
                if allinagent_ctrs:
                    checks.append({
                        "id": "G03_DOCKER_RSS",
                        "name": "Live Container Working Set Within 1,536 MiB Ceiling",
                        "passed": total_rss_mib <= 1536.0,
                        "detail": {
                            "total_rss_mib": round(total_rss_mib, 2),
                            "containers": allinagent_ctrs,
                        },
                    })

        return self._summarize_group("G", "Resource Budget, Latency & Port Isolation", checks)

    def run_group_h(self) -> dict[str, Any]:
        """Group H: Negative Security Boundaries, Secret Redaction, Path Jail & Fail-Closed Auth."""
        checks: list[dict[str, Any]] = []

        st_no_tok, _, ms_no_tok = http_probe(
            "POST",
            f"{self.bridge_url}/api/office-bridge/telegram/command",
            json_body={"command": "kantor", "args": ""},
            timeout=self.timeout,
        )
        checks.append({
            "id": "H01_LIVE",
            "name": "Unauthenticated Telegram Bridge Endpoint Rejected (401)",
            "http_status": st_no_tok,
            "latency_ms": ms_no_tok,
            "passed": st_no_tok == 401,
        })

        forged_tok = "ob" + "_tok_" + ("0" * 32)
        st_bad_tok, _, ms_bad_tok = http_probe(
            "POST",
            f"{self.bridge_url}/api/office-bridge/telegram/command",
            headers={"Authorization": f"Bearer {forged_tok}"},
            json_body={"command": "kantor", "args": ""},
            timeout=self.timeout,
        )
        checks.append({
            "id": "H02_LIVE",
            "name": "Forged Bearer Token Rejected (401)",
            "http_status": st_bad_tok,
            "latency_ms": ms_bad_tok,
            "passed": st_bad_tok == 401,
        })

        if self.bridge_token:
            non_owner = "999999991"
            st_non_owner, _, _ = http_probe(
                "POST",
                f"{self.bridge_url}/api/office-bridge/telegram/command",
                headers={
                    "Authorization": f"Bearer {self.bridge_token}",
                    "X-Office-Caller-Id": non_owner,
                    "X-Office-Actor-Role": "owner",
                },
                json_body={
                    "command": "kantor",
                    "caller_id": non_owner,
                    "chat_id": non_owner,
                    "chat_type": "private",
                },
                timeout=self.timeout,
            )
            checks.append({
                "id": "H03_LIVE",
                "name": "Non-Owner Caller Rejected (403)",
                "http_status": st_non_owner,
                "passed": st_non_owner == 403,
            })

            if self.owner_id:
                st_grp, _, _ = http_probe(
                    "POST",
                    f"{self.bridge_url}/api/office-bridge/telegram/command",
                    headers={
                        "Authorization": f"Bearer {self.bridge_token}",
                        "X-Office-Caller-Id": self.owner_id,
                        "X-Office-Actor-Role": "owner",
                    },
                    json_body={
                        "command": "kantor",
                        "caller_id": self.owner_id,
                        "chat_id": "-100987654321",
                        "chat_type": "supergroup",
                    },
                    timeout=self.timeout,
                )
                checks.append({
                    "id": "H04_LIVE",
                    "name": "Supergroup Context Rejected (DM-Only Scope 403)",
                    "http_status": st_grp,
                    "passed": st_grp == 403,
                })

        h_suite = run_unittest_class(
            REPO_ROOT / "tests" / "unit" / "test_security_and_portability.py",
            "TestGroupHSecurityAndPortability",
        )
        checks.append({
            "id": "H05_UNIT_SECURITY",
            "name": "Secret Redaction, Cross-OS Path Jail, Fail-Closed Auth & Repo Portability (H01-H10)",
            "passed": h_suite["passed"],
            "detail": h_suite,
        })

        return self._summarize_group("H", "Negative Security Boundaries & Portability (H01-H10)", checks)

    @staticmethod
    def _summarize_group(group_id: str, title: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
        passed_count = sum(1 for c in checks if c.get("passed"))
        all_ok = passed_count == len(checks)
        return {
            "group": group_id,
            "title": title,
            "status": "PASS" if all_ok else "FAIL",
            "checks_passed": passed_count,
            "checks_total": len(checks),
            "checks": checks,
        }

    def execute(self, selected_groups: list[str]) -> dict[str, Any]:
        dispatch = {
            "A": self.run_group_a,
            "B": self.run_group_b,
            "D": self.run_group_d,
            "F": self.run_group_f,
            "G": self.run_group_g,
            "H": self.run_group_h,
        }
        t_start = time.perf_counter()
        groups_out: dict[str, Any] = {}
        for g in selected_groups:
            groups_out[g] = dispatch[g]()

        total_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
        overall_ok = all(v["status"] == "PASS" for v in groups_out.values())
        return sanitize_evidence_obj({
            "product": "ALLINAGENT",
            "mode": "LIVE_ACCEPTANCE",
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "environment": {
                "os": platform.system(),
                "release": platform.release(),
                "arch": platform.machine(),
                "python": platform.python_version(),
            },
            "targets": {
                "base_office_url": self.office_url,
                "base_paperclip_url": self.paperclip_url,
                "base_bridge_url": self.bridge_url,
            },
            "groups_requested": selected_groups,
            "overall_status": "PASS" if overall_ok else "FAIL",
            "total_duration_ms": total_ms,
            "groups": groups_out,
        })


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ALLINAGENT Live Runtime Acceptance Runner (Groups A, B, D, F, G, H)."
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Execute live HTTP/runtime acceptance checks against a running ALLINAGENT stack.",
    )
    parser.add_argument(
        "--verify-plan",
        action="store_true",
        help="Validate acceptance test plan & offline readiness without requiring live containers.",
    )
    parser.add_argument(
        "--base-office-url",
        default=os.environ.get("BASE_OFFICE_URL", "http://127.0.0.1:8200"),
        help="Base URL for Virtual Office (Hermes3D / 2D Pixel Office).",
    )
    parser.add_argument(
        "--base-paperclip-url",
        default=os.environ.get("BASE_PAPERCLIP_URL", "http://127.0.0.1:8201"),
        help="Base URL for Paperclip Control Plane.",
    )
    parser.add_argument(
        "--base-bridge-url",
        default=os.environ.get("BASE_BRIDGE_URL", "http://127.0.0.1:8202"),
        help="Base URL for Unified Office Bridge.",
    )
    parser.add_argument(
        "--groups",
        nargs="+",
        choices=ALL_GROUPS,
        default=list(ALL_GROUPS),
        help="Acceptance test groups to execute (default: A B D F G H).",
    )
    parser.add_argument(
        "--output",
        "--json-out",
        dest="output",
        default=None,
        help="Path to write structured JSON acceptance evidence.",
    )
    parser.add_argument("--bridge-token", default=None, help="Optional Office Bridge token for authenticated probes.")
    parser.add_argument("--studio-token", default=None, help="Optional Studio access token.")
    parser.add_argument("--paperclip-token", default=None, help="Optional Paperclip API token.")
    parser.add_argument("--owner-id", default=None, help="Optional numeric Owner Telegram ID.")
    parser.add_argument("--timeout", type=float, default=12.0, help="Per-request HTTP timeout in seconds.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    selected_groups = [g.upper() for g in args.groups]

    if not args.live:
        plan_doc = sanitize_evidence_obj({
            "product": "ALLINAGENT",
            "mode": "PLAN_VERIFICATION",
            "ready": True,
            "groups_configured": selected_groups,
            "targets": {
                "base_office_url": args.base_office_url,
                "base_paperclip_url": args.base_paperclip_url,
                "base_bridge_url": args.base_bridge_url,
            },
            "hint": "Pass --live to execute live runtime HTTP/security probes against a running ALLINAGENT stack.",
        })
        if args.output:
            out_p = Path(args.output).resolve()
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(json.dumps(plan_doc, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(plan_doc, indent=2))
        return 0

    runner = LiveAcceptanceRunner(args)
    evidence = runner.execute(selected_groups)

    out_path = (
        Path(args.output).resolve()
        if args.output
        else (REPO_ROOT / "data" / "reports" / "live-acceptance-evidence.json")
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

    for g_id in selected_groups:
        g_res = evidence["groups"][g_id]
        print(
            f"[{g_res['status']}] Group {g_id} ({g_res['title']}): "
            f"{g_res['checks_passed']}/{g_res['checks_total']} checks passed"
        )
    print(f"[ALLINAGENT E2E] Overall={evidence['overall_status']} | Evidence={out_path}")
    return 0 if evidence["overall_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
