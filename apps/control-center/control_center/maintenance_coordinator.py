#!/usr/bin/env python3
"""Cross-Platform Coordinated Daily 03:00 WIB Auto-Update & Maintenance Coordinator.

Coordinates sequential non-disruptive checks & updates for Paperclip AI, VulnClaw,
Hermes3D, and the 11-Agent Pinned Skill Registry across Linux (Docker / systemd) and
Windows environments with:
- Active-work deferral (checks live Paperclip runs & Hermes updater lock)
- Cross-platform disk guard via `shutil.disk_usage(ALLINAGENT_ROOT)`
- Immutable container awareness (`ALLINAGENT_MUTABLE_RUNTIME=1` required for in-place pip/npm mutation;
  otherwise stages candidates safely for Docker image rollout)
- Post-check functional HTTP/runtime smoke tests & candidate quarantine
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_PKG_ROOT = str(Path(__file__).resolve().parents[1])
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from control_center.paperclip_client import PaperclipClient
from control_center.paths import (
    ALLINAGENT_ROOT,
    CONFIG_DIR,
    DATA_DIR,
    HERMES3D_URL,
    HERMES_HOME_ROOT,
    HERMES_UPDATER_DIR,
    OFFICE_BRIDGE_URL,
    VULNCLAW_VENV_PYTHON,
)
from control_center.vulnclaw_defensive import runtime_diagnostics
from control_center.workflow_engine import send_owner_telegram_notification

MAINT_DIR: Path = DATA_DIR / "maintenance"
MAINT_STATE_PATH: Path = MAINT_DIR / "state.json"
MAINT_LOCK_PATH: Path = MAINT_DIR / "maintenance.lock"
HERMES_UPDATER_STATE: Path = HERMES_UPDATER_DIR / "state" / "state.json"
LIMITS_PATH: Path = CONFIG_DIR / "resource-limits.json"
UPSTREAM_LOCKS_PATH: Path = CONFIG_DIR / "upstream-locks.json"

COORDINATOR_STATES = (
    "IDLE",
    "MAINTENANCE_PENDING",
    "DRAINING",
    "PRECHECK",
    "CANDIDATE_VALIDATION",
    "UPDATING",
    "POST_UPDATE_TEST",
    "READY",
    "DEFERRED",
    "FAILED",
    "NEEDS_ATTENTION",
)

WIB = timezone(timedelta(hours=7), name="WIB")


def now_wib() -> datetime:
    return datetime.now(timezone.utc).astimezone(WIB)


def daily_window(now: datetime | None = None) -> dict[str, Any]:
    cur = now or now_wib()
    today_03 = cur.replace(hour=3, minute=0, second=0, microsecond=0)
    if cur >= today_03:
        due = today_03
        nxt = today_03 + timedelta(days=1)
        is_catchup = (cur - today_03).total_seconds() >= 600
    else:
        due = today_03 - timedelta(days=1)
        nxt = today_03
        is_catchup = True
    return {
        "due_slot": due.isoformat(timespec="seconds"),
        "next_slot": nxt.isoformat(timespec="seconds"),
        "is_catchup": is_catchup,
    }


def read_state() -> dict[str, Any]:
    MAINT_DIR.mkdir(parents=True, exist_ok=True)
    if MAINT_STATE_PATH.exists():
        try:
            return json.loads(MAINT_STATE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "state": "IDLE",
        "schedule_mode": "daily",
        "daily_time": "03:00 Asia/Jakarta",
        "last_completed_slot": None,
        "next_scheduled_slot": daily_window()["next_slot"],
        "quarantined_candidates": {},
        "last_run_at": None,
        "last_result": None,
        "history": [],
    }


def write_state(st: dict[str, Any]) -> None:
    MAINT_DIR.mkdir(parents=True, exist_ok=True)
    st["updated_at"] = now_wib().isoformat(timespec="seconds")
    tmp = MAINT_STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, indent=2), encoding="utf-8")
    tmp.replace(MAINT_STATE_PATH)


def set_phase(st: dict[str, Any], phase: str, note: str = "") -> None:
    if phase not in COORDINATOR_STATES:
        raise ValueError(f"Unknown coordinator state: {phase}")
    st["state"] = phase
    if note:
        st["last_note"] = note
    write_state(st)


def check_active_work() -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if HERMES_UPDATER_STATE.exists():
        try:
            hs = json.loads(HERMES_UPDATER_STATE.read_text(encoding="utf-8-sig"))
            if hs.get("update_in_progress"):
                reasons.append("hermes_autoupdate_in_progress")
        except Exception:
            pass

    try:
        pc = PaperclipClient(timeout=6.0)
        cid = pc.get_primary_company()["id"]
        live = [r for r in pc.list_live_runs(cid) if r.get("status") in ("queued", "running")]
        if live:
            reasons.append(f"paperclip_live_runs:{len(live)}")
    except Exception:
        pass

    return (len(reasons) > 0, reasons)


def check_free_disk_ok() -> tuple[bool, dict[str, float]]:
    """Cross-platform disk space guard on `ALLINAGENT_ROOT`."""
    min_free_gb = 2.0
    if LIMITS_PATH.exists():
        try:
            lim = json.loads(LIMITS_PATH.read_text(encoding="utf-8")).get("limits", {})
            min_free_gb = float(lim.get("min_free_disk_gb") or lim.get("min_free_disk_gb_d") or 2.0)
        except Exception:
            pass
    target_dir = ALLINAGENT_ROOT if ALLINAGENT_ROOT.exists() else Path.cwd()
    usage = shutil.disk_usage(target_dir)
    free_gb = round(usage.free / (1024**3), 2)
    total_gb = round(usage.total / (1024**3), 2)
    return free_gb >= min_free_gb, {"root_free_gb": free_gb, "root_total_gb": total_gb, "min_required_gb": min_free_gb}


def get_installed_paperclip_version() -> str:
    for cand in (
        ALLINAGENT_ROOT / "runtime" / "paperclip-app" / "node_modules" / "paperclipai" / "package.json",
        Path("/opt/paperclip/node_modules/paperclipai/package.json"),
    ):
        if cand.is_file():
            try:
                return str(json.loads(cand.read_text(encoding="utf-8")).get("version", ""))
            except Exception:
                pass
    if UPSTREAM_LOCKS_PATH.is_file():
        try:
            locks = json.loads(UPSTREAM_LOCKS_PATH.read_text(encoding="utf-8"))
            return str((locks.get("paperclip") or {}).get("version") or "")
        except Exception:
            pass
    return os.environ.get("PAPERCLIP_VERSION", "")


def get_latest_paperclip_npm_version() -> str:
    req = urllib.request.Request(
        "https://registry.npmjs.org/paperclipai/latest",
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            ver = str(data.get("version") or "").strip()
            if ver:
                return ver
    except Exception:
        pass

    npm_bin = shutil.which("npm")
    if not npm_bin:
        raise RuntimeError("Unable to query registry.npmjs.org and `npm` binary not found")
    proc = subprocess.run(
        [npm_bin, "view", "paperclipai@latest", "version", "--registry=https://registry.npmjs.org"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"npm view paperclipai@latest failed: {proc.stderr.strip()}")
    return proc.stdout.strip().splitlines()[-1].strip().strip("'\"")


def get_installed_vulnclaw_tag() -> str:
    try:
        vdiag = runtime_diagnostics(verify_llm=False)
        ver = str(vdiag.get("vulnclaw_version") or "").strip()
        if ver:
            return ver if ver.startswith("v") else f"v{ver}"
    except Exception:
        pass

    if VULNCLAW_VENV_PYTHON.exists():
        proc = subprocess.run(
            [str(VULNCLAW_VENV_PYTHON), "-c", "import vulnclaw; print('v' + vulnclaw.__version__)"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    return os.environ.get("VULNCLAW_VERSION", "")


def _git_latest_semver_tag(repo_url: str, fallback: str = "") -> str:
    git_bin = shutil.which("git") or "git"
    proc = subprocess.run(
        [git_bin, "ls-remote", "--tags", "--refs", repo_url],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        if fallback:
            return fallback
        raise RuntimeError(f"git ls-remote {repo_url} failed: {proc.stderr.strip()}")
    tags: list[tuple[tuple[int, ...], str]] = []
    for ln in proc.stdout.splitlines():
        m = re.search(r"refs/tags/(v\d+\.\d+\.\d+)$", ln.strip())
        if m:
            ver_str = m.group(1)
            nums = tuple(int(x) for x in ver_str[1:].split("."))
            tags.append((nums, ver_str))
    if not tags:
        if fallback:
            return fallback
        raise RuntimeError(f"No stable semver tags returned for {repo_url}")
    tags.sort()
    return tags[-1][1]


def get_latest_vulnclaw_stable_tag() -> str:
    return _git_latest_semver_tag("https://github.com/Netw0rkNoob/VulnClaw.git")


def get_installed_hermes3d_version() -> str:
    for pkg in (
        ALLINAGENT_ROOT / "apps" / "hermes3d" / "package.json",
        ALLINAGENT_ROOT / "hermes3d" / "package.json",
        ALLINAGENT_ROOT / "hermes3d" / "source" / "package.json",
    ):
        if pkg.is_file():
            ver = str(json.loads(pkg.read_text(encoding="utf-8")).get("version", "")).strip()
            return f"v{ver}" if ver and not ver.startswith("v") else ver
    return "v1.0.0"


def get_latest_hermes3d_stable_tag() -> str:
    return _git_latest_semver_tag(
        "https://github.com/iamlukethedev/Hermes3D.git",
        fallback=get_installed_hermes3d_version() or "v1.0.0",
    )


def probe_hermes_gateway_healthy() -> dict[str, Any]:
    """Cross-platform check for Hermes Gateway & Updater readiness without PowerShell dependencies."""
    au_state: dict[str, Any] = {}
    if HERMES_UPDATER_STATE.is_file():
        try:
            au_state = json.loads(HERMES_UPDATER_STATE.read_text(encoding="utf-8-sig"))
        except Exception:
            pass

    gateway_pid_file = HERMES_HOME_ROOT / "gateway.pid"
    gateway_running = False
    if gateway_pid_file.is_file():
        try:
            pid = int(gateway_pid_file.read_text(encoding="utf-8").strip())
            os.kill(pid, 0)
            gateway_running = True
        except Exception:
            gateway_running = False

    health_url = os.environ.get("HERMES_GATEWAY_HEALTH_URL", "").strip()
    if health_url and not gateway_running:
        try:
            with urllib.request.urlopen(health_url, timeout=3) as resp:
                gateway_running = resp.status == 200
        except Exception:
            pass

    config_ok = (HERMES_HOME_ROOT / "config.yaml").is_file() or HERMES_HOME_ROOT.is_dir()
    return {
        "healthy": gateway_running or config_ok,
        "installed_commit": au_state.get("installed_commit", os.environ.get("HERMES_COMMIT", "")),
        "channel": au_state.get("channel", "main"),
        "gateway_running": gateway_running,
        "config_present": config_ok,
        "updater_schedule": f"{au_state.get('schedule_mode', 'daily')} @ 03:00 Asia/Jakarta",
        "last_update_success": au_state.get("last_update_success"),
        "next_maintenance_window": au_state.get("next_check"),
    }


def run_post_update_smoke_tests() -> dict[str, Any]:
    pc_ok = False
    pc_status = "offline"
    try:
        pc = PaperclipClient(timeout=10.0)
        pc_health = pc.health()
        pc_status = str(pc_health.get("status") or "")
        pc_ok = pc_status == "ok"
    except Exception:
        pc_ok = False

    vc_ver = None
    try:
        vc_diag = runtime_diagnostics(verify_llm=False)
        vc_ver = vc_diag.get("vulnclaw_version")
    except Exception:
        vc_ver = None

    h_info = probe_hermes_gateway_healthy()

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    bridge_ok = False
    h3d_ok = False
    try:
        with opener.open(f"{OFFICE_BRIDGE_URL}/health", timeout=5) as r:
            bridge_ok = r.status == 200
    except Exception:
        bridge_ok = False
    try:
        with opener.open(f"{HERMES3D_URL}/api/health", timeout=5) as r:
            h3d_ok = r.status in (200, 302, 307)
    except Exception:
        h3d_ok = False

    ok = pc_ok and bool(h_info.get("healthy"))
    return {
        "ok": ok,
        "paperclip_status": pc_status,
        "vulnclaw_version": vc_ver,
        "hermes_unified_healthy": bool(h_info.get("healthy")),
        "office_bridge_healthy": bridge_ok,
        "hermes3d_healthy": h3d_ok,
    }


def run_maintenance_cycle(
    *,
    force: bool = False,
    dry_run: bool = False,
    notify_owner: bool = False,
    simulated_now: datetime | None = None,
) -> dict[str, Any]:
    st = read_state()
    win = daily_window(simulated_now)

    if not force:
        last_done = st.get("last_completed_slot")
        if last_done and last_done >= win["due_slot"]:
            st["state"] = "IDLE"
            st["next_scheduled_slot"] = win["next_slot"]
            write_state(st)
            return {
                "outcome": "waiting_daily_window",
                "due_slot": win["due_slot"],
                "next_slot": win["next_slot"],
                "state": "IDLE",
            }

    set_phase(st, "MAINTENANCE_PENDING", f"Window due={win['due_slot']} catchup={win['is_catchup']}")

    set_phase(st, "DRAINING", "Checking active Hermes & Paperclip workloads")
    busy, busy_reasons = check_active_work()
    if busy:
        set_phase(st, "DEFERRED", f"Active workloads detected: {', '.join(busy_reasons)}")
        return {"outcome": "deferred_active_work", "reasons": busy_reasons, "state": "DEFERRED"}

    MAINT_DIR.mkdir(parents=True, exist_ok=True)
    if MAINT_LOCK_PATH.exists():
        age_s = time.time() - MAINT_LOCK_PATH.stat().st_mtime
        if age_s < 5400:
            set_phase(st, "DEFERRED", "Maintenance lock already held")
            return {"outcome": "deferred_locked", "state": "DEFERRED"}
    MAINT_LOCK_PATH.write_text(
        json.dumps({"pid": os.getpid(), "started_at": now_wib().isoformat(timespec="seconds")}),
        encoding="utf-8",
    )

    try:
        set_phase(st, "PRECHECK", "Checking free disk & runtime status")
        disk_ok, disk_info = check_free_disk_ok()
        if not disk_ok:
            set_phase(st, "NEEDS_ATTENTION", f"Insufficient free disk: {disk_info}")
            return {"outcome": "disk_guard_blocked", "disk": disk_info, "state": "NEEDS_ATTENTION"}

        set_phase(st, "CANDIDATE_VALIDATION", "Checking Paperclip, VulnClaw & Hermes3D stable candidates")
        quarantined = st.setdefault("quarantined_candidates", {})
        mutable_runtime = os.environ.get("ALLINAGENT_MUTABLE_RUNTIME") == "1"

        pc_cur = get_installed_paperclip_version()
        pc_lat = get_latest_paperclip_npm_version()
        vc_cur = get_installed_vulnclaw_tag()
        vc_lat = get_latest_vulnclaw_stable_tag()
        h3d_cur = get_installed_hermes3d_version()
        h3d_lat = get_latest_hermes3d_stable_tag()

        actions_taken: list[str] = []

        # Component A: Paperclip
        if pc_lat and pc_cur and pc_lat != pc_cur:
            q_key = f"paperclip:{pc_lat}"
            if q_key in quarantined:
                actions_taken.append(f"paperclip:{pc_lat}:quarantined_skipped")
            elif dry_run or not mutable_runtime:
                actions_taken.append(f"paperclip:{pc_cur}->{pc_lat}:candidate_staged")
            else:
                cur_major = pc_cur.split(".")[0]
                lat_major = pc_lat.split(".")[0]
                if cur_major and lat_major != cur_major:
                    set_phase(st, "NEEDS_ATTENTION", f"Major Paperclip version jump {pc_cur} -> {pc_lat} requires Owner review")
                    return {"outcome": "major_upgrade_deferred", "state": "NEEDS_ATTENTION"}
                npm_bin = shutil.which("npm")
                app_dir = ALLINAGENT_ROOT / "runtime" / "paperclip-app"
                if npm_bin and app_dir.is_dir():
                    set_phase(st, "UPDATING", f"Updating Paperclip {pc_cur} -> {pc_lat}")
                    upd = subprocess.run(
                        [npm_bin, "install", "--prefix", str(app_dir), f"paperclipai@{pc_lat}", "--omit=optional", "--no-audit", "--no-fund"],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if upd.returncode != 0:
                        quarantined[q_key] = {"failed_at": now_wib().isoformat(timespec="seconds"), "reason": "npm_install_failed"}
                        set_phase(st, "FAILED", f"Paperclip {pc_lat} install failed; candidate quarantined")
                        return {"outcome": "paperclip_update_failed", "quarantined": q_key, "state": "FAILED"}
                    actions_taken.append(f"paperclip:updated:{pc_cur}->{pc_lat}")
                else:
                    actions_taken.append(f"paperclip:{pc_cur}->{pc_lat}:candidate_staged")
        else:
            actions_taken.append(f"paperclip:up_to_date:{pc_cur or pc_lat}")

        # Component B: VulnClaw
        if vc_lat and vc_cur and vc_lat != vc_cur:
            q_key = f"vulnclaw:{vc_lat}"
            if q_key in quarantined:
                actions_taken.append(f"vulnclaw:{vc_lat}:quarantined_skipped")
            elif dry_run or not mutable_runtime:
                actions_taken.append(f"vulnclaw:{vc_cur}->{vc_lat}:candidate_staged")
            else:
                git_bin = shutil.which("git") or "git"
                uv_bin = shutil.which("uv")
                vc_repo = ALLINAGENT_ROOT / "runtime" / "vulnclaw"
                if uv_bin and vc_repo.is_dir():
                    set_phase(st, "UPDATING", f"Updating isolated VulnClaw {vc_cur} -> {vc_lat}")
                    f1 = subprocess.run([git_bin, "-C", str(vc_repo), "fetch", "--tags", "origin"], capture_output=True, check=False)
                    f2 = subprocess.run([git_bin, "-C", str(vc_repo), "checkout", vc_lat], capture_output=True, check=False)
                    f3 = subprocess.run([uv_bin, "pip", "install", "--python", str(VULNCLAW_VENV_PYTHON), "-e", str(vc_repo)], capture_output=True, check=False)
                    if f1.returncode != 0 or f2.returncode != 0 or f3.returncode != 0:
                        subprocess.run([git_bin, "-C", str(vc_repo), "checkout", vc_cur], capture_output=True, check=False)
                        quarantined[q_key] = {"failed_at": now_wib().isoformat(timespec="seconds"), "reason": "git_or_pip_failed"}
                        set_phase(st, "FAILED", f"VulnClaw {vc_lat} update failed; rolled back to {vc_cur}")
                        return {"outcome": "vulnclaw_update_failed", "quarantined": q_key, "state": "FAILED"}
                    actions_taken.append(f"vulnclaw:updated:{vc_cur}->{vc_lat}")
                else:
                    actions_taken.append(f"vulnclaw:{vc_cur}->{vc_lat}:candidate_staged")
        else:
            actions_taken.append(f"vulnclaw:up_to_date:{vc_cur or vc_lat}")

        # Component C: Hermes3D
        if h3d_lat and h3d_cur and h3d_lat != h3d_cur:
            q_key = f"hermes3d:{h3d_lat}"
            if q_key in quarantined:
                actions_taken.append(f"hermes3d:{h3d_lat}:quarantined_skipped")
            else:
                actions_taken.append(f"hermes3d:{h3d_cur}->{h3d_lat}:candidate_staged_compatibility_gate")
        else:
            actions_taken.append(f"hermes3d:up_to_date:{h3d_cur or 'v1.0.0'}")

        # Component D: Specialized 11-Agent Skills Idempotent Reconciliation
        try:
            from control_center.agent_skills_manager import (
                AGENT_SKILL_SPECS,
                install_all_agents_skills,
                verify_manifest,
            )

            mcheck = verify_manifest()
            if dry_run or not mcheck["ok"]:
                actions_taken.append(
                    f"agent_skills:pinned_lock_verified:{len(AGENT_SKILL_SPECS)}_agents:ok={mcheck['ok']}"
                )
            else:
                install_all_agents_skills(offline=True)
                actions_taken.append(f"agent_skills:reconciled_idempotent:{len(AGENT_SKILL_SPECS)}_agents")
        except Exception as sk_exc:
            actions_taken.append(f"agent_skills:reconcile_warning:{str(sk_exc)[:80]}")

        set_phase(st, "POST_UPDATE_TEST", "Running cross-platform functional smoke tests")
        smoke = run_post_update_smoke_tests()
        if not smoke["ok"] and not dry_run:
            set_phase(st, "NEEDS_ATTENTION", f"Post-update smoke test degraded: {smoke}")
            return {"outcome": "smoke_failed", "smoke": smoke, "state": "NEEDS_ATTENTION"}

        if not dry_run:
            st["last_completed_slot"] = win["due_slot"]
        st["next_scheduled_slot"] = win["next_slot"]
        st["last_run_at"] = now_wib().isoformat(timespec="seconds")
        st["last_result"] = "success"
        hist = st.setdefault("history", [])
        hist.append({
            "at": st["last_run_at"],
            "slot": win["due_slot"],
            "catchup": win["is_catchup"],
            "actions": actions_taken,
            "smoke": smoke,
        })
        st["history"] = hist[-20:]
        set_phase(st, "READY", f"Completed slot {win['due_slot']}: {', '.join(actions_taken)}")
        st["state"] = "IDLE"
        write_state(st)

        if notify_owner and any("updated:" in a for a in actions_taken):
            send_owner_telegram_notification(
                f"✅ [Maintenance 03:00 WIB] Completed: {', '.join(actions_taken)} | Health: OK"
            )

        return {
            "outcome": "completed",
            "slot_completed": win["due_slot"],
            "next_slot": win["next_slot"],
            "is_catchup": win["is_catchup"],
            "actions": actions_taken,
            "smoke": smoke,
            "state": "IDLE",
        }
    finally:
        MAINT_LOCK_PATH.unlink(missing_ok=True)
