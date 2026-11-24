#!/usr/bin/env python3
"""Cross-Platform Unified CLI & Health Engine (`allinagent-cli` / `ai-platform`).

Supports Ubuntu/Linux Docker & systemd production servers as well as local macOS/Windows
development environments:
- Linux host telemetry via `/proc/meminfo`, `/proc/loadavg`, `/proc/uptime`, and `shutil.disk_usage(ALLINAGENT_ROOT)`
- Windows host telemetry via native `ctypes` `GlobalMemoryStatusEx` (zero PowerShell spawn overhead)
- Service readiness probes across Paperclip (`PAPERCLIP_BASE_URL`), Office Bridge (`OFFICE_BRIDGE_URL`),
  Hermes3D (`HERMES3D_URL`), VulnClaw (`VULNCLAW_WORKER_URL` + isolated subprocess fallback), and Hermes Gateway
- Fail-closed Owner Telegram authorization (`OWNER_TELEGRAM_ID`)
- Integrated CLI commands for report PDF/DOCX export (`export-report`) and Skill Registry management (`skills`)
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

_PKG_ROOT = str(Path(__file__).resolve().parents[1])
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from control_center.findings_engine import FindingsStore
from control_center.maintenance_coordinator import (
    HERMES_UPDATER_STATE,
    MAINT_LOCK_PATH,
    get_installed_paperclip_version,
    get_installed_vulnclaw_tag,
    probe_hermes_gateway_healthy,
    read_state as read_maint_state,
    run_maintenance_cycle,
)
from control_center.paperclip_client import PaperclipClient
from control_center.paths import (
    ALLINAGENT_ROOT,
    HERMES3D_URL,
    IS_WINDOWS,
    LOGS_DIR,
    OFFICE_BRIDGE_URL,
    OWNER_TELEGRAM_ID,
    SECRETS_DIR,
    WORKSPACES_DIR,
    resolve_owner_telegram_id,
)
from control_center.vulnclaw_defensive import runtime_diagnostics, sanitize_text, scan_authorized_code
from control_center.workflow_engine import (
    WorkflowEngine,
    send_owner_telegram_notification,
)

OFFICE_BRIDGE_SECRET_PATH: Path = SECRETS_DIR / "office-bridge-auth.json"


def _collect_posix_metrics() -> dict[str, Any]:
    metrics: dict[str, Any] = {"os": platform.system().lower()}
    # 1. /proc/meminfo
    meminfo_path = Path("/proc/meminfo")
    if meminfo_path.is_file():
        kv: dict[str, int] = {}
        for ln in meminfo_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if ":" not in ln:
                continue
            k, rest = ln.split(":", 1)
            parts = rest.strip().split()
            if parts and parts[0].isdigit():
                kv[k.strip()] = int(parts[0])  # kB
        total_kb = kv.get("MemTotal", 0)
        avail_kb = kv.get("MemAvailable", kv.get("MemFree", 0))
        if total_kb > 0:
            total_mb = round(total_kb / 1024.0, 1)
            free_mb = round(avail_kb / 1024.0, 1)
            used_pct = round((1.0 - (avail_kb / total_kb)) * 100.0, 1)
            metrics.update({
                "ram_total_mb": total_mb,
                "ram_free_mb": free_mb,
                "ram_used_pct": used_pct,
            })

    # 2. /proc/loadavg
    loadavg_path = Path("/proc/loadavg")
    if loadavg_path.is_file():
        parts = loadavg_path.read_text(encoding="utf-8", errors="ignore").strip().split()
        if len(parts) >= 3:
            load_1m = float(parts[0])
            cpus = max(1, os.cpu_count() or 1)
            metrics["load_1m"] = round(load_1m, 2)
            metrics["load_5m"] = round(float(parts[1]), 2)
            metrics["load_15m"] = round(float(parts[2]), 2)
            metrics["cpu_cores"] = cpus
            metrics["cpu_pct"] = round(min(100.0, (load_1m / cpus) * 100.0), 1)

    # 3. /proc/uptime & process count
    uptime_path = Path("/proc/uptime")
    if uptime_path.is_file():
        first = uptime_path.read_text(encoding="utf-8", errors="ignore").strip().split()[0]
        metrics["uptime_minutes"] = int(float(first) // 60)

    proc_root = Path("/proc")
    if proc_root.is_dir():
        try:
            metrics["process_count"] = sum(1 for p in proc_root.iterdir() if p.name.isdigit())
        except OSError:
            pass

    return metrics


def _collect_windows_native_metrics() -> dict[str, Any]:
    metrics: dict[str, Any] = {"os": "windows", "cpu_cores": max(1, os.cpu_count() or 1)}

    class _MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    try:
        stat = _MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):  # type: ignore[attr-defined]
            metrics["ram_total_mb"] = round(stat.ullTotalPhys / (1024 * 1024), 1)
            metrics["ram_free_mb"] = round(stat.ullAvailPhys / (1024 * 1024), 1)
            metrics["ram_used_pct"] = float(stat.dwMemoryLoad)
        tick_ms = ctypes.windll.kernel32.GetTickCount64()  # type: ignore[attr-defined]
        metrics["uptime_minutes"] = int(tick_ms // 60000)
    except Exception:
        pass

    return metrics


def collect_host_metrics() -> dict[str, Any]:
    """Collect OS-neutral CPU, RAM, uptime, and `ALLINAGENT_ROOT` disk usage metrics."""
    info = _collect_windows_native_metrics() if IS_WINDOWS else _collect_posix_metrics()
    target_dir = ALLINAGENT_ROOT if ALLINAGENT_ROOT.exists() else Path.cwd()
    usage = shutil.disk_usage(target_dir)
    free_gb = round(usage.free / (1024**3), 2)
    total_gb = round(usage.total / (1024**3), 2)
    used_pct = round(((usage.total - usage.free) / usage.total) * 100.0, 1) if usage.total else 0.0
    info.update({
        "disk_root_path": str(target_dir),
        "disk_root_free_gb": free_gb,
        "disk_root_total_gb": total_gb,
        "disk_root_used_pct": used_pct,
    })
    return info


collect_windows_metrics = collect_host_metrics  # Backward-compatible function alias


def collect_unified_health(*, deep_llm: bool = False) -> dict[str, Any]:
    in_maint = MAINT_LOCK_PATH.exists() and (time.time() - MAINT_LOCK_PATH.stat().st_mtime < 5400)

    # 1. Hermes Gateway & Updater
    hermes_info = probe_hermes_gateway_healthy()

    # 2. Paperclip API
    paperclip_info: dict[str, Any] = {"healthy": False, "version": get_installed_paperclip_version()}
    try:
        pc = PaperclipClient(timeout=8.0)
        h = pc.health()
        co = pc.get_primary_company()
        cid = co["id"]
        agents = pc.list_agents(cid)
        issues = pc.list_issues(cid)
        runs = pc.list_live_runs(cid)
        budget = pc.budget_overview(cid)
        by_status: dict[str, int] = {}
        for it in issues:
            s = str(it.get("status", "unknown"))
            by_status[s] = by_status.get(s, 0) + 1
        active_agents = [a for a in agents if a.get("status") not in ("paused", "terminated")]
        paperclip_info.update({
            "healthy": h.get("status") == "ok",
            "server_status": h.get("status"),
            "commit": h.get("commit"),
            "database_backup_status": (h.get("databaseBackup") or {}).get("status"),
            "company_id": cid,
            "company_name": co.get("name"),
            "total_agents": len(agents),
            "active_agents": len(active_agents),
            "queued_or_running_runs": len(runs),
            "tasks_todo": by_status.get("todo", 0) + by_status.get("backlog", 0),
            "tasks_running": by_status.get("in_progress", 0) + by_status.get("in_review", 0),
            "tasks_completed": by_status.get("done", 0),
            "tasks_blocked": by_status.get("blocked", 0),
            "budget_overview": budget,
        })
    except Exception as exc:
        paperclip_info["error"] = sanitize_text(str(exc))[:180]

    # 3. VulnClaw isolated runtime & findings metrics
    vulnclaw_info: dict[str, Any] = {"healthy": False, "version": get_installed_vulnclaw_tag()}
    try:
        vdiag = runtime_diagnostics(verify_llm=deep_llm)
        fcounts = FindingsStore().summary_counts()
        vulnclaw_info.update({
            "healthy": bool(vdiag.get("vulnclaw_version")) and not vdiag.get("hermes_or_telegram_env_leaked") and len(vdiag.get("enabled_mcp_servers", [])) == 0,
            "version": vdiag.get("vulnclaw_version"),
            "python": vdiag.get("python_version"),
            "model": vdiag.get("configured_model"),
            "execution_mode": vdiag.get("execution_mode"),
            "isolation_verified": not vdiag.get("hermes_or_telegram_env_leaked") and len(vdiag.get("enabled_mcp_servers", [])) == 0,
            "findings": fcounts,
        })
    except Exception as exc:
        vulnclaw_info["error"] = sanitize_text(str(exc))[:180]
        try:
            vulnclaw_info["findings"] = FindingsStore().summary_counts()
        except Exception:
            pass

    # 4. Office Bridge & Hermes3D Virtual Office probes
    office_bridge_info: dict[str, Any] = {"healthy": False, "url": OFFICE_BRIDGE_URL}
    try:
        with urllib.request.urlopen(f"{OFFICE_BRIDGE_URL}/health", timeout=4) as r:
            bdata = json.loads(r.read().decode("utf-8", errors="replace"))
            office_bridge_info.update({
                "healthy": r.status == 200 and bool(bdata.get("ok")),
                "paperclip_reachable": bdata.get("paperclip_reachable"),
                "latest_sequence": bdata.get("latest_sequence"),
            })
    except Exception as exc:
        office_bridge_info["error"] = sanitize_text(str(exc))[:140]

    hermes3d_info: dict[str, Any] = {"healthy": False, "url": f"{HERMES3D_URL}/office"}
    try:
        with urllib.request.urlopen(f"{HERMES3D_URL}/api/health", timeout=4) as r:
            hermes3d_info["healthy"] = r.status == 200
    except Exception as exc:
        hermes3d_info["error"] = sanitize_text(str(exc))[:140]

    # 5. Host & service summary
    host_info = collect_host_metrics()
    services_info = {
        "hermes_gateway": {"healthy": bool(hermes_info.get("healthy")), "running": bool(hermes_info.get("gateway_running"))},
        "paperclip_server": {"healthy": bool(paperclip_info.get("healthy"))},
        "office_bridge": {"healthy": bool(office_bridge_info.get("healthy"))},
        "hermes3d": {"healthy": bool(hermes3d_info.get("healthy"))},
        "vulnclaw_defensive": {"healthy": bool(vulnclaw_info.get("healthy"))},
    }

    if in_maint:
        overall_state = "MAINTENANCE"
    elif (
        hermes_info["healthy"]
        and paperclip_info["healthy"]
        and office_bridge_info["healthy"]
        and hermes3d_info["healthy"]
    ):
        overall_state = "HEALTHY"
    elif not paperclip_info["healthy"] and not office_bridge_info["healthy"]:
        overall_state = "OFFLINE"
    else:
        overall_state = "DEGRADED"

    return {
        "platform_state": overall_state,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "hermes": hermes_info,
        "paperclip": paperclip_info,
        "vulnclaw": vulnclaw_info,
        "office_bridge": office_bridge_info,
        "hermes3d": hermes3d_info,
        "host": host_info,
        "windows": host_info,  # Legacy schema compatibility alias
        "services": services_info,
        "maintenance": read_maint_state(),
    }


OFFICE_BRIDGE_DELEGATED_COMMANDS = {
    "kantor",
    "menu",
    "menu_kantor",
    "agen",
    "pilih",
    "select_agent",
    "lepas",
    "release_agent",
    "info_agen",
    "agent_detail",
    "chat",
    "chat_agent",
    "ke",
    "ask_agent",
    "bangunkan",
    "aktifkan",
    "wake_agent",
    "istirahatkan",
    "pause_agen",
    "pause_agent",
    "stop_semua",
    "emergency_stop",
    "standar_wave1",
    "resume_wave1",
    "meeting",
    "meeting_start",
    "meeting_menu",
    "selesai_meeting",
    "meeting_end",
    "folder",
    "folders_status",
    "jelajah",
    "folder_browse",
    "pilih_folder",
    "folder_select",
    "analisis",
    "analisis_folder",
    "folder_analyze",
    "analytics",
    "biaya",
    "set_budget",
    "approvals",
    "persetujuan",
    "setujui",
    "tolak",
    "approve_id",
    "reject_id",
    "buat_task",
    "daftar_task",
    "cek_task",
    "selesai_task",
    "done_task",
    "keamanan",
    "kesehatan",
    "health_kantor",
    "inbound_text",
    "callback",
    "submenu",
    "delegasi",
    "ceo_delegasi",
    "bagi_tugas",
    "status_kantor",
    "ruangan",
    "lokasi_agen",
    "screenshot_kantor",
    "status_meeting",
    "diskusi_rapat",
    "tanya_rapat",
    "notulen",
    "riwayat_meeting",
    "cari_folder",
    "meta_folder",
    "dev",
    "dev_task",
    "git_status",
    "buat_branch",
    "jalankan_test",
    "cek_diff",
    "review_kode",
    "build_project",
    "projects",
    "buat_project",
    "pilih_project",
    "ubah_task",
    "pause_task",
    "resume_task",
    "cancel_task",
    "subtasks",
    "budget",
    "budgets",
    "triage_temuan",
    "remediasi_temuan",
    "log_error",
    "diagnosa",
    "pulihkan_layanan",
    "jobs",
    "cek_job",
    "batal_job",
    "reset_sesi",
    "pause_dispatch",
    "resume_dispatch",
}


def _resolve_office_bridge_token() -> str:
    env_tok = os.environ.get("OFFICE_BRIDGE_TOKEN", "").strip()
    if env_tok:
        return env_tok
    if OFFICE_BRIDGE_SECRET_PATH.is_file():
        sec = json.loads(OFFICE_BRIDGE_SECRET_PATH.read_text(encoding="utf-8-sig"))
        tok = str(sec.get("bridgeToken") or sec.get("token") or "").strip()
        if tok:
            return tok
    raise RuntimeError("Office Bridge secret token missing.")


def call_office_bridge_telegram(
    command: str,
    arg_text: str = "",
    *,
    caller_id: str | None = None,
    message_id: str = "",
    timeout: float = 95.0,
) -> dict[str, Any]:
    """Invoke Office Bridge's unified Telegram Control endpoint (`OFFICE_BRIDGE_URL`)."""
    resolved_caller = str(caller_id if caller_id is not None else resolve_owner_telegram_id()).strip()
    bridge_token = _resolve_office_bridge_token()

    req_body = json.dumps(
        {
            "command": command,
            "args": arg_text,
            "caller_id": resolved_caller,
            "message_id": str(message_id or ""),
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        f"{OFFICE_BRIDGE_URL}/api/office-bridge/telegram/command",
        data=req_body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bridge_token}",
            "X-Office-Caller-Id": resolved_caller,
            "X-Office-Actor-Role": "owner",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as http_err:
        raw_err = http_err.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw_err)
        except Exception:
            parsed = {"ok": False, "status": http_err.code, "error": sanitize_text(raw_err)[:240]}
        if http_err.code == 403:
            raise PermissionError(parsed.get("error") or f"Unauthorized caller '{resolved_caller}'") from http_err
        return parsed


def handle_telegram_command(
    cmd: str,
    arg_text: str = "",
    *,
    caller_id: str | None = None,
    message_id: str = "",
) -> dict[str, Any]:
    """Execute Telegram platform & Virtual Office commands with fail-closed Owner auth & idempotency."""
    resolved_caller = str(caller_id if caller_id is not None else resolve_owner_telegram_id()).strip()
    wf = WorkflowEngine()
    wf.assert_owner_authorized(resolved_caller, f"telegram:{cmd}")

    raw_cmd = cmd.strip()
    c = raw_cmd.lower().lstrip("/").replace("-", "_")
    if raw_cmd.startswith("uac:") or c in OFFICE_BRIDGE_DELEGATED_COMMANDS:
        return call_office_bridge_telegram(
            raw_cmd if raw_cmd.startswith("uac:") else c,
            arg_text,
            caller_id=resolved_caller,
            message_id=message_id,
        )

    if c == "help_platform":
        return call_office_bridge_telegram("kantor", "", caller_id=resolved_caller, message_id=message_id)

    if c == "platform_status":
        h = collect_unified_health(deep_llm=False)
        pc = h["paperclip"]
        hm = h["hermes"]
        vc = h["vulnclaw"]
        hs = h["host"]
        msg = (
            f"📊 *Platform Status: {h['platform_state']}*\n"
            f"• *Hermes:* `{'OK' if hm.get('healthy') else 'DEGRADED'}` (commit `{str(hm.get('installed_commit',''))[:8]}`, running=`{hm.get('gateway_running')}`)\n"
            f"• *Paperclip:* `{'OK' if pc.get('healthy') else 'OFFLINE'}` (`v{pc.get('version')}`, Active Agents=`{pc.get('active_agents')}/{pc.get('total_agents')}`, Done=`{pc.get('tasks_completed')}`, Running=`{pc.get('tasks_running')}`)\n"
            f"• *VulnClaw (Defensive):* `{'OK' if vc.get('healthy') else 'DEGRADED'}` (`v{vc.get('version')}`, Findings=`{(vc.get('findings') or {}).get('total', 0)}`)\n"
            f"• *Host:* CPU `{hs.get('cpu_pct', 'N/A')}%` | RAM `{hs.get('ram_free_mb', 'N/A')} MB` free | Disk `{hs.get('disk_root_free_gb')} GB` free"
        )
        return {"ok": True, "reply": msg, "data": h}

    pc = PaperclipClient()
    cid = pc.get_primary_company()["id"]

    if c == "agents":
        agents = pc.list_agents(cid)
        lines = ["👥 *Organization Agents*"]
        for a in agents:
            lines.append(f"• `{a.get('name')}` (`{a.get('role')}`) — status: `{a.get('status')}` | budget: `{a.get('budgetMonthlyCents', 0)}¢`")
        return {"ok": True, "reply": "\n".join(lines), "count": len(agents)}

    if c == "projects":
        projs = pc.list_projects(cid)
        lines = ["📁 *Paperclip Projects*"]
        for p in projs:
            lines.append(f"• `{p.get('name')}` (`{p['id'][:8]}`) — status: `{p.get('status')}`")
        return {"ok": True, "reply": "\n".join(lines), "count": len(projs)}

    if c == "tasks":
        issues = pc.list_issues(cid)[:15]
        lines = ["📋 *Recent Paperclip Tasks*"]
        for it in issues:
            lines.append(f"• `{it.get('identifier') or it['id'][:8]}` [{it.get('status')}] — {sanitize_text(str(it.get('title', ''))[:70])}")
        return {"ok": True, "reply": "\n".join(lines), "count": len(issues)}

    if c == "task_status":
        issue = wf.resolve_issue(pc, arg_text)
        comments = pc.list_issue_comments(issue["id"])
        last_comment = sanitize_text(str(comments[-1].get("body", ""))[:240]) if comments else "No comments yet."
        msg = (
            f"🔎 *Task `{issue.get('identifier') or issue['id'][:8]}`*\n"
            f"• *Title:* {sanitize_text(str(issue.get('title', '')))}\n"
            f"• *Status:* `{issue.get('status')}` | *Priority:* `{issue.get('priority')}`\n"
            f"• *Assignee:* `{issue.get('assigneeAgentId') or 'unassigned'}`\n"
            f"• *Latest Note:* {last_comment}"
        )
        return {"ok": True, "reply": msg, "issue": issue}

    if c == "create_task":
        raw = arg_text.strip()
        if not raw:
            raise ValueError("Usage: /create_task <title> | <description>")
        if "|" in raw:
            t_part, d_part = [x.strip() for x in raw.split("|", 1)]
        else:
            t_part, d_part = raw[:90], raw
        idem = f"tg:{resolved_caller}:{message_id}" if message_id else f"tg-sha:{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:20]}"
        projs = pc.list_projects(cid)
        proj_id = projs[0]["id"] if projs else None
        sub = wf.submit_task(
            caller_id=resolved_caller,
            title=t_part,
            description=d_part,
            role_slug="ceo_agent",
            priority="high",
            project_id=proj_id,
            idempotency_key=idem,
        )
        t_rec = sub["task"]
        ident = t_rec.get("paperclip_identifier") or t_rec["paperclip_issue_id"][:8]
        dup_note = " *(idempotent: existing task returned)*" if sub["deduplicated"] else ""
        msg = (
            f"✅ *Task Registered in Paperclip*{dup_note}\n"
            f"• *Task ID:* `{ident}` (`{t_rec['paperclip_issue_id']}`)\n"
            f"• *Stage:* `{t_rec['workflow_stage']}` -> Assigned Role: `{t_rec['assigned_role']}`"
        )
        return {"ok": True, "reply": msg, "submission": sub}

    if c == "pause_task":
        res = wf.update_stage(arg_text, "BLOCKED", caller_id=resolved_caller, comment="Paused by Owner via Telegram.")
        return {"ok": True, "reply": f"⏸️ Task `{res.get('identifier') or res['issue_id'][:8]}` paused (`BLOCKED`).", "result": res}

    if c == "resume_task":
        res = wf.update_stage(arg_text, "ASSIGNED", caller_id=resolved_caller, comment="Resumed by Owner via Telegram.")
        return {"ok": True, "reply": f"▶️ Task `{res.get('identifier') or res['issue_id'][:8]}` resumed (`ASSIGNED` / `todo`).", "result": res}

    if c == "cancel_task":
        res = wf.update_stage(arg_text, "CANCELLED", caller_id=resolved_caller, comment="Cancelled by Owner via Telegram.")
        return {"ok": True, "reply": f"🛑 Task `{res.get('identifier') or res['issue_id'][:8]}` cancelled (`CANCELLED`).", "result": res}

    if c == "security_report":
        fstore = FindingsStore()
        scan_note = ""
        if arg_text.strip():
            target = (WORKSPACES_DIR / arg_text.strip()) if not Path(arg_text.strip()).is_absolute() else Path(arg_text.strip())
            sc = scan_authorized_code(target)
            f_list = sc["scan_json"].get("findings", [])
            scan_note = f"\n• *Live Static Scan (`{target.name}`):* `{len(f_list)}` findings analyzed."
        counts = fstore.summary_counts()
        msg = (
            f"🛡️ *Defensive Security Findings Summary*\n"
            f"• *Total Findings:* `{counts['total']}`\n"
            f"• *Under Review:* `{counts['under_review']}` | *Active/Confirmed:* `{counts['confirmed']}`\n"
            f"• *False Positives:* `{counts['false_positive']}` | *Resolved:* `{counts['resolved']}`{scan_note}"
        )
        return {"ok": True, "reply": msg, "counts": counts}

    if c == "update_status":
        ms = read_maint_state()
        au = json.loads(HERMES_UPDATER_STATE.read_text(encoding="utf-8-sig")) if HERMES_UPDATER_STATE.exists() else {}
        msg = (
            f"🕒 *Coordinated Daily Auto-Update (03:00 WIB)*\n"
            f"• *Hermes Updater:* `{au.get('schedule_mode', 'daily')}` (`last_slot={au.get('last_daily_slot_completed')}`, `next={au.get('next_check')}`)\n"
            f"• *Platform Coordinator:* state=`{ms.get('state')}`, `last_slot={ms.get('last_completed_slot')}`, `next={ms.get('next_scheduled_slot')}`"
        )
        return {"ok": True, "reply": msg, "maintenance": ms}

    raise ValueError(f"Unknown platform command: {cmd}")


def emergency_stop_all() -> dict[str, Any]:
    """Governance emergency stop: cancel all live/queued Paperclip runs & pause active worker agents."""
    pc = PaperclipClient()
    cid = pc.get_primary_company()["id"]
    cancelled_runs: list[str] = []
    for r in pc.list_runs(cid, limit=40):
        if r.get("status") in ("queued", "running"):
            pc.cancel_run(r["id"])
            cancelled_runs.append(r["id"])
    targets = [a for a in pc.list_agents(cid) if a.get("status") not in ("paused", "terminated")]
    for a in targets:
        pc.request("POST", f"/api/agents/{a['id']}/pause", {})
    dl = time.time() + 25.0
    while time.time() < dl:
        cur = {a["id"]: a for a in pc.list_agents(cid)}
        if all(cur.get(t["id"], {}).get("status") == "paused" for t in targets):
            break
        time.sleep(0.8)
    return {"cancelled_runs": cancelled_runs, "paused_agents": [t["name"] for t in targets]}


def resume_wave1_agents() -> dict[str, Any]:
    """Resume the 4 Wave-1 core agents after an emergency stop."""
    node_bin = shutil.which("node")
    fix_cjs = ALLINAGENT_ROOT / "scripts" / "clear-orphan-cancelled-runs.cjs"
    if node_bin and fix_cjs.is_file():
        subprocess.run([node_bin, str(fix_cjs)], capture_output=True, timeout=10, check=False)
    pc = PaperclipClient()
    cid = pc.get_primary_company()["id"]
    wave1 = {"CEO Agent", "Backend Developer", "QA Engineer", "Security Reviewer"}
    dl_wait = time.time() + 15.0
    while time.time() < dl_wait:
        rows = [a for a in pc.list_agents(cid) if a.get("name") in wave1]
        if not any(a.get("lifecycleState") in ("pausing", "stopping") for a in rows):
            break
        time.sleep(0.8)
    targets = [a for a in pc.list_agents(cid) if a.get("name") in wave1 and a.get("status") == "paused"]
    for a in targets:
        pc.request("POST", f"/api/agents/{a['id']}/resume", {})
    dl = time.time() + 25.0
    while time.time() < dl:
        cur = {a["id"]: a for a in pc.list_agents(cid)}
        if all(cur.get(t["id"], {}).get("status") != "paused" for t in targets):
            break
        time.sleep(0.8)
    return {"resumed_agents": [t["name"] for t in targets]}


def main() -> int:
    parser = argparse.ArgumentParser(prog="allinagent-cli", description="ALLINAGENT Cross-Platform Control Center CLI")
    sub = parser.add_subparsers(dest="subcmd", required=True)

    for name in ("status", "health", "services", "agents", "tasks", "updates", "host"):
        p = sub.add_parser(name)
        p.add_argument("--json", action="store_true")

    p_logs = sub.add_parser("logs")
    p_logs.add_argument("--tail", type=int, default=30)

    p_tg = sub.add_parser("telegram-cmd")
    p_tg.add_argument("command")
    p_tg.add_argument("--args", default="")
    p_tg.add_argument("--caller-id", default=OWNER_TELEGRAM_ID)
    p_tg.add_argument("--message-id", default="")
    p_tg.add_argument("--notify", action="store_true")

    p_rep = sub.add_parser("export-report")
    p_rep.add_argument("markdown_file")
    p_rep.add_argument("--out-dir", default=None)
    p_rep.add_argument("--deliver-telegram", action="store_true")

    sub.add_parser("emergency-stop")
    sub.add_parser("resume-wave1")
    p_maint = sub.add_parser("run-maintenance")
    p_maint.add_argument("--force", action="store_true")
    p_maint.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    if args.subcmd == "host":
        print(json.dumps(collect_host_metrics(), indent=2))
        return 0

    if args.subcmd in ("status", "health"):
        data = collect_unified_health(deep_llm=False)
        if getattr(args, "json", False):
            print(json.dumps(data, indent=2))
        else:
            print(f"Unified Platform State : {data['platform_state']} ({data['checked_at']})")
            print(f"  Hermes Agent         : healthy={data['hermes'].get('healthy')} running={data['hermes'].get('gateway_running')}")
            print(f"  Paperclip Control    : healthy={data['paperclip'].get('healthy')} v{data['paperclip'].get('version')} agents={data['paperclip'].get('active_agents')}/{data['paperclip'].get('total_agents')}")
            print(f"  VulnClaw Defensive   : healthy={data['vulnclaw'].get('healthy')} v{data['vulnclaw'].get('version')} findings={(data['vulnclaw'].get('findings') or {}).get('total', 0)}")
            hs = data["host"]
            print(f"  Host Telemetry       : OS={hs.get('os')} CPU={hs.get('cpu_pct', 'N/A')}% RAM_free={hs.get('ram_free_mb')}MB Disk_free={hs.get('disk_root_free_gb')}GB")
        return 0 if data["platform_state"] in ("HEALTHY", "MAINTENANCE") else 1

    if args.subcmd == "services":
        print(json.dumps(collect_unified_health(deep_llm=False)["services"], indent=2))
        return 0

    if args.subcmd == "agents":
        pc = PaperclipClient()
        cid = pc.get_primary_company()["id"]
        rows = pc.list_agents(cid)
        if getattr(args, "json", False):
            print(json.dumps(rows, indent=2))
        else:
            for a in rows:
                print(f"{a['name']:<28} role={str(a.get('role')):<10} status={str(a.get('status')):<8} budget={a.get('budgetMonthlyCents',0)}c")
        return 0

    if args.subcmd == "tasks":
        pc = PaperclipClient()
        cid = pc.get_primary_company()["id"]
        rows = pc.list_issues(cid)
        if getattr(args, "json", False):
            print(json.dumps(rows, indent=2))
        else:
            for it in rows[:25]:
                print(f"{str(it.get('identifier') or it['id'][:8]):<10} [{str(it.get('status')):<11}] {sanitize_text(str(it.get('title',''))[:68])}")
        return 0

    if args.subcmd == "updates":
        out = {
            "platform_coordinator": read_maint_state(),
            "hermes_updater": json.loads(HERMES_UPDATER_STATE.read_text(encoding="utf-8-sig")) if HERMES_UPDATER_STATE.exists() else {},
        }
        print(json.dumps(out, indent=2))
        return 0

    if args.subcmd == "logs":
        for log_file in (LOGS_DIR / "paperclip.log", LOGS_DIR / "paperclip-launcher.log"):
            if log_file.is_file():
                lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()[-args.tail :]
                for ln in lines:
                    print(sanitize_text(ln))
                break
        return 0

    if args.subcmd == "telegram-cmd":
        res = handle_telegram_command(args.command, args.args, caller_id=args.caller_id, message_id=args.message_id)
        if args.notify and res.get("reply"):
            markup = {"inline_keyboard": res["inline_keyboard"]} if isinstance(res.get("inline_keyboard"), list) else None
            res["telegram_delivery"] = send_owner_telegram_notification(
                res["reply"],
                reply_markup=markup,
                parse_mode="Markdown",
            )
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0

    if args.subcmd == "export-report":
        from control_center.report_exporter import export_markdown_to_pdf_and_docx

        print(
            json.dumps(
                export_markdown_to_pdf_and_docx(
                    args.markdown_file,
                    args.out_dir,
                    deliver_telegram=args.deliver_telegram,
                ),
                indent=2,
            )
        )
        return 0

    if args.subcmd == "emergency-stop":
        print(json.dumps(emergency_stop_all(), indent=2))
        return 0

    if args.subcmd == "resume-wave1":
        print(json.dumps(resume_wave1_agents(), indent=2))
        return 0

    if args.subcmd == "run-maintenance":
        print(json.dumps(run_maintenance_cycle(force=args.force, dry_run=args.dry_run), indent=2))
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
