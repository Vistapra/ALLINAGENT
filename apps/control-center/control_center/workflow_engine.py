#!/usr/bin/env python3
"""Cross-Platform Central Task Lifecycle, Workflow Engine, Idempotency & Telegram Bridge."""
from __future__ import annotations

import contextlib
import hashlib
import json
import mimetypes
import os
import sqlite3
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from control_center.paperclip_client import PaperclipClient
from control_center.paths import (
    CONFIG_DIR,
    DATA_DIR,
    OWNER_TELEGRAM_ID,
    ROSTER_JSON_PATH,
    WORKSPACES_DIR,
    is_owner_authorized,
    require_owner_telegram_id,
    resolve_owner_telegram_id,
    resolve_roster_read_paths,
)
from control_center.vulnclaw_defensive import sanitize_text

WORKFLOW_DB_PATH: Path = DATA_DIR / "workflow-ledger.db"
ROSTER_PATH: Path = ROSTER_JSON_PATH
LIMITS_PATH: Path = CONFIG_DIR / "resource-limits.json"
AUTHORIZED_OWNER_ID: str = OWNER_TELEGRAM_ID  # Legacy compatibility alias

WORKFLOW_TO_PAPERCLIP_STATUS: dict[str, str] = {
    "RECEIVED": "backlog",
    "TRIAGED": "backlog",
    "PLANNED": "todo",
    "PENDING_APPROVAL": "blocked",
    "ASSIGNED": "todo",
    "IN_PROGRESS": "in_progress",
    "IN_REVIEW": "in_review",
    "IN_TESTING": "in_review",
    "READY_FOR_ACCEPTANCE": "in_review",
    "COMPLETED": "done",
    "FAILED": "blocked",
    "BLOCKED": "blocked",
    "CANCELLED": "cancelled",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def classify_owner_instruction(text: str) -> str:
    """Classify natural-language or slash instruction into canonical operational categories."""
    t = (text or "").strip().lower()
    if t.startswith(("/approve", "/deny")) or any(k in t for k in ("setujui", "izinkan tindakan", "approve request")):
        return "approval_request"
    if t.startswith(("/platform_status", "/update_status")) or any(k in t for k in ("status platform", "kesehatan sistem", "health check", "status hermes")):
        return "system_health"
    if t.startswith(("/task_status", "/tasks")) or any(k in t for k in ("status task", "progress task", "daftar task")):
        return "task_status"
    if t.startswith(("/security_report",)) or any(k in t for k in ("audit keamanan", "review keamanan", "vulnclaw", "security review", "temuan keamanan")):
        return "defensive_security_review"
    if t.startswith(("/projects", "/agents", "/pause_task", "/resume_task", "/cancel_task")):
        return "project_management"
    if t.startswith("/create_task") or any(k in t for k in ("buat aplikasi", "implementasi fitur", "refactor", "delegasikan", "perbaiki bug", "jalur branch", "unit test")):
        return "software_development"
    if any(k in t for k in ("buka aplikasi", "screenshot", "kapasitas drive", "proses host", "proses sistem", "buka browser")):
        return "host_operational"
    return "personal_assistant"


class WorkflowEngine:
    def __init__(self, db_path: Path = WORKFLOW_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS task_ledger (
                    task_uuid TEXT PRIMARY KEY,
                    paperclip_issue_id TEXT NOT NULL UNIQUE,
                    paperclip_identifier TEXT,
                    idempotency_key TEXT UNIQUE,
                    parent_issue_id TEXT,
                    delegation_depth INTEGER NOT NULL DEFAULT 0,
                    assigned_role TEXT,
                    assigned_agent_id TEXT,
                    priority TEXT NOT NULL,
                    scope_path TEXT,
                    dependencies_json TEXT NOT NULL DEFAULT '[]',
                    acceptance_criteria TEXT,
                    workflow_stage TEXT NOT NULL,
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    last_run_id TEXT,
                    evidence_json TEXT NOT NULL DEFAULT '{}',
                    owner_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    caller_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    detail TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )

    def assert_owner_authorized(self, caller_id: str | int | None, action: str) -> None:
        cid = str(caller_id if caller_id is not None else "").strip()
        configured_owner = resolve_owner_telegram_id()
        allowed = bool(configured_owner) and is_owner_authorized(cid)
        detail = "owner_check" if configured_owner else "fail_closed_owner_unconfigured"
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO auth_audit_log (caller_id, action, allowed, detail, created_at) VALUES (?, ?, ?, ?, ?)",
                (cid or "anonymous", action, 1 if allowed else 0, detail, _now_iso()),
            )
        if not configured_owner:
            raise PermissionError(
                "OWNER_TELEGRAM_ID is not configured (fail-closed security policy). Access denied."
            )
        if not allowed:
            raise PermissionError(
                f"Unauthorized caller ID '{cid}'. Access restricted exclusively to the configured Owner."
            )

    def _load_limits(self) -> dict[str, Any]:
        if LIMITS_PATH.exists():
            return json.loads(LIMITS_PATH.read_text(encoding="utf-8")).get("limits", {})
        return {
            "max_delegation_depth": 2,
            "max_subtasks_per_parent": 6,
            "max_retries_per_task": 2,
            "max_parallel_engineering_tasks": 1,
        }

    def _load_roster(self) -> dict[str, Any]:
        for cand in resolve_roster_read_paths(ROSTER_PATH):
            if cand.is_file():
                try:
                    return json.loads(cand.read_text(encoding="utf-8"))
                except Exception:
                    continue
        return {"agents": {}}

    def _check_no_cycle(self, issue_id: str, depends_on: list[str]) -> None:
        with self._connect() as conn:
            visited: set[str] = {issue_id}
            stack = list(depends_on)
            while stack:
                cur = stack.pop()
                if cur in visited:
                    raise ValueError(f"Circular task dependency detected involving {cur}")
                visited.add(cur)
                row = conn.execute("SELECT dependencies_json FROM task_ledger WHERE paperclip_issue_id = ?", (cur,)).fetchone()
                if row:
                    stack.extend(json.loads(row["dependencies_json"] or "[]"))

    def submit_task(
        self,
        *,
        caller_id: str,
        title: str,
        description: str,
        role_slug: str = "ceo_agent",
        priority: str = "medium",
        project_id: str | None = None,
        parent_issue_id: str | None = None,
        scope_path: str | None = None,
        acceptance_criteria: str = "All requested outputs verified with exit code 0 and zero out-of-scope changes.",
        dependencies: list[str] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        self.assert_owner_authorized(caller_id, "submit_task")
        limits = self._load_limits()
        deps = dependencies or []

        if idempotency_key:
            with self._connect() as conn:
                dup = conn.execute("SELECT * FROM task_ledger WHERE idempotency_key = ?", (idempotency_key,)).fetchone()
                if dup:
                    return {"deduplicated": True, "task": dict(dup)}

        depth = 0
        if parent_issue_id:
            with self._connect() as conn:
                prow = conn.execute("SELECT delegation_depth FROM task_ledger WHERE paperclip_issue_id = ?", (parent_issue_id,)).fetchone()
                depth = (int(prow["delegation_depth"]) + 1) if prow else 1
                if depth > int(limits.get("max_delegation_depth", 2)):
                    raise ValueError(f"Delegation depth {depth} exceeds limit {limits.get('max_delegation_depth', 2)}")
                child_cnt = conn.execute("SELECT COUNT(*) FROM task_ledger WHERE parent_issue_id = ?", (parent_issue_id,)).fetchone()[0]
                if int(child_cnt) >= int(limits.get("max_subtasks_per_parent", 6)):
                    raise ValueError(f"Subtask count for parent {parent_issue_id} reached cap {limits.get('max_subtasks_per_parent', 6)}")

        pc = PaperclipClient()
        roster = self._load_roster()
        company = pc.get_primary_company()
        cid = company["id"]

        agent_entry = roster.get("agents", {}).get(role_slug)
        assignee_id = agent_entry["id"] if agent_entry else None

        initial_stage = "ASSIGNED" if assignee_id else "TRIAGED"
        if deps:
            for dep_id in deps:
                dep_issue = pc.get_issue(dep_id)
                if dep_issue.get("status") != "done":
                    initial_stage = "PLANNED"
                    break

        pc_status = WORKFLOW_TO_PAPERCLIP_STATUS[initial_stage] if initial_stage != "PLANNED" else "backlog"
        safe_title = sanitize_text(title.strip())[:200]
        safe_desc = sanitize_text(description.strip())
        resolved_scope = scope_path or WORKSPACES_DIR.as_posix()
        full_body = (
            f"{safe_desc}\n\n"
            f"---\n"
            f"- **Workflow Stage:** `{initial_stage}`\n"
            f"- **Authorized Scope:** `{resolved_scope}`\n"
            f"- **Acceptance Criteria:** {sanitize_text(acceptance_criteria)}\n"
        )

        payload: dict[str, Any] = {
            "title": safe_title,
            "description": full_body,
            "status": pc_status,
            "priority": priority if priority in ("critical", "high", "medium", "low") else "medium",
        }
        if project_id:
            payload["projectId"] = project_id
        if parent_issue_id:
            payload["parentId"] = parent_issue_id
        if assignee_id and pc_status != "backlog":
            payload["assigneeAgentId"] = assignee_id

        idem_hdr = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:32] if idempotency_key else None
        created = pc.create_issue(cid, payload, idempotency_key=idem_hdr)

        if deps:
            self._check_no_cycle(created["id"], deps)

        now = _now_iso()
        with self._connect() as conn:
            existing_issue = conn.execute(
                "SELECT * FROM task_ledger WHERE paperclip_issue_id = ?", (created["id"],)
            ).fetchone()
            if existing_issue:
                return {"deduplicated": True, "task": dict(existing_issue), "paperclip_issue": created}
            conn.execute(
                """
                INSERT INTO task_ledger (
                    task_uuid, paperclip_issue_id, paperclip_identifier, idempotency_key,
                    parent_issue_id, delegation_depth, assigned_role, assigned_agent_id,
                    priority, scope_path, dependencies_json, acceptance_criteria,
                    workflow_stage, retry_count, last_run_id, evidence_json, owner_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, '{}', ?, ?, ?)
                """,
                (
                    created["id"],
                    created["id"],
                    created.get("identifier"),
                    idempotency_key,
                    parent_issue_id,
                    depth,
                    role_slug,
                    assignee_id,
                    payload["priority"],
                    str(scope_path or WORKSPACES_DIR),
                    json.dumps(deps),
                    acceptance_criteria,
                    initial_stage,
                    str(caller_id),
                    now,
                    now,
                ),
            )
            row = dict(conn.execute("SELECT * FROM task_ledger WHERE paperclip_issue_id = ?", (created["id"],)).fetchone())

        return {"deduplicated": False, "task": row, "paperclip_issue": created}

    def update_stage(
        self,
        issue_ref: str,
        new_stage: str,
        *,
        caller_id: str | None = None,
        evidence: dict[str, Any] | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        resolved_caller = caller_id if caller_id is not None else resolve_owner_telegram_id()
        self.assert_owner_authorized(resolved_caller, f"update_stage:{new_stage}")
        if new_stage not in WORKFLOW_TO_PAPERCLIP_STATUS:
            raise ValueError(f"Unsupported workflow stage: {new_stage}")
        pc = PaperclipClient()
        issue = self.resolve_issue(pc, issue_ref)
        iid = issue["id"]
        pc_status = WORKFLOW_TO_PAPERCLIP_STATUS[new_stage]

        patch: dict[str, Any] = {"status": pc_status}
        if pc_status == "blocked":
            patch["unblockDescriptor"] = {
                "owner": "board",
                "action": sanitize_text(comment or f"Awaiting Owner review/unblock for stage {new_stage}.")[:500],
            }
        else:
            patch["unblockDescriptor"] = None
        if comment:
            patch["comment"] = sanitize_text(comment)
        updated_issue = pc.update_issue(iid, patch)

        if new_stage == "CANCELLED":
            cid = updated_issue["companyId"]
            for run in pc.list_live_runs(cid):
                if run.get("agentId") == updated_issue.get("assigneeAgentId"):
                    pc.cancel_run(run["id"])

        now = _now_iso()
        with self._connect() as conn:
            existing = conn.execute("SELECT * FROM task_ledger WHERE paperclip_issue_id = ?", (iid,)).fetchone()
            if existing:
                merged_ev = json.loads(existing["evidence_json"] or "{}")
                if evidence:
                    merged_ev.update(evidence)
                conn.execute(
                    "UPDATE task_ledger SET workflow_stage = ?, evidence_json = ?, updated_at = ? WHERE paperclip_issue_id = ?",
                    (new_stage, json.dumps(merged_ev), now, iid),
                )
        return {"issue_id": iid, "identifier": updated_issue.get("identifier"), "workflow_stage": new_stage, "paperclip_status": pc_status}

    def retry_task(self, issue_ref: str, *, caller_id: str | None = None) -> dict[str, Any]:
        resolved_caller = caller_id if caller_id is not None else resolve_owner_telegram_id()
        self.assert_owner_authorized(resolved_caller, "retry_task")
        limits = self._load_limits()
        max_retries = int(limits.get("max_retries_per_task", 2))
        pc = PaperclipClient()
        issue = self.resolve_issue(pc, issue_ref)
        iid = issue["id"]
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM task_ledger WHERE paperclip_issue_id = ?", (iid,)).fetchone()
            if row:
                rc = int(row["retry_count"])
                if rc >= max_retries:
                    raise RuntimeError(f"Retry limit ({max_retries}) reached for task {issue.get('identifier') or iid}; manual review required.")
                conn.execute(
                    "UPDATE task_ledger SET retry_count = ?, workflow_stage = 'IN_PROGRESS', updated_at = ? WHERE paperclip_issue_id = ?",
                    (rc + 1, _now_iso(), iid),
                )
        pc.update_issue(iid, {"status": "todo"})
        if issue.get("assigneeAgentId"):
            try:
                pc.wake_agent(issue["assigneeAgentId"], {"source": "on_demand", "trigger": "manual"})
            except Exception:
                pass
        return {"retried": True, "issue_id": iid, "identifier": issue.get("identifier")}

    @staticmethod
    def resolve_issue(pc: PaperclipClient, issue_ref: str) -> dict[str, Any]:
        ref = issue_ref.strip()
        try:
            return pc.get_issue(ref)
        except Exception:
            cid = pc.get_primary_company()["id"]
            for it in pc.list_issues(cid):
                if str(it.get("identifier", "")).upper() == ref.upper() or it["id"].startswith(ref):
                    return it
            raise KeyError(f"Task not found: {issue_ref}")

    def reconcile_tasks(self) -> dict[str, Any]:
        """Reconcile ledger stages against Paperclip DB & unblock dependent tasks when prerequisites complete."""
        pc = PaperclipClient()
        cid = pc.get_primary_company()["id"]
        issues_by_id = {i["id"]: i for i in pc.list_issues(cid)}
        unblocked = 0
        synced = 0
        roster = self._load_roster()
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM task_ledger").fetchall()
            for r in rows:
                iid = r["paperclip_issue_id"]
                pc_issue = issues_by_id.get(iid)
                if not pc_issue:
                    continue
                if pc_issue.get("status") == "done" and r["workflow_stage"] != "COMPLETED":
                    conn.execute(
                        "UPDATE task_ledger SET workflow_stage = 'COMPLETED', updated_at = ? WHERE paperclip_issue_id = ?",
                        (_now_iso(), iid),
                    )
                    synced += 1
                elif r["workflow_stage"] == "PLANNED":
                    deps = json.loads(r["dependencies_json"] or "[]")
                    if deps and all(issues_by_id.get(d, {}).get("status") == "done" for d in deps):
                        ag_id = r["assigned_agent_id"] or roster.get("agents", {}).get(r["assigned_role"] or "", {}).get("id")
                        patch: dict[str, Any] = {"status": "todo"}
                        if ag_id:
                            patch["assigneeAgentId"] = ag_id
                        pc.update_issue(iid, patch)
                        conn.execute(
                            "UPDATE task_ledger SET workflow_stage = 'ASSIGNED', updated_at = ? WHERE paperclip_issue_id = ?",
                            (_now_iso(), iid),
                        )
                        unblocked += 1
        return {"synced_completed": synced, "dependencies_unblocked": unblocked}


def _resolve_telegram_bot_token() -> str:
    tok = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if tok:
        return tok
    explicit_env = os.environ.get("HERMES_GATEWAY_ENV_FILE", "").strip()
    if explicit_env and Path(explicit_env).is_file():
        for ln in Path(explicit_env).read_text(encoding="utf-8", errors="ignore").splitlines():
            if ln.strip().startswith("TELEGRAM_BOT_TOKEN="):
                return ln.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def send_owner_telegram_notification(
    message: str,
    *,
    reply_markup: dict[str, Any] | None = None,
    parse_mode: str | None = None,
) -> dict[str, Any]:
    """Send a strictly sanitized status/completion report to the configured Owner ONLY.

    Uses one-shot HTTPS `sendMessage` (never `getUpdates`), so it never competes with Gateway polling.
    """
    owner_id = resolve_owner_telegram_id()
    if not owner_id:
        return {"sent": False, "reason": "owner_id_not_configured"}
    bot_token = _resolve_telegram_bot_token()
    if not bot_token:
        return {"sent": False, "reason": "no_token"}

    safe_msg = sanitize_text(message)[:3900]
    body_dict: dict[str, Any] = {
        "chat_id": owner_id,
        "text": safe_msg,
        "disable_web_page_preview": True,
    }
    if reply_markup and isinstance(reply_markup, dict):
        body_dict["reply_markup"] = reply_markup
    if parse_mode:
        body_dict["parse_mode"] = parse_mode

    req = urllib.request.Request(
        f"https://api.telegram.org/bot{bot_token}/sendMessage",
        data=json.dumps(body_dict).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
            return {"sent": bool(body.get("ok")), "message_id": (body.get("result") or {}).get("message_id")}
    except Exception as exc:
        if parse_mode:
            body_dict.pop("parse_mode", None)
            try:
                req2 = urllib.request.Request(
                    f"https://api.telegram.org/bot{bot_token}/sendMessage",
                    data=json.dumps(body_dict).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req2, timeout=12) as resp2:
                    body2 = json.loads(resp2.read().decode("utf-8", errors="replace"))
                    return {"sent": bool(body2.get("ok")), "message_id": (body2.get("result") or {}).get("message_id")}
            except Exception:
                pass
        return {"sent": False, "reason": sanitize_text(str(exc))[:120]}


def send_owner_telegram_document(
    file_path: str | Path,
    *,
    caption: str = "",
) -> dict[str, Any]:
    """Deliver an exported compliance PDF/DOCX document (`FEAT-28`) to the configured Owner via `sendDocument`."""
    owner_id = resolve_owner_telegram_id()
    if not owner_id:
        return {"sent": False, "reason": "owner_id_not_configured"}
    bot_token = _resolve_telegram_bot_token()
    if not bot_token:
        return {"sent": False, "reason": "no_token"}

    fpath = Path(file_path).resolve()
    lower = fpath.name.lower()
    if lower.startswith(".env") or "secret" in lower or "auth.json" in lower:
        raise PermissionError("Refusing to transmit protected credential file via Telegram.")
    if fpath.suffix.lower() not in (".pdf", ".docx", ".md", ".json", ".txt"):
        raise ValueError(f"Unsupported report document extension: {fpath.suffix}")
    if not fpath.is_file():
        raise FileNotFoundError(f"Report document not found: {fpath}")

    boundary = f"----ALLINAGENTBoundary{uuid.uuid4().hex}"
    mime_type = mimetypes.guess_type(fpath.name)[0] or "application/octet-stream"
    safe_caption = sanitize_text(caption)[:950]

    parts: list[bytes] = []
    for field_name, field_val in (("chat_id", owner_id), ("caption", safe_caption)):
        if not field_val and field_name == "caption":
            continue
        parts.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{field_name}"\r\n\r\n'
                f"{field_val}\r\n"
            ).encode("utf-8")
        )
    parts.append(
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="document"; filename="{fpath.name}"\r\n'
            f"Content-Type: {mime_type}\r\n\r\n"
        ).encode("utf-8")
        + fpath.read_bytes()
        + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))
    body_bytes = b"".join(parts)

    req = urllib.request.Request(
        f"https://api.telegram.org/bot{bot_token}/sendDocument",
        data=body_bytes,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            parsed = json.loads(resp.read().decode("utf-8", errors="replace"))
            return {"sent": bool(parsed.get("ok")), "message_id": (parsed.get("result") or {}).get("message_id")}
    except Exception as exc:
        return {"sent": False, "reason": sanitize_text(str(exc))[:120]}
