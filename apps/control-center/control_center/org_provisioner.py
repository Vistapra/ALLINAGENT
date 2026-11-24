#!/usr/bin/env python3
"""Cross-platform Organization Provisioner & Track-B Path Migrator for ALLINAGENT.

Supports:
1. Dynamic `DEFAULT_LLM_MODEL` (never hardcoded `"combo/X"`).
2. Role-scoped `"skills"` toolsets across all 11 corporate agents:
   - `file,terminal,skills` for CEO, CTO, Backend, Frontend, DevOps, QA, and Report & Compliance.
   - `file,skills` (read-only defensive posture) for Security Lead, Security Reviewer,
     Findings Analyst, and Remediation Reviewer.
3. Configurable budget governance:
   - `ALLINAGENT_BUDGET_MODE=unlimited`: `amount=0, isActive=False, hardStopEnabled=False, unpricedUsagePolicy="allow"`
   - `ALLINAGENT_BUDGET_MODE=capped`: `ALLINAGENT_COMPANY_MONTHLY_CENTS` + per-agent caps,
     with `unpricedUsagePolicy="allow"` unless `STRICT_PRICED_BUDGET=1`.
4. Dual-track provisioning:
   - Fresh public installs: creates company + 11 agents in Paperclip, generates fresh UUIDs,
     and persists `config/organization-roster.json`.
   - Private Track-B migrations: preserves existing company & agent UUIDs in migrated PostgreSQL
     while rebinding `cwd`, `instructionsFilePath`, `hermesCommand`, `paperclipApiUrl`, and
     `env.HERMES_HOME` (plus stale Windows workspace paths) to the Linux/container paths.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterator

_PKG_ROOT = str(Path(__file__).resolve().parents[1])
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from control_center.hermes_worker_factory import (
    bind_agent_paperclip_key,
    provision_worker_home,
    to_profile_id,
)
from control_center.paperclip_client import PaperclipClient
from control_center.paths import (
    DATA_DIR,
    DEFAULT_LLM_MODEL,
    HERMES_EXE,
    HERMES_HOME_ROOT,
    LLM_PROVIDER,
    PAPERCLIP_API_URL,
    REPORTS_DIR,
    ROSTER_JSON_PATH as DEFAULT_ROSTER_JSON_PATH,
    SECRETS_DIR,
    WORKSPACES_DIR,
    resolve_reports_dir,
    resolve_roster_read_paths,
    resolve_workspaces_dir,
)

LOCKS_DIR: Path = DATA_DIR / "workspace-locks"
ROSTER_JSON_PATH: Path = DEFAULT_ROSTER_JSON_PATH
WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")


def _build_org_roster() -> list[dict[str, Any]]:
    ws_dir = str(resolve_workspaces_dir())
    rep_dir = str(resolve_reports_dir())
    return [
        {
            "slug": "ceo_agent",
            "name": "CEO Agent",
            "role": "ceo",
            "title": "Chief Executive Officer — Planning & Delegation",
            "reports_to_slug": None,
            "active_initially": True,
            "default_capped_monthly_cents": 2000,
            "timeout_sec": 240,
            "max_turns": 20,
            "toolsets": ["file", "terminal", "skills"],
            "workspace_kind": "workspaces",
            "workspace_scope": ws_dir,
            "objective": "Translate Owner objectives into structured plans, prioritized subtasks, assignments, and executive completion summaries.",
            "responsibilities": [
                "Decompose complex goals into bounded subtasks (max depth 2, max 6 subtasks).",
                "Assign tasks to engineering, QA, compliance, or security specialists according to role boundaries.",
                "Track task blockers, acceptance criteria, and synthesize final reports.",
            ],
            "prohibited": [
                "Direct modification of production databases or host OS/container settings.",
                "Approving high-risk destructive actions on behalf of the human Owner.",
                "Creating unbounded new agents (`canCreateAgents=false`).",
            ],
            "expected_output": "Structured Markdown plan, child task breakdown, delegation summary, and final acceptance report.",
        },
        {
            "slug": "cto_agent",
            "name": "CTO Agent",
            "role": "cto",
            "title": "Chief Technology Officer — Architecture & Standards",
            "reports_to_slug": "ceo_agent",
            "active_initially": False,
            "default_capped_monthly_cents": 1500,
            "timeout_sec": 240,
            "max_turns": 18,
            "toolsets": ["file", "terminal", "skills"],
            "workspace_kind": "workspaces",
            "workspace_scope": ws_dir,
            "objective": "Define software architecture, technical contracts, dependency boundaries, and code review standards.",
            "responsibilities": [
                "Produce architecture notes, ADRs, and implementation specifications.",
                "Review cross-module dependencies and engineering quality.",
            ],
            "prohibited": ["Bypassing QA/Security gates or changing host OS/container settings."],
            "expected_output": "Architecture Decision Record (ADR) and engineering review verdict.",
        },
        {
            "slug": "backend_developer",
            "name": "Backend Developer",
            "role": "engineer",
            "title": "Senior Full-Stack / Backend Software Engineer",
            "reports_to_slug": "ceo_agent",
            "active_initially": True,
            "default_capped_monthly_cents": 3000,
            "timeout_sec": 420,
            "max_turns": 25,
            "toolsets": ["file", "terminal", "skills"],
            "workspace_kind": "workspaces",
            "workspace_scope": ws_dir,
            "objective": "Implement backend/application features, bug fixes, security remediations, and unit tests on isolated Git branches.",
            "responsibilities": [
                "Inspect authorized repository code and root causes.",
                "Create or switch to an isolated feature/fix Git branch before modifying code.",
                "Write clean modular code and unit/regression tests and verify they pass locally.",
            ],
            "prohibited": [
                "Pushing to remote repositories or deploying to production without explicit Owner approval.",
                "Modifying files outside the assigned project workspace.",
            ],
            "expected_output": "Git branch diff summary, files changed, unit test command & exit code, and remediation notes.",
        },
        {
            "slug": "frontend_developer",
            "name": "Frontend Developer",
            "role": "designer",
            "title": "Senior Frontend & UI Engineer",
            "reports_to_slug": "cto_agent",
            "active_initially": False,
            "default_capped_monthly_cents": 2000,
            "timeout_sec": 240,
            "max_turns": 20,
            "toolsets": ["file", "terminal", "skills"],
            "workspace_kind": "workspaces",
            "workspace_scope": ws_dir,
            "objective": "Build accessible, responsive UI components and frontend tests inside authorized project workspaces.",
            "responsibilities": ["Implement UI components, styling, performance optimizations, and frontend unit tests."],
            "prohibited": ["Modifying backend credentials or host OS/container settings."],
            "expected_output": "UI implementation summary and frontend test results.",
        },
        {
            "slug": "devops_engineer",
            "name": "DevOps Engineer",
            "role": "devops",
            "title": "Senior DevOps & Runtime Diagnostics Engineer",
            "reports_to_slug": "cto_agent",
            "active_initially": False,
            "default_capped_monthly_cents": 1500,
            "timeout_sec": 240,
            "max_turns": 18,
            "toolsets": ["file", "terminal", "skills"],
            "workspace_kind": "workspaces",
            "workspace_scope": ws_dir,
            "objective": "Verify build pipelines, IaC modules, runtime configuration files, and non-destructive service health diagnostics.",
            "responsibilities": ["Validate Docker/CI/IaC recipes, configuration templates, and service readiness."],
            "prohibited": ["Altering host firewall/privilege policies, stopping production services, or running elevated commands."],
            "expected_output": "Build & runtime readiness report with diagnostic exit codes.",
        },
        {
            "slug": "qa_engineer",
            "name": "QA Engineer",
            "role": "qa",
            "title": "Lead Quality Assurance & Regression Engineer",
            "reports_to_slug": "ceo_agent",
            "active_initially": True,
            "default_capped_monthly_cents": 2000,
            "timeout_sec": 240,
            "max_turns": 20,
            "toolsets": ["file", "terminal", "skills"],
            "workspace_kind": "workspaces",
            "workspace_scope": ws_dir,
            "objective": "Execute functional, integration, browser E2E, and regression test suites and verify acceptance criteria.",
            "responsibilities": [
                "Run automated test suites independently in the target branch/workspace.",
                "Verify edge cases, regression coverage, and adherence to acceptance criteria.",
                "Report PASS/FAIL verdicts with concrete command outputs.",
            ],
            "prohibited": [
                "Marking untested code as PASS.",
                "Modifying production configuration outside test scope.",
            ],
            "expected_output": "QA Verification Report containing executed test commands, pass/fail counts, exit codes, and regression verdict.",
        },
        {
            "slug": "security_lead",
            "name": "Security Lead",
            "role": "security",
            "title": "Defensive Security Architecture Lead",
            "reports_to_slug": "ceo_agent",
            "active_initially": False,
            "default_capped_monthly_cents": 1000,
            "timeout_sec": 180,
            "max_turns": 15,
            "toolsets": ["file", "skills"],
            "workspace_kind": "workspaces",
            "workspace_scope": ws_dir,
            "objective": "Govern defensive security review policies, threat modeling, risk prioritization, and scope compliance.",
            "responsibilities": ["Prioritize confirmed defensive findings and verify authorization boundaries."],
            "prohibited": ["Any offensive probing, network scanning, exploit generation, or shell execution."],
            "expected_output": "Risk prioritization matrix and defensive security governance sign-off.",
        },
        {
            "slug": "security_reviewer",
            "name": "Security Reviewer",
            "role": "security",
            "title": "Defensive Code & Findings Security Reviewer",
            "reports_to_slug": "ceo_agent",
            "active_initially": True,
            "default_capped_monthly_cents": 1500,
            "timeout_sec": 180,
            "max_turns": 15,
            "toolsets": ["file", "skills"],
            "workspace_kind": "workspaces",
            "workspace_scope": ws_dir,
            "objective": "Perform read-only defensive review of sanitized security findings, dependency advisories, and code remediations.",
            "responsibilities": [
                "Evaluate sanitized static analysis findings and source code using read-only file inspection.",
                "Assess false positives vs confirmed defensive weaknesses without inventing CVE IDs.",
                "Verify whether code remediations properly address root causes.",
            ],
            "prohibited": [
                "Terminal/shell execution (`terminal` toolset is intentionally disabled).",
                "Offensive testing, live network requests, or reading files outside authorized workspaces.",
            ],
            "expected_output": "Structured Defensive Security Review (`CONFIRMED` / `FALSE_POSITIVE` / `VERIFIED`) with CWE rationale and remediation guidance.",
        },
        {
            "slug": "findings_analyst",
            "name": "Findings Analyst",
            "role": "researcher",
            "title": "Security Findings Triage & Deduplication Analyst",
            "reports_to_slug": "security_lead",
            "active_initially": False,
            "default_capped_monthly_cents": 1000,
            "timeout_sec": 180,
            "max_turns": 12,
            "toolsets": ["file", "skills"],
            "workspace_kind": "reports",
            "workspace_scope": rep_dir,
            "objective": "Classify, deduplicate, and summarize sanitized defensive audit reports.",
            "responsibilities": ["Normalize severity, check evidence quality, and flag duplicates."],
            "prohibited": ["Shell execution, network scanning, or fabricating vulnerability identifiers."],
            "expected_output": "Normalized findings summary table.",
        },
        {
            "slug": "remediation_reviewer",
            "name": "Remediation Reviewer",
            "role": "security",
            "title": "Security Remediation & Regression Verifier",
            "reports_to_slug": "security_lead",
            "active_initially": False,
            "default_capped_monthly_cents": 1000,
            "timeout_sec": 180,
            "max_turns": 12,
            "toolsets": ["file", "skills"],
            "workspace_kind": "workspaces",
            "workspace_scope": ws_dir,
            "objective": "Verify that security remediations eliminate the reported weakness without introducing insecure patterns.",
            "responsibilities": ["Inspect remediation diffs, minimal-fix scope, and regression test coverage."],
            "prohibited": ["Shell execution or modifying source code directly."],
            "expected_output": "Remediation verification sign-off (`RESOLVED` or `REWORK_REQUIRED`).",
        },
        {
            "slug": "compliance_reporter",
            "name": "Report & Compliance Agent",
            "role": "pm",
            "title": "Audit Evidence & Acceptance Compliance Specialist",
            "reports_to_slug": "ceo_agent",
            "active_initially": False,
            "default_capped_monthly_cents": 1500,
            "timeout_sec": 240,
            "max_turns": 15,
            "toolsets": ["file", "terminal", "skills"],
            "workspace_kind": "reports",
            "workspace_scope": rep_dir,
            "objective": "Compile auditable engineering & security reports (Markdown, PDF, DOCX) and verify acceptance criteria completeness.",
            "responsibilities": [
                "Aggregate run evidence, test results, and ISO 27001 / SOC 2 / NIST CSF compliance checklists.",
                "Export verified reports to deterministic `.pdf` and `.docx` artifacts inside the authorized reports directory.",
            ],
            "prohibited": ["Secret access, `.env` inspection, claiming formal legal certification, or altering task evidence."],
            "expected_output": "Executive & technical compliance summary document with exported PDF and DOCX deliverables.",
        },
    ]


ORG_ROSTER: list[dict[str, Any]] = _build_org_roster()


def build_budget_policy_config(
    *,
    mode: str | None = None,
    company_monthly_cents: int | None = None,
    strict_priced_budget: bool | None = None,
) -> dict[str, Any]:
    """Compute company and per-agent Paperclip budget policy settings deterministically."""
    resolved_mode = str(mode or os.environ.get("ALLINAGENT_BUDGET_MODE") or "unlimited").strip().lower()
    if resolved_mode not in ("unlimited", "capped"):
        raise ValueError(f"Invalid ALLINAGENT_BUDGET_MODE '{resolved_mode}'. Must be 'unlimited' or 'capped'.")

    if strict_priced_budget is None:
        strict_raw = str(os.environ.get("STRICT_PRICED_BUDGET") or "0").strip().lower()
        strict_priced = strict_raw in ("1", "true", "yes")
    else:
        strict_priced = bool(strict_priced_budget)

    unpriced_policy = "block" if (resolved_mode == "capped" and strict_priced) else "allow"

    if resolved_mode == "unlimited":
        return {
            "mode": "unlimited",
            "company_monthly_cents": 0,
            "company_policy": {
                "amount": 0,
                "isActive": False,
                "hardStopEnabled": False,
                "notifyEnabled": False,
                "windowKind": "calendar_month_utc",
                "unpricedUsagePolicy": "allow",
            },
            "agent_monthly_cents": {spec["slug"]: 0 for spec in ORG_ROSTER},
            "agent_policy_template": {
                "isActive": False,
                "hardStopEnabled": False,
                "notifyEnabled": False,
                "windowKind": "calendar_month_utc",
                "unpricedUsagePolicy": "allow",
            },
        }

    comp_cents = (
        int(company_monthly_cents)
        if company_monthly_cents is not None
        else int(os.environ.get("ALLINAGENT_COMPANY_MONTHLY_CENTS") or 10000)
    )
    default_agent_override = os.environ.get("ALLINAGENT_AGENT_DEFAULT_MONTHLY_CENTS", "").strip()
    agent_caps: dict[str, int] = {}
    for spec in ORG_ROSTER:
        slug_env = f"ALLINAGENT_AGENT_{spec['slug'].upper()}_MONTHLY_CENTS"
        if os.environ.get(slug_env, "").strip():
            agent_caps[spec["slug"]] = int(os.environ[slug_env].strip())
        elif default_agent_override:
            agent_caps[spec["slug"]] = int(default_agent_override)
        else:
            agent_caps[spec["slug"]] = int(spec["default_capped_monthly_cents"])

    return {
        "mode": "capped",
        "company_monthly_cents": comp_cents,
        "company_policy": {
            "amount": comp_cents,
            "isActive": True,
            "hardStopEnabled": True,
            "notifyEnabled": True,
            "windowKind": "calendar_month_utc",
            "unpricedUsagePolicy": unpriced_policy,
        },
        "agent_monthly_cents": agent_caps,
        "agent_policy_template": {
            "isActive": True,
            "hardStopEnabled": True,
            "notifyEnabled": True,
            "windowKind": "calendar_month_utc",
            "unpricedUsagePolicy": unpriced_policy,
        },
    }


def render_role_instructions_md(spec: dict[str, Any], *, agent_budget_cents: int = 0) -> str:
    resp_lines = "\n".join(f"- {r}" for r in spec["responsibilities"])
    proh_lines = "\n".join(f"- {p}" for p in spec["prohibited"])
    tools_csv = ", ".join(spec["toolsets"])
    ws = Path(spec["workspace_scope"]).as_posix()
    budget_label = "Unlimited (0 cents cap)" if agent_budget_cents == 0 else f"{agent_budget_cents} cents"
    return f"""# {spec['name']} — {spec['title']}

## 1. Role Definition & Objective
- **Role Slug:** `{spec['slug']}` (Paperclip role: `{spec['role']}`)
- **Objective:** {spec['objective']}

## 2. Responsibilities
{resp_lines}

## 3. Authorized Workspace & Available Tools
- **Authorized Workspace Root:** `{ws}`
- **Permitted Hermes Toolsets:** `{tools_csv}`
- For parallel coding tasks, operate on a dedicated Git branch or worktree inside the project workspace.

## 4. Prohibited Actions
{proh_lines}
- Never read or write `{HERMES_HOME_ROOT.as_posix()}` root files (Gateway/Owner private zone) or `{SECRETS_DIR.as_posix()}`.
- Never include secrets, `.env` values, tokens, or API keys in issue comments, logs, reports, or memory.

## 5. Input, Expected Output & Acceptance Criteria
- **Input Requirements:** Assigned Paperclip issue context (`$PAPERCLIP_TASK_ID`), project path, and explicit acceptance criteria.
- **Expected Output:** {spec['expected_output']}
- **Acceptance Criteria:** All claims must be backed by real file/test evidence; zero out-of-scope file edits; zero secret exposure.

## 6. Reporting Format, Escalation, Budget & Delegation Limits
- **Reporting Format:** Concise Markdown summary with `Summary`, `Actions/Files`, `Verification Evidence`, and `Status`.
- **Escalation Rules:** If an action requires production deployment, destructive deletion, privilege elevation, or out-of-scope access, mark the issue `blocked` and escalate to the Board/Owner.
- **Budget & Runtime Limits:** Monthly budget `{budget_label}` (tracked in Paperclip), timeout `{spec['timeout_sec']}s`, max `{spec['max_turns']}` turns per run, max delegation depth `2`.
"""


@contextlib.contextmanager
def workspace_exclusive_lock(workspace_name: str, holder: str, timeout_s: float = 30.0) -> Iterator[Path]:
    """File-based atomic exclusive lock (`O_CREAT | O_EXCL`) preventing concurrent conflicting edits."""
    LOCKS_DIR.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in workspace_name)
    lock_file = LOCKS_DIR / f"{safe}.lock"
    deadline = time.time() + timeout_s
    acquired = False
    while time.time() < deadline:
        try:
            fd = os.open(str(lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"holder": holder, "pid": os.getpid(), "acquired_at": time.time()}, fh)
            acquired = True
            break
        except FileExistsError:
            try:
                if time.time() - lock_file.stat().st_mtime > 900:
                    lock_file.unlink(missing_ok=True)
                    continue
            except OSError:
                pass
            time.sleep(0.25)
    if not acquired:
        raise TimeoutError(f"Workspace '{workspace_name}' is exclusively locked by another active worker.")
    try:
        yield lock_file
    finally:
        lock_file.unlink(missing_ok=True)


def create_isolated_git_worktree(repo_dir: Path, branch_name: str) -> Path:
    """Create an isolated Git worktree for parallel branch development."""
    wt_root = repo_dir.parent / f"{repo_dir.name}-worktrees"
    wt_root.mkdir(parents=True, exist_ok=True)
    safe_branch = branch_name.replace("/", "-")
    wt_path = wt_root / safe_branch
    if wt_path.exists():
        subprocess.run(["git", "-C", str(repo_dir), "worktree", "remove", "--force", str(wt_path)], capture_output=True, check=False)
    subprocess.run(
        ["git", "-C", str(repo_dir), "worktree", "add", "-B", branch_name, str(wt_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return wt_path


def _match_existing_agent(spec: dict[str, Any], agents: list[dict[str, Any]], prior_roster: dict[str, Any]) -> dict[str, Any] | None:
    """Match an existing DB agent by prior roster UUID, `metadata.role_slug`, or canonical role name."""
    prior_id = ((prior_roster.get("agents") or {}).get(spec["slug"]) or {}).get("id")
    if prior_id:
        by_id = next((a for a in agents if a.get("id") == prior_id), None)
        if by_id:
            return by_id
    by_meta = next(
        (a for a in agents if (a.get("metadata") or {}).get("role_slug") == spec["slug"]),
        None,
    )
    if by_meta:
        return by_meta
    return next((a for a in agents if a.get("name") == spec["name"]), None)


def _rebind_migrated_project_workspaces(pc: PaperclipClient, company_id: str) -> list[dict[str, str]]:
    """Rebind stale Windows drive paths in migrated Paperclip project workspaces during Track-B migration."""
    rebound: list[dict[str, str]] = []
    for proj in pc.list_projects(company_id):
        pid = proj["id"]
        ws_list = proj.get("workspaces") or pc.list_project_workspaces(pid)
        for ws in ws_list:
            old_cwd = str(ws.get("cwd") or "")
            if not WINDOWS_DRIVE_RE.match(old_cwd):
                continue
            norm_lower = old_cwd.replace("\\", "/").lower()
            if "skill-registry/reviewed" in norm_lower:
                new_cwd = str((DATA_DIR / "skill-registry" / "reviewed").resolve())
            elif norm_lower.endswith("/reports") or "/reports/" in norm_lower:
                new_cwd = str(REPORTS_DIR)
            else:
                tail = Path(old_cwd.replace("\\", "/")).name
                cand = WORKSPACES_DIR / tail
                new_cwd = str(cand if cand.exists() else WORKSPACES_DIR)
            try:
                pc.update_project_workspace(pid, ws["id"], {"cwd": new_cwd})
                rebound.append({"project_id": pid, "workspace_id": ws["id"], "from": old_cwd, "to": new_cwd})
            except Exception:
                pass
    return rebound


def provision_organization(
    *,
    budget_mode: str | None = None,
    company_monthly_cents: int | None = None,
    strict_priced_budget: bool | None = None,
    rebind_migrated_paths: bool = True,
    reset_activation_tiers: bool = False,
) -> dict[str, Any]:
    resolve_workspaces_dir().mkdir(parents=True, exist_ok=True)
    resolve_reports_dir().mkdir(parents=True, exist_ok=True)
    ROSTER_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)

    budget_cfg = build_budget_policy_config(
        mode=budget_mode,
        company_monthly_cents=company_monthly_cents,
        strict_priced_budget=strict_priced_budget,
    )
    resolved_model = (os.environ.get("DEFAULT_LLM_MODEL") or os.environ.get("LLM_MODEL") or DEFAULT_LLM_MODEL).strip()
    resolved_provider = (os.environ.get("LLM_PROVIDER") or LLM_PROVIDER or "auto").strip()

    pc = PaperclipClient()
    company = pc.get_primary_company()
    cid = company["id"]

    # Apply company-level budget policy
    pc.must("PATCH", f"/api/companies/{cid}", {"budgetMonthlyCents": budget_cfg["company_monthly_cents"]})
    pc.upsert_budget_policy(
        cid,
        {
            "scopeType": "company",
            "scopeId": cid,
            **budget_cfg["company_policy"],
        },
    )

    prior_roster: dict[str, Any] = {}
    for cand_roster in resolve_roster_read_paths(ROSTER_JSON_PATH):
        if cand_roster.is_file():
            try:
                prior_roster = json.loads(cand_roster.read_text(encoding="utf-8"))
                if prior_roster:
                    break
            except Exception:
                prior_roster = {}

    existing_list = pc.list_agents(cid)
    is_migration = len(existing_list) > 0
    slug_to_agent: dict[str, dict[str, Any]] = {}
    rebound_agents: list[str] = []

    for spec in _build_org_roster():
        agent_cents = budget_cfg["agent_monthly_cents"][spec["slug"]]
        instructions_md = render_role_instructions_md(spec, agent_budget_cents=agent_cents)
        worker_meta = provision_worker_home(
            spec["slug"],
            role_title=spec["title"],
            authorized_workspace=spec["workspace_scope"],
            allowed_toolsets=spec["toolsets"],
            extra_soul_rules=instructions_md,
            company_name=company.get("name") or "Unified AI Engineering & Operations",
        )

        reports_to_id = None
        if spec["reports_to_slug"] and spec["reports_to_slug"] in slug_to_agent:
            reports_to_id = slug_to_agent[spec["reports_to_slug"]]["id"]

        adapter_cfg = {
            "hermesCommand": HERMES_EXE,
            "model": resolved_model,
            "provider": resolved_provider,
            "timeoutSec": spec["timeout_sec"],
            "graceSec": 10,
            "maxTurnsPerRun": spec["max_turns"],
            "toolsets": ",".join(spec["toolsets"]),
            "persistSession": False,
            "worktreeMode": False,
            "quiet": True,
            "cwd": spec["workspace_scope"],
            "instructionsFilePath": worker_meta["instructions_file"],
            "paperclipApiUrl": PAPERCLIP_API_URL,
            "env": {
                "HERMES_HOME": worker_meta["hermes_home"],
            },
        }

        cur = _match_existing_agent(spec, existing_list, prior_roster)
        if cur is None:
            created = pc.create_agent(
                cid,
                {
                    "name": spec["name"],
                    "role": spec["role"],
                    "title": spec["title"],
                    "reportsTo": reports_to_id,
                    "capabilities": spec["objective"],
                    "adapterType": "hermes_local",
                    "adapterConfig": adapter_cfg,
                    "instructionsBundle": {
                        "entryFile": "AGENTS.md",
                        "files": {"AGENTS.md": instructions_md},
                    },
                    "budgetMonthlyCents": agent_cents,
                    "permissions": {
                        "canCreateAgents": False,
                        "canCreateSkills": False,
                    },
                    "metadata": {
                        "role_slug": spec["slug"],
                        "hermes_profile": worker_meta["profile_id"],
                        "activation_tier": "wave_1_active" if spec["active_initially"] else "wave_2_standby",
                    },
                },
            )
            pc.update_agent_permissions(
                created["id"],
                {
                    "canCreateAgents": False,
                    "canAssignTasks": spec["slug"] in ("ceo_agent", "cto_agent", "security_lead"),
                },
            )
            desired_status = "idle" if spec["active_initially"] else "paused"
            if desired_status == "paused":
                created = pc.pause_agent(created["id"])
            else:
                created = pc.resume_agent(created["id"])
        else:
            cur_cfg = cur.get("adapterConfig") or {}
            had_stale_path = any(
                WINDOWS_DRIVE_RE.match(str(val or ""))
                for val in (
                    cur_cfg.get("cwd"),
                    cur_cfg.get("instructionsFilePath"),
                    cur_cfg.get("hermesCommand"),
                    (cur_cfg.get("env") or {}).get("HERMES_HOME"),
                )
            )
            cfg_matches = (
                cur.get("adapterType") == "hermes_local"
                and cur_cfg.get("toolsets") == adapter_cfg["toolsets"]
                and cur_cfg.get("cwd") == adapter_cfg["cwd"]
                and cur_cfg.get("hermesCommand") == adapter_cfg["hermesCommand"]
                and cur_cfg.get("model") == adapter_cfg["model"]
                and cur_cfg.get("paperclipApiUrl") == adapter_cfg["paperclipApiUrl"]
                and cur_cfg.get("instructionsFilePath") == adapter_cfg["instructionsFilePath"]
                and (cur_cfg.get("env") or {}).get("HERMES_HOME") == adapter_cfg["env"]["HERMES_HOME"]
                and cur.get("budgetMonthlyCents") == agent_cents
            )
            if cfg_matches and not rebind_migrated_paths:
                created = cur
            else:
                merged_meta = dict(cur.get("metadata") or {})
                merged_meta.update({
                    "role_slug": spec["slug"],
                    "hermes_profile": worker_meta["profile_id"],
                })
                created = pc.update_agent(
                    cur["id"],
                    {
                        "role": spec["role"],
                        "title": spec["title"],
                        "reportsTo": reports_to_id,
                        "capabilities": spec["objective"],
                        "adapterType": "hermes_local",
                        "adapterConfig": adapter_cfg,
                        "replaceAdapterConfig": True,
                        "instructionsBundle": {
                            "entryFile": "AGENTS.md",
                            "files": {"AGENTS.md": instructions_md},
                        },
                        "budgetMonthlyCents": agent_cents,
                        "metadata": merged_meta,
                    },
                )
                if had_stale_path:
                    rebound_agents.append(spec["slug"])

            pc.update_agent_permissions(
                created["id"],
                {
                    "canCreateAgents": False,
                    "canAssignTasks": spec["slug"] in ("ceo_agent", "cto_agent", "security_lead"),
                },
            )

            if reset_activation_tiers:
                desired_status = "idle" if spec["active_initially"] else "paused"
                cur_ag = pc.get_agent(created["id"])
                if desired_status == "paused" and cur_ag.get("status") != "paused":
                    created = pc.pause_agent(created["id"])
                elif desired_status == "idle" and cur_ag.get("status") == "paused":
                    created = pc.resume_agent(created["id"])
                else:
                    created = cur_ag

        pc.upsert_budget_policy(
            cid,
            {
                "scopeType": "agent",
                "scopeId": created["id"],
                "amount": agent_cents,
                **budget_cfg["agent_policy_template"],
            },
        )

        bind_agent_paperclip_key(worker_meta["hermes_home"], pc, created["id"], spec["slug"])
        slug_to_agent[spec["slug"]] = created

    rebound_workspaces = _rebind_migrated_project_workspaces(pc, cid) if (is_migration and rebind_migrated_paths) else []

    roster_map = {
        "company_id": cid,
        "company_name": company["name"],
        "budget_mode": budget_cfg["mode"],
        "company_monthly_cents": budget_cfg["company_monthly_cents"],
        "model": resolved_model,
        "track_mode": "track_b_preserved_uuids" if is_migration else "track_a_fresh_install",
        "rebound_agents": rebound_agents,
        "rebound_workspaces": rebound_workspaces,
        "agents": {
            slug: {
                "id": ag["id"],
                "name": ag["name"],
                "profile": to_profile_id(slug),
                "role": ag.get("role"),
                "title": ag.get("title"),
                "status": ag.get("status"),
                "reportsTo": ag.get("reportsTo"),
                "toolsets": (ag.get("adapterConfig") or {}).get("toolsets"),
                "budgetMonthlyCents": ag.get("budgetMonthlyCents"),
            }
            for slug, ag in slug_to_agent.items()
        },
    }
    ROSTER_JSON_PATH.write_text(json.dumps(roster_map, indent=2) + "\n", encoding="utf-8")
    return roster_map


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision or migrate the 11-agent ALLINAGENT organization in Paperclip.")
    parser.add_argument("--budget-mode", choices=("unlimited", "capped"), default=None)
    parser.add_argument("--company-monthly-cents", type=int, default=None)
    parser.add_argument("--strict-priced-budget", action="store_true", default=None)
    parser.add_argument("--reset-activation-tiers", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="Print resolved roster, toolsets, and budget policy offline.")
    args = parser.parse_args()

    if args.dry_run:
        bcfg = build_budget_policy_config(
            mode=args.budget_mode,
            company_monthly_cents=args.company_monthly_cents,
            strict_priced_budget=args.strict_priced_budget,
        )
        roster_preview = [
            {
                "slug": s["slug"],
                "name": s["name"],
                "profile": to_profile_id(s["slug"]),
                "toolsets": ",".join(s["toolsets"]),
                "workspace_scope": s["workspace_scope"],
                "budget_monthly_cents": bcfg["agent_monthly_cents"][s["slug"]],
            }
            for s in _build_org_roster()
        ]
        print(
            json.dumps(
                {
                    "dry_run": True,
                    "default_llm_model": DEFAULT_LLM_MODEL,
                    "budget_config": bcfg,
                    "agents_count": len(roster_preview),
                    "agents": roster_preview,
                },
                indent=2,
            )
        )
        return 0

    res = provision_organization(
        budget_mode=args.budget_mode,
        company_monthly_cents=args.company_monthly_cents,
        strict_priced_budget=args.strict_priced_budget,
        reset_activation_tiers=args.reset_activation_tiers,
    )
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
