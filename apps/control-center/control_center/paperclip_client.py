#!/usr/bin/env python3
"""Official Paperclip REST API client for ALLINAGENT."""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from control_center.paths import PAPERCLIP_BASE_URL, SECRETS_DIR, resolve_secrets_dir

BOARD_KEY_PATH: Path = SECRETS_DIR / "paperclip-board-key.json"
DEFAULT_BASE_URL: str = PAPERCLIP_BASE_URL


class PaperclipApiError(RuntimeError):
    def __init__(self, status: int, body: Any, path: str) -> None:
        super().__init__(f"Paperclip API {path} returned HTTP {status}: {body}")
        self.status = status
        self.body = body
        self.path = path


def resolve_board_api_key(board_key_path: Path = BOARD_KEY_PATH, *, required: bool = False) -> str:
    """Resolve Paperclip board token from env or `paperclip-board-key.json` without logging secrets.

    In Paperclip `local_trusted` internal Docker mode (or on fresh first boot before a board key
    file is minted), returns `""` cleanly when `required=False` so requests proceed without a
    Bearer header, matching `apps/office-bridge/adapters/paperclip-adapter.js`.
    """
    for env_key in ("PAPERCLIP_BOARD_TOKEN", "PAPERCLIP_BOARD_API_KEY", "PAPERCLIP_API_KEY"):
        val = os.environ.get(env_key, "").strip()
        if val:
            return val

    candidate_paths: list[Path] = [board_key_path]
    if board_key_path == BOARD_KEY_PATH:
        dyn_secrets = resolve_secrets_dir() / "paperclip-board-key.json"
        if dyn_secrets not in candidate_paths:
            candidate_paths.append(dyn_secrets)
        docker_secrets = Path("/var/lib/allinagent/secrets/paperclip-board-key.json")
        if docker_secrets not in candidate_paths:
            candidate_paths.append(docker_secrets)

    for cand in candidate_paths:
        if cand.is_file():
            try:
                data = json.loads(cand.read_text(encoding="utf-8-sig"))
                for k in ("token", "apiKey", "boardKey", "key"):
                    if data.get(k):
                        return str(data[k]).strip()
            except (OSError, json.JSONDecodeError):
                continue

    if required:
        raise FileNotFoundError(
            f"Paperclip board API key not found in env or '{board_key_path}'."
        )
    return ""


class PaperclipClient:
    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 45.0,
        require_auth: bool = False,
    ) -> None:
        resolved_url = (
            base_url
            or os.environ.get("PAPERCLIP_BASE_URL")
            or os.environ.get("PAPERCLIP_URL")
            or PAPERCLIP_BASE_URL
        ).strip().rstrip("/")
        self.base_url = resolved_url
        if api_key is None:
            api_key = resolve_board_api_key(required=require_auth)
        self.api_key = api_key or ""
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        auth: bool = True,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, Any]:
        url = f"{self.base_url}{path}"
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        headers: dict[str, str] = {
            "Accept": "application/json",
            "Origin": self.base_url,
        }
        if auth and self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if body is not None:
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)

        for attempt in range(2):
            req = urllib.request.Request(url, data=payload, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                    try:
                        return resp.status, json.loads(raw) if raw else None
                    except json.JSONDecodeError:
                        return resp.status, raw
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8", errors="replace")
                try:
                    parsed = json.loads(raw) if raw else None
                except json.JSONDecodeError:
                    parsed = raw
                return exc.code, parsed
            except (TimeoutError, OSError, urllib.error.URLError):
                if attempt == 0 and method == "GET":
                    time.sleep(1.5)
                    continue
                raise
        raise RuntimeError("Unreachable")

    def must(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        expected: tuple[int, ...] = (200, 201, 202, 204),
        auth: bool = True,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        code, data = self.request(method, path, body, auth=auth, extra_headers=extra_headers)
        if code not in expected:
            raise PaperclipApiError(code, data, path)
        return data

    # --- Health & Companies ---
    def health(self) -> dict[str, Any]:
        return self.must("GET", "/api/health", auth=False)

    def list_companies(self) -> list[dict[str, Any]]:
        res = self.must("GET", "/api/companies")
        if isinstance(res, dict) and "companies" in res:
            return res["companies"] or []
        return res or []

    def get_primary_company(self, name: str | None = None) -> dict[str, Any]:
        target_name = (name or os.environ.get("ALLINAGENT_COMPANY_NAME") or "Unified AI Engineering & Operations").strip()
        companies = self.list_companies()
        for c in companies:
            if c.get("name") == target_name:
                return c
        if companies:
            return companies[0]
        return self.must("POST", "/api/companies", {"name": target_name})

    def get_org(self, company_id: str) -> Any:
        return self.must("GET", f"/api/companies/{company_id}/org")

    # --- Agents ---
    def list_agents(self, company_id: str) -> list[dict[str, Any]]:
        res = self.must("GET", f"/api/companies/{company_id}/agents")
        if isinstance(res, dict) and "agents" in res:
            return res["agents"] or []
        return res or []

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        return self.must("GET", f"/api/agents/{agent_id}")

    def create_agent(self, company_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.must("POST", f"/api/companies/{company_id}/agents", payload)

    def update_agent(self, agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.must("PATCH", f"/api/agents/{agent_id}", payload)

    def update_agent_permissions(self, agent_id: str, payload: dict[str, Any]) -> Any:
        return self.must("PATCH", f"/api/agents/{agent_id}/permissions", payload)

    def pause_agent(self, agent_id: str) -> dict[str, Any]:
        cur = self.get_agent(agent_id)
        wait_dl = time.time() + 45.0
        while time.time() < wait_dl and cur.get("lifecycleState") in ("verifying", "configuring", "initializing"):
            time.sleep(1.0)
            cur = self.get_agent(agent_id)
        if cur.get("status") == "paused" and cur.get("lifecycleState") not in ("pausing", "stopping"):
            return cur
        code, res = self.request("POST", f"/api/agents/{agent_id}/pause", {})
        if code == 409 or not isinstance(res, dict):
            time.sleep(2.0)
            res = self.get_agent(agent_id)
        deadline = time.time() + 30.0
        while time.time() < deadline and (
            res.get("status") != "paused"
            or res.get("lifecycleState") in ("pausing", "stopping", "verifying", "configuring")
        ):
            time.sleep(1.0)
            res = self.get_agent(agent_id)
        return res

    def resume_agent(self, agent_id: str) -> dict[str, Any]:
        cur = self.get_agent(agent_id)
        deadline_wait = time.time() + 45.0
        while time.time() < deadline_wait and cur.get("lifecycleState") in (
            "pausing",
            "stopping",
            "verifying",
            "configuring",
            "initializing",
        ):
            time.sleep(1.0)
            cur = self.get_agent(agent_id)
        if cur.get("status") != "paused" and cur.get("lifecycleState") == "ready":
            return cur
        code, res = self.request("POST", f"/api/agents/{agent_id}/resume", {})
        if code == 409 or not isinstance(res, dict):
            time.sleep(2.5)
            res = self.get_agent(agent_id)
            if res.get("status") == "paused" and res.get("lifecycleState") in ("paused", "ready"):
                _, res = self.request("POST", f"/api/agents/{agent_id}/resume", {})
                if not isinstance(res, dict):
                    res = self.get_agent(agent_id)
        deadline = time.time() + 30.0
        while time.time() < deadline and (res.get("status") == "paused" or res.get("lifecycleState") != "ready"):
            time.sleep(1.0)
            res = self.get_agent(agent_id)
        return res

    def wake_agent(self, agent_id: str, payload: dict[str, Any] | None = None) -> Any:
        return self.must("POST", f"/api/agents/{agent_id}/wakeup", payload or {"source": "on_demand", "trigger": "manual"})

    def create_agent_key(self, agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.must("POST", f"/api/agents/{agent_id}/keys", payload)

    # --- Skills Store API ---
    def list_company_skills(self, company_id: str) -> list[dict[str, Any]]:
        res = self.must("GET", f"/api/companies/{company_id}/skills")
        if isinstance(res, dict) and "skills" in res:
            return res["skills"] or []
        return res or []

    def import_company_skill(self, company_id: str, source_path: str) -> dict[str, Any]:
        return self.must("POST", f"/api/companies/{company_id}/skills/import", {"source": source_path})

    def update_company_skill(self, company_id: str, skill_id: str, payload: dict[str, Any]) -> Any:
        return self.must("PATCH", f"/api/companies/{company_id}/skills/{skill_id}", payload)

    def sync_agent_skills(self, agent_id: str, desired_skills: list[str], *, mode: str = "replace") -> dict[str, Any]:
        return self.must(
            "POST",
            f"/api/agents/{agent_id}/skills/sync",
            {"mode": mode, "desiredSkills": desired_skills},
        )

    # --- Projects & Workspaces ---
    def list_projects(self, company_id: str) -> list[dict[str, Any]]:
        res = self.must("GET", f"/api/companies/{company_id}/projects")
        if isinstance(res, dict) and "projects" in res:
            return res["projects"] or []
        return res or []

    def create_project(self, company_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.must("POST", f"/api/companies/{company_id}/projects", payload)

    def list_project_workspaces(self, project_id: str) -> list[dict[str, Any]]:
        res = self.must("GET", f"/api/projects/{project_id}/workspaces")
        if isinstance(res, dict) and "workspaces" in res:
            return res["workspaces"] or []
        return res or []

    def create_project_workspace(self, project_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.must("POST", f"/api/projects/{project_id}/workspaces", payload)

    def update_project_workspace(self, project_id: str, workspace_id: str, payload: dict[str, Any]) -> Any:
        return self.must("PATCH", f"/api/projects/{project_id}/workspaces/{workspace_id}", payload)

    # --- Issues / Tasks ---
    def list_issues(self, company_id: str, *, status: str | None = None, project_id: str | None = None) -> list[dict[str, Any]]:
        q: dict[str, str] = {}
        if status:
            q["status"] = status
        if project_id:
            q["projectId"] = project_id
        qs = f"?{urllib.parse.urlencode(q)}" if q else ""
        res = self.must("GET", f"/api/companies/{company_id}/issues{qs}")
        if isinstance(res, dict) and "issues" in res:
            return res["issues"] or []
        return res or []

    def create_issue(
        self,
        company_id: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        hdrs = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        return self.must("POST", f"/api/companies/{company_id}/issues", payload, extra_headers=hdrs)

    def get_issue(self, issue_id: str) -> dict[str, Any]:
        return self.must("GET", f"/api/issues/{issue_id}")

    def update_issue(self, issue_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.must("PATCH", f"/api/issues/{issue_id}", payload)

    def add_issue_comment(self, issue_id: str, body: str) -> dict[str, Any]:
        return self.must("POST", f"/api/issues/{issue_id}/comments", {"body": body})

    def list_issue_comments(self, issue_id: str) -> list[dict[str, Any]]:
        res = self.must("GET", f"/api/issues/{issue_id}/comments")
        if isinstance(res, dict) and "comments" in res:
            return res["comments"] or []
        return res or []

    # --- Heartbeat Runs ---
    def list_runs(self, company_id: str, *, agent_id: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        q: dict[str, str] = {"limit": str(limit)}
        if agent_id:
            q["agentId"] = agent_id
        return self.must("GET", f"/api/companies/{company_id}/heartbeat-runs?{urllib.parse.urlencode(q)}") or []

    def list_live_runs(self, company_id: str) -> list[dict[str, Any]]:
        return self.must("GET", f"/api/companies/{company_id}/live-runs") or []

    def get_run(self, run_id: str) -> dict[str, Any]:
        return self.must("GET", f"/api/heartbeat-runs/{run_id}")

    def cancel_run(self, run_id: str) -> Any:
        code, data = self.request("POST", f"/api/heartbeat-runs/{run_id}/cancel", {})
        if code in (200, 201, 202, 204, 409):
            return data
        time.sleep(2.0)
        cur = self.get_run(run_id)
        if str(cur.get("status", "")).lower() in ("cancelled", "canceled", "timed_out", "succeeded", "failed"):
            return cur
        return self.must("POST", f"/api/heartbeat-runs/{run_id}/cancel", {})

    def list_run_events(self, run_id: str, limit: int = 200) -> list[dict[str, Any]]:
        return self.must("GET", f"/api/heartbeat-runs/{run_id}/events?limit={limit}") or []

    # --- Secrets & Budgets ---
    def list_secrets(self, company_id: str) -> list[dict[str, Any]]:
        return self.must("GET", f"/api/companies/{company_id}/secrets") or []

    def create_secret(self, company_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.must("POST", f"/api/companies/{company_id}/secrets", payload)

    def budget_overview(self, company_id: str) -> Any:
        return self.must("GET", f"/api/companies/{company_id}/budgets/overview")

    def upsert_budget_policy(self, company_id: str, payload: dict[str, Any]) -> Any:
        return self.must("POST", f"/api/companies/{company_id}/budgets/policies", payload)

    def update_company_budget(self, company_id: str, payload: dict[str, Any]) -> Any:
        return self.must("PATCH", f"/api/companies/{company_id}/budgets", payload)

    def update_agent_budget(self, agent_id: str, payload: dict[str, Any]) -> Any:
        return self.must("PATCH", f"/api/agents/{agent_id}/budgets", payload)

    def wait_for_run_completion(self, run_id: str, timeout_s: float = 240.0) -> dict[str, Any]:
        deadline = time.time() + timeout_s
        terminal = {"succeeded", "completed", "failed", "error", "cancelled", "canceled", "timed_out"}
        last: dict[str, Any] = {}
        while time.time() < deadline:
            try:
                last = self.get_run(run_id)
                st = str(last.get("status", "")).lower()
                if st in terminal:
                    return last
            except (TimeoutError, OSError, urllib.error.URLError):
                pass
            time.sleep(2.5)
        raise TimeoutError(f"Run {run_id} did not finish within {timeout_s}s (last status={last.get('status')})")
