# Phase 27 (Groups A & B) — Core Stack, Paperclip, Shared Hermes, Unlimited Budgets & All 11 Corporate Agents Live Verification Evidence

- **Phase / Verifier**: `PHASE-27` — Groups A (`A01–A10`) & B (`B01–B11`) Independent Live Production Verification (`SA-49`)
- **Release Under Test**: `v1.0.0-rc.8` (`ghcr.io/vistapra/allinagent-{hermes,paperclip,office-bridge,office,vulnclaw}:1.0.0-rc.8` + `postgres:16-alpine`)
- **Target Host Profile**: `<TARGET_VPS_HOSTNAME>` (`<TARGET_VPS_IPV4>`) — Ubuntu 24.04.4 LTS (`2 vCPU`, `7,940 MiB` RAM, multi-tenant production host)
- **Installation Root**: `/opt/allinagent` (bind-mounted state under `/opt/allinagent/data`, container runtime root `/var/lib/allinagent`)
- **Verification Timestamp**: `2026-11-24T16:16:00Z` – `2026-11-24T17:08:00Z` (`TIMEZONE=Asia/Jakarta`)
- **Sanitization Guarantee**: Zero secrets, tokens, API keys, VPS IPv4s, hostnames, private domains, or personal identifiers appear in this report. All host/model/endpoint identifiers use strict placeholders (`<TARGET_VPS_IPV4>`, `<TARGET_VPS_HOSTNAME>`, `<OWNER_LLM_BASE_URL>`, `<OWNER_LLM_MODEL>`).
- **Overall Verdict**: **`PASS` (`21 / 21` Live Tests Passed — `10 / 10` Group A + `11 / 11` Group B; `0` Container Restarts; `0` Multi-Tenant Disruption)**

---

## 1. Executive Summary Table (`A01–A10` & `B01–B11`)

| Test ID | Scope / Target | Live Verification Method | Key Empirical Metric | Verdict |
|---|---|---|---|---|
| **`A01`** | Core 6-Container Stack, Cgroups, Loopback Ports & PostgreSQL (`:5432`) | `docker ps`, `docker stats --no-stream`, `ss -tln`, `pg_isready`, `psql` | `6/6` `Up (healthy)` (`34` pre-existing containers untouched); `1,045.81 MiB / 1,536 MiB` (`68.09%`); `127.0.0.1:8200-8202` only; `pg_isready` `rc=0` (`81.2 ms`) | **PASS** |
| **`A02`** | Virtual Office (`:8200`) & Office Bridge (`:8202`) Health + Auth Guard | `GET 127.0.0.1:8200/api/health`, `GET 127.0.0.1:8202/health`, unauth `/snapshot` | Office `HTTP 200` (`{"ok":true,"service":"hermes3d"}`, `31.6 ms`); Bridge `HTTP 200` (`{"ok":true,"status":"healthy","paperclip_reachable":true}`, `2.1 ms`); unauth rejected `HTTP 401` | **PASS** |
| **`A03`** | Paperclip Control Plane (`:8201`) Health & Backup Readiness | `GET 127.0.0.1:8201/api/health` | `HTTP 200` (`13.6 ms`), `status: "ok"`, `version: "2026.1117.0"`, `deploymentMode: "local_trusted"`, `authReady: true`, `databaseBackup.status: "ok"` | **PASS** |
| **`A04`** | Shared Hermes Exec Daemon (`:8650`) & Air-Gapped VulnClaw (`:8660`) | `GET 127.0.0.1:8650/health` + unauth `POST /exec`; `vulnclaw_worker.py health --probe-http` | Hermes `HTTP 200` (`max_concurrency: 1`, `11` allowed `pc*` profiles, unauth `POST /exec` -> `HTTP 401`); VulnClaw `HTTP 200` (`mode: "defensive_only"`, `rss_mb: 25.45`, `L1/L2` only) | **PASS** |
| **`A05`** | Paperclip Companies & Projects API | `GET /api/companies` + `GET /api/companies/:id/projects` | `HTTP 200`; `1` active company `Unified AI Engineering & Operations` (`e0f141c6-e469-4377-8255-44ec08ed19c0`, prefix `UNI`); `Central Verified Skill Registry` project online | **PASS** |
| **`A06`** | Paperclip 11 Corporate AI Agents Roster | `GET /api/companies/:id/agents` | `HTTP 200`; `11 / 11` corporate agents provisioned (`adapterType: "hermes_local"`, `4` Wave-1 `idle` + `7` Wave-2 `paused` standby, `7` `file,terminal,skills` + `4` read-only `file,skills`, `budgetMonthlyCents: 0` on `11/11`) | **PASS** |
| **`A07`** | Paperclip Unlimited Budget Governance | `GET /api/companies/:id/budgets/overview` | `HTTP 200`; `12` policies (`1` company + `11` agent), `12/12` with `amount: 0`, `isActive: false`, `hardStopEnabled: false`, `unpricedUsagePolicy: "allow"`, `activeIncidents: []` | **PASS** |
| **`A08`** | Office Bridge Realtime Snapshot & 33-Skill Catalog Sync | `GET /api/office-bridge/snapshot?refresh=1` + `GET /api/office-bridge/skills` | `HTTP 200`; `paperclip_reachable: true`, `11` normalized agents across `8` departments, `33` locked skills (`20` OSI-permissive + `13` `FETCH_FROM_UPSTREAM_ONLY`) | **PASS** |
| **`A09`** | Office Bridge Analytics & Bidirectional Telemetry | `GET /api/office-bridge/analytics` (before & after Group B) | `HTTP 200`; `timezone: "Asia/Jakarta"`, `corporateBudgets` all `null` (unlimited), post-Group-B `14` sessions across `11` distinct agents (`4,377` metered chat tokens) + `36` Paperclip runs | **PASS** |
| **`A10`** | Office Bridge Custom Runtime Registry & State Seam | `GET /registry` + `GET /state` | `HTTP 200` (`2.4 ms` / `1.4 ms`); `<OWNER_LLM_MODEL>` registered (`provider: "custom"`), `Paperclip × Hermes Unified Runtime`, `11` active role bindings | **PASS** |
| **`B01`** | `ceo` (`CEO Agent` — `pcceoagent`) | Profile audit + live `hermes_exec_daemon` (`ceo-advisor` + `sample-project/README.md`) | `0o700`, `.no-bundled-skills`, `skill_view(1)` + `read_file(1)`, `19,174` in / `742` out tokens, `0` cross-profile pollution | **PASS** |
| **`B02`** | `cto` (`CTO Agent` — `pcctoagent`) | Profile audit + live `hermes_exec_daemon` (`cto-review` + `src/domain.py`, `pyproject.toml`) | `0o700`, `.no-bundled-skills`, `skill_view(1)` + `read_file(2)`, `18,917` in / `864` out tokens, `0` cross-profile pollution | **PASS** |
| **`B03`** | `backend` (`Backend Developer` — `pcbackenddeveloper`) | Profile audit + live `hermes_exec_daemon` (`api-design-reviewer` + `openapi.yaml`, `src/app.py`) | `0o700`, `.no-bundled-skills`, `skill_view(1)` + `read_file(2)`, `24,591` in / `819` out tokens, `0` cross-profile pollution | **PASS** |
| **`B04`** | `frontend` (`Frontend Developer` — `pcfrontenddeveloper`) | Profile audit + live `hermes_exec_daemon` (`frontend-design` + `src/ui/billing_widget.mjs`) | `0o700`, `.no-bundled-skills`, `skill_view(1)` + `read_file(1)`, `18,676` in / `600` out tokens, `0` cross-profile pollution | **PASS** |
| **`B05`** | `devops` (`DevOps Engineer` — `pcdevopsengineer`) | Profile audit + live `hermes_exec_daemon` (`ci-cd-pipeline-builder` + `pyproject.toml`, `package.json`) | `0o700`, `.no-bundled-skills`, `skill_view(1)` + `read_file(2)`, `16,443` in / `635` out tokens, `0` cross-profile pollution | **PASS** |
| **`B06`** | `qa` (`QA Engineer` — `pcqaengineer`) | Profile audit + live `hermes_exec_daemon` (`senior-qa` + `test_order_billing.py`, `ui_contract.test.mjs`) | `0o700`, `.no-bundled-skills`, `skill_view(1)` + `read_file(2)`, `21,170` in / `535` out tokens, `0` cross-profile pollution | **PASS** |
| **`B07`** | `security-lead` (`Security Lead` — `pcsecuritylead`) | Profile audit + live `hermes_exec_daemon` (`ciso-advisor` + `config/sandbox-fixture.yaml`, `README.md`) | `0o700`, `.no-bundled-skills`, read-only `file,skills`, `skill_view(1)` + `read_file(2)`, `18,868` in / `517` out tokens, `0` cross-profile pollution | **PASS** |
| **`B08`** | `security-reviewer` (`Security Reviewer` — `pcsecurityreviewer`) | Profile audit + live `hermes_exec_daemon` (`security-audit` + `src/repository.py`, `src/sandbox_audit_fixture.py`) | `0o700`, `.no-bundled-skills`, read-only `file,skills`, `skill_view(1)` + `read_file(2)`, `21,680` in / `726` out tokens, `0` cross-profile pollution | **PASS** |
| **`B09`** | `findings` (`Findings Analyst` — `pcfindingsanalyst`) | Profile audit + live `hermes_exec_daemon` (`security-audit` + `sandbox_audit_fixture.py`, `sandbox-fixture.yaml`) | `0o700`, `.no-bundled-skills`, read-only `file,skills`, `skill_view(1)` + `read_file(3)`, `34,640` in / `1,338` out tokens, `0` cross-profile pollution | **PASS** |
| **`B10`** | `remediation` (`Remediation Reviewer` — `pcremediationreviewer`) | Profile audit + live `hermes_exec_daemon` (`security-vuln-remediation` + `sandbox_audit_fixture.py`, `repository.py`) | `0o700`, `.no-bundled-skills`, read-only `file,skills`, `skill_view(1)` + `read_file(2)`, `18,992` in / `619` out tokens, `0` cross-profile pollution | **PASS** |
| **`B11`** | `compliance` (`Report & Compliance Agent` — `pccompliancereporter`) | Profile audit + live `hermes_exec_daemon` (`compliance-os` + `LICENSE`, `.env.example`) | `0o700`, `.no-bundled-skills`, `productivity/pdf` disabled, `skill_view(1)` + `read_file(2)`, `19,992` in / `702` out tokens, `0` cross-profile pollution | **PASS** |

---

## 2. Group A (`A01–A10`) — Core Stack, Paperclip, Shared Hermes, Analytics & Unlimited Budgets

### `A01` — Core 6-Container Stack, Cgroup Footprint, Loopback Exposure & PostgreSQL Readiness (`PASS`)

Verified live via `/opt/allinagent/allinagent --production health --json`, `docker ps`, `docker stats --no-stream`, `ss -tln`, and `pg_isready`:

- **Multi-Tenant Coexistence**: `40` total running Docker containers on `<TARGET_VPS_HOSTNAME>` (`34` pre-existing multi-tenant containers **100% untouched** + `6` `allinagent-*` containers all `Up (healthy)`).
- **Loopback-Only Host Listeners (`ss -tln`)**:
  ```text
  LISTEN 0 65535 127.0.0.1:8200 0.0.0.0:*
  LISTEN 0 65535 127.0.0.1:8201 0.0.0.0:*
  LISTEN 0 65535 127.0.0.1:8202 0.0.0.0:*
  ```
  `allinagent-postgres` (`5432/tcp`), `allinagent-hermes` (`8650/tcp`), and `allinagent-vulnclaw` (`8660/tcp`) publish **zero** host ports.
- **Pre- vs Post-Group-B Cgroup Memory Footprint (`<= 1,536 MiB` Ceiling)**:

  | Container | Image | Pre-Group-B Memory | Post-11-Agent-Run Memory | Hard `mem_limit` | Health |
  |---|---|---|---|---|---|
  | `allinagent-postgres` | `postgres:16-alpine` | `85.70 MiB` (`53.56%`) | `95.73 MiB` (`59.83%`) | `160 MiB` | `Up (healthy)` |
  | `allinagent-vulnclaw` | `ghcr.io/vistapra/allinagent-vulnclaw:1.0.0-rc.8` | `21.27 MiB` (`33.24%`) | `28.67 MiB` (`44.80%`) | `64 MiB` | `Up (healthy)` |
  | `allinagent-hermes` | `ghcr.io/vistapra/allinagent-hermes:1.0.0-rc.8` | `304.10 MiB` (`67.87%`) | `275.50 MiB` (`61.49%`) | `448 MiB` | `Up (healthy)` |
  | `allinagent-paperclip` | `ghcr.io/vistapra/allinagent-paperclip:1.0.0-rc.8` | `518.80 MiB` (`85.33%`) | `530.80 MiB` (`87.30%`) | `608 MiB` | `Up (healthy)` |
  | `allinagent-office-bridge` | `ghcr.io/vistapra/allinagent-office-bridge:1.0.0-rc.8` | `54.89 MiB` (`49.01%`) | `59.54 MiB` (`53.16%`) | `112 MiB` | `Up (healthy)` |
  | `allinagent-office` | `ghcr.io/vistapra/allinagent-office:1.0.0-rc.8` | `61.05 MiB` (`42.40%`) | `63.55 MiB` (`44.14%`) | `144 MiB` | `Up (healthy)` |
  | **Total Stack** | **6 Containers** | **`1,045.81 MiB` (`68.09%`)** | **`1,053.79 MiB` (`68.61%`)** | **`1,536 MiB`** | **ALL HEALTHY** |

  Host `free -m` after executing all 11 corporate AI agents confirmed **`3,055 MiB` available RAM** (`~2.98 GiB` free headroom).
- **PostgreSQL Live Readiness**:
  - `docker exec allinagent-postgres pg_isready -U paperclip -d paperclip` -> `rc=0` (`81.2 ms`): `/var/run/postgresql:5432 - accepting connections`.
  - Relational row counts verified via `psql`: `{"companies": 1, "agents": 11, "projects": 1, "budget_policies": 12}`.

### `A02` — Virtual Office (`:8200`) & Office Bridge (`:8202`) Health + Fail-Closed Auth (`PASS`)

- `GET http://127.0.0.1:8200/api/health` -> **`HTTP 200 OK`** (`31.6 ms`):
  ```json
  {"ok": true, "service": "hermes3d"}
  ```
- `GET http://127.0.0.1:8200/login` -> **`HTTP 200 OK`** (`2.0 ms`, `ALLINAGENT — Owner Sign In` gate active).
- `GET http://127.0.0.1:8202/health` -> **`HTTP 200 OK`** (`2.1 ms`):
  ```json
  {
    "ok": true,
    "status": "healthy",
    "service": "office-bridge",
    "version": "1.0.0",
    "correlation_id": "ob-8aa8efa2-0f6",
    "paperclip_reachable": true,
    "latest_sequence": 76
  }
  ```
- Unauthenticated `GET http://127.0.0.1:8202/api/office-bridge/snapshot` -> **`HTTP 401 Unauthorized`** (`3.1 ms`, fail-closed Bearer token enforcement verified).

### `A03` — Paperclip Control Plane (`:8201`) Health & Automated Backup Verification (`PASS`)

- `GET http://127.0.0.1:8201/api/health` -> **`HTTP 200 OK`** (`13.6 ms`):
  ```json
  {
    "status": "ok",
    "version": "2026.1117.0",
    "serverVersion": "2026.1117.0",
    "commit": "c0f132898d2a2677312d8c72096187b27a3d9a38",
    "deploymentMode": "local_trusted",
    "deploymentExposure": "private",
    "authReady": true,
    "bootstrapStatus": "ready",
    "startupRecovery": {"phase": "ready"},
    "databaseBackup": {
      "enabled": true,
      "status": "ok",
      "latestBackup": {"name": "paperclip-initial-20261124T160337Z.sql.gz", "sizeBytes": 319616},
      "warnings": []
    }
  }
  ```

### `A04` — Shared Hermes Daemon (`:8650`) & Isolated VulnClaw Worker (`:8660`) Health (`PASS`)

- **Hermes Exec Daemon (`allinagent-hermes`, internal `:8650`)**:
  - `GET http://127.0.0.1:8650/health` -> **`HTTP 200 OK`**:
    ```json
    {
      "ok": true,
      "service": "hermes-exec-daemon",
      "status": "healthy",
      "max_concurrency": 1,
      "max_queue_size": 32,
      "profiles_root": "/var/lib/allinagent/hermes/profiles",
      "allowed_profiles": [
        "pcceoagent", "pcctoagent", "pcbackenddeveloper", "pcfrontenddeveloper",
        "pcdevopsengineer", "pcqaengineer", "pcsecuritylead", "pcsecurityreviewer",
        "pcfindingsanalyst", "pcremediationreviewer", "pccompliancereporter"
      ]
    }
    ```
  - Unauthenticated `POST http://127.0.0.1:8650/exec` -> **`HTTP 401 Unauthorized`** (constant-time `X-Internal-Exec-Token` check enforced).
- **VulnClaw Defensive Worker (`allinagent-vulnclaw`, internal `:8660`, air-gapped `allinagent_data`)**:
  - `vulnclaw_worker.py health --probe-http` -> **`HTTP 200 OK`**:
    `{"ok": true, "status": "healthy", "service": "vulnclaw-defensive-worker", "mode": "defensive_only", "vulnclaw_pinned_version": "0.4.1", "authenticated": true, "rss_mb": 25.45, "working_set_mb": 18.34, "subprocess_memory_reclaim": true, "authorized_workspaces_count": 2}` (`allowed_layers: ["L1", "L2"]`, `python_execute_enabled: false`, all `10` offensive capabilities blocked).

### `A05` — Paperclip Companies & Projects Inventory (`PASS`)

- `GET http://127.0.0.1:8201/api/companies` -> **`HTTP 200 OK`**:
  - `1` active organization: **`Unified AI Engineering & Operations`** (`id: e0f141c6-e469-4377-8255-44ec08ed19c0`, `issuePrefix: "UNI"`, `status: "active"`, `budgetMonthlyCents: 0`, `spentMonthlyCents: 0`).
- `GET http://127.0.0.1:8201/api/companies/e0f141c6-e469-4377-8255-44ec08ed19c0/projects` -> **`HTTP 200 OK`**:
  - Verified project **`Central Verified Skill Registry`** (`id: 95d76822-649d-4578-83f8-b9d6bc710ac3`, `status: "in_progress"`, `effectiveLocalFolder: "/var/lib/allinagent/skill-registry/reviewed"`).

### `A06` — Paperclip 11 Corporate AI Agents Roster (`PASS`)

- `GET http://127.0.0.1:8201/api/companies/e0f141c6-e469-4377-8255-44ec08ed19c0/agents` -> **`HTTP 200 OK`** (`11` agents, `all_zero_budget_cap: true`):

  | # | Paperclip UUID | Agent Name | Role | Wave Posture | Adapter | Toolsets | `budgetMonthlyCents` |
  |---:|---|---|---|---|---|---|---:|
  | 1 | `78a51e37-cff3-440c-8ec8-5ca1c762cc0d` | `CEO Agent` | `ceo` | Wave-1 (`idle`) | `hermes_local` | `file,terminal,skills` | `0` |
  | 2 | `d00c6e16-1604-485e-9300-486ca24c9728` | `CTO Agent` | `cto` | Wave-2 (`paused`) | `hermes_local` | `file,terminal,skills` | `0` |
  | 3 | `0b1ce378-5153-4f3c-a319-9826b8bcd667` | `Backend Developer` | `engineer` | Wave-1 (`idle`) | `hermes_local` | `file,terminal,skills` | `0` |
  | 4 | `3fa536f4-5d4a-4cbc-8d8a-9942b63e21fa` | `Frontend Developer` | `designer` | Wave-2 (`paused`) | `hermes_local` | `file,terminal,skills` | `0` |
  | 5 | `2f415de4-c35a-409d-a006-de70db3a5676` | `DevOps Engineer` | `devops` | Wave-2 (`paused`) | `hermes_local` | `file,terminal,skills` | `0` |
  | 6 | `07823b69-31d4-4875-8654-acee87fc190a` | `QA Engineer` | `qa` | Wave-1 (`idle`) | `hermes_local` | `file,terminal,skills` | `0` |
  | 7 | `9b39f7dd-b1b5-4c5b-ab1d-d114f01ea381` | `Security Lead` | `security` | Wave-2 (`paused`) | `hermes_local` | `file,skills` *(read-only)* | `0` |
  | 8 | `2fe87575-bcd1-4066-8d3b-0d5c48531a7a` | `Security Reviewer` | `security` | Wave-1 (`idle`) | `hermes_local` | `file,skills` *(read-only)* | `0` |
  | 9 | `5c2402cb-4c05-4489-b398-f5dfc2dd2b70` | `Findings Analyst` | `researcher` | Wave-2 (`paused`) | `hermes_local` | `file,skills` *(read-only)* | `0` |
  | 10 | `7df0d106-3a52-402e-8624-501ba287ee6e` | `Remediation Reviewer` | `security` | Wave-2 (`paused`) | `hermes_local` | `file,skills` *(read-only)* | `0` |
  | 11 | `4311b82e-ba30-4720-919e-ed3f94baa4dc` | `Report & Compliance Agent` | `pm` | Wave-2 (`paused`) | `hermes_local` | `file,terminal,skills` | `0` |

### `A07` — Paperclip Unlimited Budget Policies Verification (`PASS`)

- `GET http://127.0.0.1:8201/api/companies/e0f141c6-e469-4377-8255-44ec08ed19c0/budgets/overview` -> **`HTTP 200 OK`**:
  - **`12` total budget policies** (`1` `scopeType: "company"` + `11` `scopeType: "agent"`).
  - Across **all `12 / 12` policies**: `amount: 0`, `isActive: false`, `hardStopEnabled: false`, `notifyEnabled: false`, `unpricedUsagePolicy: "allow"`, `status: "ok"`.
  - `activeIncidents: []`, `pausedProjectCount: 0`, `pendingApprovalCount: 0`.

### `A08` — Office Bridge Snapshot & 33-Skill Supply-Chain Catalog Sync (`PASS`)

- `GET /api/office-bridge/snapshot?refresh=1` (authenticated in-memory via `OFFICE_BRIDGE_TOKEN`) -> **`HTTP 200 OK`** (`573.0 ms`):
  - `paperclip_reachable: true`, `company.id: "e0f141c6-e469-4377-8255-44ec08ed19c0"`, `agents_count: 11`, `departments_count: 8`, `governance_budget.policies_count: 12` (`active_policies_count: 0`).
  - All `11` agents dynamically bound to their exact Hermes runtime profiles (`pcceoagent` .. `pccompliancereporter`), all reporting `connectivity_state: "ONLINE"` (`4` `ACTIVE`/`IDLE`, `7` `STANDBY`/`PAUSED`).
- `GET /api/office-bridge/skills` -> **`HTTP 200 OK`**:
  - `manifest_hydrated: true`, `locked_skills_count: 33` (`20` OSI-permissive + `13` `FETCH_FROM_UPSTREAM_ONLY`), `agents_count: 11`.

### `A09` — Office Bridge Analytics & Telemetry Synchronization (`PASS`)

- `GET /api/office-bridge/analytics` (verified both baseline and post-Group-B):
  - Baseline: `HTTP 200` (`52.7 ms`), `timezone: "Asia/Jakarta"`, `corporateBudgets: {"dailySpendLimitUsd": null, "monthlySpendLimitUsd": null, "perAgentSoftLimitUsd": null, "alertThresholdPct": 80}`, `pricingModel.mode: "token_metered_reference_usd"`.
  - Post-Group-B (after 11-agent chat & execution verification): `HTTP 200`, `sessions_count: 14` across **`11 / 11` distinct corporate agents**, `runs_count: 36` live Paperclip heartbeat-runs synchronized, `totals`: `input: 2,582`, `output: 1,795`, `totalTokens: 4,377`, `durationMs: 44,800`.

### `A10` — Office Bridge Custom Runtime `/registry` & `/state` Seam (`PASS`)

- `GET /registry` -> **`HTTP 200 OK`** (`2.4 ms`):
  ```json
  {
    "models": {
      "<OWNER_LLM_MODEL>": {
        "id": "<OWNER_LLM_MODEL>",
        "provider": "custom",
        "pricing": "TOKEN_METERED_REFERENCE / COST UNKNOWN"
      }
    }
  }
  ```
- `GET /state` -> **`HTTP 200 OK`** (`1.4 ms`):
  - `profileName: "allinagent-company"`, `active_agents_count: 11`, `runtime`: `{"name": "Paperclip × Hermes Unified Runtime", "version": "2026.1117.0", "vendor": "ALLINAGENT", "status": "healthy", "active_model": "<OWNER_LLM_MODEL>", "governance": "paperclip_enforced"}`.

---

## 3. Group B (`B01–B11`) — Profile Isolation, Role-Scoped Skills & Live Execution Across All 11 Corporate Agents

### 3.1 Isolated Hermes Profile Directory & Skill Hygiene Audit (`11 / 11 PASS`)

Inspected directly inside `allinagent-hermes` under `/var/lib/allinagent/hermes/profiles/<profile_name>`:

| Test ID | Hermes Profile | Dir Mode | `.no-bundled-skills` *(hyphen)* | Legacy `.no_bundled_skills` | Installed `skills/` Entries (`SKILL.md` Verified) | `.usage.json` Locked & Pinned | Cross-Role Pollution |
|---|---|---|---|---|---|---|---|
| **`B01`** | `pcceoagent` | `0o700` | `true` | `false` | `ceo-advisor`, `c-level-skills` *(+ self-ref `autonomous-ai-agents/hermes-agent`)* | `true` (`2` role pkgs) | **`0`** |
| **`B02`** | `pcctoagent` | `0o700` | `true` | `false` | `cto-advisor`, `cto-review`, `senior-architect` | `true` (`3` role pkgs) | **`0`** |
| **`B03`** | `pcbackenddeveloper` | `0o700` | `true` | `false` | `api-design-reviewer`, `senior-architect`, `senior-backend` | `true` (`3` role pkgs) | **`0`** |
| **`B04`** | `pcfrontenddeveloper` | `0o700` | `true` | `false` | `frontend-design`, `react-best-practices` | `true` (`2` role pkgs) | **`0`** |
| **`B05`** | `pcdevopsengineer` | `0o700` | `true` | `false` | `ci-cd-pipeline-builder`, `senior-devops`, `terraform-skill` | `true` (`3` role pkgs) | **`0`** |
| **`B06`** | `pcqaengineer` | `0o700` | `true` | `false` | `pw`, `pw-coverage`, `pw-fix`, `pw-generate`, `pw-report`, `pw-review`, `senior-qa` | `true` (`7` role pkgs) | **`0`** |
| **`B07`** | `pcsecuritylead` | `0o700` | `true` | `false` | `ciso-advisor` | `true` (`1` role pkg) | **`0`** |
| **`B08`** | `pcsecurityreviewer` | `0o700` | `true` | `false` | `security-audit`, `senior-security` | `true` (`2` role pkgs) | **`0`** |
| **`B09`** | `pcfindingsanalyst` | `0o700` | `true` | `false` | `security-audit` | `true` (`1` role pkg) | **`0`** |
| **`B10`** | `pcremediationreviewer` | `0o700` | `true` | `false` | `focused-fix`, `security-vuln-remediation` | `true` (`2` role pkgs) | **`0`** |
| **`B11`** | `pccompliancereporter` | `0o700` | `true` | `false` | `compliance-os`, `docx`, `pdf` *(`productivity/pdf` disabled in `config.yaml`)* | `true` (`3` role pkgs) | **`0`** |

### 3.2 Sequential Live Role-Specialized Task Execution & Session Isolation (`B01–B11`)

Each of the **11 corporate AI agents** was executed live and sequentially (`1` worker at a time under `HEAVY_WORKER_CONCURRENCY=1`) via `hermes_exec_daemon` (`POST http://127.0.0.1:8650/exec`) against `/var/lib/allinagent/workspaces/sample-project` (plus verified via `POST /api/office-bridge/agents/:slug/chat` on Office Bridge). Before and after every single execution, all 11 SQLite `state.db` files were snapshotted to verify that the newly created `session_id` appeared **exclusively** inside the target agent's `state.db` (`cross_profile_pollution_count: 0` across all `11 / 11` runs).

#### `B01` — `ceo` (`CEO Agent`, `pcceoagent`) — **PASS**
- **Skill & Target Inspected**: `ceo-advisor` + `/var/lib/allinagent/workspaces/sample-project/README.md`
- **Execution Telemetry**: `HTTP 200`, `exit_code: 0`, worker inference `9.80 s`, session `local-e411b9ddbb1d8c55f764d3f558cc69d00e5d44510506548909ec50a17ec39d51`, `message_count: 5`, `tool_call_count: 2` (`skill_view: 1`, `read_file: 1`), `input_tokens: 19,174`, `output_tokens: 742`, `cross_profile_pollution_count: 0`.
- **Live Response Excerpt**:
  > *"To run an executive Go/No-Go release-readiness gate for order-billing-demo without becoming a bottleneck, I would delegate bounded sign-off ownership across the three leads: the engineering lead (CTO) verifies the core Python REST/SQLite billing engine, Node.js UI widget, and OpenAPI 3.1.0 contract alignment with SANDBOX_TEST_MODE disabled by default. The QA lead independently executes the stdlib Python unittest suite (`tests/test_order_billing.py`) and Node.js contract tests (`tests/ui_contract.test.mjs`) to deliver verified pass evidence across domain calculations, idempotency, and sandbox gating. Finally, the security lead (CISO) runs defensive static scans across `src/` and `config/`, confirms that `src/sandbox_audit_fixture.py` and `config/sandbox-fixture.yaml` remain inert benchmark fixtures isolated from runtime paths, and signs off on zero production-risk findings before release approval."*

#### `B02` — `cto` (`CTO Agent`, `pcctoagent`) — **PASS**
- **Skill & Target Inspected**: `cto-review` + `src/domain.py`, `pyproject.toml`
- **Execution Telemetry**: `HTTP 200`, `exit_code: 0`, worker inference `10.73 s`, session `local-13b9e83e7d576f079eda8b700fa031c51c9dfb733d35750ac8cefac6db09b57b`, `message_count: 6`, `tool_call_count: 3` (`skill_view: 1`, `read_file: 2`), `input_tokens: 18,917`, `output_tokens: 864`, `cross_profile_pollution_count: 0`.
- **Live Response Excerpt**:
  > *"Verdict: SHIP with minor sharpening — the zero-dependency (`dependencies = []` in `pyproject.toml`) stdlib-only design in `src/domain.py` avoids floating-point drift and third-party supply-chain risk by combining frozen dataclasses, strict integer/bool input guards, and deterministic half-up basis-point rounding (`(amount * bps + 5_000) // 10_000`). Its primary scaling and correctness cliffs are hardcoded `DISCOUNT_RATES_BPS` in source and uniform minor-unit ('cents') assumptions across `SUPPORTED_CURRENCIES` (such as `IDR`), which will require externalizing discount configuration and currency exponent rules before multi-region or high-velocity catalog expansion."*

#### `B03` — `backend` (`Backend Developer`, `pcbackenddeveloper`) — **PASS**
- **Skill & Target Inspected**: `api-design-reviewer` + `openapi/openapi.yaml`, `src/app.py`
- **Execution Telemetry**: `HTTP 200`, `exit_code: 0`, `duration_ms: 15,810`, session `local-cf4951d51bdacbe04b036928de483d1c9950bebd3a639f56217bbd40744af501`, `message_count: 7`, `tool_call_count: 3` (`skill_view: 1`, `read_file: 2`), `input_tokens: 24,591`, `output_tokens: 819`, `cross_profile_pollution_count: 0`.
- **Live Response Excerpt**:
  > *"The OpenAPI contract for `POST /api/v1/orders` models idempotency as an optional `Idempotency-Key` request header (maxLength 128) and specifies that a replay should return `200` with the same `OrderResponse`, versus `201` for first-time creation (`openapi/openapi.yaml`: paths `/api/v1/orders` lines 24-53). In `src/app.py`, the handler lower-cases and forwards the header to `OrderRepository.create_or_replay_order(...)` (`idempotency_key=hdrs.get(\"idempotency-key\")`, lines 91-116), but the application constructs the repository with `\":memory:\"` by default (line 38), which strongly suggests the idempotency mapping—and thus any persistence/replay—is process-local rather than a durable SQLite-backed boundary at the HTTP layer."*

#### `B04` — `frontend` (`Frontend Developer`, `pcfrontenddeveloper`) — **PASS**
- **Skill & Target Inspected**: `frontend-design` + `src/ui/billing_widget.mjs`
- **Execution Telemetry**: `HTTP 200`, `exit_code: 0`, `duration_ms: 13,443`, session `local-efc0ad11c222cf6ae7869ac4195f26c814cbbb4ca6620abc76a2e9629d2695be`, `message_count: 6`, `tool_call_count: 2` (`skill_view: 1`, `read_file: 1`), `input_tokens: 18,676`, `output_tokens: 600`, `cross_profile_pollution_count: 0`.
- **Live Response Excerpt**:
  > *"Client-side validation is fairly strong for structure and numeric safety: `renderInvoiceSummaryCard` requires an `order.invoice`, and `formatMinorUnits` enforces supported currency codes plus `amountCents` being a safe integer (throwing on invalid values)... For XSS safety, the invoice summary rendering is largely well-defended: every untrusted text interpolation (`order_id`, `customer_id`, `applied_discount_code`, and all formatted monetary strings) is run through `escapeHtml` before being embedded into HTML, including the `data-order-id` attribute and the discount badge."*

#### `B05` — `devops` (`DevOps Engineer`, `pcdevopsengineer`) — **PASS**
- **Skill & Target Inspected**: `ci-cd-pipeline-builder` + `pyproject.toml`, `package.json`
- **Execution Telemetry**: `HTTP 200`, `exit_code: 0`, `duration_ms: 10,818`, session `local-102f317b9bc6be768dd5fe0de23ae29b70b774453fac206d5d9405f196514b10`, `message_count: 6`, `tool_call_count: 3` (`skill_view: 1`, `read_file: 2`), `input_tokens: 16,443`, `output_tokens: 635`, `cross_profile_pollution_count: 0`.
- **Live Response Excerpt**:
  > *"Since `pyproject.toml` has `dependencies = []` and only declares `requires-python >= 3.10`, the Python check stage can run with zero extra dependency setup (e.g., `python -m unittest discover` based on the `tests`/`test_*.py` config). Next, run the Node.js stage using `package.json`’s `test` script (`node --test tests/ui_contract.test.mjs`) after ensuring a Node runtime matching `engines.node >=20`. Overall stage order: Python unit checks first, then Node tests, so you fail fast on the dependency-free Python correctness gate before spending time on the Node UI-contract test."*

#### `B06` — `qa` (`QA Engineer`, `pcqaengineer`) — **PASS**
- **Skill & Target Inspected**: `senior-qa` + `tests/test_order_billing.py`, `tests/ui_contract.test.mjs`
- **Execution Telemetry**: `HTTP 200`, `exit_code: 0`, `duration_ms: 24,688`, session `local-4998f86ebc19beafe397073380b25988d2309ad30460487e9677f463b000b3bd`, `message_count: 7`, `tool_call_count: 3` (`skill_view: 1`, `read_file: 2`), `input_tokens: 21,170`, `output_tokens: 535`, `cross_profile_pollution_count: 0`.
- **Live Response Excerpt**:
  > *"The Python suite covers discount + tax edge cases at the calculation layer (explicit `VOLUME10` discount applied before tax, with assertions on subtotal/discount/tax/total) and at the API layer (order creation with `discount_code=WELCOME5` and validation rejecting unknown/bad discount codes). It also includes a sandbox diagnostics gate test that verifies the diagnostics endpoint is correctly blocked with HTTP 403 + `SANDBOX_MODE_DISABLED` when `SANDBOX_TEST_MODE` is off, and returns HTTP 200 with sandbox metadata (including `synthetic_fixture`) when enabled. The UI contract test complements this by checking that displayed minor units/totals render correctly for multiple currency formats and that untrusted invoice fields are HTML-escaped."*

#### `B07` — `security-lead` (`Security Lead`, `pcsecuritylead`, Read-Only `file,skills`) — **PASS**
- **Skill & Target Inspected**: `ciso-advisor` + `config/sandbox-fixture.yaml`, `README.md`
- **Execution Telemetry**: `HTTP 200`, `exit_code: 0`, `duration_ms: 10,186`, session `local-6a5792f75d9771c3fcb9269f485e5e0f7312182009aea64eec40f6c134e3dd79`, `message_count: 7`, `tool_call_count: 3` (`skill_view: 1`, `read_file: 2`), `input_tokens: 18,868`, `output_tokens: 517`, `cross_profile_pollution_count: 0`.
- **Live Response Excerpt**:
  > *"Require production deployments to enforce `SANDBOX_TEST_MODE=false` (or be fully unset) and verify it as a deployment gate, since the sandbox fixture explicitly notes that production defaults to `SANDBOX_TEST_MODE=false`. Ensure the runtime contract stays guarded: `GET /api/v1/sandbox/diagnostics` must continue to return `403` unless `SANDBOX_TEST_MODE=true`, with 'sandbox' configs restricted to non-production environments only. Finally, prevent accidental exposure by keeping the diagnostic/static benchmark code paths inert in production (e.g., the fixture is 'never imported' by the runtime app) and require config review/audit as part of release governance."*

#### `B08` — `security-reviewer` (`Security Reviewer`, `pcsecurityreviewer`, Read-Only `file,skills`) — **PASS**
- **Skill & Target Inspected**: `security-audit` + `src/repository.py`, `src/sandbox_audit_fixture.py`
- **Execution Telemetry**: `HTTP 200`, `exit_code: 0`, `duration_ms: 10,867`, session `local-7dc91a1c8287a1cb631b02356372409ec82b85fec72929bb96c90fd7a3594bd7`, `message_count: 7`, `tool_call_count: 3` (`skill_view: 1`, `read_file: 2`), `input_tokens: 21,680`, `output_tokens: 726`, `cross_profile_pollution_count: 0`.
- **Live Response Excerpt**:
  > *"In `src/repository.py`, SQLite access is consistently done with `?` placeholders and a separate parameter tuple (e.g., `WHERE idempotency_key = ?` and `WHERE order_id = ?`), which directly mitigates the classic CWE-89 pattern of building SQL strings via concatenation/interpolation. By contrast, `src/sandbox_audit_fixture.py` includes synthetic benchmark 'legacy' patterns that resemble CWE-89 (`f\"... '{customer_id}'\"`) and CWE-327 (using `hashlib.md5`)—but they’re explicitly inert (`raise RuntimeError` plus an unreachable `if False`), while the real helper functions show the secure counterparts (`?` parameterized SQL and SHA-256)."*

#### `B09` — `findings` (`Findings Analyst`, `pcfindingsanalyst`, Read-Only `file,skills`) — **PASS**
- **Skill & Target Inspected**: `security-audit` + `src/sandbox_audit_fixture.py`, `config/sandbox-fixture.yaml`
- **Execution Telemetry**: `HTTP 200`, `exit_code: 0`, `duration_ms: 17,189`, session `local-b847cccfe29a116b01acc33e8a8ee79b4c379cfb1601480ec18992c55bfa670c`, `message_count: 8`, `tool_call_count: 4` (`skill_view: 1`, `read_file: 3`), `input_tokens: 34,640`, `output_tokens: 1,338`, `cross_profile_pollution_count: 0`.
- **Live Response Excerpt**:
  > *"I’d deduplicate first by clustering findings that share the same root cause signature (same `src/sandbox_audit_fixture.py` region + same CWE/category and nearby lines for repeats from multiple scanners), then do a semantic pass so CWE-89 (SQLi string concatenation) and CWE-327 (MD5 hashing) stay distinct even if they appear in the same fixture (different sinks/impacts), while CWE-489 (permissive sandbox/testing flag) remains separate because it’s a config-level exposure, not a code-path vulnerability. For severity, I would classify CWE-89 and CWE-327 as LOW (or dropped/false-positive under 'test/dead code') because the insecure patterns are hard-gated behind an unreachable `if False` with an earlier `RuntimeError`... CWE-489 would be LOW/INFORMATIONAL."*

#### `B10` — `remediation` (`Remediation Reviewer`, `pcremediationreviewer`, Read-Only `file,skills`) — **PASS**
- **Skill & Target Inspected**: `security-vuln-remediation` + `src/sandbox_audit_fixture.py`, `src/repository.py`
- **Execution Telemetry**: `HTTP 200`, `exit_code: 0`, `duration_ms: 12,028`, session `local-5ddc0e8f44303be4a8218276f6bfda39819405cb45aa7500dcfd789b073f1a6b`, `message_count: 7`, `tool_call_count: 3` (`skill_view: 1`, `read_file: 2`), `input_tokens: 18,992`, `output_tokens: 619`, `cross_profile_pollution_count: 0`.
- **Live Response Excerpt**:
  > *"To mark CWE-89 (SQL injection) as RESOLVED, ensure every SQL query in `repository.py` uses parameterized/prepared statements (e.g., `... WHERE ... = ?` with a separate parameters tuple) and there is no reachable string interpolation of `customer_id`/inputs into SQL. To mark CWE-327 (weak cryptographic hash) as RESOLVED, ensure hashing uses a strong digest (the secure `compute_sha256_audit_digest()` -> `hashlib.sha256`) and that any weak-hash usage (e.g., `hashlib.md5`) is either removed or provably unreachable."*

#### `B11` — `compliance` (`Report & Compliance Agent`, `pccompliancereporter`) — **PASS**
- **Skill & Target Inspected**: `compliance-os` + `LICENSE`, `.env.example`
- **Execution Telemetry**: `HTTP 200`, `exit_code: 0`, `duration_ms: 11,433`, session `local-6fc918df898f3f70a781b3dc296412bb658cb8f4de81f9f171d760604395efb7`, `message_count: 7`, `tool_call_count: 3` (`skill_view: 1`, `read_file: 2`), `input_tokens: 19,992`, `output_tokens: 702`, `cross_profile_pollution_count: 0`.
- **Live Response Excerpt**:
  > *"MIT licensing is present and permissive in `LICENSE` (standard 'Permission is hereby granted…' MIT License text and 'THE SOFTWARE IS PROVIDED AS IS…'), satisfying the permissive MIT requirement. For non-secret configuration hygiene, `.env.example` contains only non-sensitive, local/demo values (host/port, currency/tax, and `SANDBOX_TEST_MODE=false`) and does not include credentials, tokens, private keys, or URLs that would indicate secret material."*

### 3.3 Post-Execution Workspace Cleanliness & Aggregate Telemetry Summary

- **Aggregate Worker LLM Telemetry (`state.db` across all 11 isolated `pc*` profiles)**:
  - Verified live responses: **`11 / 11` (`100%`)** (`0` mocked responses, `0` auth errors on active gateway models).
  - Verified live tool calls: **`30` total tool calls** (`11` `skill_view` calls + `19` `read_file` calls).
  - Verified token accounting: **`233,143` input tokens + `8,097` output tokens = `241,240` real tokens**.
  - Verified session isolation: **`0` cross-profile session leaks** across all 11 SQLite `state.db` databases; `/var/lib/allinagent/workspaces/sample-project` `git status --short` verified **`CLEAN`**.
- **Operational Observations for Owner Follow-Up (Non-Blocking)**:
  1. **External LLM Proxy Alias Target**: On `<OWNER_LLM_BASE_URL>`, the configured default alias `<OWNER_LLM_MODEL>` currently routes its primary upstream slot to a retired `claude-sonnet-4-6` model that returns `HTTP 200` text `"Claude Sonnet 4.6 is no longer available. Please switch to Claude Sonnet 5.5."` (preventing HTTP-status failover on the external proxy), whereas active models on the same `<OWNER_LLM_BASE_URL>` gateway (such as `gh/gpt-5.4-nano` and `openrouter/google/gemini-4-hydrogen`) execute multi-turn tool-calling cleanly in `10–24 s`. Repointing the `<OWNER_LLM_MODEL>` alias on the owner's external LLM gateway (or setting `LLM_MODEL=gh/gpt-5.4-nano` during the next maintenance window) will eliminate upstream retirement text responses during unattended Paperclip heartbeats.
  2. **Secret-Free Office Bridge Analytics Boundary**: By security design (`compose.yaml`), `allinagent-office-bridge` holds zero `CUSTOM_API_KEY` credentials and does not bind-mount `data/hermes`; `GET /api/office-bridge/analytics` therefore aggregates live Paperclip `heartbeat-runs` (`36` runs) and `office_chat` sessions (`14` sessions across all `11` agents, `4,377` metered tokens), while granular worker `state.db` token ledgers remain isolated inside `allinagent-hermes`.
