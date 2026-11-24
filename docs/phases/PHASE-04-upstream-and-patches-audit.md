# PHASE 04 — Upstream Source & Custom Patch Preservation Audit (with PHASE 00 Local Runtime State)

- **Phase ID:** `PHASE-04` (including `PHASE-00` Local Runtime Service & Task State)
- **Status:** `PASS` (**Critical Post-Snapshot Divergence Detected & Full Reconciliation Plan Defined**)
- **Host Audited:** `<WINDOWS_BASELINE_HOST>` (Windows)
- **Timestamp (UTC):** `2026-11-24T08:25:00Z`
- **Audit Mode:** Strictly Read-Only (`git --no-optional-locks`, SHA-256 byte-for-byte comparison, sanitized process/task inspection; **`0` working-tree mutations**, **`0` service restarts**, **`0` secrets read or logged**)

---

## 1. Executive Summary & Critical Findings

1. **100% of Live Windows Services Run from `<LEGACY_PLATFORM_ROOT>` & `<LOCAL_RUNTIME_DATA>/hermes` — `0` Run from `<LEGACY_MONOREPO_ROOT>`:**
   - Ports `3100` (Paperclip), `3200` (Hermes3D), `3210` (Office Bridge), and `54329` (Embedded PostgreSQL 16), plus the Hermes Telegram Gateway (`python.exe -m hermes_cli.main gateway run`) and `HermesUpdater`, are all actively running and healthy from `<LEGACY_PLATFORM_ROOT>`, `<WINDOWS_USER_HOME>/<LOCAL_RUNTIME_DATA>/hermes`, `<WINDOWS_USER_HOME>/<LOCAL_RUNTIME_DATA>/npm/node_modules/hermes-agent/runtime/hermes-agent`, and `<WINDOWS_USER_HOME>/HermesUpdater`.
2. **Critical Split-Divergence Between `<LEGACY_MONOREPO_ROOT>` (Nov 20) and `<LEGACY_PLATFORM_ROOT>` / `<LOCAL_RUNTIME_DATA>/hermes` (Nov 21–23):**
   - `<LEGACY_MONOREPO_ROOT>` (`HEAD d649451b057c75eca8f46ae127980e4f5bd65ec5`, `2026-11-20 22:02:43 +0700`) introduced valuable cross-platform path resolvers (`office-bridge/contracts/paths.js`, `integration/paths.py`, and 5 portable route fixes in `hermes3d`).
   - **However**, after `<LEGACY_MONOREPO_ROOT>` was created on Nov 20, **three major engineering waves were developed on Nov 21–23 directly inside `<LEGACY_PLATFORM_ROOT>`, `<LOCAL_RUNTIME_DATA>/hermes`, and `npm\hermes-agent` without being ported into `<LEGACY_MONOREPO_ROOT>`**:
     1. **23-Phase Telegram Control Center (`2026-11-21` to `2026-11-23`):** `8` new controller/UI/security modules in `<LEGACY_PLATFORM_ROOT>/office-bridge/telegram-control/`, `adapters/telegram-control-adapter.js` expanded from `95,065 B` to **`151,852 B`**, `<LOCAL_RUNTIME_DATA>/hermes/plugins/unified-company-control/__init__.py` expanded from `20,012 B` to **`25,518 B`**, plus `17` docs and `5` verification suites.
     2. **11-Agent GitHub Skill Registry & Security Gate (`2026-11-23`):** `integration/agent_skills_manager.py` (`34,161 B`), `office-bridge/adapters/agent-skills-bridge.js` (`25,104 B`), `skill-registry/{manifests,checksums,tests}` (`363.8 KB` manifests + `105.1 KB` checksums + `6` test suites), updated `org_provisioner.py` & `maintenance_coordinator.py`, and `24` per-role skill docs (only `4` summary/manifest files were copied into `<LEGACY_MONOREPO_ROOT>` on Nov 23).
     3. **Paperclip Hermes Adapter & Hermes Agent Patches (`2026-11-23`):** `2` critical patches in `packages/adapters/hermes/src/server/{execute,skills}.ts` (and compiled `runtime/paperclip-app/node_modules/@paperclipai/hermes-paperclip-adapter/dist/server/{execute,skills}.js`) for `--query-file` large-prompt handling and `skill-registry` (`--` namespaced) symlink/junction reconciliation, plus `hermes-agent` advancing to upstream `eb49b8920a25ffa7bb2fadf548fe819221ca79d7` (`2026-11-23`) with its `1`-line `agent/error_classifier.py` patch.
3. **98.9% Repository Bloat Elimination Strategy (`1,037.68 MiB` $\rightarrow$ `~11.5 MiB`):**
   - `<LEGACY_MONOREPO_ROOT>` reached `1,037.68 MiB` (`93,957` files, including `518.61 MiB` in `LEGACY_MONOREPO_ROOT/.git` alone) because it vendored `27,109` files (`254.00 MiB`) of `hermes-agent` (for a **1-line** patch) and `17,360` files (`245.78 MiB`) of `paperclip` (for a **2-file** adapter patch).
   - Adopting **Pinned Upstream Lockfile + Declarative Patch Layer + Tracked `hermes3d` & Reconciled First-Party Source** preserves **100% of custom features** in **`~11.5 MiB` (`<950` tracked files)** with zero `.git` object bloat and zero `node_modules`.

---

## 2. PHASE 00 — Empirical Local Windows Runtime State (`<WINDOWS_BASELINE_HOST>`)

### 2.1 Active Listening Ports & Processes

| Local Address & Port | PID | Process & Parent | Sanitized Command Line / Entrypoint | Working Set | Empirical Health Probe |
| :--- | ---: | :--- | :--- | ---: | :--- |
| `127.0.0.1:3100` | `11996` | `node.exe` (`node-26.12.1`)<br>Parent: `PaperclipServiceLauncher.exe` (`10764`) | `"<WINDOWS_USER_HOME>/<LOCAL_RUNTIME_DATA>/hermes/tools/node-26.12.1-win32-x64/node.exe" "<LEGACY_PLATFORM_ROOT>/scripts/paperclip-server-entry.mjs"` $\rightarrow$ loads `paperclipai@2026.1117.0` | `713.02 MB` | `GET /api/health` $\rightarrow$ **`HTTP 200`** (`status:"ok"`, `deploymentMode:"authenticated"`, `commit:"c0f13289..."`, `bootstrapStatus:"ready"`) |
| `127.0.0.1:3200` | `10760` | `node.exe` (`node-26.12.1`)<br>Parent: `OfficeServiceLauncher.exe` (`13572`) | `"<WINDOWS_USER_HOME>/<LOCAL_RUNTIME_DATA>/hermes/tools/node-26.12.1-win32-x64/node.exe" "<LEGACY_PLATFORM_ROOT>/hermes3d/source/server/index.js"` | `12.93 MB` | `GET /api/health` $\rightarrow$ **`HTTP 200`** (`{"ok":true,"service":"hermes3d"}`); `GET /` $\rightarrow$ `HTTP 401` (Access Gate enforced) |
| `127.0.0.1:3210` | `16900` | `node.exe` (`node-26.12.1`)<br>Parent: `OfficeServiceLauncher.exe` (`13572`) | `"<WINDOWS_USER_HOME>/<LOCAL_RUNTIME_DATA>/hermes/tools/node-26.12.1-win32-x64/node.exe" "<LEGACY_PLATFORM_ROOT>/office-bridge/server.js"` | `116.80 MB` | `GET /health` $\rightarrow$ **`HTTP 200`** (`{"ok":true,"status":"healthy","paperclip_reachable":true,"latest_sequence":7323}`); `GET /api/health` $\rightarrow$ `HTTP 401` |
| `127.0.0.1:54329` & `[::1]:54329` | `4728` | `postgres.exe` (+ `15` worker backends)<br>Parent: `node.exe` (`11996`) | `<LEGACY_PLATFORM_ROOT>/runtime/paperclip-app/node_modules/@embedded-postgres/windows-x64/native/bin/postgres.exe -D <LEGACY_PLATFORM_ROOT>/data/paperclip/instances/default/db -p 54329` | `13.09 MB` master / **`430.50 MB`** total (16 procs) | Verified via Paperclip `/api/health` (`databaseBackup.status:"ok"`) |
| `127.0.0.1:64513`, `64602` | `15452` | `python.exe` (`python-3.14.9`)<br>Parent: `cmd.exe` (`2468`) / `HermesGatewayLauncher.exe` (`16092`) | `<WINDOWS_USER_HOME>/<LOCAL_RUNTIME_DATA>/hermes/tools/python-3.14.9+20261021-win32-x64/python.exe -m hermes_cli.main gateway run` (`PYTHONPATH=...\npm\node_modules\hermes-agent\runtime\hermes-agent`) | `59.04 MB` | Active single-poller Telegram & messaging gateway (`HERMES_HOME=<WINDOWS_USER_HOME>/<LOCAL_RUNTIME_DATA>/hermes`) |
| *(No TCP listen)* | `11448` | `powershell.exe`<br>Parent: `HermesAutoUpdateLauncher.exe` (`9496`) | `powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -File "<WINDOWS_USER_HOME>/HermesUpdater/hermes-autoupdate.ps1" run` | `28.78 MB` (incl. launcher) | Active upstream git watcher & customization re-applicator |

- **Combined Local Platform Working Set on Windows:** **`~1,389.2 MB`** across `25` platform processes (`0` Windows SCM services; all supervised via Windows Task Scheduler + C# launcher executables).

### 2.2 Registered Windows Scheduled Tasks (`\` & `\Hermes\`)

| Task Path & Name | State | Last Result | Triggers | Sanitized Action |
| :--- | :--- | :--- | :--- | :--- |
| `\Hermes_Gateway` | `Running` | `2147946720` *(running)* | Logon, SessionChange, Event, Every `1m` | `HermesGatewayLauncher.exe //B //Nologo "<WINDOWS_USER_HOME>/<LOCAL_RUNTIME_DATA>/hermes/gateway-service/Hermes_Gateway.vbs"` |
| `\Hermes\HermesAutoUpdate` | `Running` | `2147946720` *(running)* | Daily `03:00`, Logon, Every `1m`, SessionChange, Event | `<WINDOWS_USER_HOME>/HermesUpdater/HermesAutoUpdateLauncher.exe run` |
| `\Hermes\HermesPostRebootVerify` | `Ready` | `0` (`OK`) | Logon | `powershell.exe ... -File "<WINDOWS_USER_HOME>/HermesUpdater/post-reboot-verify.ps1"` |
| `\Hermes\OfficeVirtualCompany` | `Running` | `267009` *(running)* | Logon | `<LEGACY_PLATFORM_ROOT>/runtime/bin/OfficeServiceLauncher.exe` (supervises `:3210` & `:3200`) |
| `\Hermes\PaperclipServer` | `Running` | `2147946720` *(running)* | Logon, SessionChange, Event, Every `1m` | `<LEGACY_PLATFORM_ROOT>/runtime/bin/PaperclipServiceLauncher.exe` (supervises `:3100` & `:54329`) |
| `\Hermes\PlatformHealthWatchdog` | `Ready` | `0` (`OK`) | Logon, Every `15m` | `powershell.exe ... -File "<LEGACY_PLATFORM_ROOT>/scripts/platform-watchdog.ps1"` |
| `\Hermes\PlatformMaintenance` | `Ready` | `1` | Daily `03:02`, Logon, SessionChange | `powershell.exe ... "& '<LEGACY_PLATFORM_ROOT>/runtime/bin/ai-platform.cmd' run-maintenance"` |

---

## 3. Git Repository & Upstream Version Inventory

All `.git` directories across the 5 target roots (excluding sandbox test fixtures in `workspaces/*`) were inspected read-only with `git --no-optional-locks`:

| Repository Path | Upstream Remote (`git remote -v`) | Branch | `HEAD` Commit SHA & Date | Tag / `git describe` | `.git` Size | `git status -s` & `git diff --stat` |
| :--- | :--- | :--- | :--- | :--- | ---: | :--- |
| `<WINDOWS_USER_HOME>/<LOCAL_RUNTIME_DATA>/npm/node_modules/hermes-agent/runtime/hermes-agent` | `https://github.com/NousResearch/hermes-agent.git` | `main` | `eb49b8920a25ffa7bb2fadf548fe819221ca79d7`<br>(`2026-11-23 14:05:46 -0500`) | `canary.20261123T065600Z-v0.23.3-100-geb49b8920a` (`baseVersion: 0.23.3`) | `551.50 MiB` | `1` modified (`M agent/error_classifier.py`: `+1` line) |
| `<LEGACY_PLATFORM_ROOT>/paperclip` | `https://github.com/paperclipai/paperclip.git` | `master` | `3dffb2c9dd391a50913833c0fbb439d7a2f313a8`<br>(`2026-11-18 17:38:38 -0800`) | `canary/v2026.1119.0-canary.830200-3-g3dffb2c9`<br>*(Runtime npm: `paperclipai@2026.1117.0` / `c0f13289`)* | `75.43 MiB` | `2` modified (`packages/adapters/hermes/src/server/{execute,skills}.ts`: `+63/-9` lines) |
| `<LEGACY_PLATFORM_ROOT>/vulnclaw` | `https://github.com/Netw0rkNoob/VulnClaw.git` | `main` | `0b34878f84b089b21fcf85ecd445315f14df0672`<br>(`2026-10-05 23:34:33 +0800`) | `v0.4.1` | `3.58 MiB` | **Clean** (`0` modified, `0` untracked) |
| `<LEGACY_PLATFORM_ROOT>/hermes3d/source` | `https://github.com/iamlukethedev/Hermes3D` | `integration/unified-ai-company` | `21215d77f2a5e526eb80692c0a44f05a4face7a1`<br>(`2026-11-19 19:39:30 +0700`) | `v1.0.0-6-g21215d7` (`2` custom commits above `origin/main` `beb7629`) | `7.77 MiB` | `24` modified (`+827/-105` lines) + `2` untracked (`TargetFolderPickerModal.tsx`, `standup3dAll11Agents.test.ts`) |
| `<LEGACY_MONOREPO_ROOT>` | *(none — local staging repo)* | `main` | `d649451b057c75eca8f46ae127980e4f5bd65ec5`<br>(`2026-11-20 22:02:43 +0700`) | `d649451` | `518.61 MiB` (`47,848` files) | `1` modified (`M THIRD_PARTY_NOTICES.md`: `+15`) + `3` untracked (`config/portable-skill-manifest.json`, `docs/AGENT-SKILLS-PORTABILITY.md`, `scripts/install-agent-skills.py`) |

*(Note: `<LEGACY_PLATFORM_ROOT>` root, `office-bridge`, `integration`, `skill-registry`, and `<WINDOWS_USER_HOME>/HermesUpdater` do not have `.git` directories; `<LEGACY_MONOREPO_ROOT>` stripped nested `.git` directories when importing subtrees.)*

---

## 4. Component-by-Component SHA-256 Tree Comparison & Patch Audit

### Summary Matrix Across All Audited Trees

*(Excludes `node_modules`, `.next`, `dist`, `data`, `logs`, `__pycache__`, `.git`, `venv`, `.cache`, `office-data`, and secret files.)*

| Component | Active / Platform Tree (`Left`) | `<LEGACY_MONOREPO_ROOT>` Tree (`Right`) | Identical | Only in `Left` | Only in `Right` | `Left` Newer (Nov 21–23) | `Right` Newer (Nov 20 Port) | Audit Verdict |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| **1. `hermes-agent`** | `27,551` (`npm\runtime`) | `27,106` | `26,296` | `449` | `4` | **`806`** | `0` | Pin `eb49b8920a` + `1`-line patch |
| **2. `paperclip`** | `17,357` | `17,357` | `17,355` | `0` | `0` | **`2`** | `0` | `LEGACY_MONOREPO_ROOT` **missing** Nov 23 `execute.ts` & `skills.ts` patches! |
| **3. `vulnclaw`** | `715` | `715` | **`715`** | `0` | `0` | `0` | `0` | **100% clean upstream `v0.4.1`** |
| **4. `hermes3d`** | `655` (`source/`) | `653` | `648` | `2` *(build)* | `0` | `0` | **`5`** | `LEGACY_MONOREPO_ROOT` has all 38 custom files + 5 portability fixes |
| **5. `office-bridge`** | `26` | `18` | `0` | **`10`** | **`2`** | **`8`** | **`8`** | **SPLIT DIVERGENCE — MUST MERGE** |
| **6. `integration`** | `9` | `10` | `0` | **`1`** | **`2`** | **`5`** | **`3`** | **SPLIT DIVERGENCE — MUST MERGE** |
| **7a. `hermes-extensions/plugins`** | `2` (`<LOCAL_RUNTIME_DATA>/hermes`) | `2` | `1` | `0` | `0` | **`1`** | `0` | **SPLIT DIVERGENCE — MUST MERGE** (`__init__.py`) |
| **7b. `hermes-extensions/skills`** | `384` (`<LOCAL_RUNTIME_DATA>/hermes`) | `1` | `0` | `383` *(hub)* | `0` | `0` | **`1`** | Take `LEGACY_MONOREPO_ROOT` `unified-ai-platform/SKILL.md` + manifest installer |
| **8. `scripts`** | `21` | `25` | `0` | `0` | **`4`** | `0` | **`21`** | Take `LEGACY_MONOREPO_ROOT/scripts` (portable) + isolate Windows `.cs`/`.ps1` |
| **9. `hermes-updater`** | `16` (`HermesUpdater`) | `10` | `0` | `6` *(exe/test)* | `0` | `0` | **`10`** | Windows-legacy; replace on Linux with Docker/systemd updater |
| **10. `config` & `skill-registry`** | `2` + `7` manifests | `3` | `1` | **`1` + `7`** | **`2`** | `0` | `0` | Merge `portable-skill-manifest.json` + `skill-registry/{manifests,checksums}` |
| **11. `docs` & `tests`** | `86` docs / `21` tests | `40` docs / `10` tests | — | **`41` docs / `11` tests** | `1` doc | — | `10` tests | Bring Nov 21–23 `docs/{telegram-control,agent-skills}` & E2E suites |

---

### Detailed Component Breakdown

#### 4.1 `hermes-agent` (`https://github.com/NousResearch/hermes-agent.git`)
- **Active Runtime State:** `<WINDOWS_USER_HOME>/<LOCAL_RUNTIME_DATA>/npm/node_modules/hermes-agent/runtime/hermes-agent` is at commit `eb49b8920a25ffa7bb2fadf548fe819221ca79d7` (`2026-11-23`), ~100+ upstream commits ahead of `<LEGACY_MONOREPO_ROOT>/hermes-agent` (snapshotted `2026-11-20` around `2de9f51b80`, which explains the `806` newer files and `449` added upstream files in `npm\runtime`).
- **Exact Custom Patch (`1` file, `+1/-0` lines):**
  - `agent/error_classifier.py` (line 353): inserts `"model_not_available_for_integrator",` immediately after `"no endpoints found that support tool use",` inside `_MODEL_NOT_FOUND_PATTERNS`.
  - Automatically re-applied after `git pull` by `<WINDOWS_USER_HOME>/HermesUpdater/config.json` (`CUSTOMIZATIONS` array).
- **Bloat Warning:** Full source tree is `261.84 MiB` (`27,554` files), dominated by `tests/` (`77.66 MiB`), `apps/desktop` Electron app (`51.01 MiB`), and `website/` (`27.50 MiB`), plus a `551.50 MiB` `.git` folder. None of that belongs vendored in `ALLINAGENT`.

#### 4.2 `paperclip` (`https://github.com/paperclipai/paperclip.git`)
- **Dual-Tree Discovery:**
  1. `<LEGACY_PLATFORM_ROOT>/paperclip` is a `17,360`-file (`245.78 MiB`) clone at `3dffb2c9dd391a50913833c0fbb439d7a2f313a8` (`2026-11-18`).
  2. **Actual Production Runtime (`:3100`)** runs from `<LEGACY_PLATFORM_ROOT>/runtime/paperclip-app` (`paperclipai@2026.1117.0`, upstream commit `c0f132898d2a2677312d8c72096187b27a3d9a38`) via `scripts/paperclip-server-entry.mjs`.
- **Critical Post-LEGACY_MONOREPO_ROOT Patches (`2026-11-23 10:26–10:51 +0700`) — MISSING FROM `<LEGACY_MONOREPO_ROOT>/paperclip`:**
  1. `packages/adapters/hermes/src/server/execute.ts` (`+16/-1`) and `runtime/paperclip-app/node_modules/@paperclipai/hermes-paperclip-adapter/dist/server/execute.js`:
     - Writes prompts to a temporary file (`os.tmpdir()/paperclip-hermes-query-*.txt`) and invokes `hermes chat --query-file <file>` whenever `process.platform === "win32" || prompt.length > 6000`, with guaranteed `fs.unlink(tempQueryFile)` in `finally {}`. Essential on Windows (avoids 32 KB `CreateProcessW` `ENAMETOOLONG`) and beneficial on Linux for large multi-agent context handoffs (`> 6,000` chars).
  2. `packages/adapters/hermes/src/server/skills.ts` (`+56/-8`) and `runtime/paperclip-app/node_modules/@paperclipai/hermes-paperclip-adapter/dist/server/skills.js`:
     - Extends `reconcileHermesPaperclipSkills` to recognize `skill-registry` paths and `--` namespaced skill links (`isManagedOrigin`), normalizes symlink/junction paths across OSes, and falls back to `materializePaperclipSkillCopy` on `EPERM`/`ENOSYS`. **Without this patch, 11-agent role skill reconciliation fails.**

#### 4.3 `vulnclaw` (`https://github.com/Netw0rkNoob/VulnClaw.git`)
- **100% Unmodified Upstream (`v0.4.1`, `0b34878f84b089b21fcf85ecd445315f14df0672`):**
  - `715 / 715` files are byte-for-byte identical between `<LEGACY_PLATFORM_ROOT>/vulnclaw` and `<LEGACY_MONOREPO_ROOT>/vulnclaw`, and `git status -s` is completely clean.
  - All defensive-only sandboxing and findings normalization reside cleanly in first-party `integration/vulnclaw_defensive.py` and `config/vulnclaw.defensive.yaml`.

#### 4.4 `hermes3d` (`https://github.com/iamlukethedev/Hermes3D`)
- **Heavily Customized Frontend & Server (`38` custom/modified files, `7.93 MiB` total clean source):**
  - Branched from upstream `beb7629` (`v1.0.0` + 4 upstream commits, including `#25` 2D Gather-style pixel office mode).
  - Contains `2` local commits (`dc22e94` adding the 6-tab Enterprise Command Center Overlay, Office Bridge live hook, `/api/company/[...slug]` proxy, security hardening; `21215d7` adding 30-day `studio_access` HttpOnly cookie) **plus** `26` uncommitted modified/untracked files (`TargetFolderPickerModal.tsx`, `standup3dAll11Agents.test.ts`, 11-agent 3D/2D standup & navigation fixes, real-time analytics hooks).
  - `<LEGACY_MONOREPO_ROOT>/hermes3d` already includes **100% of those 38 files** plus `5` cross-platform portability updates (`2026-11-20 13:18–13:50 UTC`) in `src/app/api/company/[...slug]/route.ts`, `src/app/api/path-suggestions/route.ts`, `src/app/api/runtime/custom/route.ts`, `EnterpriseOfficeOverlay.tsx`, and `TargetFolderPickerModal.tsx`. *(Only `server/index.js` retains 1 fallback `LEGACY_PLATFORM_ROOT` string to clean in `PHASE-07`.)*

#### 4.5 `office-bridge` (First-Party Service — **Split Divergence**)
- **Added/Updated in `<LEGACY_PLATFORM_ROOT>/office-bridge` on Nov 21–23 (`18` files):**
  - **10 files ONLY in `LEGACY_PLATFORM_ROOT`:** `adapters/agent-skills-bridge.js`, `telegram-control/analytics-budget-security-health.js`, `telegram-control/command-center-ui.js`, `telegram-control/command-registry.js`, `telegram-control/delegation-and-paperclip-controller.js`, `telegram-control/folder-and-dev-controller.js`, `telegram-control/jobs-notifications-nl-reliability.js`, `telegram-control/office-and-meeting-controller.js`, `telegram-control/security-guard.js`, `tests/phase02_03_arch_security.test.js`.
  - **8 files NEWER in `LEGACY_PLATFORM_ROOT`:** `adapters/telegram-control-adapter.js` (`151.8 KB` vs `95.1 KB`), `adapters/agent-chat-engine.js`, `adapters/analytics-telemetry-adapter.js`, `adapters/paperclip-adapter.js`, `contracts/agent-identity.js`, `events/realtime-synchronizer.js`, `server.js`, `tests/office-bridge.test.js`.
- **Added/Updated in `<LEGACY_MONOREPO_ROOT>/office-bridge` on Nov 20 (`10` files):**
  - `contracts/paths.js` (dynamic cross-platform path & `.env` resolver) + `package.json` (`ONLY_RIGHT`), plus path-portability edits in `target-folders-manager.js`, `vulnclaw-findings-adapter.js`, `authorization/auth.js`, `contracts/{event-schema,redaction,state-machine,ws-loader}.js`, and `tests/telegram-control.test.js` (`0` hardcoded `LEGACY_PLATFORM_ROOT` or `<WINDOWS_USER_HOME>` paths in `LEGACY_MONOREPO_ROOT`, vs `21` files in `LEGACY_PLATFORM_ROOT`).
- **Required Action in `PHASE-05` / `PHASE-12`:** Take all `26` files from `<LEGACY_PLATFORM_ROOT>/office-bridge`, add `contracts/paths.js` + `package.json` from `<LEGACY_MONOREPO_ROOT>/office-bridge`, and wire all `21` files with hardcoded Windows paths to `contracts/paths.js`.

#### 4.6 `integration` (First-Party Python Package — **Split Divergence**)
- **Added/Updated in `<LEGACY_PLATFORM_ROOT>/integration` on Nov 21–23 (`6` files):**
  - `agent_skills_manager.py` (`34,161 B`, `ONLY_LEFT` — GitHub Skill Registry & Security Gate engine), plus newer Nov 21–23 versions of `findings_engine.py`, `maintenance_coordinator.py`, `org_provisioner.py` (role skill provisioning), `platform_cli.py`, and `vulnclaw_defensive.py` (`12,862 B` vs `10,050 B`).
- **Added/Updated in `<LEGACY_MONOREPO_ROOT>/integration` on Nov 20 (`5` files):**
  - `__init__.py` and `paths.py` (`ONLY_RIGHT`), plus path-refactored `hermes_worker_factory.py`, `paperclip_client.py`, and `workflow_engine.py`.
- **Required Action in `PHASE-05` / `PHASE-07`:** Combine `<LEGACY_PLATFORM_ROOT>`'s 6 newer Nov 21–23 modules with `<LEGACY_MONOREPO_ROOT>`'s `__init__.py`, `paths.py`, and 3 portable modules, replacing hardcoded `<LEGACY_PLATFORM_ROOT>`/`<WINDOWS_USER_HOME>` strings with `integration.paths` and replacing `powershell`/`schtasks` calls in `hermes_worker_factory.py`, `maintenance_coordinator.py`, and `platform_cli.py` with POSIX/Linux equivalents.

#### 4.7 `agents/hermes-extensions` & `skill-registry`
- **`unified-company-control` Plugin (`__init__.py`):** `<WINDOWS_USER_HOME>/<LOCAL_RUNTIME_DATA>/hermes/plugins/unified-company-control/__init__.py` (`25,518 B`, `2026-11-23`) contains `+5.5 KB` of new Telegram Control Center commands/inline callbacks compared to `<LEGACY_MONOREPO_ROOT>` (`20,012 B`, `2026-11-20`), whereas `<LEGACY_MONOREPO_ROOT>`'s copy has dynamic `.allinagent_root` / `ALLINAGENT_ROOT` path resolution. Merge both in `PHASE-05`/`PHASE-15`.
- **`unified-ai-platform` Skill (`SKILL.md`):** `<LEGACY_MONOREPO_ROOT>/agents/hermes-extensions/skills/unified-ai-platform/SKILL.md` (`4,414 B`) is already the cleaner, path-portable version.
- **Role-Specific Skills & License Guardrail:** `<LEGACY_MONOREPO_ROOT>` has `config/portable-skill-manifest.json` (`54.4 KB`) and `scripts/install-agent-skills.py` (`6.3 KB`), while `<LEGACY_PLATFORM_ROOT>/skill-registry` has `manifests/*` (`363.8 KB`), `checksums/skill-checksums.json` (`105.1 KB`), and `tests/*` (`182.3 KB`). Include the manifests, checksums, and installer script in `ALLINAGENT`, while strictly keeping `skill-registry/{upstream,staging,reviewed,quarantine,agents}` **excluded** from Git so `Commons Clause v1.0 + MIT` (`borghei/Claude-Skills`) and unlicensed (`vercel-labs/agent-skills`) skills remain `FETCH_FROM_UPSTREAM_ONLY` at user install time.

---

## 5. Complete Four-Category Classification (`a` / `b` / `c` / `d`)

| Category | Exact Files & Subtrees | Handling in `ALLINAGENT` |
| :--- | :--- | :--- |
| **(a) First-Party Integration Code** | • `office-bridge/**` (`28` reconciled files, `~0.68 MiB`)<br>• `integration/**` (`11` reconciled Python modules, `~0.21 MiB`)<br>• `agents/roles/**`, `agents/organization-roster.template.json`, `agents/hermes-extensions/**` (`~0.13 MiB`)<br>• `hermes3d/src/features/enterprise-company/**`, `hermes3d/src/app/api/company/**`<br>• `config/portable-skill-manifest.json`, `config/resource-limits.json`, `config/vulnclaw.defensive.yaml`, `skill-registry/{manifests,checksums,tests}/**`<br>• `start-all.mjs`, `scripts/{setup-all.mjs,init-secrets.mjs,paperclip-server-entry.mjs,install-agent-skills.py,bootstrap_and_verify_paperclip.py,phase*.py}`, `docker-compose.yml`, `docs/**`, `tests/**` | **Commit 100% as first-class source** in `ALLINAGENT` (with `ALLINAGENT_ROOT` / `paths.js` / `paths.py` portability). |
| **(b) Custom Patches to Upstream** | • **`hermes-agent`:** `agent/error_classifier.py` (`+1` line: `"model_not_available_for_integrator"`)<br>• **`paperclip`:** `packages/adapters/hermes/src/server/execute.ts` (`+16/-1`) & `skills.ts` (`+56/-8`) + matching `dist/server/{execute,skills}.js` against `paperclipai@2026.1117.0`<br>• **`hermes3d`:** `35` modified upstream/feature files (`+3,145` lines across `server/*.js`, `next.config.ts`, `src/features/{office,pixel-office,retro-office}/**`, `src/lib/office/**`)<br>• **`vulnclaw`:** **`0` patches** (pure `v0.4.1`) | • Store `hermes-agent` & `paperclip` diffs as checksum-verified patch files under `patches/hermes-agent/` and `patches/paperclip/` applied automatically during Docker build & `install.sh`.<br>• Track `hermes3d/` (`7.93 MiB`) directly in `ALLINAGENT/hermes3d`. |
| **(c) Windows-Specific Adaptations** | • C# launchers & binaries: `PaperclipServiceLauncher.cs/.exe`, `OfficeServiceLauncher.cs/.exe`, `HermesGatewayLauncher.cs/.exe`, `HermesAutoUpdateLauncher.exe`, `CuaDriverProxy.cs`<br>• Task Scheduler & PowerShell scripts: `platform-watchdog.ps1`, `register-*.ps1`, `rotate-platform-credentials.ps1`, `Hermes_Gateway.cmd/.vbs`, `hermes-updater/*.ps1`, `Open-3D-Office.cmd`, `setup.ps1`, `start-all.ps1`<br>• Win32 toolchains (`4.59 GB`): `@embedded-postgres/windows-x64`, portable `python-3.14.9-win32`, `node-26.12.1-win32`, `chromium-1248`, `ffmpeg`, `git`<br>• OS-conditional branches & residual `powershell`/`schtasks` calls in `integration/*.py` | • **Exclude all `.exe`/win32 binaries (`0 B` in Git).**<br>• Isolate optional Windows host helper scripts under `scripts/windows-legacy/` (or replace with cross-platform Docker Compose).<br>• Replace `powershell`/`schtasks` calls in `integration/*.py` with POSIX process/systemd/Docker hooks in `PHASE-07`. |
| **(d) Runtime-Generated Files** | • Databases & state: `data/paperclip/instances/**`, `<LOCAL_RUNTIME_DATA>/hermes/{state.db*,kanban.db*,projects.db,sessions,memories,pairing,profiles,installs,tools,.hermes-clone-*}`<br>• Secrets: `.env*`, `auth.json`, `office-bridge-auth.json`, `*.local.*`<br>• Logs/telemetry/caches: `office-data/**`, `logs/**`, `reports/**`, `HermesUpdater/{state,logs}/**`, `tests/results_*.json`, `skill-registry/{upstream,staging,reviewed,quarantine,agents,reports}/**`<br>• Sandboxes & build outputs: `workspaces/*`, `node_modules/**`, `.next/**`, `dist/**`, `*-venv/**`, `__pycache__/**`, `tsconfig.tsbuildinfo`, `next-env.d.ts`, `install-stamp.json` | **Strictly `.gitignore` & `.dockerignore`** (`0 B` in Git; persist operational DBs/state via named Docker volumes / `/opt/allinagent/data` in `PHASE-17`/`PHASE-18`). |

---

## 6. Recommended Reproducible Source Strategy for `ALLINAGENT`

### Architecture Comparison

| Strategy | Git Tracked Files | Git Repo Size | VPS Build RAM Risk (`2 vCPU / 8 GB`) | License & Upstream Upgradeability | Verdict |
| :--- | ---: | ---: | :--- | :--- | :--- |
| *Anti-Pattern (`<LEGACY_MONOREPO_ROOT>` raw vendor)* | `93,957` | `1,037.68 MiB` (`518.61 MiB` `.git`) | **HIGH** (building 17k-file Paperclip Turborepo OOMs `< 3.4 GiB` `MemAvailable`) | Poor (monolithic vendor hides 1-line & 2-file patches) | **REJECT** |
| **Recommended: Pinned Upstream Lockfile + Declarative Patches + Direct `hermes3d` & First-Party Monorepo** | **`~920`** | **`~11.5 MiB`** | **LOW** (`paperclipai@2026.1117.0` prebuilt npm + shallow `hermes-agent` + multi-stage `hermes3d`) | **EXCELLENT** (40-char SHA pins, auditable `patches/*.patch`, zero Commons Clause vendoring) | **ADOPT (`PHASE-05`)** |

### Exact Repository Layout & Build Reproducibility Contract (`ALLINAGENT`)

```text
ALLINAGENT/                                 (~11.5 MiB total Git repository, < 950 tracked files)
├── config/
│   ├── upstream-locks.json                 # Exact pins: hermes-agent@eb49b892..., paperclipai@2026.1117.0, vulnclaw@0b34878f..., hermes3d-base@beb7629
│   ├── portable-skill-manifest.json        # 11-agent role skill pins (FETCH_FROM_UPSTREAM_ONLY enforced for restricted licenses)
│   ├── resource-limits.json                # 2-vCPU / 1,536 MiB cgroup & worker concurrency budgets
│   └── vulnclaw.defensive.yaml             # Strictly defensive static-analysis policy
├── patches/
│   ├── hermes-agent/
│   │   └── 0001-error-classifier-integrator.patch
│   └── paperclip/
│       ├── @paperclipai+hermes-paperclip-adapter+2026.1117.0.patch
│       └── paperclip-hermes-adapter-ts-source.reference.patch
├── hermes3d/                               # Clean source (~7.93 MiB, 653 files): all 38 custom 3D/2D/Enterprise files preserved
├── office-bridge/                          # Reconciled first-party service (~0.68 MiB, 28 files): Nov 21-23 Telegram/Skills + paths.js
├── integration/                            # Reconciled Python orchestration (~0.21 MiB, 11 files): Nov 21-23 Skills/SOC + paths.py
├── agents/
│   ├── roles/                              # 01-ceo_agent .. 11-compliance_reporter prompt & role specs
│   ├── hermes-extensions/                  # Reconciled unified-company-control plugin + unified-ai-platform skill
│   └── organization-roster.template.json
├── skill-registry/
│   ├── manifests/                          # Master skill lock, security scan results & assignments (NO cloned upstream repos)
│   ├── checksums/                          # SHA-256 verification manifests
│   └── tests/                              # Skill routing, persistence & benchmark suites
├── scripts/                                # Cross-platform setup, secret init, skill installer, patch applicator & E2E verifiers
├── docker/                                 # Multi-stage Dockerfiles (hermes-gateway, paperclip-server, office-bridge, hermes3d, vulnclaw-worker)
├── docs/ & tests/                          # Full platform, Telegram Control, Agent Skills & Phase audit documentation
├── docker-compose.yml                      # Production stack with postgres:16-alpine & strict cgroup memory caps
├── install.sh                              # One-command Ubuntu/Linux installer & first-run wizard
└── THIRD_PARTY_NOTICES.md                  # Full upstream attributions & license notices
```

###Deterministic Build & Patch Verification Flow
1. **`hermes-agent`:** Shallow-fetch exact commit `eb49b8920a25ffa7bb2fadf548fe819221ca79d7` from `NousResearch/hermes-agent.git` (`--depth 1`), strip non-runtime directories (`apps/desktop`, `website`, `tests`, `evals`, `nix` $\rightarrow$ reduces footprint from `261.8 MiB` to `< 75 MiB`), apply `patches/hermes-agent/0001-error-classifier-integrator.patch` with `git apply --check`, and install into a single shared Python `uv` environment (`PHASE-08`).
2. **`paperclip`:** Install exact locked `paperclipai@2026.1117.0` (`npm ci --omit=optional` on Linux automatically skips `@embedded-postgres/windows-x64` when pointed at `postgres:16-alpine`), and apply `patches/paperclip/@paperclipai+hermes-paperclip-adapter+2026.1117.0.patch` (`execute.js` + `skills.js`) during `postinstall` (`PHASE-09`).
3. **`vulnclaw`:** Shallow-fetch exact commit `0b34878f84b089b21fcf85ecd445315f14df0672` (`v0.4.1`) into an on-demand container/venv (`0` patches needed) governed by `integration/vulnclaw_defensive.py` (`PHASE-10`).
4. **`hermes3d`:** Build directly from `ALLINAGENT/hermes3d` using Next.js `standalone` output in CI/GHCR (`PHASE-11` / `PHASE-22`) so the `2 vCPU / 8 GB` production VPS pulls prebuilt images without running heavy Webpack/TypeScript builds on-host.
