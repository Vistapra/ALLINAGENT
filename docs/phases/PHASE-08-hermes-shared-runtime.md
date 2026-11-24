# PHASE 08 — Shared Hermes Runtime Optimization & 11 Corporate Agents Portability

- **Phase ID:** `PHASE-08`
- **Status:** `PASS`
- **Scope:** `components/hermes/**`, `patches/hermes-agent/**`, `agents/**`, `docs/phases/PHASE-08-hermes-shared-runtime.md`

---

## 1. Executive Architecture Summary

On a constrained **2-vCPU / 8-GB RAM** production VPS (`<= 1,536 MiB` total cgroup budget across all ALLINAGENT containers), duplicating Python 3, `uv`, and the `hermes-agent` runtime inside every Node.js service container (`allinagent-paperclip` and `allinagent-office-bridge`), or spawning multiple concurrent Python LLM workers simultaneously, would cause severe RAM/disk bloat and swap thrashing.

`PHASE-08` solves this cleanly via a **Single Shared Hermes Runtime + Cross-Container Exec Bridge + Bounded FIFO Worker Queue**:

1. **Zero Upstream Vendoring & Zero `.git` Bloat (`< 75 MiB` vs `813 MiB`):**
   - [`components/hermes/bootstrap_hermes_source.py`](../../components/hermes/bootstrap_hermes_source.py) shallow-fetches `https://github.com/NousResearch/hermes-agent.git` at exact pinned commit `eb49b8920a25ffa7bb2fadf548fe819221ca79d7`, idempotently applies [`patches/hermes-agent/0001-error-classifier-integrator.patch`](../../patches/hermes-agent/0001-error-classifier-integrator.patch), writes a schema-v2 `install-stamp.json` (`baseVersion: "0.23.3"`, `displayVersion: "0.23.3+100"`, `distribution: "docker"`, `updateMechanism: "external"`), and strips `apps/desktop`, `website`, `tests`, `evals`, `nix`, `.github`, and `.git`.
   - `hermes_cli.version_info` reads `install-stamp.json` directly so `hermes --version` works cleanly without a `551 MiB` `.git` directory.
2. **Cross-Container Execution Daemon & Transparent Node CLI Shim (`0` Duplicate Python Venvs):**
   - [`components/hermes/hermes_exec_daemon.py`](../../components/hermes/hermes_exec_daemon.py) runs inside `allinagent-hermes` on `0.0.0.0:8650`, authenticated via constant-time `hmac.compare_digest` on `X-Internal-Exec-Token` (`ALLINAGENT_INTERNAL_TOKEN`, fail-closed).
   - [`components/hermes/hermes-cli-shim.mjs`](../../components/hermes/hermes-cli-shim.mjs) installs as `/usr/local/bin/hermes` inside `allinagent-paperclip` and `allinagent-office-bridge` (pure Node stdlib, zero npm dependencies). When `HERMES_REMOTE_EXEC_URL=http://hermes:8650` is set, it reads any local `--query-file` text, forwards `argv` + allowlisted `PAPERCLIP_*` / `HERMES_*` env vars to `hermes_exec_daemon.py`, streams `stdout`/`stderr`, and exits with `exit_code`.
   - Paperclip's `@paperclipai/hermes-paperclip-adapter` (`hermes_local`) and Office Bridge operate 100% natively without installing Python inside Node containers.
3. **Bounded Worker Concurrency (`HEAVY_WORKER_CONCURRENCY=1`) + Fast Metadata Probes:**
   - `hermes_exec_daemon.py` enforces a global `asyncio.Semaphore(int(os.environ.get("HEAVY_WORKER_CONCURRENCY", "1")))` so multi-agent Paperclip or Meeting Room dispatches queue cleanly in FIFO order without running concurrent heavy Python LLM workers on 2 vCPUs.
   - Read-only CLI metadata probes (`--version`, `-V`, `--help`, `-h`) bypass the heavy worker queue under an isolated probe semaphore (`15s` cap), ensuring Paperclip's `testEnvironment` (`10s` timeout) always succeeds in `< 1s` even during a long-running engineering task.
4. **Strict 11-Profile Isolation, Secret Stripping & `BUG-01` Fix:**
   - Strictly allowlists the 11 corporate profiles (`pcceoagent` .. `pccompliancereporter`), pins `HERMES_HOME=/data/hermes/profiles/<profile>`, enforces `0o700` directory permissions, writes `.no-bundled-skills` (**hyphenated** — fixing `BUG-01` where legacy underscore markers failed to match `tools/skills_sync.py`'s `NO_BUNDLED_SKILLS_MARKER`), and strips `TELEGRAM_BOT_TOKEN`, `OWNER_TELEGRAM_ID`, `ALLINAGENT_INTERNAL_TOKEN`, and `DATABASE_URL` from all child worker environments.
5. **Conditional Single-Poller Gateway Entrypoint (`components/hermes/entrypoint.sh`):**
   - [`components/hermes/entrypoint.sh`](../../components/hermes/entrypoint.sh) seeds `/data/hermes` (`0700`), syncs user-space extensions, starts `hermes_exec_daemon.py`, and **only** launches the single `hermes --profile default gateway run` poller when both `TELEGRAM_BOT_TOKEN` and `OWNER_TELEGRAM_ID` are non-empty and valid (rejecting unconfigured placeholders or `<OWNER_TELEGRAM_ID>` templates), with graceful `SIGTERM`/`SIGINT` handling for both processes.

---

## 2. Custom Upstream Patch & Reproducible Source Bootstrap

| Artifact | Purpose & Verification |
| :--- | :--- |
| [`patches/hermes-agent/0001-error-classifier-integrator.patch`](../../patches/hermes-agent/0001-error-classifier-integrator.patch) | Adds `"model_not_available_for_integrator",` to `_MODEL_NOT_FOUND_PATTERNS` in `agent/error_classifier.py` so OpenAI-compatible proxy/integrator model-unavailable responses trigger clean model fallback instead of burning retries. |
| [`components/hermes/bootstrap_hermes_source.py`](../../components/hermes/bootstrap_hermes_source.py) | Fetches `NousResearch/hermes-agent.git` @ `eb49b8920a25ffa7bb2fadf548fe819221ca79d7`, applies the patch idempotently (via `git apply` with deterministic anchor fallback), compiles `agent/error_classifier.py`, writes schema-v2 `install-stamp.json`, and strips non-runtime + `.git` directories. |
| [`components/hermes/config.worker.template.yaml`](../../components/hermes/config.worker.template.yaml) | Portable worker `config.yaml` template (`${LLM_MODEL}`, `${LLM_BASE_URL}`, `PAPERCLIP_*` env passthrough, backups/ledger/CUA autostart disabled). |

---

## 3. Canonical 11 Corporate Agents & Toolset Matrix (`agents/`)

All 11 corporate employees are defined under clean canonical directories in [`agents/`](../../agents/README.md), each containing `role-manifest.json`, `SOUL.md`, and `AGENTS.md` with OS-neutral `urllib.request` Paperclip API guidance and zero personal or environment-specific leaks:

| # | Directory | Role Slug | Hermes Profile | Default Tier | Toolsets | Key Phase-08 Fixes Applied |
| ---: | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | [`agents/ceo/`](../../agents/ceo/role-manifest.json) | `ceo_agent` | `pcceoagent` | Wave-1 (`ACTIVE`) | `["file", "terminal", "skills"]` | Portable `${SKILL_TOOLS_PYTHON:-python3}` & OS-neutral `urllib.request` helper |
| 2 | [`agents/cto/`](../../agents/cto/role-manifest.json) | `cto_agent` | `pcctoagent` | Wave-2 (`STANDBY`) | `["file", "terminal", "skills"]` | Independent ADR governance & portable skill paths |
| 3 | [`agents/backend/`](../../agents/backend/role-manifest.json) | `backend_developer` | `pcbackenddeveloper` | Wave-1 (`ACTIVE`) | `["file", "terminal", "skills"]` | Fixed `scripts/api_scorecard.py` typo (replacing `openapi_generator.py`) + generic [`LARAVEL-COMPATIBILITY.md`](../../agents/backend/LARAVEL-COMPATIBILITY.md) |
| 4 | [`agents/frontend/`](../../agents/frontend/role-manifest.json) | `frontend_developer` | `pcfrontenddeveloper` | Wave-2 (`STANDBY`) | `["file", "terminal", "skills"]` | Portable `${ALLINAGENT_ROOT}/hermes3d` protection boundary |
| 5 | [`agents/devops/`](../../agents/devops/role-manifest.json) | `devops_engineer` | `pcdevopsengineer` | Wave-2 (`STANDBY`) | `["file", "terminal", "skills"]` | Linux/Docker cgroup v2 & static IaC validation rules |
| 6 | [`agents/qa/`](../../agents/qa/role-manifest.json) | `qa_engineer` | `pcqaengineer` | Wave-1 (`ACTIVE`) | `["file", "terminal", "skills"]` | Ephemeral headless `${CHROMIUM_BIN:-chromium}` browser isolation |
| 7 | [`agents/security-lead/`](../../agents/security-lead/role-manifest.json) | `security_lead` | `pcsecuritylead` | Wave-2 (`STANDBY`) | `["file", "skills"]` | Strictly read-only (`terminal` disabled); portable `threat-model` reference |
| 8 | [`agents/security-reviewer/`](../../agents/security-reviewer/role-manifest.json) | `security_reviewer` | `pcsecurityreviewer` | Wave-1 (`ACTIVE`) | `["file", "skills"]` | Strictly read-only (`terminal` disabled); defensive OWASP/CWE review |
| 9 | [`agents/findings/`](../../agents/findings/role-manifest.json) | `findings_analyst` | `pcfindingsanalyst` | Wave-2 (`STANDBY`) | `["file", "skills"]` | Strictly read-only (`terminal` disabled); portable `anthropic-triage` & `cve-triage` |
| 10 | [`agents/remediation/`](../../agents/remediation/role-manifest.json) | `remediation_reviewer` | `pcremediationreviewer` | Wave-2 (`STANDBY`) | `["file", "skills"]` | Strictly read-only (`terminal` disabled); independent `RESOLVED`/`REWORK_REQUIRED` gate |
| 11 | [`agents/compliance/`](../../agents/compliance/role-manifest.json) | `compliance_reporter` | `pccompliancereporter` | Wave-2 (`STANDBY`) | `["file", "terminal", "skills"]` | **Fixed toolsets** to `["file", "terminal", "skills"]` enabling `skill_view` + `compliance-os` / `.docx` / `.pdf` report generators |

---

## 4. Portable Telegram Control Center Extensions (`agents/hermes-extensions/`)

- **Plugin ([`agents/hermes-extensions/plugins/unified-company-control/__init__.py`](../../agents/hermes-extensions/plugins/unified-company-control/__init__.py) & [`plugin.yaml`](../../agents/hermes-extensions/plugins/unified-company-control/plugin.yaml)):**
  - Registers all **59 slash commands** (`54` canonical Bahasa Indonesia control commands + `5` backward-compatible aliases), `unified_company_control` native tool, `post_gateway_admission` natural-language/Direct-Agent routing hook, `CallbackQueryHandler` (`^uac:`) with replay-ID forwarding and stale-card fallback, and `sendPhoto` multipart upload (`photo_path` + cross-container `photo_base64` support).
  - Resolves Office Bridge dynamically via `OFFICE_BRIDGE_HTTP_URL` (with `.allinagent_root` / `OFFICE_BRIDGE_PORT` fallback).
  - Enforces **fail-closed `OWNER_TELEGRAM_ID` validation**: rejects empty `""`, `"0"`, zero-padded 10-digit placeholders (`<OWNER_TELEGRAM_ID>`), or any non-numeric placeholder across slash commands, callbacks, inbound hooks, tool calls, and outbound Telegram HTTPS helpers.
- **Skill ([`agents/hermes-extensions/skills/unified-ai-platform/SKILL.md`](../../agents/hermes-extensions/skills/unified-ai-platform/SKILL.md)):**
  - Documents all 11 corporate agents and the complete 59-command / `unified_company_control` tool surface with zero hardcoded host paths or personal IDs.

---

## 5. Verification Evidence

All syntax checks, patch/stamp idempotency tests, live daemon-to-shim HTTP execution tests, concurrency serialization tests, and privacy scans passed with exit code `0`:

- **Static & Syntax Verification:**
  - `python -m py_compile` passed on `bootstrap_hermes_source.py`, `hermes_exec_daemon.py`, and `unified-company-control/__init__.py`.
  - `node --check components/hermes/hermes-cli-shim.mjs` passed.
  - `bash -n components/hermes/entrypoint.sh` passed; pure LF (`\n`) line endings verified on `.patch` and `.sh` files.
- **Patch & Stamp Verification:**
  - `0001-error-classifier-integrator.patch` applied cleanly via `git apply`, verified idempotent on re-run after `.git` removal, and `hermes_cli.version_info._stamp_version_info()` parsed `baseVersion="0.23.3"`, `displayVersion="0.23.3+100"`, `commit="eb49b8920a25ffa7bb2fadf548fe819221ca79d7"`, `distribution="docker"`.
- **Live Daemon + Shim End-to-End Integration:**
  - `GET /health` returned `HTTP 200` (`max_concurrency: 1`); invalid token rejected with `HTTP 401`; unauthorized profile (`--profile default`) rejected with `exit_code: 2`.
  - `--query-file` content forwarded across `hermes-cli-shim.mjs` $\rightarrow$ `hermes_exec_daemon.py` (`0o600` temp file unlinked after run); `.no-bundled-skills` (hyphenated) verified; `TELEGRAM_BOT_TOKEN` and `ALLINAGENT_INTERNAL_TOKEN` confirmed absent from child worker env.
  - Simultaneous dispatches (`pcceoagent` + `pcqaengineer`) executed strictly sequentially (`0` overlap) under `HEAVY_WORKER_CONCURRENCY=1`, while concurrent `hermes --version` completed immediately via the fast probe path.
- **Privacy & Leak Scan:**
  - Full recursive scan across `components/hermes/`, `patches/hermes-agent/`, `agents/`, and `docs/phases/PHASE-08-hermes-shared-runtime.md` confirmed **`0` personal identifiers, `0` private domains/paths, and `0` hardcoded UUIDs**.
