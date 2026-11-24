# PHASE 07 — Cross-Platform Windows-to-Linux Control Center Migration

- **Phase ID:** `PHASE-07`
- **Status:** `PASS`
- **Component Scope:** `apps/control-center/` (`control_center` & backward-compatible `integration` Python packages)
- **Verification Runtime:** Python 3.14 (`py_compile` across 26 modules + automated unit/integration test suite `tests/test_control_center_and_skills.py`)

---

## 1. Executive Summary

All first-party Python orchestration, governance, security-findings, workflow, maintenance, and reporting modules have been unified and ported into `apps/control-center/` as an installable package (`control_center`) with zero-copy module-identity shims under `integration/` (`pyproject.toml` + `sys.modules` aliasing). Every Windows-only path, PowerShell/Task-Scheduler dependency, `creationflags` crash vector, dummy owner fallback, and hardcoded workstation/UUID identifier has been eliminated while preserving 100% of functional capabilities across Ubuntu/Linux (Docker & systemd), macOS, and Windows.

---

## 2. Key Cross-Platform Remediations & Bug Fixes

| Area / Defect | Legacy Behavior | ALLINAGENT Cross-Platform Implementation |
|---|---|---|
| **Package & Import Layout** | Standalone scripts expecting hardcoded root path on `sys.path`. | `apps/control-center/pyproject.toml` exposes both `control_center.*` and `integration.*` (with `sys.modules` identity aliasing and direct-CLI `sys.path` bootstrap). |
| **Path & Service URL Resolver (`paths.py`)** | Hardcoded Windows drive letters and `127.0.0.1` ports; unsafe 10-digit placeholder fallback `OWNER_TELEGRAM_ID`. | Resolves `ALLINAGENT_ROOT`, `HERMES_HOME_ROOT`, `PAPERCLIP_BASE_URL`, `OFFICE_BRIDGE_URL`, `HERMES3D_URL`, `VULNCLAW_WORKER_URL`, `IS_WINDOWS = os.name == "nt"`, `venv_python_path()` (`bin/python` vs `Scripts/python.exe`), and **fail-closed `OWNER_TELEGRAM_ID`** (rejects `""`, `"0"`, 10-digit dummy placeholder IDs, and non-numeric strings). |
| **`BUG-01` Bundled Skills Marker (`hermes_worker_factory.py`)** | Wrote `.no_bundled_skills` (underscores), causing Hermes updates to copy 60+ bundled hub skills into worker profiles. | Writes `.no-bundled-skills` (**hyphens**) and removes any stale `.no_bundled_skills` marker. |
| **Worker Profile Permissions & Token Isolation (`hermes_worker_factory.py`)** | Unconditional `powershell.exe` + `icacls.exe`; risked copying gateway `.env` keys. | Branches `if IS_WINDOWS:` (`whoami /user` + `icacls.exe`) vs POSIX (`os.chmod(hermes_home, 0o700)` and `os.chmod(env_dst, 0o600)`), strips `TELEGRAM_BOT_TOKEN` / `TELEGRAM_*` / `DISCORD_*` / `SLACK_*`, and renders OS-neutral `config.yaml`, `SOUL.md`, and `AGENTS.md`. |
| **Organization Provisioning & Track-A / Track-B Support (`org_provisioner.py`)** | Hardcoded `"combo/X"` model, missing `"skills"` toolset on initial roster, fixed unlimited-only budget, and hardcoded UUIDs. | Dynamic `DEFAULT_LLM_MODEL`; adds `"skills"` across all 11 agents (`file,terminal,skills` on 7 operational roles; `file,skills` read-only on 4 security roles); supports `ALLINAGENT_BUDGET_MODE=unlimited` and `capped` (`ALLINAGENT_COMPANY_MONTHLY_CENTS`, `unpricedUsagePolicy: "allow"` unless `STRICT_PRICED_BUDGET=1`); supports both **Track-A fresh installs** (new UUIDs saved to `config/organization-roster.json`) and **Track-B DB migrations** (preserves existing UUIDs while rebinding stale Windows `cwd` / `instructionsFilePath` / `hermesCommand` / `HERMES_HOME` and project workspaces to Linux/container paths). |
| **Defensive VulnClaw Wrapper (`vulnclaw_defensive.py`)** | Unconditional Windows `creationflags=CREATE_NO_WINDOW` (raises `ValueError` on Linux), Windows `SystemRoot` env, and local-venv-only execution. | Supports on-demand HTTP `VULNCLAW_WORKER_URL` (`/api/diagnostics`, `/api/codescan`, `/api/triage`) with automatic isolated subprocess fallback (`bin/python` vs `Scripts/python.exe`), POSIX-clean minimal `env`, and Windows-guarded `creationflags`. |
| **SQLite Connection Lifecycle (`findings_engine.py`, `workflow_engine.py`)** | `with sqlite3.connect(...)` left file handles open until GC, triggering `ResourceWarning` and Windows `WinError 32` lock contention. | `@contextlib.contextmanager` `_connect()` commits on success, rolls back on error, and deterministically calls `conn.close()` in `finally:`. |
| **Host Telemetry & Maintenance (`platform_cli.py`, `maintenance_coordinator.py`)** | Spawned `powershell.exe` WMI/COM queries and checked hardcoded `C:\` / `D:\` drives. | Reads `/proc/meminfo`, `/proc/loadavg`, `/proc/uptime` on Linux (and native `ctypes` `GlobalMemoryStatusEx` on Windows) plus `shutil.disk_usage(ALLINAGENT_ROOT)`. |
| **Deterministic PDF + DOCX Exporter (`report_exporter.py` — `FEAT-28`)** | Relied on external Office tooling or ad-hoc agent scripts. | Provides `export_markdown_to_pdf_and_docx(md_path, out_dir)` using `reportlab` + `python-docx` (zero LibreOffice dependency) with spec-compliant stdlib PDF-1.4 and stdlib OpenXML `.docx` fallbacks, automatic secret redaction, and optional Telegram `sendDocument` delivery. |

---

## 3. Verification Evidence

1. **Bytecode Compilation (`py_compile`):** `26 / 26` Python modules across `apps/control-center` and `skills` compiled with exit code `0` (`0` syntax warnings).
2. **Automated Cross-Platform Test Suite (`tests/test_control_center_and_skills.py`):**
   - `test_01_package_alias_and_fail_closed_owner_id`: `PASS` (`control_center.paths is integration.paths`; `""`, `"0"`, and 10-digit placeholder IDs rejected fail-closed).
   - `test_02_worker_factory_bug01_hyphen_and_token_stripping`: `PASS` (`.no-bundled-skills` created, `.no_bundled_skills` removed, `TELEGRAM_BOT_TOKEN` stripped).
   - `test_03_org_provisioner_budgets_toolsets_and_track_ab`: `PASS` (7 `file,terminal,skills` + 4 `file,skills` agents verified; `unlimited` & `capped` policies verified; Track-A fresh UUID generation & Track-B UUID preservation + stale Windows path rebinding verified against mock Paperclip server).
   - `test_04_vulnclaw_http_worker_findings_and_host_metrics`: `PASS` (`VULNCLAW_WORKER_URL` HTTP mode, secret redaction, prompt-injection directive neutralization, fingerprint deduplication, and host metrics verified).
   - `test_05_report_exporter_pdf_and_docx_both_engines`: `PASS` (both `reportlab`/`python-docx` primary engines and `stdlib_pdf14`/`stdlib_ooxml` fallback engines verified via `pypdf.PdfReader` and `docx.Document`).
3. **Privacy & Sanitization Audit:** `0` private usernames, hostnames, Telegram IDs, private domains, local webroot paths, or hardcoded Paperclip UUIDs anywhere in `apps/control-center/`.
