# ALLINAGENT Control Center (`control_center` / `integration`)

Cross-platform Python orchestration, governance, defensive security findings pipeline, two-stage GitHub Skill Registry gate, and deterministic PDF/DOCX report exporter for **ALLINAGENT**.

## Modules

| Module | Responsibility |
|---|---|
| `control_center.paths` | Cross-platform path, venv binary (`bin/python` vs `Scripts/python.exe`), and service URL resolver with fail-closed `OWNER_TELEGRAM_ID` enforcement. |
| `control_center.hermes_worker_factory` | Provisions isolated `<HERMES_HOME_ROOT>/profiles/pc*` worker profiles with `.no-bundled-skills` (`BUG-01` fix), POSIX `0700`/`0600` vs Windows `icacls.exe`, stripped `TELEGRAM_BOT_TOKEN`, and OS-neutral `SOUL.md` / `AGENTS.md`. |
| `control_center.org_provisioner` | Provisions or Track-B migrates the 11-agent Paperclip corporate hierarchy with dynamic `DEFAULT_LLM_MODEL`, role-scoped `skills` toolsets, and configurable `unlimited` / `capped` budget policies. |
| `control_center.agent_skills_manager` | Implements the Stage-1 Security Gate (`skill-scanner` + SHA-256 + recursive Python AST scanner) and Stage-2 normalization, POSIX symlink / Windows junction materialization, and Paperclip Skills Store sync. |
| `control_center.vulnclaw_defensive` | Strictly defensive static code scan wrapper supporting both `VULNCLAW_WORKER_URL` HTTP worker containers and isolated subprocess fallback. |
| `control_center.findings_engine` | Deduplicating SQLite security findings store with prompt-injection directive neutralization and automatic Paperclip review/remediation issue creation. |
| `control_center.workflow_engine` | 13-stage task lifecycle state machine, circular-dependency prevention, idempotency ledger, and one-shot Telegram Owner notifications/documents. |
| `control_center.report_exporter` | Deterministic Markdown-to-PDF (`reportlab` + stdlib PDF-1.4 fallback) and Markdown-to-DOCX (`python-docx` + stdlib OpenXML fallback) report generator (`FEAT-28`). |
| `control_center.maintenance_coordinator` | Daily `03:00 Asia/Jakarta` active-work-aware maintenance coordinator with cross-platform disk guard and smoke tests. |
| `control_center.platform_cli` | Unified `allinagent-cli` / `ai-platform` CLI with Linux `/proc` & Windows native `ctypes` host telemetry. |

## Backward Compatibility

Both `import control_center.<module>` and `import integration.<module>` resolve to identical module instances via `pyproject.toml` and `integration/` alias shims.
