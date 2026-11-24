# ALLINAGENT — 11 Canonical Corporate AI Agents & Hermes Gateway Extensions

This directory defines the **11 Corporate AI Employees** (`ceo/` .. `compliance/`) and the **Hermes Gateway Extensions** (`hermes-extensions/`) for **ALLINAGENT**.

## Organizational Roster (`1..11`)

| # | Directory | Role Slug | Hermes Profile | Display Name & Handle | Default Tier | Permitted Toolsets |
|---:|---|---|---|---|---|---|
| 1 | `ceo/` | `ceo_agent` | `pcceoagent` | **CEO Agent** (`@ceo`) | Wave-1 (`ACTIVE`) | `file`, `terminal`, `skills` |
| 2 | `cto/` | `cto_agent` | `pcctoagent` | **CTO Agent** (`@cto`) | Wave-2 (`STANDBY`) | `file`, `terminal`, `skills` |
| 3 | `backend/` | `backend_developer` | `pcbackenddeveloper` | **Backend Developer** (`@backend`) | Wave-1 (`ACTIVE`) | `file`, `terminal`, `skills` |
| 4 | `frontend/` | `frontend_developer` | `pcfrontenddeveloper` | **Frontend Developer** (`@frontend`) | Wave-2 (`STANDBY`) | `file`, `terminal`, `skills` |
| 5 | `devops/` | `devops_engineer` | `pcdevopsengineer` | **DevOps Engineer** (`@devops`) | Wave-2 (`STANDBY`) | `file`, `terminal`, `skills` |
| 6 | `qa/` | `qa_engineer` | `pcqaengineer` | **QA Engineer** (`@qa`) | Wave-1 (`ACTIVE`) | `file`, `terminal`, `skills` |
| 7 | `security-lead/` | `security_lead` | `pcsecuritylead` | **Security Lead** (`@security_lead`) | Wave-2 (`STANDBY`) | `file`, `skills` *(read-only)* |
| 8 | `security-reviewer/` | `security_reviewer` | `pcsecurityreviewer` | **Security Reviewer** (`@security`) | Wave-1 (`ACTIVE`) | `file`, `skills` *(read-only)* |
| 9 | `findings/` | `findings_analyst` | `pcfindingsanalyst` | **Findings Analyst** (`@findings`) | Wave-2 (`STANDBY`) | `file`, `skills` *(read-only)* |
| 10 | `remediation/` | `remediation_reviewer` | `pcremediationreviewer` | **Remediation Reviewer** (`@remediation`) | Wave-2 (`STANDBY`) | `file`, `skills` *(read-only)* |
| 11 | `compliance/` | `compliance_reporter` | `pccompliancereporter` | **Report & Compliance Agent** (`@compliance`) | Wave-2 (`STANDBY`) | `file`, `terminal`, `skills` |

## Directory Layout

- `<agent_dir>/role-manifest.json` — Canonical role metadata, Hermes profile isolation path (`/data/hermes/profiles/pc*`), runtime limits, toolset allowlist, and GitHub skill assignments.
- `<agent_dir>/SOUL.md` — Isolated worker persona & non-negotiable security boundary seeded into `<HERMES_HOME>/SOUL.md`.
- `<agent_dir>/AGENTS.md` — Complete operational specification, OS-neutral Paperclip API protocol, and progressive-disclosure skill routing loaded by Paperclip (`instructionsFilePath`).
- `backend/LARAVEL-COMPATIBILITY.md` — Polyglot PHP/Laravel vs Node/TS/Python framework safety guide for `@backend`.
- `hermes-extensions/plugins/unified-company-control/` — 59-command Telegram Control Center gateway plugin (`__init__.py` + `plugin.yaml`) with fail-closed `OWNER_TELEGRAM_ID` guard, `^uac:` inline callbacks, `post_gateway_admission` natural-language routing, and `sendPhoto` 3D/2D screenshot upload.
- `hermes-extensions/skills/unified-ai-platform/SKILL.md` — Companion Owner gateway skill for `unified_company_control`.
