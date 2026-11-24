---
name: unified-ai-platform
description: Full Owner Telegram remote control, 59-command suite, 3D/2D Virtual Office screenshot delivery, and 11-agent interactive selector for ALLINAGENT (Paperclip AI, Hermes Agent, isolated defensive VulnClaw, and Hermes3D 3D/2D Virtual Office).
---

# ALLINAGENT — Unified Autonomous AI Company Telegram Control Bridge

Use this skill and the native `unified_company_control` tool whenever the authorized Owner (`<YOUR_TELEGRAM_USER_ID>`) wants to control any aspect of the 3D/2D Virtual Office, select/switch/message any of the **11 Corporate Agents**, inspect role skills, gather or run a 3D/2D Meeting Room session, capture live 3D/2D office screenshots, browse/select/analyze authorized workspace folders, run software development checks (`git_status`, `cek_diff`, `buat_branch`, `test`), manage Paperclip projects/tasks/approvals, or inspect Analytics, Budgets, VulnClaw Security, and 15-Component Health.

## The 11 Corporate Agents (`1..11`)
1. `CEO Agent` (`@ceo`, Executive — Wave-1)
2. `CTO Agent` (`@cto`, Architecture — Wave-2)
3. `Backend Developer` (`@backend`, Engineering — Wave-1)
4. `Frontend Developer` (`@frontend`, Frontend & UI — Wave-2)
5. `DevOps Engineer` (`@devops`, DevOps & Runtime — Wave-2)
6. `QA Engineer` (`@qa`, Quality Assurance — Wave-1)
7. `Security Lead` (`@security_lead`, Cybersecurity — Wave-2)
8. `Security Reviewer` (`@security`, Cybersecurity — Wave-1)
9. `Findings Analyst` (`@findings`, SOC Triage — Wave-2)
10. `Remediation Reviewer` (`@remediation`, Security Remediation — Wave-2)
11. `Report & Compliance Agent` (`@compliance`, Audit & Governance — Wave-2)

## Fast Native Tool (`unified_company_control`)
Prefer calling `unified_company_control(command=..., args=...)` directly (routed via `$OFFICE_BRIDGE_HTTP_URL` with fail-closed `OWNER_TELEGRAM_ID` verification):

- **Dashboard, Agent Selection & Skills (`18` commands):**
  - `kantor` — Main 13-submenu interactive Telegram inline dashboard
  - `agen` — List all 11 corporate agents with live `ACTIVE` / `STANDBY` and 3D/2D state
  - `pilih` (`args="1..11 | nama | @handle"`) — Lock Direct-Agent chat to a chosen employee
  - `lepas` — Exit Direct-Agent lock back to general Hermes mode
  - `info_agen` (`args="[1..11|nama]"`) — 3D/2D Employee Inspector & session card
  - `daftar_skill` / `skill_agen` (`args="[agen]"`) — List specialized GitHub skills per role
  - `skill_info` (`args="<agen> [skill]"`) — Upstream source, commit SHA, license & security gate metadata
  - `skill_status` — Global skill registry & checksum verification status
  - `chat` (`args="<pesan>"`) — Send message/task to currently selected corporate agent
  - `ke` (`args="<agen> | <pesan>"`) — One-shot instruction to a specific agent without switching active lock
  - `reset_sesi` (`args="[agen] [--clear]"`) — View or clear isolated per-agent chat history
  - `bangunkan` (`args="<agen|semua>"`), `istirahatkan` (`args="<agen>"`) — Wake or pause agents
  - `delegasi` (`args="<instruksi>"`) — Trigger multi-agent CEO decomposition & delegation
  - `pause_dispatch` (`args="[pause|resume]"`), `stop_semua`, `standar_wave1` — Dispatch & formation controls
- **3D & 2D Virtual Office & Meeting Room (`7` commands):**
  - `status_kantor` (`args="[rooms|locs]"`) — Live 3D/2D room occupancy & avatar positions
  - `screenshot_kantor` (`args="[3d|2d]"`) — Capture and deliver live PNG screenshot via `sendPhoto`
  - `meeting` (`args="[topik/folder]"`) — Gather all 11 avatars into the 3D & 2D Meeting Room
  - `status_meeting` — Inspect 10-state meeting lifecycle, attendance & turn queue
  - `diskusi_rapat` (`args="[agen |] [topik]"`) — Run structured Bahasa Indonesia discussion round
  - `notulen` (`args="[history|--tasks]"`) — Generate meeting minutes, decisions & Paperclip action items
  - `selesai_meeting` (`args="[catatan]"`) — Conclude meeting and return all 11 avatars to their desks
- **Workspace Explorer, Deep Code Analysis & Dev Controls (`6` commands):**
  - `folder`, `jelajah` (`args="[path]"`), `cari_folder` (`args="<kata_kunci>"`), `pilih_folder` (`args="<path>"`) — Symlink-safe folder browser & target selector synced with 3D/2D UI
  - `analisis` (`args="[path] [| instruksi]"`) — Deep repository/code inspection & saved Markdown report
  - `dev` (`args="<git_status|cek_diff|buat_branch|test>"`) — Safe branch/diff/test controls
- **Paperclip Kanban, Analytics, Budgets, Approvals, Security & Health (`28` commands + aliases):**
  - `projects`, `buat_project`, `buat_task` / `create_task`, `daftar_task`, `cek_task` / `task_status`, `selesai_task`, `pause_task`, `resume_task`, `cancel_task`
  - `analytics` (`args="[today|yesterday|7d|30d|agents|runs]"`), `budget`, `set_budget` (`args="<daily|monthly> <usd>"`)
  - `persetujuan`, `setujui` (`args="<approval_id>"`), `tolak` (`args="<approval_id>"`)
  - `keamanan` / `security_report` (`args="[path|list|deps]"`), `triage_temuan` (`args="<FND-ID> <STATE>"`), `remediasi_temuan` (`args="[FND-ID]"`)
  - `kesehatan` / `platform_status`, `log_error`, `pulihkan_layanan`, `update_status`, `jobs`, `help_platform`

## Routing & Security Rules
- Only private DM messages from the validated numeric `OWNER_TELEGRAM_ID` are admitted (fail-closed when `OWNER_TELEGRAM_ID` is unset, zero, or a placeholder such as `<YOUR_TELEGRAM_USER_ID>`).
- Never expose tokens, API keys, internal auth headers, or `.env` values in Telegram replies.

## Raster Images on Telegram
When asked to generate a standalone raster chart/diagram directly in general Hermes mode, render it in Python (`Pillow`) under `<HERMES_HOME>/cache/deliveries/` and attach with `MEDIA:<path>` on its own line.
