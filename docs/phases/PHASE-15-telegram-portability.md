# PHASE 15 — Telegram Control Center Portability & Self-Service Onboarding

- **Phase ID:** `PHASE-15`
- **Status:** `PASS`
- **Scope:** `integrations/telegram/**`
- **Python Verification Runtime:** `<LEGACY_PLATFORM_ROOT>/runtime/skill-tools-venv/Scripts/python.exe` (`Python 3.14.9`)

---

## 1. Executive Summary

`PHASE-15` decouples the ALLINAGENT Telegram Control Center from all single-host hardcoded paths, hardcoded bot handles, and static numeric Owner IDs, enabling any operator on Ubuntu 24.04 LTS, Docker Compose, macOS, or Windows to pair their own BotFather bot and personal Telegram account safely in one command while preserving **100% functional parity** across all **59 slash commands**, **13 interactive submenus**, **`uac:*` inline callbacks**, **17 Bahasa Indonesia natural-language intent rules**, **DM-only authorization gates**, and **PNG/PDF/DOCX/media delivery contracts**.

---

## 2. Deliverables Created

| File Path | Purpose & Key Capabilities |
| :--- | :--- |
| `integrations/telegram/__init__.py` | Package entrypoint exporting canonical `COMMAND_CATALOG_PATH` and `BUNDLED_PLUGIN_DIR`. |
| `integrations/telegram/telegram_onboarding.py` | Cross-platform CLI & interactive wizard (`--check`, `--configure`, `--verify-single-poller`, `--offline-validate`, `--self-check`) for BotFather pairing, `0600` `.env` + `HERMES_HOME` provisioning, webhook inspection/cleanup, 59-command plugin installation, and duplicate-poller conflict prevention. |
| `integrations/telegram/command_catalog.json` | Machine-readable specification consumed by onboarding parity checks and Phase 27 Group D automated tests: all **59 slash commands**, **41 canonical commands**, **13 submenus**, **52 `uac:*` callback routes**, **17 Bahasa Indonesia NL intent rules**, **DM-only authorization rules**, and **media/PDF/DOCX delivery contracts**. |
| `integrations/telegram/unified-company-control/plugin.yaml` | Portable Hermes Gateway plugin manifest (`v2.0.0`, `unified_company_control` tool + `post_gateway_admission` hook). |
| `integrations/telegram/unified-company-control/__init__.py` | Reconciled cross-platform native Hermes plugin registering all **59 slash commands**, `^uac:` inline keyboard handler, fail-closed `OWNER_TELEGRAM_ID` enforcement, DM-only scope checks, and `sendMessage` / `sendPhoto` / `sendDocument` multipart delivery without ever calling `getUpdates`. |
| `integrations/telegram/test_telegram_onboarding.py` | Automated `unittest` suite (`7` test cases + `24` sub-assertions) covering syntax/Owner validation, token redaction, webhook clearing, `0600` atomic writes, split-brain/container poller conflict detection, and 59-command plugin execution. |

---

## 3. Architecture & Security Controls Verified

1. **Bot Token Validation & Redaction (`validate_bot_token_syntax`, `verify_bot_online`):**
   - Enforces exact BotFather token syntax `^\d{6,15}:[A-Za-z0-9_-]{30,}$` and rejects placeholder strings and zero-prefixed bot IDs.
   - Optional online check calls `https://api.telegram.org/bot<token>/getMe` and `https://api.telegram.org/bot<token>/getWebhookInfo`.
   - Warns when an active webhook URL would block `getUpdates` long-polling and clears it cleanly via `deleteWebhook` when `--clear-webhook` is requested (preserving queued updates unless `--drop-pending-updates` is specified).
   - Scrubs raw bot tokens from all JSON outputs, logs, and HTTP error messages (`mask_bot_token`, `redact_secrets`).
2. **Fail-Closed `OWNER_TELEGRAM_ID` Validation (`validate_owner_telegram_id`):**
   - Strictly requires a positive numeric Telegram user ID (`^[1-9]\d{4,19}$`).
   - **Explicitly rejects empty (`""`), `"0"`, zero-padded 10-digit placeholders (`<OWNER_TELEGRAM_ID>`), negative group/channel IDs (`-100...`), and non-digits** both during onboarding and at runtime inside `unified-company-control`.
3. **Atomic `0600` Configuration Provisioning (`upsert_dotenv_0600`):**
   - Atomically writes `TELEGRAM_BOT_TOKEN`, `OWNER_TELEGRAM_ID`, and `TELEGRAM_ALLOWED_USERS` into both `<ALLINAGENT_ROOT>/.env` and `<HERMES_HOME>/.env` while preserving existing comments and unrelated keys (`LLM_MODEL`, `CUSTOM_API_KEY`, etc.).
   - Enforces `0600` (`rw-------`) POSIX file permissions (`0700` on parent directory) and restrictive user/SYSTEM NTFS ACLs when run on Windows.
   - Synchronizes `.allinagent_root` marker and enables `telegram` + `unified-company-control` in `<HERMES_HOME>/config.yaml`.
4. **Single-Poller Lock Guard (`--verify-single-poller` / `verify_single_poller`):**
   - Inspects `<HERMES_HOME>/gateway.pid`, `<HERMES_HOME>/gateway.lock`, `<HERMES_HOME>/gateway-locks/*.lock`, local OS `hermes gateway run` processes, and running Docker containers (`docker ps`).
   - Detects and blocks split-brain lock files, multiple host pollers, multiple container replicas, and simultaneous host + Docker container pollers (`DUPLICATE_POLLER_CONFLICT`) so two pollers never compete on `getUpdates` (`HTTP 409 Conflict`).
5. **59-Command, Callback, NL & Attachment Parity (`command_catalog.json`):**
   - AST-verified 1:1 match between `command_catalog.json` (`59` slash commands) and `unified-company-control/__init__.py` (`59` `_SLASH_COMMANDS`), preserving `/persetujuan` so native Hermes `/approvals` never collides.
   - Full outbound attachment safety: `sendPhoto` (`photo_path`) and `sendDocument` (`document_path` / `attachments` for `.pdf`, `.docx`, `.xlsx`, `.pptx`, `.csv`, `.md`, `.zip`, plus Hermes native `MEDIA:<path>`) verify canonical `realpath`, enforce the 50 MiB Bot API cap, restrict delivery to Owner DM, and block secret files (`.env*`, `auth.json`, `office-bridge-auth.json`, `*.local.*`, SSH keys).

---

## 4. CLI Usage Reference

```bash
# 1. Offline validation of catalog (59 slash commands, 17 NL rules) & candidate credentials
python3 integrations/telegram/telegram_onboarding.py \
  --offline-validate \
  --bot-token "<BOTFATHER_TOKEN>" \
  --owner-id "<NUMERIC_USER_ID>"

# 2. Interactive first-run pairing wizard (reads token via hidden prompt)
python3 integrations/telegram/telegram_onboarding.py \
  --configure \
  --platform-root /opt/allinagent \
  --hermes-home /opt/allinagent/data/hermes-home \
  --clear-webhook

# 3. Verify single-poller safety across gateway.pid, gateway.lock, OS processes & Docker
python3 integrations/telegram/telegram_onboarding.py \
  --verify-single-poller \
  --hermes-home /opt/allinagent/data/hermes-home

# 4. Non-destructive deployment health & parity check
python3 integrations/telegram/telegram_onboarding.py \
  --check \
  --platform-root /opt/allinagent \
  --hermes-home /opt/allinagent/data/hermes-home \
  --json
```

---

## 5. Verification Evidence

- **Bytecode Compilation (`py_compile`):** `EXIT_CODE=0` across all Python modules.
- **Built-in Deterministic Self-Checks (`--self-check`):** `24 / 24` assertions passed (`[PASS] telegram_onboarding self-checks passed (24/24)`).
- **Offline Catalog & Parity Validator (`--offline-validate`):** `slash_commands=59`, `plugin_commands=59`, `nl_rules=17`, `submenus=13`, `callback_routes=52`, `errors=[]`.
- **Unit Test Suite (`unittest -v`):** `7 / 7` test cases passed (`0` errors, `0` warnings).
- **Privacy & Secret Scan:** `0` personal/private identifiers and `0` real credentials anywhere in `integrations/telegram/**` or this document.
