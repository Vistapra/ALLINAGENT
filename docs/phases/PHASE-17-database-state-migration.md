# PHASE 17 — Database, State & Private Data Migration

- **Phase ID:** `PHASE-17`
- **Status:** `PASS` (Track A Clean Public Workspace + Track B Encrypted Private Migration Toolkit Implemented & E2E Verified)
- **Timestamp (UTC):** `2026-11-24T10:41:00Z`
- **Scope:**
  - `workspaces/**` (Track A — Clean Public Seed & Zero-Trust Sandbox Documentation)
  - `scripts/migration/**` (Track B — AES-256-GCM Private Production State Migration Toolkit)
  - `docs/phases/PHASE-17-database-state-migration.md`

---

## 1. Executive Summary & Dual-Track Architecture

Phase 17 cleanly separates **public open-source repository readiness** from **private production state continuity** using a strict two-track design:

| Track | Target Audience | Storage Location | Contents & Guarantees |
| :--- | :--- | :--- | :--- |
| **Track A — Clean Public Workspace** | Every `git clone` user, CI runner, and fresh VPS deployment | `workspaces/README.md` + `workspaces/sample-project/` | **0 bytes** of real databases, memories, reports, or private business code. Ships an **MIT-licensed** synthetic polyglot microservice (`order-billing-demo`: Python 3 REST/SQLite + Node.js UI presenter + OpenAPI 3.1 + gated synthetic security fixture) ready immediately after clone. |
| **Track B — Encrypted Private State Migration** | Operator migrating an existing private Windows/Linux deployment to Ubuntu 24.04 LTS (`/opt/allinagent`) | `scripts/migration/export_private_state.py` & `scripts/migration/import_private_state.py` (bundles staged **only** in `$TEMP` / `/tmp`) | **AES-256-GCM** (`PBKDF2-HMAC-SHA256`, `600,000` iterations) encrypted archive with WAL-safe online `sqlite3.backup()`, Paperclip PostgreSQL dump + `master.key`, `organization-roster.json`, `office-data` stores, `maintenance.lock` quiescence guard, single-poller Telegram cutover lock, and legacy host path rewriting preserving the **Company UUID** and **all 11 Agent UUIDs**. |

---

## 2. Track A — Clean Public Workspace (`workspaces/`)

### 2.1 Sandboxing & Secret Exclusion (`workspaces/README.md`)

1. **`ALLOWED_WORKSPACE_ROOTS` Enforcement:**
   - Restricts Folder Picker browsing, `/analisis` source inspection, 11-agent file/branch operations, and defensive VulnClaw `codescan` runs strictly to canonicalized roots inside `/workspaces` (or `<ALLINAGENT_ROOT>/workspaces`), blocking symlink/junction escapes and denylisting `/data/hermes`, `config/secrets`, `master.key`, and OS system directories.
2. **Docker Project Mount Patterns:**
   - Documents `:rw` bind mounts (`./workspaces:/workspaces:rw`) for isolated Git worktree engineering tasks and `:ro` bind mounts for read-only `/analisis` and security audits.
3. **Zero-Trust `.env*` Secret Exclusion:**
   - `.env`, `.env.*` (excluding `.env.example`), `*.pem`, `*.key`, `*.pfx`, and SSH private keys are hidden from directory listings, rejected with `403 Forbidden` / `PermissionError` at read/scan boundaries, and protected by multi-pattern output redaction.

### 2.2 Synthetic Polyglot Microservice Fixture (`workspaces/sample-project/`)

`order-billing-demo` provides a realistic, zero-external-dependency polyglot codebase under the **MIT License**:

- **Backend (`src/domain.py`, `src/repository.py`, `src/app.py`):**
  - Pure integer-cents line-item calculation, basis-point discount tiers (`WELCOME5`, `VOLUME10`, `ANNUAL15`), half-up basis-point tax calculation, SHA-256 request fingerprinting, `Idempotency-Key` replay handling, and 100% parameterized SQLite (`?` placeholders) persistence.
  - Exposes 5 OpenAPI 3.1 endpoints (`GET /healthz`, `POST /api/v1/orders`, `GET /api/v1/orders/{order_id}`, `POST /api/v1/invoices/preview`, and feature-gated `GET /api/v1/sandbox/diagnostics` returning `403` unless `SANDBOX_TEST_MODE=true`).
- **Frontend Presenter (`src/ui/billing_widget.mjs`):**
  - ES module currency formatter (`USD`, `EUR`, `GBP`, `SGD`, `IDR`) and HTML-escaped invoice summary card renderer (`escapeHtml` preventing `CWE-79` DOM XSS).
- **Inert Static-Analysis Benchmark (`config/sandbox-fixture.yaml` & `src/sandbox_audit_fixture.py`):**
  - Unimported at runtime and hard-gated (`raise RuntimeError(...)` prior to `if False:` reference lines), providing deterministic non-secret static findings (`CWE-489` `unsafe_debug_true`, `CWE-89` `sql_string_concat`, `CWE-327` `weak_crypto`) paired with safe remediations so users can test VulnClaw `codescan` and 11-agent SOC triage right after `git clone`.

---

## 3. Track B — Encrypted Private State Migration Toolkit (`scripts/migration/`)

### 3.1 Cryptographic Envelope & Staging Contract (`export_private_state.py`)

```text
+-----------------------------------------------------------------------------------+
| Cleartext Authenticated Header (bound as AES-GCM AAD):                            |
|   Magic: b"AIASTATE" (8 B) | Version: 0x01 (1 B) | HeaderLen: uint32 BE (4 B)     |
|   JSON: { cipher: "AES-256-GCM", kdf: "PBKDF2-HMAC-SHA256",                       |
|           kdf_iterations: 600000, salt_b64 (32 B), nonce_b64 (12 B),              |
|           payload_sha256, created_at_utc, version: 1 }                            |
+-----------------------------------------------------------------------------------+
| AES-256-GCM Ciphertext + 128-bit Authentication Tag:                              |
|   PAX tar.gz containing manifest.json + WAL-clean SQLite DBs + Postgres dump +    |
|   Paperclip master.key + organization-roster.json + office-data continuity JSONs  |
+-----------------------------------------------------------------------------------+
```

- **Key Derivation & AEAD:** `cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC` (`hashes.SHA256()`, `32`-byte salt, `600,000` iterations) $\rightarrow$ `cryptography.hazmat.primitives.ciphers.aead.AESGCM` (`12`-byte CSPRNG nonce, full header bound as `AAD`).
- **Out-of-Repo Staging Guard (`assert_outside_git_repo`):** Staging directories (`tempfile.mkdtemp` in `$TEMP` / `/tmp`, mode `0700`) and `.aiaenc` output bundles (mode `0600` + `.aiaenc.sha256` sidecar) are strictly blocked from residing inside `ALLINAGENT` or any Git working tree, and ephemeral staging directories are removed unconditionally in `finally:`.

### 3.2 Online WAL-Safe SQLite Snapshots & State Scope

`export_private_state.py` **never** copies raw `-wal` or `-shm` files. Every SQLite database is snapshotted online via `sqlite3.connect(src).backup(dst, pages=250, sleep=0.02)`, normalized with `PRAGMA wal_checkpoint(TRUNCATE)` + `PRAGMA journal_mode=DELETE`, and verified with `PRAGMA integrity_check == 'ok'` + full per-table row counts:

1. **Hermes Root Gateway DB:** `hermes/state.db` (+ `SOUL.md`, `memories/*.md`)
2. **All 11 Canonical `pc*` Worker Profile DBs:**
   `pcceoagent`, `pcctoagent`, `pcbackenddeveloper`, `pcfrontenddeveloper`, `pcdevopsengineer`, `pcqaengineer`, `pcsecuritylead`, `pcsecurityreviewer`, `pcfindingsanalyst`, `pcremediationreviewer`, `pccompliancereporter` (`hermes/profiles/<profile_id>/state.db` + `SOUL.md`, `AGENTS.md`, `memories/*.md`, `.paperclip_key_meta.json`, `.no-bundled-skills` — excluding caches/LSP/venvs)
3. **Structured Security Findings DB:** `platform-data/findings/findings.db`
4. **Central Task & Audit Ledger DB:** `platform-data/workflow-ledger.db`
5. **Paperclip State & Continuity:**
   - `paperclip/paperclip_dump.sql` (`pg_dump --no-owner --no-acl --clean --if-exists` or `paperclipai db:backup`)
   - `paperclip/secrets/master.key` (preserves encrypted Paperclip secret bindings)
   - `paperclip/organization-roster.json` (verifies Company UUID + 11 distinct Agent UUIDs)
6. **`office-data` Continuity Stores:**
   `event-history/meetings.json`, `studio-state/hermes3d/standup-store.json`, `chat-history/*.json`, `analytics-budgets.json`, `company-layout.json`, `target-folders.json`, `event-history/notified-completions.json`, and `telegram-control-state.json` (each JSON-validated on export).

### 3.3 Quiescent Target Restore, Single-Poller Cutover & Path Rewriting (`import_private_state.py`)

On the target Ubuntu 24.04 LTS VPS (`/opt/allinagent`):

1. **Authentication, Tar-Slip Defense & Pre-Restore Hash Verification:**
   - Authenticates AAD + ciphertext via `AESGCM.decrypt`, rejects non-regular/symlink/traversal tar entries, verifies every file's byte length and SHA-256 against `manifest.json`, and runs `PRAGMA integrity_check` on all staged SQLite files in `/tmp` before touching `/opt/allinagent` or `/data/hermes`.
2. **Quiescent Service Check & Atomic `maintenance.lock`:**
   - Verifies application ports (`:3100`, `:3200`, `:3210`) and non-Postgres Docker Compose services are stopped, checks coordinator `state.json`, and acquires `/opt/allinagent/data/maintenance/maintenance.lock` via `O_CREAT | O_EXCL` (`0600`).
3. **Single-Poller Telegram Cutover Guard:**
   - Prevents Telegram Bot API `HTTP 409 Conflict` dual-polling: refuses `--start-gateway` (exit code `2`) and writes `/data/hermes/.telegram_cutover_lock` (`0600`) until the source host's poller is confirmed stopped and `--cutover-telegram` is explicitly passed.
4. **Clean SQLite, `master.key` & PostgreSQL Restore (`0700` / `0600`):**
   - Purges any stale target `-wal`/`-shm` sidecars before restoring each SQLite database via `sqlite3.backup()`, re-enables clean WAL mode, verifies `PRAGMA integrity_check`, and sets `0700` on directories and `0600` on state/secret files (plus optional `--chown uid:gid`).
5. **In-Place Paperclip `agents.adapter_config` Legacy Path Rewrite (Zero UUID Mutation):**
   - Restores `paperclip_dump.sql` into PostgreSQL and updates `public.agents.adapter_config` JSONB in-place (`WHERE id = '<existing_agent_uuid>'::uuid`), rewriting legacy Windows/host paths while keeping the **Company UUID** and **all 11 Agent UUIDs** 100% unchanged:
     - `<WINDOWS_USER_HOME>/<LOCAL_RUNTIME_DATA>/hermes/profiles/pc<role>` $\rightarrow$ `/data/hermes/profiles/pc<role>`
     - `<LEGACY_PLATFORM_ROOT>/workspaces` $\rightarrow$ `/workspaces`
     - `<LEGACY_PLATFORM_ROOT>/reports` $\rightarrow$ `/workspaces/reports`
     - `<LEGACY_PLATFORM_ROOT>/workers/<slug>/AGENTS.md` $\rightarrow$ `/data/hermes/profiles/pc<role>/AGENTS.md`
     - `<WINDOWS_USER_HOME>/.../hermes.exe` $\rightarrow$ `hermes`

---

## 4. Empirical Verification Evidence

| Verification Gate | Command / Harness Executed | Result |
| :--- | :--- | :--- |
| **Python Bytecode Compilation (`py_compile`)** | `py_compile.compile(..., doraise=True)` across all `9` `.py` files in `scripts/migration/` and `workspaces/sample-project/` | **`PASS` (`9/9` compiled cleanly, `0` `__pycache__` left in repo)** |
| **Sample Project Backend Unit Suite** | `python -m unittest discover -s workspaces/sample-project/tests -p "test_*.py" -v` | **`PASS` (`6/6` tests in `0.005s`: healthz, discounts/tax, idempotency replay/conflict, SQLite, sandbox gate, inert fixture)** |
| **Sample Project Frontend & OpenAPI Suite** | `node --test workspaces/sample-project/tests/ui_contract.test.mjs` | **`PASS` (`3/3` tests: currency minor units, XSS escaping, OpenAPI 3.1 endpoints & MIT license)** |
| **Sample Project Defensive VulnClaw Scan** | `vulnclaw.codescan.scanner.scan_code("workspaces/sample-project", layers=("L1","L2"))` | **`PASS` (`11` files scanned in `38.3 ms`; detects `CWE-489`, `CWE-89`, `CWE-327` benchmark findings; `0` hardcoded secrets)** |
| **Synthetic E2E Migration Roundtrip (`scratch/`)** | Full 7-stage harness on `14` active WAL SQLite DBs with uncheckpointed `-wal` frames (`1` root + `11` `pc*` + `findings.db` + `workflow-ledger.db`) | **`PASS` (`all_tests_passed: true`; `14/14` DBs & `18/18` WAL rows intact; repo-path export blocked; wrong key & 1-bit tamper rejected; `maintenance.lock` & Telegram cutover guard enforced; `11/11` Agent UUIDs preserved; paths rewritten to `/data/hermes/profiles/pc*` & `/workspaces`; all temp/scratch files cleaned)** |
| **Zero Private Data / Identifier Audit** | Automated scan across all Phase 17 deliverables | **`PASS` (`0` real DBs, `0` secrets, `0` personal usernames, hostnames, or business identifiers)** |

---

## 5. Deliverables Inventory

- `workspaces/README.md`
- `workspaces/sample-project/LICENSE`
- `workspaces/sample-project/README.md`
- `workspaces/sample-project/.env.example`
- `workspaces/sample-project/pyproject.toml`
- `workspaces/sample-project/package.json`
- `workspaces/sample-project/openapi/openapi.yaml`
- `workspaces/sample-project/config/sandbox-fixture.yaml`
- `workspaces/sample-project/src/__init__.py`
- `workspaces/sample-project/src/domain.py`
- `workspaces/sample-project/src/repository.py`
- `workspaces/sample-project/src/app.py`
- `workspaces/sample-project/src/sandbox_audit_fixture.py`
- `workspaces/sample-project/src/ui/billing_widget.mjs`
- `workspaces/sample-project/tests/test_order_billing.py`
- `workspaces/sample-project/tests/ui_contract.test.mjs`
- `scripts/migration/__init__.py`
- `scripts/migration/export_private_state.py`
- `scripts/migration/import_private_state.py`
- `scripts/migration/README.md`
- `docs/phases/PHASE-17-database-state-migration.md`
