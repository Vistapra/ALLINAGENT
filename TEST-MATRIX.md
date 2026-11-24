# ALLINAGENT — Comprehensive Verification & Production Acceptance Matrix

`ALLINAGENT` enforces multi-layered automated verification spanning static syntax/type gates, supply-chain checksum & license audits, cross-platform unit & contract suites, browser/3D/2D `vitest` harnesses, differential synthetic security benchmarks, live 8-group production end-to-end acceptance (`Groups A–H`), and clean-room fresh installation (`Track A`).

---

## 1. Automated Verification Suites Overview

| Suite / Gate | Runner & Target Files | Scope & Assertions | Execution Command | Status |
| :--- | :--- | :--- | :--- | :---: |
| **1. Cross-Platform CI & Security Suite** | `tests/run_ci_suite.py` (`py_compile` + `unittest` + E2E readiness) | **`78` checks** (`36` syntax + `12` lock/manifest + `20` security/portability + `9` bridge/TG contracts + `1` E2E plan) | `python3 tests/run_ci_suite.py` | `PASS` |
| **2. Hermes3D & 2D Office Frontend** | `apps/hermes3d/` (`vitest` + `tsc --noEmit` + `node --check`) | **`12` suites (`70` tests)** + `0` TS errors across `335` `src/` & `201` `tests/` files + `22` `.js/.mjs` server checks | `cd apps/hermes3d && npm ci && npx tsc --noEmit && npx vitest run` | `PASS` |
| **3. Unified Office Bridge Contracts** | `apps/office-bridge/tests/*.test.js` (`node --test`) | **`12 / 12` suites (`PASS`)**: HTTP `/health`, Bearer auth, Event Bus v1.0, Gateway v3 WS, 59-command CODEXE routing, `uac:pick:0` anti-self-replay, `/screenshot-kantor` `800x460` `\x89PNG` card, skills inspector | `cd apps/office-bridge && npm ci && npm test` | `PASS` |
| **4. Telegram & Connected Runner** | `integrations/telegram/test_*.py` + `integrations/connected-device/test_*.py` | **`14` `unittest` cases** (`7 + 7`) + `49` built-in `--self-check` assertions (HMAC-SHA256, single-poller, `0600` `.env`, path jail) | `python3 -m unittest integrations/telegram/test_telegram_onboarding.py integrations/connected-device/test_connected_device.py` | `PASS` |
| **5. Control Center & PDF/DOCX Exporter** | `apps/control-center/tests/test_control_center_and_skills.py` | **`6` `unittest` cases** (`reportlab` + `stdlib_pdf14` `%PDF-`, `python-docx` + `stdlib_openxml`, Stage-1/2 skills, Track A/B org) | `python3 -m unittest apps/control-center/tests/test_control_center_and_skills.py` *(inside shared `hermes` venv)* | `PASS` |
| **6. Synthetic Vulnerable API Benchmark** | `tests/fixtures/synthetic-order-api/tests/run_fixture_tests.py` | **`13` differential checks** (`SYN-F01`..`SYN-F04` seeded vulnerable vs. patched clean mode across Python & PHPUnit) | `python3 tests/fixtures/synthetic-order-api/tests/run_fixture_tests.py` | `PASS` |
| **7. Public Release & SBOM Gate** | `scripts/audit-public-release.py` + `scripts/generate-sbom.py` | Zero secrets/tokens/private paths, blank `.env.example`, `git ls-files` hygiene, CycloneDX 1.5 SBOM validation | `python3 scripts/audit-public-release.py --self-test && python3 scripts/generate-sbom.py --validate` | `PASS` |
| **8. Track A Sample Microservice** | `workspaces/sample-project/tests/` (`unittest` + `node --test`) | **`6` Python backend tests + `3` Node UI/OpenAPI tests** + deterministic `VulnClaw` `L1`/`L2` benchmark scan | `python3 -m unittest discover -s workspaces/sample-project/tests -p "test_*.py"` | `PASS` |

---

## 2. Detailed Breakdown of Automated Suites

### 2.1 Cross-Platform CI Suite (`tests/run_ci_suite.py` — `78` Assertions)

Runs offline with `ALLINAGENT_SKIP_DOTENV=1` and zero secret-file reads across both Linux and Windows:

| Stage ID | Module Path | Checks | Verified Invariants |
| :--- | :--- | :---: | :--- |
| `syntax.py_compile` | First-party `scripts/`, `apps/`, `components/`, `integrations/`, `tests/` | `36` | Zero syntax errors; bytecode compiled cleanly to ephemeral temp dir (`0` `__pycache__` pollution). |
| `unit.manifests_and_locks` | `tests/unit/test_manifests_and_locks.py` | `12` | 40-char commit SHAs in `components.lock.json`, 33 packages in `skills.lock.json`, 11 role manifests & toolsets, `LICENSE-INVENTORY.json` zero copyleft. |
| `unit.security_and_portability` | `tests/unit/test_security_and_portability.py` | `20` | `F01–F10` skill SHA-256 tamper rejection, Sentry `skill-scanner` quarantine, `.usage.json` lock; `H01–H10` secret redaction, cross-OS path jail, fail-closed `<OWNER_TELEGRAM_ID>`. |
| `contract.telegram_and_bridge` | `tests/contract/test_telegram_and_bridge_contracts.py` | `9` | Exact 59 slash commands & 13 `uac:sub:*` submenus, dynamic 11-agent `role_slug` resolution, `compose.production.yaml` `<= 1,536 MiB` ceiling & zero host DB ports. |
| `e2e.plan_readiness` | `tests/e2e/run_live_acceptance.py --verify-plan` | `1` | Validates live acceptance harness configuration (`6` active runtime groups when invoked with `--live`). |

### 2.2 Hermes3D & 2D Pixel Office (`vitest` — `12` Suites, `70` Tests + `tsc --noEmit`)

| Test Suite (`apps/hermes3d/tests/unit/`) | Tests | Coverage Focus |
| :--- | :---: | :--- |
| `phase11PortabilityAndEnrichment.test.ts` | `6` | Env-driven token/WS resolution, POSIX path sensitivity, corporate avatar tinting, `"● Telegram Synced"` header badge |
| `enterpriseCompanyIntegration.test.ts` | `5` | 6-tab `EnterpriseOfficeOverlay` state hydration, Kanban/SOC/Budget/Health data binding |
| `customRuntimeRoute.test.ts` | `3` | SSRF allowlist enforcement (`office-bridge` allowed; internal `paperclip:3100` & `postgres:5432` blocked) |
| `pathSuggestionsRoute.test.ts` | `4` | `ALLOWED_WORKSPACE_ROOTS` containment and `/etc`, `/proc`, `~/.ssh`, `.env` denylisting |
| `studioUpstreamGatewaySettings.test.ts` | `2` | Automatic override of stale loopback `ws://127.0.0.1:3210/ws` URLs inside Docker Compose |
| `gatewayEnvDefaults.test.ts` | `8` | `OFFICE_BRIDGE_TOKEN`, `OFFICE_BRIDGE_WS_URL`, and `HERMES3D_GATEWAY_URL` precedence rules |
| `gatewayProxy.test.ts` | `12` | Bidirectional WebSocket upgrade proxy (`/api/gateway/ws` & `/api/company/events/ws`) and upstream token injection |
| `multiavatar.test.ts` | `4` | Deterministic pure-MIT first-party SVG avatar generation (`0` dependency on removed `vendor/multiavatar.js`) |
| `standup3dAll11Agents.test.ts` | `2` | 14-seat conference room A* pathfinding and simultaneous `11 / 11` corporate agent attendance |
| `pixelOfficeInputs.test.ts` | `8` | 2D Pixel Office keyboard/pointer controls, camera pan/zoom, and interactive desk selection |
| `pixelOfficeSim.test.ts` | `10` | Real-time 2D agent state machine transitions (`idle`, `working`, `meeting`, `standby`) |
| `officeRenderMode.test.ts` | `6` | Instant client-side `3D WebGL` $\leftrightarrow$ `2D Pixel Office` mode switching and low-memory defaults |

### 2.3 Office Bridge (`node --test`), Telegram/Runner (`14` Tests) & Control Center (`6` Tests)

- **Office Bridge (`apps/office-bridge/tests/office-bridge.test.js` & `telegram-control.test.js`):** Verifies `/health`, constant-time `Bearer` token validation, Normalized Event Bus v1.0 (`500`-event ring + JSONL replay), Gateway Protocol v3 RPCs, all `59` Telegram CODEXE commands, `state_version` execution receipts, idempotency replay caching, `AbortController` job cancellation (`/batal_job`, `/stop_semua`), and read-only skill telemetry (`skills.status`).
- **Telegram Onboarding & Connected Device (`14` `unittest` cases):**
  - `integrations/telegram/test_telegram_onboarding.py` (`7` tests): BotFather syntax/redaction, fail-closed `<OWNER_TELEGRAM_ID>` validation (rejecting empty, `"0"`, negative group IDs, and 10-digit placeholder IDs), `0600` `.env` atomic upsert, single-poller lock conflict detection, and 59-command DM-only plugin enforcement.
  - `integrations/connected-device/test_connected_device.py` (`7` tests): Honest `server_workspace` independence when unpaired/offline, symlink escape blocking, wildcard `0.0.0.0` bind refusal, non-admin enforcement, HMAC-SHA256 + 60s skew + nonce replay guard, and `AUTHORIZED_WINDOWS_ROOTS` jail (`403` on `.env` and `/v1/exec`).
- **Control Center & PDF/DOCX Exporter (`6` `unittest` cases in `test_control_center_and_skills.py`):** Verifies `control_center.*` / `integration.*` alias parity, `.no-bundled-skills` worker isolation, Track A/B organization provisioning, `VulnClaw` directive neutralization, dual-engine `.pdf` (`reportlab` & `stdlib_pdf14`) and `.docx` (`python-docx` & `stdlib_openxml`) generation, and Stage-1/2 skill registry normalization + `--strict-oss` MIT fallbacks.

---

## 3. Synthetic Vulnerable Benchmark Fixture (`tests/fixtures/synthetic-order-api`)

`acmebistro-synthetic-order-api` (paired with `workspaces/sample-project/src/sandbox_audit_fixture.py`) provides an offline, MIT-licensed polyglot benchmark testing `VulnClaw` static scanning, `@security` review, `@findings` triage, `@backend` minimal-diff patching, and `@remediation` re-verification across four canonical vulnerability classes:

| Finding ID | Benchmark Class & CWE Mapping | Seeded Vulnerable Behavior | Verified Patched Behavior (`mode=patched_clean`) |
| :--- | :--- | :--- | :--- |
| **`SYN-F01`** | **SQL Injection / Input & Payment Integrity** (`CWE-89` / `CWE-840`) | Unparameterized query construction in sandbox audit fixture (`CWE-89`) and client-supplied `amount_cents` trust in `PaymentController.php` (`CWE-840`, CVSS `9.1`). | Enforces `?` bound SQLite parameters and server-authoritative `order_items + tax_cents - discount_cents` calculation (`HTTP 422 AMOUNT_MISMATCH`). |
| **`SYN-F02`** | **Broken Object Level Authorization / IDOR** (`CWE-639`, OWASP `API1:2023`) | `OrderOwnershipMiddleware.php` checks header presence (`X-User-Id` / `X-Guest-Token`) without verifying caller ownership of `{id}` (CVSS `8.2`). | Enforces strict `X-User-Id === order.user_id` and constant-time SHA-256 `X-Guest-Token` verification (`HTTP 403 ORDER_OWNERSHIP_VIOLATION`). |
| **`SYN-F03`** | **Checkout Redirect & State Race Condition** (`CWE-601` / `CWE-362`) | Unvalidated `callback_url` redirect injection in `PaymentGatewayService.php` and concurrent duplicate checkout initiation window. | Enforces `https://` allowlisted callback host validation (`HTTP 422 INVALID_CALLBACK_URL`) and atomic transactional checkout state locking. |
| **`SYN-F04`** | **Idempotency TTL, Rate-Limit & Secret Hygiene** (`CWE-672` / `CWE-489`) | Missing `expires_at` purge & payload binding in `IdempotencyGuard.php` plus debug/config exposure checks (`CWE-489`). | Purges expired keys, binds SHA-256 request hashes (`HTTP 409` on payload mismatch), enforces bounded TTLs, and verifies zero hardcoded secrets. |

---

## 4. Phase 27 Live Production Acceptance Matrix (`Groups A–H` + Coexistence — `113 / 113 PASS`)

Executed live on a multi-tenant Ubuntu 24.04.4 LTS VPS (`2 vCPU / 8 GiB RAM`) across **`113 / 113` acceptance checkpoints (`100% PASS`)**:

| Group | IDs | Score | Verification Domain | Empirical Live Outcome (`v1.0.0`) |
| :---: | :---: | :---: | :--- | :--- |
| **Group A** | `A01–A10` | **`10 / 10` `PASS`** | **Core Stack, Containers, TLS & Locks** | All `6 / 6` services healthy (`1,003.84–1,052.44 MiB / 1,536.00 MiB`); loopback-only `127.0.0.1:8200–8202`; `0` public DB/exec ports; `/office` Access Gate enforced; `12` unlimited budget policies active. |
| **Group B** | `B01–B11` | **`11 / 11` `PASS`** | **11 Corporate AI Agents** | All 11 personas (`@ceo`..`@compliance`) executed live multi-turn tool calls (`30` tool calls, **`241,240` real tokens**: `233,143` in / `8,097` out) inside `0700` `.no-bundled-skills` profiles with **`0` cross-profile pollution** and `0` `TELEGRAM_BOT_TOKEN` leaks. |
| **Group C** | `C01–C17` | **`17 / 17` `PASS`** | **3D WebGL & 2D Pixel Browser UI** | Live browser verification of `/login` Access Gate (`302`/`401`), Three.js 3D WebGL + Phaser 2D Pixel Office round-trip toggling, `11 / 11` Meeting Room attendance (`UNI-1`, `UNI-2`), `/etc` `403` jail, Marketplace, SOC, and Ops/Evid overlays (`0` console errors). |
| **Group D** | `D01–D17` | **`17 / 17` `PASS`** | **Telegram 59 Commands, NL & DM Delivery** | Full `59`-command CODEXE sweep, `13 / 13` `uac:sub:*` submenus, Bahasa Indonesia NL routing + `11 / 11` meeting (`notulen`), fail-closed `401`/`403`/`409` guards, single-poller lock (**`0` HTTP `409 Conflict`**), and live outbound Telegram DM delivery (`message_id: 191`). |
| **Group E** | `E01–E16` | **`16 / 16` `PASS`** | **7-Role Kanban, VulnClaw & PDF/DOCX** | End-to-end 7-role Kanban (`UNI-10`–`UNI-16` `done`), live `:ro` `VulnClaw` scan (**`9` findings $\rightarrow$ branch fix $\rightarrow$ `0` findings**), `8/8` QA regression tests, and verified `%PDF-1.4` + `.docx` (`word/document.xml`) generation & live Telegram DM delivery (`message_id: 193`, `194`). |
| **Group F** | `F01–F10` | **`10 / 10` `PASS`** | **Skill Supply-Chain Security Gate** | `33` locked skills (`20` OSI-permissive + `13` `FETCH_FROM_UPSTREAM_ONLY`), `11` excluded files, `.usage.json` (`locked: true, pinned: true`), live Stage-1 AST + Sentry `scan_skill.py` malicious skill quarantine, and CycloneDX `1.5` SBOM / `5/5` `@sha256` digest parity. |
| **Group G** | `G01–G16` | **`16 / 16` `PASS`** | **Cgroup Benchmarks, Pool & Systemd** | Working set `1,051.30–1,068.36 MiB / 1,536.00 MiB` (`vulnclaw` `21.36` $\rightarrow$ `38.43` $\rightarrow$ `21.36 MiB` reclaimed); health latency `<= 44.42 ms`; PostgreSQL `lowmem` pool **`6` connections (`<= 12`)**; `/opt/allinagent` **`222 MiB`**; `systemd` autostart + `03:00 Asia/Jakarta` timer + `0600` `.sql.gz` backup. |
| **Group H + Coex** | `H01–H10` + `COEX-01–06` | **`16 / 16` `PASS`** *(Suites F–H+Coex = `42/42`)* | **Negative Security & Multi-Tenant Coexistence** | `401`/`403` fail-closed auth & path-traversal blocks, non-root UIDs (`10001`/`10002`/`1000`/`70`), `vulnclaw` read-only rootfs + `CapEff=0` + air-gapped network (`Errno 101`), `34 / 34` pre-existing containers + host `nginx`/`php8.3-fpm`/`mysql`/`supervisor` `100%` untouched, and `audit-public-release.py` `0` findings. |

---

## 5. Phase 28 Independent Clean-Room Fresh Installation Test (`Track A` — `PASS`)

Phase 28 independently verified on a clean-room directory with **zero pre-existing state, caches, or private archives** that cloning `https://github.com/Vistapra/ALLINAGENT.git` (`v1.0.0`) achieves `100% PASS` operational readiness:

1. **Clean Clone & Hygiene Check (`PASS`):** Fresh `git clone` into an empty directory (`11.39 MiB` checkout across `931` tracked files; `0` `.env`, `0` SQLite/SQL dumps, `0` `node_modules`).
2. **Automated Setup (`./allinagent --production setup --yes` — `PASS`):** Generated owner-only (`0600`) `.env` and CSPRNG internal tokens, launched all `6 / 6` containers (`632.37 MiB` clean-install working set), provisioned the fresh Track A company + `11` corporate agents, and installed all `33` SHA-256-verified role skills (`default=str` YAML frontmatter date serialization + `UPSTREAM_THIRD_PARTY_NOTICES.md` attribution).
3. **End-to-End Smoke & Sample Project Verification (`PASS`):** Confirmed `./allinagent health` (`6 / 6` healthy), `./allinagent doctor` (`PASS`), Paperclip `hermes_local` `test-environment` (`status: "pass"`), `/dev git_status` + `/screenshot-kantor` (`800x460` PNG) + `uac:pick:0` (`200 OK`), and read-only analysis + defensive `VulnClaw` scan against `workspaces/sample-project`.
4. **Graceful Lifecycle & Persistence (`PASS`):** Verified `./allinagent restart` preserves PostgreSQL and `pc*` profile UUIDs on host bind mounts, and `./allinagent down` stops containers cleanly without orphan processes.
