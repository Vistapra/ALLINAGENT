# ALLINAGENT — Executive & Principal Architecture Transformation Report

- **Product:** `ALLINAGENT` (`https://github.com/Vistapra/ALLINAGENT`)
- **Release Version:** `v1.0.0` (MIT License)
- **Transformation Span:** `PHASE-00` through `PHASE-29`
- **Target Production Envelope:** `2 vCPU / 8 GB RAM` Ubuntu 24.04 LTS (`<= 1,536 MiB` total cgroup v2 ceiling; `127.0.0.1:8200–8202` loopback-only)

---

## 1. Executive Summary

**ALLINAGENT** completes a 30-phase principal systems engineering transformation converting a multi-root workstation deployment (`<LEGACY_WINDOWS_WORKSPACE>`, **`11,126,312,521 B` / `10.36 GiB`** across `461,174` files and `25` host processes) into a clean, reproducible, cross-platform open-source distribution (**`11.39 MiB` Git repository across `931` tracked files**, **`99.89%` footprint reduction**; `/opt/allinagent` runtime disk **`222 MiB`**) while preserving **100% of all 30 enterprise capabilities (`FEAT-01`..`FEAT-30`)**.

Key empirical outcomes:
1. **Zero Feature Regression (`30 / 30` Capabilities & `113 / 113` Live Acceptance Checks Verified):** Unites **Hermes Agent (`v0.23.3`)**, **Paperclip (`2026.1117.0`)**, **VulnClaw (`v0.4.1` defensive)**, **Hermes3D WebGL + 2D Pixel Office**, **Unified Office Bridge**, **59-Command Telegram CODEXE Control Center**, **11 Corporate AI Agents**, **33 SHA-Pinned Agent Skills**, and **PDF/DOCX Compliance Reporting**.
2. **Constrained-VPS Memory Mastery (`<= 1,536.00 MiB` Hard Ceiling):** Enforces `memswap_limit == mem_limit` across all 6 containers (`632.37 MiB` clean Track A install; `1,003.84–1,052.44 MiB` steady production; `1,068.36 MiB` active VulnClaw scan peak; `1,110.52 MiB` post-16-step Group E workflow), leaving `~3.0 GiB` of untouched host RAM headroom on dense multi-tenant 8 GiB servers.
3. **Zero-Leak Public Supply Chain:** Verified `0` secrets, `0` hardcoded host paths, `0` copyleft violations, and `0` bundled Commons-Clause/unlicensed skills under `scripts/audit-public-release.py` and `scripts/generate-sbom.py` (`CycloneDX 1.5`).

---

## 2. Phase `00` – `29` Execution Ledger

| Phase | Objective | Key Deliverable & Empirical Outcome | Status |
| :---: | :--- | :--- | :---: |
| `PHASE-00` | Baseline & 30-Feature Inventory | Mapped all `30` capabilities (`FEAT-01`..`FEAT-30`), `11` agents, `33` skills, and `59` Telegram commands | `PASS` |
| `PHASE-01` | Directory Size & Storage Audit | Audited `10.36 GiB` (`461,174` files): `4.59 GiB` OS binaries, `1.80 GiB` CLI bloat, `1.46 GiB` SHA-256 duplicates | `PASS` |
| `PHASE-02` | VPS Capacity & Coexistence Audit | Verified 2-vCPU / 8 GB Ubuntu 24.04 LTS envelope, subnet collisions, Nginx QUIC rule & prune immunity | `PASS` |
| `PHASE-03` | Principal Architecture Design | Ratified `ADR-001` through `ADR-009` and the `<= 1,536 MiB` 6-container topology | `PASS` |
| `PHASE-04` | Upstream & Custom Patch Audit | Extracted minimal deterministic patches for `hermes-agent` (`1` patch) and `paperclip` (`4` patches) | `PASS` |
| `PHASE-05` | Build Clean `ALLINAGENT` Repo | Synthesized `< 15 MiB` repository structure reconciling portability & CODEXE/skills waves | `PASS` |
| `PHASE-06` | Supply Chain & License Review | Authored `LICENSE-INVENTORY.json`, `THIRD-PARTY-NOTICES.md`, `generate-sbom.py` & `audit-public-release.py` | `PASS` |
| `PHASE-07` | Windows-to-Linux Migration | Replaced OS-coupled paths/ACLs with `control_center/paths.py`, `contracts/paths.js` & POSIX `0700`/`0600` | `PASS` |
| `PHASE-08` | Shared Hermes Runtime | Built `hermes_exec_daemon.py` (`HEAVY_WORKER_CONCURRENCY=1`), `/usr/local/bin/hermes` shim & `11` `pc*` profiles | `PASS` |
| `PHASE-09` | Paperclip Production Optimization | Pruned `node_modules` `2,537.49 MiB` $\rightarrow$ `464.36 MiB` (`-81.70%`); capped DB pool `73` $\rightarrow$ `12` | `PASS` |
| `PHASE-10` | VulnClaw On-Demand Sandbox | Built `vulnclaw_worker.py` (`21.02 MiB` idle RSS, `:ro` workspace, `0` offensive/MCP modules, SARIF 2.1.0) | `PASS` |
| `PHASE-11` | Hermes3D & 2D Office Optimization | Reduced `819.75 MiB` $\rightarrow$ `7.90 MiB` (`-99.04%`), removed `vendor/multiavatar.js`, passed `70` `vitest` tests | `PASS` |
| `PHASE-12` | Office Bridge Portability | Containerized Event Bus v1.0, Gateway v3, Docker DNS discovery & sanitized report streaming | `PASS` |
| `PHASE-13` | GitHub Skill Registry & Gate | Enforced 40-char commit SHAs, SHA-256 verification, Sentry `skill-scanner` + AST gate & 11-file quarantine | `PASS` |
| `PHASE-14` | 11 Agent Skill Sets Portability | Materialized POSIX symlinks/junctions, Stage-2 YAML normalizations, `.usage.json` locks & MIT fallbacks | `PASS` |
| `PHASE-15` | Telegram CODEXE Portability | Built `telegram_onboarding.py`, `command_catalog.json` (`59` cmds, `13` submenus) & single-poller guard | `PASS` |
| `PHASE-16` | Workspace & Connected Runner |Separated `server_workspace` (`/workspaces`) from optional HMAC-SHA256 `windows_runner_agent.py` (`127.0.0.1:8670`) | `PASS` |
| `PHASE-17` | Database & State Migration | Delivered Track A `workspaces/sample-project` + Track B `AES-256-GCM` `export/import_private_state.py` | `PASS` |
| `PHASE-18` | Production Dockerization | Authored multi-stage non-root (`10001:10001`) Dockerfiles, `compose.yaml` & two-tier networks | `PASS` |
| `PHASE-19` | `2 vCPU / 8 GB` Resource Tuning | Locked `compose.production.yaml` (`<= 1,536 MiB`, `memswap_limit == mem_limit`) & `postgresql-lowmem.conf` | `PASS` |
| `PHASE-20` | Unified CLI & Setup Wizard | Built `./allinagent` / `allinagent.ps1` (`setup`, `up`, `down`, `status`, `health`, `doctor`, `update`) | `PASS` |
| `PHASE-21` | GitHub Actions CI Pipeline | Authored SHA-pinned `.github/workflows/ci.yml` (hygiene, Python/skills, Node/TS, SBOM, Docker smoke) | `PASS` |
| `PHASE-22` | GHCR Release & Attestations | Authored `.github/workflows/ghcr-release.yml` with SLSA provenance, `sbom.cdx.json` & `SHA256SUMS.txt` | `PASS` |
| `PHASE-23` | Public Repo Security Preflight | Verified GitHub target `Vistapra/ALLINAGENT` and fail-closed `audit-public-release.py` gates | `PASS` |
| `PHASE-24` | Ubuntu Production Deployment | Provisioned `/opt/allinagent` bind-mount layout, UFW/`DOCKER-USER` compatibility & production runbooks | `PASS` |
| `PHASE-25` | Domain, TLS 1.3 & HTTP/3 QUIC | Configured Host Nginx TLS 1.3 + WS upgrade + HTTP/3 QUIC (without `reuseport` collision) & SSH tunnel scripts | `PASS` |
| `PHASE-26` | Autostart & Coordinated Updates | Configured `restart: unless-stopped`, `systemd` maintenance timers, `pg_dump` rotation & auto-rollback | `PASS` |
| `PHASE-27` | Live Production Acceptance | Verified **`113 / 113` (`100% PASS`)** live checks (`A 10/10`, `B 11/11` `241,240` tokens, `C 17/17`, `D 17/17`, `E 16/16`, `F 10/10`, `G 16/16`, `H 10/10` + `6/6` coexistence) | `PASS` |
| `PHASE-28` | Clean-Room Fresh Install Test | Verified independent Track A `git clone` (`11.39 MiB`) $\rightarrow$ `./allinagent --production setup` $\rightarrow$ `6/6` healthy stack (`632.37 MiB`) | `PASS` |
| `PHASE-29` | Final Documentation & GA Release | Completed GA `v1.0.0` surgical runtime polish, 25-doc release suite, master `PASS` ledgers & final sign-off | `PASS` |

---

## 3. Principal Architecture Decisions (`ADR-001` .. `ADR-009`)

| ADR | Decision Title | Architectural Summary & Measured Impact |
| :---: | :--- | :--- |
| **`ADR-001`** | **Control Plane & Tuned PostgreSQL 16** | Runs locked `paperclipai@2026.1117.0` (`node_modules` pruned `-81.70%`) paired with air-gapped `postgres:16-alpine` (`jit=off`, `shared_buffers=48MB`, Paperclip pool capped `73` $\rightarrow$ `12` connections). |
| **`ADR-002`** | **Single Shared Hermes Runtime (`hermes-exec`)** | Consolidates `NousResearch/hermes-agent` `v0.23.3` and **one** Python 3.14 `uv` venv inside `allinagent-hermes` (`HEAVY_WORKER_CONCURRENCY=1` priority broker + single Telegram poller + 11 `0700` `pc*` profiles). |
| **`ADR-003`** | **`< 8 KB` Remote CLI Shim (`/usr/local/bin/hermes`)** | Pure Node stdlib shim inside `paperclip` and `office-bridge` streaming NDJSON over `http://hermes:8650`, eliminating `> 1.5 GiB` of duplicated Python container layers. |
| **`ADR-004`** | **Ephemeral `:ro` VulnClaw Sandbox** | Pure-stdlib parent daemon (`21.02 MiB` idle RSS) spawning isolated `-B` child static scans on `:ro` workspaces (`read_only: true`, `cap_drop: ALL`, `0` secrets, `0` Docker socket). |
| **`ADR-005`** | **100% Browser-Rendered 3D & 2D Office** | Next.js `standalone` + custom `server/index.js` `/login` Access Gate serving `Three.js` WebGL and `Phaser` 2D Canvas assets rendered entirely on the viewer's GPU (`0%` server GPU). |
| **`ADR-006`** | **Unified Office Bridge & CODEXE Hub** | Centralizes Event Bus v1.0 (`500`-event ring), Gateway Protocol v3, 59-command Telegram CODEXE controllers, read-only Skill Telemetry, and redacted PDF/DOCX report serving. |
| **`ADR-007`** | **Four Canonical Deployment Modes** | Supports `Standard Production` (`<= 1,536 MiB`), `Low-Resource Production` (`<= 1,024 MiB`), `Development` (live reload), and optional `Connected Device` (`127.0.0.1:8670` HMAC-SHA256 runner). |
| **`ADR-008`** | **Two-Tier Networks, Loopback & Cgroup Caps** | Isolates `allinagent_data` (`internal: true`) from `allinagent_edge`, binds host ports strictly to `127.0.0.1:8200–8202`, enforces `memswap_limit == mem_limit`, and stores state in prune-immune host bind mounts. |
| **`ADR-009`** | **Immutable Locks & License-Safe Skill Registry** | Pins all core upstreams and `10` skill repos to 40-char commit SHAs, isolates `13` `FETCH_FROM_UPSTREAM_ONLY` packages outside Git/GHCR, and provides `--strict-oss` / `--offline` MIT fallbacks. |

---

## 4. Full 30-Capability Parity Table (`FEAT-01` .. `FEAT-30`)

| ID | Capability | Legacy Baseline State | `ALLINAGENT v1.0.0` Production Implementation | Parity |
| :--- | :--- | :--- | :--- | :---: |
| `FEAT-01` | Hermes Agent `v0.23.3` | Duplicated host Python/NPM installs | Shared `allinagent-hermes` + `0001-error-classifier-integrator.patch` | `100%` |
| `FEAT-02` | Paperclip `2026.1117.0` | `2.48 GiB` `node_modules` + embedded PG | `464.36 MiB` pruned runtime + 4 patches + `postgres:16-alpine` | `100%` |
| `FEAT-03` | VulnClaw `v0.4.1` | Host venv CLI | `allinagent-vulnclaw` (`21.02 MiB` idle RSS, `:ro` sandbox, SARIF 2.1.0) | `100%` |
| `FEAT-04` | Hermes3D WebGL Office | `819.75 MiB` tree | `7.90 MiB` staged `apps/hermes3d` + `server/index.js` Access Gate | `100%` |
| `FEAT-05` | 2D Pixel Office | Browser `Phaser` Canvas | Synchronized 2D Pixel Office + instant 3D/2D mode toggle | `100%` |
| `FEAT-06` | Unified Office Bridge | Loopback-only host script | `allinagent-office-bridge` (Event Bus v1.0 + Gateway v3 + Docker DNS) | `100%` |
| `FEAT-07` | Telegram CODEXE (`59` Cmds) | Host-coupled plugin | Portable `unified-company-control` (`59` cmds, `13` submenus, ID/EN NL) | `100%` |
| `FEAT-08` | 11 Corporate AI Agents | Host ACL directories | `11` `0700` non-root `pc*` profiles (`4` Wave-1 active + `7` Wave-2 standby) | `100%` |
| `FEAT-09` | 33 Agent Skill Packages | Host junctions | Pinned `skills.lock.json` + POSIX symlinks + progressive `skill_view` | `100%` |
| `FEAT-10` | Paperclip Skills Store | Patched local `skills.js` | Deterministic `0002-hermes-adapter-skills-reconcile.patch` | `100%` |
| `FEAT-11` | Skill Security & License Gate | Local manifest checks | SHA-256 verification + 11-file quarantine + `13` `FETCH_FROM_UPSTREAM_ONLY` | `100%` |
| `FEAT-12` | Sentry `skill-scanner` | Pinned scanner script | Stage-1 `skill-scanner` (`a582c51ee2`) + Stage-1B recursive Python AST gate | `100%` |
| `FEAT-13` | GitHub Skills Registry | Local JSON manifests | `skills/manifests/` + read-only `/daftar_skill`, `/skill_info`, `/skill_status` | `100%` |
| `FEAT-14` | Usage & Cost Analytics | SQLite/API aggregator | Today/Yesterday/7d/30d token, cost & `UNPRICED USAGE` analytics | `100%` |
| `FEAT-15` | Budget Governance | Paperclip + JSON ledger | `unlimited` or `capped` corporate/agent budgets (`/budget`, `/set_budget`) | `100%` |
| `FEAT-16` | Task & Kanban Management | `workflow-ledger.db` + Kanban | 13-stage workflow ledger + read-after-write Kanban sync & receipts | `100%` |
| `FEAT-17` | Multi-Project Management | Paperclip REST portfolio | Portfolio CRUD, active project switching & workspace binding (`/projects`) | `100%` |
| `FEAT-18` | Hierarchical Agent Delegation | Unbounded child spawns | CEO $\rightarrow$ Lead $\rightarrow$ Specialist serialized via `HEAVY_WORKER_CONCURRENCY=1` | `100%` |
| `FEAT-19` | 3D & 2D Meeting Room | Standup store + WS | 14-seat A* conference room, 11-agent turn queue, minutes & action items | `100%` |
| `FEAT-20` | Sandboxed Folder Explorer | Drive-letter browser | `ALLOWED_WORKSPACE_ROOTS` explorer + secret-file exclusion (`/jelajah`) | `100%` |
| `FEAT-21` | Source Code Analysis | Agent inspection scripts | Polyglot stack/dependency/risk analyzer producing redacted evidence (`/analisis`) | `100%` |
| `FEAT-22` | Software Development | Host Git binaries | Isolated feature-branch coding, `git diff` & peer review (`/dev`, `/cek_diff`) | `100%` |
| `FEAT-23` | Automated QA & E2E Testing | Host browser binary | `pytest` / Node / ephemeral headless Chromium Playwright (`pw*` skills) | `100%` |
| `FEAT-24` | Defensive Security Assessment | Static policy checks | Container-jailed `:ro` `VulnClaw` + read-only `@security_lead` / `@security` | `100%` |
| `FEAT-25` | 10-State Findings Management | `findings.db` SQLite | Directive-neutralized 10-state `findings.db` linked to Paperclip issues | `100%` |
| `FEAT-26` | Remediation Verification | Separation-of-duties review | `focused-fix` scoping + independent `@remediation` re-scan (`RESOLVED`) | `100%` |
| `FEAT-27` | Compliance Reporting | `compliance-os` scripts | ISO 27001, SOC 2 & NIST CSF readiness & control-overlap synthesis | `100%` |
| `FEAT-28` | PDF & DOCX Report Export | Python document scripts | Dual-engine `%PDF-` & OpenXML `.docx` (`report_exporter.py`) + safe streaming | `100%` |
| `FEAT-29` | 15-Component Health Monitoring | Task Scheduler probes | Docker `HEALTHCHECK`s + `/kesehatan` + `./allinagent health` & `doctor` | `100%` |
| `FEAT-30` | Maintenance & Self-Healing | Host `.ps1` scripts | 11-state coordinator, `systemd` timer, active-run deferral & `./allinagent update` | `100%` |

---

## 5. 11-Agent & 33-Skill Supply-Chain Governance

- **Strict Worker Profile Isolation:** All 11 `pc*` profiles (`pcceoagent`..`pccompliancereporter`) enforce `0700` permissions, write hyphenated `.no-bundled-skills` markers (`BUG-01` fix preventing owner-skill bleed), strip `TELEGRAM_BOT_TOKEN` / `OWNER_TELEGRAM_ID` / `DATABASE_URL` from worker environments, and disable `terminal` toolsets on all four security review/triage personas (`@security_lead`, `@security`, `@findings`, `@remediation`).
- **33-Package Lockfile & Quarantine Gate:** `skills/manifests/skills.lock.json` pins `10` repositories (`33` packages: `20` pure OSI-permissive + `13` `FETCH_FROM_UPSTREAM_ONLY`). Every file passes SHA-256 verification, **Sentry `skill-scanner`**, and recursive Python AST checks; `11` offensive/bootstrap files are deterministically quarantined; `4` packages are isolated as `REFERENCE_ONLY`; `1` (`cve-triage`) is isolated as opt-in `EXPERIMENTAL`; and `.usage.json` locks (`locked: true, pinned: true`) prevent runtime mutation.

---

## 6. Track A (Public Clean Seed) vs. Track B (AES-256-GCM Private Migration)

| Dimension | Track A — Clean Public Seed (Default) | Track B — Optional Private State Migration |
| :--- | :--- | :--- |
| **Target Users** | Public `git clone` adopters, CI pipelines, clean-room servers | Operators migrating an existing private deployment to Ubuntu LTS |
| **Included Artifacts** | MIT-licensed `workspaces/sample-project` (`order-billing-demo`) | `scripts/migration/export_private_state.py` & `import_private_state.py` |
| **Private Data in Repo** | **`0` bytes** (`0` real DBs, `0` memories, `0` private code) | Staged strictly outside Git in `/tmp` (`0600` `.aiaenc` bundle) |
| **Cryptography & Safety** | Auto-generates fresh CSPRNG tokens & Track A UUIDs on `setup` | **AES-256-GCM** (`PBKDF2-HMAC-SHA256`, `600,000` iterations, AAD header) |
| **Continuity Guarantees** | Immediate out-of-the-box demo & `VulnClaw` benchmark readiness | Online `sqlite3.backup()` across `14` WAL DBs + `pg_dump` + `master.key`, preserving Company UUID & all **11 Agent UUIDs** with in-place legacy path rewriting, `maintenance.lock`, and single-poller Telegram cutover lock |

---

## 7. Security Posture & Final Verification Sign-Off

- **Defense-in-Depth Defaults:** Blank `.env.example` credentials; fail-closed `<OWNER_TELEGRAM_ID>` DM lock; loopback-only host bindings (`127.0.0.1:8200–8202`); air-gapped `allinagent_data` database network (`0` host ports); non-root `10001:10001` containers with `no-new-privileges:true`; `:ro` workspace + `cap_drop: ["ALL"]` on `vulnclaw`; and **zero `/var/run/docker.sock` exposure**.
- **Comprehensive Automated Sign-Off:**
  - `tests/run_ci_suite.py`: **`78 / 78` checks PASSED** (`0` failures).
  - `apps/office-bridge` (`node --test`): **`12 / 12` suites PASSED** (including `/screenshot-kantor` `800x460` `\x89PNG` card & `uac:pick:0` `200 OK`).
  - `apps/hermes3d` (`tsc --noEmit` + `vitest`): **`0` TS errors; `12 / 12` suites (`70 / 70` tests) PASSED**.
  - `integrations/{telegram,connected-device}` + `apps/control-center`: **`20` `unittest` cases + `49` self-checks PASSED**.
  - `tests/fixtures/synthetic-order-api`: **`13 / 13` differential security checks (`SYN-F01`..`SYN-F04`) PASSED**.
  - `Phase 27` Live Production Acceptance: **`113 / 113` checks (`100% PASS` across `Groups A–H` + `6/6` multi-tenant coexistence; `241,240` real worker tokens, `0` cross-profile pollution, `0` HTTP `409 Conflict`, VulnClaw `9` $\rightarrow$ `0` findings, live `.pdf`/`.docx` Telegram delivery)**.
  - `Phase 28` (`Track A` Clean-Room Fresh Installation): **`PASS` (`632.37 MiB` working set, `6 / 6` healthy)**.
  - `scripts/audit-public-release.py` & `scripts/generate-sbom.py --validate`: **`0` security/privacy/hygiene findings; valid CycloneDX `1.5` SBOM**.
