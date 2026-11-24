# Changelog

All notable changes to **ALLINAGENT** (`https://github.com/Vistapra/ALLINAGENT`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-11-24

### Added
- **General Availability Release (`v1.0.0`):** Published verified multi-service container images `ghcr.io/vistapra/allinagent-{hermes,paperclip,office-bridge,office,vulnclaw}:v1.0.0` alongside CycloneDX 1.5 SBOM (`sbom.cdx.json`), `SHA256SUMS.txt`, `release-manifest.json`, and SLSA build provenance attestations.
- **Complete 25-Document Root Operations & Architecture Suite:** Added flagship `README.md`, `LICENSE-INVENTORY.md`, `PERFORMANCE.md`, `TEST-MATRIX.md`, `RELEASE-NOTES.md`, `CHANGELOG.md`, and `FINAL-REPORT.md` cross-linked with all 18 installation, deployment, security, Telegram, agent, and SRE runbooks.
- **Phase 27 & Phase 28 End-to-End Acceptance Harnesses:** Added `tests/run_ci_suite.py` (`78` offline CI assertions), `tests/e2e/run_live_acceptance.py` (`Groups A–H` live production probes with automatic token redaction), and `tests/fixtures/synthetic-order-api` (`SYN-F01`..`SYN-F04` differential benchmark).
- **Safe Zero-Data-Loss Upgrade Lifecycle (`./allinagent update`):** Added active-work drain/deferral checks, automated pre-update `pg_dump` backups (retaining latest 7 archives), post-update 6-service health verification, and automatic rollback on failure.

### Changed
- **Per-Package Skill Supply-Chain Isolation:** Elevated `anthropics/skills` `docx` and `pdf` packages to `FETCH_FROM_UPSTREAM_ONLY` in `skills/manifests/skills.lock.json` (`20` OSI-permissive redistributable skills vs. `13` `FETCH_FROM_UPSTREAM_ONLY` skills) with automatic `--strict-oss` and `--offline` Nous Research `MIT` fallbacks (`productivity/microsoft-office` and `productivity/pdf`).
- **Production Cgroup v2 Memory Tuning (`<= 1,536 MiB`):** Finalized `memswap_limit == mem_limit`, `MALLOC_ARENA_MAX=2`, V8 `--max-old-space-size`, and `postgresql-lowmem.conf` (`jit=off`, `shared_buffers=48MB`, bounded `12`-connection Paperclip pool) for zero-swap operation on 2-vCPU / 8 GB Ubuntu 24.04 LTS hosts.

### Security
- **Public Release Zero-Leak Verification:** Verified `0` findings under `scripts/audit-public-release.py` (`SEC-001..007`, `PORT-001..003`, `AUTH-001`, `CFG-001..003`, `GOV-001..003`, `HYG-001..002`), enforcing blank `.env.example` secrets, loopback-only host bindings (`127.0.0.1:8200–8202`), zero host DB/exec ports, non-root `10001:10001` execution, and zero Docker socket mounts.

---

## [1.0.0-rc.1] - 2026-11-24

### Added
- **30-Capability Unified Autonomous AI Company (`FEAT-01`..`FEAT-30`):**
  - **Shared Hermes Runtime (`FEAT-01`, `FEAT-08`):** Integrated `NousResearch/hermes-agent` `v0.23.3` (`eb49b8920a25ffa7bb2fadf548fe819221ca79d7`) with integrator error-classifier patch, `hermes_exec_daemon.py` (`HEAVY_WORKER_CONCURRENCY=1`), `< 8 KB` `/usr/local/bin/hermes` remote CLI shim, and 11 isolated `0700` `pc*` corporate agent profiles (`Wave-1` `ceo`, `backend`, `qa`, `security-reviewer` + `Wave-2` `cto`, `frontend`, `devops`, `security-lead`, `findings`, `remediation`, `compliance`).
  - **Paperclip Corporate Control Plane (`FEAT-02`, `FEAT-10`, `FEAT-15`..`FEAT-18`):** Integrated `paperclipai@2026.1117.0` (`c0f132898d2a2677312d8c72096187b27a3d9a38`) with 4 deterministic patches (`--query-file` `0600` cleanup, `--` skill-registry reconciliation, internal Docker gateway host allowlist, and `73` $\rightarrow$ `12` PostgreSQL pool cap) plus `prune-paperclip-bloat.mjs` (`-81.70%` `node_modules` reduction).
  - **VulnClaw On-Demand Defensive Sandbox (`FEAT-03`, `FEAT-24`..`FEAT-26`):** Integrated `VulnClaw` `v0.4.1` (`0b34878f84b089b21fcf85ecd445315f14df0672`) via `vulnclaw_worker.py` (`21.02 MiB` idle RSS, `read_only: true`, `cap_drop: ["ALL"]`, `:ro` workspace jail, 10 offensive/MCP modules hard-blocked, SARIF 2.1.0 + 10-state `findings.db` lifecycle).
  - **Hermes3D WebGL & 2D Pixel Virtual Office (`FEAT-04`, `FEAT-05`, `FEAT-19`):** Reconciled `iamlukethedev/Hermes3D` (`beb76292747b816ef317aa6f9a3992e0014f81d9`, `819.75 MiB` $\rightarrow$ `7.90 MiB`), custom `server/index.js` `/login` Access Gate, 14-seat 11-agent Meeting Room, corporate avatar tinting, live `"● Telegram Synced"` header badge, and 6-tab Enterprise Command Center Overlay.
  - **Unified Office Bridge & 59-Command Telegram CODEXE (`FEAT-06`, `FEAT-07`, `FEAT-14`):** Added Event Bus v1.0, Gateway Protocol v3, `telegram_onboarding.py`, `command_catalog.json`, and `unified-company-control` plugin (`59` slash commands, `13` `uac:sub:*` submenus, `52` callback routes, `17` Bahasa Indonesia + English NL rules, single-poller lock guard).
  - **33-Package Skill Supply Chain & Compliance Exporter (`FEAT-09`, `FEAT-11`..`FEAT-13`, `FEAT-27`, `FEAT-28`):** Added `skills.lock.json`, Sentry `skill-scanner` + recursive Python AST gate, 11-file quarantine ledger, `compliance-os` readiness mapper, and `report_exporter.py` (`.pdf` + `.docx`).
  - **Dual-Track Workspace & Encrypted State Migration (`FEAT-20`..`FEAT-23`, `FEAT-29`, `FEAT-30`):** Added Track A `workspaces/sample-project`, Track B `AES-256-GCM` (`PBKDF2-HMAC-SHA256`, `600,000` iterations) `export_private_state.py` / `import_private_state.py`, optional HMAC-SHA256 `windows_runner_agent.py` (`127.0.0.1:8670`), unified `./allinagent` / `allinagent.ps1` CLI, and SHA-pinned GitHub Actions CI/CD.

### Removed
- **Eliminated `10.35 GiB` of Legacy Workspace Bloat & Non-OSI Files:** Stripped `4.59 GiB` of host-coupled Windows binaries, `1.80 GiB` of unused nested CLI tarballs, `1.46 GiB` of SHA-256 duplicates, `vendor/multiavatar.js` (`MULTIAVATAR LICENSE v1.0`), `next/font/google` build-time network fetches, and all hardcoded host paths (`<LEGACY_WINDOWS_WORKSPACE>`).

[1.0.0]: https://github.com/Vistapra/ALLINAGENT/releases/tag/v1.0.0
[1.0.0-rc.1]: https://github.com/Vistapra/ALLINAGENT/releases/tag/v1.0.0-rc.1
