# PHASE 26 — Autostart, Reverse Proxy, Maintenance & Coordinated Safe Updates

- **Phase ID:** `PHASE-26` (including `PHASE-25` Nginx HTTPS & SSH Loopback Access)
- **Status:** `PASS`
- **Scope:** `deploy/linux/*`, `deploy/proxy/*`, `deploy/windows/*`, `scripts/allinagent_cli.py` (`update`)

---

## 1. Linux `systemd` Autostart & Scheduled Maintenance (`deploy/linux/`)

1. **`allinagent.service`:**
   - Starts `ALLINAGENT` automatically after `docker.service` and `network-online.target` (`ExecStart=/opt/allinagent/allinagent --production up`, `ExecStop=/opt/allinagent/allinagent --production stop`, `RemainAfterExit=yes`).
2. **`allinagent-maintenance.service` & `allinagent-maintenance.timer`:**
   - Fires daily at `03:00:00` in the `.env`-configured `TIMEZONE` (`OnCalendar=*-*-* 03:00:00 <TIMEZONE>`) with `Persistent=true` (automatic catch-up after reboot) and `RandomizedDelaySec=120`.
   - Runs under strict OS resource controls (`Nice=10`, `IOSchedulingClass=best-effort`, `CPUQuota=75%`, `MemoryMax=512M`) so scheduled maintenance never impacts co-hosted services on 2-vCPU servers.
3. **`install-systemd.sh`:**
   - Idempotently substitutes the installation root and `.env` `TIMEZONE`, reloads systemd, and enables both `allinagent.service` and `allinagent-maintenance.timer`.

---

## 2. Coordinated Safe Update & Automatic Rollback Engine

`./allinagent update` implements a deterministic 6-step update state machine persisted in `${ALLINAGENT_DATA_DIR}/maintenance/state.json`:

1. **Lock Guard:** Checks `maintenance/maintenance.lock`; defers (`DEFERRED`, exit `0`) if an active maintenance window (`< 5,400s`) is already running.
2. **Active-Work Deferral:** Queries Office Bridge (`:8202/health`) and Paperclip live heartbeat runs (`:8201/api/companies/*/heartbeat-runs`); defers cleanly if any agent run is `queued` or `running`.
3. **Release-Aware Manifest Check:** Fetches `release-manifest.json` from GitHub Releases and skips any candidate version recorded in `quarantined_candidates`.
4. **Rollback Snapshot & Database Backup:** Tags every currently running image as `allinagent-rollback/<service>:previous`, writes `rollback-snapshot.json`, and streams a gzipped PostgreSQL backup (`pg_dump | gzip` -> `data/backups/paperclip-pre-update-<timestamp>.sql.gz`, retaining last 7).
5. **Recreate & Health Gate:** Pulls target images, updates `.env` `ALLINAGENT_VERSION`, runs `docker compose up -d --remove-orphans`, and polls all 6 service healthchecks (`wait_for_healthy`).
6. **Automatic Rollback on Failure:** If `up` or post-update health verification fails, `rollback_to_previous_images()` restores `allinagent-rollback/<service>:previous`, reverts `ALLINAGENT_VERSION`, restarts the known-good containers, verifies recovery, and quarantines the broken candidate tag.

---

## 3. Reverse Proxy (`Nginx` TLS 1.2/1.3 + QUIC) & SSH Tunnel (`deploy/proxy/`)

- **`nginx-allinagent.conf.template` & `install-nginx.sh`:**
  - Enforces HTTPS redirect, TLS 1.2/1.3, HTTP/2, and HTTP/3 QUIC (`listen 443 quic;` and `listen [::]:443 quic;` **strictly without `reuseport`** so `nginx -t` never collides with an existing `default_server` QUIC socket).
  - Configures WebSocket upgrades (`Upgrade` / `Connection`) for `/api/gateway/ws`, `/api/company/events/ws`, and `/ws`, rate limiting (`25r/s` web, `10r/s` API), HSTS/security headers, `client_max_body_size` caps (`16m` web / `1m` API), automatic `nginx -t` rollback on error, and **zero** public exposure of PostgreSQL (`5432`), Hermes (`8650`), VulnClaw (`8660`), or raw Paperclip admin ports.
- **`ssh-tunnel-access.sh` & `ssh-tunnel-access.ps1`:**
  - Provide zero-domain encrypted SSH loopback port-forwarding (`127.0.0.1:8200–8202`) with `ExitOnForwardFailure=yes` and keepalives.
- **`deploy/windows/*.ps1`:**
  - Dynamic `$PSScriptRoot`-resolved Windows Task Scheduler, watchdog, credential-rotation, and connected-device scripts (`0` unresolved template placeholders or hardcoded path bugs, AST-verified via PowerShell parser).
