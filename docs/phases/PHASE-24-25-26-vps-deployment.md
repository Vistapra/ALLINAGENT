# Phases 24, 25 & 26 — Ubuntu 24.04 LTS Production Deployment, Telegram Cutover & Systemd Evidence

- **Release Tag Deployed**: `v1.0.0-rc.8` (`ghcr.io/vistapra/allinagent-{hermes,paperclip,office-bridge,office,vulnclaw}:1.0.0-rc.8` + `postgres:16-alpine`)
- **Target Host Profile**: `<TARGET_VPS_HOSTNAME>` (`<TARGET_VPS_IPV4>`) — Ubuntu 24.04.4 LTS (`6.8.0-149-generic`), `2 vCPU`, `7,940 MiB` physical RAM, `96 GiB` SSD
- **Installation Root**: `/opt/allinagent` (persistent host bind-mounts under `/opt/allinagent/data`)
- **Deployment & Cutover Timestamp**: `2026-11-24` (`TIMEZONE=Asia/Jakarta`)
- **Sanitization Guarantee**: All host-identifying strings, domains, chat IDs, and credentials are represented strictly via placeholders (`<TARGET_VPS_IPV4>`, `<TARGET_VPS_HOSTNAME>`, `<OWNER_LLM_BASE_URL>`, `<OWNER_LLM_MODEL>`). Zero secrets or private identifiers are stored in version control.

---

## 1. Pre-Deployment Multi-Tenant Baseline vs Post-Deployment Coexistence

| Metric | Pre-Deployment Baseline | Post-Deployment Verified | Verdict |
|---|---|---|---|
| Pre-Existing Multi-Tenant Containers | `34` running | `34` running (`40` total incl. `6` `allinagent-*`) | **100% Untouched** |
| Host `nginx` Service | `active` (`nginx -t` ok) | `active` (`nginx -t` ok; `0` vhosts altered) | **100% Untouched** |
| Host `php8.3-fpm` Service | `active` | `active` | **100% Untouched** |
| Host `mysql` Service | `active` | `active` | **100% Untouched** |
| Host `supervisor` Service | `active` | `active` | **100% Untouched** |
| Host Available RAM (`free -m`) | `3,396 MiB` available (`7,940 MiB` total) | `2,991 MiB` available (`7,940 MiB` total) | **PASS (~2.92 GiB free headroom)** |
| Root Filesystem Free Space (`df -h /`) | `48 GiB` free (`51%` used) | `46 GiB` free (`54%` used) | **PASS (> 24 GiB safety floor)** |
| Loopback Ports `8200`, `8201`, `8202` | Free | Bound strictly to `127.0.0.1:8200-8202` | **PASS (`0` wildcard listeners)** |

---

## 2. Phase 24 — Production Stack, 11 Corporate Agents & 33 Security-Gated Skills

### 2.1 Container Health & Cgroup Resource Footprint (`<= 1,536 MiB` Hard Ceiling)

All 6 containers were pulled directly from pre-built SLSA-attested GHCR release images (`0` unconstrained host image builds, `0` `docker system prune` invocations) and verified `Up (healthy)` via `./allinagent --production health --json`:

| Container | Image Coordinate | Network Exposure | Live Memory Usage | Physical `mem_limit` | Status |
|---|---|---|---|---|---|
| `allinagent-postgres` | `postgres:16-alpine` | Internal-only (`allinagent_data`) | `80.51 MiB` (`50.32%`) | `160 MiB` | `Up (healthy)` |
| `allinagent-vulnclaw` | `ghcr.io/vistapra/allinagent-vulnclaw:1.0.0-rc.8` | Internal-only (`:8660`, air-gapped, `read_only`, `cap_drop: ALL`) | `19.17 MiB` (`29.95%`) | `64 MiB` | `Up (healthy)` |
| `allinagent-hermes` | `ghcr.io/vistapra/allinagent-hermes:1.0.0-rc.8` | Internal-only (`:8650`, `HEAVY_WORKER_CONCURRENCY=1`) | `301.50 MiB` (`67.30%`) | `448 MiB` | `Up (healthy)` |
| `allinagent-paperclip` | `ghcr.io/vistapra/allinagent-paperclip:1.0.0-rc.8` | Loopback-only (`127.0.0.1:8201 -> :3100`) | `511.80 MiB` (`84.17%`) | `608 MiB` | `Up (healthy)` |
| `allinagent-office-bridge` | `ghcr.io/vistapra/allinagent-office-bridge:1.0.0-rc.8` | Loopback-only (`127.0.0.1:8202 -> :3210`) | `46.63 MiB` (`41.63%`) | `112 MiB` | `Up (healthy)` |
| `allinagent-office` | `ghcr.io/vistapra/allinagent-office:1.0.0-rc.8` | Loopback-only (`127.0.0.1:8200 -> :3200`) | `44.23 MiB` (`30.71%`) | `144 MiB` | `Up (healthy)` |
| **Total Stack** | **6 Production Containers** | **Zero Public Ports** | **`1,003.84 MiB` (`65.35%`)** | **`1,536 MiB` (`100%`)** | **ALL HEALTHY** |

### 2.2 Secret & File Permission Hygiene (`0` Plaintext Exposure)

- `/opt/allinagent/.env` generated via CSPRNG and synced over opaque SSH stdin (`chmod 0600`, `root:root`).
- `/opt/allinagent/data/secrets/worker-llm.env` (`chmod 0600`, `10001:10001`), `/opt/allinagent/data/secrets/paperclip-auth.env` (`chmod 0600`, `1000:1000`), `/opt/allinagent/data/secrets/office-bridge-auth.json` (`chmod 0640`, `1000:10001`), and `/opt/allinagent/data/office-secrets/office-bridge-auth.json` (`chmod 0600`, `1000:1000`) provisioned without mounting `paperclip-auth.env` into `allinagent-office` and with zero secrets mounted into `allinagent-vulnclaw`.
- Workspace fixtures `sample-project` and `synthetic-order-api` initialized as clean local Git repositories under `/opt/allinagent/data/workspaces/` (`/var/lib/allinagent/workspaces` inside containers).
- Initial compressed PostgreSQL backup saved to `/opt/allinagent/data/backups/` (`chmod 0600`).

### 2.3 11 Corporate AI Agents & `UNLIMITED` Budget Governance

Provisioned via `control_center.org_provisioner --budget-mode unlimited` and verified across Paperclip (`GET /api/companies`, `GET /api/companies/:id/agents`, `GET /api/companies/:id/budgets/overview`) and Office Bridge (`GET /api/office-bridge/snapshot`, `GET /api/office-bridge/agents`):

- **Company**: `Unified AI Engineering & Operations` (`budget_mode: "unlimited"`, `company_monthly_cents: 0`, `12` budget policies with `isActive: false`, `hardStopEnabled: false`, `unpricedUsagePolicy: "allow"`).
- **Wave 1 Active Agents (`status: "idle"`, `lifecycleState: "ready"`, `budgetMonthlyCents: 0`)**:
  1. `CEO Agent` (`pcceoagent`, `file,terminal,skills`)
  2. `Backend Developer` (`pcbackenddeveloper`, `file,terminal,skills`)
  3. `QA Engineer` (`pcqaengineer`, `file,terminal,skills`)
  4. `Security Reviewer` (`pcsecurityreviewer`, `file,skills` — read-only defensive posture)
- **Wave 2 On-Demand Standby Agents (`status: "paused"`, `budgetMonthlyCents: 0`)**:
  5. `CTO Agent` (`pcctoagent`, `file,terminal,skills`)
  6. `Frontend Developer` (`pcfrontenddeveloper`, `file,terminal,skills`)
  7. `DevOps Engineer` (`pcdevopsengineer`, `file,terminal,skills`)
  8. `Security Lead` (`pcsecuritylead`, `file,skills`)
  9. `Findings Analyst` (`pcfindingsanalyst`, `file,skills`)
  10. `Remediation Reviewer` (`pcremediationreviewer`, `file,skills`)
  11. `Report & Compliance Agent` (`pccompliancereporter`, `file,terminal,skills`)
- Every isolated profile under `/var/lib/allinagent/hermes/profiles/pc*` enforces `0700` permissions, `.no-bundled-skills` (hyphenated `BUG-01` fix), stripped messaging tokens, and live OpenAI-compatible inference against `<OWNER_LLM_BASE_URL>` (`<OWNER_LLM_MODEL>`, verified `HTTP 200 OK`).

### 2.4 33 SHA-Pinned Agent Skills (Two-Stage Supply-Chain Security Gate)

Verified via `control_center.agent_skills_manager` and `GET http://127.0.0.1:8202/api/office-bridge/skills`:

- `manifest_hydrated: true`
- `locked_skills_count: 33` (`1` bootstrap `getsentry/skills` `skill-scanner` + `32` role packages; `0` skipped, `0` quarantined)
- `osi_permissive_count: 20`
- `fetch_from_upstream_only_count: 13` (`commons_clause_count: 10` + `docx`, `pdf`, `react-best-practices`)
- `agents_len: 11` (all 11 agent profiles linked via POSIX symlinks with `.usage.json` `locked: true, pinned: true`; `REFERENCE_ONLY` and `EXPERIMENTAL` skills isolated outside active runtime `skills/` directories)

---

## 3. Zero-Conflict Single-Poller Telegram Cutover (`MIG-02`)

1. **Pre-Boot Lock**: `/opt/allinagent/data/hermes/.telegram_cutover_lock` (`0600`, `10001:10001`) was created prior to first container startup. `allinagent-hermes` verified the lock on boot (`MIG-02 cutover lock active; skipping Telegram gateway poller (exec daemon active on :8650)`).
2. **Source Poller Drain**: Disabled and stopped the legacy workstation `Hermes_Gateway` scheduled task and terminated the single local gateway poller process (`REMAINING_GATEWAY_PROCS=0`) while leaving non-Telegram local services untouched, followed by a `>6s` long-poll lease expiration wait.
3. **Target Poller Activation**: Removed `/opt/allinagent/data/hermes/.telegram_cutover_lock` and restarted `allinagent-hermes`.
4. **Post-Cutover Verification**:
   - `unified-company-control` plugin loaded (`CallbackQueryHandler (^uac:)` + all `59` slash commands registered; Telegram command scopes updated).
   - `Telegram polling confirmed healthy: getUpdates progressing (generation 1)` / `Connected to Telegram (polling mode)`.
   - **HTTP `409 Conflict` count**: **`0`** (`DOCKER_LOGS_409_CONFLICT_COUNT=0`, `POST_CUTOVER_HTTP_409_CONFLICTS=0`).

---

## 4. Phase 25 — Loopback-Only Exposure, SSH Tunnel & Reverse-Proxy Readiness

- **Socket Verification (`ss -tlnp`)**:
  ```text
  LISTEN 0 65535 127.0.0.1:8200 0.0.0.0:*
  LISTEN 0 65535 127.0.0.1:8201 0.0.0.0:*
  LISTEN 0 65535 127.0.0.1:8202 0.0.0.0:*
  WILDCARD_820X_COUNT=0
  ```
- **Internal-Only Container Verification (`docker inspect`)**:
  - `allinagent-postgres`: `{}` (`0` host ports; `allinagent_data` internal network only)
  - `allinagent-hermes`: `{}` (`0` host ports; `:8650` internalauthenticated token bridge)
  - `allinagent-vulnclaw`: `{}` (`0` host ports; `:8660` air-gapped `allinagent_data` network only)
- **Encrypted Remote Access & TLS Templates**:
  - `/opt/allinagent/deploy/proxy/ssh-tunnel-access.sh` (`0755`) and `ssh-tunnel-access.ps1` ready for zero-domain SSH loopback forwarding (`-L 127.0.0.1:8200:127.0.0.1:8200` .. `8202`).
  - `/opt/allinagent/deploy/proxy/nginx-allinagent.conf.template` and `install-nginx.sh` staged cleanly (omits `reuseport` on `listen 443 quic;` to preserve multi-vhost compatibility; host `nginx -t` verified `syntax is ok / test is successful`).

---

## 5. Phase 26 — `systemd` Boot Autostart & `03:00 Asia/Jakarta` Maintenance Timer

Installed via `/opt/allinagent/deploy/linux/install-systemd.sh` into `/etc/systemd/system/`:

| Systemd Unit | Enabled State | Active State | Configuration Summary |
|---|---|---|---|
| `allinagent.service` | `enabled` | `active` | `WorkingDirectory=/opt/allinagent`, `ExecStart=/opt/allinagent/allinagent --production up`, `ExecStop=/opt/allinagent/allinagent --production stop` |
| `allinagent-maintenance.service` | `static` (timer-triggered) | `inactive (dead)` | `Nice=10`, `CPUQuota=75%`, `MemoryMax=512M`, `ExecStart=/opt/allinagent/allinagent --production update --scheduled-maintenance --yes` (defers on active runs/`maintenance.lock`, backs up PostgreSQL, auto-rolls back on failed healthcheck, never runs `docker system prune`) |
| `allinagent-maintenance.timer` | `enabled` | `active (waiting)` | `OnCalendar=*-*-* 03:00:00 Asia/Jakarta`, `Persistent=true`, `RandomizedDelaySec=120` |

Verified timer schedule via `systemctl list-timers allinagent-maintenance.timer --no-pager`:
```text
NEXT                            LEFT     LAST PASSED UNIT                         ACTIVATES
Tue 2026-11-24 20:01:32 UTC     3h 57min -    -      allinagent-maintenance.timer allinagent-maintenance.service
```
*(Note: `20:01:32 UTC` equals `03:01:32 WIB / Asia/Jakarta`, within the `120s` jitter window of `03:00:00 Asia/Jakarta`.)*
