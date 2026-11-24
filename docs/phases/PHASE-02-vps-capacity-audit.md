# PHASE 02 — VPS Capacity, Service & Compatibility Audit (`<TARGET_VPS_IPV4>`)

- **Audit Timestamp (UTC)**: `2026-11-24T07:32:44Z`
- **Target Host**: `root@<TARGET_VPS_IPV4>` (Hostname: `<TARGET_VPS_HOSTNAME>`)
- **Audit Method**: Strictly Read-Only SSH (`ssh -o BatchMode=yes`), **0 mutations**, **0 service restarts**, **0 secrets read**
- **Overall Compatibility Verdict**: **PASS WITH STRICT RESOURCE CAPS (`PASS_WITH_STRICT_RESOURCE_CAPS`)**

---

## 1. Executive Summary & Key Numbers

The target production VPS (`<TARGET_VPS_IPV4>`, **Ubuntu 24.04.4 LTS**, **2 vCPU AMD EPYC 9354P**, **7.755 GiB RAM**, **95.82 GiB SSD/NVMe ext4**) already hosts a dense multi-tenant production workload (**41 running systemd services** + **34 running Docker containers** across 10 custom bridge networks behind **Nginx 1.30.2** with HTTP/3 QUIC).

Despite this density, the host is stable (**17d 22h 40m uptime**, 15-minute load average **`0.71`** = **35.5% of 2 vCPUs**), well-hardened (`UFW` + `DOCKER-USER` eth0 drop rule + `CrowdSec` + `Fail2Ban` + `Monarx`), and has sufficient headroom to host **ALLINAGENT** safely under `/opt/allinagent` **provided strict cgroup memory/CPU caps and build constraints are enforced**:

| Metric | Empirical Measurement | Engineering Budget / Allocation for ALLINAGENT |
| :--- | :--- | :--- |
| **CPU** | **2 vCPUs** (`AMD EPYC 9354P`, KVM); Load Avg: `0.92 / 0.74 / 0.71` (`0%` `wa`, `4–8%` `st`) | Idle `< 0.05 vCPU`; Sustained Active `<= 0.75 vCPU`; Per-container cap `cpus: "1.00"` max |
| **Physical RAM (`MemTotal`)** | **`7,940.88 MiB`** (`7.755 GiB` / `8,326,610,944 B`) | — |
| **Currently Used RAM** | **`4,533.67 MiB`** (`4.427 GiB` / `57.09%`) | Existing host services (`~2.47 GiB`) + 34 Docker containers (`2,066.08 MiB`) |
| **Actual Available RAM (`MemAvailable`)** | **`3,407.21 MiB`** (`3.327 GiB` / `3,572,715,520 B` / `42.91%`) | **Reserved Host + Existing-App Burst Buffer**: **`1,871 MiB` (`1.83 GiB`)** |
| **Swap (`SwapTotal` / `Used` / `Free`)** | **`6.00 GiB` total** (`/swapfile` 4G + `/home/.swap` 2G); **`2.63 GiB` used**, **`3.37 GiB` free** | Swap is emergency OOM cushion ONLY (`so=700 KB/s` observed); ALLINAGENT must stay in physical RAM |
| **ALLINAGENT RAM Budget** | Derived from `3,407 MiB` `MemAvailable` minus `1,871 MiB` safety buffer | **Idle**: **`350–768 MiB`** \| **Active**: **`<= 1,280 MiB`** \| **Hard Cgroup Cap**: **`1,536 MiB` (`1.50 GiB`)** |
| **Root Disk (`/dev/sda1` ext4)** | **`95.82 GiB` total**, **`47.97 GiB` used (`51%`)**, **`47.84 GiB` available (`49%`)** | **`<= 12.0 GiB` max** (`3.0–6.0 GiB` steady target), preserving **`>= 24.0 GiB`** host free floor |
| **Root Inodes (`df -i`)** | **`12,976,128` total**, `1,103,848` used (`9%`), **`11,872,280` free (`91%`)** | `<= 250,000` inodes (`~2%` of free capacity) |
| **Deployment Directory** | `/opt` uses `388 MiB`; `/opt/allinagent` **DOES NOT EXIST** | **`/opt/allinagent`** (bind-mount persistent state in `/opt/allinagent/data`) |
| **Safe Loopback Port Range** | `8181–8442` completely unoccupied on `0.0.0.0`, `[::]`, and `127.0.0.1` | **`127.0.0.1:8200–8219`** (`8200` Web, `8201` API/Gateway, `8202` WS/Bridge) |
| **Network Isolation** | `172.17/16`, `172.18/16`, `172.20.0–8/24` already in use by Docker | **`allinagent_edge`** (`192.168.240.0/24`) + **`allinagent_data`** (`192.168.241.0/24`, `internal: true`) |

---

## 2. OS, Kernel, CPU & Virtualization (`PASS`)

- **Operating System**: `Ubuntu 24.04.4 LTS (Noble Numbat)` (`x86_64`)
- **Kernel**: `Linux <TARGET_VPS_HOSTNAME> 6.8.0-149-generic #149-Ubuntu SMP PREEMPT_DYNAMIC Fri Oct 23 13:21:10 UTC 2026`
- **Cgroup Hierarchy**: Unified **`cgroup2fs` (cgroup v2)** (`Docker CgroupDriver=systemd`, `CgroupVersion=2`) — supports accurate per-container `memory.max` (`mem_limit`) and `memory.high` throttling.
- **CPU & Hypervisor**:
  - `2 vCPUs` (`1 socket × 2 cores × 1 thread`), `AMD EPYC 9354P 32-Core Processor` (Zen 4 with AVX2 & AVX-512) under `KVM` (`QEMU pc-i440fx-11.0`).
  - Cache topology: L1d `128 KiB`, L1i `128 KiB`, L2 `1 MiB`, L3 `32 MiB` (2 instances).
- **Clock & Timezone**: `Etc/UTC (+0000)`, NTP active and synchronized (`chrony.service`).
- **Key Kernel Sysctls**:
  - `vm.swappiness = 10`
  - `vm.overcommit_memory = 0`, `vm.overcommit_ratio = 50`
  - `vm.max_map_count = 1048576`
  - `fs.inotify.max_user_watches = 524288`, `fs.inotify.max_user_instances = 512`
  - `fs.file-max = 2097152`

---

## 3. Memory, Swap & Commit Accounting (`PASS WITH CONSTRAINTS`)

### 3.1 Physical RAM & Swap Snapshot (`free -b` & `/proc/meminfo`)

| Metric | Bytes | KiB | MiB | GiB | Notes |
| :--- | ---: | ---: | ---: | ---: | :--- |
| **`MemTotal`** | `8,326,610,944` | `8,131,456` | `7,940.88` | `7.755` | Nominal 8 GB VPS |
| **`MemUsed` (`free`)** | `4,753,895,424` | `4,642,476` | `4,533.67` | `4.427` | `57.09%` of physical RAM |
| **`MemFree`** | `502,636,544` | `490,856` | `479.35` | `0.468` | Unallocated pages |
| **`Shared` (`Shmem`)** | `433,569,792` | `423,408` | `413.48` | `0.404` | Shared memory / tmpfs |
| **`Buff/Cache`** | `3,816,624,128` | `3,727,172` | `3,639.82` | `3.555` | `Buffers` 418.6 MiB + `Cached` 2,334.0 MiB + `SReclaimable` 887.3 MiB |
| **`MemAvailable`** | **`3,572,715,520`** | **`3,488,980`** | **`3,407.21`** | **`3.327`** | **`42.91%` truly available without swapping** |
| **`SwapTotal`** | `6,442,442,752` | `6,291,448` | `6,144.00` | `6.000` | `/swapfile` (`4.0G`, prio `-2`) + `/home/.swap` (`2.0G`, prio `-3`) |
| **`SwapUsed`** | `2,819,960,832` | `2,753,868` | `2,689.32` | `2.626` | `43.77%` used (`SwapCached`: `425.13 MiB`) |
| **`SwapFree`** | `3,622,481,920` | `3,537,580` | `3,454.67` | `3.374` | `56.23%` free |
| **`CommitLimit`** | — | `10,357,176` | `10,114.43` | `9.877` | 50% RAM + 100% Swap |
| **`Committed_AS`** | — | `22,743,376` | `22,210.33` | `21.690` | **2.20× `CommitLimit`** (V8/Node/Python/MySQL virtual address reservations) |

> **Critical SRE Finding on Swap & Virtual Commit**:
> `2.626 GiB` of swap is already populated after 17.9 days of uptime, and `vmstat 1 3` recorded a transient swap-out burst (`so = 700 KB/s`) when `MemFree` dipped to `~219 MiB`. Swap must be treated strictly as an emergency OOM buffer — **ALLINAGENT's entire active working set (`<= 1,280 MiB`) and hard cgroup limit (`1,536 MiB`) must fit inside physical `MemAvailable` (`3,407 MiB`)** while leaving `>= 1,871 MiB` untouched for the host kernel and existing-service bursts.

---

## 4. Disk & Inode Capacity (`PASS`)

- **Root Partition (`/dev/sda1` on `/`, `ext4`)**:
  - **Capacity**: `102,888,095,744 B` (`95.82 GiB`)
  - **Used**: `51,508,563,968 B` (`47.97 GiB` / **`51%`**)
  - **Available**: `51,362,754,560 B` (**`47.84 GiB`** / **`49%`**)
  - **Inodes**: `12,976,128` total | `1,103,848` used (`9%`) | **`11,872,280` free (`91%`)**
- **Top-Level Directory & Docker Storage Breakdown**:
  - Docker Images (`/var/lib/docker`): **`27.0 GB`** across 39 images (`18.96 GB` reclaimable — *untouched per read-only rule*)
  - Docker Build Cache: **`2.837 GB`** (137 entries)
  - Docker Local Volumes: **`1.665 GB`** (12 active volumes)
  - Docker Containers RW Layers: **`366.5 MB`** (34 containers)
  - `/home`: **`7.4 GiB`** (includes `2.0 GiB` `/home/.swap` + CloudPanel app directories)
  - `/swapfile`: **`4.0 GiB`**
  - `/var/www`: **`1.2 GiB`**
  - `/var/log`: **`665 MiB`**
  - `/opt`: **`388 MiB`** (`/opt/allinagent` verified **`DOES_NOT_EXIST`**)
  - `/var/lib/containerd`: **`379 MiB`** | `/var/lib/apt`: **`208 MiB`** | `/var/cache`: **`187 MiB`** | `/var/lib/crowdsec`: **`101 MiB`**

---

## 5. Uptime, Load Average & Live CPU/IO Telemetry (`PASS`)

- **Uptime**: `17 days, 22:40` (`9` runnable threads / `1,458` total kernel tasks)
- **Load Average**: `0.92` (1m) | `0.74` (5m) | `0.71` (15m) -> **35.5%–46.0% average utilization across 2 vCPUs**
- **`vmstat 1 3` Empirical Sample**:
  - Sample 1 (since-boot avg): `us=6%`, `sy=5%`, `id=84%`, `wa=0%`, `st=4%`
  - Sample 2 (live 1s): `us=40%`, `sy=30%`, `id=25%`, `wa=0%`, `st=5%`, `bi=244`, `bo=1192`, `cs=8784`
  - Sample 3 (live 1s): `us=20%`, `sy=23%`, `id=49%`, `wa=0%`, `st=8%`, `so=700`, `bo=1656`, `cs=9559`
  - **Assessment**: Disk I/O wait is `0%` (fast NVMe/SSD), hypervisor steal is `4–8%`. Because only 2 vCPUs exist, per-container Docker `cpus` limits (`<= 1.00`) are mandatory so ALLINAGENT cannot starve `nginx` or `php8.3-fpm` latency.

---

## 6. Existing Services, Processes, Supervisor & Cron Inventory

### 6.1 Host Systemd Services — Current vs Historical Cgroup Peak (`MemoryCurrent` vs `MemoryPeak`)

41 systemd services are `active (running)`. Kernel cgroup v2 memory accounting over the 17.9-day uptime reveals both steady-state and historical burst peaks:

| Systemd Unit | Current (`MiB`) | Historical Peak (`MiB`) | Peak Delta (`+MiB`) | Role / Notes |
| :--- | ---: | ---: | ---: | :--- |
| `mysql.service` | `1,157.68` | `1,591.71` | `+434.03` | Host Percona Server `8.4.8-8` (`*:3306`, `*:33060`), RSS `1,002.8 MiB` |
| `cron.service` | `343.55` | `1,418.43` | `+1,074.88` | Scheduled prune/backups (`04:00 UTC` `/root/remote_prune.sh` + `/etc/cron.d/*`) |
| `supervisor.service` | `335.29` | `453.36` | `+118.07` | 2× `tenant-commerce-queue-worker`, `tenant-commerce-telegram-worker`, `tenant-commerce-reverb` (`:6001`) |
| `monarx-agent.service` | `285.70` | `1,023.44` | `+737.74` | Host security/malware scanner |
| `containerd.service` | `271.55` | `287.13` | `+15.58` | Container runtime + 34 `containerd-shim` processes |
| `pm2-tenant-commerce-work.service` | `265.62` | `441.06` | `+175.44` | `work.<EXISTING_TENANT_DOMAIN>` (`next-server` on `127.0.0.1:20128`) |
| `php8.3-fpm.service` | `213.50` | `567.54` | `+354.04` | 11 procs on `127.0.0.1:18000` (`<EXISTING_TENANT_DOMAIN>`, `dbadmin.<EXISTING_TENANT_DOMAIN>`) |
| `docker.service` | `185.62` | `1,484.60` | `+1,298.98` | Docker Engine `29.1.3` (peaks during `docker build` / layer extraction) |
| `nginx.service` | `177.48` | `302.78` | `+125.30` | Main public reverse proxy (`nginx/1.30.2` HTTP/2 + HTTP/3 QUIC) |
| `systemd-journald.service` | `165.77` | `356.43` | `+190.66` | System journal daemon |
| `qemu-guest-agent.service` | `115.73` | `1,028.57` | `+912.84` | KVM hypervisor guest agent |
| `crowdsec.service` (+ bouncer) | `113.98` | `285.65` | `+171.67` | IPS engine (`127.0.0.1:8180`, `127.0.0.1:6060`) + netfilter bouncer |
| `clp-*` + `php8.5-fpm` | `82.16` | `128.93` | `+46.77` | CloudPanel UI (`:8443`) + `php8.5-fpm` (`127.0.0.1:20000–20001`) |
| `vps-guardian-mas.service` | `40.03` | `60.77` | `+20.74` | Cgroup-capped (`MemoryHigh=192 MiB`, `MemoryMax=256 MiB`) |
| `tailscaled.service` | `39.25` | `46.47` | `+7.22` | Tailscale mesh (`<TAILSCALE_MESH_IPV4>`) |
| `tenant-vps-admin.service` | `25.30` | `161.53` | `+136.23` | Host `uvicorn` agent on `172.20.8.1:8130` |
| `fail2ban.service` | `25.23` | `82.28` | `+57.05` | SSH/Nginx ban daemon |
| `redis-server.service` | `7.82` | `123.94` | `+116.12` | Host Redis `7.0.15` on `127.0.0.1:6379` / `[::1]:6379` |
| `tenant-tunnel-hris/mrp` | `1.35` | `4.84` | `+3.49` | Outbound SSH DB tunnels bound on `0.0.0.0:3311` & `0.0.0.0:3312` |

### 6.2 Supervisor & Cron Operational Findings

- **Supervisor (`/etc/supervisor/conf.d/tenant-commerce.conf`)**:
  - `tenant-commerce-queue-worker_00` (`RUNNING`, `www-data`), `tenant-commerce-queue-worker_01` (`RUNNING`, `www-data`), `tenant-commerce-telegram-worker` (`RUNNING`, `www-data`), `tenant-commerce-reverb` (`RUNNING`, `www-data`, `:6001`).
- **Cron Jobs (Prune & Maintenance Hazard Identified)**:
  - Root `crontab -l`: `0 4 * * * bash /root/remote_prune.sh`
  - `/etc/cron.d/`: `certbot`, `clp`, **`docker-builder-prune`**, `e2scrub_all`, `tenant-iot`, `tenant-agent-cleanup`, `tenant-watchdog`, `monarx-update`, `php`, `sysstat`, `tenant-router-backup`, `tenant-router-export`.
  - **Safeguard for ALLINAGENT**: Because automated prune jobs run nightly at `04:00 UTC`, ALLINAGENT containers **MUST** use `restart: unless-stopped` (staying active so `docker image/container prune` never removes them) and store persistent files in **host bind-mounts under `/opt/allinagent/data/`** (immune to `docker volume prune`).

---

## 7. Docker & Docker Compose Environment (`PASS`)

- **Docker Engine**: `29.1.3` (API `1.52`, `overlay2`, `cgroup2fs` via `systemd`, `LiveRestore=true`, `json-file` logging)
- **Docker Compose Plugin**: `docker compose` **`v2.40.3`** (`docker-compose` v1 standalone binary is `NOT_INSTALLED` — deployment scripts **MUST** invoke `docker compose` with a space, never `docker-compose`!).
- **Running Containers**: **34 / 34 running** (0 exited/dead), consuming **`2,066.08 MiB` (`2.018 GiB`)** live RAM total:
  - Largest containers: `open-webui` (`637.9 MiB / 2 GiB`), `tenant-gateway` (`155.1 MiB / 1.5 GiB`), `tenant-grafana` (`128.1 MiB / 512 MiB`), `tenant-events-app` (`116.6 MiB / 512 MiB`), `tenant-loki` (`113.8 MiB / 256 MiB`), `tenant-uptime-kuma` (`100.9 MiB / 384 MiB`), `tenant-iot-db` (`98.6 MiB / 768 MiB`), `tenant-erp-db` (`97.9 MiB / 768 MiB`).
- **Existing Docker Bridge Subnets (Do Not Collide)**:
  - `172.17.0.0/16` (`bridge`), `172.18.0.0/16` (`tenant-signage_default`), and `172.20.0.0/24` through `172.20.8.0/24` (`tenant-commerce-monitoring`, `order-tenant-commerce`, `tenant-events`, `tenant-ops`, `tenant-iot`, `tenant-erp`, `tenant-portal`, `tenant-vms`, `open-webui-app_tenant-internal`).

---

## 8. Ports, Reverse Proxy, TLS, Databases & Firewall (`PASS`)

### 8.1 Occupied Ports Summary (`ss -lntup`)

- **Public / Wildcard TCP**: `22` (sshd), `25` (postfix), `80` (nginx), `443` (nginx), `3002` (tenant-events), `3080` (tenant-signage), **`3306` & `33060` (host Percona MySQL)**, `3307` (tenant-iot-db), `3311–3312` (SSH DB tunnels), `5050` (tenant-ops-pgadmin), **`5432` (Docker `tenant-ops-pgsql`)**, `6001` (reverb), `6380` (tenant-iot-redis), `8000` (tenant-ops-app), `8001` (tenant-iot-web), `8080` (nginx tenant-ops), `8082` (tenant-erp-pma), `8085` (tenant-erp-nginx), `8088–8089` (nginx tenant-commerce), `8443` (clp-nginx), `8888` (tenant-iot-pma), `9090` (prometheus), `9100/9101/9104/9113/9121` (exporters).
- **Public / Wildcard UDP**: `443` (nginx QUIC HTTP/3), `41641` (tailscaled).
- **Loopback (`127.0.0.1`) TCP**: `53` (systemd-resolved), `3000` (grafana), `3001` (uptime-kuma), `3100` (loki), `4040` (ngrok), `6060` (crowdsec), **`6379` (host Redis 7.0.15)**, `8083` (tenant-portal), `8086` (order-tenant-commerce), `8090` (open-webui), `8098` (nginx mirror), `8100` (tenant-gateway), `8101–8102` (tenant-vms), `8180` (crowdsec LAPI), `18000` (php-fpm8.3), `20000–20001` (php-fpm8.5), `20128` (next-server), `28341` (containerd), `65529` (monarx).
- **Bridge-Specific TCP**: `172.20.8.1:8130` (`tenant-vps-admin`).

> **Database Port Collisions Prevented**:
> - `0.0.0.0:3306` (Host Percona MySQL 8.4), `0.0.0.0:5432` (Docker `tenant-ops-pgsql`), and `127.0.0.1:6379` (Host Redis 7.0) are **ALL OCCUPIED**.
> - ALLINAGENT's database/cache containers **MUST NOT** publish `5432`, `3306`, or `6379` to the host — keep them strictly inside `allinagent_data` (`internal: true`).

### 8.2 Reverse Proxy (`nginx/1.30.2`) & TLS Compatibility

- **Host Nginx (`nginx.service`)**: `nginx/1.30.2` (`worker_processes auto;`, `worker_connections 2000;`), including `/etc/nginx/sites-enabled/*.conf`.
- **15 Active Vhost Files in `/etc/nginx/sites-enabled/`**:
  `agent.<EXISTING_TENANT_DOMAIN>.conf`, `api.tenant-vms.<EXISTING_CORP_DOMAIN>.conf`, `tenant-backend-app.conf`, `dbadmin.<EXISTING_TENANT_DOMAIN>.conf`, `default.conf`, `signage.<EXISTING_CORP_DOMAIN>.conf`, `tenant-frontend-app.conf`, `iot.<EXISTING_CORP_DOMAIN>.conf`, `tenant-commerce-mirror.conf`, `portal.<EXISTING_CORP_DOMAIN>.conf`, `ops.<EXISTING_CORP_DOMAIN>.conf`, `events.<EXISTING_CORP_DOMAIN>.conf`, `erp.<EXISTING_CORP_DOMAIN>.conf`, `tenant-vms.<EXISTING_CORP_DOMAIN>.conf`, `work.<EXISTING_TENANT_DOMAIN>.conf`.
- **Certbot & Let's Encrypt**: `/usr/bin/certbot` (`nginx` authenticator/installer) installed; `/etc/letsencrypt/live/` currently holds `agent.<EXISTING_TENANT_DOMAIN>`, `dbadmin.<EXISTING_TENANT_DOMAIN>`, `tenant-commerce-mirror`, `<EXISTING_TENANT_DOMAIN>`, `order.<EXISTING_TENANT_DOMAIN>`.
- **Critical Nginx QUIC Gotcha**: `/etc/nginx/sites-enabled/default.conf` already declares `listen 443 quic reuseport default_server;` and `listen [::]:443 quic reuseport default_server;`. Any new ALLINAGENT Nginx vhost using HTTP/3 **MUST** use `listen 443 quic;` **WITHOUT** `reuseport`, otherwise `nginx -t` will reject the config!

### 8.3 Firewall (`UFW` + `DOCKER-USER` + `CrowdSec`)

- **UFW**: Active (`Default: deny incoming, allow outgoing, allow routed`). Publicly allowed ports: `21/tcp`, `22/tcp`, `80/tcp`, `443/tcp`, `443/udp`, `4443/tcp`, `5050/tcp`, `8080/tcp`, `8082/tcp`, `8443/tcp`.
- **`DOCKER-USER` Hardening (`host-docker-user`)**: Custom iptables/ip6tables rules drop **all** `NEW` inbound packets arriving on `eth0` destined for forwarded Docker container ports (`[HOST-DOCKER-BLOCK]`). All external HTTP/HTTPS/WSS traffic **must** enter via Host Nginx (`80`/`443`) -> `127.0.0.1:<port>`.

---

## 9. Engineering Resource Budget & Isolation Architecture for ALLINAGENT

### 9.1 Memory, CPU & Disk Budget

1. **Memory Budget (Out of `3,407 MiB` Live `MemAvailable`)**:
   - **Untouchable Host + Existing-App Burst Buffer**: **`1,871 MiB` (`1.83 GiB`)** (absorbs concurrent bursts from `mysql`, `php8.3-fpm`, `supervisor/reverb`, `pm2/next`, `open-webui`, and nightly `cron`/`monarx` scans while preserving Linux page cache to avoid swap thrashing).
   - **ALLINAGENT Idle Target**: **`350 – 768 MiB`** (leaves `2.6–3.0 GiB` `MemAvailable` on host).
   - **ALLINAGENT Active Sustained Budget**: **`<= 1,280 MiB` (`1.25 GiB`)** (leaves `>= 2.08 GiB` `MemAvailable` on host).
   - **ALLINAGENT Hard Cgroup Ceiling (Sum of `mem_limit`s)**: **`1,536 MiB` (`1.50 GiB`)**:
     - `web` (Frontend): `mem_limit: 384m` (`NODE_OPTIONS="--max-old-space-size=256"`)
     - `api` / `agent` (Core Runtime): `mem_limit: 640m`
     - `db` (PostgreSQL 16-alpine tuned `shared_buffers=64MB`, `max_connections=40`, if deployed): `mem_limit: 256m`
     - `redis` (Redis 7-alpine `--maxmemory 96mb --maxmemory-policy allkeys-lru`, if deployed): `mem_limit: 128m`
     - `worker` / `bridge` sidecar (if deployed): `mem_limit: 128m`
   - **Mandatory Image Build Rule**: **DO NOT** run unconstrained `docker compose build` (`next build` / `tsc`) on this 2-vCPU VPS (`docker.service` previously peaked at `1,485 MiB`). Build images off-host (on `<WINDOWS_BASELINE_HOST>` / CI and transfer via registry or compressed `docker save | ssh docker load`) OR strictly enforce `--memory=1280m --cpus=1.0` + `NODE_OPTIONS="--max-old-space-size=1024"`.
2. **CPU Budget (Out of `2.0 vCPUs`)**:
   - Idle `<= 0.05 vCPU`, Active `<= 0.75 vCPU`; enforce Docker `cpus` caps (`1.00` on `api/agent`, `0.75` on `web`, `0.50` on `db/worker`, `0.25` on `redis`).
3. **Disk Budget (Out of `47.84 GiB` Available on `/`)**:
   - **ALLINAGENT Max Cap**: **`12.0 GiB`** (`3.0–6.0 GiB` steady-state target), keeping `>= 24.0 GiB` free on `/`.
   - Enforce Docker log rotation on every ALLINAGENT service: `logging: { driver: "json-file", options: { "max-size": "10m", "max-file": "3" } }`.

### 9.2 Deployment Path, Safe Loopback Ports & Network Isolation

- **Deployment Directory**: **`/opt/allinagent`** (`/opt/allinagent/compose`, `/opt/allinagent/data`, `/opt/allinagent/logs`, `/opt/allinagent/backups` — `chmod 750` root-owned, immune to Docker volume prunes).
- **Safe Loopback Port Range**: **`127.0.0.1:8200–8219`** (100% free; zero public `0.0.0.0` port bindings):
  - `127.0.0.1:8200` -> ALLINAGENT Web / UI
  - `127.0.0.1:8201` -> ALLINAGENT API / Gateway
  - `127.0.0.1:8202` -> Optional WebSocket / Bridge endpoint
- **Two-Tier Docker Network Isolation**:
  - `allinagent_edge` (`bridge`, `internal: false`, subnet **`192.168.240.0/24`**): Ingress from `127.0.0.1:8200–8202` + outbound HTTPS egress for LLM/external APIs. Using `192.168.240.0/24` avoids all `172.17–172.20` Docker bridges AND prevents unintended access to UFW's `172.16.0.0/12` rules for HRIS/MRP MySQL tunnels (`3311`/`3312`).
  - `allinagent_data` (`bridge`, **`internal: true`**, subnet **`192.168.241.0/24`**): Air-gapped internal network for ALLINAGENT PostgreSQL/Redis — no host ports, no internet egress, and zero cross-bridge visibility to the 34 existing containers.
