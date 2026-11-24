# ALLINAGENT — Hardware Sizing, `2 vCPU / 8 GB RAM` Tuning & Cgroup Budget

`ALLINAGENT` is engineered to run a complete 6-container autonomous AI company **24/7 inside a hard `<= 1,536 MiB` (`1.50 GiB`) cgroup v2 ceiling** on a **`2 vCPU / 8 GB RAM` Ubuntu LTS VPS** — even on dense multi-tenant servers already hosting existing databases, web apps, and background workers — with **zero server GPU required** and **zero swap thrashing**.

Authoritative configuration files:
- [`compose.production.yaml`](./compose.production.yaml) — Production cgroup `mem_limit`, `memswap_limit`, `cpus`, `pids_limit` & V8/Python allocator caps
- [`config/resource-limits.json`](./config/resource-limits.json) — `2_vcpu_8gb_profile` vs `standard_profile` concurrency & memory budgets
- [`deploy/docker/postgresql-lowmem.conf`](./deploy/docker/postgresql-lowmem.conf) — Tuned PostgreSQL 16 configuration (`< 220 MiB` ceiling)

---

## 1. Supported Hardware Tiers & Deployment Profiles

| Tier / Profile | CPU | Physical RAM | Free Disk | Compose / Entrypoint | Recommended Use Case |
| :--- | :---: | :---: | :---: | :--- | :--- |
| **Low-Resource Production** | `2 vCPU` | `4 GiB` (`>= 3.5 GiB`) | `>= 10 GiB` | Low-memory profile (`2D Pixel Office` default, zero headless Chromium) | Entry-level 4 GB cloud VPS or constrained edge node (`<= 1,024 MiB` stack target). |
| **2 vCPU / 8 GB Production** *(Default Target)* | **`2 vCPU`** | **`8 GiB`** (`>= 1.6 GiB` `MemAvailable`) | **`>= 24 GiB`** *(multi-tenant floor; `6 GiB` min)* | `./allinagent --production up` (`compose.yaml` + `compose.production.yaml`) | Shared or dedicated `2 vCPU / 8 GB RAM` Ubuntu 24.04 LTS VPS (`<= 1,536 MiB` steady cgroup ceiling; full 3D + 2D Office). |
| **Standard Workstation / Dedicated Server** | `4+ vCPU` | `16+ GiB` | `>= 30 GiB` | `./allinagent --local up` (`standard_profile` in `config/resource-limits.json`) | Contributor workstations & dedicated 16 GB+ servers (`HEAVY_WORKER_CONCURRENCY=2`, `4,096 MiB` stack ceiling). |

### Linux Kernel & Runtime Prerequisites
- **OS & Cgroups:** Ubuntu 22.04 / 24.04 LTS or Debian 12 (`x86_64` or `arm64`) with **unified `cgroup v2`** (`cgroup2fs`) enabled so Docker enforces per-container `memory.max` (`mem_limit`) and `memory.swap.max` (`memswap_limit`) accurately.
- **Container Engine:** Docker Engine `>= 24.0` + **Docker Compose v2 plugin** (`docker compose version`; standalone v1 `docker-compose` is unsupported).
- **Zero Server GPU:** 100% of `Three.js` 3D WebGL and `Phaser` 2D Canvas rendering executes in the **viewer's client browser**.

---

## 2. Empirical `2 vCPU / 8 GB RAM` Host Memory Math

On a shared `8 GiB` (`~7,941 MiB`) multi-tenant Linux VPS where existing host services and containers already consume `~4.4 GiB` (`~3,407 MiB` `MemAvailable`), relying on Linux swap causes severe latency spikes. `ALLINAGENT` fits strictly inside physical `MemAvailable`:

| Budget Envelope | Target / Limit | Engineering Purpose |
| :--- | :---: | :--- |
| **Untouched Host & Existing-App Burst Buffer** | **`>= 1,850 – 1,871 MiB`** | Preserves Linux page cache and absorbs bursts from co-located host databases, PHP/Node workers, Nginx, and cron jobs without swap-out stalls. |
| **ALLINAGENT Idle Working Set** | **`~415 – 512 MiB`** | 4 Wave-1 agents active (`idle`), 7 Wave-2 agents suspended (`STANDBY`), single shared Python 3.14 venv, tuned PostgreSQL 16. |
| **ALLINAGENT Sustained Active Working Set** | **`<= 1,070 – 1,280 MiB`** | Active turn or delegated Kanban subtask serialized by `HEAVY_WORKER_CONCURRENCY=1`. |
| **ALLINAGENT Hard Cgroup Ceiling** | **`1,536 MiB` (`1.50 GiB`)** | `1,408 MiB` core 5-service `mem_limit` sum (`224 + 416 + 384 + 160 + 224`) + `128 MiB` `vulnclaw` `mem_limit` (`1,536 MiB` total ceiling; heavy runs serialized via `HEAVY_WORKER_CONCURRENCY=1`). |

---

## 3. Per-Container Cgroup v2 Allocation (`compose.production.yaml` & `config/resource-limits.json`)

Notice that every production service sets **`memswap_limit` equal to `mem_limit`**, preventing any container from spilling into host swap (`0 MiB` container swap allowance), alongside `MALLOC_ARENA_MAX=2` and bounded `pids_limit`:

| Service (`Container`) | `mem_reservation` | Hard `mem_limit` (`memswap_limit`) | `cpus` Cap | `pids_limit` | Heap / Allocator Tuning | Loopback / Network Exposure |
| :--- | :---: | :---: | :---: | :---: | :--- | :--- |
| `postgres` (`allinagent-postgres`) | `96m` | **`224m`** (`224m`) | `0.45` | `128` | `shared_buffers=48MB`, `work_mem=2MB`, `jit=off`, `max_connections=40` | Internal `allinagent_data` only (`0` host ports) |
| `paperclip` (`allinagent-paperclip`) | `160m` | **`416m`** (`416m`) | `0.75` | `192` | `NODE_OPTIONS="--max-old-space-size=300"`, `MALLOC_ARENA_MAX=2` | `127.0.0.1:8201` $\rightarrow$ `:3100` |
| `hermes` (`allinagent-hermes`) | `128m` | **`384m`** (`384m`) | `0.85` | `192` | `HEAVY_WORKER_CONCURRENCY=1`, `PYTHONMALLOC=malloc`, `MALLOC_ARENA_MAX=2` | Internal `:8650` only (`0` host ports) |
| `office-bridge` (`allinagent-office-bridge`) | `64m` | **`160m`** (`160m`) | `0.40` | `128` | `NODE_OPTIONS="--max-old-space-size=112"`, `MALLOC_ARENA_MAX=2`, 500-event ring | `127.0.0.1:8202` $\rightarrow$ `:3210` |
| `office` (`allinagent-office`) | `80m` | **`224m`** (`224m`) | `0.50` | `128` | Next.js `standalone`, `NODE_OPTIONS="--max-old-space-size=128"`, `MALLOC_ARENA_MAX=2` | `127.0.0.1:8200` $\rightarrow$ `:3200` |
| **Core 5 Subtotal** | **`528m`** | **`1,408 MiB`** | *Shared 2 vCPU* | — | Steady RSS `~395 MiB` idle / `~950 MiB` active | — |
| `vulnclaw` (`allinagent-vulnclaw`) | `32m` | **`128m`** (`128m`) | `0.50` | `64` | `PYTHONMALLOC=malloc`, `MALLOC_ARENA_MAX=2`, `read_only: true`, `~21 MiB` idle RSS | Air-gapped `allinagent_data` (`:8660`, `0` host ports) |
| **TOTAL HARD STACK CEILING** | **`560m`** | **`1,536 MiB`** (`1.50 GiB`) | `<= 0.85`/ctr | `832` total | `1,408 MiB` core + `128 MiB` VulnClaw; `HEAVY_WORKER_CONCURRENCY=1` | `127.0.0.1:8200–8202` only |

---

## 4. Six Key Architectural Optimizations for `2 vCPU / 8 GB RAM`

### 4.1 `HEAVY_WORKER_CONCURRENCY=1` Priority Semaphore (`hermes_exec_daemon.py`)
Spawning 6 parallel Python/LLM sub-agents during a CEO `/delegasi` workflow would multiply memory spikes and saturate 2 vCPUs. Instead, `allinagent-hermes` runs an internal broker (`:8650`) enforcing **`HEAVY_WORKER_CONCURRENCY=1`**:
- **Priority 0 (Interactive Owner Lane):** Direct `/chat`, `/ke`, and `/diskusi-rapat` turns run next immediately after any current turn completes.
- **Priority 1 (Background Kanban & Security Lane):** Delegated subtasks, source code analyses, and `VulnClaw` scans queue cleanly and execute one at a time (`max_parallel_engineering_tasks: 1`).

### 4.2 Single Shared Python 3.14 Venv + `< 8 KB` `/usr/local/bin/hermes` CLI Shim
- Neither `allinagent-paperclip` nor `allinagent-office-bridge` installs Python or duplicates `hermes-agent`. Both invoke `/usr/local/bin/hermes` (`components/hermes/hermes-cli-shim.mjs`), streaming NDJSON over `http://hermes:8650` — saving **`> 1.5 GB` of container image layers** and **`> 400 MiB` RAM**.
- Inside `allinagent-hermes`, all 11 `pc*` profiles share `/opt/hermes-venv` (`0 MB` per-agent virtualenv duplication).
- `prune-paperclip-bloat.mjs` strips optional `codex`, `claude`, `opencode`, and `@embedded-postgres` binaries from `paperclip`, saving another **`~1.80 GB`** of disk bloat.

### 4.3 Low-Memory PostgreSQL 16 Configuration (`deploy/docker/postgresql-lowmem.conf`)
- `shared_buffers = 48MB`, `work_mem = 2MB`, `maintenance_work_mem = 24MB`, `temp_buffers = 4MB`, `wal_buffers = 4MB`, `effective_cache_size = 128MB`, `max_connections = 40`.
- **`jit = off` & `huge_pages = off`:** Disabling LLVM JIT prevents `50–100 MiB` per-connection compilation spikes inside the `224m` container limit (`80–120 MiB` typical RSS).

### 4.4 Wave-1 Active (`4`) vs. Wave-2 Standby (`7`) Roster
Only 4 core roles (`@ceo`, `@backend`, `@qa`, `@security`) start active; the remaining 7 specialists remain paused (`0` background heartbeat overhead) until woken on demand.

### 4.5 Off-Host GHCR Image Pulls & RAM-Capped Local Build Fallback
Unconstrained `next build` / `tsc` / `uv` Docker builds can spike Docker daemon memory above `1.4 GiB`.
- **Default (`./allinagent setup`):** Pulls prebuilt multi-arch images from GHCR (`docker compose pull`), consuming near-zero build CPU/RAM on the VPS.
- **Automatic Low-RAM Build Guard (`scripts/allinagent_cli.py`):** If `--build` is requested on a host with `<= 9,000 MiB` RAM, `pull_or_build_images()` builds images **sequentially one service at a time** with `--memory=1280m --cpus=1.0`.

### 4.6 Disk & Log Rotation Budget (`<= 12.0 GiB` Max Cap)
- **Steady-State Disk Footprint:** `~3.0 – 6.0 GiB` (hard operational budget `<= 12.0 GiB`, preserving `>= 24.0 GiB` free disk on multi-tenant hosts).
- **Bounded Container Logs:** Every service enforces `json-file` rotation (`max-size: "10m"`, `max-file: "3"`), capping all 6 containers' logs combined at **`<= 180 MiB`**.
- **Bounded PostgreSQL Backups:** Pre-update `pg_dump` archives (`data/backups/paperclip-pre-update-*.sql.gz`) automatically prune beyond the **7 most recent** snapshots.

---

## 5. Verifying Live Resource Consumption

```bash
# Run preflight & cgroup/memory/port audit
./allinagent doctor

# Inspect real-time per-container cgroup RSS vs hard limits
docker stats --no-stream \
  allinagent-postgres allinagent-paperclip allinagent-hermes \
  allinagent-office-bridge allinagent-office allinagent-vulnclaw
```
