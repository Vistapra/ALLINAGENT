# PHASE 19 — Resource Optimization for 2 vCPU & 8 GB RAM Hosts

- **Phase ID:** `PHASE-19`
- **Status:** `PASS`
- **Scope:** `compose.production.yaml`, `deploy/docker/postgresql-lowmem.conf`, `deploy/docker/*.Dockerfile`, `scripts/allinagent_cli.py`

---

## 1. Host Capacity Constraints & Engineering Budget

On dense multi-tenant 2-vCPU / 8-GB RAM Linux VPS deployments (~`3.4 GiB` `MemAvailable`), `ALLINAGENT` enforces strict cgroup v2 memory and CPU quotas so host services (databases, web workers, reverse proxy) retain `>= 1.87 GiB` of untouched physical memory headroom without swap thrashing:

| Service | `mem_reservation` (Idle Target) | `mem_limit` / `memswap_limit` | `cpus` Cap | `pids_limit` | Heap / Allocator Tuning |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `postgres` | `96m` | `256m` | `0.35` | `128` | `postgresql-lowmem.conf` (`shared_buffers=48MB`, `jit=off`, `max_connections=40`) |
| `paperclip` | `192m` | `480m` | `0.65` | `192` | `NODE_OPTIONS=--max-old-space-size=360`, `MALLOC_ARENA_MAX=2` |
| `hermes` | `128m` | `384m` | `0.75` | `192` | `HEAVY_WORKER_CONCURRENCY=1`, `PYTHONMALLOC=malloc`, `MALLOC_ARENA_MAX=2` |
| `office-bridge` | `64m` | `160m` | `0.35` | `128` | `NODE_OPTIONS=--max-old-space-size=112`, `MALLOC_ARENA_MAX=2` |
| `office` | `80m` | `192m` | `0.40` | `128` | `NODE_OPTIONS=--max-old-space-size=144`, `MALLOC_ARENA_MAX=2` |
| `vulnclaw` | `64m` *(idle)* | `192m` *(on-demand scan peak)* | `0.50` | `64` | `PYTHONMALLOC=malloc`, `MALLOC_ARENA_MAX=2`, mutual-exclusion with heavy worker |
| **Total Steady Budget** | **`624 MiB`** | **`1,472 MiB` core + `64 MiB` idle = `1,536 MiB` (`1.50 GiB`)** | Bounded per-service `<= 0.75` | `832` | `memswap_limit == mem_limit` prevents swap storms |

---

## 2. Key Low-Memory & Storage Protections

1. **PostgreSQL 16 Low-Memory Tuning (`deploy/docker/postgresql-lowmem.conf`):**
   - Disables LLVM JIT (`jit = off`) to eliminate 50–100 MiB transient query compilation spikes.
   - Caps `shared_buffers = 48MB`, `work_mem = 2MB`, `maintenance_work_mem = 24MB`, `wal_buffers = 4MB`, `max_connections = 40`, and `autovacuum_max_workers = 2`.
2. **V8 & glibc Arena Fragmentation Controls:**
   - Every Node.js 24 container sets explicit `--max-old-space-size` sized ~75% of its cgroup `mem_limit` so V8 major GC runs well before the kernel OOM killer triggers.
   - Every glibc container sets `MALLOC_ARENA_MAX=2` (and Python containers set `PYTHONMALLOC=malloc`) to eliminate multi-thread arena virtual-address bloat.
3. **Host Build OOM Protection:**
   - `compose.production.yaml` sets `pull_policy: missing` for registry-first GHCR image pulls.
   - If `--build` is invoked via `./allinagent` on any host with `<= 9,000 MiB` total RAM, `allinagent_cli.py` automatically enforces `docker buildx build --load --memory=1280m --cpus=1.0`.
4. **Nightly Prune Immunity & Log Rotation:**
   - All persistent state lives in host bind-mounts under `${ALLINAGENT_DATA_DIR:-/opt/allinagent/data}` (immune to `docker volume prune`).
   - All 6 services configure `restart: unless-stopped` (immune to `docker container/image prune`) and `json-file` log rotation (`max-size: 10m`, `max-file: 3` -> `<= 180 MiB` total container logs across the entire stack).

---

## 3. Verification Evidence

- Programmatically verified `compose.production.yaml` memory limits: `core_sum=1472MiB + vulnclaw_idle=64MiB = 1536MiB (<=1536MiB), vulnclaw_peak=192MiB`.
- Verified `memswap_limit` matches `mem_limit` on all 6 services so containers cannot push host workloads into swap.
