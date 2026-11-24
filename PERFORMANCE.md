# ALLINAGENT — Empirical Performance, Storage & Memory Optimization Report

`ALLINAGENT` transforms a multi-gigabyte, single-host workstation setup (`<LEGACY_WINDOWS_WORKSPACE>`) into a lightweight, container-native production stack capable of running **all 30 capabilities (`FEAT-01`..`FEAT-30`), 11 AI corporate agents, 33 skill packages, 3D/2D Virtual Office, and 59 Telegram commands** inside a strict **`<= 1,536 MiB` (`1.50 GiB`) cgroup v2 ceiling** on a **2-vCPU / 8 GB RAM Ubuntu 24.04 LTS VPS**.

---

## 1. Headline Before-vs-After Optimization Summary

| Optimization Dimension | Legacy Multi-Root Baseline (`<LEGACY_WINDOWS_WORKSPACE>`) | Optimized `ALLINAGENT` (`v1.0.0`) | Empirical Improvement |
| :--- | ---: | ---: | ---: |
| **Total Source & Workspace Disk Footprint** | `11,126,312,521 B` (`10.36 GiB` across `461,174` files) | **`< 15 MiB`** clean Git repository (`~11.5 MiB` tracked source) | **`> 99.8%` reduction** (`100%` capability parity) |
| **Paperclip `node_modules` Runtime Tree** | `2,660,753,330 B` (`2,537.49 MiB`, `76,082` files) | **`486,915,970 B` (`464.36 MiB`, `52,598` files)** | **`-2,073.13 MiB` (`-81.70%`)** |
| **Paperclip PostgreSQL Max Connections** | **`73` connections** (`10` main + `9` sub-pools + `2` listen + `52` dedicated) | **`12` connections** (`5` main + `3` sub-pools + `2` listen + `2` dedicated) | **`-83.6%` DB backend slots** |
| **Hermes3D + 2D Pixel Office Directory** | `859,565,444 B` (`819.75 MiB`, `39,794` files) | **`8,281,358 B` (`7.90 MiB`, `656` files)** | **`-99.04%` bytes / `-98.35%` files** |
| **Agent Python Runtime Architecture** | Duplicated portable Python + NPM wrappers (`2.11+ GiB`) | **`1` shared container & `1` Python 3.14 venv** + `< 8 KB` CLI shim | **`0 B` duplicate virtualenvs** |
| **Active Agent Roster Overhead** | All processes/launchers unmanaged across `25` OS processes | **`4` Wave-1 warm profiles** (`ceo`, `backend`, `qa`, `security-reviewer`) + `7` Wave-2 standby | **`-63.6%` idle agent footprint** |
| **VulnClaw Security Worker Idle RSS** | Full red-team ML/browser extras (`> 2.5 GiB` disk, `> 95 MiB` RSS) | **`21.02 MiB` measured idle RSS** (`0` background LLM loops) | **`~78%` lower idle RAM** + 100% post-scan reclamation |
| **Total Production Stack Memory Ceiling** | Unbounded host processes (`~1,389.2 MB` working set + embedded PG) | **`<= 1,536 MiB` hard cgroup v2 ceiling** (`~415 MiB` idle RSS) | **`0` swap storms** (`memswap_limit == mem_limit`) |

---

## 2. Source Footprint Reduction (`10.36 GiB` $\rightarrow$ `< 15 MiB`)

Phase 01 empirical storage auditing across `<LEGACY_WINDOWS_WORKSPACE>` measured **`11,126,312,521` bytes (`10.36 GiB`)** across **`461,174` files** and `2,017` filesystem links:

- **`4.59 GiB` (`44.34%`) — Host-Specific Binary Toolchains:** Bundled Chromium browsers, portable Python/Node binaries, `ffmpeg`, duplicate Git distributions, and OS-specific desktop drivers.
- **`1.80 GiB` — Nested Vendor CLI Bloat:** Unused `@anthropic-ai/claude-code*`, `@anthropic-ai/claude-agent-sdk*`, `@openai/codex*`, `@github/copilot*`, `opencode-*`, and `@embedded-postgres/*` binaries inside Paperclip transitive dependencies.
- **`1.46 GiB` — Exact SHA-256 Content Duplicates:** Repeated `models_dev_cache.json` snapshots, duplicated per-profile language-server `node_modules`, and redundant staging copies.
- **Architectural Resolution:** By locking core upstreams to immutable 40-character commit SHAs in [`components.lock.json`](./components.lock.json), expressing customizations as minimal unified diffs in [`patches/`](./patches/), and fetching SHA-256-verified skills into host volumes at setup time, the clean `ALLINAGENT` Git repository achieves a **`> 99.8%` size reduction (`< 15 MiB`)** with zero functional loss.

---

## 3. Subsystem Optimization Breakdowns

### 3.1 Paperclip `node_modules` Prune (`-81.70%`) & Connection Pool Cap (`73` $\rightarrow$ `12`)

1. **Deterministic Post-Install Bloat Pruner (`components/paperclip/prune-paperclip-bloat.mjs`):**
   - Strips `1,648.48 MiB` of unused proprietary/third-party agent CLIs, `134.26 MiB` of foreign-OS/duplicate `paperclip-runnerd` binaries, `104.02 MiB` of `@embedded-postgres/*` binaries (in Docker mode where `postgres:16-alpine` is used), `40.36 MiB` of foreign-architecture native addons, and `146.01 MiB` of `.map` / `__tests__` artifacts.
   - Shrinks `node_modules` from **`2,537.49 MiB` to `464.36 MiB` (`-81.70%`)** while verifying all `11` required server, UI, database migration, and Hermes adapter entrypoints remain intact.
2. **Low-Memory PostgreSQL Pool Patch (`patches/paperclip/0004-db-low-memory-connection-pool.patch`):**
   - Caps the main worker pool at `5` (`idle_timeout = 20s`), trims `liveness`, `checkpoint`, and `fileStorage` private pools to `1` connection each, retains `2` `LISTEN/NOTIFY` channels, and bounds `withDedicatedDbConnection` with a re-entrant `AsyncLocalStorage` semaphore (`limit = 2`).
   - Reduces per-server PostgreSQL connection demand from **`73` down to `12` steady connections**, fitting comfortably inside tuned `postgres:16-alpine` (`max_connections = 35–40`, `shared_buffers = 48MB`, `jit = off`).

### 3.2 Hermes3D + 2D Pixel Office Optimization (`819.75 MiB` $\rightarrow$ `7.90 MiB`)

- **99.04% Source Staging Reduction:** Stripped `765.41 MiB` of `node_modules`, `38.20 MiB` of `.next` caches (including `165` browser `.map` files totaling `26.78 MiB`), `7.77 MiB` of nested `.git` objects, and `68.10 KiB` of non-OSI `vendor/multiavatar.js`, leaving **`7.90 MiB` (`8,281,358 B` across `656` files)**.
- **Zero Server GPU & Offline Build Resilience:**
  - 100% of `Three.js` WebGL 3D rendering and `Phaser` 2D Canvas animation runs on the **client browser GPU** (`0%` server GPU utilization).
  - Replaced `next/font/google` (`26` build-time `.woff2` HTTPS downloads) with offline-safe CSS custom property font stacks and Next.js `output: "standalone"` (`productionBrowserSourceMaps: false`), cutting container runtime RSS to `65–125 MiB`.

### 3.3 Shared Hermes Runtime, Wave-1 Warm Profiles & `HEAVY_WORKER_CONCURRENCY=1`

- **Single Shared Container (`allinagent-hermes`):** Consolidates `NousResearch/hermes-agent` (`v0.23.3`, stripped of `apps/desktop`, `website`, `tests`, `evals`, `nix` to `< 75 MiB`) and **one** shared Python 3.14 `uv` virtual environment across all 11 isolated `pc*` profiles — avoiding `11 x ~150 MiB` (`> 1.6 GiB`) of separate Python containers.
- **Zero-Python Remote CLI Shim (`/usr/local/bin/hermes`):** `paperclip` and `office-bridge` invoke a `< 8 KB` Node stdlib shim (`components/hermes/hermes-cli-shim.mjs`) that streams NDJSON over `http://hermes:8650`, saving **`> 1.5 GiB` of image layers** and **`> 400 MiB` RAM**.
- **Wave-1 Warm Profiles (`4`) + Wave-2 Standby (`7`):** Only **`ceo`** (`pcceoagent`), **`backend`** (`pcbackenddeveloper`), **`qa`** (`pcqaengineer`), and **`security-reviewer`** (`pcsecurityreviewer`) run warm in `Wave-1 ACTIVE`; the remaining 7 specialist profiles stay in zero-overhead `Wave-2 STANDBY` until woken by task delegation or direct `@agent` mention.
- **Priority Worker Serialization (`HEAVY_WORKER_CONCURRENCY=1`):** `hermes_exec_daemon.py` serializes heavy LLM/engineering subtasks through a bounded semaphore (with Priority 0 interactive owner turns and a `< 1s` fast-lane bypass for `hermes --version` health probes), preventing 2-vCPU saturation and memory spikes during multi-agent delegations.

### 3.4 VulnClaw On-Demand Defensive Worker (`21.02 MiB` Idle RSS)

- Replaces `> 2.5 GiB` of optional ML/reranker/browser packages (`torch`, `chromadb`, `sentence-transformers`, `playwright`, `mitmproxy`) with a 9-package pure-Python defensive manifest (`requirements-defensive.txt`).
- Runs a pure-stdlib `asyncio` parent HTTP/1.1 daemon (`components/vulnclaw/vulnclaw_worker.py`) measuring **`21.02 MiB` idle RSS** (`21.02–21.23 MiB` across benchmarks, `< 25 MiB` budget) with **zero background LLM loops**.
- Spawns an isolated `python -B` child subprocess for each `L1`/`L2` static code scan (`max_files = 250`, `max_file_bytes = 1 MiB`, `timeout = 60s`) that exits immediately upon completion, returning **100% of AST and scan buffers to the Linux kernel**.

---

## 4. Production Cgroup v2 Memory Budget (`<= 1,536 MiB` Ceiling)

Every container in [`compose.production.yaml`](./compose.production.yaml) enforces `memswap_limit == mem_limit` (`0 MiB` container swap allowance), `MALLOC_ARENA_MAX=2` (preventing glibc multi-arena virtual memory fragmentation), explicit V8 `--max-old-space-size` caps, and bounded `pids_limit`:

### 4.1 Canonical `1,536 MiB` 6-Service Production Cgroup Budget (`compose.production.yaml` & `config/resource-limits.json`)

| Service | Container Name | Hard `mem_limit` (`memswap_limit`) | Steady-State RSS | CPU Quota (`cpus`) | `pids_limit` | Key Allocator & Runtime Controls |
| :--- | :--- | ---: | ---: | :---: | :---: | :--- |
| `postgres` | `allinagent-postgres` | **`224m`** (`224m`) | `55 – 115 MiB` | `0.45` | `128` | `postgres:16-alpine`, `shared_buffers=48MB`, `work_mem=2MB`, `jit=off` |
| `paperclip` | `allinagent-paperclip` | **`416m`** (`416m`) | `145 – 255 MiB` | `0.75` | `192` | `NODE_OPTIONS="--max-old-space-size=300"`, pruned `node_modules` (`464 MiB`), `DB_POOL_MAX=5` (`12` max conns), CLI shim |
| `hermes` | `allinagent-hermes` | **`384m`** (`384m`) | `95 – 320 MiB` | `0.85` | `192` | `1` shared Py3.14 venv, `HEAVY_WORKER_CONCURRENCY=1`, `PYTHONMALLOC=malloc` |
| `office-bridge` | `allinagent-office-bridge` | **`160m`** (`160m`) | `55 – 95 MiB` | `0.40` | `128` | `NODE_OPTIONS="--max-old-space-size=112"`, 500-event ring buffer, CLI shim |
| `office` | `allinagent-office` | **`224m`** (`224m`) | `65 – 125 MiB` | `0.50` | `128` | Next.js `standalone`, `NODE_OPTIONS="--max-old-space-size=128"`, 100% browser WebGL/Canvas |
| **Core 5 Subtotal** | **5 Core Containers** | **`1,408 MiB`** | `~395 – 910 MiB` | *Shared 2 vCPU* | `768` | `224 + 416 + 384 + 160 + 224 = 1,408 MiB` |
| `vulnclaw` | `allinagent-vulnclaw` | **`128m`** (`128m`) | `21.02 MiB` *(idle)* | `0.50` | `64` | Air-gapped `allinagent_data` (`internal: true`), pure-stdlib daemon + ephemeral child scan subprocess (`:ro` workspace) |
| **TOTAL STACK** | **6 Containers** | **`1,536 MiB` (`1.50 GiB`)** | **`~415 MiB` idle / `<= 1,070 MiB` active** | `<= 0.85`/ctr | **`832`** | **Preserves `>= 1,850 MiB` untouched host RAM headroom on 8 GB VPS** |

*(Note: In `compose.production.yaml` and `config/resource-limits.json`, the 5 core containers sum to `224 + 416 + 384 + 160 + 224 = 1,408 MiB` plus `vulnclaw` `128 MiB` = **`1,536 MiB` (`1.50 GiB`) hard cgroup ceiling**, while `HEAVY_WORKER_CONCURRENCY=1` serializes heavy Hermes worker runs and defensive static scans.)*

---

## 5. Low-RAM Build Guard & Log/Backup Disk Caps

1. **Sequential Low-RAM BuildKit Guard (`scripts/allinagent_cli.py`):**
   - Production deployments pull prebuilt images from GHCR (`pull_policy: missing`), consuming near-zero build CPU/RAM on the VPS.
   - When `--build` is invoked on a host with `<= 9,000 MiB` RAM, `./allinagent` automatically builds images sequentially one at a time with `docker buildx build --load --memory=1280m --cpus=1.0`, preventing `next build` / `tsc` OOM spikes.
2. **Bounded Logs & Backups:**
   - Docker `json-file` rotation (`max-size: "10m"`, `max-file: "3"`) caps combined container logs across all 6 services at **`<= 180 MiB`**.
   - Automated pre-update `pg_dump` snapshots (`data/backups/paperclip-pre-update-*.sql.gz`) retain only the **7 most recent** archives.

---

## 6. Reproducing Benchmarks & Live Telemetry

```bash
# 1. Inspect live container RSS, cgroup limits, and CPU percentages
docker stats --no-stream \
  allinagent-postgres allinagent-paperclip allinagent-hermes \
  allinagent-office-bridge allinagent-office allinagent-vulnclaw

# 2. Verify Paperclip bloat pruning metrics in dry-run JSON mode
node components/paperclip/prune-paperclip-bloat.mjs --dry-run --json

# 3. Run VulnClaw standalone idle RSS & post-scan memory reclamation self-test
python3 components/vulnclaw/vulnclaw_worker.py self-test

# 4. Probe service health latencies (< 2,500 ms SLA) & cgroup budget compliance
python3 tests/e2e/run_live_acceptance.py --live --groups G
```
