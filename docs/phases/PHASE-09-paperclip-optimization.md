# PHASE 09 — Paperclip Production Optimization & Deterministic Patch Layer

- **Phase ID:** `PHASE-09`
- **Status:** `PASS` (`100%` Verified — Syntax, Patch Convergence, Idempotency, Bloat Pruning, & Low-Memory DB Budget)
- **Pinned Upstream Package:** `paperclipai@2026.1117.0` (`MIT`, Node `>=24.11.0`)
- **Target Production Profile:** Shared `2 vCPU / 8 GB RAM` Linux VPS (`Docker Compose` + `postgres:16-alpine`) and Cross-Platform Host Mode

---

## 1. Executive Summary & Empirical Results

| Optimization Dimension | Unoptimized Baseline (`paperclipai@2026.1117.0`) | Optimized `ALLINAGENT` Production Build | Net Improvement |
| :--- | ---: | ---: | ---: |
| **`node_modules` Footprint (Docker `linux-x64`, `PRUNE_EMBEDDED_POSTGRES=1`)** | `2,660,753,330 B` (`2,537.49 MiB` / **`2.48 GiB`**, `76,082` files) | `486,915,970 B` (`464.36 MiB` / **`0.45 GiB`**, `52,598` files) | **`-2,073.13 MiB` (`-81.70%`)** |
| **`node_modules` Footprint (Native Host Mode, `PRUNE_EMBEDDED_POSTGRES=0`)** | `2,660,753,330 B` (`2,537.49 MiB` / **`2.48 GiB`**, `76,082` files) | `598,998,043 B` (`571.26 MiB` / **`0.56 GiB`**) | **`-1,966.23 MiB` (`-77.49%`)** |
| **Proprietary / Unused Third-Party Agent Binaries in Runtime** | `1,648.48 MiB` (`@anthropic-ai/claude-agent-sdk*`, `@github/copilot*`, `@openai/codex*`, `opencode-*`) | **`0 B`** (100% removed across top-level & nested `node_modules` + `provider-assets`) | **100% License & Binary Sanitization** |
| **PostgreSQL Connection Ceiling per Paperclip Server** | **`73` connections** (`10` main + `9` private + `2` listeners + `52` / unbounded dedicated) | **`12` connections** (`5` main + `3` private + `2` listeners + `2` bounded dedicated; `<= 12–15` peak) | **`-83.6%` backend slots** (fits `max_connections = 35`) |
| **PostgreSQL Container Shared Memory (`postgresql-lowmem.conf`)** | Untuned defaults / `430.5 MB` embedded cluster | `shared_buffers = 128MB`, `work_mem = 4MB`, `max_worker_processes = 2`, `max_parallel_workers_per_gather = 0` | Fits strictly inside **`256 MiB` cgroup cap** |
| **Large Prompt Tempfile Hygiene (`execute.js`)** | Risk of `%TEMP%` / `/tmp` prompt file leak on early throw or `unlink` miss | `0o600` tempfile creation inside `try` + `fs.rm(tempQueryFile, { force: true })` in `finally` | **`0` leaked prompt files** |

---

## 2. Deliverable Inventory

### 2.1 Runtime Wrapper & Launcher (`components/paperclip/`)

| File | Role & Production Guarantees |
| :--- | :--- |
| `components/paperclip/package.json` | Minimal MIT wrapper pinning exact `"paperclipai": "2026.1117.0"` with `"engines": { "node": ">=24.11.0" }` and automated `postinstall` (`apply-paperclip-patches.mjs` $\rightarrow$ `prune-paperclip-bloat.mjs`). |
| `components/paperclip/prune-paperclip-bloat.mjs` | Recursive post-install production optimizer and license sanitizer supporting `--dry-run`, `--prune-embedded-postgres` / `PRUNE_EMBEDDED_POSTGRES=1`, `--target-platform`, `--target-arch`, and `--json`, followed by an 11-path core runtime integrity gate. |
| `components/paperclip/apply-paperclip-patches.mjs` | Idempotent, marker-verified runtime patcher (`--dry-run`, `--verify-only`, `--json`) applying all 4 production patches and SHA-256 verifying convergence on repeat runs. |
| `components/paperclip/paperclip-server-entry.mjs` | Cross-platform production entrypoint setting `SERVE_UI=true`, `PAPERCLIP_UI_DEV_MIDDLEWARE=false`, `PAPERCLIP_MIGRATION_AUTO_APPLY=true`, `PAPERCLIP_MIGRATION_PROMPT=never`, `PAPERCLIP_TELEMETRY_DISABLED=1`, `DO_NOT_TRACK=1`, `PAPERCLIP_LOW_MEMORY=1`, `PAPERCLIP_DB_POOL_MAX=5`, resolving `DATABASE_URL` & `PORT`, executing `process.chdir(...)`, calling `await mod.startServer()`, and handling `SIGTERM`/`SIGINT` with bounded timeout protection. |
| `components/paperclip/postgresql-lowmem.conf` | Tuned PostgreSQL 16 configuration for `2 vCPU / 8 GB` VPS deployments (`max_connections = 35`, `shared_buffers = 128MB`, `effective_cache_size = 384MB`, `work_mem = 4MB`, `maintenance_work_mem = 32MB`, `max_worker_processes = 2`, `max_parallel_workers_per_gather = 0`). |

### 2.2 Declarative Reference Diffs (`patches/paperclip/`)

All four patches are stored as standard unified diffs (`git apply --check` verified) alongside `patches/paperclip/patch-manifest.json`:

| Patch File | Target Module (`paperclipai@2026.1117.0`) | Patched SHA-256 | Summary |
| :--- | :--- | :--- | :--- |
| `0001-hermes-adapter-query-file-cleanup.patch` | `@paperclipai/hermes-paperclip-adapter/dist/server/execute.js` | `af0733237e66f6d04b010dd629da2d8034c87de38ef9b4f0198148f5e80dbb6a` | Uses `--query-file` (`mode: 0o600`) when `process.platform === "win32" \|\| prompt.length > 6000` and guarantees cleanup via `await fs.rm(tempQueryFile, { force: true }).catch(() => {})` inside `finally {}`. |
| `0002-hermes-adapter-skills-reconcile.patch` | `@paperclipai/hermes-paperclip-adapter/dist/server/skills.js` | `f07e4977cea6e56aba726c59134e11cabd26f3bf0ed46e85605298007194a1fb` | Preserves `skill-registry` and `--` namespaced role skill symlinks/junctions (`PHASE-13`/`PHASE-14`), enables symlinked directory discovery in `scanHermesSkills`, normalizes Windows `\\?\` link prefixes, and falls back to `materializePaperclipSkillCopy` on `EPERM`/`ENOSYS`/`EXDEV`. |
| `0003-hermes-gateway-internal-hosts.patch` | `@paperclipai/hermes-paperclip-adapter/dist/gateway/server/transport-security.js` | `2d76673df589aefa19f8390c5dd80a779eee0d3d3683fcb7bd24427826247dcf` | Parses `process.env.HERMES_GATEWAY_INTERNAL_HOSTS` (e.g., `hermes,allinagent-hermes,hermes-gateway`) so trusted internal Docker Compose service hostnames pass `isLoopbackHostname` / `!isRemotePlainHttp` without enabling unsafe global remote HTTP. |
| `0004-db-low-memory-connection-pool.patch` | `@paperclipai/db/dist/client.js` | `04a474937da6d67e96a59eae66184d8b8e33d5d3bdb6d593362bf4c0e3a83b55` | Exports `DEFAULT_MAIN_POOL_CONNECTIONS` (`Number(process.env.PAPERCLIP_DB_POOL_MAX \|\| 5)`), trims private sub-pools (`liveness`, `checkpoint`, `fileStorage`) to `1` each when `PAPERCLIP_LOW_MEMORY=1`, lowers idle timeout to `20s`, and bounds `withDedicatedDbConnection` with an `AsyncLocalStorage` re-entrant semaphore (`limit = 2` in low-memory mode). |

---

## 3. Detailed Bloat & License Pruning Breakdown (`prune-paperclip-bloat.mjs`)

Empirical dry-run measurement across the full `paperclipai@2026.1117.0` `node_modules` installation (`2,537.49 MiB` / `2.48 GiB`, `76,082` files):

| Category | Reclaimed Size | Files Removed | Sample Packages / Paths Removed |
| :--- | ---: | ---: | :--- |
| **1. Proprietary & Unused Agent CLIs / SDKs** | **`1,648.48 MiB`** (`1,728,558,617 B`) | `150` | `@anthropic-ai/claude-code*`, `@anthropic-ai/claude-agent-sdk*` (top-level + nested inside `@paperclipai/server/node_modules` — non-OSI `"SEE LICENSE IN README.md"`), `@github/copilot*` + `@paperclipai/server/provider-assets/copilot`, `@openai/codex*` (top-level + nested), `opencode-*` |
| **2. Foreign & Duplicate `paperclip-runnerd` Binaries** | **`134.26 MiB`** (`140,784,216 B`) | `4` | `darwin-arm64/paperclip-runnerd` (`29.63 MiB`), `darwin-x64/paperclip-runnerd` (`32.46 MiB`), `linux-arm64/paperclip-runnerd` (`34.52 MiB`), plus redundant duplicate `bin/paperclip-runnerd` (`37.65 MiB`) when `bin/linux-x64/paperclip-runnerd` (`37.48 MiB`) is present |
| **3. Embedded PostgreSQL Binaries (`PRUNE_EMBEDDED_POSTGRES=1`)** | **`104.02 MiB`** (`109,068,400 B`) | `1,502` | `@embedded-postgres/*` (omitted in Docker where `postgres:16-alpine` is used; retained on native host mode when `PRUNE_EMBEDDED_POSTGRES=0`) |
| **4. Foreign-OS/Arch Native Optional Packages** | **`40.36 MiB`** (`42,322,073 B`) | `22` | Non-target `@esbuild/*`, `@img/sharp-*`, `@cursor/sdk-*` binaries |
| **5. Compiled Unit Tests & Source Maps** | **`146.01 MiB`** (`153,104,054 B`) | `21,806` | `*.test.js`, `__tests__/`, `__fixtures__/`, `*.js.map`, `*.d.ts.map` (strictly skipping `ui-dist`, `skills`, `skills-catalog`, and `migrations`) |
| **TOTAL RECLAIMED (Docker Mode)** | **`2,073.13 MiB`** (`2,173,837,360 B`) | **`23,484`** | **`2.48 GiB` $\rightarrow$ `0.45 GiB` (`-81.70%` reduction)** |

**Protected Core Runtime Integrity Check (`11 / 11` Verified Intact After Prune):**
- `@paperclipai/server` (`package.json`, `dist/index.js`, and `ui-dist/index.html`)
- `@paperclipai/db` (`package.json`, `dist/client.js`, and `dist/migrations`)
- `@paperclipai/skills-catalog` (`package.json`, `catalog/`, `dist/`)
- `@paperclipai/hermes-paperclip-adapter` (`package.json`, `dist/server/execute.js`, `dist/server/skills.js`, `dist/gateway/server/transport-security.js`)
- `@anthropic-ai/sdk` (MIT client library preserved)

---

## 4. PostgreSQL Connection & Memory Budget (`PAPERCLIP_LOW_MEMORY=1`)

### 4.1 Per-Process Connection Accounting (`@paperclipai/db/dist/client.js`)

| Pool / Client Group | Unpatched Default | Patched (`PAPERCLIP_LOW_MEMORY=1`) | Notes |
| :--- | ---: | ---: | :--- |
| **Main Request/Worker Pool** | `10` | **`5`** | Controlled via `PAPERCLIP_DB_POOL_MAX` / `DATABASE_POOL_MAX` (`idle_timeout = 20s`) |
| **Controller Liveness Pool** | `2` | **`1`** | `paperclip-controller-lease` |
| **Runner Checkpoint Pool** | `3` | **`1`** | `paperclip-runner-checkpoint` |
| **File Storage Pool** | `2` | **`1`** | `paperclip-file-storage` |
| **Owned `LISTEN/NOTIFY` Clients** | `2` | **`2`** | `work-signals` + `plugin-lifecycle-delivery` |
| **Dedicated Advisory-Lock Pool** | `52` *(or unbounded in `2026.1117.0`)* | **`2`** | Bounded by `AsyncLocalStorage` re-entrant semaphore (`PAPERCLIP_DEDICATED_POOL_MAX`) |
| **Steady Maximum Total** | **`73`** *(or unbounded)* | **`12`** *(peak `<= 14` with transient migration/backup utility connection)* | Leaves `> 20` free slots under `max_connections = 35` |

### 4.2 Production PostgreSQL 16 Tuning (`postgresql-lowmem.conf`)

- `max_connections = 35` (`superuser_reserved_connections = 3`)
- `shared_buffers = 128MB`
- `effective_cache_size = 384MB`
- `work_mem = 4MB`
- `maintenance_work_mem = 32MB`
- `max_worker_processes = 2`
- `max_parallel_workers_per_gather = 0` (`max_parallel_workers = 0`, `max_parallel_maintenance_workers = 0`)
- `wal_buffers = 4MB`, `min_wal_size = 32MB`, `max_wal_size = 256MB`, `huge_pages = off`

---

## 5. Verification & Acceptance Evidence

1. **Syntax Validation (`node --check`):**
   - `node --check components/paperclip/apply-paperclip-patches.mjs` $\rightarrow$ **`PASS`**
   - `node --check components/paperclip/prune-paperclip-bloat.mjs` $\rightarrow$ **`PASS`**
   - `node --check components/paperclip/paperclip-server-entry.mjs` $\rightarrow$ **`PASS`**
   - `node --check` on all patched target `.js` files (`execute.js`, `skills.js`, `transport-security.js`, `client.js`, `index.js`) $\rightarrow$ **`PASS`**
2. **Patch Dry-Run, Convergence & Idempotency:**
   - Tested against isolated scratch copies of both pristine `paperclipai@2026.1117.0` modules and previously live-patched runtime modules (`0` modifications to any external directory).
   - Both inputs converged to identical SHA-256 hashes across all patched files; a second execution returned `already_patched` with `0` byte changes; `--verify-only` confirmed all 4 markers.
   - `git apply --check` succeeded cleanly on all 4 unified `.patch` files in `patches/paperclip/`.
3. **Behavioral Runtime Unit Tests:**
   - `transport-security.js`: Verified `HERMES_GATEWAY_INTERNAL_HOSTS="hermes, allinagent-hermes, hermes-gateway"` permits `http://hermes:8642/api` and `http://allinagent-hermes:8642/api` while rejecting untrusted external HTTP hosts (`http://untrusted.example.com:8642/api`) and failing closed when unset.
   - `client.js`: Verified `DEFAULT_MAIN_POOL_CONNECTIONS === 5`, `idleTimeoutSeconds === 20`, private pool `max === 1` (`liveness`, `checkpoint`, `fileStorage`), `databaseConnectionBudget().total === 12`, and `8` concurrent + nested `withDedicatedDbConnection` calls respected `peakNonNested <= 2` with `0` deadlocks.
   - `paperclip-server-entry.mjs`: Verified end-to-end startup with mock `@paperclipai/server` (`SERVE_UI=true`, `PAPERCLIP_UI_DEV_MIDDLEWARE=false`, `PAPERCLIP_MIGRATION_AUTO_APPLY=true`, `PAPERCLIP_MIGRATION_PROMPT=never`, `PAPERCLIP_TELEMETRY_DISABLED=1`, `DATABASE_URL` synthesis, `process.chdir`, `await mod.startServer()`, graceful `SIGTERM` shutdown exiting `0`, and zero credential logging).
