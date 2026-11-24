# ALLINAGENT — Docker & Container Architecture Guide

**ALLINAGENT** packages its entire autonomous software company into a hardened, multi-stage **Docker Compose v2** stack ([compose.yaml](./compose.yaml) + [compose.production.yaml](./compose.production.yaml)) engineered to run comfortably inside a **1,536 MiB (`1.50 GiB`)** steady cgroup ceiling on a **2 vCPU / 8 GB RAM** Linux host.

---

## 1. Container Topology & Service Matrix

All custom images are defined under [deploy/docker/](./deploy/docker/), run under `tini` as PID 1, drop privilege escalation (`no-new-privileges:true`), and execute as **non-root users** (`0` containers run application code as `root`, and `/var/run/docker.sock` is **never** mounted).

| Compose Service | Container Name | Dockerfile / Base Image | Runtime User (`UID:GID`) | Internal Port | Host Loopback Port | Networks | Role |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- | :--- |
| `postgres` | `allinagent-postgres` | Official `postgres:16-alpine` + `postgresql-lowmem.conf` | `postgres` (`70:70`) | `5432` | *None (internal)* | `allinagent_data` | Tuned PostgreSQL 16 control-plane database (`jit=off`, `shared_buffers=48MB`) |
| `vulnclaw` | `allinagent-vulnclaw` | `deploy/docker/vulnclaw.Dockerfile` (`python:3.12-slim-bookworm`) | `vulnclaw` (`10002:10002`, `nologin`) | `8660` | *None (internal)* | `allinagent_data` | Read-only (`read_only: true`, `cap_drop: ALL`), zero-secret defensive static code analyzer |
| `hermes` | `allinagent-hermes` | `deploy/docker/hermes.Dockerfile` (`debian:bookworm-slim` + `uv` Py3.14) | `allinagent` (`10001:10001`) | `8650` | *None (internal)* | `allinagent_edge`, `allinagent_data` | Single shared Hermes `v0.23.3` runtime, `hermes-exec` broker, 11 `pc*` profiles & single Telegram poller |
| `paperclip` | `allinagent-paperclip` | `deploy/docker/paperclip.Dockerfile` (`node:24-bookworm-slim`) | `node` (`1000:1000`) | `3100` | `127.0.0.1:8201` | `allinagent_edge`, `allinagent_data` | Paperclip `2026.1117.0` control plane + patched Hermes adapter + `/usr/local/bin/hermes` CLI shim |
| `office-bridge` | `allinagent-office-bridge` | `deploy/docker/office-bridge.Dockerfile` (`node:24-bookworm-slim`) | `node` (`1000:1000`) | `3210` | `127.0.0.1:8202` | `allinagent_edge`, `allinagent_data` | Normalized Event Bus v1.0, Gateway Protocol v3, 59-cmd CODEXE suite & `/usr/local/bin/hermes` shim |
| `office` | `allinagent-office` | `deploy/docker/office.Dockerfile` (`node:24-bookworm-slim`) | `node` (`1000:1000`) | `3200` | `127.0.0.1:8200` | `allinagent_edge` | Next.js production Virtual Office (`3D WebGL` + `2D Pixel`) + `server/index.js` Access Gate & WS proxy |

---

## 2. Two-Tier Network Isolation (`192.168.240.0/23`)

Many multi-tenant servers already allocate `172.17.0.0/16`, `172.18.0.0/16`, and `172.20.0.0/16` to existing Docker stacks. ALLINAGENT isolates its traffic inside two dedicated RFC1918 `/24` subnets:

1. **`allinagent_edge` (`192.168.240.0/24`, `internal: false`):**
   - Attaches `office`, `office-bridge`, `paperclip`, and `hermes`.
   - Allows loopback host ingress (`127.0.0.1:8200–8202`) and outbound HTTPS (`:443`) for LLM inference APIs and `api.telegram.org`.
2. **`allinagent_data` (`192.168.241.0/24`, `internal: true`):**
   - Air-gapped internal bridge with **zero internet egress** and **zero host port bindings**.
   - Isolates `postgres` (`:5432`) and `vulnclaw` (`:8660`) completely from external networks.

---

## 3. Production Cgroup v2 Resource Budget (`compose.production.yaml`)

When invoked with `./allinagent --production up` (or automatically under `/opt/allinagent`), `compose.production.yaml` enforces strict memory, swap, CPU, and PID caps:

| Service | `mem_reservation` | `mem_limit` | `memswap_limit` | `cpus` | `pids_limit` | Runtime Heap / Allocator Tuning |
| :--- | ---: | ---: | ---: | ---: | ---: | :--- |
| `postgres` | `96m` | **`224m`** | `224m` | `0.45` | `128` | `shared_buffers=48MB`, `work_mem=2MB`, `jit=off`, `max_connections=40` |
| `paperclip` | `160m` | **`416m`** | `416m` | `0.75` | `192` | `NODE_OPTIONS="--max-old-space-size=300"`, `MALLOC_ARENA_MAX=2` |
| `hermes` | `128m` | **`384m`** | `384m` | `0.85` | `192` | `HEAVY_WORKER_CONCURRENCY=1`, `PYTHONMALLOC=malloc`, `MALLOC_ARENA_MAX=2` |
| `office-bridge` | `64m` | **`160m`** | `160m` | `0.40` | `128` | `NODE_OPTIONS="--max-old-space-size=112"`, `MALLOC_ARENA_MAX=2` |
| `office` | `80m` | **`224m`** | `224m` | `0.50` | `128` | `NODE_OPTIONS="--max-old-space-size=128"`, `MALLOC_ARENA_MAX=2` |
| `vulnclaw` | `32m` | **`128m`** | `128m` | `0.50` | `64` | Ephemeral scan subprocesses; `~21 MiB` idle RSS; `read_only: true` |

- **Core 5 Services `mem_limit` Sum:** `224 + 416 + 384 + 160 + 224 = 1,408 MiB`
- **With `vulnclaw` `mem_limit` (`128 MiB`):** `1,408 + 128 =` **`1,536 MiB` (`1.50 GiB`) hard total cgroup ceiling**
- **Zero Swap Thrashing:** Setting `memswap_limit == mem_limit` guarantees containers stay in physical RAM instead of degrading neighboring host services via swap I/O.

---

## 4. Zero-Duplication Shared Runtime & Remote CLI Shim

Instead of installing Python 3.14, `hermes-agent`, and document libraries separately inside `paperclip`, `office-bridge`, and `hermes` (which would add `> 1.5 GB` of duplicate image layers and `> 400 MiB` RAM):

1. **`allinagent-hermes`** owns the **single** CPython 3.14 `uv` virtual environment (`/opt/hermes-venv`), the pinned `hermes-agent` runtime (`eb49b8920a25ffa7bb2fadf548fe819221ca79d7` + `0001-error-classifier-integrator.patch`), permissive PDF/DOCX libraries (`pypdf`, `pdfplumber`, `reportlab`, `python-docx` — verified free of `pymupdf`/`marker-pdf` copyleft packages at build time), and `hermes_exec_daemon.py` on `:8650`.
2. **`allinagent-paperclip`** and **`allinagent-office-bridge`** install only a lightweight Node.js CLI shim at `/usr/local/bin/hermes` (`components/hermes/hermes-cli-shim.mjs`).
3. Whenever Paperclip or Office Bridge invokes `hermes chat --profile pc* --query-file <path>`, the shim authenticates via `HERMES_EXEC_SHARED_SECRET` to `http://hermes:8650`, streams NDJSON `stdout`/`stderr` in real time, enforces `HEAVY_WORKER_CONCURRENCY=1`, and forwards `SIGTERM`/`SIGINT` cancellations cleanly.

---

## 5. Building, Pulling & Inspecting Images

### Pull Prebuilt GHCR Images (Default)

```bash
./allinagent --production setup
# Underlying Compose command:
docker compose --env-file .env -f compose.yaml -f compose.production.yaml pull
```

Image coordinates are controlled via `.env`:
- `ALLINAGENT_REGISTRY` (default: `ghcr.io`)
- `ALLINAGENT_IMAGE_NAMESPACE` (default: `allinagent`, or your GitHub organization/namespace)
- `ALLINAGENT_VERSION` (default: `1.0.0`, or `latest`)

### Build Multi-Stage Images Locally

```bash
# Recommended: uses RAM-capped sequential buildx on <= 8 GB hosts
./allinagent --production setup --build

# Rebuild a single service manually
docker compose --env-file .env -f compose.yaml -f compose.production.yaml build office-bridge
```

Optional build arguments:
- `deploy/docker/office-bridge.Dockerfile`: pass `--build-arg INSTALL_CHROMIUM=true` if you want in-container headless Chromium installed inside `office-bridge` (omitted by default to keep the image compact).
- `deploy/docker/hermes.Dockerfile`: `ARG HERMES_UPSTREAM_SHA=eb49b8920a25ffa7bb2fadf548fe819221ca79d7`
- `deploy/docker/paperclip.Dockerfile`: `ARG PAPERCLIP_VERSION=2026.1117.0`
- `deploy/docker/vulnclaw.Dockerfile`: `ARG VULNCLAW_UPSTREAM_SHA=0b34878f84b089b21fcf85ecd445315f14df0672`

### Build Context Hygiene (`.dockerignore`)

[.dockerignore](./.dockerignore) strictly excludes `.git/`, `node_modules/`, `.venv/`, `.next/`, `.env`, `.env.*` (except `*.example`), `config/secrets/`, `data/`, `office-data/`, `*.db`, `*.pem`, and user workspaces (keeping only `workspaces/README.md` and `workspaces/sample-project/**`), ensuring secrets can **never** enter Docker image layers.

---

## 6. Container Healthchecks & Debugging Commands

Every container defines a native Docker `HEALTHCHECK`:

```bash
# View container states and health status
./allinagent status

# Probe all 6 internal + loopback endpoints
./allinagent health --json

# Tail logs for specific containers
./allinagent logs -f hermes paperclip office-bridge

# Inspect live cgroup memory & CPU utilization
docker stats --no-stream allinagent-postgres allinagent-vulnclaw allinagent-hermes allinagent-paperclip allinagent-office-bridge allinagent-office

# Verify VulnClaw read-only rootfs and zero-secret environment
docker compose -f compose.yaml -f compose.production.yaml exec -T vulnclaw env
```
