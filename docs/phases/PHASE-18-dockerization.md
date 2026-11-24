# PHASE 18 — Multi-Stage Production Dockerization

- **Phase ID:** `PHASE-18`
- **Status:** `PASS`
- **Scope:** `deploy/docker/*.Dockerfile`, `compose.yaml`, `compose.production.yaml`

---

## 1. Architecture & Container Topology

`ALLINAGENT` runs as an isolated 6-container stack inside the dedicated Compose namespace `allinagent`, partitioned across two custom Docker bridge networks (`192.168.240.0/24` and `192.168.241.0/24`) to prevent subnet collisions with default `172.17.0.0/16`–`172.20.0.0/16` bridges:

| Service | Dockerfile / Image | Runtime Base | Non-Root User (`UID:GID`) | Internal Port | Host Loopback Port | Attached Networks |
| :--- | :--- | :--- | :--- | :---: | :---: | :--- |
| `postgres` | `postgres:16-alpine` | Alpine Linux | `postgres` (`70:70`) | `5432` | **None (`0`)** | `allinagent_data` (`internal: true`) |
| `hermes` | `deploy/docker/hermes.Dockerfile` | `debian:bookworm-slim` + CPython `3.14` | `allinagent` (`10001:10001`) | `8650` | **None (`0`)** | `allinagent_edge`, `allinagent_data` |
| `paperclip` | `deploy/docker/paperclip.Dockerfile` | `node:24-bookworm-slim` | `node` (`1000:1000`) | `3100` | `127.0.0.1:8201` | `allinagent_edge`, `allinagent_data` |
| `office-bridge` | `deploy/docker/office-bridge.Dockerfile` | `node:24-bookworm-slim` | `node` (`1000:1000`) | `3210` | `127.0.0.1:8202` | `allinagent_edge`, `allinagent_data` |
| `office` | `deploy/docker/office.Dockerfile` | `node:24-bookworm-slim` | `node` (`1000:1000`) | `3200` | `127.0.0.1:8200` | `allinagent_edge` |
| `vulnclaw` | `deploy/docker/vulnclaw.Dockerfile` | `python:3.12-slim-bookworm` | `vulnclaw` (`10002:10002`, `nologin`) | `8660` | **None (`0`)** | `allinagent_data` (`internal: true`) |

---

## 2. Multi-Stage Image Engineering & Supply-Chain Hardening

1. **`deploy/docker/hermes.Dockerfile`:**
   - **Builder Stage:** Uses `uv` (`ghcr.io/astral-sh/uv:0.6.6`) to install standalone CPython `3.14` into `/opt/python` and materialize `/opt/hermes-venv` (`UV_NO_CACHE=1`).
   - **Upstream Pin & Patch:** Fetches `NousResearch/hermes-agent` pinned at commit `eb49b8920a25ffa7bb2fadf548fe819221ca79d7`, applies `0001-error-classifier-integrator.patch` (`model_not_available_for_integrator`), and strips non-runtime directories (`.git`, `apps/desktop`, `website`, `tests`, `evals`, `nix`, `benchmarks`, `docs`).
   - **Open-Source License Gate:** Installs permissive messaging and document dependencies (`python-telegram-bot`, `python-docx`, `reportlab`, `pypdf`, `pdfplumber`) and enforces a build-time Python metadata assertion guaranteeing **zero** AGPL (`pymupdf`) or GPL (`marker-pdf`) packages exist in `/opt/hermes-venv`.
   - **Runtime Stage:** Copies only `/opt/python`, `/opt/hermes-venv`, and `/opt/allinagent` (`apps/control-center`, `components/hermes`, `agents/`, `skills/`), runs under `tini` PID 1 as `allinagent` (`10001:10001`), and probes `http://127.0.0.1:8650/health`.
2. **`deploy/docker/paperclip.Dockerfile`:**
   - Installs `paperclipai@2026.1117.0` with `--omit=dev --no-optional` (eliminating embedded platform PostgreSQL binaries), runs `prune-paperclip-bloat.mjs` and `apply-paperclip-patches.mjs`, installs `/usr/local/bin/hermes` (`hermes-cli-shim.mjs`), and runs under `tini` as `node` (`1000`) with `HEALTHCHECK` on `:3100/api/health`.
3. **`deploy/docker/office-bridge.Dockerfile`:**
   - Multi-stage `node:24-bookworm-slim` image packaging `apps/office-bridge`, `apps/control-center`, lightweight `python3` stdlib CLI support, `/usr/local/bin/hermes` shim, and optional `--build-arg INSTALL_CHROMIUM=true` support while keeping the default production image lightweight. Probes `:3210/health`.
4. **`deploy/docker/office.Dockerfile`:**
   - Multi-stage Next.js 16 production build (`npm ci && npm run build && npm prune --omit=dev && rm -rf .next/cache`), running `node server/index.js` as non-root `node` (`1000`) with `STUDIO_ACCESS_TOKEN` gate enforcement and `HEALTHCHECK` on `:3200/api/health`.
5. **`deploy/docker/vulnclaw.Dockerfile`:**
   - Multi-stage `python:3.12-slim-bookworm` packaging `Netw0rkNoob/VulnClaw` (`0b34878f84b089b21fcf85ecd445315f14df0672`, `v0.4.1`) + minimal `<25 MB` defensive wheels (`pyyaml`, `httpx`, `pydantic`), running as `uid 10002` (`/usr/sbin/nologin`) on a `read_only: true` root filesystem with `cap_drop: [ALL]`, `no-new-privileges:true`, `:ro` workspace mount, air-gapped `allinagent_data` network, and **zero** platform secrets.

---

## 3. Verification Evidence

- Validated `compose.yaml` and `compose.production.yaml` via `yaml.safe_load` (`YAML_SAFE_LOAD_OK`).
- Verified all 18 POSIX Docker/Compose/shell/systemd files contain pure LF (`\n`) line endings (`LF_NORMALIZED_OK`) and strip CRLF during image builds (`sed -i 's/\r$//'`).
- Verified `postgres`, `hermes`, and `vulnclaw` publish **zero** host ports in both `compose.yaml` and `compose.production.yaml`.
