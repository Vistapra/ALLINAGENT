# PHASE 20 — One-Command Installer, First-Run Wizard & Operations CLI

- **Phase ID:** `PHASE-20`
- **Status:** `PASS`
- **Scope:** `./allinagent`, `allinagent.ps1`, `allinagent.cmd`, `scripts/allinagent_cli.py`

---

## 1. Cross-Platform CLI Architecture

`ALLINAGENT` provides a zero-dependency Python 3.10+ standard-library management engine (`scripts/allinagent_cli.py`) wrapped by native entrypoints for every major operating system:

- **Linux / macOS / WSL:** `./allinagent <subcommand>` (`#!/usr/bin/env bash`, pure LF)
- **Windows PowerShell:** `.\allinagent.ps1 <subcommand>`
- **Windows Command Prompt:** `allinagent.cmd <subcommand>`

Because `scripts/allinagent_cli.py` uses **only** Python standard-library modules (`argparse`, `ctypes`, `gzip`, `hashlib`, `json`, `secrets`, `shutil`, `socket`, `stat`, `subprocess`, `urllib.request`), it runs immediately on fresh Ubuntu 22.04/24.04, Debian, macOS, and Windows hosts prior to installing any pip packages.

---

## 2. Complete Subcommand Matrix

| Subcommand | Capabilities Implemented |
| :--- | :--- |
| `setup` | 1. **Preflight:** Checks OS, CPU architecture, vCPU count, physical/available RAM, free disk space, Docker Engine, Docker Compose v2 plugin (`docker compose`), and loopback port availability.<br>2. **Wizard / `--yes`:** Interactive masked prompt (`getpass`) or non-interactive `--yes` mode.<br>3. **CSPRNG Secrets (`0600`):** Generates 256-bit `secrets.token_hex` values for `POSTGRES_PASSWORD`, `STUDIO_ACCESS_TOKEN`, `OFFICE_BRIDGE_TOKEN`, `BETTER_AUTH_SECRET`, `PAPERCLIP_AGENT_JWT_SECRET`, `PAPERCLIP_TOOL_ACTION_SIGNING_SECRET`, and `HERMES_EXEC_SHARED_SECRET`; writes `.env` and scoped `data/secrets/*` with mode `0600` and container UID ownership (`70`, `1000`, `10001`, `10002`).<br>4. **Image Pull / Constrained Build:** Pulls GHCR images or builds locally with `--memory=1280m --cpus=1.0` on `<= 9 GiB` hosts.<br>5. **DB Init & Provisioning:** Boots `postgres`, waits for `pg_isready`, launches stack, runs 11-agent `org_provisioner.py` and Sentry-gated skill installation, verifies all 6 health checks, and prints dashboard URL + masked Studio token summary. |
| `up` / `down` | Starts stack (`up -d --remove-orphans`) or removes containers (`down --remove-orphans`) while preserving all host bind-mount data. |
| `start` / `stop` | Starts or stops existing containers without removing them. |
| `status` | Displays container table + maintenance coordinator state (`--json` supported). |
| `health` | Probes internal `postgres`, `hermes` (`:8650/health`), `vulnclaw` (`:8660/health`) and loopback `office` (`:8200/api/health`), `paperclip` (`:8201/api/health`), `office-bridge` (`:8202/health`), atomically writing `data/last-health-snapshot.json`. |
| `logs` | Streams (`-f`) or tails (`--tail N`) logs for all or selected services. |
| `doctor` | Audits host capacity, Compose v2 plugin, `.env` `0600` permissions, CSPRNG secret strength, loopback-only port bindings, and `maintenance.lock` staleness (`--json` supported). |
| `update` | Release-aware `release-manifest.json` check, `maintenance.lock` + live agent work deferral, pre-update `pg_dump` `.sql.gz` backup, rolling container update, post-update health gate, and **automatic rollback** to `allinagent-rollback/<svc>:previous` + candidate quarantine on failure. |
| `version` | Prints CLI version and pinned upstream commits (`--json` supported). |

---

## 3. Empirical Smoke Test Evidence

- `python -m py_compile D:\ALLINAGENT\scripts\allinagent_cli.py` -> `EXIT 0` (`PY_COMPILE_OK`).
- `allinagent.ps1 version --json` -> `EXIT 0` (emits JSON with `cli_version: "1.0.0"` and upstream pins).
- `allinagent.cmd --help` -> `EXIT 0` (lists all 11 subcommands).
- `allinagent.ps1 --env-file <scratch> --production setup --yes --config-only --data-dir <scratch>/data` -> `EXIT 0` (generated `0600` config + all 11 isolated subdirectories `backups`, `hermes`, `logs`, `maintenance`, `office-data`, `paperclip`, `postgres`, `secrets`, `studio-state`, `vulnclaw`, `workspaces`).
