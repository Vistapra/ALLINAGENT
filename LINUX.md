# ALLINAGENT — Linux Platform & Operations Guide

**Linux (Ubuntu 22.04 / 24.04 LTS & Debian 12 Bookworm, `x86_64` / `arm64`)** is the primary, first-class production operating system for **ALLINAGENT**.

---

## 1. Execution Topologies on Linux: Honest Capability Matrix

Understanding filesystem and desktop boundaries across deployment topologies prevents misconfiguration:

| Capability | Native Linux Server / VPS (`/opt/allinagent` Docker) | Local Linux Workstation (`compose.yaml` Docker) | Linux Server + Paired Windows/Desktop Runner |
| :--- | :--- | :--- | :--- |
| **11 Corporate AI Agents (`pc*` profiles)** | Yes (shared CPython 3.14 inside `allinagent-hermes`) | Yes | Yes |
| **3D WebGL & 2D Pixel Virtual Office** | Served by Linux (`0%` server GPU); rendered in user's browser | Served & viewed locally | Served by Linux; rendered in user's browser |
| **59-Command Telegram CODEXE Control** | Yes (single outbound `getUpdates` poller) | Yes | Yes |
| **VulnClaw Defensive Static Security Scan** | Yes (`:ro` container mount on `allinagent_data`) | Yes | Yes |
| **Browse / Analyze Linux Server `/workspaces`** | Yes (strictly jailed to `ALLOWED_WORKSPACE_ROOTS`) | Yes (bind-mounted local Linux projects) | Yes |
| **Browse / Analyze a Remote Windows PC's `C:\` or `D:\` Drive** | **No** — a cloud Ubuntu VPS has zero direct access to your home/office PC's local disks | N/A | **Only when `integrations/connected-device/windows_runner_agent.py` is explicitly paired, online, allowlisted, and Owner-approved** |
| **Interactive Desktop GUI / Browser Automation on User PC** | Headless container browser / SVG floorplan only | Local X11/Wayland or container browser | **Only via paired & online Connected Device runner with explicit Owner approval (`/persetujuan` $\rightarrow$ `/setujui`)** |

> [!IMPORTANT]
> **Filesystem Honesty Guarantee:** An Ubuntu VPS running in a cloud data center **cannot** read or inspect a remote Windows workstation's `C:\` or `D:\` drives unless you explicitly pair and run the Connected Device agent (`integrations/connected-device/windows_runner_agent.py`) on that Windows PC with an explicit folder allowlist. Without an online paired runner, `/folder`, `/jelajah`, and `/analisis` operate strictly on repositories mounted inside the Linux server's authorized `/workspaces` directory.

---

## 2. Supported Linux Distributions & Kernel Features

- **Recommended OS:** Ubuntu `24.04 LTS` (Noble), Ubuntu `22.04 LTS` (Jammy), Debian `12` (Bookworm)
- **Kernel & Cgroups:** Linux Kernel `>= 5.15` (`6.8+` on Ubuntu 24.04) with **unified cgroup v2 (`cgroup2fs`)**
- **Verify cgroup v2 & Docker systemd driver:**
  ```bash
  stat -fc %T /sys/fs/cgroup/
  # Expected: cgroup2fs

  docker info --format 'CgroupVersion={{.CgroupVersion}} Driver={{.CgroupDriver}}'
  # Expected: CgroupVersion=2 Driver=systemd
  ```

### Recommended Sysctl Baseline for Multi-Tenant 8 GB Linux Hosts

The default Ubuntu 24.04 LTS kernel settings work out of the box. On memory-constrained 2-vCPU / 8-GB RAM hosts running multiple workloads, verify:

```bash
# Prefer keeping working sets in physical RAM rather than aggressive swapping
sudo sysctl -w vm.swappiness=10
sudo sysctl -w fs.inotify.max_user_watches=524288
```

To persist across reboots, write these keys to `/etc/sysctl.d/60-allinagent.conf` and run `sudo sysctl --system`.

---

## 3. Non-Root Container UIDs & Host Bind-Mount Permissions

ALLINAGENT containers never run application processes as `root`. When `./allinagent setup` runs as `root` on Linux (`sudo ./allinagent --production setup`), `scaffold_data_directories()` automatically creates and assigns exact POSIX ownership and modes under `${ALLINAGENT_DATA_DIR}` (`/opt/allinagent/data`):

| Host Directory | Container Mount | Container UID:GID | POSIX Mode | Purpose |
| :--- | :--- | :---: | :---: | :--- |
| `data/postgres` | `/var/lib/postgresql/data` | `70:70` (`postgres` alpine) | `0700` | PostgreSQL 16 database cluster |
| `data/paperclip` | `/var/lib/allinagent/paperclip` | `1000:1000` (`node`) | `0750` | Paperclip control plane runtime home |
| `data/hermes` | `/var/lib/allinagent/hermes` | `10001:10001` (`allinagent`) | `0750` | Shared Hermes state + 11 `0700` `pc*` profiles |
| `data/office-data` | `/var/lib/allinagent/office-data` | `1000:1000` (`node`) | `0750` | Event ring history, layouts, meetings & audit logs |
| `data/studio-state/hermes3d` | `/var/lib/allinagent/studio-state` | `1000:1000` (`node`) | `0750` | Studio gateway settings (`settings.json` `0600`) |
| `data/vulnclaw` | `/var/lib/vulnclaw` | `10002:10002` (`vulnclaw`) | `0750` | Isolated defensive scan data (`0` secrets) |
| `data/secrets` | `/var/lib/allinagent/secrets:ro` | `0:0` dir / scoped `0600` files | `0755` dir / `0600` files | Scoped auth files (never mounted into `vulnclaw`) |
| `data/maintenance` | *(Host CLI managed)* | `0:0` | `0750` | `state.json`, `maintenance.lock` & rollback metadata |
| `data/backups` | *(Host CLI managed)* | `0:0` | `0700` | Gzipped `pg_dump` pre-update backups (`0600`) |
| `data/workspaces` | `/var/lib/allinagent/workspaces` (`:ro` in `vulnclaw`) | `10001:1000` | `0775` | Authorized project workspaces shared by Hermes & Node |

### Running Rootless / Non-Root on a Linux Desktop

If you clone ALLINAGENT into a user directory (e.g. `~/src/ALLINAGENT`) on a Linux desktop where your user belongs to the `docker` group, run `./allinagent setup` without `sudo`. If a container reports permission errors writing to `./data/*` due to UID mapping differences (`1000` vs `10001` vs `10002`), run once with `sudo ./allinagent setup --config-only --yes` so `chown` sets exact container UIDs on `./data/*`.

---

## 4. Linux CLI & Systemd Service Lifecycle

### Direct CLI Operations

```bash
cd /opt/allinagent
sudo ./allinagent --production status
sudo ./allinagent --production health
sudo ./allinagent --production logs -f hermes office-bridge
sudo ./allinagent --production doctor
```

### Systemd Supervision (`deploy/linux/install-systemd.sh`)

```bash
# Install and enable boot autostart + daily 03:00 maintenance timer
sudo /opt/allinagent/deploy/linux/install-systemd.sh

# Start / stop / restart via systemd
sudo systemctl start allinagent.service
sudo systemctl stop allinagent.service
sudo systemctl reload allinagent.service

# Inspect daily maintenance timer and logs
systemctl list-timers allinagent-maintenance.timer
sudo journalctl -u allinagent.service -u allinagent-maintenance.service --since "24 hours ago"
```

---

## 5. Pairing an Optional Remote Workstation to a Linux Server

If your ALLINAGENT control plane runs on a Linux VPS (`https://office.example.com` or via SSH tunnel) and you occasionally want agents to inspect an allowlisted project directory on your personal Windows PC:

1. Keep ALLINAGENT running normally on the Linux VPS (`/opt/allinagent`).
2. Follow [WINDOWS.md — Mode 3: Paired Windows Connected Device Runner](./WINDOWS.md#5-mode-3-paired-windows-connected-device-runner) to run `integrations/connected-device/windows_runner_agent.py` (or `.\deploy\windows\connected-device-node.ps1`) on your Windows PC.
3. The Windows PC initiates an **outbound** authenticated connection to your Linux server, registers only the directories you explicitly allowlist, and requires Owner approval (`/persetujuan` $\rightarrow$ `/setujui`) for privileged device actions. When you close or stop the runner on Windows, the Linux VPS immediately marks the device `offline` and falls back cleanly to Linux `/workspaces`.

---

## 6. Linux Troubleshooting

| Symptom | Cause | Resolution |
| :--- | :--- | :--- |
| `docker-compose: command not found` | Legacy Compose v1 invoked instead of v2 plugin | Install `docker-compose-plugin` (`sudo apt-get install docker-compose-plugin`) and use `./allinagent` (which invokes `docker compose`) |
| `Bind for 127.0.0.1:8200 failed: port is already allocated` | Another local process owns `8200`, `8201`, or `8202` | Check `sudo ss -lntup \| grep 820` and override `ALLINAGENT_OFFICE_PORT`, `ALLINAGENT_PAPERCLIP_PORT`, or `ALLINAGENT_BRIDGE_PORT` in `.env` |
| `nginx: [emerg] duplicate listen options for 0.0.0.0:443` | `reuseport` added to a second `listen 443 quic` block | Keep `listen 443 quic;` **without** `reuseport` as shipped in `deploy/proxy/nginx-allinagent.conf.template` |
| Telegram bot does not respond | `TELEGRAM_BOT_TOKEN` or `OWNER_TELEGRAM_ID` unset or invalid | `components/hermes/entrypoint.sh` skips the poller when either value is blank/invalid (fail-closed). Set both in `.env` and run `sudo ./allinagent --production up` |
| `409 Conflict: terminated by other getUpdates request` | Another host or local dev instance is polling the same `TELEGRAM_BOT_TOKEN` | Stop any duplicate Gateway instance using that bot token, or mint a dedicated bot token via `@BotFather` |
