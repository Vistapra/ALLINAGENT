# ALLINAGENT — Windows Platform & Connected Device Guide

**ALLINAGENT** supports Windows 10 / Windows 11 (`x64` / `ARM64`) across three clearly defined operating modes using the native PowerShell CLI (`.\allinagent.ps1`) and CMD wrapper (`allinagent.cmd`).

---

## 1. Choosing the Right Windows Operating Mode

| Operating Mode | Best For | Recommended Windows Hardware | Where Containers / Agents Run | Access to Local Windows `C:\` / `D:\` Projects |
| :--- | :--- | :--- | :--- | :--- |
| **Mode 1: Windows Docker Desktop (WSL2)** | Full local stack parity on a developer desktop | `4+ Cores` / **`16+ GB RAM`** *(WSL2 VM uses ~2–4 GB RAM overhead)* | Local Linux containers inside Docker Desktop WSL2 | Bind-mounted folders under `ALLINAGENT_WORKSPACES_DIR` |
| **Mode 2: Native Windows Host Dev Mode** | Lightweight local development on `8 GB RAM` Windows PCs without WSL2 VM overhead | `2+ Cores` / **`8+ GB RAM`** | Native Windows Node.js (`>= 20`) + Python (`>= 3.11`) + PostgreSQL | Authorized local Windows workspace folders (`AUTHORIZED_WORKSPACES`) |
| **Mode 3: Paired Windows Connected Device Runner** | **Production Cloud Ubuntu VPS + Local Windows Workstation** | Any Windows 10/11 PC (`>= 4 GB RAM`) | Core 6-service stack runs 24/7 on **Linux VPS**; lightweight runner runs on **Windows PC** | **Explicitly allowlisted Windows folders (`authorized_windows_roots`) when runner is paired & online** |

> [!WARNING]
> **Strict Architectural Boundary (No False Remote-Disk Claims):**
> When ALLINAGENT is deployed on a remote Ubuntu/Linux VPS, that cloud server **cannot** read your Windows PC's `C:\` or `D:\` drives on its own (`WINDOWS_DRIVE_ON_POSIX_FORBIDDEN` / `capability_not_supported_on_server: true`). Remote Windows folder inspection and Windows desktop/browser actions work **only** when **Mode 3 (`integrations/connected-device/windows_runner_agent.py`)** is explicitly configured, paired via HMAC-SHA256, online over an encrypted tunnel, and pointed at your allowlisted directories. Whenever your Windows PC is asleep or disconnected, the Linux VPS reports `state: "device_offline"` while keeping 100% of server-side `/workspaces` engineering, Kanban, Virtual Office, and Telegram features active.

---

## 2. Unified Windows CLI (`.\allinagent.ps1`)

Every `./allinagent` command on Linux has an identical PowerShell counterpart on Windows:

```powershell
# Interactive first-run wizard, secret generation, image pull/build & health verification
.\allinagent.ps1 setup

# Non-interactive setup with explicit production resource caps
.\allinagent.ps1 --production setup --yes

# Everyday lifecycle commands
.\allinagent.ps1 up
.\allinagent.ps1 down
.\allinagent.ps1 start
.\allinagent.ps1 stop
.\allinagent.ps1 status
.\allinagent.ps1 status --json
.\allinagent.ps1 health
.\allinagent.ps1 logs -f hermes office-bridge
.\allinagent.ps1 doctor
.\allinagent.ps1 update --check-only
.\allinagent.ps1 version
```

*(From classic `cmd.exe`, invoke `allinagent.cmd <subcommand>` with identical arguments.)*

---

## 3. Mode 1: Running the Full Docker Stack on Windows (Docker Desktop + WSL2)

### Prerequisites
1. **Windows 10 (22H2+)** or **Windows 11** with **WSL2** enabled (`wsl --install`).
2. **Docker Desktop for Windows** (`>= 4.28`) configured to use the **WSL 2 based engine**.
3. **Python `>= 3.10`** (`winget install Python.Python.3.12`) and **Git for Windows** (`winget install Git.Git`).

### Recommended `.wslconfig` Memory Cap
Docker Desktop's WSL2 utility VM can claim up to 50% of host RAM by default. Create or edit `%USERPROFILE%\.wslconfig` to bound WSL2 memory cleanly:

```ini
[wsl2]
memory=6GB
processors=4
swap=2GB
```

Restart WSL2 (`wsl --shutdown`) and start Docker Desktop, then run:

```powershell
git clone https://github.com/Vistapra/ALLINAGENT.git C:\Projects\ALLINAGENT
Set-Location C:\Projects\ALLINAGENT
.\allinagent.ps1 setup
```

Once `[6/6] ALLINAGENT SETUP COMPLETE & VERIFIED HEALTHY` prints, open `http://127.0.0.1:8200/office` in Edge, Chrome, or Firefox and sign in with `STUDIO_ACCESS_TOKEN` from `.env`.

> [!TIP]
> **Line-Ending Safety:** `.gitattributes` enforces `LF` on `*.sh`, `*.py`, `*.mjs`, `*.patch`, and `Dockerfile*`, and every multi-stage Dockerfile in `deploy/docker/` strips stray `\r` (`CRLF`) bytes at build time so Windows checkouts never break Linux container entrypoints.

---

## 4. Mode 2: Native Windows Host Development & Task Scheduler Helpers

On an **8 GB RAM** Windows PC where running a Linux WSL2 VM alongside browsers and IDEs is undesirable, contributors can run the first-party Node.js and Python services natively on Windows (`apps/office-bridge`, `apps/hermes3d`, `apps/control-center`) against a local PostgreSQL 16 instance:

1. Install **Node.js `>= 20` LTS**, **Python `>= 3.11`**, and **PostgreSQL `16`**.
2. Generate local configuration and CSPRNG secrets without starting Docker containers:
   ```powershell
   .\allinagent.ps1 setup --config-only --yes
   ```
3. Worker profile directories created by `apps/control-center/control_center/hermes_worker_factory.py` automatically apply strict per-user NTFS ACLs (`icacls.exe /inheritance:r`) and `.no-bundled-skills` isolation on Windows.

### Dynamic-Path Windows Operational Scripts (`deploy/windows/`)

All Windows operational scripts resolve `ALLINAGENT_ROOT` dynamically at runtime (zero hardcoded drive letters or usernames):

| Script | Purpose & Example Invocation |
| :--- | :--- |
| [register-scheduled-tasks.ps1](./deploy/windows/register-scheduled-tasks.ps1) | Registers `\ALLINAGENT\StackAutostart` (at logon), `\ALLINAGENT\HealthWatchdog` (every 15m), and `\ALLINAGENT\DailyMaintenance` (`03:00` daily):<br>`.\deploy\windows\register-scheduled-tasks.ps1`<br>Remove tasks cleanly: `.\deploy\windows\register-scheduled-tasks.ps1 -Unregister` |
| [platform-watchdog.ps1](./deploy/windows/platform-watchdog.ps1) | Respects `data\maintenance\maintenance.lock`, probes `.\allinagent.ps1 health --json`, and runs non-destructive `.\allinagent.ps1 up` on degradation |
| [rotate-credentials.ps1](./deploy/windows/rotate-credentials.ps1) | Inspects SHA-256 secret fingerprints or rotates credentials via masked `SecureString` input:<br>`.\deploy\windows\rotate-credentials.ps1 -Target status`<br>`.\deploy\windows\rotate-credentials.ps1 -Target provider`<br>`.\deploy\windows\rotate-credentials.ps1 -Target telegram`<br>`.\deploy\windows\rotate-credentials.ps1 -Target internal-secrets` |
| [connected-device-node.ps1](./deploy/windows/connected-device-node.ps1) | Companion wrapper to check local diagnostics (`-StatusOnly`) or launch an encrypted SSH loopback tunnel (`-RemoteSshTarget ubuntu@203.0.113.10`) |

---

## 5. Mode 3: Paired Windows Connected Device Runner

When your primary ALLINAGENT stack runs 24/7 on a **Linux VPS** (`/opt/allinagent`) and you want to securely access your Windows workstation's Virtual Office over SSH **or** pair allowlisted local Windows folders (`D:\Projects\my-service`) with the remote AI company:

### 5.1 Encrypted Zero-Domain SSH Tunnel to a Linux VPS

Forward the Linux server's loopback-only ports (`8200`, `8201`, `8202`) directly to `127.0.0.1` on your Windows PC:

```powershell
.\deploy\proxy\ssh-tunnel-access.ps1 -RemoteTarget ubuntu@203.0.113.10 -SshPort 22
# Optional custom SSH key:
# .\deploy\proxy\ssh-tunnel-access.ps1 -RemoteTarget ubuntu@203.0.113.10 -IdentityFile "$env:USERPROFILE\.ssh\id_ed25519"
```

Then open `http://127.0.0.1:8200/office` in your Windows browser (WebGL 3D & 2D rendering runs 100% on your Windows GPU).

### 5.2 Pairing `windows_runner_agent.py` for Authorized Local Folder & Device Tasks

ALLINAGENT's Connected Device architecture ([integrations/connected-device/capability_discovery.py](./integrations/connected-device/capability_discovery.py) and `integrations/connected-device/windows_runner_agent.py`) enforces four strict security layers:

1. **Private Encrypted Transport Required:** `validate_connected_device_url()` refuses plain `http://` over public IP addresses (`PUBLIC_HTTP_FORBIDDEN`). Connect over **Tailscale / WireGuard** (`100.64.0.0/10` / RFC1918), an **SSH reverse port forward** (`ssh -R 127.0.0.1:8670:127.0.0.1:8670 ubuntu@203.0.113.10`), or **HTTPS**.
2. **HMAC-SHA256 + Nonce Replay Protection:** Every request between the Linux server and the Windows runner is signed with `CONNECTED_DEVICE_SHARED_SECRET` (`>= 32` hex/random characters) using `X-AllInAgent-Timestamp`, `X-AllInAgent-Nonce`, and `X-AllInAgent-Signature`.
3. **Explicit Folder Allowlist & Secret Blocking:** Only directories passed in your runner allowlist (`authorized_windows_roots`, e.g., `D:\Projects\billing-web`) are accessible. `.env`, `.env.*`, `auth.json`, `*.local.*`, `.ssh`, `.gnupg`, `*.pem`, and `*.key` files are unconditionally blocked (`SENSITIVE_SECRET_FILE_BLOCKED`).
4. **Human-in-the-Loop Owner Approval Gate:** Privileged interactive desktop or execution requests require explicit Owner approval via Telegram (`/persetujuan` $\rightarrow$ `/setujui <id>`) or the Virtual Office Governance tab.

#### Step-by-Step Pairing

1. **Generate a 32-byte shared secret:**
   ```powershell
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
2. **Start the runner on your Windows PC** (binding to loopback `127.0.0.1:8670` or your Tailscale IP and specifying only the project roots you wish to share):
   ```powershell
   $env:CONNECTED_DEVICE_SHARED_SECRET = "<YOUR_64_HEX_CHAR_SHARED_SECRET>"
   $env:AUTHORIZED_WINDOWS_ROOTS = "D:\Projects\my-service;C:\Projects\frontend-app"
   python .\integrations\connected-device\windows_runner_agent.py --serve --bind 127.0.0.1 --port 8670
   ```
3. **Expose `127.0.0.1:8670` privately to your Linux VPS** (via SSH reverse tunnel or Tailscale/WireGuard) and set on the Linux VPS `.env`:
   ```dotenv
   CONNECTED_WINDOWS_DEVICE_URL=http://127.0.0.1:8670
   CONNECTED_DEVICE_SHARED_SECRET=<YOUR_64_HEX_CHAR_SHARED_SECRET>
   ```
   *(If running inside Docker on Linux over a host SSH reverse tunnel, route via `host-gateway` or Tailscale interface IP reachable from `allinagent_edge`.)*
4. **Verify live capability discovery:**
   ```bash
   python3 integrations/connected-device/capability_discovery.py
   ```
   When connected, `windows_connected_device.state` reports `"device_online"` alongside `authorized_windows_roots`. When stopped, it honestly transitions to `"device_offline"`.
