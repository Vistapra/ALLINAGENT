# ALLINAGENT — 5-Minute Quickstart

Get **ALLINAGENT** running locally or on an Ubuntu LTS server in minutes using the unified one-command CLI (`./allinagent` on Linux/macOS, `.\allinagent.ps1` on Windows).

> [!IMPORTANT]
> **Hardware Sizing Note:** On a **2 vCPU / 8 GB RAM** cloud VPS, always configure an **external LLM API provider** (OpenAI, OpenRouter, Anthropic-compatible proxy, Google Gemini OpenAI-compatible endpoint, or custom gateway) via `LLM_BASE_URL` + `CUSTOM_API_KEY`. Running local LLM weights (Ollama/vLLM) requires dedicated RAM/VRAM (`>= 16 GB RAM` or a discrete GPU). See [MODEL-PROVIDERS.md](./MODEL-PROVIDERS.md).

---

## 1. Prerequisites

| Requirement | Minimum Version | Notes |
| :--- | :--- | :--- |
| **Docker Engine** | `>= 24.0` | Linux native `docker.service` or Docker Desktop (`>= 4.28`) on Windows/macOS |
| **Docker Compose v2** | `>= 2.20` | Invoked as `docker compose` (with a space; legacy `docker-compose` v1 is unsupported) |
| **Python** | `>= 3.10` | Host standard library only (`0` `pip` packages required on the host to run `./allinagent`) |
| **Git** | `>= 2.34` | Required to clone the repository |
| **CPU / RAM / Disk** | `2 vCPU` / `4–8 GB RAM` / `10 GB free` | Production profile caps the full 6-container stack at `<= 1,536 MiB` physical RAM |

---

## 2. Clone the Repository

### Linux / macOS

```bash
git clone https://github.com/Vistapra/ALLINAGENT.git
cd ALLINAGENT
chmod +x ./allinagent
```

### Windows (PowerShell)

```powershell
git clone https://github.com/Vistapra/ALLINAGENT.git
Set-Location .\ALLINAGENT
```

---

## 3. Run One-Command Setup

`setup` runs preflight checks, launches an interactive `.env` configuration wizard, generates owner-only (`0600`) CSPRNG platform secrets, pulls or builds container images, initializes PostgreSQL 16, starts all 6 services, provisions the **11 corporate AI agents**, verifies **33 SHA-pinned role skills**, and validates all service health endpoints.

### Option A — Interactive Wizard (Recommended for First Run)

- **Linux / macOS:**
  ```bash
  ./allinagent setup
  ```
- **Windows (PowerShell):**
  ```powershell
  .\allinagent.ps1 setup
  ```

When prompted, enter:
1. **LLM Base URL** (default: `https://api.openai.com/v1` — or OpenRouter `https://openrouter.ai/api/v1`, Gemini, etc.)
2. **Default LLM Model** (e.g., `gpt-4o-mini`, `openai/gpt-4.1-mini`, `gemini-2.5-flash`)
3. **LLM Provider API Key** (`<YOUR_API_KEY>`, masked input)
4. *(Optional)* **Telegram Bot Token** (`<YOUR_TELEGRAM_BOT_TOKEN>`) and **Owner Telegram Numeric ID** (`<YOUR_TELEGRAM_ID>`) for the 59-command Telegram CODEXE Control Center

### Option B — Non-Interactive / Automated Provisioning (`--yes`)

```bash
LLM_BASE_URL="https://api.openai.com/v1" \
LLM_MODEL="gpt-4o-mini" \
CUSTOM_API_KEY="<YOUR_API_KEY>" \
OWNER_TELEGRAM_ID="<YOUR_TELEGRAM_ID>" \
TELEGRAM_BOT_TOKEN="<YOUR_TELEGRAM_BOT_TOKEN>" \
./allinagent --production setup --yes
```

> [!TIP]
> If prebuilt GHCR images are not yet cached on your host or you modified local Dockerfiles, append `--build` (`./allinagent setup --build`). On `<= 8 GB RAM` hosts, the CLI automatically caps Docker BuildKit at `--memory=1280m --cpus=1.0` per image to prevent host swap thrashing.

---

## 4. Open the 3D & 2D Virtual Office

By default, ALLINAGENT binds ports **exclusively to `127.0.0.1`** (zero public `0.0.0.0` Docker ports):

| Loopback Endpoint | Default URL | Purpose |
| :--- | :--- | :--- |
| **3D & 2D Virtual Office** | `http://127.0.0.1:8200/office` | Interactive WebGL 3D Office, Phaser 2D Pixel Office & 6-tab Command Center |
| **Paperclip Control API** | `http://127.0.0.1:8201/api/health` | Organizational control plane, Kanban issues, approvals & budgets |
| **Unified Office Bridge** | `http://127.0.0.1:8202/health` | Real-time Event Bus v1.0, Gateway Protocol v3 & Telegram CODEXE bridge |

1. Retrieve your auto-generated **Studio Access Token** (`STUDIO_ACCESS_TOKEN`, formatted `st_tok_<hex>`) from your local `.env` file (`data/secrets/office-bridge-auth.json` also stores `studioAccessToken`).
2. **If running on your local machine:** Open `http://127.0.0.1:8200/office` in a WebGL-capable browser and sign in at `/login` using `STUDIO_ACCESS_TOKEN`.
3. **If running on a remote Linux VPS (before domain/HTTPS setup):** Open an encrypted SSH loopback tunnel from your laptop:
   - **Linux / macOS:**
     ```bash
     ./deploy/proxy/ssh-tunnel-access.sh ubuntu@203.0.113.10
     ```
   - **Windows (PowerShell):**
     ```powershell
     .\deploy\proxy\ssh-tunnel-access.ps1 ubuntu@203.0.113.10
     ```
   Then open `http://127.0.0.1:8200/office` locally.

---

## 5. Verify Health & Run Your First Task

```bash
# Check container states & maintenance status
./allinagent status

# Probe all 6 internal and loopback health endpoints
./allinagent health

# Run deep SRE, security, permission, and port diagnostics
./allinagent doctor
```

### Try the Included Sandbox Fixture (`workspaces/sample-project`)

1. **In the Web Virtual Office (`http://127.0.0.1:8200/office`):**
   - Switch freely between **3D Office** (Three.js WebGL) and **2D Pixel Office** (Phaser Canvas) — 100% rendered on your browser GPU (`0%` server GPU usage).
   - Open the **Command Center Overlay** $\rightarrow$ select **Target Folder** $\rightarrow$ pick `sample-project` to inspect the polyglot demo service or create a multi-agent task.
2. **In Telegram (if configured):**
   - Open a DM with your bot from `<YOUR_TELEGRAM_ID>` (fail-closed authorization rejects any other Telegram user ID).
   - Send `/kantor` for the interactive 2-column inline menu, `/agen` to inspect all 11 corporate agents, `/analisis sample-project` for instant read-only repository analysis, or `/delegasi` to assign a goal to `@ceo`.

---

## 6. Everyday CLI Reference

| Command (Linux / macOS) | Command (Windows PowerShell) | Description |
| :--- | :--- | :--- |
| `./allinagent up` | `.\allinagent.ps1 up` | Create and start the container stack in the background |
| `./allinagent down` | `.\allinagent.ps1 down` | Stop and remove containers (preserves bind-mounted `data/`) |
| `./allinagent start` | `.\allinagent.ps1 start` | Start existing stopped containers |
| `./allinagent stop` | `.\allinagent.ps1 stop` | Gracefully stop running containers |
| `./allinagent status` | `.\allinagent.ps1 status` | Show container runtime statuses and maintenance state (`--json` supported) |
| `./allinagent health` | `.\allinagent.ps1 health` | Probe all 6 service health checks (`--json` supported) |
| `./allinagent logs -f` | `.\allinagent.ps1 logs -f` | Follow live container logs (optionally pass service names, e.g. `hermes office`) |
| `./allinagent doctor` | `.\allinagent.ps1 doctor` | Validate `.env` (`0600`), CSPRNG secrets, loopback bindings, and host capacity |
| `./allinagent update` | `.\allinagent.ps1 update` | Safe release update with active-work deferral, `pg_dump` backup & auto-rollback |
| `./allinagent version` | `.\allinagent.ps1 version` | Print CLI version and immutable upstream component pins |

---

## Next Steps

- **Full Installation & Directory Layout:** [INSTALLATION.md](./INSTALLATION.md)
- **Ubuntu Production VPS, Nginx HTTPS/QUIC & Systemd:** [PRODUCTION-DEPLOYMENT.md](./PRODUCTION-DEPLOYMENT.md)
- **OS-Specific Guides & Connected Device Mode:** [LINUX.md](./LINUX.md) · [WINDOWS.md](./WINDOWS.md)
- **Container & Network Reference:** [DOCKER.md](./DOCKER.md)
- **Environment Variables & LLM Providers:** [CONFIGURATION.md](./CONFIGURATION.md) · [MODEL-PROVIDERS.md](./MODEL-PROVIDERS.md)
