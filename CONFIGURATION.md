# ALLINAGENT — Configuration Reference

This reference documents every environment variable, secret file, port binding, workspace boundary, and resource profile consumed by **ALLINAGENT** across `./allinagent` (`scripts/allinagent_cli.py`), `compose.yaml`, `compose.production.yaml`, `apps/office-bridge/contracts/paths.js`, `apps/control-center/control_center/paths.py`, `config/resource-limits.json`, and `integrations/connected-device/capability_discovery.py`.

---

## 1. Configuration Precedence & File Locations

1. **Process Environment Variables** (highest priority — overrides `.env` values)
2. **Root `.env` File** (`<ALLINAGENT_ROOT>/.env`, created with `chmod 0600` by `./allinagent setup`, gitignored and `.dockerignore`d)
3. **Scoped Secret Files** (`${ALLINAGENT_DATA_DIR}/secrets/*`, `chmod 0600`, mounted `:ro` only into authorized containers; **never** mounted into `allinagent-vulnclaw`)
4. **Safe Code Defaults** (`127.0.0.1` loopback bindings, fail-closed blank credentials, `HEAVY_WORKER_CONCURRENCY=1`)

> [!CAUTION]
> Never commit `.env`, `data/secrets/*`, `office-bridge-auth.json`, or `*.local.*` to version control. Run `python3 scripts/audit-public-release.py` before publishing any fork or custom commit.

---

## 2. Core Platform, Image Registry & Storage Variables

| Variable | Default | Required | Description |
| :--- | :--- | :---: | :--- |
| `ALLINAGENT_PROFILE` | `production` (under `/opt/allinagent` or `--production`) / `local` | No | Selects `compose.yaml + compose.production.yaml` (`production`) vs base `compose.yaml` (`local`). |
| `ALLINAGENT_REGISTRY` | `ghcr.io` | No | Container registry hostname used by `compose.yaml` and `./allinagent update`. |
| `ALLINAGENT_IMAGE_NAMESPACE` | `allinagent` | No | Container image organization/owner namespace (e.g., `allinagent` or `vistapra`). |
| `ALLINAGENT_VERSION` | `latest` | No | Image tag deployed across `hermes`, `paperclip`, `office-bridge`, `office`, and `vulnclaw`. |
| `ALLINAGENT_GITHUB_REPO` | `allinagent/allinagent` | No | GitHub `owner/repo` queried by `./allinagent update` for `release-manifest.json` (e.g. `Vistapra/ALLINAGENT`). |
| `ALLINAGENT_DATA_DIR` | `/opt/allinagent/data` (Linux `/opt`) or `./data` | No | Host bind-mount root for persistent PostgreSQL, Hermes profiles, Office state, secrets, and backups. |
| `ALLINAGENT_WORKSPACES_DIR` | `${ALLINAGENT_DATA_DIR}/workspaces` | No | Host folder mounted into containers as the sandboxed project workspace root. |
| `AUTHORIZED_WORKSPACES` | `/workspaces` (Linux/Docker) or `<ROOT>/workspaces` | No | Comma- or semicolon-separated allowlist of directories agents may browse, analyze, or edit. Symlink escapes and `.env*` files are blocked. |
| `TIMEZONE` | Host IANA timezone (fallback `UTC`) | No | IANA timezone (e.g., `UTC`, `America/New_York`, `Asia/Tokyo`) applied to containers and `allinagent-maintenance.timer` (`03:00`). |

---

## 3. Loopback Host Port Variables

All published Docker ports bind strictly to `127.0.0.1` (never `0.0.0.0`):

| Variable | Default | Container Target | Purpose |
| :--- | :---: | :--- | :--- |
| `ALLINAGENT_OFFICE_PORT` | `8200` | `allinagent-office:3200` | Web Virtual Office (`3D` + `2D`) & Nginx reverse-proxy upstream |
| `ALLINAGENT_PAPERCLIP_PORT` | `8201` | `allinagent-paperclip:3100` | Localhost-only Paperclip Control Plane API & health probe |
| `ALLINAGENT_BRIDGE_PORT` | `8202` | `allinagent-office-bridge:3210` | Localhost-only Unified Office Bridge HTTP + WebSocket (`/ws`) |

*(Internal container ports `postgres:5432`, `hermes:8650`, and `vulnclaw:8660` are never published to the host.)*

---

## 4. LLM Model Provider Variables

See [MODEL-PROVIDERS.md](./MODEL-PROVIDERS.md) for provider-specific examples (OpenAI, Anthropic, OpenRouter, Google Gemini, custom gateways, Ollama, and vLLM).

| Variable | Default | Required | Description |
| :--- | :--- | :---: | :--- |
| `LLM_BASE_URL` | `https://api.openai.com/v1` | **Yes** | OpenAI-compatible base URL propagated to Hermes, Paperclip, Office Bridge, and worker profiles. |
| `LLM_MODEL` | `gpt-4o-mini` | **Yes** | Primary model identifier used across the 11 corporate agents (`DEFAULT_LLM_MODEL` is also honored as an alias). |
| `DEFAULT_LLM_MODEL` | *(Alias of `LLM_MODEL`)* | No | Optional explicit default model override recognized by `control_center/paths.py` and `office-bridge/contracts/paths.js`. |
| `LLM_PROVIDER` | `auto` | No | Provider selector for generated Hermes `config.yaml` (`auto` selects `openai` for `api.openai.com` and `custom` for all other OpenAI-compatible URLs). |
| `CUSTOM_API_KEY` | *(Blank — fail-closed)* | **Yes** *(for cloud APIs)* | Primary API credential (`<YOUR_API_KEY>`) injected into `hermes`, `paperclip`, and `data/secrets/worker-llm.env` (never exposed to browsers or `vulnclaw`). |
| `OPENAI_API_KEY` / `OPENROUTER_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` | *(Optional)* | No | Optional provider-specific keys passed through to sanitized worker `.env` files by `hermes_worker_factory.py` when set. |

---

## 5. Telegram Control Center & Governance Variables

| Variable | Default | Required | Description |
| :--- | :--- | :---: | :--- |
| `TELEGRAM_BOT_TOKEN` | *(Blank — disabled)* | Optional | Bot token from `@BotFather` (`<YOUR_TELEGRAM_BOT_TOKEN>`). Strictly stripped from all 11 `pc*` worker profiles so only the single Gateway poller inside `allinagent-hermes` ever calls `getUpdates`. |
| `OWNER_TELEGRAM_ID` | *(Blank — fail-closed)* | Required if Telegram enabled | Numeric Telegram user ID (`<YOUR_TELEGRAM_ID>`, e.g. from `@userinfobot`). **Fail-closed:** if blank, non-numeric, `0`, or a dummy placeholder, `components/hermes/entrypoint.sh` skips starting the poller and `control_center/paths.py` rejects all caller IDs. |
| `TELEGRAM_BOT_USERNAME` | `@allinagent_bot` | Optional | Display handle shown in Virtual Office & Telegram status cards. |
| `UNIFIED_COMPANY_GOVERNANCE` | `1` | Yes | Enforces route lockdowns, SSRF allowlists, workspace path jails, and server-side token injection in Hermes3D & Office Bridge. Keep set to `1`. |
| `HEAVY_WORKER_CONCURRENCY` | `1` | Yes | Global semaphore limit inside `hermes_exec_daemon.py` (`:8650`). Keep at `1` on 2-vCPU / 8-GB RAM hosts (`2` on 4+ vCPU / 16+ GB hosts). |

---

## 6. CSPRNG Internal Platform Secrets (Auto-Generated by `./allinagent setup`)

`./allinagent setup` automatically generates cryptographically strong random hex tokens (`secrets.token_hex`) and writes `.env` + `data/secrets/*` with mode `0600`. You do **not** need to invent these manually:

| Variable | Format / Bytes | Consumed By | Purpose |
| :--- | :--- | :--- | :--- |
| `POSTGRES_USER` | `paperclip` | `postgres`, `paperclip` | Internal PostgreSQL database role |
| `POSTGRES_DB` | `paperclip` | `postgres`, `paperclip` | Internal PostgreSQL database name |
| `POSTGRES_PASSWORD` | `48` hex chars (`24 B`) | `postgres`, `paperclip` | Internal PostgreSQL password (`allinagent_data` network only) |
| `STUDIO_ACCESS_TOKEN` | `st_tok_<48-hex>` | `office`, `office-bridge` | Owner login token for `/login` at the Web Virtual Office (`30-day` `HttpOnly` cookie) |
| `OFFICE_BRIDGE_TOKEN` | `ob_tok_<64-hex>` | `office`, `office-bridge` | Server-to-server WebSocket & REST bearer token between `office` and `office-bridge` |
| `BETTER_AUTH_SECRET` | `64` hex chars (`32 B`) | `paperclip` | Paperclip control-plane session encryption key |
| `PAPERCLIP_AGENT_JWT_SECRET` | `64` hex chars (`32 B`) | `paperclip` | Signs short-lived JWTs for Paperclip agent runs |
| `PAPERCLIP_TOOL_ACTION_SIGNING_SECRET` | `64` hex chars (`32 B`) | `paperclip` | Signs governed Paperclip tool/approval actions |
| `HERMES_EXEC_SHARED_SECRET` | `hx_tok_<64-hex>` | `hermes`, `paperclip`, `office-bridge` | Authenticates `/usr/local/bin/hermes` CLI shim requests to `http://hermes:8650` |

### Scoped Secret Files Created in `${ALLINAGENT_DATA_DIR}/secrets/`

- `office-bridge-auth.json` (`0600`, `UID 1000`): `{ bridgeToken, studioAccessToken, allowedOwnerId }`
- `paperclip-auth.env` (`0600`, `UID 1000`): Paperclip internal signing secrets
- `worker-llm.env` (`0600`, `UID 10001`): Stripped LLM-only credentials (`OPENAI_BASE_URL`, `LLM_MODEL`, `CUSTOM_API_KEY`) copied into `pc*` worker profiles with **zero** Telegram or admin tokens

### Rotating Secrets Safely

```bash
# Regenerate all internal CSPRNG secrets without overwriting your LLM or Telegram keys
./allinagent setup --yes --rotate-secrets --config-only
./allinagent up
```

*(On Windows, you can also run `.\deploy\windows\rotate-credentials.ps1 -Target status|provider|telegram|internal-secrets`.)*

---

## 7. Optional Paired Windows Connected Device Variables

Configured only when pairing a remote Windows workstation (`integrations/connected-device/windows_runner_agent.py`) to a Linux ALLINAGENT server:

| Variable | Default | Requirements & Validation |
| :--- | :--- | :--- |
| `CONNECTED_WINDOWS_DEVICE_URL` | *(Unset — `unpaired`)* | Must be `https://...` or `http://` over loopback (`127.0.0.1`), RFC1918 private LAN, or Tailscale/WireGuard (`100.64.0.0/10`). Plain HTTP to public IPs is blocked. |
| `CONNECTED_DEVICE_SHARED_SECRET` | *(Unset)* | Minimum `32` random non-placeholder characters used for HMAC-SHA256 request signing (`X-AllInAgent-Timestamp`, `X-AllInAgent-Nonce`, `X-AllInAgent-Signature`). |

---

## 8. Resource & Concurrency Policy Files (`config/`)

- **[config/resource-limits.json](./config/resource-limits.json):** Defines hardware-neutral operational profiles (`2_vcpu_8gb_profile` active by default vs. `standard_profile` for 4+ vCPU / 16+ GB hosts) and agent guardrails (`worker_max_turns_per_run: 25`, `worker_default_timeout_sec: 300`, `max_delegation_depth: 2`, `max_subtasks_per_parent: 6`, `max_retries_per_task: 2`).
- **[config/vulnclaw.defensive.yaml](./config/vulnclaw.defensive.yaml):** Locks VulnClaw strictly into defensive static code analysis (`enable_python_execute: false`, `mcp.servers: {}`, zero offensive recon keys).
