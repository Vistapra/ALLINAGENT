# ALLINAGENT — Operations & Troubleshooting Runbook

This guide provides deterministic diagnostics and step-by-step resolutions for common deployment, Docker, reverse-proxy, Telegram, agent runtime, skill supply-chain, and resource issues in `ALLINAGENT`.

---

## 1. Fast Triage Commands (Start Here)

Before changing configuration files manually, run the built-in non-destructive diagnostics:

```bash
# 1. Deep environment, 0600 secrets, loopback port, Docker Compose v2 & maintenance.lock audit
./allinagent doctor

# 2. Live 6-service health probe (postgres, hermes, vulnclaw, paperclip, office-bridge, office)
./allinagent health

# 3. Inspect container states & last maintenance outcome (add --json for machine output)
./allinagent status

# 4. Tail sanitized logs for a specific service
./allinagent logs --tail 100 hermes
./allinagent logs --tail 100 paperclip
./allinagent logs --tail 100 office-bridge
```

From Telegram DM, you can also run `/kesehatan` (15-component health matrix), `/log-error` (sanitized recent errors), and `/pulihkan-layanan` (graceful non-destructive drain & recovery).

---

## 2. Docker, Preflight & Port Binding Issues

### 2.1 `docker-compose: command not found` or Compose v1 Failure
- **Cause:** Modern Linux distributions ship the **Docker Compose v2 plugin** (`docker compose` with a space) rather than the deprecated Python v1 `docker-compose` binary.
- **Resolution:** Install `docker-compose-plugin` (`sudo apt-get update && sudo apt-get install -y docker-compose-plugin`) and always use `./allinagent` or `docker compose -f compose.yaml -f compose.production.yaml ...`.

### 2.2 Loopback Port `8200`, `8201`, or `8202` Already in Use
- **Symptom:** `./allinagent setup` or `docker compose up` reports `bind: address already in use` on `127.0.0.1:8200–8202`.
- **Resolution:**
  1. Check which process owns the port: `sudo ss -lntup | grep -E ':820[0-2]\b'`
  2. Override `ALLINAGENT_OFFICE_PORT`, `ALLINAGENT_PAPERCLIP_PORT`, or `ALLINAGENT_BRIDGE_PORT` in `.env` (`chmod 0600`) to any free loopback ports (e.g., `8210–8212`), update your Host Nginx `proxy_pass` upstream to match `ALLINAGENT_OFFICE_PORT`, and run `./allinagent up`.
  3. **Never** publish `postgres` (`:5432`), `hermes` (`:8650`), or `vulnclaw` (`:8660`) to host ports — keeping them internal avoids collisions with host MySQL/PostgreSQL/Redis daemons.

### 2.3 Permission Denied Inside Bind-Mounted `/opt/allinagent/data/*`
- **Cause:** Containers run as dedicated non-root UIDs (`postgres`=`70:70`, `paperclip`/`office-bridge`/`office`=`1000:1000`, `hermes`=`10001:10001`, `vulnclaw`=`10002:10002`). Manual root copies can leave files owned by `0:0` with restrictive modes.
- **Resolution:** Re-run directory permission scaffolding safely without rotating secrets:
  ```bash
  sudo ./allinagent setup --config-only --yes
  ./allinagent up
  ```

---

## 3. Virtual Office Web UI & Host Nginx Reverse Proxy Issues

### 3.1 `HTTP 401 Unauthorized` or Redirect to `/login` When Opening `/office`
- **Cause:** `allinagent-office` enforces `server/access-gate.js` across all UI and WebSocket endpoints.
- **Resolution:** Retrieve `STUDIO_ACCESS_TOKEN` from `/opt/allinagent/.env` (`sudo grep '^STUDIO_ACCESS_TOKEN=' /opt/allinagent/.env`), paste it into the `/login` prompt, and sign in. The server sets a 30-day `HttpOnly` `studio_access` session cookie.

### 3.2 `nginx: [emerg] duplicate listen options for 0.0.0.0:443` (HTTP/3 QUIC `reuseport`)
- **Cause:** On servers (such as CloudPanel or multi-vhost Nginx `1.25+` hosts) where `/etc/nginx/sites-enabled/default.conf` already declares `listen 443 quic reuseport default_server;`, Linux allows `reuseport` to be specified **only once** per `IP:port` protocol tuple.
- **Resolution:** In your `ALLINAGENT` Nginx vhost file, declare HTTP/3 **without** `reuseport`:
  ```nginx
  listen 443 ssl;
  listen [::]:443 ssl;
  listen 443 quic;
  listen [::]:443 quic;
  ```
  Then verify with `sudo nginx -t && sudo systemctl reload nginx`.

### 3.3 3D/2D Avatars Show `Disconnected` Behind Reverse Proxy
- **Cause:** Missing WebSocket `Upgrade` / `Connection` headers on `/api/gateway/ws` and `/api/company/events/ws`.
- **Resolution:** Ensure your Nginx `location /` block proxies to `http://127.0.0.1:8200` with:
  ```nginx
  proxy_http_version 1.1;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection "upgrade";
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_read_timeout 3600s;
  ```

### 3.4 Low Client FPS or WebGL Context Lost on Older Laptops/Mobile Devices
- **Cause:** 3D rendering runs in your client browser's GPU (`Three.js`), not on the server.
- **Resolution:** Toggle seamlessly to **`2D Pixel Office`** inside the `EnterpriseOfficeOverlay` header; both views share the exact same live 11-agent state machine and Meeting Room.

---

## 4. Telegram Control Center Issues

### 4.1 Bot Replies `⛔ OWNER_TELEGRAM_ID belum dikonfigurasi (fail-closed)` or Ignores Messages
- **Cause:** `OWNER_TELEGRAM_ID` is blank, `"0"`, a synthetic placeholder ID, or does not match your numeric Telegram User ID (`^[1-9][0-9]{4,19}$`).
- **Resolution:**
  ```bash
  python3 integrations/telegram/telegram_onboarding.py --check
  python3 integrations/telegram/telegram_onboarding.py --configure
  ./allinagent up
  ```

### 4.2 `HTTP 409 Conflict: terminated by other getUpdates request`
- **Cause:** Another host (e.g., an old workstation installation) or a duplicate external script is polling the same `TELEGRAM_BOT_TOKEN`, or a stale webhook URL was previously registered on the bot.
- **Resolution:**
  1. Stop any legacy gateway on other machines.
  2. Run the single-poller & webhook cleaner:
     ```bash
     python3 integrations/telegram/telegram_onboarding.py --verify-single-poller
     python3 integrations/telegram/telegram_onboarding.py --configure --clear-webhook --non-interactive \
       --owner-id "<YOUR_NUMERIC_TELEGRAM_USER_ID>" --bot-token "<YOUR_BOT_TOKEN>"
     docker restart allinagent-hermes
     ```

### 4.3 `403 GROUP_OR_CHANNEL_FORBIDDEN`
- **Cause:** By security design, corporate control is strictly restricted to the Owner's private 1-on-1 DM (`dm_policy: "allowlist"`, `group_policy: "disabled"`).
- **Resolution:** Message your bot directly in a **private DM**, never from a group, supergroup, or channel.

### 4.4 `409 CALLBACK_REPLAY_DETECTED` or `410 APPROVAL_EXPIRED`
- **Cause:** Inline callback queries are deduplicated for `30` minutes (`consumed_callbacks`), and target-bound approval cards (`req_*`) expire after `15` minutes (`900,000 ms`) or after one-time consumption.
- **Resolution:** Send `/kantor` or `/persetujuan` to render a fresh dashboard/approval card, or re-trigger the gated command to mint a fresh `req_*` token.

---

## 5. Agent Execution, `hermes-exec` & Skill Registry Issues

### 5.1 Delegated Subtasks Remain `queued` While Another Agent Is Running
- **Cause:** Expected behavior on `2 vCPU / 8 GB RAM` hosts! `HEAVY_WORKER_CONCURRENCY=1` serializes heavy background subtasks one at a time inside `allinagent-hermes:8650` so memory stays safely below `1,536 MiB`. Direct Owner `/chat` and `/ke` turns automatically take `Priority 0` ahead of queued Kanban subtasks once the current turn finishes.
- **Resolution:** Check live progress via `/jobs` or `/daftar-task`. Only increase `HEAVY_WORKER_CONCURRENCY=2` if running on a `>= 4 vCPU / 16 GB RAM` server (`standard_profile`).

### 5.2 Wave-2 Specialist Agent Does Not Pick Up Autonomous Background Tasks
- **Cause:** By default, the 7 Wave-2 agents (`@cto`, `@frontend`, `@devops`, `@security_lead`, `@findings`, `@remediation`, `@compliance`) start in `STANDBY` (`paused`) to conserve idle resources.
- **Resolution:** Wake the needed specialist with `/bangunkan @cto` (or `/bangunkan semua`), and return to baseline afterward with `/standar-wave1`.

### 5.3 Upstream Provider Returns `model_not_available_for_integrator` or Connection Errors
- **Cause:** The configured `LLM_MODEL` in `.env` is unavailable on your `LLM_BASE_URL` OpenAI-compatible endpoint, or `CUSTOM_API_KEY` is invalid/expired. (Hermes's patched `agent/error_classifier.py` classifies `model_not_available_for_integrator` cleanly rather than crashing.)
- **Resolution:** Update `LLM_BASE_URL`, `LLM_MODEL`, and `CUSTOM_API_KEY` in `/opt/allinagent/.env`, refresh `worker-llm.env` via `./allinagent setup --config-only --yes`, and run `./allinagent up`.

### 5.4 Skill Installation Fails on Air-Gapped Host (`FETCH_FROM_UPSTREAM_ONLY`)
- **Cause:** 13 skill packages (`borghei/Claude-Skills`, `vercel-labs/agent-skills`, and Anthropic `docx`/`pdf`) are never bundled in Git/GHCR and require HTTPS access to `raw.githubusercontent.com` during default setup.
- **Resolution:** Run skill installation with `--offline` or `--strict-oss`; `ALLINAGENT` automatically activates the permissive MIT Nous Research bundled fallbacks (`productivity/microsoft-office` for `docx` and `productivity/pdf` for `pdf`).

---

## 6. `VulnClaw`, Memory Ceiling & Maintenance Lock Recovery

### 6.1 `VulnClaw` Rejects Target Path (`Access denied` / Outside `/workspaces`)
- **Cause:** `allinagent-vulnclaw` mounts `${ALLINAGENT_WORKSPACES_DIR}` read-only at `/workspaces:ro` and blocks `.env*`, `/etc`, secret directories, and arbitrary host paths.
- **Resolution:** Place or bind-mount repositories to be audited inside `${ALLINAGENT_WORKSPACES_DIR}` (`/opt/allinagent/data/workspaces/<project>`), select it via `/pilih-folder`, and run `/keamanan`.

### 6.2 Container Exits with Code `137` (`OOMKilled`)
- **Diagnosis:** Inspect `docker inspect allinagent-<service> --format '{{json .State}}'` and `docker stats --no-stream`.
- **Resolution:**
  - If `docker build` caused host memory pressure on an 8 GB VPS, **do not** run unconstrained `docker compose build`; pull prebuilt GHCR images (`./allinagent up`) or use `./allinagent setup --build` (which enforces `--memory=1280m --cpus=1.0` sequentially).
  - Keep `HEAVY_WORKER_CONCURRENCY=1` in `.env`.

### 6.3 `./allinagent update` Reports `DEFERRED` Due to `maintenance.lock` or `quarantined_candidates`
- **Cause:** Either another update run is active (`data/maintenance/maintenance.lock` `< 90` minutes old), an agent run is currently executing, or the target version previously failed post-update healthchecks and was added to `quarantined_candidates` in `data/maintenance/state.json`.
- **Resolution:**
  1. Check `./allinagent doctor` and inspect `cat /opt/allinagent/data/maintenance/state.json`.
  2. Verify no `allinagent update` process is running (`ps aux | grep allinagent_cli`).
  3. After fixing the underlying network/disk issue, re-run explicitly with `--force` (or specify a known-good `--target-tag`):
     ```bash
     ./allinagent --production update --force
     ```
