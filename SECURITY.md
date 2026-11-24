# ALLINAGENT — Security Architecture, Sandboxing & Disclosure Policy

`ALLINAGENT` orchestrates 11 autonomous AI corporate agents, a web-based 3D/2D Virtual Office, a 59-command Telegram Control Center, 33 third-party GitHub skill packages, and a static-analysis security scanner (`VulnClaw`). Because autonomous agents inspect source code, run tests, and interact with external APIs, `ALLINAGENT` enforces **defense-in-depth isolation** across network topology, container privileges, filesystem permissions, credential scoping, skill supply-chain verification, and human-in-the-loop governance approvals.

Related documentation:
- [`SKILL-SUPPLY-CHAIN.md`](./SKILL-SUPPLY-CHAIN.md) — 40-char commit SHA pins, SHA-256 checksums, Sentry `skill-scanner` + AST gate & quarantine ledger
- [`TELEGRAM.md`](./TELEGRAM.md) — Fail-closed `OWNER_TELEGRAM_ID` DM-only guard, single-poller lock & HMAC-SHA256 approval cards
- [`AGENTS.md`](./AGENTS.md) — `file,terminal,skills` vs read-only `file,skills` toolset boundaries & `0700` `pc*` profile isolation

---

## 1. Defense-in-Depth Security Matrix

| Security Layer | Enforcement Mechanism | Authoritative File(s) |
| :--- | :--- | :--- |
| **Network Segmentation** | Two isolated Docker bridges: `allinagent_edge` (`192.168.240.0/24`, `internal: false`) and air-gapped `allinagent_data` (`192.168.241.0/24`, `internal: true` — zero internet egress, zero host ports for `postgres` & `vulnclaw`). | `compose.yaml`, `compose.production.yaml` |
| **Zero Public Docker Ports** | Only `office` (`127.0.0.1:8200`), `paperclip` (`127.0.0.1:8201`), and `office-bridge` (`127.0.0.1:8202`) bind to host loopback; `postgres` (`:5432`), `hermes` (`:8650`), and `vulnclaw` (`:8660`) publish **`0` host ports**. | `compose.production.yaml`, `scripts/allinagent_cli.py` (`doctor`) |
| **Web UI Access Gate** | `allinagent-office` (`server/access-gate.js`) gates all HTTP and WebSocket routes (`/api/gateway/ws`, `/api/company/events/ws`) behind `/login` (`STUDIO_ACCESS_TOKEN`), issuing an `HttpOnly` `studio_access` session cookie behind Host Nginx TLS 1.3. | `apps/hermes3d/server/access-gate.js` |
| **Zero Docker Socket Exposure** | `/var/run/docker.sock` is **never** mounted into any `ALLINAGENT` container, preventing container-escape privilege escalation. | `compose.yaml`, `deploy/docker/*.Dockerfile` |
| **Non-Root Container UIDs** | `paperclip`, `office-bridge`, and `office` run as `UID 1000:1000` (`node`); `hermes` runs as `UID 10001:10001` (`allinagent`); `vulnclaw` runs as `UID 10002:10002` (`vulnclaw`, `/usr/sbin/nologin`); `postgres` runs as `UID 70:70`. Every service sets `security_opt: ["no-new-privileges:true"]` and `pids_limit`. | `deploy/docker/*.Dockerfile`, `compose.production.yaml` |
| **Defensive-Only `VulnClaw` Sandbox** | `read_only: true` rootfs, `cap_drop: ["ALL"]`, `noexec,nosuid,nodev` `/tmp` tmpfs, `:ro` workspace mount, **zero secrets mounted**, `allinagent_data` internal network (`0` internet egress), and `config/vulnclaw.defensive.yaml` disabling all MCP servers, `python_execute`, plugins, and offensive actions. | `deploy/docker/vulnclaw.Dockerfile`, `config/vulnclaw.defensive.yaml`, `components/vulnclaw/` |
| **Agent Toolset & Profile Isolation** | 4 SOC/security roles (`security_lead`, `security_reviewer`, `findings_analyst`, `remediation_reviewer`) enforce strictly read-only `file,skills` (`terminal` disabled). Each `pc*` profile (`chmod 0700`) receives only `worker-llm.env` + a scoped Paperclip agent key (`0` `TELEGRAM_BOT_TOKEN` access) and sets `canCreateAgents: false`, `canCreateSkills: false`. | `apps/control-center/control_center/org_provisioner.py`, `hermes_worker_factory.py` |
| **Internal RPC Authentication** | Remote CLI shim calls from `paperclip` / `office-bridge` to `hermes:8650` require CSPRNG `HERMES_EXEC_SHARED_SECRET`; internal bridge calls require `OFFICE_BRIDGE_TOKEN`. | `components/hermes/hermes_exec_daemon.py`, `hermes-cli-shim.mjs` |
| **Telegram DM-Only & Anti-Replay** | Fail-closed `OWNER_TELEGRAM_ID` check (`^[1-9][0-9]{4,19}$`), group/channel rejection (`403`), HMAC-SHA256 `\|sig=` callback verification, 30-min callback replay ledger (`409`), and 15-min target/arg-bound one-time `req_*` approvals. | `integrations/telegram/unified-company-control/__init__.py`, `security-guard.js` |
| **Secret Redaction & Outbound File Guard** | All logs, API responses, VulnClaw findings, and Telegram replies pass through regex credential scrubbers (`[REDACTED_API_KEY]`, `[REDACTED_BOT_TOKEN]`, `[REDACTED_TOKEN]`); `_is_safe_outbound_file` blocks `.env*`, `*auth.json`, `*.pem`, `*.key`, `id_rsa`, and `.git-credentials` from ever being served or sent. | `apps/office-bridge/contracts/redaction.js`, `unified-company-control/__init__.py` |

---

## 2. Cryptographic Secret Provisioning & File Permissions

Running `./allinagent setup` (`scripts/allinagent_cli.py`) generates high-entropy CSPRNG secrets (`secrets.token_hex`) with atomic `0600` file permissions (`O_CREAT | O_TRUNC`, mode `0o600`):

- **`POSTGRES_PASSWORD`** (`48` hex chars / 192 bits) — PostgreSQL authentication over internal `allinagent_data`
- **`STUDIO_ACCESS_TOKEN`** (`st_tok_` + `48` hex chars) — Web Virtual Office `/login` gate credential
- **`OFFICE_BRIDGE_TOKEN`** (`ob_tok_` + `64` hex chars / 256 bits) — Internal Bearer token between `office`, `hermes`, and `office-bridge`
- **`HERMES_EXEC_SHARED_SECRET`** (`hx_tok_` + `64` hex chars / 256 bits) — Authenticates `/usr/local/bin/hermes` CLI shim requests to `hermes:8650`
- **`BETTER_AUTH_SECRET`**, **`PAPERCLIP_AGENT_JWT_SECRET`**, **`PAPERCLIP_TOOL_ACTION_SIGNING_SECRET`** (`64` hex chars / 256 bits each) — Paperclip session, agent JWT, and tool-action signing keys

Scoped runtime secret mounts under `${ALLINAGENT_DATA_DIR}/secrets` (`:ro` inside `paperclip`, `hermes`, `office-bridge`, and `office` — **never** mounted into `vulnclaw`):
- `office-bridge-auth.json` (`0600`, `UID 1000:1000`)
- `paperclip-auth.env` (`0600`, `UID 1000:1000`)
- `worker-llm.env` (`0600`, `UID 10001:10001` — contains only LLM base URL/model/key; excludes Telegram and admin tokens)

To rotate all internal platform secrets cleanly:
```bash
./allinagent setup --rotate-secrets --yes
```

---

## 3. Strictly Defensive `VulnClaw` Isolation & Prompt-Injection Neutralization

`ALLINAGENT` integrates unmodified upstream `Netw0rkNoob/VulnClaw` `v0.4.1` (`0b34878f84b089b21fcf85ecd445315f14df0672`) **exclusively** for authorized, non-destructive static source-code analysis (`L1`/`L2` `codescan`):

1. **Blocked Offensive Capabilities:** `exploit`, `solve`, `run`, `persistent`, `recon`, `scan_network`, `python_execute`, `shell_command`, `http_probe_batch`, and `traffic_repeat` are blocked at both configuration (`config/vulnclaw.defensive.yaml`) and Python wrapper levels (`VULNCLAW_DEFENSIVE_ONLY=1`).
2. **All External MCP Servers Disabled:** `fetch`, `memory`, `chrome-devtools`, `burp`, and `scanmalware` are forced to `enabled: false`.
3. **Air-Gapped Read-Only Container:** `allinagent-vulnclaw` attaches **only** to `allinagent_data` (`internal: true`), mounts `/workspaces:ro` and its own root filesystem as `read_only: true`, drops all Linux capabilities (`cap_drop: ["ALL"]`), and runs as `UID 10002` (`/usr/sbin/nologin`).
4. **Prompt-Injection & Secret Sanitization:** Candidate scan outputs are scrubbed of credential literals and directive markers before entering `findings.db`, and LLM triage treats findings strictly as inert JSON data (`temperature: 0.0`, never executing embedded instructions or inventing CVE IDs).

---

## 4. Connected Device & Workspace Governance

- **Workspace Sandboxing:** Agents operate strictly inside `${ALLINAGENT_WORKSPACES_DIR}` (`/var/lib/allinagent/workspaces`) and `${ALLINAGENT_REPORTS_DIR}`. Concurrent branch edits use atomic lockfiles (`data/workspace-locks/*.lock`, stale recovery `> 15m`) and isolated Git worktrees (`create_isolated_git_worktree`) without touching uncommitted host files or `.env` files.
- **Optional Connected Device Mode:** When an operator pairs a personal workstation over an outbound-only authenticated WSS / WireGuard / Tailscale tunnel, only explicitly allowlisted folder roots are browsable, and any desktop/browser CUA or high-impact mutation is **blocked until explicitly approved by the Owner** via a target-bound `/persetujuan` $\rightarrow$ `/setujui <req_id>` token.

---

## 5. Automated Pre-Release & CI Security Gates

Every commit and release is validated by `scripts/audit-public-release.py` and `scripts/generate-sbom.py`:

```bash
# Run built-in security gate unit tests + full repository secret/path/license audit
python3 scripts/audit-public-release.py --self-test
python3 scripts/audit-public-release.py --strict-clean-tree

# Run runtime environment, 0600 permissions, and loopback-only port verification
./allinagent doctor
```

`audit-public-release.py` fails closed (`exit 1`) on:
- API keys (`SEC-001`), Telegram bot tokens (`SEC-002`), GitHub PATs (`SEC-003`), cloud/SaaS tokens (`SEC-004`), PEM private keys (`SEC-005`), internal runtime tokens (`SEC-006`), or non-template DB credentials (`SEC-007`).
- Hardcoded workstation paths (`PORT-001`..`PORT-003`) or synthetic placeholder Owner Telegram IDs (`AUTH-001`).
- Any tracked `.env*` (except `.env.example`), `*secret*.json`, `*.db`, `*.sql`, `node_modules/`, virtualenvs, or `FETCH_FROM_UPSTREAM_ONLY` skill directories in `git ls-files`.

---

## 6. Reporting Security Vulnerabilities

**Do not open public GitHub issues for suspected security vulnerabilities.**

Please report security issues privately through **GitHub Private Vulnerability Reporting** (`Security` tab $\rightarrow$ `Report a vulnerability`) on the official `ALLINAGENT` repository, including:
1. Affected component (`paperclip`, `hermes`, `office-bridge`, `office`, `vulnclaw`, `skills`, or `cli`) and commit SHA / version.
2. Minimal, non-destructive reproduction steps and configuration context.
3. Impact assessment (confidentiality, integrity, or availability boundary affected).

Reports are acknowledged within **72 hours**, triaged for root-cause remediation with regression tests, and disclosed responsibly after a patched release image is published.
