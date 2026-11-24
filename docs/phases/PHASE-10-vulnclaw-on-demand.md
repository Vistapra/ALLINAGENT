# PHASE 10 — VulnClaw Lightweight On-Demand Defensive Sandbox

- **Phase ID:** `PHASE-10`
- **Status:** `PASS`
- **Component Scope:** `components/vulnclaw/`
- **Upstream Pin:** `https://github.com/Netw0rkNoob/VulnClaw.git` @ `0b34878f84b089b21fcf85ecd445315f14df0672` (`v0.4.1`, `MIT`)
- **Internal Worker Endpoint:** `127.0.0.1:8660` (container internal port `8660`, authenticated via `X-Internal-Scan-Token` / `ALLINAGENT_INTERNAL_TOKEN`)

---

## 1. Executive Summary & Footprint Reduction

Upstream `VulnClaw` (`v0.4.1`) bundles optional knowledge-base, neural reranker, browser/proxy traffic interception, Rust TUI, and Vite web assets intended for full interactive red-team workstations. Installing all extras pulls **> 2.5 GB** of Python/Rust/Node artifacts (`torch`, `sentence-transformers`, `chromadb`, `playwright`, `mitmproxy`) — incompatible with `ALLINAGENT`'s `2 vCPU / 8 GB RAM` production target.

Phase 10 replaces heavy resident imports with a **two-tier ephemeral sandbox architecture**:

| Metric | Unoptimized Full Install | Phase 10 On-Demand Worker | Improvement |
| :--- | :--- | :--- | :--- |
| **Upstream Source Pin** | Unpinned / full clone (`~12 MiB` + `.git`) | Exact SHA `0b34878f84b0...` (`v0.4.1`), pruned to `~4.9 MiB` | **~60% smaller source tree**, zero upstream patches required |
| **Dependency Set** | `[kb]` + `[rerank]` + `[traffic]` + `[web]` (`~2.5+ GB`) | `requirements-defensive.txt` (`9` pure-Python packages, `0` ML/browser binaries) | **> 95% dependency footprint reduction** |
| **Parent Worker Idle RSS** | Resident FastAPI/Pydantic/OpenAI stack (`> 95 MB`) | Pure stdlib `asyncio` HTTP/1.1 daemon (**`21.10 MiB` empirical RSS**, `< 25 MiB` budget) | **~78% lower idle RAM** |
| **Post-Scan Parent RSS** | Retains AST/rule/report heaps in-process | **`21.27–21.33 MiB` RSS** (`< +0.25 MiB` delta; ephemeral `-B` child subprocess exits per scan) | **100% OS kernel memory reclamation after every scan** |

---

## 2. Deliverables Created in `components/vulnclaw/`

| File | Purpose |
| :--- | :--- |
| `components/vulnclaw/__init__.py` | Package constants (`VULNCLAW_UPSTREAM_REPO`, `VULNCLAW_PINNED_COMMIT`, `VULNCLAW_PINNED_VERSION`, `DEFAULT_WORKER_PORT = 8660`). |
| `components/vulnclaw/requirements-defensive.txt` | Minimal pure-Python defensive core manifest (`pydantic>=2.0`, `pydantic-settings>=2.0`, `pyyaml>=6.0`, `httpx>=0.27`, `openai>=1.66`, `typer>=0.12`, `rich>=13.7`, `toml>=0.10`, `jsonschema>=4.20`). |
| `components/vulnclaw/vulnclaw.defensive.yaml` | Zero-secret defensive runtime configuration (`safety.enable_python_execute: false`, `mcp.servers: {}`, `subagent.enabled: false`, `session.plugin_runtime_enabled: false`). |
| `components/vulnclaw/bootstrap_vulnclaw.py` | Reproducible shallow-cloner, `MIT` license & LF-normalized SHA-256 supply-chain verifier, non-defensive tree pruner (`frontend/`, `tui/`, `assets/`, `tests/`, `demo/`, `.github/`), and bloat-free installer. |
| `components/vulnclaw/vulnclaw_worker.py` | Pure-stdlib `asyncio` HTTP (`GET /health`, `POST /scan`) + CLI (`serve`, `scan`, `health`, `self-test`) defensive scan worker with strict path jail and ephemeral child subprocess isolation. |
| `components/vulnclaw/Dockerfile` | Multi-stage `python:3.12-slim` container definition running non-root (`10001:10001`), mounting `/workspaces:ro`, and exposing internal port `8660`. |

---

## 3. Supply-Chain Verification Contract (`bootstrap_vulnclaw.py`)

`bootstrap_vulnclaw.py` enforces deterministic verification across Linux containers and Windows checkouts using LF-normalized SHA-256 (`raw.replace(b"\r\n", b"\n")`, matching exact Git blob hashes at commit `0b34878f84b089b21fcf85ecd445315f14df0672`):

| Verified Upstream File | Expected LF SHA-256 |
| :--- | :--- |
| `LICENSE` (`MIT`) | `798df5f8d0f84b2e5805c53b2ecdaa75e182fee606199e996cfb1bd98e75f84b` |
| `pyproject.toml` (`0.4.1`) | `23ef5239db489cdeaaa2ec5822ddaee6983af7ef84e26df67bc4f281fc2d8791` |
| `vulnclaw/__init__.py` | `66c0da0603d198818067bff0bb4c18d2604930d126cfae347e3f3b20c7cc5e71` |
| `vulnclaw/cli/main.py` | `8c1a5661d3df1cd2c4f28eaeb87dab1e588fffbd7ff44973d1b716a9cec8b3e9` |
| `vulnclaw/config/schema.py` | `45c6752ff912287985f186b01977f86e74c13ff1a7035a786784ff241a9796ee` |
| `vulnclaw/codescan/scanner.py` | `49162b2f455da4c5fa1d1b627a30aa12aff7274b3b5b6fc00d32369f31c8d6db` |
| `vulnclaw/codescan/rules.py` | `f7715a5dfb46bed9fbcc24d10c6794d437fffecada7c167fa7320c743e91a080` |
| `vulnclaw/codescan/report.py` | `c079faeafce72399bc6c170611cdd01812bd44b07cc273d93d7ea0a574d073fd` |

Post-install verification asserts via `importlib.util.find_spec()` that none of `chromadb`, `sentence_transformers`, `torch`, `mitmproxy`, `playwright`, or `reportlab` exist in the target Python environment.

---

## 4. Defense-in-Depth Sandbox & API Contract (`vulnclaw_worker.py`)

### 4.1 Authentication & Network Isolation
- Binds to `127.0.0.1:8660` by default (or internal Docker network `:8660` with zero public host port mapping).
- `POST /scan` fails closed (`HTTP 503` if `ALLINAGENT_INTERNAL_TOKEN` is unset on the server; `HTTP 401` if `X-Internal-Scan-Token` is missing or fails constant-time `_compare_digest` verification).
- `ALLINAGENT_INTERNAL_TOKEN` and all platform API/bot credentials are **never** inherited by the ephemeral scanner child subprocess (`_build_child_clean_env()`).

### 4.2 Defensive-Only Policy Enforcement
- **10 Blocked Offensive Capabilities (`HTTP 403 OFFENSIVE_CAPABILITY_BLOCKED`):**
  1. `exploit`
  2. `payload`
  3. `c2`
  4. `reverse_shell`
  5. `lateral_movement`
  6. `credential_dump`
  7. `privilege_escalation`
  8. `network_scan`
  9. `port_scan`
  10. `traffic_intercept`
- **Runtime Tool & MCP Neutralization:**
  - Disables `BUILTIN_MCP_SERVERS` (`fetch`, `memory`, and all sibling entries) in `vulnclaw.config.schema` and blocks `vulnclaw.mcp*`, `vulnclaw.tools*`, `vulnclaw.recon*`, `vulnclaw.traffic*`, `vulnclaw.agent*`, and `vulnclaw.subagent*` via a `sys.meta_path` `MetaPathFinder` inside the child subprocess.
  - Permanently disables `python_execute` and blocks `L3` external LLM calls; permits static `L1` (regex + Shannon entropy) and `L2` (structural taint/sink) layers only.
  - Rejects any URL/network target (`http://`, `https://`, `tcp://`, `ssh://`) with `HTTP 403`.

### 4.3 Strict Workspace Path Jail & Resource Ceilings
- **Workspace Containment:** Every target must resolve inside `AUTHORIZED_WORKSPACES` (mounted `:ro` in production containers).
- **Blocked System & Secret Paths (`HTTP 403 PATH_JAIL_VIOLATION` + recursive walker skip):**
  - System paths: `/etc`, `/proc`, `/sys`, `/root`, `/var/run`, `/run`, `/boot`, `/dev`, and OS system directories.
  - Credential directories & files: `~/.ssh`, `.gnupg`, `.aws`, `.kube`, `secrets/`, `.env`, `.env.*` (allowing only `.env.example`, `.env.sample`, `.env.template`), `auth.json`, `office-bridge-auth.json`, `*.local.*`, `id_rsa*`, `id_ed25519*`, `*.pem`, `*.key`, `*.pfx`, `.git-credentials`, `.netrc`.
  - Upstream `vulnclaw.codescan.rules.ALWAYS_SCAN_FILES` has `".env"` explicitly removed inside the child subprocess before scanning so workspace `.env` files are **never** opened or read.
  - Symlinks (`followlinks=False`, `is_symlink()`) and `..` traversal segments are rejected to prevent git-committed symlink escape attacks.
- **Hard Resource Caps:**
  - `max_files = 250` (security-surface directories `routes/`, `controllers/`, `middleware/`, `auth/`, `api/`, `src/`, `app/` prioritized first)
  - `max_file_bytes = 1,048,576` (`1 MiB` per file)
  - `timeout_sec = 60` (`asyncio.wait_for` + immediate child process termination -> `HTTP 504`)
  - `max_output_bytes = 524,288` (`512 KiB` hard cap on serialized JSON + SARIF output)

### 4.4 `FindingsStore.ingest_finding()` & SARIF 2.1.0 Output Schema
- `POST /scan` returns:
  - `findings`: Sanitized, directive-neutralized records containing `source_reference: "vulnclaw_codescan"`, `project_id`, `asset_reference`, `finding_title`, `finding_description`, `severity`, `confidence` (clamped strictly to `[0.0, 1.0]`), `cwe_reference`, `cve_reference`, `affected_component` (workspace-relative `file:line`), `sanitized_evidence` (`[REDACTED_API_KEY]`, `[REDACTED_AWS_KEY]`, `[REDACTED_SECRET]`, `[DATA_LITERAL_DIRECTIVE_IGNORED]`), `remediation_recommendation`, `vuln_type`, `detection_layer`, and `owner: "security_reviewer"`.
  - `sarif`: Valid SARIF `2.1.0` document with workspace-relative `artifactLocation.uri` and sanitized `properties.evidence`.

---

## 5. Empirical Verification Summary

All verification suites executed cleanly with `0` errors and `0` mutations outside authorized scope:

1. **Bytecode Compilation (`py_compile`):**
   - `python -m py_compile components/vulnclaw/__init__.py components/vulnclaw/bootstrap_vulnclaw.py components/vulnclaw/vulnclaw_worker.py` -> **`PASS` (exit `0`)**.
2. **Upstream Supply-Chain Checksum & License Verification (`bootstrap_vulnclaw.py --verify-only`):**
   - Verified `git rev-parse HEAD == 0b34878f84b089b21fcf85ecd445315f14df0672`, `version == "0.4.1"`, `MIT` license, `requirements-defensive.txt` 9-package manifest, and all `8 / 8` LF-normalized SHA-256 checksums -> **`PASS`**.
3. **End-to-End Standalone Worker Self-Test (`vulnclaw_worker.py self-test`):**
   - Standalone `serve` daemon idle RSS: **`21.10 MiB`** (`< 25.0 MiB` budget) in pure-stdlib mode; **`21.23 MiB`** with `vulnclaw-venv` (`pydantic` schema mode).
   - Post-scan daemon RSS after child subprocess exit: **`21.33 MiB`** / **`21.27 MiB`** (`subprocess_memory_reclaimed: true`).
   - Authentication checks: missing token -> **`HTTP 401`**; invalid token -> **`HTTP 401`**.
   - Policy checks: all `10` offensive capabilities + `fetch` + `memory` + `python_execute` + `enable_python_execute=true` + `L3` -> **`HTTP 403`**.
   - Path jail checks: `/etc/passwd`, `/proc/self/environ`, `/sys/kernel`, `/root/.bashrc`, `/var/run/docker.sock`, `~/.ssh/id_rsa`, `../outside`, `.env`, `auth.json`, `office-bridge-auth.json` -> **`HTTP 403`**.
   - Real `L1` + `L2` static scan against synthetic vulnerable snippet in `<SCRATCH_DIR>`: detected `6` findings across `["L1", "L2"]` (`hardcoded_openai_key`, `dangerous_eval`, `sql_string_concat`, `command_injection`, `insecure_deserialization`) in `11.9 ms`, skipped `.env` decoy (`skipped_secrets: 1`) and `> 1 MiB` decoy (`skipped_oversize: 1`), redacted credential literals (`[REDACTED_API_KEY]`), and emitted `6` valid SARIF `2.1.0` results -> **`PASS`**.
4. **`FindingsStore.ingest_finding()` & Resource Cap Integration Tests:**
   - CLI `vulnclaw_worker.py scan` output piped directly into `FindingsStore.ingest_finding()`: `5 / 5` findings imported (`IMPORTED`) and repeat ingestion deduplicated (`deduplicated: true`) -> **`PASS`**.
   - `max_files` truncation (`--max-files 3` on `6` files -> `files_scanned: 3, truncated_by_max_files: true`) and `512 KiB` output cap (`398,975 <= 524,288` bytes, `output_truncated: true`) -> **`PASS`**.
