# ALLINAGENT — Sandboxed Project Workspaces (`/workspaces`)

This directory is the default **authorized workspace root** (`ALLOWED_WORKSPACE_ROOTS`) for all **ALLINAGENT** services, including:

- **Hermes3D / 2D Pixel Office Folder Picker** (`TargetFolderPickerModal`)
- **Telegram Control Center** (`/folder`, `/analisis`, `/create_task`, `/security_report`)
- **11-Agent Paperclip Engineering & Security Organization** (`ceo_agent` through `compliance_reporter`)
- **VulnClaw Defensive Static Code Scanner** (`codescan` layers `L1` and `L2`)

---

## 1. Workspace Sandboxing (`ALLOWED_WORKSPACE_ROOTS`)

ALLINAGENT enforces a strict zero-trust filesystem boundary across Office Bridge, Hermes worker profiles, and the isolated VulnClaw defensive runner:

1. **Explicit Allowlist (`ALLOWED_WORKSPACE_ROOTS`):**
   - Only directories listed in `ALLOWED_WORKSPACE_ROOTS` (comma- or colon-separated absolute paths; defaults to `/workspaces` inside Docker containers and `<ALLINAGENT_ROOT>/workspaces` on bare-metal installs) can be browsed, pinned, analyzed, edited on isolated Git branches, or scanned.
   - Every candidate path is canonicalized with `os.path.realpath` / `path.resolve` before access. Symlinks, NTFS junctions, or `..` segments that escape an allowed workspace root are rejected with `HTTP 403` / `PermissionError`.
2. **Hard Denylist of Platform & OS Zones:**
   - Even if a parent directory is mounted, ALLINAGENT unconditionally blocks access to:
     - `/data/hermes` and `~/.hermes` (Owner gateway credentials, pairing state, and worker profile `.env` tokens)
     - `/opt/allinagent/config/secrets` and Paperclip `secrets/master.key`
     - System directories (`/etc`, `/proc`, `/sys`, `/var/run/docker.sock`, `/root`, `C:\Windows`, `~/.ssh`)
3. **Concurrent Multi-Agent Isolation & Least-Privilege Toolsets:**
   - Pure review & triage roles (`security_lead`, `security_reviewer`, `findings_analyst`, `remediation_reviewer`) receive only the `file` and `skills` toolsets (`terminal` disabled).
   - `compliance_reporter` (`agents/compliance`) has `file`, `terminal`, and `skills` enabled (matching `agents/compliance/AGENTS.md`) to generate deterministic PDF and DOCX compliance reports into `/data/reports/` without modifying target source repositories.
   - Executive, implementation, and QA roles (`ceo_agent`, `cto_agent`, `backend_developer`, `frontend_developer`, `devops_engineer`, `qa_engineer`) receive `file`, `terminal`, and `skills`, with implementation roles operating on isolated Git branches/worktrees coordinated by atomic workspace lockfiles (`O_CREAT | O_EXCL`).

---

## 2. Mounting Your Own Projects in Docker (`/workspaces`)

In production Docker deployments (`/opt/allinagent`), bind-mount the host directories you want agents to inspect or collaborate on under `/workspaces` using `docker-compose.override.yml`:

```yaml
services:
  office-bridge:
    environment:
      ALLOWED_WORKSPACE_ROOTS: "/workspaces"
    volumes:
      - ./workspaces:/workspaces:rw
      # Optional: mount an external repository read-only for audits & /analisis
      # - /srv/projects/payments-service:/workspaces/payments-service:ro

  paperclip:
    environment:
      ALLOWED_WORKSPACE_ROOTS: "/workspaces"
    volumes:
      - ./workspaces:/workspaces:rw
      # - /srv/projects/payments-service:/workspaces/payments-service:ro

  vulnclaw:
    environment:
      ALLOWED_WORKSPACE_ROOTS: "/workspaces"
    volumes:
      # VulnClaw defensive static scanner only ever requires read-only source access
      - ./workspaces:/workspaces:ro
```

> **Tip:** Mount repositories `:ro` (read-only) when you only want architectural reviews (`/analisis`) or defensive security audits without code modifications. Mount `:rw` when delegating feature implementation, bug fixes, or branch-isolated security remediations.

---

## 3. Zero-Trust Secret Exclusion (`.env*` Hidden & Blocked)

ALLINAGENT enforces defense-in-depth so repository secrets inside user projects are never exposed to UI clients, logs, Telegram chats, or LLM prompts:

- **Hidden in Folder Picker & Directory Listings:** `.env`, `.env.*` (such as `.env.local`, `.env.production`, `.env.staging`), `*.pem`, `*.key`, `*.pfx`, `id_rsa`, `id_ed25519`, and `*secret*` files are filtered out of directory browser responses. Safe `.env.example` templates remain visible so agents understand required configuration keys without seeing secret values.
- **Blocked at Read & Scan Boundaries:** Direct read requests via `inspectWorkspaceEvidence` or `validate_authorized_scan_path` against `.env` or private key files immediately fail with `403 Forbidden` / `PermissionError`.
- **Automatic Output Redaction:** All evidence snippets, test outputs, and static-analysis findings pass through deterministic secret redaction (`[REDACTED_API_KEY]`, `[REDACTED_BOT_TOKEN]`, `[REDACTED_TOKEN]`, `[REDACTED_SECRET]`) prior to persistence in `findings.db` or delivery over WebSocket/Telegram.
- **Git Exclusion:** `.gitignore` and `.dockerignore` keep user repositories under `workspaces/*` (except this `README.md` and the public `workspaces/sample-project/` fixture) out of Git commits and container build contexts.

---

## 4. Included Public Fixture: `workspaces/sample-project` (`order-billing-demo`)

Right after `git clone`, `workspaces/sample-project/` provides a clean, **MIT-licensed**, zero-dependency polyglot microservice fixture (`order-billing-demo`: Python 3 REST & SQLite service + Node.js ES module UI billing widget + OpenAPI 3.1 contract + gated synthetic sandbox fixture) so you can verify every platform workflow immediately:

| Capability | How to Test on `workspaces/sample-project` | Expected Result |
| :--- | :--- | :--- |
| **Folder Picker** | Open Enterprise Command Center Overlay $\rightarrow$ **Select Target Folder** $\rightarrow$ choose `/workspaces/sample-project` | Auto-detects `Python` + `Node.js / NPM` stack and `has_test_suite: true`, hiding any `.env` file |
| **Source Analysis (`/analisis`)** | Run `/analisis sample-project` in Telegram or Command Center | Summarizes REST routes, integer-cents billing engine, SQLite repository, and OpenAPI 3.1 spec |
| **11-Agent Collaborative Review** | Create a task or standup targeting `workspaces/sample-project` | CEO plans subtasks; CTO, Backend, Frontend, QA, and Security roles review in parallel |
| **QA Unit Tests** | `python3 -m unittest discover -s workspaces/sample-project/tests -p "test_*.py"` and `node --test workspaces/sample-project/tests/ui_contract.test.mjs` | 100% passing unit & contract suites with zero external package installs |
| **Defensive VulnClaw Scan** | Trigger defensive `codescan` on `workspaces/sample-project` | Detects intentional inert benchmark findings (`CWE-489`, `CWE-89`, `CWE-327`) in `config/sandbox-fixture.yaml` and `src/sandbox_audit_fixture.py` for SOC triage testing |
