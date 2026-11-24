# PHASE 13 — GitHub Skill Registry & Two-Stage Security Gate

- **Phase ID:** `PHASE-13`
- **Status:** `PASS`
- **Component Scope:** `skills/manifests/skills.lock.json`, `skills/manifests/skill-security-results.json`, `skills/policies/skill-policy.json`, `skills/install_agent_skills.py`, `apps/control-center/control_center/agent_skills_manager.py`
- **Verification Runtime:** `install_agent_skills.py --verify-manifest` + Stage-1 Quarantine & AST Security Gate unit tests (`tests/test_control_center_and_skills.py`)

---

## 1. Executive Summary

ALLINAGENT implements a reproducible, zero-vendored-bloat **GitHub Skill Registry & Two-Stage Security Gate** governing all **33 skill packages** across **10 upstream GitHub repositories**. Every skill package is pinned to an immutable 40-character Git commit SHA, verified against per-file and package-level SHA-256 digests (`upstream_package_sha256`), scanned by `getsentry/skills` `skill-scanner` (`scan_skill.py`) plus a recursive Python `ast` dangerous-pattern analyzer before promotion to `reviewed/`, and governed by strict license redistribution rules (`FETCH_FROM_UPSTREAM_ONLY` + permissive MIT `strict_oss_fallback`).

---

## 2. Lockfile, Quarantine & License Governance (`skills.lock.json` & `skill-policy.json`)

1. **Complete Pinning & Cryptographic Integrity:**
   - **33 packages** across **10 upstream repositories**, 100% pinned to 40-character lowercase commit SHAs (`unpinned_commits: []`, `invalid_package_sha256: []`).
   - Records both individual `file_sha256s` and deterministic `upstream_package_sha256` (`sha256("path:file_sha256\n"...)`).
2. **Quarantined File Exclusions (`11` Offensive / Bootstrap Files Removed):**
   - Explicitly removed from package `files` arrays and recorded under `"quarantined_excluded_files"` in both `skills.lock.json` and `skill-policy.json`:
     - `secondsky-cybersecurity-ref` (`10` files): `references/aradotso-agent-safety.md`, `references/aradotso-ai-security.md`, `references/aradotso-code-audit.md`, `references/aradotso-compliance.md`, `references/aradotso-web-vuln-testing.md`, `references/testing-business-logic.md`, `references/testing-forced-browsing.md`, `references/testing-host-header.md`, `references/testing-open-redirect.md`, `references/testing-xss.md`.
     - `threat-model` (`1` file): `bootstrap.md` (deprecated autonomous harness bootstrap).
3. **License Redistribution Boundaries (`13` `FETCH_FROM_UPSTREAM_ONLY` Packages):**
   - Marked `"redistribution_policy": "FETCH_FROM_UPSTREAM_ONLY"` (never bundled in Git or GHCR container layers; fetched directly into the host volume during `./allinagent setup`):
     - All `10` packages from `borghei/Claude-Skills` (`MIT-Commons-Clause-1.0`).
     - `1` package from `vercel-labs/agent-skills` (`react-best-practices`, `MIT-Check-Skill-Header`).
     - `2` packages from `anthropics/skills` (`docx` and `pdf`).
   - Permissive MIT fallbacks recorded under `"strict_oss_fallback"` for `--strict-oss` and `--offline` installations:
     - `docx` $\rightarrow$ `productivity/microsoft-office` (`MIT`, Nous Research Hermes bundled skill).
     - `pdf` $\rightarrow$ `productivity/pdf` (`MIT`, Nous Research Hermes bundled skill).
4. **Runtime Classification Enforcement (`skill-policy.json`):**
   - Enforces `locked: true`, `pinned: true`, `block_arbitrary_remote_skill_installs: true`, and `allow_agent_self_skill_mutation: false`.
   - Keeps `cve-triage` strictly `EXPERIMENTAL` (isolated under `agents/findings/experimental/cve-triage`; never auto-activated in Paperclip/Hermes runtime without `--enable-experimental`).
   - Keeps `threat-model`, `secondsky-cybersecurity-ref`, `anthropic-triage`, and `anthropic-patch` strictly `REFERENCE_ONLY` (isolated under `agents/<role>/references/<pkg>`).

---

## 3. Stage-1 Security Gate Architecture

1. **Bootstrap Verification First:** Downloads `getsentry/skills` `skill-scanner` @ `a582c51ee29d0f35e6ac321340796f77d43da733`, verifies its SHA-256 (`a51d7dceaa0778b2d17dac89d83fde191260b26ecdad566a85ff51c0441b19db`), runs `ast_scan_python_tree` on `scripts/scan_skill.py`, and promotes it to `<SKILL_REGISTRY_DIR>/reviewed/skill-scanner`.
2. **Five-Layer Package Gate (Before Promotion to `reviewed/`):**
   - **Layer 1 (Quarantine Blocklist):** Rejects any staged directory containing any of the 11 excluded files.
   - **Layer 2 (Symlink Escape Guard):** Rejects any symlink resolving outside the staged skill directory.
   - **Layer 3 (Per-File & Package SHA-256):** Verifies every file digest and overall `upstream_package_sha256`.
   - **Layer 4 (Recursive Python AST Scanner):** Parses every `.py` file recursively (`rglob("*.py")`) with `ast.parse` and flags `eval()`, `exec()`, `os.system()`, `os.popen()`, `pty.spawn()`, `pickle.loads()`, `marshal.loads()`, and `subprocess.*(..., shell=True)`.
   - **Layer 5 (Sentry `scan_skill.py`):** Scans frontmatter, prompt injection, Unicode Tag / zero-width / RTL obfuscation, hardcoded secrets, lifecycle hooks, and image metadata against the reviewed baseline.
3. **Automatic Quarantine on Failure:** Any failing or tampered staged directory is moved atomically into `<SKILL_REGISTRY_DIR>/quarantine/<pkg_id>-<timestamp>/` with a structured `QUARANTINE_REASON.json` audit record, raising `SecurityGateError`.

---

## 4. Verification Evidence

- `skills/install_agent_skills.py --verify-manifest` output:
  ```json
  {
    "ok": true,
    "packages_count": 33,
    "repositories_count": 10,
    "roles_count": 11,
    "quarantined_excluded_files_count": 11,
    "fetch_from_upstream_only_count": 13,
    "missing_package_refs": [],
    "unpinned_commits": [],
    "invalid_package_sha256": [],
    "unauthorized_repos": [],
    "leaked_quarantined_files": [],
    "policy_violations": []
  }
  ```
- Automated negative security tests (`test_06_skill_registry_stage1_quarantine_and_stage2_materialization`): verified deterministic detection and quarantine of SHA-256 mismatches and AST `eval()` / `subprocess.run(..., shell=True)` payloads.
