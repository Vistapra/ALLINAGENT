# PHASE 06 — Software Supply Chain & Open-Source License Review

- **Phase ID:** `PHASE-06`
- **Status:** `PASS`
- **Timestamp (UTC):** `2026-11-24T10:32:00Z`
- **Prerequisites Satisfied:** `PHASE-04` (Upstream Source & Custom Patch Preservation), `PHASE-05` (Build Lightweight ALLINAGENT Repository)

---

## 1. Executive Summary

`PHASE-06` establishes end-to-end open-source license compliance, immutable upstream provenance pinning, CycloneDX 1.5 Software Bill of Materials (SBOM) generation, and an automated fail-closed public release auditor for **ALLINAGENT**:

1. **Permissive First-Party & Core Upstream Licensing (`100% MIT`):**
   - First-party ALLINAGENT code is licensed under **MIT** ([`LICENSE`](../../LICENSE)).
   - All four core upstream projects (`hermes-agent`, `paperclip`, `vulnclaw`, `hermes3d`) are licensed under **MIT**, pinned to exact 40-character Git commit SHAs in [`components.lock.json`](../../components.lock.json), and attributed in [`THIRD-PARTY-NOTICES.md`](../../THIRD-PARTY-NOTICES.md).
2. **Zero Copyleft Contamination & Zero Restricted Skill Bundling:**
   - All 10 upstream GitHub Agent Skill repositories (`33` skill packages) were audited and cataloged in [`LICENSE-INVENTORY.json`](../../LICENSE-INVENTORY.json):
     - **`22` packages (`8` repos)** use permissive `MIT` or `Apache-2.0` licenses (`ALLOW_WITH_ATTRIBUTION_OR_FETCH`).
     - **`10` packages (`borghei/Claude-Skills`)** use **`Commons Clause License Condition v1.0 + MIT`**, and **`1` package (`vercel-labs/agent-skills`)** lacks a standalone root `LICENSE` file. All `11` restricted/unlicensed packages are classified **`FETCH_FROM_UPSTREAM_ONLY`** and excluded from Git and GHCR container layers via `.gitignore`, `.dockerignore`, and CI release gates (`0` restricted files bundled).
3. **Deterministic CycloneDX 1.5 SBOM & Automated Public Release Gate:**
   - [`scripts/generate-sbom.py`](../../scripts/generate-sbom.py) builds and validates a CycloneDX 1.5 BOM (`bomFormat: "CycloneDX"`, `specVersion: "1.5"`) across `components.lock.json`, skill lock manifests, `package.json` files, and Python manifests using pure Python standard library modules.
   - [`scripts/audit-public-release.py`](../../scripts/audit-public-release.py) enforces secret/token scanning (with automatic match redaction and zero secret-file reads), Windows/legacy path rejection, fail-closed `.env.example` verification, `git ls-files` hygiene, `--strict-clean-tree`, external private blocklist support (`ALLINAGENT_PRIVATE_BLOCKLIST_FILE`), and salted/unsalted SHA-256 private identifier hash matching (`ALLINAGENT_PRIVATE_HASH_FILE`).

---

## 2. Upstream Provenance & License Compliance Matrix

### 2.1 Core Platform Upstreams (`4 / 4 MIT`)

| Component | Upstream Repository | Pinned Version / Package | Pinned 40-Char Commit SHA | License | Bundled in Git | Compliance Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `hermes-agent` | `https://github.com/NousResearch/hermes-agent.git` | `v0.23.3` | `eb49b8920a25ffa7bb2fadf548fe819221ca79d7` | `MIT` | `false` (shallow checkout + 1-line patch) | `COMPATIBLE` |
| `paperclip` | `https://github.com/paperclipai/paperclip.git` | `paperclipai@2026.1117.0` | `c0f132898d2a2677312d8c72096187b27a3d9a38` | `MIT` | `false` (locked npm install + adapter patch) | `COMPATIBLE` |
| `vulnclaw` | `https://github.com/Netw0rkNoob/VulnClaw.git` | `v0.4.1` | `0b34878f84b089b21fcf85ecd445315f14df0672` | `MIT` | `false` (isolated on-demand defensive runtime) | `COMPATIBLE` |
| `hermes3d` | `https://github.com/iamlukethedev/Hermes3D.git` | `v1.0.0` (base) | `beb76292747b816ef317aa6f9a3992e0014f81d9` | `MIT` | `true` (`./hermes3d` with MIT notice retained) | `COMPATIBLE` |

### 2.2 Role-Specific Agent Skill Repositories (`10` Repos, `33` Packages)

| Upstream Repository | Pinned 40-Char Commit SHA | License Classification | Packages | Redistribution Policy | Bundled in Repo / GHCR |
| :--- | :--- | :--- | ---: | :--- | :--- |
| `getsentry/skills` | `a582c51ee29d0f35e6ac321340796f77d43da733` | `Apache-2.0` | `1` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `false` |
| `alirezarezvani/claude-skills` | `5909a72e62b5fbb809935fb6a55b58bdbe175074` | `MIT` | `11` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `false` |
| `anthropics/skills` | `e4bb5d960d87126ff3b3a8af1a104b7db67560ba` | `Apache-2.0` | `3` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `false` |
| `anthropics/defending-code-reference-harness` | `d3bea6b5793b5f3d59a75ebe69a58efa88383145` | `Apache-2.0` | `3` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `false` |
| `antonbabenko/terraform-skill` | `f5a195992d84c8fb075b0176d666967cd07d2081` | `Apache-2.0` | `1` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `false` |
| `stacklok/toolhive-studio` | `4d87c91d49b881ccc7dc64667c1dce5a84c535d6` | `Apache-2.0` | `1` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `false` |
| `fedius01/cve-triage` | `3517c8fb10531103c403f09143966d62b2a0790f` | `MIT` | `1` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `false` |
| `secondsky/claude-skills` | `14966c3024f48eea0386eb970b230ea0f4bebd33` | `MIT` | `1` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `false` |
| `borghei/Claude-Skills` | `25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3` | `LicenseRef-MIT-Commons-Clause-1.0` | `10` | **`FETCH_FROM_UPSTREAM_ONLY`** | **`false` (Prohibited)** |
| `vercel-labs/agent-skills` | `5a37a6329fbad3666c3207392a6a7c0110e92efb` | `LicenseRef-Missing-Root-License` | `1` | **`FETCH_FROM_UPSTREAM_ONLY`** | **`false` (Prohibited)** |

---

## 3. Supply-Chain & Release Gate Tooling

### 3.1 CycloneDX 1.5 SBOM Generator ([`scripts/generate-sbom.py`](../../scripts/generate-sbom.py))

- **Inputs:** [`components.lock.json`](../../components.lock.json), `skills/manifests/skills.lock.json` (with fallback to `config/portable-skill-manifest.json` and [`LICENSE-INVENTORY.json`](../../LICENSE-INVENTORY.json)), all workspace `package.json` / `package-lock.json` files, and Python `pyproject.toml` / `requirements*.txt` files.
- **Compliance Validation (`--validate`):**
  - Verifies CycloneDX `1.5` header (`bomFormat`, `specVersion`, deterministic UUIDv5 `serialNumber`), unique `bom-ref` identifiers, complete `dependencies` graph integrity, 40-character commit SHAs on all core upstreams, SPDX `license.id` vs custom `license.name` separation, and zero restricted/copyleft components marked `bundled_in_git=true`.

### 3.2 Public Release Security & Privacy Auditor ([`scripts/audit-public-release.py`](../../scripts/audit-public-release.py))

- **Zero-Plaintext Design:** Contains **zero** hardcoded personal usernames, domains, Telegram IDs, IP addresses, or organization UUIDs. Supports external untracked blocklists (`--blocklist-file` / `ALLINAGENT_PRIVATE_BLOCKLIST_FILE`) and salted or unsalted SHA-256 hash files (`--hash-blocklist-file` / `ALLINAGENT_PRIVATE_HASH_FILE`).
- **Fail-Closed Detection Rules:**
  - `SEC-001..007`: OpenAI/Anthropic/OpenRouter keys, Telegram bot tokens, GitHub PATs, AWS/GCP/Slack/HF tokens, PEM private key blocks, internal `ob_tok_*` / `st_tok_*` / `pcp_*` tokens, and embedded DB passwords (with automatic snippet redaction).
  - `PORT-001..003`: Hardcoded Windows user profile paths, legacy platform directory paths (single or double backslash), and Windows `AppData` / `laragon` paths.
  - `AUTH-001` & `CFG-001..003`: Rejects placeholder 10-digit Telegram IDs and enforces blank credentials in `.env.example`.
  - `HYG-001..002` & `GIT-001..002`: Audits `git ls-files` against forbidden secret/runtime/dependency/binary globs without opening secret files, and enforces `--strict-clean-tree`.

---

## 4. Empirical Verification Evidence

| Verification Step | Executed Command | Empirical Output | Verdict |
| :--- | :--- | :--- | :--- |
| CycloneDX 1.5 SBOM Generation & Validation | `python scripts/generate-sbom.py --validate --output <scratch>/sbom.cdx.json` | `{"ok": true, "bomFormat": "CycloneDX", "specVersion": "1.5", "validation_errors": []}` | `PASS` |
| Public Release Auditor Synthetic Self-Test | `python scripts/audit-public-release.py --self-test` | `{"self_test": "PASSED", "verified_rules": ["AUTH-001", "CFG-002", "GIT-001", "GOV-001", "HYG-001", "PORT-001", "PORT-002", "PRIV-HASH-001", "PRIV-HASH-002", "SEC-001", "SEC-002", "SEC-005", "SEC-006"], "redaction_verified": true, "strict_clean_tree_verified": true}` | `PASS` |
| License Inventory Integrity Check | Verified `LICENSE`, `THIRD-PARTY-NOTICES.md`, `LICENSE-INVENTORY.json`, `licenses/README.md` | `copyleft_violations: 0`, `restricted_files_bundled: 0`, `4 / 4` core upstreams MIT, `11 / 11` restricted skills `FETCH_FROM_UPSTREAM_ONLY` | `PASS` |
