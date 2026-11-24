# ALLINAGENT — Role-Specialized Agent Skills Catalog

`ALLINAGENT` equips its 11 corporate AI agents with **33 security-vetted, SHA-256-verified skill packages** sourced from **10 pinned upstream GitHub repositories** (`skills/manifests/skills.lock.json` and `skills/policies/skill-policy.json`). Rather than dumping every skill into a single global folder, skills are strictly scoped per role (`PRIMARY`, `SPECIALIST`, `ON_DEMAND`, `REFERENCE_ONLY`, and `EXPERIMENTAL`), synchronized through the **Paperclip Skills Store**, and locked against runtime self-modification via `.usage.json`.

Related documentation:
- [`SKILL-SUPPLY-CHAIN.md`](./SKILL-SUPPLY-CHAIN.md) — 40-char SHA pinning, SHA-256 verification, Sentry `skill-scanner` + AST gate, quarantine ledger, and `FETCH_FROM_UPSTREAM_ONLY` legal isolation
- [`AGENTS.md`](./AGENTS.md) — 11-agent hierarchy, toolset boundaries, and isolated `pc*` profiles
- [`THIRD-PARTY-NOTICES.md`](./THIRD-PARTY-NOTICES.md) — Upstream copyright and SPDX license attributions

---

## 1. Quantitative Overview

| Metric | Count | Details |
| :--- | :---: | :--- |
| **Total Unique Skill Packages** | **`33`** | Defined in `skills/manifests/skills.lock.json` (`schema_version: "2.0.0"`) |
| **Pinned Upstream GitHub Repositories** | **`10`** | Locked to immutable 40-character Git commit SHAs (zero floating branches/tags) |
| **Corporate Agents Specialized** | **`11 / 11`** | `pcceoagent` through `pccompliancereporter` |
| **Runtime Production Packages (`PRIMARY` + `SPECIALIST` + `ON_DEMAND`)** | **`27`** | `23` active (`PRIMARY` + `SPECIALIST`) + `4` unique `ON_DEMAND`-only (`cto-advisor`, `pw-fix`, `pw-coverage`, `pw-report`; `senior-architect` is `SPECIALIST` on CTO and `ON_DEMAND` on Backend) |
| **Methodology Reference Packages (`REFERENCE_ONLY`)** | **`4`** | `threat-model`, `secondsky-cybersecurity-ref`, `anthropic-triage`, `anthropic-patch` |
| **Opt-In Experimental Packages (`EXPERIMENTAL`)** | **`1`** | `cve-triage` (disabled in Paperclip runtime unless `--enable-experimental` is passed) |
| **Pipeline Supply-Chain Security Gate (`SECURITY_GATE`)** | **`1`** | `skill-scanner` (`getsentry/skills` — executes during setup/CI, not assigned to worker chat) |
| **`FETCH_FROM_UPSTREAM_ONLY` Packages** | **`13`** | Never bundled in Git or GHCR; fetched directly at setup time with MIT `--strict-oss` / `--offline` fallbacks for `docx` & `pdf` |

---

## 2. Complete 33-Package Catalog Across 10 Upstream Repositories

### 2.1 Upstream Repository Index

| # | Repository (`owner/name`) | Pinned 40-Character Commit SHA | License (SPDX) | Packages (`33` Total) |
| :---: | :--- | :--- | :--- | :--- |
| `01` | `getsentry/skills` | `a582c51ee29d0f35e6ac321340796f77d43da733` | `Apache-2.0` | `skill-scanner` (`1`) |
| `02` | `alirezarezvani/claude-skills` | `5909a72e62b5fbb809935fb6a55b58bdbe175074` | `MIT` | `ceo-advisor`, `c-level-skills`, `cto-review`, `ciso-advisor`, `compliance-os`, `pw`, `pw-generate`, `pw-review`, `pw-fix`, `pw-coverage`, `pw-report` (`11`) |
| `03` | `borghei/Claude-Skills` | `25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3` | `MIT-Commons-Clause-1.0` | `api-design-reviewer`, `ci-cd-pipeline-builder`, `cto-advisor`, `focused-fix`, `security-audit`, `senior-architect`, `senior-backend`, `senior-devops`, `senior-qa`, `senior-security` (`10`) |
| `04` | `anthropics/skills` | `e4bb5d960d87126ff3b3a8af1a104b7db67560ba` | `Apache-2.0` | `frontend-design`, `docx`, `pdf` (`3`) |
| `05` | `anthropics/defending-code-reference-harness` | `d3bea6b5793b5f3d59a75ebe69a58efa88383145` | `Apache-2.0` | `threat-model`, `anthropic-triage`, `anthropic-patch` (`3`) |
| `06` | `antonbabenko/terraform-skill` | `f5a195992d84c8fb075b0176d666967cd07d2081` | `Apache-2.0` | `terraform-skill` (`1`) |
| `07` | `stacklok/toolhive-studio` | `4d87c91d49b881ccc7dc64667c1dce5a84c535d6` | `Apache-2.0` | `security-vuln-remediation` (`1`) |
| `08` | `fedius01/cve-triage` | `3517c8fb10531103c403f09143966d62b2a0790f` | `MIT` | `cve-triage` (`1`) |
| `09` | `secondsky/claude-skills` | `14966c3024f48eea0386eb970b230ea0f4bebd33` | `MIT` | `secondsky-cybersecurity-ref` (`1`) |
| `10` | `vercel-labs/agent-skills` | `5a37a6329fbad3666c3207392a6a7c0110e92efb` | `MIT-Check-Skill-Header` | `react-best-practices` (`1`) |

### 2.2 Master 33-Skill Package Matrix

| # | Package ID (`pkg_id`) | Display Name | Upstream Repo & Subpath | Tier / Disposition | Redistribution Policy | Assigned Agent(s) |
| :---: | :--- | :--- | :--- | :--- | :--- | :--- |
| `01` | `skill-scanner` | Sentry Skill Scanner | `getsentry/skills` (`skills/skill-scanner`) | `SECURITY_GATE` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | Stage-1 Supply-Chain Gate |
| `02` | `ceo-advisor` | CEO Advisor | `alirezarezvani/claude-skills` (`c-level-advisor/skills/ceo-advisor`) | `PRIMARY` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@ceo` |
| `03` | `c-level-skills` | C-Level Skills Router | `alirezarezvani/claude-skills` (`c-level-advisor/skills/c-level-skills`) | `SPECIALIST` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@ceo` |
| `04` | `cto-review` | CTO Review | `alirezarezvani/claude-skills` (`c-level-agents/skills/cto-review`) | `PRIMARY` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@cto` |
| `05` | `senior-architect` | Senior Architect | `borghei/Claude-Skills` (`engineering/senior-architect`) | `SPECIALIST` / `ON_DEMAND` | `FETCH_FROM_UPSTREAM_ONLY` | `@cto` (`SPECIALIST`), `@backend` (`ON_DEMAND`) |
| `06` | `cto-advisor` | CTO Advisor | `borghei/Claude-Skills` (`c-level-advisor/cto-advisor`) | `ON_DEMAND` | `FETCH_FROM_UPSTREAM_ONLY` | `@cto` |
| `07` | `senior-backend` | Senior Backend | `borghei/Claude-Skills` (`engineering/senior-backend`) | `PRIMARY` | `FETCH_FROM_UPSTREAM_ONLY` | `@backend` |
| `08` | `api-design-reviewer` | API Design Reviewer | `borghei/Claude-Skills` (`engineering/api-design-reviewer`) | `SPECIALIST` | `FETCH_FROM_UPSTREAM_ONLY` | `@backend` |
| `09` | `react-best-practices` | Vercel React Best Practices | `vercel-labs/agent-skills` (`skills/react-best-practices`) | `PRIMARY` | `FETCH_FROM_UPSTREAM_ONLY` | `@frontend` |
| `10` | `frontend-design` | Anthropic Frontend Design | `anthropics/skills` (`skills/frontend-design`) | `SPECIALIST` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@frontend` |
| `11` | `senior-devops` | Senior DevOps | `borghei/Claude-Skills` (`engineering/senior-devops`) | `PRIMARY` | `FETCH_FROM_UPSTREAM_ONLY` | `@devops` |
| `12` | `terraform-skill` | Terraform Skill | `antonbabenko/terraform-skill` (`skills/terraform-skill`) | `SPECIALIST` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@devops` |
| `13` | `ci-cd-pipeline-builder` | CI/CD Pipeline Builder | `borghei/Claude-Skills` (`engineering/ci-cd-pipeline-builder`) | `SPECIALIST` | `FETCH_FROM_UPSTREAM_ONLY` | `@devops` |
| `14` | `pw` | Playwright Pro Router | `alirezarezvani/claude-skills` (`engineering-team/playwright-pro/skills/pw`) | `PRIMARY` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@qa` |
| `15` | `pw-generate` | Playwright Generate | `alirezarezvani/claude-skills` (`engineering-team/playwright-pro/skills/generate`) | `SPECIALIST` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@qa` |
| `16` | `pw-review` | Playwright Review | `alirezarezvani/claude-skills` (`engineering-team/playwright-pro/skills/pw-review`) | `SPECIALIST` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@qa` |
| `17` | `senior-qa` | Senior QA | `borghei/Claude-Skills` (`engineering/senior-qa`) | `SPECIALIST` | `FETCH_FROM_UPSTREAM_ONLY` | `@qa` |
| `18` | `pw-fix` | Playwright Fix | `alirezarezvani/claude-skills` (`engineering-team/playwright-pro/skills/fix`) | `ON_DEMAND` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@qa` |
| `19` | `pw-coverage` | Playwright Coverage | `alirezarezvani/claude-skills` (`engineering-team/playwright-pro/skills/coverage`) | `ON_DEMAND` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@qa` |
| `20` | `pw-report` | Playwright Report | `alirezarezvani/claude-skills` (`engineering-team/playwright-pro/skills/report`) | `ON_DEMAND` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@qa` |
| `21` | `ciso-advisor` | CISO Advisor | `alirezarezvani/claude-skills` (`c-level-advisor/skills/ciso-advisor`) | `PRIMARY` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@security_lead` |
| `22` | `threat-model` | Anthropic Defensive Threat Model | `anthropics/defending-code-reference-harness` (`.claude/skills/threat-model`) | `REFERENCE_ONLY` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@security_lead` |
| `23` | `security-audit` | Security Audit | `borghei/Claude-Skills` (`engineering/security-audit`) | `PRIMARY` | `FETCH_FROM_UPSTREAM_ONLY` | `@security`, `@findings` |
| `24` | `senior-security` | Senior Security | `borghei/Claude-Skills` (`engineering/senior-security`) | `SPECIALIST` | `FETCH_FROM_UPSTREAM_ONLY` | `@security` |
| `25` | `secondsky-cybersecurity-ref` | SecondSky Cybersecurity (Sanitized) | `secondsky/claude-skills` (`plugins/cybersecurity/skills/cybersecurity`) | `REFERENCE_ONLY` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@security` |
| `26` | `anthropic-triage` | Anthropic Defensive Triage | `anthropics/defending-code-reference-harness` (`.claude/skills/triage`) | `REFERENCE_ONLY` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@findings` |
| `27` | `cve-triage` | CVE Triage (Experimental) | `fedius01/cve-triage` (`skill`) | `EXPERIMENTAL` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@findings` |
| `28` | `focused-fix` | Focused Fix | `borghei/Claude-Skills` (`engineering/focused-fix`) | `PRIMARY` | `FETCH_FROM_UPSTREAM_ONLY` | `@remediation` |
| `29` | `security-vuln-remediation` | Security Vulnerability Remediation | `stacklok/toolhive-studio` (`.claude/skills/security-vuln-remediation`) | `SPECIALIST` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@remediation` |
| `30` | `anthropic-patch` | Anthropic Defensive Patch Verification | `anthropics/defending-code-reference-harness` (`.claude/skills/patch`) | `REFERENCE_ONLY` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@remediation` |
| `31` | `compliance-os` | Compliance OS | `alirezarezvani/claude-skills` (`compliance-os/skills/compliance-os`) | `PRIMARY` | `ALLOW_WITH_ATTRIBUTION_OR_FETCH` | `@compliance` |
| `32` | `docx` | Anthropic DOCX *(+ MIT Fallback)* | `anthropics/skills` (`skills/docx`) | `SPECIALIST` | `FETCH_FROM_UPSTREAM_ONLY` | `@compliance` |
| `33` | `pdf` | Anthropic PDF *(+ MIT Fallback)* | `anthropics/skills` (`skills/pdf`) | `SPECIALIST` | `FETCH_FROM_UPSTREAM_ONLY` | `@compliance` |

---

## 3. Per-Agent Specialization & Progressive Disclosure Routing

Every agent also retains the 3 core Paperclip coordination skills (`paperclip`, `complain`, `suggestion-box`). When an agent begins a task matching its domain, its `SOUL.md` / `AGENTS.md` routing block instructs it to invoke `skill_view(name='<skill>')` first (progressive disclosure), loading only the specific `references/*.md` or `scripts/*.py` files required for that turn.

| # | Agent (`@handle` / Profile) | `PRIMARY` | `SPECIALIST` | `ON_DEMAND` | `REFERENCE_ONLY` / `EXPERIMENTAL` | Key Helper Scripts & Domain Guardrails |
| :---: | :--- | :--- | :--- | :--- | :--- | :--- |
| `01` | **CEO Agent** (`@ceo` / `pcceoagent`) | `ceo-advisor` | `c-level-skills` | — | — | `strategy_analyzer.py`, `financial_scenario_analyzer.py`, plus `references/paperclip-11-agent-routing.md`. Delegates; never edits app code directly. |
| `02` | **CTO Agent** (`@cto` / `pcctoagent`) | `cto-review` | `senior-architect` | `cto-advisor` | — | `architecture_diagram_generator.py`, `dependency_analyzer.py`, `tech_debt_analyzer.py`, `team_scaling_calculator.py`. Produces ADRs & independent reviews. |
| `03` | **Backend Developer** (`@backend` / `pcbackenddeveloper`) | `senior-backend` | `api-design-reviewer` | `senior-architect` | — | `api_linter.py`, `api_scorecard.py`, `breaking_change_detector.py`. Enforces `LARAVEL-COMPATIBILITY.md` (detects PHP/Laravel vs Node/TS first; never touches `.env`). |
| `04` | **Frontend Developer** (`@frontend` / `pcfrontenddeveloper`) | `react-best-practices` | `frontend-design` | — | — | 72 granular `rules/*.md` performance patterns (async waterfalls, bundle splitting, memoization, hydration) + accessible responsive design. |
| `05` | **DevOps Engineer** (`@devops` / `pcdevopsengineer`) | `senior-devops` | `terraform-skill`, `ci-cd-pipeline-builder` | — | — | `pipeline_generator.py`, `pipeline_linter.py`, `cache_optimizer.py`, Terraform HCL references. Never executes `terraform apply` without Owner approval. |
| `06` | **QA Engineer** (`@qa` / `pcqaengineer`) | `pw` | `pw-generate`, `pw-review`, `senior-qa` | `pw-fix`, `pw-coverage`, `pw-report` | — | `test_suite_generator.py`, `coverage_analyzer.py`, `e2e_test_scaffolder.py` + 55 Playwright templates. Uses fresh headless browser context only. |
| `07` | **Security Lead** (`@security_lead` / `pcsecuritylead`) | `ciso-advisor` | — | — | Ref: `threat-model` | `risk_quantifier.py`, `compliance_tracker.py` *(read-only reference in `file,skills` mode)* + asset/trust-boundary threat modeling. |
| `08` | **Security Reviewer** (`@security` / `pcsecurityreviewer`) | `security-audit` | `senior-security` | — | Ref: `secondsky-cybersecurity-ref` | OWASP auth/authz/crypto review, coverage ledger & false-positive separation. Strictly read-only (`file,skills`). |
| `09` | **Findings Analyst** (`@findings` / `pcfindingsanalyst`) | `security-audit` | — | — | Ref: `anthropic-triage`<br>Exp: `cve-triage` | Candidate deduplication & confidence classification. `cve-triage` (SSVC/OpenVEX/CycloneDX VEX) stays isolated unless `--enable-experimental` is passed. |
| `10` | **Remediation Reviewer** (`@remediation` / `pcremediationreviewer`) | `focused-fix` | `security-vuln-remediation` | — | Ref: `anthropic-patch` | Minimal-diff scope verification & least-invasive dependency fix review (`RESOLVED` vs `REWORK_REQUIRED`). |
| `11` | **Report & Compliance Agent** (`@compliance` / `pccompliancereporter`) | `compliance-os` | `docx`, `pdf` | — | — | `framework_selector.py`, `cross_framework_mapper.py`, `evidence_pool_generator.py`, `audit_simulator.py` + `.docx`/`.pdf` generation (`python-docx`, `reportlab`, `pypdf`, `pdfplumber`). Disables bundled `productivity/pdf` when upstream `pdf` is installed to prevent name collision. |

---

## 4. `--strict-oss` and `--offline` MIT Fallback (`docx` & `pdf`)

To guarantee 100% document and report generation capability in air-gapped environments (`--offline`) or strict permissive-only deployments (`--strict-oss` where `FETCH_FROM_UPSTREAM_ONLY` downloads are skipped), `skills/policies/skill-policy.json` defines automatic MIT fallbacks provided by **Nous Research** inside the pinned `hermes-agent` runtime:

| Upstream Package (`FETCH_FROM_UPSTREAM_ONLY`) | `--strict-oss` / `--offline` Bundled Fallback | Fallback License & Provider | Runtime Behavior on `pccompliancereporter` |
| :--- | :--- | :--- | :--- |
| `docx` (`anthropics/skills/skills/docx`) | `productivity/microsoft-office` | **`MIT`** — Nous Research (Hermes Bundled Skill) | Automatically retained and routed for `.docx` / Office document creation and XML validation using `python-docx` in `/opt/hermes-venv`. |
| `pdf` (`anthropics/skills/skills/pdf`) | `productivity/pdf` | **`MIT`** — Nous Research (Hermes Bundled Skill) | `keep_bundled_skill_enabled: true` keeps Hermes's native `productivity/pdf` active (instead of archiving/disabling it), backed by permissive `reportlab`, `pypdf`, and `pdfplumber` (zero AGPL `pymupdf` or GPL `marker-pdf`). |

---

## 5. Paperclip Skills Store Sync & `.usage.json` Runtime Lock

### 5.1 Paperclip Skills Store Reconciliation
1. **Verified Registry Workspace:** `agent_skills_manager.py` registers `data/skill-registry/reviewed` as the primary workspace of the `Central Verified Skill Registry` project in Paperclip.
2. **Metadata-Tagged Import:** Each reviewed `PRIMARY`, `SPECIALIST`, and `ON_DEMAND` package is imported via `POST /api/companies/<company_id>/skills/import` and annotated with `pinnedCommitSha`, `repoUrl`, `licenseSpdx`, `packageSha256`, and `securityGate: "PASS"`.
3. **Exact Per-Agent Sync:** `POST /api/agents/<agent_id>/skills/sync` (`mode: "replace"`) binds **only** the core Paperclip skills (`paperclip`, `complain`, `suggestion-box`) plus that specific agent's assigned role skills.
4. **Patched Adapter Link Preservation:** `patches/paperclip/@paperclipai+hermes-paperclip-adapter+2026.1117.0.patch` updates `reconcileHermesPaperclipSkills` (`skills.js`) to recognize `skill-registry` paths and `--` namespaced directories (`<pkg_id>--<hash>`) as managed origins, using POSIX symlinks on Linux and falling back cleanly to `materializePaperclipSkillCopy` on `EPERM`/`ENOSYS`.

### 5.2 `.usage.json` Immutability Guard (`locked: true, pinned: true`)
Every materialized skill entry in `<HERMES_HOME>/profiles/<pc*>/skills/.usage.json` (both `<pkg_id>` and `<pkg_id>--<hash>`) is written with:

```json
{
  "senior-backend": {
    "state": "active",
    "pinned": true,
    "locked": true
  }
}
```

- Setting `"locked": true` and `"pinned": true` activates Hermes's native `_locked_guard`, blocking `skill_manage` create/edit/delete/overwrite calls from inside any agent turn (`allow_agent_self_skill_mutation: false`).
- `.skills_prompt_snapshot.json` is invalidated automatically during skill reconciliation so the next turn immediately reflects the verified skill index.

---

## 6. Inspecting & Verifying Skills

### Via Telegram Control Center (Read-Only)
- `/daftar-skill` *(or `/skill-agen [agent]`)* — Lists specialized skills across all 11 agents or for a specific `@handle`.
- `/skill-info <agent> [skill]` — Displays upstream GitHub URL, 40-char commit SHA, SPDX license, SHA-256 digest, helper scripts count, and last-used timestamp.
- `/skill-status` — Displays global skill registry state, Sentry `skill-scanner` gate verdict, and quarantine counts.

### Via CLI
```bash
# Validate lockfile 40-char commit SHAs and role mappings offline
python3 scripts/audit-public-release.py

# Inspect or reconcile role skills inside the running Hermes container
docker compose -f compose.yaml -f compose.production.yaml exec -T hermes \
  /opt/hermes-venv/bin/python /opt/allinagent/apps/control-center/control_center/org_provisioner.py --dry-run
```
