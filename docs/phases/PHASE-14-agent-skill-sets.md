# PHASE 14 — 11-Agent Portable Skill Sets, Stage-2 Normalizer & Paperclip Sync

- **Phase ID:** `PHASE-14`
- **Status:** `PASS`
- **Component Scope:** `apps/control-center/control_center/agent_skills_manager.py`, `apps/control-center/control_center/org_provisioner.py`, `skills/install_agent_skills.py`, `skills/manifests/skills.lock.json`
- **Verification Runtime:** `install_agent_skills.py --dry-run` (`--strict-oss` & standard) + `test_06_skill_registry_stage1_quarantine_and_stage2_materialization`

---

## 1. Executive Summary

All **11 corporate AI agents** in ALLINAGENT now receive deterministic, OS-portable, role-scoped skill sets materialized from the central verified registry (`<SKILL_REGISTRY_DIR>/reviewed/`) into isolated Hermes worker profiles (`<HERMES_HOME_ROOT>/profiles/pc*/skills/`) via POSIX symlinks on Linux/macOS or NTFS directory junctions on Windows, with locked `.usage.json` state and automatic Paperclip Skills Store synchronization whenever Paperclip is reachable.

---

## 2. Stage-2 Normalization & Adaptation Pipeline

1. **Universal `UPSTREAM_LICENSE` Attribution:**
   - Guarantees an `UPSTREAM_LICENSE` file inside 100% of installed skill folders (retaining root `LICENSE` downloads for 8 repositories, copying `LICENSE.txt` $\rightarrow$ `UPSTREAM_LICENSE` for `anthropics/skills`, and generating a commit-pinned provenance header notice for `vercel-labs/agent-skills`).
2. **Deterministic YAML Frontmatter Normalizer (`normalize_skill_frontmatter`):**
   - **ISO Date Quoting:** Wraps unquoted YAML ISO dates (`YYYY-MM-DD`) in double quotes so YAML loaders preserve `str` types required by Hermes `skill_view`.
   - **5 Mismatched `name:` Rewrites:** Aligns frontmatter `name:` with runtime skill identifiers:
     - `vercel-react-best-practices` $\rightarrow$ `react-best-practices`
     - `generate` $\rightarrow$ `pw-generate`
     - `fix` $\rightarrow$ `pw-fix`
     - `coverage` $\rightarrow$ `pw-coverage`
     - `report` $\rightarrow$ `pw-report`
   - **Model Invocation Unlock:** Strips `disable-model-invocation: true` from `c-level-skills` so `@ceo` can invoke `skill_view(name='c-level-skills')`.
   - **Apache-2.0 Section 4(b) Compliance:** Inserts a prominent `# Apache-2.0 Section 4(b) Notice:` YAML header comment whenever an `Apache-2.0` `SKILL.md` file is modified during normalization.
3. **Sanitized Local Adaptation References:**
   - Generates `c-level-skills/references/paperclip-11-agent-routing.md` mapping executive coordination strictly to the 11 provisioned Paperclip agents (preventing hallucinated unprovisioned C-suite agents).
   - Generates `LARAVEL-COMPATIBILITY.md` instructing `@backend` to detect `composer.json` / `artisan` / `Modules/` before selecting tooling and never apply Node/Express scaffolders to PHP/Laravel repositories.
4. **Bundled Skill Conflict Resolution & `--strict-oss` Fallback:**
   - When Anthropic `pdf` is installed on `pccompliancereporter` (`Report & Compliance Agent`), Stage 2 adds `"productivity/pdf"` to `skills.disabled` in `pccompliancereporter/config.yaml` and archives `skills/productivity/pdf` into `<SKILL_REGISTRY_DIR>/agents/compliance/archived-bundled/productivity/pdf`.
   - When `--strict-oss` or `--offline` is active and `FETCH_FROM_UPSTREAM_ONLY` packages (`docx`, `pdf`) are skipped, Stage 2 activates the MIT `strict_oss_fallback` mappings (`productivity/microsoft-office` and `productivity/pdf`) and keeps bundled `productivity/pdf` intact and enabled.

---

## 3. Complete 11-Agent Skill Assignment & Toolset Matrix

| Role Slug | Agent Name (`Handle`) | Hermes Profile | Permitted Toolsets | Primary Skills | Specialist Skills | On-Demand / Isolated Non-Runtime |
|---|---|---|---|---|---|---|
| `ceo_agent` | CEO Agent (`@ceo`) | `pcceoagent` | `file,terminal,skills` | `ceo-advisor` | `c-level-skills` | — |
| `cto_agent` | CTO Agent (`@cto`) | `pcctoagent` | `file,terminal,skills` | `cto-review` | `senior-architect` | On-demand: `cto-advisor` |
| `backend_developer` | Backend Developer (`@backend`) | `pcbackenddeveloper` | `file,terminal,skills` | `senior-backend` | `api-design-reviewer` | On-demand: `senior-architect` |
| `frontend_developer` | Frontend Developer (`@frontend`) | `pcfrontenddeveloper` | `file,terminal,skills` | `react-best-practices` | `frontend-design` | — |
| `devops_engineer` | DevOps Engineer (`@devops`) | `pcdevopsengineer` | `file,terminal,skills` | `senior-devops` | `terraform-skill`, `ci-cd-pipeline-builder` | — |
| `qa_engineer` | QA Engineer (`@qa`) | `pcqaengineer` | `file,terminal,skills` | `pw` | `pw-generate`, `pw-review`, `senior-qa` | On-demand: `pw-fix`, `pw-coverage`, `pw-report` |
| `security_lead` | Security Lead (`@security_lead`) | `pcsecuritylead` | `file,skills` *(read-only)* | `ciso-advisor` | — | Ref-only: `threat-model` |
| `security_reviewer` | Security Reviewer (`@security`) | `pcsecurityreviewer` | `file,skills` *(read-only)* | `security-audit` | `senior-security` | Ref-only: `secondsky-cybersecurity-ref` |
| `findings_analyst` | Findings Analyst (`@findings`) | `pcfindingsanalyst` | `file,skills` *(read-only)* | `security-audit` | — | Ref-only: `anthropic-triage`; Experimental: `cve-triage` |
| `remediation_reviewer` | Remediation Reviewer (`@remediation`) | `pcremediationreviewer` | `file,skills` *(read-only)* | `focused-fix` | `security-vuln-remediation` | Ref-only: `anthropic-patch` |
| `compliance_reporter` | Report & Compliance Agent (`@compliance`) | `pccompliancereporter` | `file,terminal,skills` | `compliance-os` | `docx`, `pdf` | Disables bundled `productivity/pdf` (or MIT fallback under `--strict-oss`) |

---

## 4. Verification Evidence

1. **Stage-2 Frontmatter & Materialization Unit Tests (`test_06`):**
   - Verified ISO date quoting, `name:` rewriting, `disable-model-invocation` removal on `c-level-skills`, and Apache-2.0 §4(b) comment injection.
   - Verified symlink/junction creation into `profiles/pccompliancereporter/skills/`, `.usage.json` (`locked: true, pinned: true`), `productivity/pdf` archiving in standard mode, and `productivity/pdf` preservation + `strict_oss_fallback` activation in `--strict-oss --offline` mode.
2. **Dry-Run Role Matrix Verification (`skills/install_agent_skills.py --dry-run` & `--dry-run --strict-oss`):**
   - Verified all 11 agent roles, toolsets (`7` `file,terminal,skills` + `4` `file,skills`), and zero missing or unpinned package references.
