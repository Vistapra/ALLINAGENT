#!/usr/bin/env python3
"""Central Agent Skills Registry, Two-Stage Security Gate, Hermes Profile Linker & Paperclip Synchronizer.

Stage 1 (Cryptographic & Static Security Gate):
- Bootstraps `getsentry/skills` `skill-scanner` @ `a582c51ee29d0f35e6ac321340796f77d43da733` first
  and verifies its exact SHA-256 (`a51d7dceaa0778b2d17dac89d83fde191260b26ecdad566a85ff51c0441b19db`).
- Enforces `skills/policies/skill-policy.json` (40-char commit SHAs, allowed repos only,
  blocks arbitrary remote installs, excludes all 11 quarantined files).
- Runs per-file + package SHA-256 verification, `scan_skill.py`, and recursive Python AST
  dangerous-pattern inspection on every staged skill before promoting to `reviewed/`
  (quarantining any tampered or failing package into `quarantine/`).

Stage 2 (Normalization, Isolation & Runtime Materialization):
- Ensures `UPSTREAM_LICENSE` is present in every installed skill folder.
- Normalizes `SKILL.md` YAML frontmatter: quotes ISO dates, rewrites the 5 mismatched `name:`
  fields (`react-best-practices`, `pw-generate`, `pw-fix`, `pw-coverage`, `pw-report`), strips
  `disable-model-invocation: true` in `c-level-skills`, and adds Apache-2.0 Section 4(b)
  modification comments whenever an Apache-2.0 `SKILL.md` is modified.
- Writes sanitized local adaptation files (`c-level-skills/references/paperclip-11-agent-routing.md`
  and `LARAVEL-COMPATIBILITY.md`).
- Keeps `threat-model`, `secondsky-cybersecurity-ref`, `anthropic-triage`, and `anthropic-patch`
  strictly `REFERENCE_ONLY`, and keeps `cve-triage` `EXPERIMENTAL` unless `--enable-experimental`
  is explicitly passed.
- Resolves `--strict-oss` / `--offline` fallbacks (`docx` -> `productivity/microsoft-office`,
  `pdf` -> `productivity/pdf`), or disables/archives bundled `productivity/pdf` on
  `pccompliancereporter` when Anthropic `pdf` is installed.
- Creates POSIX symlinks (or Windows NTFS junctions) into `<HERMES_HOME>/profiles/pc*/skills/`,
  writes `.usage.json` (`locked: true, pinned: true`), and syncs with the Paperclip Skills Store
  API (`/api/companies/:id/skills` & `/api/agents/:id/skills/sync`) when Paperclip is reachable.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_PKG_ROOT = str(Path(__file__).resolve().parents[1])
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from control_center.paperclip_client import PaperclipClient
from control_center.paths import (
    CONFIG_DIR,
    IS_WINDOWS,
    PROFILES_ROOT,
    REPORTS_DIR,
    ROSTER_JSON_PATH as DEFAULT_ROSTER_JSON_PATH,
    SKILL_MANIFESTS_DIR,
    SKILL_NODE_TOOLS_DIR,
    SKILL_POLICIES_DIR,
    SKILL_REGISTRY_DIR,
    SKILL_VENV_PYTHON,
    WORKERS_DIR,
    resolve_roster_read_paths,
)

LOCKFILE_PATH: Path = SKILL_MANIFESTS_DIR / "skills.lock.json"
SECURITY_BASELINE_PATH: Path = SKILL_MANIFESTS_DIR / "skill-security-results.json"
POLICY_PATH: Path = SKILL_POLICIES_DIR / "skill-policy.json"
ROSTER_JSON_PATH: Path = DEFAULT_ROSTER_JSON_PATH

DATE_VAL_RE = re.compile(
    r"^(\s*[A-Za-z0-9_-]+\s*:\s*)(\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}[^\s\"']*)?)\s*$"
)
NAME_LINE_RE = re.compile(r"^(\s*name\s*:\s*)(.+?)\s*$")
DISABLE_INVOCATION_RE = re.compile(r"^\s*disable-model-invocation\s*:\s*true\s*$", re.IGNORECASE)


class SecurityGateError(RuntimeError):
    """Raised when a staged skill package fails SHA-256, policy, `scan_skill.py`, or AST checks."""


def build_agent_skill_specs(
    *,
    registry_root: Path = SKILL_REGISTRY_DIR,
    workers_root: Path = WORKERS_DIR,
    reports_root: Path = REPORTS_DIR,
    skill_venv_py: Path = SKILL_VENV_PYTHON,
    skill_node_dir: Path = SKILL_NODE_TOOLS_DIR,
) -> list[dict[str, Any]]:
    py_str = skill_venv_py.as_posix()
    node_str = skill_node_dir.as_posix()
    reg_str = registry_root.as_posix()
    wrk_str = workers_root.as_posix()
    rep_str = reports_root.as_posix()

    return [
        {
            "role_slug": "ceo_agent",
            "agent_dir": "ceo",
            "name": "CEO Agent",
            "handle": "@ceo",
            "profile": "pcceoagent",
            "toolsets": "file,terminal,skills",
            "primary": ["ceo-advisor"],
            "specialist": ["c-level-skills"],
            "on_demand": [],
            "reference_only": [],
            "experimental": [],
            "disabled_bundled": [],
            "routing_rules": [
                f"Load `skill_view(name='ceo-advisor')` for strategic planning, 3-option executive trade-offs, risk/assumption registers, board memos, and financial scenarios (`scripts/strategy_analyzer.py`, `scripts/financial_scenario_analyzer.py` via `{py_str}`).",
                "Load `skill_view(name='c-level-skills')` and `skill_view(name='c-level-skills', file_path='references/paperclip-11-agent-routing.md')` when routing multi-domain initiatives to Paperclip specialists (`@cto`, `@security_lead`, `@compliance`, `@backend`, `@frontend`, `@devops`, `@qa`). Act strictly as synthesizer and delegator; never mutate application source code directly.",
            ],
        },
        {
            "role_slug": "cto_agent",
            "agent_dir": "cto",
            "name": "CTO Agent",
            "handle": "@cto",
            "profile": "pcctoagent",
            "toolsets": "file,terminal,skills",
            "primary": ["cto-review"],
            "specialist": ["senior-architect"],
            "on_demand": ["cto-advisor"],
            "reference_only": [],
            "experimental": [],
            "disabled_bundled": [],
            "routing_rules": [
                "Load `skill_view(name='cto-review')` for independent technical strategy, scalability, reliability, and build-vs-buy architecture evaluations.",
                "Load `skill_view(name='senior-architect')` for system design, database comparisons, API/message-queue patterns, capacity planning, and Architecture Decision Records (ADRs).",
                "Load `skill_view(name='cto-advisor')` on demand when evaluating engineering organization scaling, DORA metrics, or technical debt roadmaps (`scripts/tech_debt_analyzer.py`, `scripts/team_scaling_calculator.py`).",
                "Role boundary: CTO provides technical governance, ADRs, and independent reviews; never directly mutate application feature branches or trigger production deployments.",
            ],
        },
        {
            "role_slug": "backend_developer",
            "agent_dir": "backend",
            "name": "Backend Developer",
            "handle": "@backend",
            "profile": "pcbackenddeveloper",
            "toolsets": "file,terminal,skills",
            "primary": ["senior-backend"],
            "specialist": ["api-design-reviewer"],
            "on_demand": ["senior-architect"],
            "reference_only": [],
            "experimental": [],
            "disabled_bundled": [],
            "routing_rules": [
                "Load `skill_view(name='senior-backend')` for REST API implementation, input validation, auth/authz, error handling, schema analysis, and isolated branch coding.",
                "Load `skill_view(name='api-design-reviewer')` when reviewing OpenAPI contracts, detecting breaking API changes, or generating REST OpenAPI specs (`scripts/api_linter.py`, `scripts/breaking_change_detector.py`). Do NOT claim full GraphQL/gRPC/WebSocket contract linting beyond REST/OpenAPI.",
                "Load `skill_view(name='senior-architect')` ONLY on demand when a backend task requires cross-service architecture reasoning.",
                f"Framework safety (`{wrk_str}/backend_developer/LARAVEL-COMPATIBILITY.md`): detect PHP/Laravel (`composer.json`, `artisan`, `Modules/`) vs Node/TS (`package.json`) vs Python (`pyproject.toml`) first; NEVER force Express/Fastify scaffolders onto Laravel projects, NEVER read `.env` files, and NEVER run migration/load-test scripts against production.",
            ],
        },
        {
            "role_slug": "frontend_developer",
            "agent_dir": "frontend",
            "name": "Frontend Developer",
            "handle": "@frontend",
            "profile": "pcfrontenddeveloper",
            "toolsets": "file,terminal,skills",
            "primary": ["react-best-practices"],
            "specialist": ["frontend-design"],
            "on_demand": [],
            "reference_only": [],
            "experimental": [],
            "disabled_bundled": [],
            "routing_rules": [
                "Load `skill_view(name='react-best-practices')` (and relevant `rules/*.md` via `skill_view`) for React/Next.js performance engineering, eliminating request waterfalls, bundle optimization, and re-render analysis. Do not apply React-specific rules to non-React projects.",
                "Load `skill_view(name='frontend-design')` for UI/UX layout, visual hierarchy, typography, responsive design, and accessibility.",
                "Operate strictly inside the assigned project workspace; never modify core platform services without explicit Owner approval.",
            ],
        },
        {
            "role_slug": "devops_engineer",
            "agent_dir": "devops",
            "name": "DevOps Engineer",
            "handle": "@devops",
            "profile": "pcdevopsengineer",
            "toolsets": "file,terminal,skills",
            "primary": ["senior-devops"],
            "specialist": ["terraform-skill", "ci-cd-pipeline-builder"],
            "on_demand": [],
            "reference_only": [],
            "experimental": [],
            "disabled_bundled": [],
            "routing_rules": [
                "Load `skill_view(name='senior-devops')` for Docker container hardening, deployment readiness, service health/SLO diagnostics, and rollback planning.",
                "Load `skill_view(name='terraform-skill')` (and `references/*.md`) for Terraform / OpenTofu IaC authoring, module structure review, and static HCL validation. NEVER run `terraform apply` or mutate cloud/production infrastructure without explicit Owner approval.",
                "Load `skill_view(name='ci-cd-pipeline-builder')` for GitHub Actions / GitLab CI pipeline generation, caching, SBOM, and defensive quality gates.",
            ],
        },
        {
            "role_slug": "qa_engineer",
            "agent_dir": "qa",
            "name": "QA Engineer",
            "handle": "@qa",
            "profile": "pcqaengineer",
            "toolsets": "file,terminal,skills",
            "primary": ["pw"],
            "specialist": ["pw-generate", "pw-review", "senior-qa"],
            "on_demand": ["pw-fix", "pw-coverage", "pw-report"],
            "reference_only": [],
            "experimental": [],
            "disabled_bundled": [],
            "routing_rules": [
                "Load `skill_view(name='pw')` for Playwright E2E routing, locators, assertions, and templates (`reference/*.md`, `templates/**/*.md`), delegating into `pw-generate` (test authoring), `pw-review` (anti-pattern & assertion review), `pw-fix` (flaky test diagnosis), `pw-coverage`, and `pw-report`.",
                "Load `skill_view(name='senior-qa')` for test plans, unit/integration/regression matrices, negative testing, and running `scripts/test_suite_generator.py`, `scripts/coverage_analyzer.py`, `scripts/e2e_test_scaffolder.py`.",
                "Browser isolation rule: always run headless Chromium with an ephemeral fresh context — never access personal browser profiles or persistent cookies.",
            ],
        },
        {
            "role_slug": "security_lead",
            "agent_dir": "security-lead",
            "name": "Security Lead",
            "handle": "@security_lead",
            "profile": "pcsecuritylead",
            "toolsets": "file,skills",
            "primary": ["ciso-advisor"],
            "specialist": [],
            "on_demand": [],
            "reference_only": ["threat-model"],
            "experimental": [],
            "disabled_bundled": [],
            "routing_rules": [
                "Load `skill_view(name='ciso-advisor')` for security governance, risk registers, incident response planning, compliance roadmaps, and executive security reporting.",
                f"For architecture threat modeling, read the reviewed defensive methodology reference at `{reg_str}/agents/security-lead/references/threat-model/SKILL.md` (`REFERENCE_ONLY` — asset identification, trust boundaries, data flows, defensive assumptions; never run autonomous offensive harnesses).",
            ],
        },
        {
            "role_slug": "security_reviewer",
            "agent_dir": "security-reviewer",
            "name": "Security Reviewer",
            "handle": "@security",
            "profile": "pcsecurityreviewer",
            "toolsets": "file,skills",
            "primary": ["security-audit"],
            "specialist": ["senior-security"],
            "on_demand": [],
            "reference_only": ["secondsky-cybersecurity-ref"],
            "experimental": [],
            "disabled_bundled": [],
            "routing_rules": [
                "Load `skill_view(name='security-audit')` for read-only defensive source code review, coverage ledger tracking, evidence validation, and false-positive separation.",
                "Load `skill_view(name='senior-security')` for OWASP-aligned authentication, authorization, cryptography, and API security review.",
                f"Optional sanitized defensive reference (`REFERENCE_ONLY`) is available at `{reg_str}/agents/security-reviewer/references/secondsky-cybersecurity-ref/SKILL.md`. Strictly maintain read-only defensive reviewer posture (never offensive execution).",
            ],
        },
        {
            "role_slug": "findings_analyst",
            "agent_dir": "findings",
            "name": "Findings Analyst",
            "handle": "@findings",
            "profile": "pcfindingsanalyst",
            "toolsets": "file,skills",
            "primary": ["security-audit"],
            "specialist": [],
            "on_demand": [],
            "reference_only": ["anthropic-triage"],
            "experimental": ["cve-triage"],
            "disabled_bundled": [],
            "routing_rules": [
                "Load `skill_view(name='security-audit')` scoped specifically to candidate finding validation, deduplication, confidence classification (`confirmed` vs `unverified` vs `false_positive`), evidence correlation, and remediation priority ranking.",
                f"Read reviewed defensive triage methodology (`REFERENCE_ONLY`) at `{reg_str}/agents/findings/references/anthropic-triage/SKILL.md`.",
                f"`cve-triage` (`{reg_str}/agents/findings/experimental/cve-triage/SKILL.md`) is classified `EXPERIMENTAL` (Python/Poetry/uv SSVC & VEX modeling only; never treat as universal dependency scanner, never fabricate CVEs, and never send source code externally).",
            ],
        },
        {
            "role_slug": "remediation_reviewer",
            "agent_dir": "remediation",
            "name": "Remediation Reviewer",
            "handle": "@remediation",
            "profile": "pcremediationreviewer",
            "toolsets": "file,skills",
            "primary": ["focused-fix"],
            "specialist": ["security-vuln-remediation"],
            "on_demand": [],
            "reference_only": ["anthropic-patch"],
            "experimental": [],
            "disabled_bundled": [],
            "routing_rules": [
                "Load `skill_view(name='focused-fix')` strictly in independent reviewer mode: verify root-cause elimination, minimal-change discipline, regression test adequacy, and reject unproven fixes (`RESOLVED` vs `REWORK_REQUIRED`). Never author, review, and self-approve your own code changes.",
                "Load `skill_view(name='security-vuln-remediation')` for least-invasive dependency & container vulnerability fix evaluation (adapting workflow generically without applying upstream repo-specific configs).",
                f"Read reviewed defensive patch verification reference (`REFERENCE_ONLY`) at `{reg_str}/agents/remediation/references/anthropic-patch/SKILL.md`.",
            ],
        },
        {
            "role_slug": "compliance_reporter",
            "agent_dir": "compliance",
            "name": "Report & Compliance Agent",
            "handle": "@compliance",
            "profile": "pccompliancereporter",
            "toolsets": "file,terminal,skills",
            "primary": ["compliance-os"],
            "specialist": ["docx", "pdf"],
            "on_demand": [],
            "reference_only": [],
            "experimental": [],
            "disabled_bundled": ["productivity/pdf"],
            "routing_rules": [
                f"Load `skill_view(name='compliance-os')` for ISO 27001, SOC 2, and NIST CSF control mapping, cross-framework evidence deduplication, gap analysis, and running `scripts/framework_selector.py`, `scripts/cross_framework_mapper.py`, `scripts/evidence_pool_generator.py` via `{py_str}`. Never claim formal legal certification.",
                f"Load `skill_view(name='docx')` and `skill_view(name='pdf')` (or `python -m control_center.report_exporter <report.md> --out-dir {rep_str}`) to generate and validate structured Word (`.docx`) and PDF (`.pdf`) audit reports inside `{rep_str}` using `{py_str}` or `{node_str}`. Never include secrets or `.env` values in reports.",
            ],
        },
    ]


AGENT_SKILL_SPECS: list[dict[str, Any]] = build_agent_skill_specs()


# --- Local Adaptation Content Templates (100% Sanitized, Zero Private Identifiers) ---

PAPERCLIP_11_AGENT_ROUTING_MD = """# Paperclip 11-Agent Organization Routing Matrix (Local Integration Reference)

This reference adapts `c-level-skills` routing to the **actual 11-agent Paperclip roster** in **ALLINAGENT (`Unified AI Engineering & Operations`)**:

## Provisioned Paperclip Roles (Delegate via Paperclip Child Issues)

| C-Suite / Specialist Domain | Provisioned Paperclip Agent | Handle | Primary / Specialist Skills |
|---|---|---|---|
| Executive Strategy, Prioritization, Financial Scenarios, Board Synthesis | **CEO Agent** | `@ceo` | `ceo-advisor`, `c-level-skills` |
| Architecture, Tech Debt, Build-vs-Buy, Scalability, ADRs | **CTO Agent** | `@cto` | `cto-review`, `senior-architect`, `cto-advisor` |
| Security Governance, Risk Register, Threat Modeling, Incident Readiness | **Security Lead** | `@security_lead` | `ciso-advisor`, `threat-model` (ref) |
| Multi-Framework Compliance (ISO 27001, SOC 2, NIST CSF), Audit DOCX/PDF | **Report & Compliance Agent** | `@compliance` | `compliance-os`, `docx`, `pdf` |
| Backend Implementation, REST/OpenAPI Contracts, Schema & Migrations | **Backend Developer** | `@backend` | `senior-backend`, `api-design-reviewer`, `senior-architect` (on-demand) |
| React / Next.js Performance & UI/UX Design | **Frontend Developer** | `@frontend` | `react-best-practices`, `frontend-design` |
| Docker, CI/CD Pipelines, Terraform/OpenTofu IaC, Reliability & Rollback | **DevOps Engineer** | `@devops` | `senior-devops`, `terraform-skill`, `ci-cd-pipeline-builder` |
| Browser E2E Testing (Playwright), Test Plans, Coverage & Regression | **QA Engineer** | `@qa` | `pw`, `pw-generate`, `pw-review`, `senior-qa` |
| Independent Defensive Code & Auth/Authz Security Review | **Security Reviewer** | `@security` | `security-audit`, `senior-security` |
| Vulnerability Triage, Deduplication & Evidence Ranking | **Findings Analyst** | `@findings` | `security-audit`, `anthropic-triage` (ref), `cve-triage` (experimental) |
| Independent Remediation Diff & Minimal-Fix Verification | **Remediation Reviewer** | `@remediation` | `focused-fix`, `security-vuln-remediation`, `anthropic-patch` (ref) |

## Unprovisioned Upstream Roles (Do NOT Invent Agents)

Upstream C-suite roles not provisioned as standalone Paperclip agents (`CFO`, `CMO`, `CRO`, `COO`, `CHRO`, `General Counsel`, `CDO`, `CAIO`, `CCO`):
- **Financial scenario & unit-economics modeling**: Execute directly in `@ceo` using `ceo-advisor/scripts/financial_scenario_analyzer.py`.
- **Legal, Regulatory Certification Sign-off, HR, or Commercial Go-To-Market**: Mark as `NOT_PROVISIONED_IN_PAPERCLIP` and escalate decisions requiring legal/board authority to the Human Owner via the Paperclip Board.
- **Write Boundary**: `c-level-skills` grants **delegation and synthesis coordination only** — never direct source-code mutation or production system modification by `@ceo`.
"""

LARAVEL_COMPATIBILITY_MD = """# Local Framework Compatibility Note — PHP / Laravel & Multi-Stack Projects

> **Provenance Note:** This is a local ALLINAGENT platform compatibility note for `@backend` (`Backend Developer`), NOT an upstream skill.

1. **Detect Actual Project Stack Before Choosing Tooling:**
   - Inspect `composer.json` + `artisan` + `Modules/` (`nwidart/laravel-modules`) for **PHP / Laravel** repositories.
   - Inspect `package.json` + `tsconfig.json` for **Node.js / TypeScript** repositories.
   - Inspect `pyproject.toml` / `requirements.txt` for **Python** repositories.
2. **Do NOT Force Node/Express Scaffolders onto Laravel:**
   - The supporting script `senior-backend/scripts/api_scaffolder.py` targets Express/Fastify/Node patterns. **Never** run Node/Express scaffolders on a Laravel/PHP codebase.
   - On Laravel projects, apply `senior-backend` and `api-design-reviewer` **architectural principles** (REST resource naming, FormRequest input validation, Sanctum/Passport/JWT auth middleware, Eloquent eager-loading to prevent N+1 queries, non-breaking API versioning, standardized error envelopes, and idempotent migrations) using native PHP/Laravel conventions (`routes/api.php`, `Modules/*/Routes/api.php`, `FormRequest`, `JsonResource`, `PHPUnit`/`Pest`).
3. **Production & Credential Safety:**
   - **Never** read `.env` files or credential stores.
   - **Never** run `database_migration_tool.py` or `php artisan migrate` against production databases without explicit Owner approval.
   - **Never** run `api_load_tester.py` against live production endpoints.
"""


# --- Manifest & Policy Verification ---

def load_lock_and_policy(
    lock_path: Path = LOCKFILE_PATH,
    policy_path: Path = POLICY_PATH,
) -> tuple[dict[str, Any], dict[str, Any]]:
    lock_doc = json.loads(lock_path.read_text(encoding="utf-8"))
    policy_doc = json.loads(policy_path.read_text(encoding="utf-8"))
    return lock_doc, policy_doc


def verify_manifest(
    lock_doc: dict[str, Any] | None = None,
    policy_doc: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate lockfile completeness, 40-char commit SHAs, quarantine exclusions, and license policies offline."""
    if lock_doc is None or policy_doc is None:
        lock_doc, policy_doc = load_lock_and_policy()

    pkgs = lock_doc.get("packages") or {}
    roles = lock_doc.get("role_assignments") or []
    allowed_repos = (policy_doc.get("allowed_repositories") or {})
    quarantined_list = lock_doc.get("quarantined_excluded_files") or []
    quarantine_by_pkg: dict[str, set[str]] = {}
    for q in quarantined_list:
        quarantine_by_pkg.setdefault(q["pkg_id"], set()).add(q["file"])

    missing_refs: list[str] = []
    bad_shas: list[str] = []
    bad_pkg_hashes: list[str] = []
    unauthorized_repos: list[str] = []
    leaked_quarantined_files: list[str] = []
    policy_violations: list[str] = []

    for pkg_id, p in pkgs.items():
        sha = str(p.get("pinned_commit_sha") or "")
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            bad_shas.append(pkg_id)
        pkg_hash = str(p.get("upstream_package_sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", pkg_hash):
            bad_pkg_hashes.append(pkg_id)
        owner_repo = p.get("repo_owner_name")
        if owner_repo not in allowed_repos or allowed_repos[owner_repo] != sha:
            unauthorized_repos.append(f"{pkg_id}:{owner_repo}@{sha}")

        for qf in quarantine_by_pkg.get(pkg_id, set()):
            if qf in (p.get("files") or []):
                leaked_quarantined_files.append(f"{pkg_id}:{qf}")

        if owner_repo in ("borghei/Claude-Skills", "vercel-labs/agent-skills") or pkg_id in ("docx", "pdf"):
            if p.get("redistribution_policy") != "FETCH_FROM_UPSTREAM_ONLY":
                policy_violations.append(f"{pkg_id}:expected_FETCH_FROM_UPSTREAM_ONLY")
        if pkg_id in ("docx", "pdf") and not p.get("strict_oss_fallback"):
            policy_violations.append(f"{pkg_id}:missing_strict_oss_fallback")

    exp_pkgs = set(((policy_doc.get("classifications") or {}).get("experimental") or {}).get("packages") or [])
    ref_pkgs = set(((policy_doc.get("classifications") or {}).get("reference_only") or {}).get("packages") or [])

    for r in roles:
        for cat in ("primary", "specialist", "on_demand", "reference_only", "experimental"):
            for ref in r.get(cat) or []:
                if ref not in pkgs:
                    missing_refs.append(f"{r['role_slug']}:{ref}")
                if cat in ("primary", "specialist", "on_demand") and (ref in exp_pkgs or ref in ref_pkgs):
                    policy_violations.append(f"{r['role_slug']}:{ref}_restricted_in_active_category_{cat}")

    enforcement = policy_doc.get("enforcement") or {}
    if not (enforcement.get("locked") is True and enforcement.get("pinned") is True):
        policy_violations.append("policy_enforcement_not_locked_and_pinned")

    ok = (
        not missing_refs
        and not bad_shas
        and not bad_pkg_hashes
        and not unauthorized_repos
        and not leaked_quarantined_files
        and not policy_violations
        and len(pkgs) == 33
        and len(allowed_repos) == 10
        and len(roles) == 11
        and len(quarantined_list) == 11
    )
    return {
        "ok": ok,
        "packages_count": len(pkgs),
        "repositories_count": len(allowed_repos),
        "roles_count": len(roles),
        "quarantined_excluded_files_count": len(quarantined_list),
        "fetch_from_upstream_only_count": sum(1 for p in pkgs.values() if p.get("redistribution_policy") == "FETCH_FROM_UPSTREAM_ONLY"),
        "missing_package_refs": missing_refs,
        "unpinned_commits": bad_shas,
        "invalid_package_sha256": bad_pkg_hashes,
        "unauthorized_repos": unauthorized_repos,
        "leaked_quarantined_files": leaked_quarantined_files,
        "policy_violations": policy_violations,
    }


# --- Stage 1: Cryptographic Hash, Sentry `scan_skill.py`, and Recursive Python AST Scanner ---

def compute_directory_package_sha256(pkg_dir: Path, expected_rel_paths: list[str]) -> tuple[str, dict[str, str]]:
    """Compute per-file SHA-256 and deterministic package SHA-256 over `expected_rel_paths`."""
    file_hashes: dict[str, str] = {}
    for rel in sorted(set(expected_rel_paths)):
        fp = pkg_dir / rel
        if not fp.is_file():
            raise SecurityGateError(f"Missing expected file '{rel}' in '{pkg_dir}'")
        file_hashes[rel] = hashlib.sha256(fp.read_bytes()).hexdigest()
    digest_input = "".join(f"{rel}:{file_hashes[rel]}\n" for rel in sorted(file_hashes)).encode("utf-8")
    return hashlib.sha256(digest_input).hexdigest(), file_hashes


def ast_scan_python_tree(pkg_dir: Path) -> list[dict[str, Any]]:
    """Recursively parse all `.py` files with `ast.parse` and detect dangerous AST patterns."""
    findings: list[dict[str, Any]] = []
    for py_file in sorted(pkg_dir.rglob("*.py")):
        rel = py_file.relative_to(pkg_dir).as_posix()
        try:
            src = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(src, filename=rel)
        except SyntaxError as exc:
            findings.append({
                "severity": "high",
                "type": "AST Syntax Error",
                "location": f"{rel}:{exc.lineno}",
                "description": f"Unparseable Python file: {exc.msg}",
            })
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        func_name = f"{node.func.value.id}.{node.func.attr}"
                    else:
                        func_name = node.func.attr

                lineno = getattr(node, "lineno", 1)
                if func_name in ("eval", "exec"):
                    findings.append({
                        "severity": "critical",
                        "type": "AST Dangerous Builtin",
                        "location": f"{rel}:{lineno}",
                        "description": f"Direct `{func_name}()` invocation detected in AST",
                    })
                elif func_name in ("os.system", "os.popen", "pty.spawn", "pickle.loads", "marshal.loads"):
                    findings.append({
                        "severity": "high",
                        "type": "AST Dangerous Call",
                        "location": f"{rel}:{lineno}",
                        "description": f"`{func_name}()` invocation detected in AST",
                    })
                elif func_name.startswith("subprocess."):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append({
                                "severity": "high",
                                "type": "AST Subprocess Shell=True",
                                "location": f"{rel}:{lineno}",
                                "description": f"`{func_name}(..., shell=True)` detected in AST",
                            })
    return findings


def _run_sentry_scan_skill(scanner_script: Path, target_dir: Path) -> dict[str, Any]:
    """Execute `getsentry/skills` `scan_skill.py` against `target_dir`."""
    proc = subprocess.run(
        [str(SKILL_VENV_PYTHON), str(scanner_script), str(target_dir)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=45,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise SecurityGateError(
            f"skill-scanner execution failed on '{target_dir.name}' (exit={proc.returncode}): {(proc.stderr or proc.stdout)[:300]}"
        )
    parsed = json.loads(proc.stdout)
    if "error" in parsed:
        raise SecurityGateError(f"skill-scanner error on '{target_dir.name}': {parsed['error']}")
    return parsed


def quarantine_staged_package(staging_dir: Path, quarantine_root: Path, pkg_id: str, reason: str) -> Path:
    quarantine_root.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    q_dest = quarantine_root / f"{pkg_id}-{ts}"
    if q_dest.exists():
        shutil.rmtree(q_dest)
    if staging_dir.exists():
        shutil.move(str(staging_dir), str(q_dest))
    else:
        q_dest.mkdir(parents=True, exist_ok=True)
    (q_dest / "QUARANTINE_REASON.json").write_text(
        json.dumps(
            {
                "pkg_id": pkg_id,
                "quarantined_at": datetime.now(timezone.utc).isoformat(),
                "reason": reason,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return q_dest


def verify_and_gate_staged_package(
    pkg_id: str,
    pkg_meta: dict[str, Any],
    staging_dir: Path,
    *,
    quarantine_root: Path,
    scanner_script: Path | None,
    policy_doc: dict[str, Any],
    baseline_results: dict[str, Any],
) -> dict[str, Any]:
    """Run Stage-1 integrity, quarantined-file, `scan_skill.py`, and recursive AST checks on `staging_dir`."""
    try:
        # 1. Block any quarantined excluded file
        quarantined_files = {
            q["file"]
            for q in (policy_doc.get("quarantined_excluded_files") or [])
            if q["pkg_id"] == pkg_id
        }
        for qf in quarantined_files:
            if (staging_dir / qf).exists():
                raise SecurityGateError(f"Quarantined file '{qf}' present in staged package '{pkg_id}'")

        # 2. Reject any symlink escaping staging_dir
        for p in staging_dir.rglob("*"):
            if p.is_symlink():
                resolved = p.resolve()
                if not resolved.is_relative_to(staging_dir.resolve()):
                    raise SecurityGateError(f"External symlink escape in '{pkg_id}': {p.name} -> {resolved}")

        # 3. Verify individual file SHA-256s + package SHA-256
        expected_rel = list(pkg_meta["files"])
        if pkg_meta.get("upstream_license_url") and pkg_meta.get("upstream_license_sha256"):
            expected_rel.append("UPSTREAM_LICENSE")

        computed_pkg_sha, actual_hashes = compute_directory_package_sha256(staging_dir, expected_rel)
        expected_file_shas = pkg_meta.get("file_sha256s") or {}
        for rel, exp_h in expected_file_shas.items():
            if actual_hashes.get(rel) != exp_h:
                raise SecurityGateError(
                    f"File SHA-256 mismatch in '{pkg_id}/{rel}': expected {exp_h}, got {actual_hashes.get(rel)}"
                )
        if pkg_meta.get("upstream_license_sha256"):
            if actual_hashes.get("UPSTREAM_LICENSE") != pkg_meta["upstream_license_sha256"]:
                raise SecurityGateError(f"UPSTREAM_LICENSE SHA-256 mismatch in '{pkg_id}'")

        if computed_pkg_sha != pkg_meta["upstream_package_sha256"]:
            raise SecurityGateError(
                f"Package SHA-256 mismatch for '{pkg_id}': expected {pkg_meta['upstream_package_sha256']}, got {computed_pkg_sha}"
            )

        # 4. Run recursive Python AST scanner
        ast_findings = ast_scan_python_tree(staging_dir)
        baseline_entry = baseline_results.get(pkg_id) or {}
        allowed_ast_count = int(baseline_entry.get("deep_extra_findings_count", 0))
        critical_ast = [f for f in ast_findings if f["severity"] == "critical"]
        if critical_ast or len(ast_findings) > allowed_ast_count:
            raise SecurityGateError(
                f"AST dangerous-pattern gate failed for '{pkg_id}': {ast_findings}"
            )

        # 5. Run Sentry `scan_skill.py` (for all packages once scanner_script is available)
        sentry_report: dict[str, Any] = {}
        if scanner_script is not None and scanner_script.is_file():
            sentry_report = _run_sentry_scan_skill(scanner_script, staging_dir)
            # Hard-block structural supply-chain attacks unconditionally
            unconditional_block_types = {
                "Frontmatter Hooks",
                "npm Lifecycle Hook",
                "Unicode Tag Smuggling",
                "Hidden Injection in Comment",
                "Unrestricted Tools",
            }
            for f in sentry_report.get("findings") or []:
                if f.get("type") in unconditional_block_types:
                    raise SecurityGateError(
                        f"Critical structural attack '{f.get('type')}' detected in '{pkg_id}': {f.get('description')}"
                    )
                if f.get("type") == "Symlink Detected" and f.get("severity") == "critical":
                    raise SecurityGateError(f"External symlink detected in '{pkg_id}'")

            baseline_counts = baseline_entry.get("sentry_finding_counts") or {}
            actual_counts = sentry_report.get("finding_counts") or {}
            for sev in ("critical", "high"):
                if int(actual_counts.get(sev, 0)) > int(baseline_counts.get(sev, 0)):
                    raise SecurityGateError(
                        f"Sentry skill-scanner {sev} findings ({actual_counts.get(sev)}) exceed reviewed baseline "
                        f"({baseline_counts.get(sev, 0)}) for '{pkg_id}'"
                    )

        return {
            "pkg_id": pkg_id,
            "gate": "PASS",
            "upstream_package_sha256": computed_pkg_sha,
            "ast_findings_count": len(ast_findings),
            "sentry_finding_counts": sentry_report.get("finding_counts", {}),
        }
    except Exception as exc:
        q_path = quarantine_staged_package(staging_dir, quarantine_root, pkg_id, str(exc))
        raise SecurityGateError(f"Package '{pkg_id}' quarantined at '{q_path}': {exc}") from exc


def download_package_to_staging(pkg_meta: dict[str, Any], staging_dir: Path) -> None:
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)

    owner_repo = pkg_meta["repo_owner_name"]
    sha = pkg_meta["pinned_commit_sha"]
    subpath = pkg_meta["subpath"].strip("/")

    for rel in pkg_meta["files"]:
        raw_url = f"https://raw.githubusercontent.com/{owner_repo}/{sha}/{subpath}/{rel}"
        out_f = staging_dir / rel
        out_f.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(raw_url, timeout=35) as resp:
            out_f.write_bytes(resp.read())

    lic_url = pkg_meta.get("upstream_license_url")
    if lic_url:
        with urllib.request.urlopen(lic_url, timeout=30) as resp:
            (staging_dir / "UPSTREAM_LICENSE").write_bytes(resp.read())


# --- Stage 2: License Attribution, Frontmatter Normalization & Link Materialization ---

def ensure_upstream_license_file(pkg_id: str, pkg_meta: dict[str, Any], reviewed_pkg_dir: Path) -> Path:
    """Ensure `UPSTREAM_LICENSE` exists inside every installed `reviewed/<pkg_id>` folder."""
    lic_dst = reviewed_pkg_dir / "UPSTREAM_LICENSE"
    if lic_dst.is_file():
        return lic_dst
    for cand_name in ("LICENSE.txt", "LICENSE", "LICENSE.md"):
        cand = reviewed_pkg_dir / cand_name
        if cand.is_file():
            shutil.copyfile(cand, lic_dst)
            return lic_dst

    synthesized = (
        f"Upstream License & Provenance Notice — {pkg_meta['display_name']} ({pkg_id})\n"
        f"Repository: {pkg_meta['repo_url']}\n"
        f"Pinned Commit SHA: {pkg_meta['pinned_commit_sha']}\n"
        f"Subpath: {pkg_meta['subpath']}\n"
        f"Declared License (SKILL.md / metadata.json): {pkg_meta['license_spdx']}\n"
    )
    lic_dst.write_text(synthesized, encoding="utf-8")
    return lic_dst


def normalize_skill_frontmatter(
    pkg_id: str,
    md_path: Path,
    *,
    license_spdx: str,
    policy_doc: dict[str, Any],
) -> dict[str, bool]:
    """Normalize `SKILL.md` YAML frontmatter per Stage-2 rules (including Apache-2.0 §4(b) notice)."""
    txt = md_path.read_text(encoding="utf-8")
    if not txt.startswith("---"):
        return {"modified": False}
    parts = txt.split("---", 2)
    if len(parts) < 3:
        return {"modified": False}

    s2 = policy_doc.get("stage2_normalizations") or {}
    name_rewrites = s2.get("name_rewrites") or {}
    strip_keys = set((s2.get("strip_frontmatter_keys") or {}).get(pkg_id) or [])
    apache_comment = str(
        s2.get("apache_2_0_section_4b_comment")
        or "# Apache-2.0 Section 4(b) Notice: YAML frontmatter normalized by ALLINAGENT Skill Registry."
    )

    orig_lines = parts[1].splitlines()
    new_lines: list[str] = []
    dates_quoted = False
    name_rewritten = False
    stripped_invocation = False

    rewrite_target = (name_rewrites.get(pkg_id) or {}).get("to")

    for ln in orig_lines:
        if "disable-model-invocation" in strip_keys and DISABLE_INVOCATION_RE.match(ln):
            stripped_invocation = True
            continue

        nm = NAME_LINE_RE.match(ln)
        if nm and rewrite_target:
            cur_val = nm.group(2).strip().strip('"').strip("'")
            if cur_val != rewrite_target:
                ln = f'{nm.group(1)}"{rewrite_target}"'
                name_rewritten = True

        dm = DATE_VAL_RE.match(ln)
        if dm:
            ln = f'{dm.group(1)}"{dm.group(2)}"'
            dates_quoted = True

        new_lines.append(ln)

    modified = dates_quoted or name_rewritten or stripped_invocation
    is_apache = "Apache-2.0" in license_spdx
    if is_apache and modified and not any("Apache-2.0 Section 4(b)" in x for x in new_lines):
        new_lines.append(apache_comment)

    if modified:
        rebuilt = "---\n" + "\n".join(new_lines).strip() + "\n---" + parts[2]
        md_path.write_text(rebuilt, encoding="utf-8")

    return {
        "modified": modified,
        "dates_quoted": dates_quoted,
        "name_rewritten": name_rewritten,
        "stripped_disable_model_invocation": stripped_invocation,
        "apache_4b_notice_added": bool(is_apache and modified),
    }


def write_local_adaptation_files(
    reviewed_root: Path,
    registry_root: Path,
    workers_root: Path = WORKERS_DIR,
) -> list[str]:
    """Write sanitized `paperclip-11-agent-routing.md` and `LARAVEL-COMPATIBILITY.md`."""
    written: list[str] = []
    clevel_dir = reviewed_root / "c-level-skills"
    if clevel_dir.is_dir():
        ref_file = clevel_dir / "references" / "paperclip-11-agent-routing.md"
        ref_file.parent.mkdir(parents=True, exist_ok=True)
        ref_file.write_text(PAPERCLIP_11_AGENT_ROUTING_MD, encoding="utf-8")
        written.append(str(ref_file))

    for laravel_dst in (
        workers_root / "backend_developer" / "LARAVEL-COMPATIBILITY.md",
        registry_root / "agents" / "backend" / "LARAVEL-COMPATIBILITY.md",
    ):
        laravel_dst.parent.mkdir(parents=True, exist_ok=True)
        laravel_dst.write_text(LARAVEL_COMPATIBILITY_MD, encoding="utf-8")
        written.append(str(laravel_dst))
    return written


def remove_existing_skill_link_or_dir(target_path: Path) -> None:
    """Safely remove an existing POSIX symlink, Windows NTFS junction, or directory."""
    is_junc = getattr(target_path, "is_junction", lambda: False)()
    if target_path.is_symlink() or is_junc:
        if IS_WINDOWS and is_junc and not target_path.is_symlink():
            os.rmdir(target_path)
        else:
            target_path.unlink(missing_ok=True)
        return
    if target_path.is_dir():
        shutil.rmtree(target_path)
    elif target_path.exists():
        target_path.unlink(missing_ok=True)


def create_skill_link(source_dir: Path, link_path: Path) -> str:
    """Create a POSIX directory symlink or Windows NTFS junction pointing `link_path -> source_dir`."""
    src = source_dir.resolve()
    link_path.parent.mkdir(parents=True, exist_ok=True)
    remove_existing_skill_link_or_dir(link_path)

    if not IS_WINDOWS:
        os.symlink(src, link_path, target_is_directory=True)
        return "posix_symlink"

    # Windows: try symlink first, then stdlib `_winapi.CreateJunction`, then copy fallback
    try:
        os.symlink(src, link_path, target_is_directory=True)
        return "windows_symlink"
    except OSError:
        pass

    try:
        import _winapi  # type: ignore[import-not-found]

        _winapi.CreateJunction(str(src), str(link_path))
        return "windows_junction"
    except Exception:
        shutil.copytree(src, link_path)
        return "directory_copy_fallback"


def stage1_and_stage2_prepare_packages(
    needed_pkg_ids: list[str],
    *,
    registry_root: Path = SKILL_REGISTRY_DIR,
    workers_root: Path = WORKERS_DIR,
    offline: bool = False,
    strict_oss: bool = False,
    lock_doc: dict[str, Any] | None = None,
    policy_doc: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute Stage-1 Security Gate + Stage-2 Normalization for `needed_pkg_ids`."""
    if lock_doc is None or policy_doc is None:
        lock_doc, policy_doc = load_lock_and_policy()

    manifest_check = verify_manifest(lock_doc, policy_doc)
    if not manifest_check["ok"]:
        raise SecurityGateError(f"skills.lock.json / skill-policy.json validation failed: {manifest_check}")

    baseline_results = {}
    if SECURITY_BASELINE_PATH.is_file():
        baseline_results = json.loads(SECURITY_BASELINE_PATH.read_text(encoding="utf-8")).get("results", {})

    staging_root = registry_root / "staging"
    reviewed_root = registry_root / "reviewed"
    quarantine_root = registry_root / "quarantine"
    staging_root.mkdir(parents=True, exist_ok=True)
    reviewed_root.mkdir(parents=True, exist_ok=True)
    quarantine_root.mkdir(parents=True, exist_ok=True)

    pkgs_map = lock_doc["packages"]
    scanner_pkg_meta = pkgs_map["skill-scanner"]
    scanner_reviewed_dir = reviewed_root / "skill-scanner"
    scanner_script = scanner_reviewed_dir / "scripts" / "scan_skill.py"

    # Bootstrap `skill-scanner` first unless already verified or offline
    if not scanner_script.is_file():
        if offline:
            raise SecurityGateError("Offline mode requested, but bootstrap `skill-scanner` is not present in reviewed/.")
        st_scanner = staging_root / "skill-scanner"
        download_package_to_staging(scanner_pkg_meta, st_scanner)
        verify_and_gate_staged_package(
            "skill-scanner",
            scanner_pkg_meta,
            st_scanner,
            quarantine_root=quarantine_root,
            scanner_script=None,
            policy_doc=policy_doc,
            baseline_results=baseline_results,
        )
        if scanner_reviewed_dir.exists():
            shutil.rmtree(scanner_reviewed_dir)
        shutil.move(str(st_scanner), str(scanner_reviewed_dir))
        ensure_upstream_license_file("skill-scanner", scanner_pkg_meta, scanner_reviewed_dir)
        normalize_skill_frontmatter(
            "skill-scanner",
            scanner_reviewed_dir / "SKILL.md",
            license_spdx=scanner_pkg_meta["license_spdx"],
            policy_doc=policy_doc,
        )

    gated_packages: dict[str, Any] = {}
    skipped_strict_or_offline: dict[str, str] = {}

    for pkg_id in sorted(set(needed_pkg_ids)):
        if pkg_id == "skill-scanner":
            continue
        pkg_meta = pkgs_map[pkg_id]
        if strict_oss and pkg_meta["redistribution_policy"] == "FETCH_FROM_UPSTREAM_ONLY":
            skipped_strict_or_offline[pkg_id] = "strict_oss_skipped_fetch_only"
            continue

        rev_dir = reviewed_root / pkg_id
        if rev_dir.is_dir() and (rev_dir / "SKILL.md").is_file() and (rev_dir / "UPSTREAM_LICENSE").is_file():
            gated_packages[pkg_id] = {"pkg_id": pkg_id, "gate": "CACHED_REVIEWED"}
            continue

        if offline:
            skipped_strict_or_offline[pkg_id] = "offline_not_cached"
            continue

        st_dir = staging_root / pkg_id
        download_package_to_staging(pkg_meta, st_dir)
        gate_res = verify_and_gate_staged_package(
            pkg_id,
            pkg_meta,
            st_dir,
            quarantine_root=quarantine_root,
            scanner_script=scanner_script,
            policy_doc=policy_doc,
            baseline_results=baseline_results,
        )
        if rev_dir.exists():
            shutil.rmtree(rev_dir)
        shutil.move(str(st_dir), str(rev_dir))

        # Stage 2 per-package license & YAML frontmatter normalization
        ensure_upstream_license_file(pkg_id, pkg_meta, rev_dir)
        norm_res = normalize_skill_frontmatter(
            pkg_id,
            rev_dir / "SKILL.md",
            license_spdx=pkg_meta["license_spdx"],
            policy_doc=policy_doc,
        )
        gate_res["stage2_frontmatter"] = norm_res
        gated_packages[pkg_id] = gate_res

    adapt_files = write_local_adaptation_files(reviewed_root, registry_root, workers_root)
    return {
        "gated_packages": gated_packages,
        "skipped_packages": skipped_strict_or_offline,
        "local_adaptation_files": adapt_files,
    }


def _update_profile_config_disabled_skills(profile_home: Path, disabled_list: list[str]) -> None:
    cfg_path = profile_home / "config.yaml"
    if not cfg_path.is_file():
        return
    txt = cfg_path.read_text(encoding="utf-8")
    lines = txt.splitlines()
    out_lines: list[str] = []
    i = 0
    inserted = False
    while i < len(lines):
        ln = lines[i]
        out_lines.append(ln)
        if ln.strip() == "skills:":
            i += 1
            while i < len(lines) and (lines[i].startswith("  ") or not lines[i].strip()):
                sub = lines[i]
                if sub.startswith("  disabled:"):
                    i += 1
                    while i < len(lines) and lines[i].startswith("    - "):
                        i += 1
                    continue
                out_lines.append(sub)
                i += 1
            if disabled_list:
                out_lines.append("  disabled:")
                for d in sorted(set(disabled_list)):
                    out_lines.append(f'    - "{d}"')
            inserted = True
            continue
        i += 1
    if not inserted and disabled_list:
        out_lines.append("skills:")
        out_lines.append("  disabled:")
        for d in sorted(set(disabled_list)):
            out_lines.append(f'    - "{d}"')
    cfg_path.write_text("\n".join(out_lines).rstrip() + "\n", encoding="utf-8")
    (profile_home / ".skills_prompt_snapshot.json").unlink(missing_ok=True)


def _append_skill_routing_to_instructions(
    spec: dict[str, Any],
    *,
    profiles_root: Path = PROFILES_ROOT,
    workers_root: Path = WORKERS_DIR,
) -> None:
    marker_begin = "<!-- BEGIN SPECIALIZED AGENT SKILLS ROUTING -->"
    marker_end = "<!-- END SPECIALIZED AGENT SKILLS ROUTING -->"
    block_lines = [
        marker_begin,
        "## 7. Specialized Role Skills & Progressive Disclosure Routing",
        f"- **Primary Skills:** {', '.join(f'`{s}`' for s in spec['primary']) or 'None'}",
        f"- **Specialist Skills:** {', '.join(f'`{s}`' for s in spec['specialist']) or 'None'}",
        f"- **On-Demand Skills:** {', '.join(f'`{s}`' for s in spec['on_demand']) or 'None'}",
        f"- **Reference-Only Methodologies:** {', '.join(f'`{s}`' for s in spec['reference_only']) or 'None'}",
        f"- **Experimental Skills:** {', '.join(f'`{s}`' for s in spec['experimental']) or 'None'}",
        "- **Mandatory Skill Usage Protocol:** When a task matches your Primary or Specialist domain, call `skill_view(name='<skill>')` first (progressive disclosure) and load only the specific supporting `references/` or `scripts/` needed for that task. Supporting `scripts/` and `references/` live inside the `skill_dir` path returned by `skill_view` (never assume they exist inside the target project workspace `cwd`). Never modify or delete approved skills (`skill_manage` mutations are locked).",
    ]
    for r in spec["routing_rules"]:
        block_lines.append(f"- {r}")
    block_lines.append(marker_end)
    block = "\n".join(block_lines)

    targets = [
        workers_root / spec["role_slug"] / "AGENTS.md",
        profiles_root / spec["profile"] / "SOUL.md",
    ]
    for tp in targets:
        if not tp.is_file():
            continue
        cur = tp.read_text(encoding="utf-8")
        if marker_begin in cur and marker_end in cur:
            pattern = re.compile(re.escape(marker_begin) + r"[\s\S]*?" + re.escape(marker_end))
            updated = pattern.sub(lambda _m: block, cur)
        else:
            updated = cur.rstrip() + "\n\n" + block + "\n"
        tp.write_text(updated, encoding="utf-8")


def _try_get_reachable_paperclip() -> tuple[PaperclipClient | None, str | None, dict[str, str]]:
    """Return `(client, company_id, role_slug_to_agent_uuid)` if Paperclip is reachable & authenticated."""
    roster_company_id: str | None = None
    roster_uuids: dict[str, str] = {}
    for cand_roster in resolve_roster_read_paths(ROSTER_JSON_PATH):
        if cand_roster.is_file():
            try:
                rdata = json.loads(cand_roster.read_text(encoding="utf-8"))
                roster_company_id = rdata.get("company_id")
                for slug, info in (rdata.get("agents") or {}).items():
                    if info.get("id"):
                        roster_uuids[slug] = str(info["id"])
                if roster_uuids or roster_company_id:
                    break
            except Exception:
                pass

    try:
        pc = PaperclipClient(timeout=4.0)
        h = pc.health()
        if h.get("status") != "ok":
            return None, roster_company_id, roster_uuids
        co = pc.get_primary_company()
        cid = co["id"]
        agents = pc.list_agents(cid)
        name_to_slug = {s["name"]: s["role_slug"] for s in AGENT_SKILL_SPECS}
        for ag in agents:
            slug = (ag.get("metadata") or {}).get("role_slug") or name_to_slug.get(ag.get("name", ""))
            if slug and ag.get("id"):
                roster_uuids[slug] = str(ag["id"])
        return pc, cid, roster_uuids
    except Exception:
        return None, roster_company_id, roster_uuids


def _ensure_paperclip_registry_workspace(pc: PaperclipClient, company_id: str, reviewed_root: Path) -> str:
    projects = pc.list_projects(company_id)
    proj = next((p for p in projects if p.get("name") == "Central Verified Skill Registry"), None)
    if not proj:
        proj = pc.create_project(
            company_id,
            {
                "name": "Central Verified Skill Registry",
                "description": "Verified immutable Agent Skills staging & distribution root.",
                "status": "in_progress",
            },
        )
    ws_list = proj.get("workspaces") or pc.list_project_workspaces(proj["id"])
    rev_str = str(reviewed_root)
    if not any(str(w.get("cwd") or "") == rev_str for w in ws_list):
        pc.create_project_workspace(
            proj["id"],
            {
                "name": "reviewed-skills-root",
                "cwd": rev_str,
                "isPrimary": True,
            },
        )
    return proj["id"]


def install_agent_skills(
    role_slug: str,
    *,
    registry_root: Path = SKILL_REGISTRY_DIR,
    profiles_root: Path = PROFILES_ROOT,
    workers_root: Path = WORKERS_DIR,
    enable_experimental: bool = False,
    strict_oss: bool = False,
    offline: bool = False,
    skip_download: bool = False,
) -> dict[str, Any]:
    specs = build_agent_skill_specs(registry_root=registry_root, workers_root=workers_root)
    spec = next((s for s in specs if s["role_slug"] == role_slug), None)
    if not spec:
        raise ValueError(f"Unknown agent role_slug: {role_slug}")

    lock_doc, policy_doc = load_lock_and_policy()
    lock_pkgs = lock_doc["packages"]

    runtime_pkgs: list[tuple[str, str]] = (
        [(p, "PRIMARY") for p in spec["primary"]]
        + [(p, "SPECIALIST") for p in spec["specialist"]]
        + [(p, "ON_DEMAND") for p in spec["on_demand"]]
    )
    if enable_experimental:
        runtime_pkgs.extend((p, "EXPERIMENTAL") for p in spec["experimental"])

    all_role_pkgs = [
        p for p, _ in runtime_pkgs
    ] + list(spec["reference_only"]) + list(spec["experimental"])

    if not skip_download:
        stage1_and_stage2_prepare_packages(
            all_role_pkgs,
            registry_root=registry_root,
            workers_root=workers_root,
            offline=offline,
            strict_oss=strict_oss,
            lock_doc=lock_doc,
            policy_doc=policy_doc,
        )

    reviewed_root = registry_root / "reviewed"
    agents_reg_root = registry_root / "agents"
    agent_reg_dir = agents_reg_root / spec["agent_dir"]
    agent_reg_dir.mkdir(parents=True, exist_ok=True)

    profile_home = profiles_root / spec["profile"]
    skills_dir = profile_home / "skills"
    skills_dir.mkdir(parents=True, exist_ok=True)

    # Materialize REFERENCE_ONLY & EXPERIMENTAL into isolated non-runtime registry subdirs
    isolated_refs: dict[str, str] = {}
    for ref_pkg in spec["reference_only"]:
        rev_src = reviewed_root / ref_pkg
        if rev_src.is_dir():
            ref_dst = agent_reg_dir / "references" / ref_pkg
            create_skill_link(rev_src, ref_dst)
            isolated_refs[ref_pkg] = str(ref_dst)

    isolated_exp: dict[str, str] = {}
    for exp_pkg in spec["experimental"]:
        rev_src = reviewed_root / exp_pkg
        if rev_src.is_dir():
            exp_dst = agent_reg_dir / "experimental" / exp_pkg
            create_skill_link(rev_src, exp_dst)
            isolated_exp[exp_pkg] = str(exp_dst)

    # Materialize active runtime skills via POSIX symlink / Windows NTFS junction (or record strict_oss_fallback)
    materialized_map: dict[str, str] = {}
    link_modes: dict[str, str] = {}
    activated_fallbacks: dict[str, Any] = {}
    installed_records: list[dict[str, Any]] = []

    for pkg_id, cat in runtime_pkgs:
        lk = lock_pkgs[pkg_id]
        rev_src = reviewed_root / pkg_id
        if not (rev_src / "SKILL.md").is_file():
            fb = lk.get("strict_oss_fallback")
            if (strict_oss or offline) and fb:
                activated_fallbacks[pkg_id] = fb
                continue
            if strict_oss and lk.get("redistribution_policy") == "FETCH_FROM_UPSTREAM_ONLY":
                continue
            raise FileNotFoundError(f"Reviewed skill package missing SKILL.md: {rev_src}")

        link_dst = skills_dir / pkg_id
        lmode = create_skill_link(rev_src, link_dst)
        materialized_map[pkg_id] = str(link_dst)
        link_modes[pkg_id] = lmode
        installed_records.append({
            "pkg_id": pkg_id,
            "category": cat,
            "link_mode": lmode,
            "pinned_commit_sha": lk["pinned_commit_sha"],
            "repo_url": lk["repo_url"],
            "license_spdx": lk["license_spdx"],
            "upstream_package_sha256": lk["upstream_package_sha256"],
        })

    # Conflict resolution: disable & archive bundled `productivity/pdf` ONLY when Anthropic `pdf` is installed!
    effective_disabled: list[str] = []
    for rel_b in spec["disabled_bundled"]:
        if rel_b == "productivity/pdf" and "pdf" not in materialized_map:
            continue
        effective_disabled.append(rel_b)

    _update_profile_config_disabled_skills(profile_home, effective_disabled)
    for rel_b in effective_disabled:
        bundled_dir = skills_dir / Path(rel_b)
        if bundled_dir.is_dir():
            arch_dest = agent_reg_dir / "archived-bundled" / Path(rel_b)
            arch_dest.parent.mkdir(parents=True, exist_ok=True)
            if arch_dest.exists():
                shutil.rmtree(arch_dest)
            shutil.move(str(bundled_dir), str(arch_dest))

    # Write `.usage.json` (`locked: true, pinned: true`)
    usage_path = skills_dir / ".usage.json"
    usage_data = json.loads(usage_path.read_text(encoding="utf-8")) if usage_path.is_file() else {}
    for pkg_id in materialized_map:
        usage_data[pkg_id] = {
            **usage_data.get(pkg_id, {}),
            "state": "active",
            "pinned": True,
            "locked": True,
        }
        for d in skills_dir.iterdir():
            if d.name.startswith(f"{pkg_id}--"):
                usage_data[d.name] = {
                    **usage_data.get(d.name, {}),
                    "state": "active",
                    "pinned": True,
                    "locked": True,
                }
    usage_path.write_text(json.dumps(usage_data, indent=2) + "\n", encoding="utf-8")
    (profile_home / ".skills_prompt_snapshot.json").unlink(missing_ok=True)

    # Update role-manifest.json & append routing instructions
    rm_path = workers_root / spec["role_slug"] / "role-manifest.json"
    if rm_path.is_file():
        rm = json.loads(rm_path.read_text(encoding="utf-8"))
        rm["toolsets"] = spec["toolsets"]
        rm_path.write_text(json.dumps(rm, indent=2) + "\n", encoding="utf-8")
    _append_skill_routing_to_instructions(spec, profiles_root=profiles_root, workers_root=workers_root)

    # Sync with Paperclip Skills Store API when reachable
    pc, company_id, slug_uuids = _try_get_reachable_paperclip()
    agent_uuid = slug_uuids.get(role_slug)
    paperclip_sync_status = "DEFERRED_OFFLINE"
    desired_keys: list[str] = []
    core_keys = [
        "paperclipai/paperclip/paperclip",
        "paperclipai/paperclip/complain",
        "paperclipai/paperclip/suggestion-box",
    ]

    if pc is not None and company_id and agent_uuid:
        try:
            _ensure_paperclip_registry_workspace(pc, company_id, reviewed_root)
            for rec in installed_records:
                pkg_id = rec["pkg_id"]
                lk = lock_pkgs[pkg_id]
                imp_res = pc.import_company_skill(company_id, str(reviewed_root / pkg_id))
                imported = (imp_res.get("imported") or [None])[0]
                if imported:
                    desired_keys.append(imported["key"])
                    rec["paperclip_skill_id"] = imported["id"]
                    rec["paperclip_skill_key"] = imported["key"]
                    try:
                        pc.update_company_skill(
                            company_id,
                            imported["id"],
                            {
                                "metadata": {
                                    "pkgId": pkg_id,
                                    "pinnedCommitSha": lk["pinned_commit_sha"],
                                    "repoUrl": lk["repo_url"],
                                    "subpath": lk["subpath"],
                                    "licenseSpdx": lk["license_spdx"],
                                    "packageSha256": lk["upstream_package_sha256"],
                                    "securityGate": "PASS",
                                    "categoryHint": rec["category"],
                                }
                            },
                        )
                    except Exception:
                        pass

            ag = pc.get_agent(agent_uuid)
            acfg = dict(ag.get("adapterConfig") or {})
            acfg["env"] = {**(acfg.get("env") or {}), "HERMES_HOME": str(profile_home)}
            acfg["toolsets"] = spec["toolsets"]
            pc.update_agent(agent_uuid, {"adapterConfig": acfg})
            if ag.get("status") == "error":
                try:
                    pc.resume_agent(agent_uuid)
                except Exception:
                    pass

            pc.sync_agent_skills(agent_uuid, core_keys + desired_keys, mode="replace")
            paperclip_sync_status = "SYNCED"
        except Exception as exc:
            paperclip_sync_status = f"WARNING:{str(exc)[:120]}"

    now_iso = datetime.now(timezone.utc).isoformat()
    skill_set_doc = {
        "agent": spec["role_slug"],
        "agent_uuid": agent_uuid,
        "agent_name": spec["name"],
        "handle": spec["handle"],
        "profile": spec["profile"],
        "hermes_home": str(profile_home),
        "toolsets": spec["toolsets"],
        "updated_at": now_iso,
        "paperclip_sync": paperclip_sync_status,
        "primary": spec["primary"],
        "specialist": spec["specialist"],
        "on_demand": spec["on_demand"],
        "reference_only": spec["reference_only"],
        "experimental": spec["experimental"],
        "experimental_enabled": enable_experimental,
        "disabled_bundled": effective_disabled,
        "strict_oss_fallbacks_activated": activated_fallbacks,
        "paperclip_desired_skills": core_keys + desired_keys,
        "materialized_paths": materialized_map,
        "link_modes": link_modes,
        "isolated_references": isolated_refs,
        "isolated_experimental": isolated_exp,
        "installed_packages": installed_records,
    }
    (agent_reg_dir / "skill-set.json").write_text(json.dumps(skill_set_doc, indent=2) + "\n", encoding="utf-8")

    yaml_lines = [
        f"agent: {spec['role_slug']}",
        f'agent_uuid: "{agent_uuid or ""}"',
        f"profile: {spec['profile']}",
        f'toolsets: "{spec["toolsets"]}"',
        "primary:" + ("" if spec["primary"] else " []"),
        *[f"  - {x}" for x in spec["primary"]],
        "specialist:" + ("" if spec["specialist"] else " []"),
        *[f"  - {x}" for x in spec["specialist"]],
        "on_demand:" + ("" if spec["on_demand"] else " []"),
        *[f"  - {x}" for x in spec["on_demand"]],
        "reference_only:" + ("" if spec["reference_only"] else " []"),
        *[f"  - {x}" for x in spec["reference_only"]],
        "experimental:" + ("" if spec["experimental"] else " []"),
        *[f"  - {x}" for x in spec["experimental"]],
    ]
    (agent_reg_dir / "skill-set.yaml").write_text("\n".join(yaml_lines) + "\n", encoding="utf-8")

    write_global_assignments_manifest(registry_root=registry_root, profiles_root=profiles_root)
    return skill_set_doc


def install_all_agents_skills(
    *,
    registry_root: Path = SKILL_REGISTRY_DIR,
    profiles_root: Path = PROFILES_ROOT,
    workers_root: Path = WORKERS_DIR,
    enable_experimental: bool = False,
    strict_oss: bool = False,
    offline: bool = False,
) -> dict[str, Any]:
    """Run Stage-1 once across all required packages, then Stage-2 across all 11 agent profiles."""
    lock_doc, policy_doc = load_lock_and_policy()
    needed: set[str] = {"skill-scanner"}
    specs = build_agent_skill_specs(registry_root=registry_root, workers_root=workers_root)
    for s in specs:
        needed.update(s["primary"], s["specialist"], s["on_demand"], s["reference_only"], s["experimental"])

    prep = stage1_and_stage2_prepare_packages(
        sorted(needed),
        registry_root=registry_root,
        workers_root=workers_root,
        offline=offline,
        strict_oss=strict_oss,
        lock_doc=lock_doc,
        policy_doc=policy_doc,
    )
    per_agent = {}
    for s in specs:
        per_agent[s["role_slug"]] = install_agent_skills(
            s["role_slug"],
            registry_root=registry_root,
            profiles_root=profiles_root,
            workers_root=workers_root,
            enable_experimental=enable_experimental,
            strict_oss=strict_oss,
            offline=offline,
            skip_download=True,
        )
    return {
        "installed_agents": len(per_agent),
        "stage1_summary": {
            "gated_count": len(prep["gated_packages"]),
            "skipped_count": len(prep["skipped_packages"]),
        },
        "agents": per_agent,
    }


def write_global_assignments_manifest(
    *,
    registry_root: Path = SKILL_REGISTRY_DIR,
    profiles_root: Path = PROFILES_ROOT,
) -> dict[str, Any]:
    lock_doc, _ = load_lock_and_policy()
    lock_pkgs = lock_doc["packages"]
    _, company_id, slug_uuids = _try_get_reachable_paperclip()
    agents_reg_root = registry_root / "agents"
    manifests_out_dir = registry_root / "manifests"
    manifests_out_dir.mkdir(parents=True, exist_ok=True)

    assignments_by_agent: dict[str, Any] = {}
    for spec in build_agent_skill_specs(registry_root=registry_root):
        ss_file = agents_reg_root / spec["agent_dir"] / "skill-set.json"
        ss = json.loads(ss_file.read_text(encoding="utf-8")) if ss_file.is_file() else None
        profile_home = profiles_root / spec["profile"]
        usage_file = profile_home / "skills" / ".usage.json"
        usage_map = json.loads(usage_file.read_text(encoding="utf-8")) if usage_file.is_file() else {}

        last_used_by_skill: dict[str, str] = {}
        db_file = profile_home / "state.db"
        if db_file.is_file():
            try:
                con = sqlite3.connect(str(db_file))
                rows = con.execute(
                    "SELECT content, timestamp FROM messages WHERE content LIKE '%skill_view%' OR tool_name='skill_view' ORDER BY id DESC LIMIT 40"
                ).fetchall()
                con.close()
                for content_str, ts_val in rows:
                    c_txt = str(content_str or "")
                    for pkg_id in (*spec["primary"], *spec["specialist"], *spec["on_demand"]):
                        if pkg_id in c_txt and pkg_id not in last_used_by_skill:
                            last_used_by_skill[pkg_id] = str(ts_val or "")
            except Exception:
                pass

        items: list[dict[str, Any]] = []
        for cat_key, cat_label, default_status in [
            ("primary", "PRIMARY", "ACTIVE"),
            ("specialist", "SPECIALIST", "ACTIVE"),
            ("on_demand", "ON_DEMAND", "AVAILABLE"),
            ("reference_only", "REFERENCE_ONLY", "REFERENCE_ONLY"),
            ("experimental", "EXPERIMENTAL", "EXPERIMENTAL"),
        ]:
            for pkg_id in spec[cat_key]:
                lk = lock_pkgs[pkg_id]
                urec = usage_map.get(pkg_id) or {}
                last_used = urec.get("last_viewed_at") or urec.get("last_used_at") or last_used_by_skill.get(pkg_id)
                is_mat = bool(ss and pkg_id in (ss.get("materialized_paths") or {}))
                status_val = default_status if (is_mat or cat_key in ("reference_only", "experimental")) else "PENDING_INSTALL"
                items.append({
                    "pkg_id": pkg_id,
                    "display_name": lk["display_name"],
                    "category": cat_label,
                    "status": status_val,
                    "version": lk["pinned_commit_sha"][:10],
                    "pinned_commit_sha": lk["pinned_commit_sha"],
                    "repo_url": lk["repo_url"],
                    "license_spdx": lk["license_spdx"],
                    "upstream_package_sha256": lk["upstream_package_sha256"],
                    "redistribution_policy": lk["redistribution_policy"],
                    "scripts_count": len(lk.get("scripts") or []),
                    "files_count": len(lk.get("files") or []),
                    "dependency_status": "READY",
                    "last_verified": ss.get("updated_at") if ss else None,
                    "last_used": last_used,
                })

        assignments_by_agent[spec["role_slug"]] = {
            "agent_uuid": (ss.get("agent_uuid") if ss else None) or slug_uuids.get(spec["role_slug"]),
            "agent_name": spec["name"],
            "handle": spec["handle"],
            "profile": spec["profile"],
            "toolsets": spec["toolsets"],
            "installed": ss is not None,
            "updated_at": ss.get("updated_at") if ss else None,
            "skills": items,
        }

    payload = {
        "schema_version": "2.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "company_id": company_id,
        "agents": assignments_by_agent,
    }
    out_path = manifests_out_dir / "agent-skill-assignments.json"
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="ALLINAGENT Central Agent Skills Manager")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ver = sub.add_parser("verify-manifest")
    p_ver.add_argument("--json", action="store_true", default=True)

    p_inst = sub.add_parser("install")
    p_inst.add_argument("--agent", required=True, help="role_slug or 'all'")
    p_inst.add_argument("--enable-experimental", action="store_true")
    p_inst.add_argument("--strict-oss", action="store_true")
    p_inst.add_argument("--offline", action="store_true")
    p_inst.add_argument("--registry-dir", default=str(SKILL_REGISTRY_DIR))
    p_inst.add_argument("--hermes-home", default=None)

    p_rec = sub.add_parser("reconcile")
    p_rec.add_argument("--enable-experimental", action="store_true")
    p_rec.add_argument("--strict-oss", action="store_true")
    p_rec.add_argument("--offline", action="store_true")

    sub.add_parser("status")

    args = parser.parse_args()
    if args.cmd == "verify-manifest":
        res = verify_manifest()
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1

    if args.cmd == "install":
        reg_dir = Path(args.registry_dir).resolve()
        prof_dir = (Path(args.hermes_home).resolve() / "profiles") if args.hermes_home else PROFILES_ROOT
        if args.agent == "all":
            res = install_all_agents_skills(
                registry_root=reg_dir,
                profiles_root=prof_dir,
                enable_experimental=args.enable_experimental,
                strict_oss=args.strict_oss,
                offline=args.offline,
            )
            print(json.dumps({"installed_agents": res["installed_agents"], "stage1": res["stage1_summary"]}, indent=2))
        else:
            res = install_agent_skills(
                args.agent,
                registry_root=reg_dir,
                profiles_root=prof_dir,
                enable_experimental=args.enable_experimental,
                strict_oss=args.strict_oss,
                offline=args.offline,
            )
            print(json.dumps(res, indent=2))
        return 0

    if args.cmd == "reconcile":
        res = install_all_agents_skills(
            enable_experimental=args.enable_experimental,
            strict_oss=args.strict_oss,
            offline=args.offline,
        )
        print(json.dumps({"reconciled_agents": res["installed_agents"], "status": "OK"}, indent=2))
        return 0

    if args.cmd == "status":
        print(json.dumps(write_global_assignments_manifest(), indent=2))
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
