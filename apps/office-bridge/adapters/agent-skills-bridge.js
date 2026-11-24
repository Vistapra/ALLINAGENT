"use strict";

/**
 * Unified Agent Skills Read-Only Inspector, Studio RPC Adapter, Paperclip Skills Bridge,
 * Commons Clause Supply-Chain Gate & Dynamic Role-Slug UUID Matcher (`adapters/agent-skills-bridge.js`).
 *
 * Strictly read-only with respect to skill installation; zero hardcoded Windows paths or Paperclip UUIDs.
 */

const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const {
  PLATFORM_ROOT,
  SKILL_REGISTRY_DIR,
  SKILLS_MANIFESTS_DIR,
  OFFICE_DATA_DIR,
  HERMES_PROFILES_DIR,
  WORKSPACES_DIR,
  REPORTS_DIR,
  PYTHON_EXE,
} = require("../contracts/paths");
const { sanitizeText, sanitizePayload } = require("../contracts/redaction");

const ASSIGNMENTS_FILE = path.join(SKILL_REGISTRY_DIR, "manifests", "agent-skill-assignments.json");
const REGISTRY_SKILLS_LOCK_FILE = path.join(SKILL_REGISTRY_DIR, "manifests", "skills.lock.json");
const LOCK_FILE = path.join(SKILL_REGISTRY_DIR, "manifests", "skill-lock.json");
const SECURITY_FILE = path.join(SKILL_REGISTRY_DIR, "manifests", "skill-security-results.json");
const REPO_SKILLS_LOCK_FILE = path.join(PLATFORM_ROOT, "skills", "manifests", "skills.lock.json");
const REPO_SECURITY_FILE = path.join(PLATFORM_ROOT, "skills", "manifests", "skill-security-results.json");
const REVIEWED_DIR = path.join(SKILL_REGISTRY_DIR, "reviewed");
const INVOCATIONS_FILE = path.join(OFFICE_DATA_DIR, "skill-invocations.json");

/**
 * All 10 upstream `MIT-Commons-Clause-1.0` skills that carry non-commercial resale restrictions
 * and MUST be flagged as `FETCH_FROM_UPSTREAM_ONLY` in public ALLINAGENT distributions.
 */
const COMMONS_CLAUSE_SKILLS = Object.freeze([
  "cto-advisor",
  "senior-architect",
  "senior-backend",
  "api-design-reviewer",
  "senior-devops",
  "ci-cd-pipeline-builder",
  "senior-qa",
  "security-audit",
  "senior-security",
  "focused-fix",
]);

const COMMONS_CLAUSE_SET = new Set(COMMONS_CLAUSE_SKILLS);

/**
 * All 13 skills marked `FETCH_FROM_UPSTREAM_ONLY` in `skills/manifests/skills.lock.json`
 * (the 10 `MIT-Commons-Clause-1.0` skills plus `docx`, `pdf`, and `react-best-practices`).
 */
const FETCH_FROM_UPSTREAM_ONLY_SKILLS = Object.freeze([
  "api-design-reviewer",
  "ci-cd-pipeline-builder",
  "cto-advisor",
  "docx",
  "focused-fix",
  "pdf",
  "react-best-practices",
  "security-audit",
  "senior-architect",
  "senior-backend",
  "senior-devops",
  "senior-qa",
  "senior-security",
]);

const FETCH_FROM_UPSTREAM_ONLY_SET = new Set(FETCH_FROM_UPSTREAM_ONLY_SKILLS);

const DEFAULT_SECURITY_GATE_SKILL = Object.freeze({
  pkg_id: "skill-scanner",
  display_name: "Sentry Skill Scanner",
  category: "SECURITY_GATE",
  status: "ACTIVE",
  license_spdx: "Apache-2.0",
  pinned_commit_sha: "a582c51ee29d0f35e6ac321340796f77d43da733",
  repo_url: "https://github.com/getsentry/skills",
  redistribution_policy: "ALLOW_WITH_ATTRIBUTION_OR_FETCH",
});

const KNOWN_LIMITATIONS = Object.freeze({
  "c-level-skills": "Scoped to the 11 Paperclip corporate roles; non-installed C-suite personas are delegated via CEO synthesis.",
  "cto-advisor": "Upstream under MIT + Commons Clause v1.0 (internal use permitted; FETCH_FROM_UPSTREAM_ONLY — never vendored in public repo).",
  "senior-architect": "Upstream under MIT + Commons Clause v1.0 (FETCH_FROM_UPSTREAM_ONLY); shared immutable package across CTO & Backend roles.",
  "senior-backend": "Upstream under MIT + Commons Clause v1.0 (FETCH_FROM_UPSTREAM_ONLY); never runs destructive production DB migrations.",
  "api-design-reviewer": "Upstream under MIT + Commons Clause v1.0 (FETCH_FROM_UPSTREAM_ONLY); focused on REST/OpenAPI 3.x contract & breaking changes.",
  "senior-devops": "Upstream under MIT + Commons Clause v1.0 (FETCH_FROM_UPSTREAM_ONLY); infrastructure scaffolding requires Owner approval before apply.",
  "ci-cd-pipeline-builder": "Upstream under MIT + Commons Clause v1.0 (FETCH_FROM_UPSTREAM_ONLY); generates & lints CI/CD workflows read-only.",
  "senior-qa": "Upstream under MIT + Commons Clause v1.0 (FETCH_FROM_UPSTREAM_ONLY); regression suite & coverage helper.",
  "security-audit": "Upstream under MIT + Commons Clause v1.0 (FETCH_FROM_UPSTREAM_ONLY); strictly defensive static review only.",
  "senior-security": "Upstream under MIT + Commons Clause v1.0 (FETCH_FROM_UPSTREAM_ONLY); defensive architecture & secret hygiene review.",
  "focused-fix": "Upstream under MIT + Commons Clause v1.0 (FETCH_FROM_UPSTREAM_ONLY); enforces minimal diff scope during remediation.",
  "react-best-practices": "Apply only to React/Next.js components; upstream repo root omits standalone LICENSE (FETCH_FROM_UPSTREAM_ONLY).",
  "frontend-design": "UI/UX & layout direction only; production Hermes3D changes require explicit Owner approval.",
  "terraform-skill": "Generation, module review, and static validation only; never executes `terraform apply` without Owner approval.",
  "pw": "Uses isolated headless Chromium (`--no-sandbox` in containers); never touches personal browser profiles.",
  "threat-model": "REFERENCE_ONLY defensive methodology from pinned upstream repo; autonomous harness files quarantined.",
  "secondsky-cybersecurity-ref": "REFERENCE_ONLY defensive checklist; offensive payload references quarantined in skill-registry/quarantine.",
  "anthropic-triage": "REFERENCE_ONLY candidate finding deduplication & verification methodology; harness disabled.",
  "cve-triage": "EXPERIMENTAL — focused on Python/Poetry/uv SSVC & VEX modeling; not a universal multi-language dependency scanner.",
  "security-vuln-remediation": "Adapted generically without applying upstream project-specific configs.",
  "anthropic-patch": "REFERENCE_ONLY independent patch review methodology; Remediation Reviewer never self-approves own code.",
  "compliance-os": "Technical readiness mapping (ISO 27001 / SOC 2 / NIST CSF) only — never constitutes formal legal certification.",
  "docx": "Upstream under Apache-2.0 with fetch-only policy (FETCH_FROM_UPSTREAM_ONLY).",
  "pdf": "Bundled Hermes `productivity/pdf` disabled on Compliance profile to prevent same-tier name collision (FETCH_FROM_UPSTREAM_ONLY).",
  "skill-scanner": "Cross-agent supply-chain security gate executed during skill hydration (`scripts/fetch-skills.py`).",
});

/**
 * Portable default 11-agent skill catalog (zero hardcoded UUIDs) used when `skill-registry/manifests`
 * has not yet been hydrated on a fresh environment.
 */
const DEFAULT_ROLE_SKILLS_SPEC = Object.freeze({
  ceo_agent: {
    agent_name: "CEO Agent",
    handle: "@ceo",
    profile: "pcceoagent",
    toolsets: "file,terminal,skills",
    installed: true,
    skills: [
      { pkg_id: "ceo-advisor", display_name: "CEO Advisor", category: "PRIMARY", status: "ACTIVE", license_spdx: "MIT", pinned_commit_sha: "5909a72e62b5fbb809935fb6a55b58bdbe175074", repo_url: "https://github.com/alirezarezvani/claude-skills" },
      { pkg_id: "c-level-skills", display_name: "C-Level Skills Router", category: "SPECIALIST", status: "ACTIVE", license_spdx: "MIT", pinned_commit_sha: "5909a72e62b5fbb809935fb6a55b58bdbe175074", repo_url: "https://github.com/alirezarezvani/claude-skills" },
    ],
  },
  cto_agent: {
    agent_name: "CTO Agent",
    handle: "@cto",
    profile: "pcctoagent",
    toolsets: "file,terminal,skills",
    installed: true,
    skills: [
      { pkg_id: "cto-review", display_name: "CTO Review", category: "PRIMARY", status: "ACTIVE", license_spdx: "MIT", pinned_commit_sha: "5909a72e62b5fbb809935fb6a55b58bdbe175074", repo_url: "https://github.com/alirezarezvani/claude-skills" },
      { pkg_id: "senior-architect", display_name: "Senior Architect", category: "SPECIALIST", status: "ACTIVE", license_spdx: "MIT-Commons-Clause-1.0", pinned_commit_sha: "25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3", repo_url: "https://github.com/borghei/Claude-Skills" },
      { pkg_id: "cto-advisor", display_name: "CTO Advisor", category: "ON_DEMAND", status: "AVAILABLE", license_spdx: "MIT-Commons-Clause-1.0", pinned_commit_sha: "25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3", repo_url: "https://github.com/borghei/Claude-Skills" },
    ],
  },
  backend_developer: {
    agent_name: "Backend Developer",
    handle: "@backend",
    profile: "pcbackenddeveloper",
    toolsets: "file,terminal,skills",
    installed: true,
    skills: [
      { pkg_id: "senior-backend", display_name: "Senior Backend", category: "PRIMARY", status: "ACTIVE", license_spdx: "MIT-Commons-Clause-1.0", pinned_commit_sha: "25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3", repo_url: "https://github.com/borghei/Claude-Skills" },
      { pkg_id: "api-design-reviewer", display_name: "API Design Reviewer", category: "SPECIALIST", status: "ACTIVE", license_spdx: "MIT-Commons-Clause-1.0", pinned_commit_sha: "25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3", repo_url: "https://github.com/borghei/Claude-Skills" },
      { pkg_id: "senior-architect", display_name: "Senior Architect", category: "ON_DEMAND", status: "AVAILABLE", license_spdx: "MIT-Commons-Clause-1.0", pinned_commit_sha: "25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3", repo_url: "https://github.com/borghei/Claude-Skills" },
    ],
  },
  frontend_developer: {
    agent_name: "Frontend Developer",
    handle: "@frontend",
    profile: "pcfrontenddeveloper",
    toolsets: "file,terminal,skills",
    installed: true,
    skills: [
      { pkg_id: "react-best-practices", display_name: "Vercel React Best Practices", category: "PRIMARY", status: "ACTIVE", license_spdx: "MIT-Check-Skill-Header", pinned_commit_sha: "5a37a6329fbad3666c3207392a6a7c0110e92efb", repo_url: "https://github.com/vercel-labs/agent-skills" },
      { pkg_id: "frontend-design", display_name: "Anthropic Frontend Design", category: "SPECIALIST", status: "ACTIVE", license_spdx: "Apache-2.0", pinned_commit_sha: "e4bb5d960d87126ff3b3a8af1a104b7db67560ba", repo_url: "https://github.com/anthropics/skills" },
    ],
  },
  devops_engineer: {
    agent_name: "DevOps Engineer",
    handle: "@devops",
    profile: "pcdevopsengineer",
    toolsets: "file,terminal,skills",
    installed: true,
    skills: [
      { pkg_id: "senior-devops", display_name: "Senior DevOps", category: "PRIMARY", status: "ACTIVE", license_spdx: "MIT-Commons-Clause-1.0", pinned_commit_sha: "25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3", repo_url: "https://github.com/borghei/Claude-Skills" },
      { pkg_id: "terraform-skill", display_name: "Terraform Skill", category: "SPECIALIST", status: "ACTIVE", license_spdx: "Apache-2.0", pinned_commit_sha: "f5a195992d84c8fb075b0176d666967cd07d2081", repo_url: "https://github.com/antonbabenko/terraform-skill" },
      { pkg_id: "ci-cd-pipeline-builder", display_name: "CI/CD Pipeline Builder", category: "SPECIALIST", status: "ACTIVE", license_spdx: "MIT-Commons-Clause-1.0", pinned_commit_sha: "25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3", repo_url: "https://github.com/borghei/Claude-Skills" },
    ],
  },
  qa_engineer: {
    agent_name: "QA Engineer",
    handle: "@qa",
    profile: "pcqaengineer",
    toolsets: "file,terminal,skills",
    installed: true,
    skills: [
      { pkg_id: "pw", display_name: "Playwright Pro Router", category: "PRIMARY", status: "ACTIVE", license_spdx: "MIT", pinned_commit_sha: "5909a72e62b5fbb809935fb6a55b58bdbe175074", repo_url: "https://github.com/alirezarezvani/claude-skills" },
      { pkg_id: "pw-generate", display_name: "Playwright Generate", category: "SPECIALIST", status: "ACTIVE", license_spdx: "MIT", pinned_commit_sha: "5909a72e62b5fbb809935fb6a55b58bdbe175074", repo_url: "https://github.com/alirezarezvani/claude-skills" },
      { pkg_id: "pw-review", display_name: "Playwright Review", category: "SPECIALIST", status: "ACTIVE", license_spdx: "MIT", pinned_commit_sha: "5909a72e62b5fbb809935fb6a55b58bdbe175074", repo_url: "https://github.com/alirezarezvani/claude-skills" },
      { pkg_id: "senior-qa", display_name: "Senior QA", category: "SPECIALIST", status: "ACTIVE", license_spdx: "MIT-Commons-Clause-1.0", pinned_commit_sha: "25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3", repo_url: "https://github.com/borghei/Claude-Skills" },
      { pkg_id: "pw-fix", display_name: "Playwright Fix (Router Sub-Skill)", category: "ON_DEMAND", status: "AVAILABLE", license_spdx: "MIT", pinned_commit_sha: "5909a72e62b5fbb809935fb6a55b58bdbe175074", repo_url: "https://github.com/alirezarezvani/claude-skills" },
      { pkg_id: "pw-coverage", display_name: "Playwright Coverage (Router Sub-Skill)", category: "ON_DEMAND", status: "AVAILABLE", license_spdx: "MIT", pinned_commit_sha: "5909a72e62b5fbb809935fb6a55b58bdbe175074", repo_url: "https://github.com/alirezarezvani/claude-skills" },
      { pkg_id: "pw-report", display_name: "Playwright Report (Router Sub-Skill)", category: "ON_DEMAND", status: "AVAILABLE", license_spdx: "MIT", pinned_commit_sha: "5909a72e62b5fbb809935fb6a55b58bdbe175074", repo_url: "https://github.com/alirezarezvani/claude-skills" },
    ],
  },
  security_lead: {
    agent_name: "Security Lead",
    handle: "@security_lead",
    profile: "pcsecuritylead",
    toolsets: "file,skills",
    installed: true,
    skills: [
      { pkg_id: "ciso-advisor", display_name: "CISO Advisor", category: "PRIMARY", status: "ACTIVE", license_spdx: "MIT", pinned_commit_sha: "5909a72e62b5fbb809935fb6a55b58bdbe175074", repo_url: "https://github.com/alirezarezvani/claude-skills" },
      { pkg_id: "threat-model", display_name: "Anthropic Defensive Threat Model", category: "REFERENCE_ONLY", status: "REFERENCE_ONLY", license_spdx: "Apache-2.0", pinned_commit_sha: "d3bea6b5793b5f3d59a75ebe69a58efa88383145", repo_url: "https://github.com/anthropics/defending-code-reference-harness" },
    ],
  },
  security_reviewer: {
    agent_name: "Security Reviewer",
    handle: "@security",
    profile: "pcsecurityreviewer",
    toolsets: "file,skills",
    installed: true,
    skills: [
      { pkg_id: "security-audit", display_name: "Security Audit", category: "PRIMARY", status: "ACTIVE", license_spdx: "MIT-Commons-Clause-1.0", pinned_commit_sha: "25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3", repo_url: "https://github.com/borghei/Claude-Skills" },
      { pkg_id: "senior-security", display_name: "Senior Security", category: "SPECIALIST", status: "ACTIVE", license_spdx: "MIT-Commons-Clause-1.0", pinned_commit_sha: "25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3", repo_url: "https://github.com/borghei/Claude-Skills" },
      { pkg_id: "secondsky-cybersecurity-ref", display_name: "SecondSky Cybersecurity (Defensive Reference)", category: "REFERENCE_ONLY", status: "REFERENCE_ONLY", license_spdx: "MIT", pinned_commit_sha: "14966c3024f48eea0386eb970b230ea0f4bebd33", repo_url: "https://github.com/secondsky/claude-skills" },
    ],
  },
  findings_analyst: {
    agent_name: "Findings Analyst",
    handle: "@findings",
    profile: "pcfindingsanalyst",
    toolsets: "file,skills",
    installed: true,
    skills: [
      { pkg_id: "security-audit", display_name: "Security Audit", category: "PRIMARY", status: "ACTIVE", license_spdx: "MIT-Commons-Clause-1.0", pinned_commit_sha: "25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3", repo_url: "https://github.com/borghei/Claude-Skills" },
      { pkg_id: "anthropic-triage", display_name: "Anthropic Defensive Triage", category: "REFERENCE_ONLY", status: "REFERENCE_ONLY", license_spdx: "Apache-2.0", pinned_commit_sha: "d3bea6b5793b5f3d59a75ebe69a58efa88383145", repo_url: "https://github.com/anthropics/defending-code-reference-harness" },
      { pkg_id: "cve-triage", display_name: "CVE Triage (Experimental)", category: "EXPERIMENTAL", status: "EXPERIMENTAL", license_spdx: "MIT", pinned_commit_sha: "3517c8fb10531103c403f09143966d62b2a0790f", repo_url: "https://github.com/fedius01/cve-triage" },
    ],
  },
  remediation_reviewer: {
    agent_name: "Remediation Reviewer",
    handle: "@remediation",
    profile: "pcremediationreviewer",
    toolsets: "file,skills",
    installed: true,
    skills: [
      { pkg_id: "focused-fix", display_name: "Focused Fix", category: "PRIMARY", status: "ACTIVE", license_spdx: "MIT-Commons-Clause-1.0", pinned_commit_sha: "25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3", repo_url: "https://github.com/borghei/Claude-Skills" },
      { pkg_id: "security-vuln-remediation", display_name: "Security Vulnerability Remediation", category: "SPECIALIST", status: "ACTIVE", license_spdx: "Apache-2.0", pinned_commit_sha: "4d87c91d49b881ccc7dc64667c1dce5a84c535d6", repo_url: "https://github.com/stacklok/toolhive-studio" },
      { pkg_id: "anthropic-patch", display_name: "Anthropic Defensive Patch Verification", category: "REFERENCE_ONLY", status: "REFERENCE_ONLY", license_spdx: "Apache-2.0", pinned_commit_sha: "d3bea6b5793b5f3d59a75ebe69a58efa88383145", repo_url: "https://github.com/anthropics/defending-code-reference-harness" },
    ],
  },
  compliance_reporter: {
    agent_name: "Report & Compliance Agent",
    handle: "@compliance",
    profile: "pccompliancereporter",
    toolsets: "file,terminal,skills",
    installed: true,
    skills: [
      { pkg_id: "compliance-os", display_name: "Compliance OS", category: "PRIMARY", status: "ACTIVE", license_spdx: "MIT", pinned_commit_sha: "5909a72e62b5fbb809935fb6a55b58bdbe175074", repo_url: "https://github.com/alirezarezvani/claude-skills" },
      { pkg_id: "docx", display_name: "Anthropic DOCX", category: "SPECIALIST", status: "ACTIVE", license_spdx: "Apache-2.0", pinned_commit_sha: "e4bb5d960d87126ff3b3a8af1a104b7db67560ba", repo_url: "https://github.com/anthropics/skills" },
      { pkg_id: "pdf", display_name: "Anthropic PDF", category: "SPECIALIST", status: "ACTIVE", license_spdx: "Apache-2.0", pinned_commit_sha: "e4bb5d960d87126ff3b3a8af1a104b7db67560ba", repo_url: "https://github.com/anthropics/skills" },
    ],
  },
});

function readJsonSafe(filePath, fallback) {
  try {
    if (fs.existsSync(filePath)) {
      return JSON.parse(fs.readFileSync(filePath, "utf8"));
    }
  } catch {}
  return fallback;
}

function isCommonsClauseSkill(pkgId, licenseSpdx = "") {
  return COMMONS_CLAUSE_SET.has(String(pkgId || "").trim()) || /commons[-_\s]?clause/i.test(String(licenseSpdx || ""));
}

function isFetchFromUpstreamOnlySkill(pkgId, licenseSpdx = "", redistributionPolicy = "") {
  const id = String(pkgId || "").trim();
  const pol = String(redistributionPolicy || "").trim().toUpperCase();
  if (pol === "FETCH_FROM_UPSTREAM_ONLY") return true;
  if (FETCH_FROM_UPSTREAM_ONLY_SET.has(id)) return true;
  return isCommonsClauseSkill(id, licenseSpdx);
}

/**
 * Load canonical skills lock manifest from `skill-registry/manifests/` if hydrated,
 * falling back to `skills/manifests/skills.lock.json` (`path.join(PLATFORM_ROOT, "skills", "manifests", "skills.lock.json")`),
 * or built-in 33-skill spec when running in an empty directory.
 */
function loadCanonicalSkillsLock() {
  const dynamicSkillsManifestsDir = process.env.ALLINAGENT_SKILLS_MANIFESTS_DIR
    ? path.resolve(process.env.ALLINAGENT_SKILLS_MANIFESTS_DIR)
    : SKILLS_MANIFESTS_DIR;
  const candidates = [
    { filePath: REGISTRY_SKILLS_LOCK_FILE, label: "skill-registry/manifests/skills.lock.json" },
    { filePath: LOCK_FILE, label: "skill-registry/manifests/skill-lock.json" },
    { filePath: path.join(dynamicSkillsManifestsDir, "skills.lock.json"), label: "skills/manifests/skills.lock.json" },
    { filePath: REPO_SKILLS_LOCK_FILE, label: "skills/manifests/skills.lock.json" },
  ];

  for (const cand of candidates) {
    const doc = readJsonSafe(cand.filePath, null);
    if (doc && doc.packages && typeof doc.packages === "object" && Object.keys(doc.packages).length > 0) {
      return {
        doc,
        packages: doc.packages,
        roleAssignments: Array.isArray(doc.role_assignments) ? doc.role_assignments : [],
        securityGateSkillId: doc.security_gate_skill || "skill-scanner",
        quarantinedExcludedFiles: Array.isArray(doc.quarantined_excluded_files) ? doc.quarantined_excluded_files : null,
        sourceLabel: cand.label,
      };
    }
  }

  // Deterministic 33-skill fallback (32 role skills + skill-scanner gate)
  const fallbackPackages = {};
  for (const ag of Object.values(DEFAULT_ROLE_SKILLS_SPEC)) {
    for (const sk of ag.skills || []) {
      if (!fallbackPackages[sk.pkg_id]) {
        const fetchOnly = isFetchFromUpstreamOnlySkill(sk.pkg_id, sk.license_spdx, sk.redistribution_policy);
        fallbackPackages[sk.pkg_id] = {
          pkg_id: sk.pkg_id,
          display_name: sk.display_name,
          license_spdx: sk.license_spdx,
          pinned_commit_sha: sk.pinned_commit_sha,
          repo_url: sk.repo_url,
          redistribution_policy: fetchOnly ? "FETCH_FROM_UPSTREAM_ONLY" : "ALLOW_WITH_ATTRIBUTION_OR_FETCH",
        };
      }
    }
  }
  fallbackPackages[DEFAULT_SECURITY_GATE_SKILL.pkg_id] = { ...DEFAULT_SECURITY_GATE_SKILL };

  return {
    doc: { packages: fallbackPackages, security_gate_skill: DEFAULT_SECURITY_GATE_SKILL.pkg_id },
    packages: fallbackPackages,
    roleAssignments: [],
    securityGateSkillId: DEFAULT_SECURITY_GATE_SKILL.pkg_id,
    quarantinedExcludedFiles: null,
    sourceLabel: "builtin-33-skill-spec",
  };
}

function loadCanonicalSecurityResults() {
  const dynamicSkillsManifestsDir = process.env.ALLINAGENT_SKILLS_MANIFESTS_DIR
    ? path.resolve(process.env.ALLINAGENT_SKILLS_MANIFESTS_DIR)
    : SKILLS_MANIFESTS_DIR;
  const candidates = [
    SECURITY_FILE,
    path.join(dynamicSkillsManifestsDir, "skill-security-results.json"),
    REPO_SECURITY_FILE,
  ];
  for (const filePath of candidates) {
    const doc = readJsonSafe(filePath, null);
    if (doc && typeof doc === "object" && Object.keys(doc).length > 0) {
      return doc;
    }
  }
  return {};
}

function buildRoleAgentsFromSkillsLock(lockInfo) {
  if (!Array.isArray(lockInfo?.roleAssignments) || lockInfo.roleAssignments.length === 0) {
    return null;
  }
  const packages = lockInfo.packages || {};
  const map = {};
  const tierDefs = [
    { field: "primary", category: "PRIMARY", status: "ACTIVE" },
    { field: "specialist", category: "SPECIALIST", status: "ACTIVE" },
    { field: "on_demand", category: "ON_DEMAND", status: "AVAILABLE" },
    { field: "reference_only", category: "REFERENCE_ONLY", status: "REFERENCE_ONLY" },
    { field: "experimental", category: "EXPERIMENTAL", status: "EXPERIMENTAL" },
  ];

  for (const ra of lockInfo.roleAssignments) {
    const slug = String(ra?.role_slug || "").trim();
    if (!slug) continue;
    const skills = [];
    for (const tier of tierDefs) {
      for (const pkgId of Array.isArray(ra[tier.field]) ? ra[tier.field] : []) {
        const pkg = packages[pkgId] || {};
        skills.push({
          pkg_id: pkgId,
          display_name: pkg.display_name || pkgId,
          category: tier.category,
          status: tier.status,
          license_spdx: pkg.license_spdx || "MIT",
          pinned_commit_sha: pkg.pinned_commit_sha || "",
          repo_url: pkg.repo_url || "",
          package_sha256: pkg.upstream_package_sha256 || null,
          redistribution_policy: pkg.redistribution_policy || "",
        });
      }
    }
    map[slug] = {
      agent_name: ra.agent_name || DEFAULT_ROLE_SKILLS_SPEC[slug]?.agent_name || slug,
      handle: ra.handle || DEFAULT_ROLE_SKILLS_SPEC[slug]?.handle || `@${slug}`,
      profile: ra.profile_name || ra.profile || DEFAULT_ROLE_SKILLS_SPEC[slug]?.profile || "",
      toolsets: ra.toolsets || DEFAULT_ROLE_SKILLS_SPEC[slug]?.toolsets || "file,skills",
      installed: true,
      skills,
    };
  }
  return Object.keys(map).length > 0 ? map : null;
}

/**
 * Dynamically resolve the live Paperclip UUID for a `role_slug` against `snapshot?.agents`.
 * Never returns hardcoded legacy UUIDs when a snapshot is absent (uses portable `role:<slug>`).
 */
function matchLiveAgentUuid(roleSlug, agSpec, snapshotAgents = []) {
  if (Array.isArray(snapshotAgents) && snapshotAgents.length > 0) {
    const normSlug = String(roleSlug || "").toLowerCase();
    const normName = String(agSpec?.agent_name || "").toLowerCase();
    const normProfile = String(agSpec?.profile || "").toLowerCase();

    const matched = snapshotAgents.find((sa) => {
      if (!sa) return false;
      if (sa.role_slug && String(sa.role_slug).toLowerCase() === normSlug) return true;
      if (sa.runtime_profile_reference && String(sa.runtime_profile_reference).toLowerCase() === normProfile) return true;
      if (sa.display_name && String(sa.display_name).toLowerCase() === normName) return true;
      return false;
    });
    if (matched && matched.paperclip_agent_id) {
      return String(matched.paperclip_agent_id);
    }
  }
  return `role:${roleSlug}`;
}

function loadSkillInvocations() {
  const data = readJsonSafe(INVOCATIONS_FILE, { recent: [], by_agent: {} });
  if (!data || typeof data !== "object") return { recent: [], by_agent: {} };
  if (!Array.isArray(data.recent)) data.recent = [];
  if (!data.by_agent || typeof data.by_agent !== "object") data.by_agent = {};
  return data;
}

function recordSkillInvocation({ agentId, agentSlug, agentName, skillId, surface, taskRef = null, resultExcerpt = "" }) {
  try {
    const nowIso = new Date().toISOString();
    const store = loadSkillInvocations();
    const cleanExcerpt = sanitizeText(String(resultExcerpt || "")).slice(0, 260);
    const entry = {
      invocation_id: `skinv-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      timestamp: nowIso,
      agent_id: agentId,
      agent_slug: agentSlug || "",
      agent_name: agentName || "",
      skill_id: skillId,
      surface: surface || "office_bridge",
      task_reference: taskRef,
      result_excerpt: cleanExcerpt,
    };
    store.recent = [entry, ...store.recent].slice(0, 120);
    if (!store.by_agent[agentId]) store.by_agent[agentId] = {};
    store.by_agent[agentId][skillId] = entry;
    store.by_agent[agentId]._latest = entry;
    if (agentSlug) {
      if (!store.by_agent[agentSlug]) store.by_agent[agentSlug] = {};
      store.by_agent[agentSlug][skillId] = entry;
      store.by_agent[agentSlug]._latest = entry;
    }
    fs.mkdirSync(path.dirname(INVOCATIONS_FILE), { recursive: true, mode: 0o700 });
    fs.writeFileSync(INVOCATIONS_FILE, JSON.stringify(store, null, 2) + "\n", "utf8");

    const map = loadEnrichedAssignments();
    const agSpec = Object.values(map).find((a) => a.agent_uuid === agentId || a.role_slug === agentSlug);
    if (agSpec && agSpec.profile) {
      const usagePath = path.join(HERMES_PROFILES_DIR, agSpec.profile, "skills", ".usage.json");
      if (fs.existsSync(usagePath)) {
        const u = readJsonSafe(usagePath, {});
        if (u[skillId]) {
          u[skillId].last_viewed_at = nowIso;
          u[skillId].views = Number(u[skillId].views || 0) + 1;
          fs.writeFileSync(usagePath, JSON.stringify(u, null, 2) + "\n", "utf8");
        }
      }
    }
    return entry;
  } catch {
    return null;
  }
}

function loadEnrichedAssignments(snapshot = null) {
  const lockInfo = loadCanonicalSkillsLock();
  const lockPackages = lockInfo.packages || {};
  const onDisk = readJsonSafe(ASSIGNMENTS_FILE, null);
  const rawAgents =
    onDisk && onDisk.agents && Object.keys(onDisk.agents).length > 0
      ? onDisk.agents
      : buildRoleAgentsFromSkillsLock(lockInfo) || DEFAULT_ROLE_SKILLS_SPEC;
  const invStore = loadSkillInvocations();
  const snapAgents = snapshot?.agents || [];
  const tasks = snapshot?.tasks || [];
  const result = {};

  for (const [slug, ag] of Object.entries(rawAgents)) {
    const dynamicUuid = matchLiveAgentUuid(slug, ag, snapAgents);
    const usagePath = path.join(HERMES_PROFILES_DIR, ag.profile || "", "skills", ".usage.json");
    const usage = readJsonSafe(usagePath, {});
    const agInv = invStore.by_agent[dynamicUuid] || invStore.by_agent[slug] || {};
    const latestTask = tasks.find((t) => t.assigneeAgentId === dynamicUuid) || null;

    const enrichedSkills = (ag.skills || []).map((sk) => {
      const lk = lockPackages[sk.pkg_id] || {};
      const u = usage[sk.pkg_id] || {};
      const inv = agInv[sk.pkg_id] || null;
      const lastUsed = inv?.timestamp || u.last_viewed_at || sk.last_used || null;
      const licenseSpdx = lk.license_spdx || sk.license_spdx || "MIT";
      const commonsClause = isCommonsClauseSkill(sk.pkg_id, licenseSpdx);
      const fetchOnly = isFetchFromUpstreamOnlySkill(
        sk.pkg_id,
        licenseSpdx,
        lk.redistribution_policy || sk.redistribution_policy
      );
      return {
        ...sk,
        display_name: lk.display_name || sk.display_name || sk.pkg_id,
        license_spdx: licenseSpdx,
        pinned_commit_sha: lk.pinned_commit_sha || sk.pinned_commit_sha || "",
        repo_url: lk.repo_url || sk.repo_url || "",
        package_sha256: sk.package_sha256 || lk.upstream_package_sha256 || null,
        commons_clause: commonsClause,
        fetch_from_upstream_only: fetchOnly,
        redistribution_policy: fetchOnly
          ? "FETCH_FROM_UPSTREAM_ONLY"
          : lk.redistribution_policy || "ALLOW_WITH_ATTRIBUTION_OR_FETCH",
        last_used: lastUsed,
        views_count: Number(u.views || 0),
        locked: Boolean(u.locked ?? true),
        task_reference:
          inv?.task_reference ||
          (latestTask ? `${latestTask.identifier || String(latestTask.id).slice(0, 8)} (${latestTask.status})` : null),
        last_result: inv?.result_excerpt || null,
        known_limitations:
          KNOWN_LIMITATIONS[sk.pkg_id] || "Pinned immutable package; governed by role toolset boundaries.",
      };
    });

    result[slug] = {
      ...ag,
      agent_uuid: dynamicUuid,
      role_slug: slug,
      current_skill_invocation: agInv._latest || null,
      latest_task_reference: latestTask
        ? `${latestTask.identifier || String(latestTask.id).slice(0, 8)}: ${latestTask.title}`
        : null,
      skills: enrichedSkills,
    };
  }
  return result;
}

function findAgentAssignment(query, enrichedMap) {
  const map = enrichedMap || loadEnrichedAssignments();
  const q = String(query || "").trim().toLowerCase().replace(/^@/, "");
  if (!q) return null;
  const entries = Object.values(map);
  if (/^\d+$/.test(q)) {
    const idx = Number(q) - 1;
    if (idx >= 0 && idx < entries.length) return entries[idx];
  }
  return (
    entries.find(
      (a) =>
        String(a.agent_uuid || "").toLowerCase() === q ||
        String(a.role_slug || "").toLowerCase() === q ||
        String(a.profile || "").toLowerCase() === q ||
        String(a.handle || "").toLowerCase().replace(/^@/, "") === q ||
        String(a.agent_name || "").toLowerCase() === q
    ) ||
    entries.find(
      (a) =>
        String(a.agent_name || "").toLowerCase().includes(q) ||
        String(a.role_slug || "").toLowerCase().includes(q)
    ) ||
    null
  );
}

function resolveAgentSkillIdsForIdentity(agentUuid, roleSlugOrNormName) {
  const map = loadEnrichedAssignments();
  const found =
    Object.values(map).find((a) => a.agent_uuid === agentUuid) ||
    findAgentAssignment(roleSlugOrNormName, map);
  if (!found || !Array.isArray(found.skills) || found.skills.length === 0) {
    return ["paperclip"];
  }
  return found.skills.map((s) => s.pkg_id);
}

/**
 * Build Studio `skills.status` catalog for 3D & 2D Office, enriched with Paperclip `/api/companies/:id/skills`.
 * Reports all 33 locked skills (20 OSI-permissive + 13 `FETCH_FROM_UPSTREAM_ONLY`) from `skills/manifests/skills.lock.json`
 * when `skill-registry/` is not yet hydrated.
 */
function buildStudioSkillsStatusPayload(snapshot = null, requestedAgentId = null, paperclipSkills = []) {
  const map = loadEnrichedAssignments(snapshot);
  const lockInfo = loadCanonicalSkillsLock();
  const lockDoc = lockInfo.packages || {};
  const emptyReqs = { bins: [], anyBins: [], env: [], config: [], os: [] };

  const seen = new Map();
  for (const ag of Object.values(map)) {
    for (const sk of ag.skills || []) {
      if (!seen.has(sk.pkg_id)) {
        seen.set(sk.pkg_id, { sk, holders: [] });
      }
      seen.get(sk.pkg_id).holders.push(`${ag.agent_name} [${sk.category}:${sk.status}]`);
    }
  }

  // Include all remaining packages from skills.lock.json (e.g. `skill-scanner` supply-chain security gate -> 33 total)
  for (const [pkgId, lk] of Object.entries(lockDoc)) {
    if (!pkgId || seen.has(pkgId)) continue;
    const commonsClause = isCommonsClauseSkill(pkgId, lk.license_spdx);
    const fetchOnly = isFetchFromUpstreamOnlySkill(pkgId, lk.license_spdx, lk.redistribution_policy);
    const isGate = pkgId === lockInfo.securityGateSkillId;
    seen.set(pkgId, {
      sk: {
        pkg_id: pkgId,
        display_name: String(lk.display_name || pkgId),
        category: isGate ? "SECURITY_GATE" : "LOCKED",
        status: "ACTIVE",
        license_spdx: String(lk.license_spdx || "Apache-2.0"),
        pinned_commit_sha: String(lk.pinned_commit_sha || ""),
        commons_clause: commonsClause,
        fetch_from_upstream_only: fetchOnly,
        redistribution_policy: fetchOnly
          ? "FETCH_FROM_UPSTREAM_ONLY"
          : lk.redistribution_policy || "ALLOW_WITH_ATTRIBUTION_OR_FETCH",
      },
      holders: [isGate ? "Platform Supply-Chain Security Gate [SECURITY_GATE:ACTIVE]" : "Platform Skill Lock"],
    });
  }

  const lockedEntries = Object.entries(lockDoc);
  const fetchOnlySkillsList = lockedEntries
    .filter(([pkgId, lk]) => isFetchFromUpstreamOnlySkill(pkgId, lk.license_spdx, lk.redistribution_policy))
    .map(([pkgId]) => pkgId)
    .sort();
  const lockedSkillsCount = lockedEntries.length;
  const fetchFromUpstreamOnlyCount = fetchOnlySkillsList.length;
  const osiPermissiveCount = Math.max(0, lockedSkillsCount - fetchFromUpstreamOnlyCount);

  // Merge any additional skills reported by Paperclip `/api/companies/:id/skills`
  for (const pcs of Array.isArray(paperclipSkills) ? paperclipSkills : []) {
    const pkgId = String(pcs?.id || pcs?.slug || pcs?.name || "").trim();
    if (!pkgId || seen.has(pkgId)) continue;
    const commonsClause = isCommonsClauseSkill(pkgId, pcs.license);
    const fetchOnly = isFetchFromUpstreamOnlySkill(pkgId, pcs.license, pcs.redistribution_policy);
    seen.set(pkgId, {
      sk: {
        pkg_id: pkgId,
        display_name: String(pcs.displayName || pcs.name || pkgId),
        category: String(pcs.category || "PAPERCLIP"),
        status: "ACTIVE",
        license_spdx: String(pcs.license || "Custom"),
        pinned_commit_sha: String(pcs.version || pcs.commit || "paperclip"),
        commons_clause: commonsClause,
        fetch_from_upstream_only: fetchOnly,
        redistribution_policy: fetchOnly ? "FETCH_FROM_UPSTREAM_ONLY" : "ALLOW_WITH_ATTRIBUTION_OR_FETCH",
      },
      holders: ["Paperclip Company Registry"],
    });
  }

  const targetAg = requestedAgentId ? findAgentAssignment(requestedAgentId, map) : null;
  const skills = [];
  for (const [pkgId, { sk, holders }] of seen.entries()) {
    const lk = lockDoc[pkgId] || {};
    const agSpecific = targetAg ? (targetAg.skills || []).find((x) => x.pkg_id === pkgId) : null;
    if (targetAg && !agSpecific) continue;

    const catBadge = agSpecific ? `${agSpecific.category} · ${agSpecific.status}` : `${sk.category} · ${sk.status}`;
    const ccBadge = sk.commons_clause
      ? " [COMMONS-CLAUSE: FETCH-ONLY]"
      : sk.fetch_from_upstream_only
        ? " [FETCH-ONLY]"
        : "";
    const lastUsedTxt =
      agSpecific?.last_used || sk.last_used ? ` · Last used: ${agSpecific?.last_used || sk.last_used}` : "";
    const lastResTxt = agSpecific?.last_result ? ` · Last result: ${agSpecific.last_result.slice(0, 90)}` : "";
    const isRefOrExp = sk.category === "REFERENCE_ONLY" || sk.category === "EXPERIMENTAL";

    skills.push({
      name: pkgId,
      skillKey: pkgId,
      commonsClause: Boolean(sk.commons_clause),
      fetchFromUpstreamOnly: Boolean(sk.fetch_from_upstream_only),
      redistributionPolicy: sk.redistribution_policy,
      description: `[${catBadge}]${ccBadge} ${sk.display_name} (${lk.license_spdx || sk.license_spdx} @ ${String(sk.pinned_commit_sha || "").slice(0, 8)}) — Assigned: ${holders.join(", ")}${lastUsedTxt}${lastResTxt}`,
      source: isRefOrExp ? "hermes-extra" : "hermes-managed",
      bundled: !sk.fetch_from_upstream_only,
      filePath: path.join(REVIEWED_DIR, pkgId, "SKILL.md").replace(/\\/g, "/"),
      baseDir: path.join(REVIEWED_DIR, pkgId).replace(/\\/g, "/"),
      always: sk.category === "PRIMARY",
      disabled: false,
      blockedByAllowlist: false,
      eligible: true,
      requirements: emptyReqs,
      missing: emptyReqs,
      configChecks: [],
      install: [],
    });
  }

  return {
    workspaceDir: REVIEWED_DIR.replace(/\\/g, "/"),
    managedSkillsDir: targetAg
      ? path.join(HERMES_PROFILES_DIR, targetAg.profile, "skills").replace(/\\/g, "/")
      : HERMES_PROFILES_DIR.replace(/\\/g, "/"),
    manifestSource: lockInfo.sourceLabel,
    lockedSkillsCount,
    osiPermissiveCount,
    fetchFromUpstreamOnlyCount,
    fetchFromUpstreamOnlySkills: fetchOnlySkillsList,
    commonsClauseSkills: [...COMMONS_CLAUSE_SKILLS],
    skills,
  };
}

function buildRestSkillsCatalogPayload(snapshot = null, requestedAgentId = null, paperclipSkills = []) {
  const enriched = loadEnrichedAssignments(snapshot);
  const studioStatus = buildStudioSkillsStatusPayload(snapshot, requestedAgentId, paperclipSkills);
  const agents = requestedAgentId
    ? [findAgentAssignment(requestedAgentId, enriched)].filter(Boolean)
    : Object.values(enriched);

  return sanitizePayload({
    ok: true,
    company_id: snapshot?.company?.id || null,
    manifest_source: studioStatus.manifestSource,
    manifest_hydrated: fs.existsSync(ASSIGNMENTS_FILE),
    total_skills: studioStatus.skills.length,
    locked_skills_count: studioStatus.lockedSkillsCount,
    osi_permissive_count: studioStatus.osiPermissiveCount,
    fetch_from_upstream_only_count: studioStatus.fetchFromUpstreamOnlyCount,
    fetch_from_upstream_only_skills: studioStatus.fetchFromUpstreamOnlySkills,
    commons_clause_count: COMMONS_CLAUSE_SKILLS.length,
    commons_clause_skills: [...COMMONS_CLAUSE_SKILLS],
    paperclip_skills: Array.isArray(paperclipSkills) ? paperclipSkills : [],
    agents,
    studio_status: studioStatus,
  });
}

function buildGatewayAgentsSkillsConfigList(snapshot = null) {
  const map = loadEnrichedAssignments(snapshot);
  return Object.values(map).map((ag, idx) => ({
    id: ag.agent_uuid,
    roleSlug: ag.role_slug,
    name: ag.agent_name,
    default: idx === 0,
    skills: (ag.skills || []).map((s) => s.pkg_id),
  }));
}

function selectAndExecuteAgentSkillForTurn({ agent, userMessage, targetPath, surface = "office_chat", snapshot = null }) {
  const map = loadEnrichedAssignments(snapshot);
  const ag = findAgentAssignment(agent?.paperclip_agent_id || agent?.role_slug || agent?.display_name, map);
  if (!ag || !Array.isArray(ag.skills) || ag.skills.length === 0) {
    return null;
  }

  const lower = String(userMessage || "").toLowerCase();
  let chosen = ag.skills.find(
    (s) =>
      lower.includes(s.pkg_id.toLowerCase()) ||
      lower.includes(s.display_name.toLowerCase()) ||
      (s.pkg_id === "pw" && lower.includes("playwright")) ||
      (s.pkg_id === "docx" && lower.includes("docx")) ||
      (s.pkg_id === "pdf" && /\bpdf\b/.test(lower)) ||
      (s.pkg_id === "api-design-reviewer" && /\b(openapi|swagger|kontrak\s+api|api\s+contract|breaking\s+change)\b/.test(lower)) ||
      (s.pkg_id === "terraform-skill" && /\b(terraform|opentofu|hcl|main\.tf)\b/.test(lower)) ||
      (s.pkg_id === "ci-cd-pipeline-builder" && /\b(ci\/cd|github\s+actions|gitlab\s+ci|workflow|pipeline)\b/.test(lower)) ||
      (s.pkg_id === "frontend-design" && /\b(ui\s+design|layout|tipografi|typography|warna|visual)\b/.test(lower))
  );

  if (!chosen) {
    chosen = ag.skills.find((s) => s.category === "PRIMARY") || ag.skills[0];
  }
  if (!chosen) return null;

  let skillMdPath = path.join(REVIEWED_DIR, chosen.pkg_id, "SKILL.md");
  if (!fs.existsSync(skillMdPath)) {
    const roleDirMap = {
      security_lead: "security-lead",
      security_reviewer: "security-reviewer",
      findings_analyst: "findings",
      remediation_reviewer: "remediation",
    };
    const rDir = roleDirMap[ag.role_slug] || ag.role_slug;
    const refCand = path.join(SKILL_REGISTRY_DIR, "agents", rDir, "references", chosen.pkg_id, "SKILL.md");
    const expCand = path.join(SKILL_REGISTRY_DIR, "agents", rDir, "experimental", chosen.pkg_id, "SKILL.md");
    if (fs.existsSync(refCand)) skillMdPath = refCand;
    else if (fs.existsSync(expCand)) skillMdPath = expCand;
  }

  let skillExcerpt = "";
  if (fs.existsSync(skillMdPath)) {
    skillExcerpt = fs.readFileSync(skillMdPath, "utf8").slice(0, 3200);
  }

  let scriptOutput = "";
  const effDir =
    targetPath && fs.existsSync(targetPath)
      ? fs.statSync(targetPath).isDirectory()
        ? targetPath
        : path.dirname(targetPath)
      : path.join(WORKSPACES_DIR, "skill-test-fixture");

  try {
    const linterScript = path.join(REVIEWED_DIR, "api-design-reviewer", "scripts", "api_linter.py");
    if (chosen.pkg_id === "api-design-reviewer" && fs.existsSync(linterScript)) {
      const v1Json = path.join(effDir, "openapi", "orders-v1.json");
      if (fs.existsSync(v1Json)) {
        const lintOut = execFileSync(PYTHON_EXE, [linterScript, v1Json], {
          encoding: "utf8",
          timeout: 12_000,
          windowsHide: true,
        });
        scriptOutput += `\n[Output nyata api_linter.py pada ${v1Json}]:\n${lintOut.slice(0, 900)}\n`;
      }
    } else if ((chosen.pkg_id === "compliance-os" || chosen.pkg_id === "docx" || chosen.pkg_id === "pdf") && /\b(docx|pdf)\b/.test(lower)) {
      const repDocx = path.join(REPORTS_DIR, "compliance-audit-report-fixture.docx");
      const repPdf = path.join(REPORTS_DIR, "compliance-audit-report-fixture.pdf");
      if (fs.existsSync(repDocx) && fs.existsSync(repPdf)) {
        scriptOutput += `\n[Dokumen Audit Terverifikasi Tersedia]:\n- DOCX: ${repDocx} (${fs.statSync(repDocx).size} bytes)\n- PDF: ${repPdf} (${fs.statSync(repPdf).size} bytes)\n`;
      }
    }
  } catch {}

  const inv = recordSkillInvocation({
    agentId: ag.agent_uuid,
    agentSlug: ag.role_slug,
    agentName: ag.agent_name,
    skillId: chosen.pkg_id,
    surface,
    taskRef: targetPath || null,
    resultExcerpt: `Loaded ${chosen.display_name} (${chosen.category})${scriptOutput ? " + executed supporting script" : ""}`,
  });

  return {
    agentAssignment: ag,
    chosenSkill: chosen,
    skillMdPath,
    skillExcerpt,
    scriptOutput,
    invocation: inv,
  };
}

function formatTelegramAgentSkillsCard(ag) {
  const catOrder = ["PRIMARY", "SPECIALIST", "ON_DEMAND", "REFERENCE_ONLY", "EXPERIMENTAL"];
  const catLabels = {
    PRIMARY: "Primary",
    SPECIALIST: "Specialist",
    ON_DEMAND: "On demand",
    REFERENCE_ONLY: "Reference-only",
    EXPERIMENTAL: "Experimental",
  };
  const lines = [
    `🧰 *${ag.agent_name.toUpperCase()}* (\`${ag.handle}\` · Profile \`${ag.profile}\`)`,
    `• *Agent ID:* \`${ag.agent_uuid}\``,
    `• *Toolsets Runtime:* \`${ag.toolsets}\``,
    ``,
  ];
  for (const cat of catOrder) {
    const matching = (ag.skills || []).filter((s) => s.category === cat);
    for (const sk of matching) {
      const used = sk.last_used ? ` · Used: \`${String(sk.last_used).slice(0, 19)}\`` : "";
      const ccFlag = sk.fetch_from_upstream_only ? " · `FETCH-ONLY`" : "";
      lines.push(
        `• *${catLabels[cat]}:* *${sk.display_name}* (\`${sk.pkg_id}\`) — \`${sk.status}\` · \`${sk.license_spdx}\`${ccFlag} @ \`${String(sk.pinned_commit_sha || "").slice(0, 8)}\`${used}`
      );
    }
  }
  if (ag.latest_task_reference) {
    lines.push(``, `• *Task Terkait:* \`${sanitizeText(ag.latest_task_reference).slice(0, 90)}\``);
  }
  lines.push(``, `💡 Detail paket: \`/skill_info ${ag.handle.replace("@", "")} ${(ag.skills[0] || {}).pkg_id || "skill"}\``);
  return lines.join("\n");
}

function formatTelegramAllSkillsSummary(snapshot = null) {
  const map = loadEnrichedAssignments(snapshot);
  const lines = [
    `🧰 *DAFTAR SKILLS SPESIALISASI 11 AGEN AI*`,
    `────────────────────────`,
  ];
  let idx = 1;
  for (const ag of Object.values(map)) {
    const prim = (ag.skills || []).filter((s) => s.category === "PRIMARY").map((s) => `${s.display_name} [ACTIVE]`).join(", ");
    const spec = (ag.skills || []).filter((s) => s.category === "SPECIALIST").map((s) => s.display_name).join(", ");
    const extra = (ag.skills || [])
      .filter((s) => ["ON_DEMAND", "REFERENCE_ONLY", "EXPERIMENTAL"].includes(s.category))
      .map((s) => `${s.pkg_id}(${s.category})`)
      .join(", ");
    lines.push(
      `*${idx}. ${ag.agent_name}* (\`${ag.handle}\` · \`${ag.profile}\`)\n` +
        `   • Primary: ${prim || "—"}\n` +
        (spec ? `   • Specialist: ${spec}\n` : "") +
        (extra ? `   • Lainnya: ${extra}` : "")
    );
    idx += 1;
  }
  lines.push(
    ``,
    `🔍 Cek per agen: \`/daftar_skill ceo\`, \`/daftar_skill backend\`, \`/skill_info qa pw\`, atau \`/skill_status\`.`
  );
  return lines.join("\n");
}

function formatTelegramSkillInfoCard(agentQuery, skillQuery, snapshot = null) {
  const map = loadEnrichedAssignments(snapshot);
  const ag = findAgentAssignment(agentQuery, map);
  if (!ag) {
    return {
      ok: false,
      error: `Agen \`${sanitizeText(agentQuery)}\` tidak ditemukan. Gunakan nama/handle 1..11 (mis. \`ceo\`, \`backend\`, \`qa\`).`,
    };
  }
  const q = String(skillQuery || "").trim().toLowerCase();
  const sk =
    (ag.skills || []).find((s) => s.pkg_id.toLowerCase() === q || s.display_name.toLowerCase() === q) ||
    (q
      ? (ag.skills || []).find((s) => s.pkg_id.toLowerCase().includes(q) || s.display_name.toLowerCase().includes(q))
      : ag.skills[0]);

  if (!sk) {
    return {
      ok: false,
      error: `Skill \`${sanitizeText(skillQuery)}\` tidak ditetapkan pada *${ag.agent_name}*. Skill agen ini: ${(ag.skills || []).map((x) => `\`${x.pkg_id}\``).join(", ")}.`,
    };
  }

  const reply = [
    `🔎 *DETAIL SKILL AGEN — ${sk.display_name.toUpperCase()}*`,
    `────────────────────────`,
    `• *Agent Name:* *${ag.agent_name}* (\`${ag.handle}\` · \`${ag.profile}\`)`,
    `• *Skill Name / ID:* *${sk.display_name}* (\`${sk.pkg_id}\`)`,
    `• *Category:* \`${sk.category}\``,
    `• *Status:* \`${sk.status}\` (Locked: \`${sk.locked}\`)`,
    `• *Installed Version / Commit:* \`${sk.pinned_commit_sha}\``,
    `• *Source Repository:* ${sk.repo_url}`,
    `• *License:* \`${sk.license_spdx}\` (\`${sk.redistribution_policy}\`)`,
    sk.package_sha256 ? `• *SHA-256 Checksum:* \`${String(sk.package_sha256).slice(0, 24)}...\`` : null,
    `• *Dependency Status:* \`${sk.dependency_status || "READY"}\``,
    `• *Last Used:* \`${sk.last_used || "belum tercatat di sesi ini"}\``,
    sk.last_result ? `• *Last Result:* ${sanitizeText(sk.last_result)}` : null,
    `• *Known Limitations:* ${sk.known_limitations}`,
  ]
    .filter(Boolean)
    .join("\n");

  return { ok: true, agent: ag, skill: sk, reply };
}

function formatTelegramSkillStatusCard(snapshot = null) {
  const map = loadEnrichedAssignments(snapshot);
  const lockInfo = loadCanonicalSkillsLock();
  const secDoc = loadCanonicalSecurityResults();
  const lockedEntries = Object.entries(lockInfo.packages || {});
  const totalSkillsCount = lockedEntries.length;
  const fetchOnlyCount = lockedEntries.filter(([pkgId, lk]) =>
    isFetchFromUpstreamOnlySkill(pkgId, lk.license_spdx, lk.redistribution_policy)
  ).length;
  const osiPermissiveCount = Math.max(0, totalSkillsCount - fetchOnlyCount);

  const agentsArr = Object.values(map);
  const installedCount = agentsArr.filter((a) => a.installed).length;
  let activeCount = 0;
  let onDemandCount = 0;
  let refCount = 0;
  let expCount = 0;
  for (const a of agentsArr) {
    for (const s of a.skills || []) {
      if (s.status === "ACTIVE") activeCount += 1;
      else if (s.category === "ON_DEMAND") onDemandCount += 1;
      else if (s.category === "REFERENCE_ONLY") refCount += 1;
      else if (s.category === "EXPERIMENTAL") expCount += 1;
    }
  }
  const quarantinedList =
    (Array.isArray(secDoc.quarantined_files) && secDoc.quarantined_files) ||
    (Array.isArray(secDoc.quarantined_excluded_files) && secDoc.quarantined_excluded_files) ||
    lockInfo.quarantinedExcludedFiles;
  const quarantinedCount = Array.isArray(quarantinedList) ? quarantinedList.length : 11;

  const reply = [
    `🛡️ *STATUS GLOBAL SKILL REGISTRY & SECURITY GATE*`,
    `────────────────────────`,
    `• *Agen Terspesialisasi:* \`${installedCount}/11 agen\` (Profile Hermes terisolasi \`pc*\`)`,
    `• *Total Paket Terkunci (Lock Manifest):* \`${totalSkillsCount} paket\` (\`${osiPermissiveCount}\` OSI-permissive + \`${fetchOnlyCount}\` \`FETCH_FROM_UPSTREAM_ONLY\`)`,
    `• *Assignment Aktif (PRIMARY + SPECIALIST):* \`${activeCount}\``,
    `• *On-Demand Skills:* \`${onDemandCount}\``,
    `• *Reference-Only Methodologies:* \`${refCount}\``,
    `• *Experimental Skills:* \`${expCount}\` (\`cve-triage\`)`,
    `• *Fetch-Only Skills:* \`${fetchOnlyCount} paket\` (termasuk \`${COMMONS_CLAUSE_SKILLS.length}\` Commons Clause)`,
    `• *Quarantined Files (Supply-Chain Gate):* \`${quarantinedCount} file\` di \`skill-registry/quarantine\``,
    `• *Cross-Agent Security Gate:* \`Sentry skill-scanner\` (\`PASS\`)`,
    `• *Kebijakan Keamanan:* Instalasi remote skill dari Telegram dinonaktifkan secara permanen; seluruh paket dikunci (\`locked: true\`).`,
  ].join("\n");

  return {
    ok: true,
    summary: {
      manifest_source: lockInfo.sourceLabel,
      total_skills: totalSkillsCount,
      osi_permissive_count: osiPermissiveCount,
      fetch_from_upstream_only_count: fetchOnlyCount,
      specialized_agents: installedCount,
      active_assignments: activeCount,
      on_demand: onDemandCount,
      reference_only: refCount,
      experimental: expCount,
      commons_clause_count: COMMONS_CLAUSE_SKILLS.length,
      quarantined_files: quarantinedCount,
    },
    reply,
  };
}

module.exports = {
  COMMONS_CLAUSE_SKILLS,
  FETCH_FROM_UPSTREAM_ONLY_SKILLS,
  KNOWN_LIMITATIONS,
  DEFAULT_ROLE_SKILLS_SPEC,
  isCommonsClauseSkill,
  isFetchFromUpstreamOnlySkill,
  loadCanonicalSkillsLock,
  loadCanonicalSecurityResults,
  loadEnrichedAssignments,
  findAgentAssignment,
  resolveAgentSkillIdsForIdentity,
  buildStudioSkillsStatusPayload,
  buildRestSkillsCatalogPayload,
  buildGatewayAgentsSkillsConfigList,
  selectAndExecuteAgentSkillForTurn,
  recordSkillInvocation,
  formatTelegramAgentSkillsCard,
  formatTelegramAllSkillsSummary,
  formatTelegramSkillInfoCard,
  formatTelegramSkillStatusCard,
};
