"use strict";

/**
 * Canonical Paperclip Agent Identity Mapping, 8-Department Spatial Layout Registry,
 * and Deterministic Avatar Profiles for ALLINAGENT Office Bridge.
 *
 * Strictly zero hardcoded private paths or Paperclip UUIDs.
 */

const fs = require("node:fs");
const path = require("node:path");
const {
  HERMES_PROFILES_DIR,
  DEFAULT_LLM_MODEL,
  resolveAuthorizedWorkspaces,
} = require("./paths");

const DEPARTMENTS = Object.freeze({
  executive: {
    id: "executive",
    name: "Executive Office",
    shortLabel: "EXEC",
    color: "#f59e0b",
    cameraTarget: { x: 260, y: 210, preset: "executive" },
    facilities: ["Executive Desks", "Company Overview Board", "Strategy Monitor", "Delegation Board"],
  },
  engineering: {
    id: "engineering",
    name: "Engineering Department",
    shortLabel: "ENG",
    color: "#3b82f6",
    cameraTarget: { x: 560, y: 360, preset: "engineering" },
    facilities: ["Individual Workstations", "Project Monitors", "Development Status Board", "Build Status Display"],
  },
  qa_lab: {
    id: "qa_lab",
    name: "Quality Assurance Laboratory",
    shortLabel: "QA LAB",
    color: "#10b981",
    cameraTarget: { x: 1410, y: 310, preset: "qa_lab" },
    facilities: ["Test Dashboard", "Regression Status", "Test Execution Monitor", "Acceptance Board"],
  },
  soc: {
    id: "soc",
    name: "Security Operations Center",
    shortLabel: "SOC",
    color: "#ef4444",
    cameraTarget: { x: 860, y: 250, preset: "soc" },
    facilities: ["Findings Dashboard", "Risk Overview", "Remediation Board", "Defensive Review Status"],
  },
  compliance: {
    id: "compliance",
    name: "Compliance Office",
    shortLabel: "COMP",
    color: "#8b5cf6",
    cameraTarget: { x: 260, y: 540, preset: "compliance" },
    facilities: ["Evidence Archive", "Report Dashboard", "Documentation Board"],
  },
  meeting_room: {
    id: "meeting_room",
    name: "Meeting Room",
    shortLabel: "MEET",
    color: "#06b6d4",
    cameraTarget: { x: 145, y: 118, preset: "meeting_room" },
    facilities: ["Conference Table", "Delegation Handoff Display", "Action Item Tracker"],
  },
  ops_center: {
    id: "ops_center",
    name: "Operations Control Center",
    shortLabel: "OPS",
    color: "#ec4899",
    cameraTarget: { x: 960, y: 680, preset: "ops_center" },
    facilities: ["Service Health Rack", "Runtime Telemetry", "Scheduled Maintenance Monitor", "Resource & Error Console"],
  },
  lobby: {
    id: "lobby",
    name: "Lobby & Lounge",
    shortLabel: "LOBBY",
    color: "#64748b",
    cameraTarget: { x: 320, y: 880, preset: "lobby" },
    facilities: ["Reception Desk", "Standby Lounge", "Company Directory"],
  },
});

const ROLE_VISUAL_CATALOG = Object.freeze({
  "ceo agent": {
    roleSlug: "ceo_agent",
    departmentId: "executive",
    officeLocationId: "dept-executive-desk-1",
    deskCoords: { x: 220, y: 190, facing: 0 },
    color: "#f59e0b",
    visualProfileId: "vp-ceo-01",
    wave: 1,
    badgeEmoji: "👑",
  },
  "cto agent": {
    roleSlug: "cto_agent",
    departmentId: "executive",
    officeLocationId: "dept-executive-desk-2",
    deskCoords: { x: 340, y: 190, facing: 0 },
    color: "#d97706",
    visualProfileId: "vp-cto-02",
    wave: 2,
    badgeEmoji: "🏛️",
  },
  "backend developer": {
    roleSlug: "backend_developer",
    departmentId: "engineering",
    officeLocationId: "dept-engineering-desk-1",
    deskCoords: { x: 480, y: 340, facing: 0 },
    color: "#2563eb",
    visualProfileId: "vp-backend-03",
    wave: 1,
    badgeEmoji: "⚙️",
  },
  "frontend developer": {
    roleSlug: "frontend_developer",
    departmentId: "engineering",
    officeLocationId: "dept-engineering-desk-2",
    deskCoords: { x: 600, y: 340, facing: 0 },
    color: "#0ea5e9",
    visualProfileId: "vp-frontend-04",
    wave: 2,
    badgeEmoji: "🎨",
  },
  "devops engineer": {
    roleSlug: "devops_engineer",
    departmentId: "engineering",
    officeLocationId: "dept-engineering-desk-3",
    deskCoords: { x: 720, y: 340, facing: 0 },
    color: "#4f46e5",
    visualProfileId: "vp-devops-05",
    wave: 2,
    badgeEmoji: "🚀",
  },
  "qa engineer": {
    roleSlug: "qa_engineer",
    departmentId: "qa_lab",
    officeLocationId: "dept-qa-station-1",
    deskCoords: { x: 1410, y: 300, facing: 180 },
    color: "#10b981",
    visualProfileId: "vp-qa-06",
    wave: 1,
    badgeEmoji: "🧪",
  },
  "security lead": {
    roleSlug: "security_lead",
    departmentId: "soc",
    officeLocationId: "dept-soc-desk-1",
    deskCoords: { x: 820, y: 210, facing: 0 },
    color: "#dc2626",
    visualProfileId: "vp-seclead-07",
    wave: 2,
    badgeEmoji: "🛡️",
  },
  "security reviewer": {
    roleSlug: "security_reviewer",
    departmentId: "soc",
    officeLocationId: "dept-soc-desk-2",
    deskCoords: { x: 940, y: 210, facing: 0 },
    color: "#ef4444",
    visualProfileId: "vp-secreview-08",
    wave: 1,
    badgeEmoji: "🔍",
  },
  "findings analyst": {
    roleSlug: "findings_analyst",
    departmentId: "soc",
    officeLocationId: "dept-soc-desk-3",
    deskCoords: { x: 820, y: 330, facing: 180 },
    color: "#f97316",
    visualProfileId: "vp-findings-09",
    wave: 2,
    badgeEmoji: "📊",
  },
  "remediation reviewer": {
    roleSlug: "remediation_reviewer",
    departmentId: "soc",
    officeLocationId: "dept-soc-desk-4",
    deskCoords: { x: 940, y: 330, facing: 180 },
    color: "#e11d48",
    visualProfileId: "vp-remreview-10",
    wave: 2,
    badgeEmoji: "✅",
  },
  "report & compliance agent": {
    roleSlug: "compliance_reporter",
    departmentId: "compliance",
    officeLocationId: "dept-compliance-desk-1",
    deskCoords: { x: 260, y: 540, facing: 90 },
    color: "#8b5cf6",
    visualProfileId: "vp-compliance-11",
    wave: 2,
    badgeEmoji: "📋",
  },
});

function inferDepartmentByRole(roleStr) {
  const r = String(roleStr || "").toLowerCase();
  if (r === "ceo" || r === "cto") return "executive";
  if (r === "qa") return "qa_lab";
  if (r === "security" || r === "researcher") return "soc";
  if (r === "pm" || r === "compliance") return "compliance";
  if (r === "devops") return "ops_center";
  return "engineering";
}

const KNOWN_ROLE_PROFILES = Object.freeze({
  "ceo agent": "pcceoagent",
  "cto agent": "pcctoagent",
  "backend developer": "pcbackenddeveloper",
  "frontend developer": "pcfrontenddeveloper",
  "devops engineer": "pcdevopsengineer",
  "qa engineer": "pcqaengineer",
  "security lead": "pcsecuritylead",
  "security reviewer": "pcsecurityreviewer",
  "findings analyst": "pcfindingsanalyst",
  "remediation reviewer": "pcremediationreviewer",
  "report & compliance agent": "pccompliancereporter",
});

function extractHermesProfileRef(adapterConfig, normName = "") {
  if (adapterConfig && typeof adapterConfig === "object") {
    const env = adapterConfig.env && typeof adapterConfig.env === "object" ? adapterConfig.env : {};
    const rawHome = env.HERMES_HOME ?? adapterConfig.hermesHome ?? "";
    const hermesHome =
      rawHome && typeof rawHome === "object"
        ? String(rawHome.value || rawHome.default || "")
        : String(rawHome || "");
    if (hermesHome && hermesHome !== "[object Object]" && !hermesHome.includes("REDACTED")) {
      const parts = hermesHome.replace(/\\/g, "/").split("/").filter(Boolean);
      if (parts.length > 0) return parts[parts.length - 1];
    }
  }
  const known = KNOWN_ROLE_PROFILES[normName];
  if (known) {
    const profileDir = path.join(HERMES_PROFILES_DIR, known);
    if (fs.existsSync(profileDir)) {
      return known;
    }
    return known;
  }
  return null;
}

function resolveAuthorizedToolsForRole(role, normName) {
  const base = ["read_file", "search_files", "paperclip_api_scoped"];
  if (normName.includes("ceo") || normName.includes("cto") || role === "pm") {
    return [...base, "issue_decomposition", "comment_publish"];
  }
  if (role === "security" || role === "researcher") {
    return [...base, "vulnclaw_defensive_codescan_readonly", "findings_triage"];
  }
  if (role === "qa") {
    return [...base, "local_terminal_test_runner", "git_diff_readonly"];
  }
  return [...base, "write_file", "edit_file", "local_terminal", "git_branch_worktree"];
}

function resolveRoleSkills(canonicalId, role, normName) {
  try {
    const { resolveAgentSkillIdsForIdentity } = require("../adapters/agent-skills-bridge");
    const assigned = resolveAgentSkillIdsForIdentity(canonicalId, normName || role);
    if (Array.isArray(assigned) && assigned.length > 0) {
      return assigned;
    }
  } catch {}
  const common = ["paperclip"];
  if (normName.includes("ceo")) return [...common, "ceo-advisor", "c-level-skills"];
  if (normName.includes("cto")) return [...common, "cto-review", "senior-architect", "cto-advisor"];
  if (role === "security" || role === "researcher") return [...common, "security-audit"];
  if (role === "qa") return [...common, "pw", "pw-generate", "pw-review", "senior-qa"];
  return [...common, "senior-backend"];
}

function mapPaperclipAgentIdentity(agent, allAgents = [], index = 0) {
  const canonicalId = String(agent.id || "").trim();
  const displayName = String(agent.name || `Agent ${index + 1}`).trim();
  const normName = displayName.toLowerCase();
  const preset = ROLE_VISUAL_CATALOG[normName] || null;
  const departmentId = preset ? preset.departmentId : inferDepartmentByRole(agent.role);
  const dept = DEPARTMENTS[departmentId] || DEPARTMENTS.engineering;

  const subordinates = allAgents
    .filter((other) => other && String(other.reportsTo || "") === canonicalId)
    .map((other) => String(other.id));

  const adapterCfg = agent.adapterConfig && typeof agent.adapterConfig === "object" ? agent.adapterConfig : {};
  const profileRef = extractHermesProfileRef(adapterCfg, normName);
  const rawStatus = String(agent.status || "unknown").toLowerCase();
  const rawLifecycle = String(agent.lifecycleState || "").toLowerCase();
  const activationStatus =
    rawStatus === "paused" || rawLifecycle === "pausing" || rawLifecycle === "paused"
      ? "STANDBY"
      : rawStatus === "idle" ||
          rawStatus === "running" ||
          rawStatus === "active" ||
          (rawStatus === "error" && rawLifecycle === "ready")
        ? "ACTIVE"
        : rawStatus === "terminated" || rawStatus === "archived"
          ? "DEACTIVATED"
          : "UNKNOWN";

  const fallbackX = 460 + (index % 5) * 95;
  const fallbackY = 480 + Math.floor(index / 5) * 95;
  const workspaces = resolveAuthorizedWorkspaces(process.env).map((w) => w.replace(/\\/g, "/"));

  return {
    paperclip_agent_id: canonicalId,
    role_slug: preset?.roleSlug || String(agent.roleSlug || normName.replace(/[^a-z0-9]+/g, "_")),
    company_id: String(agent.companyId || ""),
    display_name: displayName,
    department_id: departmentId,
    department: dept.name,
    department_short: dept.shortLabel,
    role: String(agent.role || "specialist"),
    title: String(agent.title || displayName),
    manager_id: agent.reportsTo ? String(agent.reportsTo) : null,
    subordinate_ids: subordinates,
    runtime_type: String(agent.adapterType || "hermes_local"),
    runtime_profile_reference: profileRef,
    model_id: String(adapterCfg.model || DEFAULT_LLM_MODEL),
    visual_profile_id: preset ? preset.visualProfileId : `vp-dynamic-${canonicalId.slice(0, 8)}`,
    avatar_id: `avatar-${canonicalId.slice(0, 8)}`,
    color: preset ? preset.color : dept.color,
    badge_emoji: preset ? preset.badgeEmoji : "🤖",
    wave: preset ? preset.wave : 2,
    office_location_id: preset ? preset.officeLocationId : `dept-${departmentId}-slot-${index + 1}`,
    desk_coords: preset ? preset.deskCoords : { x: fallbackX, y: fallbackY, facing: 0 },
    authorized_workspaces: workspaces,
    authorized_tools: resolveAuthorizedToolsForRole(String(agent.role || ""), normName),
    skills: resolveRoleSkills(canonicalId, String(agent.role || ""), normName),
    can_create_agents: Boolean(agent.permissions?.canCreateAgents ?? false),
    activation_status: activationStatus,
    raw_status: rawStatus,
    lifecycle_state: String(agent.lifecycleState || "unknown"),
    last_heartbeat_at: agent.lastHeartbeatAt || agent.updatedAt || null,
    observed_at: new Date().toISOString(),
  };
}

module.exports = {
  DEPARTMENTS,
  ROLE_VISUAL_CATALOG,
  KNOWN_ROLE_PROFILES,
  mapPaperclipAgentIdentity,
};
