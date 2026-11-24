"use strict";

/**
 * CODEXE — ALLINAGENT UNIFIED AUTONOMOUS AI COMPANY
 * FULL TELEGRAM REMOTE CONTROL, 11-AGENT ORCHESTRATION & 3D/2D OFFICE SYNCHRONIZATION
 * (`apps/office-bridge/adapters/telegram-control-adapter.js`)
 *
 * Cross-platform portable (`contracts/paths.js`) with dynamic `role_slug` Paperclip UUID binding,
 * zero hardcoded UUIDs, zero personal identifiers, and fail-closed Owner DM security.
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const {
  OFFICE_DATA_DIR,
  WORKSPACES_DIR,
  DEFAULT_LLM_MODEL,
  resolveAuthorizedOwnerId,
} = require("../contracts/paths");
const { sanitizeText, sanitizePayload } = require("../contracts/redaction");
const {
  loadTargetFoldersStore,
  getTargetFoldersStatus,
  mutateTargetFolders,
  inspectLocalTargetDeep,
} = require("./target-folders-manager");
const {
  readAgentChatHistory,
  clearAgentChatHistory,
  handleEmployeeChatTurn,
  extractTargetProjectPath,
} = require("./agent-chat-engine");
const {
  runDefensiveVulnclawScan,
  invokePlatformCliJson,
} = require("./vulnclaw-findings-adapter");
const { syncBudgetsWithPaperclip } = require("./analytics-telemetry-adapter");

const {
  resolveCanonicalCommand,
  validateCommandArguments,
  generateCorrelationId,
  checkIdempotency,
  saveIdempotency,
  buildExecutionReceipt,
  buildStructuredError,
} = require("../telegram-control/command-registry");
const {
  verifyTelegramRequestSecurity,
  createBoundApprovalRequest,
  consumeBoundApprovalRequest,
} = require("../telegram-control/security-guard");
const {
  btn,
  navFooter,
  paginationRow,
  paginateItems,
  buildContextHeader,
  buildCodexeHomeKeyboard,
  buildSubmenuView,
} = require("../telegram-control/command-center-ui");
const {
  loadMeetingsV2,
  getActiveMeetingV2,
  buildOfficeRemoteStatus,
  captureOfficeScreenshot,
  startFullLifecycleMeeting,
  conductMeetingDiscussion,
  summarizeOrConcludeMeeting,
} = require("../telegram-control/office-and-meeting-controller");
const {
  validateSecureFolderOrFile,
  exploreDirectoryPaginated,
  searchDirectoriesSafe,
  performRealSourceCodeAnalysis,
  executeSafeDevOperation,
} = require("../telegram-control/folder-and-dev-controller");
const {
  loadDispatchControl,
  setDispatchPaused,
  loadActiveProjectSelection,
  saveActiveProjectSelection,
  readAfterWriteVerifyIssue,
  cancelTaskWithActiveRuns,
  orchestrateCeoMultiAgentDelegation,
} = require("../telegram-control/delegation-and-paperclip-controller");
const {
  buildTelegramAnalyticsReport,
  getGovernedBudgetOverview,
  updateGovernedBudget,
  buildUnifiedApprovalsCenter,
  listDefensiveFindings,
  inspectDependencyAndConfigRisks,
  transitionFindingViaPython,
  buildComplete15ComponentHealth,
  readRecentSanitizedErrorLogs,
  executeSafeGracefulRecovery,
} = require("../telegram-control/analytics-budget-security-health");
const {
  executeWithResilience,
  withSingletonLock,
  isMaintenanceLockActive,
  listDeadLetters,
  getCircuitBreakerSnapshot,
  emitActivityNotification,
  loadAsyncJobs,
  enqueueAsyncJob,
  cancelAsyncJob,
  routeIndonesianNaturalIntent,
} = require("../telegram-control/jobs-notifications-nl-reliability");

const TELEGRAM_STATE_FILE = path.resolve(path.join(OFFICE_DATA_DIR, "telegram-control-state.json"));

/**
 * Canonical 11 Corporate Roles (ordered 1..11).
 * Uses portable `role:<slug>` default IDs and dynamically binds to live Paperclip UUIDs
 * via `resolveLiveCorporateDirectory(snapshot)` whenever a Paperclip snapshot is present.
 */
const CORPORATE_AGENT_DIRECTORY = [
  {
    index: 1,
    id: "role:ceo_agent",
    slug: "ceo_agent",
    role_slug: "ceo_agent",
    profile: "pcceoagent",
    handle: "@ceo",
    shortLabel: "1. CEO Agent",
    emoji: "👔",
    name: "CEO Agent",
    department: "Executive",
    wave: 1,
    aliases: ["ceo_agent", "ceo agent", "pcceoagent", "chief executive", "ceo", "direktur utama", "eksekutif"],
  },
  {
    index: 2,
    id: "role:cto_agent",
    slug: "cto_agent",
    role_slug: "cto_agent",
    profile: "pcctoagent",
    handle: "@cto",
    shortLabel: "2. CTO Agent",
    emoji: "🏛️",
    name: "CTO Agent",
    department: "Architecture",
    wave: 2,
    aliases: ["cto_agent", "cto agent", "pcctoagent", "chief technology", "cto", "arsitek utama"],
  },
  {
    index: 3,
    id: "role:backend_developer",
    slug: "backend_developer",
    role_slug: "backend_developer",
    profile: "pcbackenddeveloper",
    handle: "@backend",
    shortLabel: "3. Backend Dev",
    emoji: "💻",
    name: "Backend Developer",
    department: "Engineering",
    wave: 1,
    aliases: ["backend_developer", "backend developer", "pcbackenddeveloper", "backend dev", "back-end", "backend"],
  },
  {
    index: 4,
    id: "role:frontend_developer",
    slug: "frontend_developer",
    role_slug: "frontend_developer",
    profile: "pcfrontenddeveloper",
    handle: "@frontend",
    shortLabel: "4. Frontend Dev",
    emoji: "🎨",
    name: "Frontend Developer",
    department: "Frontend & UI",
    wave: 2,
    aliases: ["frontend_developer", "frontend developer", "pcfrontenddeveloper", "frontend dev", "front-end", "frontend", "ui engineer"],
  },
  {
    index: 5,
    id: "role:devops_engineer",
    slug: "devops_engineer",
    role_slug: "devops_engineer",
    profile: "pcdevopsengineer",
    handle: "@devops",
    shortLabel: "5. DevOps Eng",
    emoji: "⚙️",
    name: "DevOps Engineer",
    department: "DevOps & Runtime",
    wave: 2,
    aliases: ["devops_engineer", "devops engineer", "pcdevopsengineer", "devops eng", "devops", "sre"],
  },
  {
    index: 6,
    id: "role:qa_engineer",
    slug: "qa_engineer",
    role_slug: "qa_engineer",
    profile: "pcqaengineer",
    handle: "@qa",
    shortLabel: "6. QA Engineer",
    emoji: "🧪",
    name: "QA Engineer",
    department: "Quality Assurance",
    wave: 1,
    aliases: ["qa_engineer", "qa engineer", "pcqaengineer", "quality assurance", "qa", "tester"],
  },
  {
    index: 7,
    id: "role:security_lead",
    slug: "security_lead",
    role_slug: "security_lead",
    profile: "pcsecuritylead",
    handle: "@security_lead",
    shortLabel: "7. Security Lead",
    emoji: "🛡️",
    name: "Security Lead",
    department: "Cybersecurity",
    wave: 2,
    aliases: ["security_lead", "security lead", "pcsecuritylead", "seclead", "securitylead", "kepala keamanan", "lead security"],
  },
  {
    index: 8,
    id: "role:security_reviewer",
    slug: "security_reviewer",
    role_slug: "security_reviewer",
    profile: "pcsecurityreviewer",
    handle: "@security",
    shortLabel: "8. Security Rev",
    emoji: "🔐",
    name: "Security Reviewer",
    department: "Cybersecurity",
    wave: 1,
    aliases: ["security_reviewer", "security reviewer", "pcsecurityreviewer", "secreview", "securityreviewer", "reviewer keamanan", "security"],
  },
  {
    index: 9,
    id: "role:findings_analyst",
    slug: "findings_analyst",
    role_slug: "findings_analyst",
    profile: "pcfindingsanalyst",
    handle: "@findings",
    shortLabel: "9. Findings Anl",
    emoji: "🔎",
    name: "Findings Analyst",
    department: "SOC Triage",
    wave: 2,
    aliases: ["findings_analyst", "findings analyst", "pcfindingsanalyst", "findings", "analis temuan", "soc analyst"],
  },
  {
    index: 10,
    id: "role:remediation_reviewer",
    slug: "remediation_reviewer",
    role_slug: "remediation_reviewer",
    profile: "pcremediationreviewer",
    handle: "@remediation",
    shortLabel: "10. Remediation",
    emoji: "🩹",
    name: "Remediation Reviewer",
    department: "Security Remediation",
    wave: 2,
    aliases: ["remediation_reviewer", "remediation reviewer", "pcremediationreviewer", "remediation", "reviewer remediasi", "remediasi"],
  },
  {
    index: 11,
    id: "role:compliance_reporter",
    slug: "compliance_reporter",
    role_slug: "compliance_reporter",
    profile: "pccompliancereporter",
    handle: "@compliance",
    shortLabel: "11. Compliance",
    emoji: "📜",
    name: "Report & Compliance Agent",
    department: "Audit & Governance",
    wave: 2,
    aliases: [
      "report & compliance agent",
      "report and compliance agent",
      "compliance_reporter",
      "compliance reporter",
      "pccompliancereporter",
      "compliance",
      "report agent",
      "laporan kepatuhan",
    ],
  },
];

function matchSnapshotAgentForRole(entry, snapAgents = []) {
  if (!Array.isArray(snapAgents) || snapAgents.length === 0) return null;
  const slugLower = entry.slug.toLowerCase();
  const profileLower = entry.profile.toLowerCase();
  const nameLower = entry.name.toLowerCase();
  return (
    snapAgents.find((a) => {
      if (!a) return false;
      if (a.role_slug && String(a.role_slug).toLowerCase() === slugLower) return true;
      if (a.runtime_profile_reference && String(a.runtime_profile_reference).toLowerCase() === profileLower) return true;
      if (a.display_name && String(a.display_name).toLowerCase() === nameLower) return true;
      return false;
    }) || null
  );
}

/**
 * Dynamically bind the 11 corporate directory entries to live Paperclip agent UUIDs
 * from `snapshot?.agents` via `role_slug` / `runtime_profile_reference` / `display_name`.
 */
function resolveLiveCorporateDirectory(snapshot = null) {
  const snapAgents = snapshot?.agents || [];
  return CORPORATE_AGENT_DIRECTORY.map((entry) => {
    const live = matchSnapshotAgentForRole(entry, snapAgents);
    const dynamicId = live?.paperclip_agent_id ? String(live.paperclip_agent_id) : entry.id;
    return {
      ...entry,
      id: dynamicId,
      default_id: entry.id,
      paperclip_agent_id: dynamicId,
      live_agent: live,
    };
  });
}

function samePath(a, b) {
  if (!a || !b) return false;
  return process.platform === "win32"
    ? String(a).toLowerCase() === String(b).toLowerCase()
    : String(a) === String(b);
}

function defaultTelegramState() {
  return {
    version: 2,
    owner_id: resolveAuthorizedOwnerId(process.env),
    selected_agent_id: CORPORATE_AGENT_DIRECTORY[0].id,
    selected_agent_slug: CORPORATE_AGENT_DIRECTORY[0].slug,
    selected_agent_name: CORPORATE_AGENT_DIRECTORY[0].name,
    direct_agent_mode: false,
    last_command: null,
    last_analysis_report: null,
    last_updated_at: new Date().toISOString(),
    path_tokens: {},
    approval_tokens: {},
  };
}

function loadTelegramControlState() {
  const currentOwner = resolveAuthorizedOwnerId(process.env);
  try {
    if (fs.existsSync(TELEGRAM_STATE_FILE)) {
      const raw = fs.readFileSync(TELEGRAM_STATE_FILE, "utf8").replace(/^\uFEFF/, "").trim();
      if (raw) {
        const parsed = JSON.parse(raw);
        return {
          ...defaultTelegramState(),
          ...parsed,
          owner_id: currentOwner,
          path_tokens: parsed.path_tokens && typeof parsed.path_tokens === "object" ? parsed.path_tokens : {},
          approval_tokens: parsed.approval_tokens && typeof parsed.approval_tokens === "object" ? parsed.approval_tokens : {},
        };
      }
    }
  } catch {}
  const initial = defaultTelegramState();
  saveTelegramControlState(initial);
  return initial;
}

function saveTelegramControlState(state) {
  fs.mkdirSync(path.dirname(TELEGRAM_STATE_FILE), { recursive: true, mode: 0o700 });
  const next = {
    ...defaultTelegramState(),
    ...state,
    owner_id: resolveAuthorizedOwnerId(process.env),
    last_updated_at: new Date().toISOString(),
  };
  const pathEntries = Object.entries(next.path_tokens || {});
  if (pathEntries.length > 250) {
    next.path_tokens = Object.fromEntries(pathEntries.slice(-250));
  }
  const apprEntries = Object.entries(next.approval_tokens || {});
  if (apprEntries.length > 120) {
    next.approval_tokens = Object.fromEntries(apprEntries.slice(-120));
  }
  fs.writeFileSync(TELEGRAM_STATE_FILE, JSON.stringify(next, null, 2) + "\n", "utf8");
  return next;
}

function registerShortPathToken(state, targetPath) {
  const clean = String(targetPath || "").trim();
  const hashSrc = process.platform === "win32" ? clean.toLowerCase() : clean;
  const tok = `p_${crypto.createHash("sha1").update(hashSrc).digest("hex").slice(0, 8)}`;
  state.path_tokens = state.path_tokens || {};
  state.path_tokens[tok] = clean;
  return tok;
}

function resolvePathOrToken(state, rawArg) {
  const trimmed = String(rawArg || "").trim().replace(/^["']|["']$/g, "");
  if (!trimmed) return "";
  if (state.path_tokens && state.path_tokens[trimmed]) {
    return state.path_tokens[trimmed];
  }
  return trimmed;
}

function registerShortApprovalToken(state, approvalId) {
  const clean = String(approvalId || "").trim();
  const tok = `a_${clean.slice(0, 10)}`;
  state.approval_tokens = state.approval_tokens || {};
  state.approval_tokens[tok] = clean;
  return tok;
}

function resolveApprovalOrToken(state, rawArg) {
  const trimmed = String(rawArg || "").trim();
  if (!trimmed) return "";
  if (state.approval_tokens && state.approval_tokens[trimmed]) {
    return state.approval_tokens[trimmed];
  }
  return trimmed;
}

/**
 * Resolve any of the 11 corporate agents by index (`1..11`), `@handle`, `slug`, `role_slug`,
 * `profile`, portable `role:<slug>` ID, live Paperclip UUID, display name, or Indonesian/English alias.
 */
function resolveCorporateAgentEntry(query, snapshot = null) {
  const raw = String(query || "").trim();
  if (!raw) return null;
  const directory = snapshot ? resolveLiveCorporateDirectory(snapshot) : CORPORATE_AGENT_DIRECTORY;
  const cleaned = raw
    .toLowerCase()
    .replace(/^@+/, "")
    .replace(/^(agen|agent|nomor|no\.?|ke)\s+/i, "")
    .trim();
  if (!cleaned) return null;

  if (/^\d{1,2}$/.test(cleaned)) {
    const idx = Number(cleaned);
    return directory.find((a) => a.index === idx) || null;
  }

  const leadIdx = cleaned.match(/^(?:[^\d]{0,4})?(\d{1,2})\.\s+/);
  if (leadIdx) {
    const idx = Number(leadIdx[1]);
    const byIdx = directory.find((a) => a.index === idx);
    if (byIdx) return byIdx;
  }

  for (const entry of directory) {
    if (
      entry.id.toLowerCase() === cleaned ||
      (entry.default_id && entry.default_id.toLowerCase() === cleaned) ||
      (entry.id.toLowerCase().startsWith(cleaned) && cleaned.length >= 8) ||
      entry.slug.toLowerCase() === cleaned ||
      entry.profile.toLowerCase() === cleaned ||
      entry.handle.slice(1).toLowerCase() === cleaned ||
      entry.name.toLowerCase() === cleaned ||
      entry.shortLabel.toLowerCase() === cleaned
    ) {
      return entry;
    }
  }

  const allPairs = [];
  for (const entry of directory) {
    for (const al of entry.aliases) {
      allPairs.push({ alias: al.toLowerCase(), entry });
    }
  }
  allPairs.sort((a, b) => b.alias.length - a.alias.length);
  for (const { alias, entry } of allPairs) {
    if (cleaned === alias) return entry;
  }
  for (const { alias, entry } of allPairs) {
    const escaped = alias.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (new RegExp(`(?:^|\\b)${escaped}(?:\\b|$)`, "i").test(cleaned)) {
      return entry;
    }
  }
  return null;
}

/**
 * Normalized enrichment exposing BOTH `id` and `paperclip_agent_id` dynamically bound to `snapshot.agents`.
 */
function enrichDirectoryWithSnapshot(snapshot, tgState) {
  const liveDir = resolveLiveCorporateDirectory(snapshot);
  return liveDir.map((entry) => {
    const live = entry.live_agent || null;
    const activationStatus = live?.activation_status || (entry.wave === 1 ? "ACTIVE" : "STANDBY");
    const visualState = live?.state?.visual_state || (activationStatus === "ACTIVE" ? "IDLE_AT_DESK" : "STANDBY");
    const isSelected =
      tgState?.selected_agent_id === entry.id || tgState?.selected_agent_slug === entry.slug;
    return {
      ...entry,
      paperclip_agent_id: entry.id,
      activation_status: activationStatus,
      raw_status: live?.raw_status || "unknown",
      visual_state: visualState,
      connectivity_state: live?.state?.connectivity_state || "ONLINE",
      model_id: live?.model_id || DEFAULT_LLM_MODEL,
      current_task: live?.current_task || null,
      current_run: live?.current_run || null,
      selected_in_telegram: isSelected,
      live_agent: live,
    };
  });
}

function buildAgentSelectorKeyboard(enrichedAgents, tgState) {
  const rows = [];
  for (let i = 0; i < enrichedAgents.length; i += 2) {
    const pair = enrichedAgents.slice(i, i + 2).map((ag) => {
      const stIcon = ag.activation_status === "ACTIVE" ? "🟢" : "⏸️";
      const check =
        (tgState.selected_agent_id === ag.id || tgState.selected_agent_slug === ag.slug) && tgState.direct_agent_mode
          ? " ✓"
          : "";
      return btn(`${stIcon} ${ag.shortLabel}${check}`, `uac:pick:${ag.index}`);
    });
    rows.push(pair);
  }
  rows.push([
    btn(
      tgState.direct_agent_mode ? "🔓 Lepas Mode Agen (Ke Hermes)" : "🔓 Mode Hermes Umum (Aktif ✓)",
      "uac:pick:0"
    ),
    btn("🧰 Skills 11 Agen", "uac:sk_all"),
  ]);
  rows.push([btn("⚡ Aktifkan Semua 11 Agen", "uac:wake_all"), btn("🔄 Standar Wave-1", "uac:wave1")]);
  rows.push(navFooter({ backTo: "uac:home", refreshCb: "uac:agents" }));
  return rows;
}

function buildSelectedAgentActionsKeyboard(agentEntry, activationStatus, tgState) {
  const idx = agentEntry.index;
  const toggleBtn =
    activationStatus === "ACTIVE"
      ? btn("⏸️ Pause ke Standby", `uac:pause:${idx}`)
      : btn("▶️ Aktifkan Agen Ini", `uac:wake:${idx}`);
  return [
    [toggleBtn, btn("⚡ Wake Heartbeat", `uac:wakehb:${idx}`)],
    [btn("🔍 Inspector Detail", `uac:info:${idx}`), btn("🧰 Skills Agen Ini", `uac:sk:${idx}`)],
    [btn("📁 Analisis Folder Aktif", `uac:anl_active:${idx}`), btn("💬 Info/Reset Sesi", `uac:ses:${idx}`)],
    [
      btn(
        tgState.direct_agent_mode ? "🔓 Lepas Mode Agen" : "🎯 Kunci Chat ke Agen Ini",
        tgState.direct_agent_mode ? "uac:pick:0" : `uac:pick:${idx}`
      ),
      btn("👥 Ganti Agen", "uac:agents"),
    ],
    [btn("🏠 Home", "uac:home")],
  ];
}

function buildFolderControlKeyboard(tgState, folderStatus) {
  const rows = [];
  if (folderStatus.active_folder) {
    rows.push([
      btn(
        `🔍 Analisis Folder Aktif (${path.basename(folderStatus.active_folder) || folderStatus.active_folder})`,
        "uac:anl_active"
      ),
    ]);
  }
  const pinned = (folderStatus.pinned_folders || []).filter((p) => p.exists).slice(0, 6);
  for (let i = 0; i < pinned.length; i += 2) {
    rows.push(
      pinned.slice(i, i + 2).map((p) => {
        const tok = registerShortPathToken(tgState, p.path);
        const mark = samePath(folderStatus.active_folder, p.path) ? " ✓" : "";
        return btn(`📌 ${(p.name || p.path).slice(0, 22)}${mark}`, `uac:sel:${tok}`);
      })
    );
  }
  const roots = (folderStatus.quick_roots || []).slice(0, 6);
  const rootRow = [];
  for (const r of roots) {
    const rPath = typeof r === "string" ? r : r.path;
    const rLabel = typeof r === "string" ? path.basename(r) || r : r.label || r.path;
    if (!rPath) continue;
    const tok = registerShortPathToken(tgState, rPath);
    rootRow.push(btn(`📂 ${String(rLabel).slice(0, 18)}`, `uac:br:${tok}:1`));
    if (rootRow.length === 2) {
      rows.push([...rootRow]);
      rootRow.length = 0;
    }
  }
  if (rootRow.length > 0) rows.push(rootRow);
  rows.push(navFooter({ backTo: "uac:home", refreshCb: "uac:folders" }));
  return rows;
}

function buildBrowseDirectoryKeyboard(tgState, browseResult) {
  const rows = [];
  if (browseResult.current_path) {
    const curTok = registerShortPathToken(tgState, browseResult.current_path);
    rows.push([
      btn(`✅ Pilih Folder Ini (${path.basename(browseResult.current_path) || browseResult.current_path})`, `uac:sel:${curTok}`),
      btn("🔍 Analisis Ini", `uac:anl:${curTok}`),
    ]);
  }
  const dirs = browseResult.directories || [];
  for (let i = 0; i < dirs.length; i += 2) {
    rows.push(
      dirs.slice(i, i + 2).map((d) => {
        const tok = registerShortPathToken(tgState, d.path);
        const badge = d.markers && d.markers.length > 0 ? "📦" : "📁";
        return btn(`${badge} ${d.name.slice(0, 22)}`, `uac:br:${tok}:1`);
      })
    );
  }
  if (browseResult.total_pages > 1 && browseResult.current_path) {
    const curTok = registerShortPathToken(tgState, browseResult.current_path);
    const pRow = paginationRow({
      prefix: `uac:brp:${curTok}`,
      page: browseResult.page,
      totalPages: browseResult.total_pages,
    });
    if (pRow) rows.push(pRow);
  }
  const navRow = [];
  if (browseResult.parent_path !== null && browseResult.parent_path !== undefined) {
    const parentTok =
      browseResult.parent_path && browseResult.parent_path !== "drives"
        ? registerShortPathToken(tgState, browseResult.parent_path)
        : "drives";
    navRow.push(btn("⬆️ Naik Folder Induk", `uac:br:${parentTok}:1`));
  }
  navRow.push(btn("📁 Menu Folder", "uac:folders"));
  navRow.push(btn("🏠 Home", "uac:home"));
  rows.push(navRow);
  return rows;
}

/**
 * Public natural-language parser (backward-compatible signature `(rawText, tgState, snapshot = null)`).
 */
function parseNaturalTelegramIntent(rawText, tgState, snapshot = null) {
  const folderStatus = getTargetFoldersStatus();
  return routeIndonesianNaturalIntent(rawText, {
    tgState,
    folderStatus,
    resolveCorporateAgentEntry: (q) => resolveCorporateAgentEntry(q, snapshot),
    extractTargetProjectPath,
  });
}

function getTelegramControlPublicState(sync) {
  const tgState = loadTelegramControlState();
  const snap = sync.getFullSnapshot();
  const enriched = enrichDirectoryWithSnapshot(snap, tgState);
  const selectedMatch =
    enriched.find((a) => a.id === tgState.selected_agent_id || a.slug === tgState.selected_agent_slug) || enriched[0];
  const folderStatus = getTargetFoldersStatus();
  const activeMeeting = getActiveMeetingV2(sync);
  const dispatch = loadDispatchControl();
  const activeJobs = loadAsyncJobs().filter((j) => j.status === "RUNNING" || j.status === "QUEUED");
  return sanitizePayload({
    ok: true,
    owner_id: resolveAuthorizedOwnerId(process.env),
    selected_agent_id: selectedMatch ? selectedMatch.id : tgState.selected_agent_id,
    selected_agent_slug: selectedMatch ? selectedMatch.slug : tgState.selected_agent_slug,
    selected_agent_name: selectedMatch ? selectedMatch.name : tgState.selected_agent_name,
    direct_agent_mode: Boolean(tgState.direct_agent_mode),
    active_folder: folderStatus.active_folder || null,
    active_meeting: activeMeeting || null,
    dispatch_paused: Boolean(dispatch.dispatch_paused),
    running_async_jobs: activeJobs.length,
    last_command: tgState.last_command,
    last_updated_at: tgState.last_updated_at,
    agents: enriched.map(({ live_agent, ...rest }) => rest),
  });
}

function formatUsd(val) {
  return `$${Number(val || 0).toFixed(2)}`;
}

function formatNumber(val) {
  return Number(val || 0).toLocaleString("en-US");
}

function formatDurationMs(ms) {
  const s = Math.max(0, Math.round(Number(ms || 0) / 1000));
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

/**
 * Map compact `uac:*` callback data strings into `{ cmd, args }`.
 */
function mapCallbackDataToCommand(rawCb, tgState, snapshot = null) {
  const cleanCb = String(rawCb || "uac:home").split("|sig=")[0];
  const parts = cleanCb.split(":");
  const verb = parts[1] || "home";
  const p1 = parts[2] || "";
  const p2 = parts[3] || "";
  const rest = parts.slice(2).join(":");
  const defaultWorkspace = WORKSPACES_DIR.replace(/\\/g, "/");

  switch (verb) {
    case "noop":
      return { cmd: "noop", args: "" };
    case "menu":
    case "home":
      return { cmd: "kantor", args: "" };
    case "sub":
      if (p1 === "agents") return { cmd: "agen", args: "" };
      if (p1 === "folders") return { cmd: "folder", args: "" };
      if (p1 === "approvals") return { cmd: "persetujuan", args: "" };
      if (p1 === "health") return { cmd: "kesehatan", args: "" };
      return { cmd: "submenu", args: p1 };
    case "agents":
      return { cmd: "agen", args: "" };
    case "pick":
      return { cmd: "pilih", args: p1 };
    case "info":
      return { cmd: "info_agen", args: p1 };
    case "sk":
      return { cmd: "daftar_skill", args: p1 };
    case "sk_all":
      return { cmd: "daftar_skill", args: "" };
    case "sk_st":
      return { cmd: "skill_status", args: "" };
    case "ses":
      return { cmd: "reset_sesi", args: p1 };
    case "ses_clr":
      return { cmd: "reset_sesi", args: `${p1} --clear` };
    case "wake":
      return { cmd: "bangunkan", args: p1 };
    case "wakehb":
      return { cmd: "bangunkan", args: `${p1} --heartbeat` };
    case "wake_all":
      return { cmd: "bangunkan", args: "semua" };
    case "pause":
      return { cmd: "istirahatkan", args: p1 };
    case "wave1":
      return { cmd: "standar_wave1", args: "" };
    case "disp":
      return { cmd: "pause_dispatch", args: p1 };
    case "stop_ask":
      return { cmd: "stop_semua", args: "--ask" };
    case "stop_all":
      return { cmd: "stop_semua", args: "--confirm" };
    case "ceo_del_active": {
      const f = loadTargetFoldersStore().active_folder || defaultWorkspace;
      return {
        cmd: "delegasi",
        args: `CEO, delegasikan audit ${f} kepada CTO, Backend Developer, QA Engineer, dan Security Reviewer`,
      };
    }
    case "off":
      return { cmd: "status_kantor", args: p1 };
    case "shot":
      return { cmd: "screenshot_kantor", args: p1 || "3d" };
    case "meet_menu":
      return { cmd: "submenu", args: "meeting" };
    case "meet_all":
      return { cmd: "meeting", args: rest || "Rapat Koordinasi Penuh 11 Agen Eksekutif & Teknis" };
    case "meet_active_folder": {
      const f = loadTargetFoldersStore().active_folder;
      return {
        cmd: "meeting",
        args: f ? `Bahas arsitektur & hasil audit folder ${f}` : "Rapat Koordinasi Penuh 11 Agen",
      };
    }
    case "meet_end":
      return { cmd: "selesai_meeting", args: "Ditutup oleh Owner melalui kontrol Telegram." };
    case "meet":
      if (p1 === "status") return { cmd: "status_meeting", args: "" };
      if (p1 === "discuss") return { cmd: "diskusi_rapat", args: "" };
      if (p1 === "minutes") return { cmd: "notulen", args: p2 === "tasks" ? "--tasks" : "" };
      if (p1 === "history") return { cmd: "notulen", args: "history" };
      return { cmd: "submenu", args: "meeting" };
    case "folders":
      return { cmd: "folder", args: "" };
    case "br": {
      const target = p1 === "drives" ? "drives" : resolvePathOrToken(tgState, p1);
      const pg = p2 || "1";
      return { cmd: "jelajah", args: `${target}::page=${pg}` };
    }
    case "brp": {
      const target = resolvePathOrToken(tgState, p1);
      return { cmd: "jelajah", args: `${target}::page=${p2 || "1"}` };
    }
    case "sel":
      return { cmd: "pilih_folder", args: resolvePathOrToken(tgState, p1) };
    case "anl":
      return { cmd: "analisis", args: resolvePathOrToken(tgState, p1) };
    case "anl_active": {
      if (p1 && /^\d+$/.test(p1)) {
        const picked = resolveCorporateAgentEntry(p1, snapshot);
        if (picked) {
          tgState.selected_agent_id = picked.id;
          tgState.selected_agent_slug = picked.slug;
          tgState.selected_agent_name = picked.name;
        }
      }
      return { cmd: "analisis", args: loadTargetFoldersStore().active_folder || "" };
    }
    case "dev":
      if (p1 === "git") return { cmd: "dev", args: "git_status" };
      if (p1 === "diff") return { cmd: "dev", args: "cek_diff" };
      if (p1 === "test") return { cmd: "dev", args: "jalankan_test" };
      if (p1 === "build") return { cmd: "dev", args: "build_project" };
      if (p1 === "review") return { cmd: "dev", args: "review_kode" };
      return { cmd: "submenu", args: "dev" };
    case "pc":
      if (p1 === "projects") return { cmd: "projects", args: "" };
      if (p1 === "quick_audit") {
        const f = loadTargetFoldersStore().active_folder || defaultWorkspace;
        return { cmd: "buat_task", args: `backend_developer | Audit Teknis ${path.basename(f)} | Periksa struktur & kode pada ${f}` };
      }
      return { cmd: "submenu", args: "paperclip" };
    case "tasks":
      return { cmd: "daftar_task", args: `${p1 || "all"} ${p2 || "1"}`.trim() };
    case "anx":
      return { cmd: "analytics", args: [p1, p2].filter(Boolean).join(" ") };
    case "analytics":
      return { cmd: "analytics", args: "" };
    case "bdg":
      if (p1 === "set") return { cmd: "set_budget", args: `${p2} ${parts[4] || ""}` };
      return { cmd: "budget", args: p1 || "overview" };
    case "security":
      return { cmd: "keamanan", args: "" };
    case "sec":
      if (p1 === "summary") return { cmd: "keamanan", args: "" };
      if (p1 === "list") return { cmd: "keamanan", args: `list ${p2 || "1"}` };
      if (p1 === "scan_active") return { cmd: "keamanan", args: loadTargetFoldersStore().active_folder || defaultWorkspace };
      if (p1 === "deps") return { cmd: "keamanan", args: `deps ${loadTargetFoldersStore().active_folder || defaultWorkspace}` };
      if (p1 === "remediate") return { cmd: "remediasi_temuan", args: p2 || "latest" };
      if (p1 === "verify") return { cmd: "keamanan", args: "verify" };
      return { cmd: "keamanan", args: "" };
    case "approvals":
      return { cmd: "persetujuan", args: "" };
    case "app_ok":
      return { cmd: "setujui", args: resolveApprovalOrToken(tgState, p1) };
    case "app_no":
      return { cmd: "tolak", args: resolveApprovalOrToken(tgState, p1) };
    case "health":
      return { cmd: "kesehatan", args: "" };
    case "sys":
      if (p1 === "updates") return { cmd: "update_status", args: "" };
      if (p1 === "sched") return { cmd: "kesehatan", args: "scheduler" };
      if (p1 === "jobs") return { cmd: "jobs", args: "" };
      if (p1 === "logs") return { cmd: "log_error", args: "" };
      if (p1 === "recover") return { cmd: "pulihkan_layanan", args: "reconcile" };
      return { cmd: "submenu", args: "system" };
    default:
      return { cmd: "kantor", args: "" };
  }
}

/**
 * Primary Unified Entrypoint for ALL Telegram Commands, Callbacks & Natural Language Turns.
 */
async function executeTelegramControlCommand(ctx, payload = {}) {
  const { sync, paperclip, eventBus, handleCreateTaskAction, buildAgentInspectorPayload, buildUnifiedHealthMatrix } =
    ctx;

  const correlationId = payload.correlation_id || generateCorrelationId("tg");
  const callerId = String(payload.caller_id || "").trim();
  const rawCommand = String(payload.command || "kantor").trim();
  const rawArgs = String(payload.args || "").trim();

  // PHASE 03 — Strict Owner (Fail-Closed), Private-DM, Replay & Tampering Security Guard
  const sec = verifyTelegramRequestSecurity({
    caller_id: callerId,
    chat_id: payload.chat_id,
    chat_type: payload.chat_type || "private",
    callback_sender_id: payload.callback_sender_id,
    callback_query_id: payload.callback_query_id,
    session_owner_id: payload.session_owner_id,
    command: rawCommand,
  });
  if (!sec.ok) {
    if (sec.code === "UNAUTHORIZED_USER" || sec.code === "OWNER_ID_NOT_CONFIGURED") {
      const err = new Error(sec.error);
      err.status = 403;
      err.code = sec.code;
      throw err;
    }
    return buildStructuredError({
      correlationId,
      command: rawCommand,
      code: sec.code,
      status: sec.status || 403,
      message: sec.error,
    });
  }

  const snap = sync.getFullSnapshot();
  const liveDirectory = resolveLiveCorporateDirectory(snap);
  const tgState = loadTelegramControlState();

  // Automatically align selected_agent_id with live Paperclip UUID matching selected_agent_slug
  const syncedSel =
    liveDirectory.find((a) => a.id === tgState.selected_agent_id) ||
    liveDirectory.find((a) => a.slug === tgState.selected_agent_slug) ||
    liveDirectory[0];
  if (syncedSel && tgState.selected_agent_id !== syncedSel.id) {
    tgState.selected_agent_id = syncedSel.id;
    tgState.selected_agent_slug = syncedSel.slug;
    tgState.selected_agent_name = syncedSel.name;
  }

  let invokedCmd = rawCommand.toLowerCase().replace(/^\/+/, "").replace(/@[a-z0-9_]+$/i, "").replace(/-/g, "_");
  let args = rawArgs;

  if (invokedCmd === "callback" || rawCommand.startsWith("uac:")) {
    const cbRaw = rawCommand.startsWith("uac:") ? rawCommand : args;
    const mapped = mapCallbackDataToCommand(cbRaw, tgState, snap);
    if (mapped.cmd === "noop") {
      return { ok: true, command: "noop", noop: true, reply: "ℹ️ Halaman saat ini." };
    }
    invokedCmd = mapped.cmd;
    args = mapped.args;
  }

  // Handle inbound plain-text natural language
  if (invokedCmd === "inbound_text") {
    const intent = parseNaturalTelegramIntent(args, tgState, snap);
    if (intent.kind === "passthrough") {
      return { ok: true, handled: false };
    }
    if (intent.kind === "destructive_blocked") {
      const req = createBoundApprovalRequest({
        ownerId: callerId,
        action: "destructive_operation",
        target: loadTargetFoldersStore().active_folder || "unspecified",
        args,
        riskCategory: "CRITICAL",
        originAgent: "Telegram NL Guard",
      });
      return {
        ok: true,
        handled: true,
        requires_confirmation: true,
        approval_request: req,
        reply:
          `🛑 *Konfirmasi Spesifik Diperlukan (${req.request_id})*\n` +
          `${intent.reason}\n` +
          `• *Request ID:* \`${req.request_id}\` (berlaku 15 menit)\n` +
          `Gunakan \`/persetujuan\` untuk meninjau atau menolak permintaan ini.`,
        inline_keyboard: [[btn("✅ Buka Approvals", "uac:approvals"), btn("🏠 Home", "uac:home")]],
      };
    }
    if (intent.kind === "command") {
      const subRes = await executeTelegramControlCommand(ctx, {
        ...payload,
        callback_query_id: undefined,
        command: intent.command,
        args: intent.args,
      });
      return { ...subRes, handled: true };
    }
    if (intent.kind === "ask_agent" || intent.kind === "direct_selected_agent") {
      const targetEntry =
        (intent.agentEntry && resolveCorporateAgentEntry(intent.agentEntry.slug || intent.agentEntry.id, snap)) ||
        liveDirectory.find((a) => a.id === tgState.selected_agent_id || a.slug === tgState.selected_agent_slug) ||
        liveDirectory[0];
      const liveTarget =
        (snap.agents || []).find((a) => a.paperclip_agent_id === targetEntry.id) ||
        (snap.agents || []).find((a) => a.role === "ceo") ||
        (snap.agents || [])[0] || {
          paperclip_agent_id: targetEntry.id,
          role_slug: targetEntry.slug,
          display_name: targetEntry.name,
          title: targetEntry.name,
          department: targetEntry.department,
          department_short: targetEntry.department,
          runtime_type: "hermes_local",
          runtime_profile_reference: targetEntry.profile,
          model_id: DEFAULT_LLM_MODEL,
          activation_status: "ACTIVE",
        };
      const idemKey = payload.message_id
        ? `tg-chat:${callerId}:${payload.message_id}`
        : `tg-chat:${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;

      const cached = payload.message_id ? checkIdempotency(idemKey) : null;
      if (cached) return { ...cached, deduplicated: true, handled: true };

      const turn = await handleEmployeeChatTurn({
        agent: liveTarget,
        snapshot: snap,
        rawMessage: intent.message,
        idempotencyKey: idemKey,
        createTaskFn: handleCreateTaskAction,
        sync,
        paperclip,
        callerId,
      });

      tgState.last_command = `${intent.kind}:${targetEntry.slug}`;
      saveTelegramControlState(tgState);

      const receipt = buildExecutionReceipt({
        correlationId,
        command: intent.kind,
        invokedAs: "inbound_text",
        mutated: Boolean(turn.createdTask || turn.createdMeeting),
        taskId: turn.createdTask?.identifier || turn.createdTask?.id || null,
        meetingId: turn.createdMeeting?.meeting_id || null,
        agentId: targetEntry.id,
        targetWorkspace: turn.inspectedTarget || null,
      });

      const taskBadge = turn.createdTask
        ? `\n\n📌 *Paperclip Task:* \`${turn.createdTask.identifier || String(turn.createdTask.id).slice(0, 8)}\` (\`${turn.createdTask.status}\`)`
        : "";
      const mtgBadge = turn.createdMeeting
        ? `\n🤝 *Meeting 3D/2D Aktif:* \`${(turn.createdMeeting.participants || []).length} agen berkumpul di Ruang Meeting\``
        : "";
      const modeFooter =
        intent.kind === "direct_selected_agent"
          ? `\n\n_💬 Mode Agen Aktif: ${targetEntry.emoji} ${targetEntry.name} • /pilih ganti agen • /lepas ke Hermes umum_`
          : `\n\n_📨 Mention Sementara ke ${targetEntry.handle} (Agen default tetap: ${tgState.selected_agent_name})_`;

      const out = {
        ok: true,
        handled: true,
        agent_id: targetEntry.id,
        agent_name: targetEntry.name,
        created_task: turn.createdTask || null,
        created_meeting: turn.createdMeeting || null,
        receipt,
        reply: `${targetEntry.emoji} *[${targetEntry.name} — ${targetEntry.department}]*\n\n${turn.text}${taskBadge}${mtgBadge}${modeFooter}`,
        inline_keyboard: buildSelectedAgentActionsKeyboard(
          targetEntry,
          liveTarget?.activation_status || "ACTIVE",
          tgState
        ),
      };
      if (payload.message_id) saveIdempotency(idemKey, out);
      return out;
    }
  }

  // PHASE 02 — Canonical Command Resolution & Schema Validation
  const resolved = resolveCanonicalCommand(invokedCmd);
  const canonicalId = resolved.canonical_id;
  if (!canonicalId) {
    return buildStructuredError({
      correlationId,
      command: invokedCmd,
      code: "UNKNOWN_COMMAND",
      status: 400,
      message: `Perintah \`/${sanitizeText(invokedCmd)}\` tidak dikenali. Ketik \`/kantor\` untuk membuka pusat kontrol CODEXE.`,
      inlineKeyboard: buildCodexeHomeKeyboard(tgState, Boolean(getActiveMeetingV2(sync))),
    });
  }

  const argCheck = validateCommandArguments(resolved.spec, args);
  if (!argCheck.ok && argCheck.code !== "MISSING_REQUIRED_ARGUMENT") {
    return buildStructuredError({
      correlationId,
      command: canonicalId,
      code: argCheck.code,
      status: 400,
      message: argCheck.error,
    });
  }

  const enrichedAgents = enrichDirectoryWithSnapshot(snap, tgState);
  const folderStatus = getTargetFoldersStatus();
  const activeMeeting = getActiveMeetingV2(sync);
  const runningJobs = loadAsyncJobs().filter((j) => j.status === "RUNNING" || j.status === "QUEUED");
  const dispatchState = loadDispatchControl();
  const defaultWorkspace = WORKSPACES_DIR.replace(/\\/g, "/");

  // ===========================================================================
  // PHASE 04 — INTERACTIVE COMMAND CENTER (`kantor` & `submenu`)
  // ===========================================================================
  if (canonicalId === "kantor") {
    const header = buildContextHeader({
      tgState,
      snap,
      folderStatus,
      activeMeeting,
      runningJobsCount: runningJobs.length,
    });
    const usageQuick = await buildTelegramAnalyticsReport({ snap, paperclip, directory: liveDirectory, windowArg: "30d" });
    const reply = [
      header,
      `• *Telemetry Valid (30d):* \`${formatNumber(usageQuick.metrics.total_tokens)} tok\` • Est \`${formatUsd(usageQuick.cost_transparency.estimated_token_metered_cost_usd)}\``,
      ``,
      `🧭 *Pilih salah satu dari 13 Submenu Kendali di bawah (atau ketik perintah / Bahasa Indonesia alami):*`,
    ].join("\n");

    tgState.last_command = invokedCmd;
    saveTelegramControlState(tgState);
    return {
      ok: true,
      command: invokedCmd,
      receipt: buildExecutionReceipt({ correlationId, command: canonicalId, invokedAs: invokedCmd, mutated: false }),
      reply,
      inline_keyboard: buildCodexeHomeKeyboard(tgState, Boolean(activeMeeting)),
    };
  }

  if (canonicalId === "submenu") {
    const view = buildSubmenuView(args || "ceo", {
      tgState,
      snap,
      folderStatus,
      activeMeeting,
      runningJobsCount: runningJobs.length,
      dispatchPaused: dispatchState.dispatch_paused,
      registerPathToken: (p) => registerShortPathToken(tgState, p),
    });
    saveTelegramControlState(tgState);
    if (!view) {
      return executeTelegramControlCommand(ctx, { ...payload, command: "kantor", args: "" });
    }
    return {
      ok: true,
      command: "submenu",
      submenu: args,
      receipt: buildExecutionReceipt({ correlationId, command: canonicalId, invokedAs: invokedCmd, mutated: false }),
      ...view,
    };
  }

  // ===========================================================================
  // PHASE 05 — COMPLETE 11-AGENT SELECTION, INSPECTOR, SESSION & CHAT CONTROL
  // ===========================================================================
  if (canonicalId === "agen") {
    const lines = [
      `👥 *Daftar 11 Karyawan AI (` + (snap.company?.name || "ALLINAGENT Operations") + `)*`,
      `_Ketuk tombol agen di bawah atau ketik \`/pilih <1..11>\` untuk memilih agen aktif di Telegram:_`,
      ``,
    ];
    for (const ag of enrichedAgents) {
      const stBadge = ag.activation_status === "ACTIVE" ? "🟢 ACTIVE" : "⏸️ STANDBY";
      const picked =
        tgState.selected_agent_id === ag.id || tgState.selected_agent_slug === ag.slug
          ? tgState.direct_agent_mode
            ? " 👈 *[AKTIF DI TELEGRAM]*"
            : " *(Default)*"
          : "";
      const taskNote = ag.current_task ? ` — 📋 \`${ag.current_task.identifier || "Task"}\`` : "";
      lines.push(
        `*${ag.index}.* ${ag.emoji} *${ag.name}* (\`${ag.handle}\`)\n   └ ${ag.department} • \`${stBadge}\` • 3D/2D: \`${ag.visual_state}\`${taskNote}${picked}`
      );
    }
    tgState.last_command = "agen";
    saveTelegramControlState(tgState);
    return {
      ok: true,
      command: "agen",
      count: enrichedAgents.length,
      agents: enrichedAgents.map(({ live_agent, ...r }) => r),
      receipt: buildExecutionReceipt({ correlationId, command: "agen", invokedAs: invokedCmd }),
      reply: lines.join("\n"),
      inline_keyboard: buildAgentSelectorKeyboard(enrichedAgents, tgState),
    };
  }

  if (canonicalId === "lepas") {
    tgState.direct_agent_mode = false;
    tgState.last_command = "lepas";
    saveTelegramControlState(tgState);
    return {
      ok: true,
      command: "lepas",
      direct_agent_mode: false,
      selected_agent_id: tgState.selected_agent_id,
      receipt: buildExecutionReceipt({
        correlationId,
        command: "lepas",
        invokedAs: invokedCmd,
        mutated: true,
        agentId: tgState.selected_agent_id,
      }),
      reply:
        `🔓 *Mode Kunci Agen Dinonaktifkan*\n` +
        `Chat biasa di Telegram kini kembali ke mode **Hermes Orchestrator Umum**.\n` +
        `• Anda tetap dapat memanggil agen spesifik kapan saja dengan \`@ceo\`, \`@cto\`, \`@backend\`, \`@qa\`, dll., atau ketik \`/pilih\` untuk memilih agen kembali.`,
      inline_keyboard: buildCodexeHomeKeyboard(tgState, Boolean(activeMeeting)),
    };
  }

  if (canonicalId === "pilih") {
    const cleanArg = args.trim();
    if (!cleanArg) {
      return {
        ok: true,
        command: "pilih",
        needs_choice: true,
        choices: [
          ...enrichedAgents.map((a) => `${a.index}. ${a.name} (${a.activation_status} — ${a.department})`),
          "0. Mode Hermes Umum (Lepas Kunci Agen)",
        ],
        reply:
          `🎯 *Pilih Agen Aktif di Telegram (1–11)*\n` +
          `Agen terpilih saat ini: *${tgState.selected_agent_name}* (${tgState.direct_agent_mode ? "Mode Chat Langsung ON" : "Mode Umum"}).\n\n` +
          `Silakan ketuk salah satu dari **11 Agen** di bawah (atau ketik \`/pilih <1..11|nama>\`):`,
        inline_keyboard: buildAgentSelectorKeyboard(enrichedAgents, tgState),
      };
    }
    if (/^(0|off|none|lepas|hermes|reset|umum)\b/i.test(cleanArg)) {
      return executeTelegramControlCommand(ctx, { ...payload, command: "lepas", args: "" });
    }
    const entry = resolveCorporateAgentEntry(cleanArg, snap);
    if (!entry) {
      return {
        ok: false,
        status: 400,
        error: `Agen '${cleanArg}' tidak ditemukan.`,
        reply:
          `⚠️ Agen \`${sanitizeText(cleanArg)}\` tidak ditemukan.\n` +
          `Gunakan nomor \`1\` s/d \`11\` atau \`@handle\` (contoh: \`/pilih 1\`, \`/pilih @cto\`, \`/pilih backend\`, \`/pilih security_lead\`, \`/pilih compliance\`).`,
        inline_keyboard: buildAgentSelectorKeyboard(enrichedAgents, tgState),
      };
    }

    const enriched = enrichedAgents.find((a) => a.slug === entry.slug || a.id === entry.id) || entry;
    tgState.selected_agent_id = entry.id;
    tgState.selected_agent_slug = entry.slug;
    tgState.selected_agent_name = entry.name;
    tgState.direct_agent_mode = true;
    tgState.last_command = `pilih:${entry.slug}`;
    saveTelegramControlState(tgState);

    if (eventBus && typeof eventBus.publish === "function") {
      eventBus.publish({
        event_type: "agent.updated",
        source: "telegram_gateway",
        company_id: snap.company?.id || "company",
        agent_id: entry.id,
        dedupe_key: `tg_sel:${entry.id}:${Date.now()}`,
        payload: {
          selected_in_telegram: true,
          agent_id: entry.id,
          agent_name: entry.name,
          direct_agent_mode: true,
        },
      });
    }

    const recentChat = readAgentChatHistory(entry.id, 2);
    const lastTurnSnippet =
      recentChat.length > 0
        ? `\n• *Sesi Percakapan Terakhir:* _"${sanitizeText(String(recentChat[recentChat.length - 1].content || "")).slice(0, 120)}..."_`
        : `\n• *Sesi Percakapan:* Siap memulai sesi terisolasi baru`;
    const curTaskLine = enriched.current_task
      ? `\`${enriched.current_task.identifier || "Task"}\` — ${sanitizeText(String(enriched.current_task.title || "")).slice(0, 70)}`
      : "`Tidak ada task aktif (siap menerima instruksi)`";

    const receipt = buildExecutionReceipt({
      correlationId,
      command: "pilih",
      invokedAs: invokedCmd,
      mutated: true,
      agentId: entry.id,
      evidenceRef: TELEGRAM_STATE_FILE,
    });

    return {
      ok: true,
      command: "pilih",
      selected_agent: {
        index: entry.index,
        id: entry.id,
        paperclip_agent_id: entry.id,
        slug: entry.slug,
        handle: entry.handle,
        name: entry.name,
        department: entry.department,
        model_id: enriched.model_id || DEFAULT_LLM_MODEL,
        activation_status: enriched.activation_status,
        visual_state: enriched.visual_state,
      },
      direct_agent_mode: true,
      receipt,
      reply: [
        `✅ *Agen Aktif di Telegram Berhasil Dipilih!*`,
        ``,
        `${entry.emoji} *${entry.name}* (\`${entry.handle}\` • Agen #${entry.index})`,
        `• *Departemen:* \`${entry.department}\` • *Model:* \`${enriched.model_id || DEFAULT_LLM_MODEL}\``,
        `• *Status Aktivasi:* \`${enriched.activation_status}\` (3D/2D: \`${enriched.visual_state}\`)`,
        `• *Task Saat Ini:* ${curTaskLine}`,
        `• *Folder Target Aktif:* \`${folderStatus.active_folder || "(belum dipilih)"}\`${lastTurnSnippet}`,
        ``,
        `💬 *Mode Chat Langsung AKTIF (Tersinkron ke 3D & 2D Office):*`,
        `Seluruh pesan berikutnya di Telegram akan diarahkan eksklusif ke *${entry.name}*.`,
        `_Gunakan \`@agen <pesan>\` untuk mention sementara ke agen lain, \`/pilih\` untuk ganti agen, atau \`/lepas\` untuk kembali ke Hermes umum._`,
      ].join("\n"),
      inline_keyboard: buildSelectedAgentActionsKeyboard(entry, enriched.activation_status, tgState),
    };
  }

  if (canonicalId === "reset_sesi") {
    const isClear = /--clear|\bhapus\b|\breset\b/i.test(args) || invokedCmd === "reset_chat";
    const cleanTarget = args.replace(/--clear|\bhapus\b|\breset\b/gi, "").trim();
    const entry = cleanTarget
      ? resolveCorporateAgentEntry(cleanTarget, snap)
      : liveDirectory.find((a) => a.id === tgState.selected_agent_id || a.slug === tgState.selected_agent_slug) || liveDirectory[0];
    if (!entry) {
      return buildStructuredError({ correlationId, command: "reset_sesi", message: "Agen tidak ditemukan." });
    }
    const prevHistory = readAgentChatHistory(entry.id, 50);
    if (isClear) {
      clearAgentChatHistory(entry.id);
      return {
        ok: true,
        command: "reset_sesi",
        agent_id: entry.id,
        cleared_messages: prevHistory.length,
        receipt: buildExecutionReceipt({ correlationId, command: "reset_sesi", mutated: true, agentId: entry.id }),
        reply:
          `🧹 *Sesi Percakapan Terisolasi Direset*\n` +
          `• *Agen:* ${entry.emoji} *${entry.name}* (\`${entry.handle}\`)\n` +
          `• *Pesan Dibersihkan:* \`${prevHistory.length}\` pesan (Task Paperclip & sesi 10 agen lainnya tetap utuh tanpa kontaminasi).`,
        inline_keyboard: buildSelectedAgentActionsKeyboard(entry, "ACTIVE", tgState),
      };
    }
    const preview = prevHistory
      .slice(-4)
      .map((m) => `• *${m.role === "user" ? "Owner" : entry.name}:* ${sanitizeText(String(m.content || "")).slice(0, 110)}`);
    return {
      ok: true,
      command: "reset_sesi",
      agent_id: entry.id,
      session_message_count: prevHistory.length,
      reply: [
        `💬 *Status Sesi Percakapan Terisolasi — ${entry.emoji} ${entry.name}*`,
        `• *Agent ID:* \`${entry.id}\``,
        `• *Total Pesan Tersimpan:* \`${prevHistory.length}\` (terpisah penuh dari 10 agen lain, heartbeat, & meeting)`,
        ...(preview.length ? [``, `*Cuplikan Terakhir:*`, ...preview] : [``, `_(Belum ada riwayat percakapan)_`]),
      ].join("\n"),
      inline_keyboard: [
        [btn("🧹 Bersihkan Sesi Agen Ini", `uac:ses_clr:${entry.index}`), btn("🎯 Pilih Agen Ini", `uac:pick:${entry.index}`)],
        navFooter({ backTo: "uac:agents" }),
      ],
    };
  }

  if (canonicalId === "daftar_skill") {
    const {
      loadEnrichedAssignments,
      findAgentAssignment,
      formatTelegramAgentSkillsCard,
      formatTelegramAllSkillsSummary,
    } = require("./agent-skills-bridge");
    const cleanArg = args.trim();
    if (!cleanArg || /^(all|semua)$/i.test(cleanArg)) {
      return {
        ok: true,
        command: "daftar_skill",
        receipt: buildExecutionReceipt({ correlationId, command: "daftar_skill" }),
        reply: formatTelegramAllSkillsSummary(snap),
        inline_keyboard: [
          [btn("🛡️ Status Global Skill Gate", "uac:sk_st"), btn("👥 Pilih Agen", "uac:agents")],
          navFooter({ backTo: "uac:agents", refreshCb: "uac:sk_all" }),
        ],
      };
    }
    const agMap = loadEnrichedAssignments(snap);
    const ag = findAgentAssignment(cleanArg, agMap);
    if (!ag) {
      return buildStructuredError({
        correlationId,
        command: "daftar_skill",
        status: 404,
        message: `Agen \`${sanitizeText(cleanArg)}\` tidak ditemukan. Contoh: \`/daftar_skill ceo\`, \`/daftar_skill backend\`, \`/daftar_skill qa\`.`,
      });
    }
    const corpEntry = liveDirectory.find((c) => c.slug === ag.role_slug || c.id === ag.agent_uuid);
    return {
      ok: true,
      command: "daftar_skill",
      agent_id: ag.agent_uuid,
      skills: ag.skills,
      receipt: buildExecutionReceipt({ correlationId, command: "daftar_skill", agentId: ag.agent_uuid }),
      reply: formatTelegramAgentSkillsCard(ag),
      inline_keyboard: [
        ...(corpEntry ? [[btn(`🎯 Pilih ${corpEntry.shortLabel}`, `uac:pick:${corpEntry.index}`), btn("🔍 Inspector", `uac:info:${corpEntry.index}`)]] : []),
        [btn("🧰 Semua 11 Agen", "uac:sk_all"), btn("🛡️ Skill Status", "uac:sk_st")],
        navFooter({ backTo: "uac:agents" }),
      ],
    };
  }

  if (canonicalId === "skill_info") {
    const { formatTelegramSkillInfoCard } = require("./agent-skills-bridge");
    const parts = args.trim().split(/\s+/).filter(Boolean);
    const agQ = parts[0] || tgState.selected_agent_slug || "ceo";
    const skQ = parts.slice(1).join(" ");
    const info = formatTelegramSkillInfoCard(agQ, skQ, snap);
    if (!info.ok) {
      return buildStructuredError({ correlationId, command: "skill_info", status: 404, message: info.error });
    }
    return {
      ok: true,
      command: "skill_info",
      agent_id: info.agent.agent_uuid,
      skill: info.skill,
      receipt: buildExecutionReceipt({
        correlationId,
        command: "skill_info",
        agentId: info.agent.agent_uuid,
        evidenceRef: info.skill.pkg_id,
      }),
      reply: info.reply,
      inline_keyboard: [
        [btn("🧰 Skills Agen Ini", `uac:sk:${info.agent.handle.replace("@", "")}`), btn("🛡️ Skill Status", "uac:sk_st")],
        navFooter({ backTo: "uac:agents" }),
      ],
    };
  }

  if (canonicalId === "skill_status") {
    const { formatTelegramSkillStatusCard } = require("./agent-skills-bridge");
    const stCard = formatTelegramSkillStatusCard(snap);
    return {
      ok: true,
      command: "skill_status",
      summary: stCard.summary,
      receipt: buildExecutionReceipt({ correlationId, command: "skill_status" }),
      reply: stCard.reply,
      inline_keyboard: [
        [btn("🧰 Daftar Skills 11 Agen", "uac:sk_all"), btn("👥 Daftar Agen", "uac:agents")],
        navFooter({ backTo: "uac:home", refreshCb: "uac:sk_st" }),
      ],
    };
  }

  if (canonicalId === "info_agen") {
    const entry = args.trim()
      ? resolveCorporateAgentEntry(args.trim(), snap)
      : liveDirectory.find((a) => a.id === tgState.selected_agent_id || a.slug === tgState.selected_agent_slug) || liveDirectory[0];
    if (!entry) {
      return buildStructuredError({
        correlationId,
        command: "info_agen",
        status: 404,
        message: `Agen \`${sanitizeText(args)}\` tidak ditemukan. Gunakan nomor \`1..11\` atau \`/agen\`.`,
      });
    }
    const inspector = await buildAgentInspectorPayload(entry.id);
    const ov = inspector.overview;
    const mgr = inspector.hierarchy?.manager?.display_name || "Owner (Board)";
    const subs = (inspector.hierarchy?.subordinates || []).map((s) => s.display_name).join(", ") || "-";
    const perf = inspector.performance || {};
    const usage = inspector.budget?.usage || {};
    const tools = (ov.authorized_tools || []).slice(0, 8).join(", ") || "standard";
    const sessCount = readAgentChatHistory(entry.id, 60).length;

    return {
      ok: true,
      command: "info_agen",
      agent_id: entry.id,
      inspector,
      receipt: buildExecutionReceipt({ correlationId, command: "info_agen", agentId: entry.id }),
      reply: [
        `🔍 *3D/2D Employee Inspector — ${entry.emoji} ${ov.display_name} (${entry.handle})*`,
        `• *Agent ID:* \`${ov.paperclip_agent_id}\``,
        `• *Jabatan & Dept:* ${ov.title || ov.role} (\`${ov.department}\`)`,
        `• *Atasan:* \`${mgr}\` | *Bawahan:* \`${subs}\``,
        `• *Status:* Aktivasi=\`${ov.activation_status}\` | Koneksi=\`${inspector.health?.connectivity_state}\` | Visual=\`${inspector.health?.visual_state}\``,
        `• *Model & Runtime:* \`${ov.model_id || DEFAULT_LLM_MODEL}\` (\`${ov.adapter_type || "hermes_local"}\`)`,
        `• *Current Task:* ${ov.current_task ? `\`${ov.current_task.identifier}\` — ${sanitizeText(ov.current_task.title)}` : "`Idle / Siap ditugaskan`"}`,
        `• *Current Run:* ${ov.current_run ? `\`${String(ov.current_run.id).slice(0, 8)}\` (\`${ov.current_run.status}\`)` : "`Tidak ada run aktif`"}`,
        `• *Sesi Chat Owner:* \`${sessCount} pesan\` | *Antrean Task:* \`${(inspector.task_queue || []).length}\` | *Selesai:* \`${perf.completed_tasks || 0}\``,
        `• *Runs & Token:* \`${perf.run_count || 0} runs\` (\`${perf.succeeded_runs || 0} ok\`) • \`${formatNumber(usage.total_tokens || 0)} tokens\``,
        `• *Tools Diizinkan:* \`${tools}\``,
      ].join("\n"),
      inline_keyboard: buildSelectedAgentActionsKeyboard(entry, ov.activation_status, tgState),
    };
  }

  if (canonicalId === "chat" || canonicalId === "ke") {
    let targetEntry = null;
    let msgPart = "";

    if (canonicalId === "chat") {
      if (!args.trim()) {
        return {
          ok: false,
          status: 400,
          reply: `Gunakan: \`/chat <pesan/instruksi>\` untuk mengirim ke agen terpilih (*${tgState.selected_agent_name}*), atau \`/pilih\` untuk mengganti agen.`,
        };
      }
      targetEntry =
        liveDirectory.find((a) => a.id === tgState.selected_agent_id || a.slug === tgState.selected_agent_slug) || liveDirectory[0];
      msgPart = args.trim();
    } else {
      let agentPart = "";
      if (args.includes("|")) {
        const idx = args.indexOf("|");
        agentPart = args.slice(0, idx).trim();
        msgPart = args.slice(idx + 1).trim();
      } else if (args.includes(":")) {
        const idx = args.indexOf(":");
        if (resolveCorporateAgentEntry(args.slice(0, idx).trim(), snap)) {
          agentPart = args.slice(0, idx).trim();
          msgPart = args.slice(idx + 1).trim();
        }
      }
      if (!agentPart) {
        const tokens = args.trim().split(/\s+/);
        for (let len = Math.min(4, tokens.length - 1); len >= 1; len -= 1) {
          const cand = tokens.slice(0, len).join(" ");
          if (resolveCorporateAgentEntry(cand, snap)) {
            agentPart = cand;
            msgPart = tokens.slice(len).join(" ").trim();
            break;
          }
        }
      }
      targetEntry = resolveCorporateAgentEntry(agentPart, snap);
      if (!targetEntry || !msgPart) {
        return {
          ok: false,
          status: 400,
          reply:
            `Gunakan format: \`/ke <nomor/nama agen> | <pesan>\`\n` +
            `Contoh:\n• \`/ke cto | Analisis arsitektur folder ${defaultWorkspace}\`\n• \`/ke 3 | Periksa endpoint API autentikasi\``,
        };
      }
    }

    const liveTarget =
      (snap.agents || []).find((a) => a.paperclip_agent_id === targetEntry.id) ||
      (snap.agents || [])[0] || {
        paperclip_agent_id: targetEntry.id,
        role_slug: targetEntry.slug,
        display_name: targetEntry.name,
        title: targetEntry.name,
        department: targetEntry.department,
        department_short: targetEntry.department,
        runtime_type: "hermes_local",
        runtime_profile_reference: targetEntry.profile,
        model_id: DEFAULT_LLM_MODEL,
        activation_status: "ACTIVE",
      };
    const idemKey = payload.message_id
      ? `tg-${canonicalId}:${callerId}:${payload.message_id}`
      : `tg-${canonicalId}:${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;

    const turn = await handleEmployeeChatTurn({
      agent: liveTarget,
      snapshot: snap,
      rawMessage: msgPart,
      idempotencyKey: idemKey,
      createTaskFn: handleCreateTaskAction,
      sync,
      paperclip,
      callerId,
    });

    const receipt = buildExecutionReceipt({
      correlationId,
      command: canonicalId,
      invokedAs: invokedCmd,
      mutated: true,
      taskId: turn.createdTask?.identifier || turn.createdTask?.id || null,
      meetingId: turn.createdMeeting?.meeting_id || null,
      agentId: targetEntry.id,
      targetWorkspace: turn.inspectedTarget || null,
    });

    const taskBadge = turn.createdTask
      ? `\n\n📌 *Paperclip Task:* \`${turn.createdTask.identifier || String(turn.createdTask.id).slice(0, 8)}\` (\`${turn.createdTask.status}\`)`
      : "";
    const mtgBadge = turn.createdMeeting
      ? `\n🤝 *Meeting 3D/2D Aktif:* \`${(turn.createdMeeting.participants || []).length} agen berkumpul\``
      : "";

    return {
      ok: true,
      command: canonicalId,
      agent_id: targetEntry.id,
      agent_name: targetEntry.name,
      created_task: turn.createdTask || null,
      created_meeting: turn.createdMeeting || null,
      receipt,
      reply: `${targetEntry.emoji} *[${targetEntry.name} — ${targetEntry.department}]*\n\n${turn.text}${taskBadge}${mtgBadge}`,
      inline_keyboard: buildSelectedAgentActionsKeyboard(
        targetEntry,
        liveTarget?.activation_status || "ACTIVE",
        tgState
      ),
    };
  }

  // ===========================================================================
  // PHASE 06 — LIFECYCLE, DISPATCH GATE & CEO MULTI-AGENT DELEGATION
  // ===========================================================================
  if (canonicalId === "pause_dispatch") {
    const wantResume = invokedCmd === "resume_dispatch" || /^resume|buka|on|false$/i.test(args.trim());
    const st = setDispatchPaused(!wantResume, `Diubah oleh Owner via Telegram (${invokedCmd})`);
    return {
      ok: true,
      command: "pause_dispatch",
      dispatch: st,
      receipt: buildExecutionReceipt({ correlationId, command: "pause_dispatch", mutated: true }),
      reply: st.dispatch_paused
        ? `⏸️ *Pengiriman Task Baru Ditahan (\`dispatch_paused = true\`)*\nPekerjaan yang sedang berjalan tidak dihentikan, namun delegasi baru ditahan sementara hingga dibuka kembali.`
        : `▶️ *Pengiriman Task Baru Dibuka Kembali (\`dispatch_paused = false\`)*\nSeluruh agen siap menerima delegasi baru.`,
      inline_keyboard: buildSubmenuView("ceo", { tgState, snap, folderStatus, activeMeeting, dispatchPaused: st.dispatch_paused }).inline_keyboard,
    };
  }

  if (canonicalId === "delegasi") {
    const ext = extractTargetProjectPath(args, { returnAttemptInfo: true });
    const targetFolder = ext.resolved || folderStatus.active_folder || null;
    const idemKey = payload.message_id ? `tg-del:${callerId}:${payload.message_id}` : null;

    const delRes = await orchestrateCeoMultiAgentDelegation({
      instruction: args,
      targetPath: targetFolder,
      sync,
      paperclip,
      handleCreateTaskAction,
      directory: liveDirectory,
      callerId,
      idempotencyKey: idemKey,
    });
    if (!delRes.ok) {
      return buildStructuredError({
        correlationId,
        command: "delegasi",
        code: delRes.code || "DELEGATION_ERROR",
        status: delRes.status || 400,
        message: delRes.error,
      });
    }

    if (delRes.code_audit?.report_path) {
      tgState.last_analysis_report = delRes.code_audit.report_path;
      saveTelegramControlState(tgState);
    }

    await emitActivityNotification({
      eventType: "task.created",
      severity: "INFO",
      dedupeKey: `ceo_del:${delRes.parent_task.id}`,
      title: `CEO Delegation ${delRes.parent_task.identifier}`,
      detail: `${delRes.subtasks.length} subtasks created`,
      deliverToTelegram: false,
    });

    const receipt = buildExecutionReceipt({
      correlationId,
      command: "delegasi",
      invokedAs: invokedCmd,
      mutated: true,
      taskId: delRes.parent_task.identifier,
      agentId: liveDirectory[0].id,
      targetWorkspace: delRes.code_audit?.verified_path || targetFolder,
      evidenceRef: delRes.code_audit?.report_path || delRes.parent_task.id,
    });

    return {
      ok: true,
      command: "delegasi",
      delegation: delRes,
      receipt,
      reply: [
        `👔 *CEO Multi-Agent Delegation Berhasil Dieksekusi!*${delRes.deduplicated ? " _(idempotent)_" : ""}`,
        delRes.project ? `• *Project Paperclip:* \`${delRes.project.name}\` (\`${String(delRes.project.id).slice(0, 8)}\`)` : null,
        `• *Parent Task CEO:* \`${delRes.parent_task.identifier}\` — ${sanitizeText(delRes.parent_task.title)}`,
        delRes.awakened_agents.length
          ? `• *Agen Dibangunkan dari Standby:* ${delRes.awakened_agents.map((n) => `\`${n}\``).join(", ")}`
          : `• *Status Agen:* Seluruh spesialis sudah \`ACTIVE\``,
        ``,
        `📋 *Subtasks Terverifikasi (Read-After-Write):*`,
        ...delRes.subtasks.map(
          (s) => `• \`${s.identifier}\` → *${s.agent_name}* (\`${s.handle}\`) [\`${s.status}\`]`
        ),
        delRes.code_audit?.report_path ? `\n📄 *Laporan Bukti Analisis:* \`${delRes.code_audit.report_path}\`` : null,
      ]
        .filter(Boolean)
        .join("\n"),
      inline_keyboard: [
        [btn("🗣 Rapat 11 Agen Bahas Hasil Ini", "uac:meet_active_folder")],
        [btn("📋 Lihat Kanban Paperclip", "uac:tasks:all:1"), btn("🏠 Home", "uac:home")],
      ],
    };
  }

  if (canonicalId === "bangunkan") {
    const clean = args.replace(/--heartbeat/gi, "").trim();
    const triggerHeartbeat = /--heartbeat/i.test(args);
    if (/^(semua|all|11|seluruh(\s+agen)?)$/i.test(clean)) {
      const resumed = [];
      for (const ag of snap.agents || []) {
        if (ag.raw_status === "paused" || ag.activation_status !== "ACTIVE") {
          await paperclip.resumeAgent(ag.paperclip_agent_id).catch(() => {});
          resumed.push(ag.display_name);
        }
      }
      await sync.reconcileNow("telegram_wake_all_11");
      const afterSnap = sync.getFullSnapshot();
      const activeNow = (afterSnap.agents || []).filter((a) => a.activation_status === "ACTIVE").length;
      return {
        ok: true,
        command: "bangunkan_semua",
        resumed_agents: resumed,
        active_count: activeNow,
        receipt: buildExecutionReceipt({ correlationId, command: "bangunkan", mutated: true }),
        reply:
          `⚡ *Seluruh Karyawan AI Diaktifkan!*\n` +
          `• *Status Organisasi:* \`${activeNow}/11 ACTIVE\`\n` +
          `• *Agen Dibangunkan dari Standby:* ${resumed.length ? resumed.map((n) => `\`${n}\``).join(", ") : "`Semua sudah ACTIVE`"}\n` +
          `_Ketik \`/standar_wave1\` kapan saja untuk mengembalikan 7 agen Wave-2 ke mode hemat Standby._`,
        inline_keyboard: buildAgentSelectorKeyboard(enrichDirectoryWithSnapshot(afterSnap, tgState), tgState),
      };
    }

    const entry = clean
      ? resolveCorporateAgentEntry(clean, snap)
      : liveDirectory.find((a) => a.id === tgState.selected_agent_id || a.slug === tgState.selected_agent_slug);
    if (!entry) {
      return {
        ok: false,
        status: 400,
        reply: `Gunakan: \`/bangunkan <1..11|nama|semua>\` (contoh: \`/bangunkan cto\` atau \`/bangunkan semua\`).`,
      };
    }
    await paperclip.resumeAgent(entry.id);
    let wakeRes = null;
    if (triggerHeartbeat) {
      wakeRes = await paperclip
        .wakeAgent(entry.id, "telegram_owner_manual_wake", { origin: "telegram_owner" })
        .catch((e) => ({ warning: sanitizeText(e.message) }));
    }
    await sync.reconcileNow("telegram_agent_wake");
    await emitActivityNotification({
      eventType: "agent.awakened",
      severity: "INFO",
      dedupeKey: `wake:${entry.id}:${Math.floor(Date.now() / 15000)}`,
      title: `${entry.name} Awakened`,
      detail: "Activated via Telegram",
    });
    return {
      ok: true,
      command: "bangunkan",
      agent_id: entry.id,
      agent_name: entry.name,
      wake: wakeRes,
      receipt: buildExecutionReceipt({ correlationId, command: "bangunkan", mutated: true, agentId: entry.id }),
      reply:
        `▶️ *${entry.emoji} ${entry.name}* berhasil diaktifkan (\`ACTIVE\`)` +
        (triggerHeartbeat ? ` dan sinyal heartbeat dikirim!` : ` dan siap menerima penugasan!`),
      inline_keyboard: buildSelectedAgentActionsKeyboard(entry, "ACTIVE", tgState),
    };
  }

  if (canonicalId === "istirahatkan") {
    const entry = args.trim()
      ? resolveCorporateAgentEntry(args.trim(), snap)
      : liveDirectory.find((a) => a.id === tgState.selected_agent_id || a.slug === tgState.selected_agent_slug);
    if (!entry) {
      return {
        ok: false,
        status: 400,
        reply: `Gunakan: \`/istirahatkan <1..11|nama>\` (contoh: \`/istirahatkan cto\`).`,
      };
    }
    await paperclip.pauseAgent(entry.id);
    await sync.reconcileNow("telegram_agent_pause");
    return {
      ok: true,
      command: "istirahatkan",
      agent_id: entry.id,
      agent_name: entry.name,
      receipt: buildExecutionReceipt({ correlationId, command: "istirahatkan", mutated: true, agentId: entry.id }),
      reply: `⏸️ *${entry.emoji} ${entry.name}* berhasil dipindahkan ke mode \`STANDBY\` (\`paused\`).`,
      inline_keyboard: buildSelectedAgentActionsKeyboard(entry, "STANDBY", tgState),
    };
  }

  if (canonicalId === "stop_semua") {
    if (args.trim() === "--ask") {
      return {
        ok: true,
        command: "stop_semua_confirm",
        reply:
          `⚠️ *Konfirmasi Emergency Stop*\n` +
          `Tindakan ini akan membatalkan seluruh run aktif dan memindahkan ke-11 agen ke mode \`STANDBY\`.\n` +
          `Ketuk tombol konfirmasi di bawah jika Anda yakin:`,
        inline_keyboard: [
          [btn("🛑 Ya, Hentikan Semua Sekarang", "uac:stop_all")],
          [btn("⬅️ Batal", "uac:sub:ceo"), btn("🏠 Home", "uac:home")],
        ],
      };
    }
    const pausedNames = [];
    const cancelledRuns = [];
    for (const r of snap.runs || []) {
      if (r.status === "running" || r.status === "queued") {
        await paperclip.cancelRun(r.id).catch(() => {});
        cancelledRuns.push(r.id);
      }
    }
    for (const a of snap.agents || []) {
      if (a.activation_status === "ACTIVE" || a.raw_status !== "paused") {
        await paperclip.pauseAgent(a.paperclip_agent_id).catch(() => {});
        pausedNames.push(a.display_name);
      }
    }
    await sync.reconcileNow("telegram_emergency_stop");
    return {
      ok: true,
      command: "stop_semua",
      cancelled_runs: cancelledRuns,
      paused_agents: pausedNames,
      receipt: buildExecutionReceipt({ correlationId, command: "stop_semua", mutated: true }),
      reply:
        `🛑 *EMERGENCY STOP DIEKSEKUSI TERKENDALI*\n` +
        `• *Run Dibatalkan:* \`${cancelledRuns.length}\`\n` +
        `• *Agen Dipause ke Standby:* \`${pausedNames.length}\` (${pausedNames.join(", ") || "semua sudah standby"})\n` +
        `Ketik \`/standar_wave1\` untuk menghidupkan kembali 4 agen inti Wave-1.`,
      inline_keyboard: [[btn("🔄 Pulihkan Standar Wave-1", "uac:wave1"), btn("🏠 Home", "uac:home")]],
    };
  }

  if (canonicalId === "standar_wave1") {
    const resumed = [];
    const standby = [];
    for (const a of snap.agents || []) {
      if (a.wave === 1) {
        await paperclip.resumeAgent(a.paperclip_agent_id).catch(() => {});
        resumed.push(a.display_name);
      } else {
        if (a.raw_status !== "paused") {
          await paperclip.pauseAgent(a.paperclip_agent_id).catch(() => {});
        }
        standby.push(a.display_name);
      }
    }
    setDispatchPaused(false, "Restored standard Wave-1");
    await sync.reconcileNow("telegram_resume_wave1");
    return {
      ok: true,
      command: "standar_wave1",
      resumed_wave1: resumed,
      standby_wave2: standby,
      receipt: buildExecutionReceipt({ correlationId, command: "standar_wave1", mutated: true }),
      reply:
        `🔄 *Formasi Standar Wave-1 Dipulihkan!*\n` +
        `• *Wave-1 ACTIVE (4 Agen):* ${resumed.map((n) => `\`${n}\``).join(", ")}\n` +
        `• *Wave-2 STANDBY (7 Agen):* Siap aktif otomatis saat diberi tugas.`,
      inline_keyboard: buildCodexeHomeKeyboard(tgState, Boolean(activeMeeting)),
    };
  }

  // ===========================================================================
  // PHASE 07 — 3D & 2D OFFICE REMOTE CONTROL & SCREENSHOT CAPTURE
  // ===========================================================================
  if (canonicalId === "status_kantor") {
    const office = await buildOfficeRemoteStatus(sync, liveDirectory);
    const subMode = (args || invokedCmd).toLowerCase();

    if (subMode.includes("room") || subMode.includes("ruangan")) {
      const rLines = office.rooms.map(
        (r) =>
          `• *${r.name}*\n  └ 3D: \`${r.zone_3d}\` • 2D: \`${r.zone_2d}\` • Okupansi: \`${r.occupant_count}\` (${r.occupants.join(", ") || "kosong"})`
      );
      return {
        ok: true,
        command: "status_kantor",
        office,
        reply: [`🏛️ *Daftar 8 Ruangan Kantor Virtual 3D & 2D*`, ``, ...rLines].join("\n"),
        inline_keyboard: [
          [btn("📍 Posisi 11 Agen", "uac:off:locs"), btn("📸 Screenshot 3D", "uac:shot:3d")],
          navFooter({ backTo: "uac:sub:office", refreshCb: "uac:off:rooms" }),
        ],
      };
    }

    if (subMode.includes("loc") || subMode.includes("lokasi")) {
      const lLines = office.agent_locations.map(
        (a) =>
          `*${a.index}. ${a.name}* (\`${a.handle}\`) — \`${a.visual_state}\`\n  └ Ruang: *${a.room_label}* | 3D: \`(${a.coords_3d.x}, ${a.coords_3d.z})\` | 2D: \`Tile(${a.coords_2d.tileX},${a.coords_2d.tileY})\``
      );
      return {
        ok: true,
        command: "status_kantor",
        office,
        reply: [`📍 *Lokasi Live 11 Agen (3D & 2D Parity)*`, ``, ...lLines].join("\n"),
        inline_keyboard: [
          [btn("🏛️ Daftar Ruangan", "uac:off:rooms"), btn("📸 Screenshot 2D", "uac:shot:2d")],
          navFooter({ backTo: "uac:sub:office", refreshCb: "uac:off:locs" }),
        ],
      };
    }

    return {
      ok: true,
      command: "status_kantor",
      office,
      receipt: buildExecutionReceipt({ correlationId, command: "status_kantor" }),
      reply: [
        `🏢 *Status Kantor Virtual 3D & 2D*`,
        `• *HTTP Server:* \`${office.http_reachable ? "ONLINE (200)" : "OFFLINE"}\``,
        `• *Studio Auth Gate:* \`${office.studio_auth_ready ? "VERIFIED" : "CHECK TOKEN"}\``,
        `• *3D Render Engine (Three.js):* \`${office.render_3d_ready ? "READY" : "DEGRADED"}\``,
        `• *2D Pixel Engine (Phaser):* \`${office.render_2d_ready ? "READY" : "DEGRADED"}\``,
        `• *Meeting Room:* \`${office.active_meeting ? `AKTIF (${office.active_meeting.meeting_id})` : "IDLE"}\``,
        `• *Akses Perangkat:* \`${office.office_url}\``,
      ].join("\n"),
      inline_keyboard: [
        [btn("🏛️ 8 Ruangan", "uac:off:rooms"), btn("📍 Lokasi 11 Agen", "uac:off:locs")],
        [btn("📸 Kirim Screenshot 3D", "uac:shot:3d"), btn("📸 Kirim Screenshot 2D", "uac:shot:2d")],
        navFooter({ backTo: "uac:home", refreshCb: "uac:off:render" }),
      ],
    };
  }

  if (canonicalId === "screenshot_kantor") {
    const mode = /2d/i.test(args) ? "2d" : "3d";
    const shot = await captureOfficeScreenshot(mode);
    if (!shot.ok) {
      return buildStructuredError({
        correlationId,
        command: "screenshot_kantor",
        status: 500,
        message: shot.error || "Gagal menangkap layar Virtual Office.",
      });
    }
    return {
      ok: true,
      command: "screenshot_kantor",
      mode: shot.mode,
      photo_path: shot.photo_path,
      size_bytes: shot.size_bytes,
      receipt: buildExecutionReceipt({
        correlationId,
        command: "screenshot_kantor",
        evidenceRef: shot.photo_path,
      }),
      reply:
        `📸 *Tangkapan Layar ${shot.mode.toUpperCase()} Virtual Office Berhasil Diambil!*\n` +
        `• *Mode Render:* \`${shot.mode.toUpperCase()}\`\n` +
        `• *Ukuran Berkas:* \`${Math.round(shot.size_bytes / 1024)} KB\`\n` +
        `• *Meeting Aktif:* \`${activeMeeting ? activeMeeting.meeting_id : "Workstation Mode"}\``,
      inline_keyboard: [
        [btn("📸 Screenshot 3D", "uac:shot:3d"), btn("📸 Screenshot 2D", "uac:shot:2d")],
        navFooter({ backTo: "uac:sub:office" }),
      ],
    };
  }

  // ===========================================================================
  // PHASE 08 — FULL 10-STATE 11-AGENT MEETING LIFECYCLE
  // ===========================================================================
  if (canonicalId === "meeting_menu") {
    return executeTelegramControlCommand(ctx, { ...payload, command: "submenu", args: "meeting" });
  }

  if (canonicalId === "meeting") {
    const topicRaw = args.trim() || "Rapat Koordinasi Seluruh 11 Agen Eksekutif & Engineering";
    const extracted = extractTargetProjectPath(topicRaw, { returnAttemptInfo: true });
    const targetPath = extracted.resolved || folderStatus.active_folder || null;
    let folderSummaryNote = "";
    let agendaBody = sanitizeText(topicRaw);

    if (targetPath) {
      const vPath = validateSecureFolderOrFile(targetPath, { allowFile: false });
      if (vPath.ok) {
        mutateTargetFolders({ action: "select", path: vPath.fs_path });
        const deep = inspectLocalTargetDeep(vPath.fs_path);
        if (deep.ok) {
          const stackStr = Array.isArray(deep.stack) ? deep.stack.join(", ") : "Project";
          const topDirs = (deep.directories || []).slice(0, 8).join(", ") || "(root)";
          folderSummaryNote = `\n• *Konteks Proyek:* \`${vPath.resolved_path}\` (${stackStr})`;
          agendaBody = `${sanitizeText(topicRaw)}\nTarget Folder: ${vPath.resolved_path} (${stackStr}; Subfolder: ${topDirs})`;
        }
      }
    }

    let invitedIds = null;
    if (!/\b(semua|seluruh|11|kesebelas|all)\b/i.test(topicRaw)) {
      const specific = liveDirectory
        .filter(
          (d) =>
            topicRaw.toLowerCase().includes(d.handle.toLowerCase()) ||
            topicRaw.toLowerCase().includes(d.name.toLowerCase())
        )
        .map((d) => d.id);
      if (specific.length >= 2) invitedIds = specific;
    }

    const titleClean = targetPath
      ? `Rapat Koordinasi & Review: ${path.basename(targetPath)}`
      : sanitizeText(topicRaw).slice(0, 90);

    const idemKey = payload.message_id ? `tg-mtg:${callerId}:${payload.message_id}` : null;
    const started = await startFullLifecycleMeeting({
      sync,
      directory: liveDirectory,
      title: titleClean,
      agenda: agendaBody,
      targetPath,
      participantAgentIds: invitedIds,
      idempotencyKey: idemKey,
    });
    const meeting = started.meeting;

    if (/\b(diskusikan|bahas|membahas)\b/i.test(topicRaw)) {
      await conductMeetingDiscussion({
        sync,
        paperclip,
        directory: liveDirectory,
        inspectLocalTargetDeep,
        questionOrTopic: topicRaw,
      });
    }

    tgState.last_command = "meeting";
    saveTelegramControlState(tgState);

    await emitActivityNotification({
      eventType: "meeting.started",
      severity: "INFO",
      dedupeKey: `mtg_start:${meeting.meeting_id}`,
      title: `Meeting Dimulai (${meeting.meeting_id})`,
      detail: `${meeting.invited_count}/11 agen di Ruang Meeting`,
    });

    return {
      ok: true,
      command: "meeting",
      deduplicated: started.deduplicated,
      meeting,
      target_path: targetPath,
      receipt: buildExecutionReceipt({
        correlationId,
        command: "meeting",
        mutated: true,
        meetingId: meeting.meeting_id,
        taskId: meeting.paperclip_identifier,
        targetWorkspace: targetPath,
      }),
      reply:
        `🤝 *Rapat Kantor Virtual 3D & 2D Dimulai!*${started.deduplicated ? " _(idempotent)_" : ""}\n` +
        `• *Meeting ID Unik:* \`${meeting.meeting_id}\` (Paperclip \`${meeting.paperclip_identifier}\`)\n` +
        `• *Lifecycle State:* \`${meeting.lifecycle_state}\` (\`${meeting.transition_history.map((t) => t.state).join(" → ")}\`)\n` +
        `• *Kehadiran:* \`${meeting.arrived_3d_count}/${meeting.invited_count} Arrived (3D)\` • \`${meeting.arrived_2d_count}/${meeting.invited_count} Arrived (2D)\`${folderSummaryNote}\n\n` +
        `_Gunakan tombol di bawah untuk menjalankan diskusi Bahasa Indonesia, membuat notulen & action items, atau menutup rapat._`,
      inline_keyboard: [
        [btn("💬 Diskusi Bahasa Indonesia", "uac:meet:discuss"), btn("📝 Buat Notulen", "uac:meet:minutes")],
        [btn("📋 Buat Task Tindak Lanjut", "uac:meet:minutes:tasks"), btn("🏁 Selesaikan Rapat", "uac:meet_end")],
        navFooter({ backTo: "uac:sub:meeting" }),
      ],
    };
  }

  if (canonicalId === "status_meeting") {
    if (!activeMeeting) {
      return {
        ok: true,
        command: "status_meeting",
        active_meeting: null,
        reply: `ℹ️ Saat ini tidak ada rapat aktif (\`IDLE\`). Ketik \`/meeting <topik>\` untuk mengumpulkan 11 agen.`,
        inline_keyboard: [[btn("🗣 Mulai Meeting 11 Agen", "uac:meet_all"), btn("🏠 Home", "uac:home")]],
      };
    }
    const qLines = (activeMeeting.speaking_queue || [])
      .slice(0, 11)
      .map((q, i) => `${i + 1}. *${q.name}* (\`${q.handle}\`) — \`${q.status}\``);
    return {
      ok: true,
      command: "status_meeting",
      active_meeting: activeMeeting,
      reply: [
        `🗣 *Status Lifecycle Rapat Aktif — \`${activeMeeting.meeting_id}\`*`,
        `• *Judul:* ${sanitizeText(activeMeeting.title)}`,
        `• *State:* \`${activeMeeting.lifecycle_state || activeMeeting.status}\``,
        `• *Peserta Hadir:* \`${(activeMeeting.participants || []).length}/11 Agen\` (3D & 2D tersinkron)`,
        `• *Pernyataan Tercatat:* \`${(activeMeeting.transcript || []).length}\``,
        ``,
        `*Antrean Bicara:*`,
        ...qLines,
      ].join("\n"),
      inline_keyboard: [
        [btn("💬 Lanjutkan Diskusi", "uac:meet:discuss"), btn("📝 Notulen", "uac:meet:minutes")],
        navFooter({ backTo: "uac:sub:meeting", refreshCb: "uac:meet:status" }),
      ],
    };
  }

  if (canonicalId === "diskusi_rapat") {
    let targetAg = null;
    let question = args;
    if (args.includes("|")) {
      const [aPart, qPart] = args.split("|", 2);
      const foundAg = resolveCorporateAgentEntry(aPart.trim(), snap);
      if (foundAg) {
        targetAg = foundAg;
        question = qPart.trim();
      }
    }
    const disc = await conductMeetingDiscussion({
      sync,
      paperclip,
      directory: liveDirectory,
      inspectLocalTargetDeep,
      targetAgentEntry: targetAg,
      questionOrTopic: question,
    });
    if (!disc.ok) {
      return buildStructuredError({ correlationId, command: "diskusi_rapat", message: disc.error });
    }
    const turnLines = disc.turns.map((t) => `• *${t.name}* (\`${t.handle}\`): ${t.statement}`);
    return {
      ok: true,
      command: "diskusi_rapat",
      meeting_id: disc.meeting.meeting_id,
      turns: disc.turns,
      receipt: buildExecutionReceipt({ correlationId, command: "diskusi_rapat", mutated: true, meetingId: disc.meeting.meeting_id }),
      reply: [
        `💬 *Diskusi Ruang Meeting (\`${disc.meeting.meeting_id}\`)*`,
        `• *State:* \`${disc.meeting.lifecycle_state}\``,
        ``,
        ...turnLines,
      ].join("\n"),
      inline_keyboard: [
        [btn("📝 Buat Notulen & Action Items", "uac:meet:minutes"), btn("🏁 Selesaikan Rapat", "uac:meet_end")],
        navFooter({ backTo: "uac:sub:meeting" }),
      ],
    };
  }

  if (canonicalId === "notulen") {
    if (invokedCmd === "riwayat_meeting" || /^history|riwayat$/i.test(args.trim())) {
      const hist = loadMeetingsV2().slice(-8).reverse();
      const lines = hist.map(
        (m) =>
          `• \`${m.meeting_id}\` [\`${m.lifecycle_state}\`] — ${sanitizeText(m.title)} (\`${m.invited_count || 11} agen\`, \`${(m.transcript || []).length} diskusi\`)`
      );
      return {
        ok: true,
        command: "riwayat_meeting",
        count: hist.length,
        history: hist,
        reply: [
          `📜 *Riwayat Sesi Meeting Terisolasi (${hist.length})*`,
          ...(lines.length ? lines : ["• _(Belum ada riwayat meeting)_"]),
        ].join("\n"),
        inline_keyboard: [navFooter({ backTo: "uac:sub:meeting" })],
      };
    }

    const createTasks = /--tasks|tindak_lanjut/i.test(args) || invokedCmd === "tindak_lanjut_rapat";
    const sumRes = await summarizeOrConcludeMeeting({
      sync,
      paperclip,
      handleCreateTaskAction,
      directory: liveDirectory,
      callerId,
      mode: "summarize",
      createFollowupTasks: createTasks,
    });
    if (!sumRes.ok) {
      const lastDone = loadMeetingsV2().filter((m) => m.minutes).pop();
      if (lastDone) {
        return {
          ok: true,
          command: "notulen",
          minutes: lastDone.minutes,
          reply: [
            `📝 *Notulen Rapat Terakhir — \`${lastDone.meeting_id}\`*`,
            `• *Judul:* ${lastDone.title}`,
            `• *Keputusan:*`,
            ...lastDone.minutes.decisions.map((d) => `  - ${d}`),
            `• *Action Items:*`,
            ...lastDone.minutes.action_items.map((a) => `  - *${a.owner_name}:* ${a.title}`),
          ].join("\n"),
          inline_keyboard: [navFooter({ backTo: "uac:sub:meeting" })],
        };
      }
      return buildStructuredError({ correlationId, command: "notulen", message: sumRes.error });
    }
    const min = sumRes.meeting.minutes;
    return {
      ok: true,
      command: "notulen",
      meeting_id: sumRes.meeting.meeting_id,
      minutes: min,
      created_followups: sumRes.created_followups,
      receipt: buildExecutionReceipt({ correlationId, command: "notulen", mutated: true, meetingId: sumRes.meeting.meeting_id }),
      reply: [
        `📝 *Notulen & Action Items — \`${sumRes.meeting.meeting_id}\`*`,
        `• *Judul:* ${min.title}`,
        `• *Peserta:* \`${min.attendees_count}/11 Agen\` | *Pernyataan Diskusi:* \`${min.spoken_count}\``,
        ``,
        `*Keputusan Rapat:*`,
        ...min.decisions.map((d) => `• ${d}`),
        ``,
        `*Action Items:*`,
        ...min.action_items.map((a) => `• *${a.owner_name}:* ${a.title}`),
        ...(sumRes.created_followups.length
          ? [``, `📌 *Follow-up Task Paperclip Dibuat:* ${sumRes.created_followups.map((x) => `\`${x}\``).join(", ")}`]
          : []),
      ].join("\n"),
      inline_keyboard: [
        [btn("📋 Buat Task dari Action Items", "uac:meet:minutes:tasks"), btn("🏁 Selesaikan Rapat", "uac:meet_end")],
        navFooter({ backTo: "uac:sub:meeting" }),
      ],
    };
  }

  if (canonicalId === "selesai_meeting") {
    const isCancel = invokedCmd === "batal_meeting" || /^--cancel\b/i.test(args);
    const cleanNote = args.replace(/^--cancel\s*/i, "").trim();
    const ended = await summarizeOrConcludeMeeting({
      sync,
      paperclip,
      handleCreateTaskAction,
      directory: liveDirectory,
      callerId,
      mode: isCancel ? "cancel" : "complete",
      note: cleanNote,
    });

    if (ended.already_idle) {
      return {
        ok: true,
        command: "selesai_meeting",
        already_idle: true,
        reply: `ℹ️ Saat ini tidak ada sesi rapat aktif di Ruang Meeting 3D/2D. Seluruh agen berada di workstation departemen masing-masing.`,
        inline_keyboard: buildCodexeHomeKeyboard(tgState, false),
      };
    }

    tgState.last_command = "selesai_meeting";
    saveTelegramControlState(tgState);
    return {
      ok: true,
      command: "selesai_meeting",
      meeting: ended.meeting,
      receipt: buildExecutionReceipt({
        correlationId,
        command: "selesai_meeting",
        mutated: true,
        meetingId: ended.meeting.meeting_id,
      }),
      reply:
        `🏁 *Rapat Kantor Virtual ${isCancel ? "Dibatalkan" : "Selesai"}!*\n` +
        `• *Meeting ID:* \`${ended.meeting.meeting_id}\` (\`${ended.meeting.lifecycle_state}\`)\n` +
        `• *Status 3D & 2D:* Seluruh **11 avatar agen** kini kembali ke meja kerja departemen masing-masing.`,
      inline_keyboard: buildCodexeHomeKeyboard(tgState, false),
    };
  }

  // ===========================================================================
  // PHASES 09 & 10 — SAFE WORKSPACE EXPLORER & REAL SOURCE CODE ANALYSIS
  // ===========================================================================
  if (canonicalId === "folder") {
    if (args.trim()) {
      const subParts = args.trim().split(/\s+/);
      const first = subParts[0].toLowerCase();
      if (first === "browse" || first === "jelajah") {
        return executeTelegramControlCommand(ctx, { ...payload, command: "jelajah", args: subParts.slice(1).join(" ") });
      }
      if (first === "cari" || first === "search") {
        return executeTelegramControlCommand(ctx, { ...payload, command: "cari_folder", args: subParts.slice(1).join(" ") });
      }
      return executeTelegramControlCommand(ctx, { ...payload, command: "pilih_folder", args: args.trim() });
    }
    const kb = buildFolderControlKeyboard(tgState, folderStatus);
    saveTelegramControlState(tgState);
    const pinnedLines = (folderStatus.pinned_folders || []).slice(0, 8).map((p) => {
      const activeMark = samePath(folderStatus.active_folder, p.path) ? " 👈 *[AKTIF]*" : "";
      const stackLabel = Array.isArray(p.stack) && p.stack.length ? p.stack.join(", ") : "Folder";
      return `• \`${p.path}\` (${p.exists ? stackLabel : "tidak ditemukan"})${activeMark}`;
    });
    return {
      ok: true,
      command: "folder",
      folders: folderStatus,
      receipt: buildExecutionReceipt({ correlationId, command: "folder", targetWorkspace: folderStatus.active_folder }),
      reply: [
        `📁 *Kontrol Folder Workspace Terotorisasi*`,
        `• *Folder Aktif Saat Ini:* \`${folderStatus.active_folder || "(belum dipilih)"}\``,
        `• *Agen Analisis Aktif:* *${tgState.selected_agent_name}*`,
        ``,
        `📌 *Daftar Folder Terotorisasi:*`,
        ...(pinnedLines.length ? pinnedLines : ["• _(Belum ada folder tersimpan)_"]),
        ``,
        `💡 *Perintah:* \`/jelajah ${defaultWorkspace}\`, \`/cari_folder app\`, \`/pilih_folder <path>\`, \`/analisis\`.`,
        `_Proteksi aktif: realpath symlink check, permission check, serta blokir otomatis \`.env\` & direktori sistem/kredensial._`,
      ].join("\n"),
      inline_keyboard: kb,
    };
  }

  if (canonicalId === "jelajah") {
    let rawPath = args;
    let page = 1;
    if (args.includes("::page=")) {
      const [p, pg] = args.split("::page=");
      rawPath = p;
      page = Number(pg) || 1;
    }
    const targetPath = rawPath === "drives" ? "drives" : resolvePathOrToken(tgState, rawPath);
    const browsed = exploreDirectoryPaginated(targetPath, { page, perPage: 10 });
    if (!browsed.ok) {
      return {
        ok: false,
        status: browsed.status || 403,
        error_code: browsed.code,
        error: browsed.error,
        reply: `🛡️ *Akses Folder Ditolak / Tidak Valid:*\n\`${sanitizeText(browsed.error)}\``,
      };
    }
    const kb = buildBrowseDirectoryKeyboard(tgState, browsed);
    saveTelegramControlState(tgState);
    const dirLines = browsed.directories.map((d) => {
      const m = d.markers && d.markers.length ? ` [${d.markers.join(", ")}]` : "";
      return `• 📁 \`${d.path}\`${m}`;
    });
    const fileLines = browsed.files.slice(0, 8).map((f) => `• 📄 \`${f.name}\` (\`${Math.round(f.size_bytes / 1024)} KB\`)`);
    return {
      ok: true,
      command: "jelajah",
      browse: browsed,
      receipt: buildExecutionReceipt({ correlationId, command: "jelajah", targetWorkspace: browsed.current_path }),
      reply: [
        `📂 *Workspace Explorer:* \`${browsed.current_path || "Authorized Workspace Roots"}\` (Hal \`${browsed.page}/${browsed.total_pages}\`)`,
        ``,
        ...(dirLines.length ? [`*Subfolder (${browsed.total_directories}):*`, ...dirLines] : ["_(Tidak ada subfolder)_"]),
        ...(fileLines.length ? [``, `*Berkas (${browsed.total_files}, sensitif disembunyikan):*`, ...fileLines] : []),
      ].join("\n"),
      inline_keyboard: kb,
    };
  }

  if (canonicalId === "cari_folder") {
    if (!args.trim()) {
      return buildStructuredError({ correlationId, command: "cari_folder", message: "Gunakan: `/cari_folder <nama_folder>`." });
    }
    if (invokedCmd === "meta_folder") {
      const v = validateSecureFolderOrFile(resolvePathOrToken(tgState, args), { allowFile: true });
      if (!v.ok) {
        return buildStructuredError({ correlationId, command: "meta_folder", status: v.status, code: v.code, message: v.error });
      }
      return {
        ok: true,
        command: "meta_folder",
        metadata: v,
        reply: [
          `ℹ️ *Metadata Path Terverifikasi*`,
          `• *Resolved Path:* \`${v.resolved_path}\``,
          `• *Tipe:* \`${v.is_directory ? "Directory" : "File"}\` | *Ukuran:* \`${v.size_bytes} bytes\``,
          `• *Symlink/Reparse:* \`${v.is_symlink_or_reparse}\` | *Modified:* \`${v.mtime_iso}\``,
        ].join("\n"),
        inline_keyboard: [navFooter({ backTo: "uac:folders" })],
      };
    }
    const found = searchDirectoriesSafe(args.trim());
    if (!found.ok) {
      return buildStructuredError({ correlationId, command: "cari_folder", message: found.error });
    }
    const rows = [];
    for (const mPath of found.matches.slice(0, 8)) {
      const tok = registerShortPathToken(tgState, mPath);
      rows.push([btn(`📌 Pilih ${path.basename(mPath)}`, `uac:sel:${tok}`), btn("📂 Buka", `uac:br:${tok}:1`)]);
    }
    rows.push(navFooter({ backTo: "uac:folders" }));
    saveTelegramControlState(tgState);
    return {
      ok: true,
      command: "cari_folder",
      search: found,
      reply: [
        `🔎 *Hasil Pencarian Folder \`"${sanitizeText(args.trim())}"\` (${found.count} ditemukan)*`,
        ...(found.matches.length ? found.matches.map((m) => `• \`${m}\``) : ["• _(Tidak ada folder yang cocok)_"]),
      ].join("\n"),
      inline_keyboard: rows,
    };
  }

  if (canonicalId === "pilih_folder") {
    const targetPath = resolvePathOrToken(tgState, args);
    if (!targetPath) {
      return {
        ok: false,
        status: 400,
        reply: `Gunakan: \`/pilih_folder <path lengkap>\` (contoh: \`/pilih_folder ${defaultWorkspace}\`).`,
      };
    }
    const v = validateSecureFolderOrFile(targetPath, { allowFile: false });
    if (!v.ok) {
      return {
        ok: false,
        status: v.status || 403,
        error_code: v.code,
        error: v.error,
        reply: `🛡️ *Folder Ditolak oleh Guardrail Keamanan:*\n\`${sanitizeText(v.error)}\``,
      };
    }
    const mutated = mutateTargetFolders({ action: "select", path: v.fs_path });
    const deep = inspectLocalTargetDeep(mutated.active_folder);
    const tok = registerShortPathToken(tgState, mutated.active_folder);
    saveTelegramControlState(tgState);

    return {
      ok: true,
      command: "pilih_folder",
      active_folder: mutated.active_folder,
      inspection: deep.ok ? deep : null,
      receipt: buildExecutionReceipt({
        correlationId,
        command: "pilih_folder",
        mutated: true,
        targetWorkspace: mutated.active_folder,
      }),
      reply: [
        `✅ *Folder Target Aktif Berhasil Disetel & Diverifikasi!*`,
        `• *Path Kanonis:* \`${mutated.active_folder}\``,
        `• *Tersinkron ke:* Tombol \`📁 Folder Target\` di 3D & 2D Virtual Office`,
        ...(deep.ok
          ? [
              `• *Technology Stack:* \`${Array.isArray(deep.stack) ? deep.stack.join(", ") : "General Folder"}\``,
              `• *Struktur:* \`${(deep.directories || []).length} subfolder\` • \`${(deep.files || []).length} berkas utama\``,
            ]
          : []),
      ].join("\n"),
      inline_keyboard: [
        [btn(`🔍 Analisis Kode (${tgState.selected_agent_name.split(" ")[0]})`, `uac:anl:${tok}`)],
        [btn("🗣 Rapat 11 Agen Bahas Folder Ini", "uac:meet_active_folder")],
        navFooter({ backTo: "uac:folders" }),
      ],
    };
  }

  if (canonicalId === "analisis") {
    if (args.trim() === "--latest") {
      const latest = tgState.last_analysis_report;
      if (latest && fs.existsSync(latest)) {
        const txt = sanitizeText(fs.readFileSync(latest, "utf8")).slice(0, 3200);
        return {
          ok: true,
          command: "analisis",
          report_path: latest,
          reply: `📄 *Laporan Audit Terbaru (\`${path.basename(latest)}\`):*\n\n${txt}`,
          inline_keyboard: [navFooter({ backTo: "uac:folders" })],
        };
      }
    }

    const rawTarget = resolvePathOrToken(tgState, args);
    let targetCandidate = rawTarget;
    let customFocus = "";
    if (rawTarget && rawTarget.includes("|")) {
      const [pPart, iPart] = rawTarget.split("|", 2);
      targetCandidate = pPart.trim();
      customFocus = iPart.trim();
    }
    if (!targetCandidate) {
      targetCandidate = folderStatus.active_folder || "";
    }
    if (!targetCandidate) {
      return {
        ok: false,
        status: 400,
        reply: `⚠️ Belum ada folder target dipilih. Gunakan \`/analisis ${defaultWorkspace}\` atau \`/folder\`.`,
      };
    }

    const v = validateSecureFolderOrFile(targetCandidate, { allowFile: true });
    if (!v.ok) {
      return {
        ok: false,
        status: v.status || 403,
        error_code: v.code,
        error: v.error,
        reply: `🛡️ *Analisis Ditolak oleh Guardrail Keamanan:*\n\`${sanitizeText(v.error)}\``,
      };
    }

    const dirToSelect = v.is_directory ? v.fs_path : path.dirname(v.fs_path);
    mutateTargetFolders({ action: "select", path: dirToSelect });

    const targetEntry =
      liveDirectory.find((a) => a.id === tgState.selected_agent_id || a.slug === tgState.selected_agent_slug) ||
      liveDirectory[0];
    const analysis = performRealSourceCodeAnalysis(v.fs_path, {
      agentName: targetEntry.name,
      customFocus,
    });
    if (!analysis.ok) {
      return buildStructuredError({ correlationId, command: "analisis", status: 403, message: analysis.error });
    }

    const taskRes = await handleCreateTaskAction(
      {
        title: `[Source Code Analysis] ${analysis.project_name} (${targetEntry.name})`,
        description: `Analisis source code terverifikasi pada \`${analysis.verified_path}\`.\nLaporan tersimpan di: \`${analysis.report_path}\``,
        assignee_agent_id: targetEntry.id,
        priority: "medium",
        status: "done",
        wake_immediately: false,
        idempotency_key: payload.message_id
          ? `tg-anl:${callerId}:${payload.message_id}`
          : `tg-anl:${analysis.project_name}:${Math.floor(Date.now() / 10000)}`,
        notify_telegram: false,
      },
      callerId
    ).catch(() => null);

    tgState.last_analysis_report = analysis.report_path;
    tgState.last_command = "analisis";
    saveTelegramControlState(tgState);

    const receipt = buildExecutionReceipt({
      correlationId,
      command: "analisis",
      invokedAs: invokedCmd,
      mutated: true,
      taskId: taskRes?.task?.identifier || null,
      agentId: targetEntry.id,
      targetWorkspace: analysis.verified_path,
      evidenceRef: analysis.report_path,
    });

    return {
      ok: true,
      command: "analisis",
      target_path: analysis.verified_path,
      agent_id: targetEntry.id,
      agent_name: targetEntry.name,
      analysis,
      created_task: taskRes?.task || null,
      receipt,
      reply: [
        `📂 *Hasil Analisis Source Code Nyata — ${targetEntry.emoji} ${targetEntry.name}*`,
        `• *Path Terverifikasi:* \`${analysis.verified_path}\``,
        `• *Stack Teknologi:* \`${analysis.stack.join(", ")}\``,
        `• *Subdirektori Utama (${analysis.top_directories.length}):* ${analysis.top_directories.slice(0, 10).map((d) => `\`${d}\``).join(", ")}`,
        analysis.modules.length
          ? `• *Modul Aplikasi (${analysis.modules.length}):* ${analysis.modules.slice(0, 8).join(", ")}`
          : null,
        `• *Entry Points:* ${analysis.entry_points.map((e) => `\`${e}\``).join(", ") || "-"}`,
        `• *Dependensi:* \`${analysis.runtime_dependencies_count} runtime\` • \`${analysis.dev_dependencies_count} dev\` (${analysis.sample_dependencies.slice(0, 6).map((d) => `\`${d}\``).join(", ")})`,
        `• *Build/Test Commands:* ${analysis.build_test_commands.slice(0, 3).map((c) => `\`${c}\``).join(" | ") || "-"}`,
        ``,
        `⚠️ *Temuan & Perhatian:*`,
        ...analysis.potential_issues.map((i) => `• ${i}`),
        ``,
        `💡 *Rekomendasi:*`,
        ...analysis.recommendations.slice(0, 2).map((r) => `• ${r}`),
        ``,
        `📑 *Berkas Diperiksa (${analysis.examined_files.length}):* ${analysis.examined_files.slice(0, 6).map((f) => `\`${f.file}\` (${f.lines}L)`).join(", ")}`,
        `📄 *Laporan Tersimpan:* \`${analysis.report_path}\``,
        taskRes?.task ? `📌 *Paperclip Issue:* \`${taskRes.task.identifier}\`` : null,
      ]
        .filter(Boolean)
        .join("\n"),
      inline_keyboard: [
        [btn("🗣 Rapat 11 Agen Bahas Hasil Ini", "uac:meet_active_folder")],
        [btn("💻 Buka Menu Development", "uac:sub:dev"), btn("🏠 Home", "uac:home")],
      ],
    };
  }

  // ===========================================================================
  // PHASE 11 — SOFTWARE DEVELOPMENT CONTROL
  // ===========================================================================
  if (canonicalId === "dev") {
    const tokens = args.trim().split(/\s+/).filter(Boolean);
    const subAction = invokedCmd !== "dev" ? invokedCmd : (tokens[0] || "git_status").toLowerCase();
    const subArgs = invokedCmd !== "dev" ? args.trim() : tokens.slice(1).join(" ").replace(/--notify/gi, "").trim();
    const notifyDone = /--notify/i.test(args);

    if (subAction === "dev_task" || subAction === "review_kode") {
      const targetFolder = folderStatus.active_folder || defaultWorkspace;
      const assigneeSlug = subAction === "review_kode" ? "qa_engineer" : "backend_developer";
      const assignee = resolveCorporateAgentEntry(assigneeSlug, snap) || liveDirectory[2];
      const desc = subArgs || `Review kualitas kode & jalankan pengujian non-destruktif pada ${targetFolder}`;
      const created = await handleCreateTaskAction(
        {
          title: `[${subAction === "review_kode" ? "QA Code Review" : "Dev Task"}] ${path.basename(targetFolder)}: ${desc.slice(0, 70)}`,
          description: `Workspace: \`${targetFolder}\`\nInstruksi: ${desc}\nKebijakan: Gunakan branch terisolasi, jangan menyentuh .env.`,
          assignee_agent_id: assignee.id,
          priority: "high",
          status: "todo",
          wake_immediately: true,
          notify_telegram: notifyDone,
        },
        callerId
      );
      const testRun = await executeSafeDevOperation({ action: "jalankan_test", targetPath: targetFolder }).catch(() => null);
      return {
        ok: true,
        command: subAction,
        task: created.task,
        verification_run: testRun,
        receipt: buildExecutionReceipt({
          correlationId,
          command: subAction,
          mutated: true,
          taskId: created.task.identifier,
          agentId: assignee.id,
          targetWorkspace: targetFolder,
          exitCode: testRun ? testRun.exit_code || 0 : 0,
        }),
        reply: [
          `💻 *${subAction === "review_kode" ? "Review Kode QA" : "Development Task"} Terdaftar & Diuji!*`,
          `• *Task ID:* \`${created.task.identifier}\` → *${assignee.name}*`,
          `• *Workspace:* \`${targetFolder}\``,
          ...(testRun?.command_executed
            ? [
                `• *Command Dieksekusi:* \`${testRun.command_executed}\` (Exit Code: \`${testRun.exit_code}\`)`,
                `• *Output:* \`${String(testRun.output || "").slice(0, 300)}\``,
              ]
            : []),
        ].join("\n"),
        inline_keyboard: [navFooter({ backTo: "uac:sub:dev" })],
      };
    }

    const devRes = await executeSafeDevOperation({
      action: subAction,
      targetPath: folderStatus.active_folder,
      args: subArgs,
    });

    if (notifyDone) {
      await emitActivityNotification({
        eventType: devRes.ok ? "build.completed" : "test.failed",
        severity: devRes.ok ? "SUCCESS" : "ERROR",
        dedupeKey: `dev_op:${subAction}:${Date.now()}`,
        title: `${subAction} ${devRes.ok ? "Berhasil" : "Gagal"}`,
        detail: `${devRes.path || ""} (exit=${devRes.exit_code ?? 0})`,
        deliverToTelegram: false,
      });
    }

    if (!devRes.ok) {
      return {
        ok: false,
        status: devRes.status || 400,
        dev_result: devRes,
        reply:
          `⚠️ *Operasi Development (\`${subAction}\`) Gagal:*\n` +
          `${sanitizeText(devRes.error || "")}` +
          (devRes.output ? `\n\`\`\`\n${devRes.output.slice(0, 900)}\n\`\`\`` : ""),
        inline_keyboard: [navFooter({ backTo: "uac:sub:dev" })],
      };
    }

    const receipt = buildExecutionReceipt({
      correlationId,
      command: subAction,
      invokedAs: invokedCmd,
      mutated: subAction === "buat_branch",
      targetWorkspace: devRes.path,
      exitCode: devRes.exit_code ?? 0,
    });

    if (subAction === "git_status") {
      return {
        ok: true,
        command: "git_status",
        git: devRes,
        receipt,
        reply: devRes.is_git
          ? [
              `🌿 *Git Status — \`${devRes.path}\`*`,
              `• *Branch Aktif:* \`${devRes.branch}\``,
              `• *Berkas Berubah (${devRes.changed_files.length}):* ${devRes.changed_files.slice(0, 10).map((f) => `\`${f}\``).join(", ") || "`Working tree bersih`"}`,
              `• *Commit Terbaru:*`,
              ...devRes.recent_commits.map((c) => `  - \`${c}\``),
            ].join("\n")
          : `ℹ️ \`${devRes.path}\` bukan repositori Git.`,
        inline_keyboard: [navFooter({ backTo: "uac:sub:dev", refreshCb: "uac:dev:git" })],
      };
    }

    if (subAction === "cek_diff" || subAction === "git_diff") {
      return {
        ok: true,
        command: "cek_diff",
        diff: devRes,
        receipt,
        reply: [
          `📄 *Git Diff — \`${devRes.path}\`*`,
          `• *Stat:* \`${devRes.diff_stat}\``,
          `\`\`\`diff\n${devRes.diff_preview.slice(0, 1400)}\n\`\`\``,
        ].join("\n"),
        inline_keyboard: [navFooter({ backTo: "uac:sub:dev", refreshCb: "uac:dev:diff" })],
      };
    }

    return {
      ok: true,
      command: subAction,
      dev_result: devRes,
      receipt,
      reply: [
        `🛠️ *Eksekusi Development (\`${subAction}\`) Berhasil!*`,
        `• *Workspace:* \`${devRes.path}\``,
        devRes.branch ? `• *Branch Kerja:* \`${devRes.branch}\`` : null,
        `• *Command:* \`${devRes.command_executed}\` | *Exit Code:* \`${devRes.exit_code}\``,
        devRes.output ? `\`\`\`\n${devRes.output.slice(0, 1200)}\n\`\`\`` : null,
      ]
        .filter(Boolean)
        .join("\n"),
      inline_keyboard: [navFooter({ backTo: "uac:sub:dev" })],
    };
  }

  // ===========================================================================
  // PHASE 12 — PAPERCLIP PROJECT & KANBAN CONTROL (READ-AFTER-WRITE VERIFIED)
  // ===========================================================================
  if (canonicalId === "projects") {
    if (invokedCmd === "buat_project" || /^buat\s+/i.test(args)) {
      const nameRaw = invokedCmd === "buat_project" ? args.trim() : args.replace(/^buat\s+/i, "").trim();
      if (!nameRaw) {
        return buildStructuredError({ correlationId, command: "buat_project", message: "Gunakan: `/buat_project <nama_project>`." });
      }
      const proj = await paperclip.ensureProject(snap.company.id, nameRaw);
      saveActiveProjectSelection(proj.id, proj.name);
      await sync.reconcileNow("telegram_create_project");
      return {
        ok: true,
        command: "buat_project",
        project: proj,
        receipt: buildExecutionReceipt({ correlationId, command: "buat_project", mutated: true, evidenceRef: proj.id }),
        reply: `✅ *Project Paperclip Siap & Aktif!*\n• *Nama:* \`${sanitizeText(proj.name)}\`\n• *Project ID:* \`${proj.id}\``,
        inline_keyboard: [navFooter({ backTo: "uac:sub:paperclip" })],
      };
    }

    if (invokedCmd === "pilih_project") {
      const q = args.trim().toLowerCase();
      const found = (snap.projects || []).find(
        (p) => String(p.id).toLowerCase().startsWith(q) || String(p.name).toLowerCase().includes(q)
      );
      if (!found) {
        return buildStructuredError({ correlationId, command: "pilih_project", status: 404, message: "Project tidak ditemukan." });
      }
      saveActiveProjectSelection(found.id, found.name);
      return {
        ok: true,
        command: "pilih_project",
        project: found,
        reply: `🎯 Project aktif disetel ke: *${sanitizeText(found.name)}* (\`${String(found.id).slice(0, 8)}\`).`,
        inline_keyboard: [navFooter({ backTo: "uac:sub:paperclip" })],
      };
    }

    const activeProj = loadActiveProjectSelection();
    const projs = snap.projects || [];
    const allTasks = snap.tasks || [];
    const lines = [`📁 *Daftar Project Paperclip (${projs.length})*`];
    for (const p of projs.slice(0, 20)) {
      const pTasks = allTasks.filter((t) => t.projectId === p.id);
      const pDone = pTasks.filter((t) => t.status === "done").length;
      const pct = pTasks.length > 0 ? Math.round((pDone / pTasks.length) * 100) : 100;
      const mark = activeProj.project_id === p.id ? " 👈 *[AKTIF]*" : "";
      lines.push(
        `• *${sanitizeText(p.name)}* (\`${String(p.id).slice(0, 8)}\`) — \`${pDone}/${pTasks.length} done (${pct}%)\`${mark}`
      );
    }
    return {
      ok: true,
      command: "projects",
      count: projs.length,
      projects: projs,
      reply: lines.join("\n"),
      inline_keyboard: [navFooter({ backTo: "uac:sub:paperclip", refreshCb: "uac:pc:projects" })],
    };
  }

  if (canonicalId === "daftar_task") {
    const parts = args.trim().split(/\s+/).filter(Boolean);
    const filterKey = (parts[0] || "all").toLowerCase();
    const pageNum = Number(parts[1] || (/^\d+$/.test(filterKey) ? filterKey : 1)) || 1;
    let list = snap.tasks || [];
    if (filterKey && filterKey !== "all" && !/^\d+$/.test(filterKey)) {
      if (filterKey === "active") {
        list = list.filter((t) => ["todo", "backlog", "in_progress", "in_review"].includes(String(t.status)));
      } else {
        list = list.filter((t) => String(t.status || "").toLowerCase() === filterKey);
      }
    }
    const pg = paginateItems(list, pageNum, 10);
    const lines = [`📋 *Daftar Task Kanban Paperclip (Hal ${pg.page}/${pg.totalPages} — Total ${pg.total})*`];
    for (const it of pg.slice) {
      const ag = liveDirectory.find((a) => a.id === it.assigneeAgentId);
      const agTag = ag ? ` → ${ag.emoji} ${ag.name}` : "";
      lines.push(
        `• \`${it.identifier || String(it.id).slice(0, 8)}\` [\`${it.status}\`] — ${sanitizeText(String(it.title || "")).slice(0, 60)}${agTag}`
      );
    }
    const kb = [];
    const pRow = paginationRow({ prefix: `uac:tasks:${filterKey}`, page: pg.page, totalPages: pg.totalPages });
    if (pRow) kb.push(pRow);
    kb.push(navFooter({ backTo: "uac:sub:paperclip", refreshCb: `uac:tasks:${filterKey}:${pg.page}` }));
    return {
      ok: true,
      command: "daftar_task",
      count: list.length,
      page: pg.page,
      total_pages: pg.totalPages,
      tasks: pg.slice,
      reply: lines.join("\n"),
      inline_keyboard: kb,
    };
  }

  if (canonicalId === "cek_task") {
    const ref = args.trim();
    if (!ref) {
      return { ok: false, status: 400, reply: `Gunakan: \`/cek_task <UNI-XX atau UUID>\`.` };
    }
    const found = (snap.tasks || []).find(
      (t) =>
        String(t.identifier || "").toLowerCase() === ref.toLowerCase() ||
        String(t.id || "").toLowerCase() === ref.toLowerCase() ||
        String(t.id || "").toLowerCase().startsWith(ref.toLowerCase())
    );
    if (!found) {
      return { ok: false, status: 404, reply: `⚠️ Task \`${sanitizeText(ref)}\` tidak ditemukan.` };
    }
    const verified = await readAfterWriteVerifyIssue(paperclip, found.id);
    const issue = verified.issue;
    const comments = verified.comments;
    const subtasks = (snap.tasks || []).filter((t) => t.parentId === issue.id);
    const lastComment =
      comments.length > 0
        ? sanitizeText(String(comments[comments.length - 1].body || "")).slice(0, 320)
        : "Belum ada komentar eksekusi.";
    const assignee = liveDirectory.find((a) => a.id === issue.assigneeAgentId);

    return {
      ok: true,
      command: "cek_task",
      task: issue,
      subtasks,
      comments_count: comments.length,
      reply: [
        `🔎 *Detail Task \`${issue.identifier || String(issue.id).slice(0, 8)}\` (Read-Verified)*`,
        `• *Judul:* ${sanitizeText(issue.title || "")}`,
        `• *Status:* \`${issue.status}\` | *Prioritas:* \`${issue.priority || "medium"}\``,
        `• *Penanggung Jawab:* ${assignee ? `${assignee.emoji} *${assignee.name}* (\`${assignee.handle}\`)` : "`Unassigned`"}`,
        subtasks.length
          ? `• *Subtasks (${subtasks.length}):* ${subtasks.map((s) => `\`${s.identifier}\` [${s.status}]`).join(", ")}`
          : null,
        `• *Komentar Aktivitas (${comments.length}):* ${lastComment}`,
      ]
        .filter(Boolean)
        .join("\n"),
      inline_keyboard: [navFooter({ backTo: "uac:sub:paperclip" })],
    };
  }

  if (canonicalId === "buat_task") {
    const raw = args.trim();
    if (!raw) {
      return {
        ok: false,
        status: 400,
        reply:
          `Gunakan:\n` +
          `• \`/buat_task <judul> | <deskripsi>\` (ke agen aktif: *${tgState.selected_agent_name}*)\n` +
          `• \`/buat_task <agen> | <judul> | <deskripsi> [| priority=high]\``,
      };
    }
    const segments = raw.split("|").map((s) => s.trim()).filter(Boolean);
    let targetEntry =
      liveDirectory.find((a) => a.id === tgState.selected_agent_id || a.slug === tgState.selected_agent_slug) ||
      liveDirectory[0];
    let title = "";
    let description = "";
    let priority = "high";

    const prioIdx = segments.findIndex((s) => /^priority\s*=/i.test(s));
    if (prioIdx >= 0) {
      const pVal = segments[prioIdx].split("=")[1].trim().toLowerCase();
      if (["critical", "high", "medium", "low"].includes(pVal)) priority = pVal;
      segments.splice(prioIdx, 1);
    }

    if (segments.length >= 3) {
      const maybeAg = resolveCorporateAgentEntry(segments[0], snap);
      if (maybeAg) {
        targetEntry = maybeAg;
        title = segments[1];
        description = segments.slice(2).join(" | ");
      } else {
        title = segments[0];
        description = segments.slice(1).join(" | ");
      }
    } else if (segments.length === 2) {
      const maybeAg = resolveCorporateAgentEntry(segments[0], snap);
      if (maybeAg && segments[1].length >= 4) {
        targetEntry = maybeAg;
        title = segments[1].slice(0, 100);
        description = segments[1];
      } else {
        title = segments[0];
        description = segments[1];
      }
    } else {
      title = segments[0].slice(0, 100);
      description = segments[0];
    }

    const liveAg = (snap.agents || []).find((a) => a.paperclip_agent_id === targetEntry.id);
    let autoResumed = false;
    if (liveAg && liveAg.activation_status !== "ACTIVE") {
      await paperclip.resumeAgent(targetEntry.id).catch(() => {});
      autoResumed = true;
    }

    const activeProj = loadActiveProjectSelection();
    const idem = payload.message_id
      ? `tg-task:${callerId}:${payload.message_id}`
      : `tg-task:${crypto.createHash("sha256").update(`${targetEntry.id}:${title}:${description}`).digest("hex").slice(0, 20)}`;

    const created = await handleCreateTaskAction(
      {
        title,
        description,
        project_id: activeProj.project_id || null,
        assignee_agent_id: targetEntry.id,
        priority,
        status: "todo",
        idempotency_key: idem,
        notify_telegram: false,
      },
      callerId
    );
    const verified = await readAfterWriteVerifyIssue(paperclip, created.task.id);
    const issue = verified.issue;

    return {
      ok: true,
      command: "buat_task",
      submission: { ...created, task: issue },
      auto_resumed: autoResumed,
      read_after_write_verified: true,
      receipt: buildExecutionReceipt({
        correlationId,
        command: "buat_task",
        mutated: true,
        taskId: issue.identifier || issue.id,
        agentId: targetEntry.id,
      }),
      reply: [
        `✅ *Task Baru Berhasil Dibuat & Diverifikasi di Paperclip!*${created.deduplicated ? " _(idempotent)_" : ""}`,
        `• *Task ID:* \`${issue.identifier || String(issue.id).slice(0, 8)}\``,
        `• *Judul:* ${sanitizeText(issue.title)}`,
        `• *Penanggung Jawab:* ${targetEntry.emoji} *${targetEntry.name}*${autoResumed ? " _(otomatis diaktifkan dari Standby)_" : ""}`,
        `• *Prioritas:* \`${issue.priority}\` | *Status:* \`${issue.status}\` (Read-After-Write OK)`,
      ].join("\n"),
      inline_keyboard: [navFooter({ backTo: "uac:sub:paperclip" })],
    };
  }

  if (canonicalId === "ubah_task") {
    const tokens = args.trim().split(/\s+/).filter(Boolean);
    const ref = tokens[0] || "";
    if (!ref) {
      return { ok: false, status: 400, reply: `Gunakan: \`/${invokedCmd} <UNI-XX> [parameter]\`.` };
    }
    const found = (snap.tasks || []).find(
      (t) =>
        String(t.identifier || "").toLowerCase() === ref.toLowerCase() ||
        String(t.id || "").toLowerCase() === ref.toLowerCase() ||
        String(t.id || "").toLowerCase().startsWith(ref.toLowerCase())
    );
    if (!found) {
      return { ok: false, status: 404, reply: `⚠️ Task \`${sanitizeText(ref)}\` tidak ditemukan.` };
    }

    if (invokedCmd === "cancel_task") {
      const cancelled = await cancelTaskWithActiveRuns({
        paperclip,
        sync,
        taskId: found.id,
        note: "Cancelled gracefully by Owner via Telegram.",
      });
      return {
        ok: true,
        command: "cancel_task",
        task: cancelled.issue,
        cancelled_runs: cancelled.cancelled_runs,
        read_after_write_verified: true,
        receipt: buildExecutionReceipt({ correlationId, command: "cancel_task", mutated: true, taskId: cancelled.issue.identifier }),
        reply:
          `🛑 Task \`${cancelled.issue.identifier || String(found.id).slice(0, 8)}\` dibatalkan (\`cancelled\`)` +
          ` beserta \`${cancelled.cancelled_runs.length}\` run aktif.`,
      };
    }

    if (invokedCmd === "assign_task") {
      const ag = resolveCorporateAgentEntry(tokens.slice(1).join(" "), snap);
      if (!ag) return buildStructuredError({ correlationId, command: "assign_task", message: "Agen tujuan tidak valid." });
      await paperclip.updateTask(found.id, { assigneeAgentId: ag.id });
      const verified = await readAfterWriteVerifyIssue(paperclip, found.id, (i) => i.assigneeAgentId === ag.id);
      await sync.reconcileNow("telegram_assign_task");
      return {
        ok: true,
        command: "assign_task",
        task: verified.issue,
        read_after_write_verified: true,
        reply: `✅ Task \`${verified.issue.identifier}\` ditugaskan ulang ke *${ag.name}* (\`${ag.handle}\`).`,
      };
    }

    if (invokedCmd === "prioritas_task") {
      const prio = (tokens[1] || "").toLowerCase();
      if (!["critical", "high", "medium", "low"].includes(prio)) {
        return buildStructuredError({ correlationId, command: "prioritas_task", message: "Prioritas harus critical|high|medium|low." });
      }
      await paperclip.updateTask(found.id, { priority: prio });
      const verified = await readAfterWriteVerifyIssue(paperclip, found.id, (i) => i.priority === prio);
      await sync.reconcileNow("telegram_prio_task");
      return {
        ok: true,
        command: "prioritas_task",
        task: verified.issue,
        read_after_write_verified: true,
        reply: `✅ Prioritas task \`${verified.issue.identifier}\` diubah ke \`${prio}\`.`,
      };
    }

    const statusMap = {
      pause_task: "blocked",
      resume_task: "todo",
      selesai_task: "done",
      done_task: "done",
    };
    const nextStatus =
      statusMap[invokedCmd] || (["todo", "in_progress", "blocked", "done"].includes(tokens[1]) ? tokens[1] : "done");
    const patchBody = {
      status: nextStatus,
      unblockDescriptor:
        nextStatus === "blocked"
          ? { owner: "board", action: `Paused by Owner (${callerId}) via Telegram remote control.` }
          : null,
    };
    if (nextStatus === "done" || nextStatus === "blocked") {
      const preDet = await paperclip.getTaskDetail(found.id).catch(() => null);
      let hadLiveRun = false;
      for (const lr of preDet?.liveRuns || []) {
        if (lr && lr.id && (lr.status === "running" || lr.status === "queued")) {
          await paperclip.cancelRun(lr.id).catch(() => {});
          hadLiveRun = true;
        }
      }
      if (hadLiveRun) {
        await new Promise((r) => setTimeout(r, 450));
      }
    }
    if (nextStatus !== "done" && nextStatus !== "blocked") {
      await paperclip
        .addTaskComment(found.id, `Status diubah menjadi '${nextStatus}' oleh Owner melalui kontrol Telegram.`)
        .catch(() => {});
    }
    for (let attempt = 0; attempt < 4; attempt += 1) {
      await paperclip.updateTask(found.id, patchBody).catch(async (err) => {
        if (attempt < 3) {
          await new Promise((r) => setTimeout(r, 600));
          return null;
        }
        throw err;
      });
      const checkDet = await paperclip.getTaskDetail(found.id).catch(() => null);
      if (checkDet?.issue?.status === nextStatus) break;
      for (const lr of checkDet?.liveRuns || []) {
        if (lr && lr.id && (lr.status === "running" || lr.status === "queued")) {
          await paperclip.cancelRun(lr.id).catch(() => {});
        }
      }
      await new Promise((r) => setTimeout(r, 600));
    }
    const verified = await readAfterWriteVerifyIssue(paperclip, found.id, (i) => i.status === nextStatus);
    await sync.reconcileNow(`telegram_${invokedCmd}`);
    return {
      ok: true,
      command: invokedCmd,
      task: verified.issue,
      read_after_write_verified: true,
      receipt: buildExecutionReceipt({ correlationId, command: invokedCmd, mutated: true, taskId: verified.issue.identifier }),
      reply: `✅ Task \`${verified.issue.identifier || String(found.id).slice(0, 8)}\` berhasil diperbarui & diverifikasi ke status \`${nextStatus}\`.`,
    };
  }

  // ===========================================================================
  // PHASES 13 & 14 — ANALYTICS & GOVERNED BUDGET MANAGEMENT
  // ===========================================================================
  if (canonicalId === "analytics") {
    const parts = args.trim().split(/\s+/).filter(Boolean);
    const p0 = (parts[0] || "30d").toLowerCase();
    const pageNum = Number(parts[1] || 1) || 1;
    const isSubView = ["agents", "models", "cost", "runs", "history"].includes(p0);
    const windowArg = isSubView ? "30d" : p0;
    const viewArg = isSubView ? p0 : "summary";

    const report = await buildTelegramAnalyticsReport({
      snap,
      paperclip,
      directory: liveDirectory,
      windowArg,
      viewArg,
      page: pageNum,
    });
    const m = report.metrics;
    const c = report.cost_transparency;

    let replyLines = [];
    const kb = [];

    if (viewArg === "agents") {
      const pg = paginateItems(report.per_agent, pageNum, 6);
      replyLines = [
        `👥 *Analytics Per-Agen (${report.window.label} — Hal ${pg.page}/${pg.totalPages})*`,
        ...pg.slice.map(
          (a) =>
            `*${a.index}. ${a.name}* (\`${a.handle}\`)\n  └ \`${formatNumber(a.tokens)} tok\` • Est \`${formatUsd(a.estimated_cost_usd)}\` • \`${a.runs} runs\` • \`${a.tool_calls} tools\``
        ),
      ];
      const pRow = paginationRow({ prefix: "uac:anx:agents", page: pg.page, totalPages: pg.totalPages });
      if (pRow) kb.push(pRow);
    } else if (viewArg === "models") {
      replyLines = [
        `🤖 *Analytics Per Model & Provider (${report.window.label})*`,
        ...report.per_model.map(
          (x) => `• *${x.model_provider}:* \`${formatNumber(x.tokens)} tok\` • Est \`${formatUsd(x.estimated_cost_usd)}\` • \`${x.sessions} sesi\``
        ),
      ];
    } else if (viewArg === "runs") {
      const pg = paginateItems(report.recent_runs, pageNum, 8);
      replyLines = [
        `⚡ *Riwayat Eksekusi Runs (Hal ${pg.page}/${pg.totalPages} — Total ${pg.total})*`,
        ...pg.slice.map(
          (r) =>
            `• \`${String(r.id).slice(0, 8)}\` [\`${r.outcome}\`] *${sanitizeText(r.agentName || r.agentId)}* — \`${formatNumber(r.totalTokens || 0)} tok\``
        ),
      ];
      const pRow = paginationRow({ prefix: "uac:anx:runs", page: pg.page, totalPages: pg.totalPages });
      if (pRow) kb.push(pRow);
    } else if (viewArg === "history") {
      replyLines = [
        `📈 *Tren Harian Token & Estimasi Biaya (14 Hari Terakhir)*`,
        ...report.daily_history.map(
          (d) => `• \`${d.date}\`: \`${formatNumber(d.tokens || d.totalTokens || 0)} tok\` • Est \`${formatUsd(d.cost || d.totalCost || 0)}\``
        ),
      ];
    } else {
      const topAgents = [...report.per_agent]
        .sort((a, b) => b.tokens - a.tokens)
        .slice(0, 5)
        .map((a) => `• *${a.name}:* \`${formatNumber(a.tokens)} tok\` • Est \`${formatUsd(a.estimated_cost_usd)}\` • \`${a.tool_calls} tools\``);

      replyLines = [
        `📊 *ANALYTICS — ${report.window.label}*`,
        `• *Diperbarui:* \`${report.checked_at}\` (\`${report.timezone}\`)`,
        `• *Sumber Data:* SQLite \`state.db\` (Owner + 11 Agen) + Paperclip API`,
        ``,
        `🔢 *Token & Transparansi Biaya:*`,
        `• *Measured Tokens:* \`${formatNumber(m.total_tokens)}\` (In: \`${formatNumber(m.input_tokens)}\` | Out: \`${formatNumber(m.output_tokens)}\` | Cache: \`${formatNumber(m.cache_read_tokens)}\`)`,
        `• *Actual Billed Provider Cost:* \`${formatUsd(c.actual_billed_cost_usd)}\` (\`${c.provider_billing_mode}\`)`,
        `• *Estimated Token-Metered Cost:* \`${formatUsd(c.estimated_token_metered_cost_usd)}\` _(Tarif asumsi: $${c.assumed_rates_per_1m_usd.input}/$${c.assumed_rates_per_1m_usd.output} per 1M)_`,
        `• *Utilisasi Budget:* Harian \`${formatUsd(c.daily_estimated_usd)} / ${c.daily_limit_usd !== null ? `${formatUsd(c.daily_limit_usd)} (${c.daily_utilization_pct}%)` : "♾️ UNLIMITED"}\` • Bulanan \`${formatUsd(c.monthly_estimated_usd)} / ${c.monthly_limit_usd !== null ? `${formatUsd(c.monthly_limit_usd)} (${c.monthly_utilization_pct}%)` : "♾️ UNLIMITED"}\``,
        ``,
        `⚡ *Performa & Keandalan:*`,
        `• *Runs:* \`${m.completed_runs} selesai\` / \`${m.failed_runs} gagal\` (Success Rate: \`${m.success_rate_pct}%\`)`,
        `• *Avg Runtime:* \`${formatDurationMs(m.avg_runtime_ms)}\` | *Sesi:* \`${m.total_sessions}\` | *Tool Calls:* \`${formatNumber(m.tool_calls)}\``,
        `• *Approvals:* \`${m.approvals_count}\` (Intervention Rate: \`${m.intervention_rate_pct}%\`)`,
        ``,
        `🏆 *Top 5 Aktivitas Agen:*`,
        ...topAgents,
      ];
      kb.push([btn("📅 Today", "uac:anx:today"), btn("⏮️ Yesterday", "uac:anx:yesterday"), btn("📆 7d", "uac:anx:7d"), btn("🗓️ 30d", "uac:anx:30d")]);
      kb.push([btn("👥 Per Agen", "uac:anx:agents:1"), btn("🤖 Per Model", "uac:anx:models"), btn("⚡ Runs", "uac:anx:runs:1")]);
    }

    kb.push(navFooter({ backTo: "uac:sub:analytics", refreshCb: `uac:anx:${p0}` }));

    return {
      ok: true,
      command: "analytics",
      analytics: report,
      totals: {
        totalTokens: m.total_tokens,
        input: m.input_tokens,
        output: m.output_tokens,
        totalCost: c.estimated_token_metered_cost_usd,
        actualBilledCost: c.actual_billed_cost_usd,
      },
      budgets: {
        dailySpendLimitUsd: c.daily_limit_usd,
        monthlySpendLimitUsd: c.monthly_limit_usd,
        dailyLimitUsd: c.daily_limit_usd,
        monthlyLimitUsd: c.monthly_limit_usd,
      },
      performance: {
        total_runs: m.total_runs,
        completed_runs: m.completed_runs,
        failed_runs: m.failed_runs,
        success_rate_pct: m.success_rate_pct,
        avg_runtime_ms: m.avg_runtime_ms,
        total_tool_calls: m.tool_calls,
      },
      receipt: buildExecutionReceipt({ correlationId, command: "analytics" }),
      reply: replyLines.join("\n"),
      inline_keyboard: kb,
    };
  }

  if (canonicalId === "budget") {
    const bdg = getGovernedBudgetOverview(snap);
    const fmtLim = (v) => (typeof v === "number" && v > 0 ? formatUsd(v) : "♾️ UNLIMITED (Tanpa Batas)");
    const sub = (args || "overview").toLowerCase();
    if (sub === "agents") {
      const lines = bdg.agent_policies.map((p) => {
        const q =
          Number(p.quota_cents || 0) > 0 && p.is_active !== false
            ? `$${(Number(p.quota_cents) / 100).toFixed(2)}/bln`
            : "♾️ UNLIMITED";
        return `• *${p.scope_name}:* Kuota \`${q}\` • HardStop=\`${p.hard_stop_enabled}\` • Status=\`${p.paused ? "PAUSED" : "ACTIVE"}\``;
      });
      return {
        ok: true,
        command: "budget",
        budget: bdg,
        reply: [`💰 *Pagu Anggaran Bulanan Paperclip per 11 Agen*`, ``, ...lines].join("\n"),
        inline_keyboard: [navFooter({ backTo: "uac:sub:budgets" })],
      };
    }
    if (sub === "history") {
      const fmtHist = (v) => (typeof v === "number" ? `$${v}` : String(v || "UNLIMITED"));
      const hLines = bdg.history.map(
        (h) => `• \`${h.timestamp.slice(0, 19)}\` — \`${h.scope}\`: \`${fmtHist(h.previous_limit_usd)}\` → \`${fmtHist(h.effective_limit_usd)}\``
      );
      return {
        ok: true,
        command: "budget",
        budget: bdg,
        reply: [`📜 *Riwayat Audit Perubahan Budget*`, ...(hLines.length ? hLines : ["• _(Belum ada riwayat perubahan)_"])].join("\n"),
        inline_keyboard: [navFooter({ backTo: "uac:sub:budgets" })],
      };
    }
    return {
      ok: true,
      command: "budget",
      budget: bdg,
      receipt: buildExecutionReceipt({ correlationId, command: "budget" }),
      reply: [
        `💰 *Status Anggaran & Cost Governance*`,
        `• *Mode Kebijakan:* \`${bdg.is_unlimited ? "♾️ UNLIMITED (Tanpa Batas Harian / Bulanan / Per-Agen)" : "CUSTOM LIMIT"}\``,
        `• *Hard Ceiling Perusahaan (Paperclip):* \`${fmtLim(bdg.paperclip_company_hard_ceiling_usd)}\``,
        `• *Batas Harian:* \`${fmtLim(bdg.dailySpendLimitUsd)}\` (Terpakai Hari Ini: \`${formatUsd(bdg.current_daily_spend_usd)}\`)`,
        `• *Batas Bulanan:* \`${fmtLim(bdg.monthlySpendLimitUsd)}\` (Terpakai Bulan Ini: \`${formatUsd(bdg.current_monthly_spend_usd)}\`)`,
        `• *Batas per Agen (11/11 Agen):* \`${fmtLim(bdg.perAgentSoftLimitUsd)}\` (HardStop=\`OFF\`)`,
        `• *Agen Paused karena Budget:* \`${bdg.paused_due_to_budget.length}\``,
        ...(bdg.alerts.length ? [``, `🚨 *Alerts:*`, ...bdg.alerts.map((a) => `• ${a}`)] : []),
        ``,
        `💡 Gunakan \`/set_budget unlimited\` untuk mode tanpa batas penuh, atau \`/set_budget daily <usd>\` / \`/set_budget monthly <usd>\` bila ingin memasang batas opsional.`,
      ].join("\n"),
      inline_keyboard: buildSubmenuView("budgets", { tgState, snap, folderStatus, activeMeeting }).inline_keyboard,
    };
  }

  if (canonicalId === "set_budget") {
    const parts = args.trim().split(/\s+/).filter(Boolean);
    const scope = (parts[0] || "unlimited").toLowerCase();
    const rawVal = parts[1] !== undefined ? parts[1] : "";
    const val = rawVal !== "" ? Number(rawVal) : NaN;
    const currency = parts[2] || "USD";
    const upd = updateGovernedBudget({
      snap,
      callerId,
      scope,
      amountUsd: val,
      rawAmountArg: rawVal,
      currency,
    });
    if (!upd.ok) {
      return {
        ok: false,
        status: upd.status || 400,
        error_code: upd.code,
        error: upd.error,
        reply:
          `⚠️ *Perubahan Budget Ditolak (\`${upd.code}\`)*\n${upd.error}\n` +
          `💡 Contoh valid: \`/set_budget unlimited\`, \`/set_budget daily 20\`, atau \`/set_budget monthly 100\`.`,
      };
    }

    const syncRes = await syncBudgetsWithPaperclip({
      nextBudgets: upd.budgets,
      paperclip,
      companyId: snap?.company?.id || null,
      sync,
    });

    const fmtLim = (v) => (typeof v === "number" && v > 0 ? formatUsd(v) : "♾️ UNLIMITED");
    return {
      ok: true,
      command: "set_budget",
      budgets: upd.budgets,
      paperclip_synced: Boolean(syncRes.paperclip_synced),
      audit: upd.audit,
      receipt: buildExecutionReceipt({ correlationId, command: "set_budget", mutated: true }),
      reply:
        `💰 *Target Budget Diperbarui & Tercatat di Audit Trail!*\n` +
        `• *Scope:* \`${upd.audit.scope}\` (\`${upd.audit.previous_limit_usd}\` → \`${upd.audit.effective_limit_usd}\`)\n` +
        `• *Daily Limit:* \`${fmtLim(upd.budgets.dailySpendLimitUsd)}\`\n` +
        `• *Monthly Limit:* \`${fmtLim(upd.budgets.monthlySpendLimitUsd)}\`\n` +
        `• *Per-Agent Limit:* \`${fmtLim(upd.budgets.perAgentSoftLimitUsd)}\``,
      inline_keyboard: [navFooter({ backTo: "uac:sub:budgets" })],
    };
  }

  // ===========================================================================
  // PHASE 15 — INTERACTIVE GOVERNANCE APPROVALS (`/persetujuan`, `/setujui`, `/tolak`)
  // ===========================================================================
  if (canonicalId === "persetujuan") {
    const center = buildUnifiedApprovalsCenter(snap, liveDirectory);
    const kb = [];
    for (const p of center.pending.slice(0, 5)) {
      const tok = registerShortApprovalToken(tgState, p.id);
      kb.push([
        btn(`✅ Setujui ${String(p.id).slice(0, 10)}`, `uac:app_ok:${tok}`),
        btn(`❌ Tolak ${String(p.id).slice(0, 10)}`, `uac:app_no:${tok}`),
      ]);
    }
    kb.push(navFooter({ backTo: "uac:home", refreshCb: "uac:approvals" }));
    saveTelegramControlState(tgState);

    const pLines = center.pending.map(
      (a) =>
        `• \`${String(a.id).slice(0, 12)}\` [\`${a.risk_category}\`] — *${a.requested_action}*\n  └ Origin: \`${a.origin_agent}\` • Target: \`${a.project_or_task}\`${a.expires_at ? ` • Exp: \`${a.expires_at.slice(11, 19)}\`` : ""}`
    );
    const hLines = center.history.slice(0, 5).map(
      (a) => `• \`${String(a.id).slice(0, 12)}\` [\`${a.status}\`] — ${a.requested_action}`
    );

    return {
      ok: true,
      command: "persetujuan",
      pending_count: center.pending.length,
      expired_count: center.expired.length,
      approvals: center.all.slice(0, 15),
      receipt: buildExecutionReceipt({ correlationId, command: "persetujuan" }),
      reply: [
        `✅ *Pusat Governance Approvals (Paperclip & Hermes)*`,
        `• *Pending:* \`${center.pending.length}\` | *Expired:* \`${center.expired.length}\` | *Riwayat:* \`${center.history.length}\``,
        ``,
        ...(pLines.length ? [`*Menunggu Keputusan Owner:*`, ...pLines] : [`_(Tidak ada permintaan approval pending saat ini)_`]),
        ...(hLines.length ? [``, `*Riwayat Keputusan Terakhir:*`, ...hLines] : []),
      ].join("\n"),
      inline_keyboard: kb,
    };
  }

  if (canonicalId === "setujui" || canonicalId === "tolak") {
    const decision = canonicalId === "setujui" ? "approve" : "reject";
    const parts = args.trim().split(/\s+/).filter(Boolean);
    const rawId = resolveApprovalOrToken(tgState, parts[0] || "");
    const note = parts.slice(1).join(" ") || `Resolved (${decision}) by Owner via Telegram.`;
    if (!rawId) {
      return { ok: false, status: 400, reply: `Gunakan: \`/${invokedCmd} <approval_id> [catatan]\`.` };
    }

    if (rawId.startsWith("req_")) {
      const consumed = consumeBoundApprovalRequest({
        requestId: rawId,
        callerId,
        decision,
        note,
      });
      if (!consumed.ok) {
        return buildStructuredError({
          correlationId,
          command: canonicalId,
          code: consumed.code,
          status: consumed.status,
          message: consumed.error,
        });
      }
      return {
        ok: true,
        command: canonicalId,
        decision,
        approval: consumed.record,
        receipt: buildExecutionReceipt({ correlationId, command: canonicalId, mutated: true, evidenceRef: consumed.record.request_id }),
        reply: `${decision === "approve" ? "✅" : "❌"} Bound Approval \`${consumed.record.request_id}\` (\`${consumed.record.action}\`) berhasil di-*${decision}*.`,
        inline_keyboard: [navFooter({ backTo: "uac:approvals" })],
      };
    }

    await sync.reconcileNow("telegram_approval_precheck");
    const freshSnap = sync.getFullSnapshot();
    const target = (freshSnap.approvals || []).find(
      (a) => a.id === rawId || String(a.id).toLowerCase().startsWith(rawId.toLowerCase())
    );
    if (!target) {
      return buildStructuredError({
        correlationId,
        command: canonicalId,
        code: "APPROVAL_NOT_FOUND",
        status: 404,
        message: `Approval Paperclip \`${sanitizeText(rawId)}\` tidak ditemukan.`,
      });
    }
    if (String(target.status).toLowerCase() !== "pending") {
      return buildStructuredError({
        correlationId,
        command: canonicalId,
        code: "STALE_OR_DUPLICATE_APPROVAL",
        status: 409,
        message: `Approval \`${String(target.id).slice(0, 8)}\` sudah berstatus \`${target.status}\` (duplikasi/stale dicegah).`,
      });
    }

    const resolvedApp = await paperclip.resolveApproval(target.id, decision, note);
    await sync.reconcileNow("telegram_approval_resolved");
    return {
      ok: true,
      command: canonicalId,
      decision,
      approval: resolvedApp,
      receipt: buildExecutionReceipt({ correlationId, command: canonicalId, mutated: true, evidenceRef: target.id }),
      reply: `${decision === "approve" ? "✅" : "❌"} Approval Paperclip \`${String(target.id).slice(0, 8)}\` berhasil di-*${decision}* melalui Telegram.`,
      inline_keyboard: [navFooter({ backTo: "uac:approvals" })],
    };
  }

  // ===========================================================================
  // PHASE 16 — DEFENSIVE SECURITY & ISOLATED VULNCLAW 8-STATE CONTROL
  // ===========================================================================
  if (canonicalId === "keamanan") {
    const tokens = args.trim().split(/\s+/).filter(Boolean);
    const first = (tokens[0] || "").toLowerCase();

    if (invokedCmd === "triage_temuan" || first === "triage") {
      const fid = invokedCmd === "triage_temuan" ? tokens[0] : tokens[1];
      const nextSt = invokedCmd === "triage_temuan" ? tokens[1] : tokens[2];
      const note = (invokedCmd === "triage_temuan" ? tokens.slice(2) : tokens.slice(3)).join(" ");
      if (!fid || !nextSt) {
        return buildStructuredError({
          correlationId,
          command: "triage_temuan",
          message: "Gunakan: `/triage_temuan <FND-ID> <UNDER_REVIEW|CONFIRMED|FALSE_POSITIVE|REMEDIATION_REQUIRED|IN_PROGRESS|READY_FOR_VERIFICATION|RESOLVED> [catatan]`",
        });
      }
      const tr = await transitionFindingViaPython({ findingId: fid, toStatus: nextSt, note });
      if (!tr.ok) return buildStructuredError({ correlationId, command: "triage_temuan", message: tr.error });
      await sync.reconcileNow("telegram_finding_triage");
      return {
        ok: true,
        command: "triage_temuan",
        finding: tr.finding,
        receipt: buildExecutionReceipt({ correlationId, command: "triage_temuan", mutated: true, evidenceRef: fid }),
        reply: `🛡️ Temuan \`${tr.finding.finding_id}\` diperbarui ke state \`${tr.finding.verification_status}\`.`,
        inline_keyboard: [navFooter({ backTo: "uac:sub:security" })],
      };
    }

    if (invokedCmd === "remediasi_temuan" || first === "remediate") {
      const fData = listDefensiveFindings(20);
      const rawId = invokedCmd === "remediasi_temuan" ? tokens[0] : tokens[1];
      const targetFinding =
        !rawId || rawId === "latest"
          ? fData.findings.find((f) => f.verification_status !== "FALSE_POSITIVE") || fData.findings[0]
          : fData.findings.find((f) => f.finding_id.toLowerCase() === rawId.toLowerCase());
      if (!targetFinding) {
        return buildStructuredError({ correlationId, command: "remediasi_temuan", status: 404, message: "Temuan tidak ditemukan." });
      }
      const backendEntry = liveDirectory.find((d) => d.slug === "backend_developer") || liveDirectory[2];
      const tr = await transitionFindingViaPython({
        findingId: targetFinding.finding_id,
        toStatus: "REMEDIATION_REQUIRED",
        note: "Remediation requested by Owner via Telegram.",
        createRemediation: true,
        developerAgentId: backendEntry.id,
      });
      if (!tr.ok) return buildStructuredError({ correlationId, command: "remediasi_temuan", message: tr.error });
      await sync.reconcileNow("telegram_finding_remediate");
      return {
        ok: true,
        command: "remediasi_temuan",
        finding: tr.finding,
        receipt: buildExecutionReceipt({
          correlationId,
          command: "remediasi_temuan",
          mutated: true,
          taskId: tr.finding.paperclip_remediation_issue_id,
          evidenceRef: tr.finding.finding_id,
        }),
        reply:
          `🩹 *Task Remediasi Keamanan Dibuat!*\n` +
          `• *Finding:* \`${tr.finding.finding_id}\` — ${sanitizeText(tr.finding.finding_title)}\n` +
          `• *State:* \`${tr.finding.verification_status}\`\n` +
          `• *Remediation Issue ID:* \`${tr.finding.paperclip_remediation_issue_id || "tercatat"}\` (ditugaskan ke Backend Developer)`,
        inline_keyboard: [navFooter({ backTo: "uac:sub:security" })],
      };
    }

    if (first === "deps") {
      const depTarget = tokens.slice(1).join(" ") || folderStatus.active_folder || defaultWorkspace;
      const riskRes = inspectDependencyAndConfigRisks(depTarget);
      if (!riskRes.ok) return buildStructuredError({ correlationId, command: "keamanan", status: riskRes.status, message: riskRes.error });
      return {
        ok: true,
        command: "keamanan",
        advisory_check: riskRes,
        reply: [
          `📦 *Review Dependensi & Risiko Konfigurasi Defensif*`,
          `• *Target:* \`${riskRes.verified_path}\``,
          ``,
          `*Dependency Advisories:*`,
          ...riskRes.dependency_advisories.map((a) => `• ${a}`),
          ``,
          `*Configuration Risks (.env tidak dibaca):*`,
          ...riskRes.configuration_risks.map((c) => `• ${c}`),
        ].join("\n"),
        inline_keyboard: [navFooter({ backTo: "uac:sub:security" })],
      };
    }

    if (first === "verify") {
      const targetFolder = folderStatus.active_folder || defaultWorkspace;
      const secReviewer = liveDirectory.find((d) => d.slug === "security_reviewer") || liveDirectory[7];
      const created = await handleCreateTaskAction(
        {
          title: `[Security Verification] Verifikasi Mitigasi Defensif: ${path.basename(targetFolder)}`,
          description: `Lakukan verifikasi keamanan defensif pasca-remediasi pada \`${targetFolder}\`.`,
          assignee_agent_id: secReviewer.id,
          priority: "high",
          status: "todo",
          wake_immediately: true,
          notify_telegram: false,
        },
        callerId
      );
      return {
        ok: true,
        command: "keamanan_verify",
        task: created.task,
        reply: `✅ Permintaan verifikasi keamanan dibuat: \`${created.task.identifier}\` → *${secReviewer.name}*.`,
        inline_keyboard: [navFooter({ backTo: "uac:sub:security" })],
      };
    }

    if (first === "list") {
      const pgNum = Number(tokens[1] || 1) || 1;
      const fData = listDefensiveFindings(40);
      const pg = paginateItems(fData.findings, pgNum, 6);
      const lines = pg.slice.map(
        (f) =>
          `• \`${f.finding_id}\` [\`${f.severity}\` • \`${f.verification_status}\`] *${f.finding_title}*\n  └ Komponen: \`${f.affected_component}\` • Rekomendasi: ${String(f.remediation_recommendation).slice(0, 90)}`
      );
      const kb = [];
      const pRow = paginationRow({ prefix: "uac:sec:list", page: pg.page, totalPages: pg.totalPages });
      if (pRow) kb.push(pRow);
      kb.push(navFooter({ backTo: "uac:sub:security" }));
      return {
        ok: true,
        command: "keamanan",
        findings: pg.slice,
        counts: fData.counts,
        reply: [`🔎 *Daftar Temuan VulnClaw (Hal ${pg.page}/${pg.totalPages})*`, ``, ...lines].join("\n"),
        inline_keyboard: kb,
      };
    }

    if (args.trim()) {
      const vPath = validateSecureFolderOrFile(args.trim(), { allowFile: true });
      if (!vPath.ok) {
        return {
          ok: false,
          status: vPath.status || 403,
          error_code: vPath.code,
          error: vPath.error,
          reply: `🛡️ *Scan Keamanan Ditolak:* \`${sanitizeText(vPath.error)}\``,
        };
      }
      const scanRes = await executeWithResilience("vulnclaw", () =>
        runDefensiveVulnclawScan(vPath.fs_path, { callerId, timeoutMs: 45_000 })
      );
      return {
        ok: true,
        command: "keamanan",
        ...scanRes,
        receipt: buildExecutionReceipt({ correlationId, command: "keamanan", targetWorkspace: vPath.resolved_path }),
        inline_keyboard: [navFooter({ backTo: "uac:sub:security" })],
      };
    }

    const fData = listDefensiveFindings(10);
    const counts = fData.counts;
    const topFindings = fData.findings.slice(0, 5).map(
      (f) =>
        `• [\`${f.severity}\`] \`${f.finding_id}\` — ${sanitizeText(f.finding_title).slice(0, 62)} (\`${f.verification_status}\`)`
    );

    return {
      ok: true,
      command: "keamanan",
      counts,
      findings: fData.findings,
      receipt: buildExecutionReceipt({ correlationId, command: "keamanan" }),
      reply: [
        `🛡️ *VulnClaw Defensive Security Center (Isolated Runtime)*`,
        `• *Total Findings:* \`${counts.total || 0}\` | *Received/Review:* \`${(counts.received || 0) + (counts.under_review || 0)}\``,
        `• *Confirmed/Remediating:* \`${(counts.confirmed || 0) + (counts.remediation_required || 0) + (counts.in_progress || 0)}\``,
        `• *Resolved:* \`${counts.resolved || 0}\` | *False Positive:* \`${counts.false_positive || 0}\``,
        ...(topFindings.length ? [``, `*Temuan Terkini:*`, ...topFindings] : []),
        ``,
        `_Perintah: \`/keamanan <path>\`, \`/triage_temuan <FND-ID> <STATE>\`, \`/remediasi_temuan <FND-ID>\`._`,
      ].join("\n"),
      inline_keyboard: buildSubmenuView("security", { tgState, snap, folderStatus, activeMeeting }).inline_keyboard,
    };
  }

  // ===========================================================================
  // PHASES 17, 18 & 20 — 15-COMPONENT HEALTH, LOGS, SAFE RECOVERY & ASYNC JOBS
  // ===========================================================================
  if (canonicalId === "kesehatan") {
    const matrix = await buildComplete15ComponentHealth({ buildUnifiedHealthMatrix, sync });
    const compLines = Object.entries(matrix.components).map(([k, v]) => {
      const icon = v.state === "HEALTHY" ? "🟢" : v.state === "MAINTENANCE" ? "🟡" : "🔴";
      return `• ${icon} *${k}:* \`${v.state}\``;
    });
    const host = matrix.host_metrics || matrix.windows || {};
    const breakers = getCircuitBreakerSnapshot();
    const diskLabel = host.disk_free_gb !== null && host.disk_free_gb !== undefined ? ` | Disk Free \`${host.disk_free_gb} GB\`` : "";
    const hostLine =
      host.cpu_pct !== undefined
        ? `\n💻 *Host (${host.platform || process.platform}/${host.arch || process.arch}):* CPU \`${host.cpu_pct}%\` | RAM Free \`${host.ram_free_mb} MB\`${diskLabel}`
        : "";

    return {
      ok: true,
      command: "kesehatan",
      health: matrix,
      circuit_breakers: breakers,
      maintenance_locked: isMaintenanceLockActive(),
      receipt: buildExecutionReceipt({ correlationId, command: "kesehatan" }),
      reply: [
        `🩺 *Unified System Health Matrix: ${matrix.overall_state}*`,
        `_(15 Komponen Aktual Diperiksa — ${matrix.checked_at.slice(11, 19)} UTC)_`,
        ``,
        ...compLines,
        hostLine,
      ]
        .filter(Boolean)
        .join("\n"),
      inline_keyboard: [
        [btn("📜 Lihat Error Logs", "uac:sys:logs"), btn("🔧 Pemulihan Aman", "uac:sys:recover")],
        navFooter({ backTo: "uac:home", refreshCb: "uac:health" }),
      ],
    };
  }

  if (canonicalId === "log_error") {
    if (invokedCmd === "pulihkan_layanan" || /^recover|pulihkan/i.test(args)) {
      const svc =
        invokedCmd === "pulihkan_layanan"
          ? args.trim() || "reconcile"
          : args.replace(/^recover|pulihkan/i, "").trim() || "reconcile";
      const rec = await withSingletonLock(`recover:${svc}`, () =>
        executeSafeGracefulRecovery({ sync, targetService: svc })
      );
      if (!rec.ok) {
        return buildStructuredError({
          correlationId,
          command: "pulihkan_layanan",
          code: rec.code,
          status: rec.status,
          message: rec.error,
        });
      }
      await emitActivityNotification({
        eventType: "recovery.completed",
        severity: "SUCCESS",
        dedupeKey: `rec:${svc}:${Math.floor(Date.now() / 30000)}`,
        title: `Pemulihan Aman Selesai (${svc})`,
        detail: `Paperclip reachable=${rec.paperclip_reachable}`,
      });
      return {
        ok: true,
        command: "pulihkan_layanan",
        recovery: rec,
        receipt: buildExecutionReceipt({ correlationId, command: "pulihkan_layanan", mutated: true }),
        reply:
          `🔧 *Pemulihan Layanan Aman Berhasil!*\n` +
          `• *Target:* \`${rec.service}\` (Graceful Drain OK)\n` +
          `• *Paperclip Reachable:* \`${rec.paperclip_reachable}\`\n` +
          `• *Waktu:* \`${rec.recovered_at}\``,
        inline_keyboard: [navFooter({ backTo: "uac:sub:system" })],
      };
    }

    const errLogs = readRecentSanitizedErrorLogs(14);
    const dlq = listDeadLetters(5);
    return {
      ok: true,
      command: "log_error",
      logs: errLogs,
      dead_letters: dlq,
      reply: [
        `📜 *Log Diagnostik & Dead-Letter Terbaru (Tersanitasi)*`,
        ``,
        ...(errLogs.length ? errLogs.map((l) => `• \`${l}\``) : ["• _(Tidak ada entri error terbaru)_"]),
        ...(dlq.length ? [``, `*Dead-Letter Queue (${dlq.length}):*`, ...dlq.map((d) => `• \`${d.dead_letter_id}\`: ${d.error}`)] : []),
      ].join("\n"),
      inline_keyboard: [navFooter({ backTo: "uac:sub:system", refreshCb: "uac:sys:logs" })],
    };
  }

  if (canonicalId === "update_status") {
    const cliRes = await invokePlatformCliJson(["telegram-cmd", "update_status", "--caller-id", callerId], 15_000);
    return {
      ok: true,
      command: "update_status",
      ...cliRes,
      reply:
        cliRes.reply ||
        `🕒 *Status Pembaruan Otomatis Hermes*\n• *Status CLI:* \`${cliRes.available === false ? "Standalone Container Mode" : "Ready"}\``,
      receipt: buildExecutionReceipt({ correlationId, command: "update_status" }),
      inline_keyboard: [navFooter({ backTo: "uac:sub:system", refreshCb: "uac:sys:updates" })],
    };
  }

  if (canonicalId === "jobs") {
    const tokens = args.trim().split(/\s+/).filter(Boolean);
    if (invokedCmd === "batal_job" || tokens[0] === "cancel" || tokens[0] === "batal") {
      const jid = invokedCmd === "batal_job" ? tokens[0] : tokens[1];
      const res = cancelAsyncJob(jid);
      if (!res.ok) return buildStructuredError({ correlationId, command: "batal_job", status: 404, message: res.error });
      return {
        ok: true,
        command: "batal_job",
        job: res.job,
        receipt: buildExecutionReceipt({ correlationId, command: "batal_job", mutated: true, evidenceRef: res.job.job_id }),
        reply: `🛑 Async Job \`${res.job.job_id}\` berhasil dibatalkan (\`${res.job.status}\`).`,
        inline_keyboard: [navFooter({ backTo: "uac:sub:system" })],
      };
    }

    if (args.trim().startsWith("--start-audit")) {
      const target = args.replace("--start-audit", "").trim() || folderStatus.active_folder || defaultWorkspace;
      const enq = enqueueAsyncJob({
        title: `Background Source Audit: ${path.basename(target)}`,
        command: "analisis",
        target,
        idempotencyKey: payload.message_id ? `job-anl:${callerId}:${payload.message_id}` : null,
        notifyOnFinish: false,
        workerFn: async ({ updateProgress }) => {
          updateProgress(40, "Memeriksa manifest & source code...");
          const res = performRealSourceCodeAnalysis(target, { agentName: tgState.selected_agent_name });
          updateProgress(95, "Menyimpan laporan...");
          return { report_path: res.report_path, examined_count: res.examined_files?.length || 0 };
        },
      });
      return {
        ok: true,
        command: "jobs",
        queued_job: enq.job,
        deduplicated: enq.deduplicated,
        receipt: buildExecutionReceipt({
          correlationId,
          command: "jobs",
          mutated: true,
          executionStatus: "ACCEPTED_ASYNC",
          evidenceRef: enq.job.job_id,
        }),
        reply:
          `⏳ *Pekerjaan Berdurasi Panjang Diterima!*\n` +
          `• *Job ID:* \`${enq.job.job_id}\`\n` +
          `• *Status:* \`${enq.job.status}\` (\`${enq.job.progress_pct}%\`)\n` +
          `Cek progres: \`/cek_job ${enq.job.job_id}\` atau batalkan: \`/batal_job ${enq.job.job_id}\`.`,
        inline_keyboard: [navFooter({ backTo: "uac:sub:system", refreshCb: "uac:sys:jobs" })],
      };
    }

    const allJobs = loadAsyncJobs().slice(-12).reverse();
    if (invokedCmd === "cek_job" && tokens[0]) {
      const one = allJobs.find((j) => j.job_id === tokens[0]);
      if (!one) return buildStructuredError({ correlationId, command: "cek_job", status: 404, message: "Job tidak ditemukan." });
      return {
        ok: true,
        command: "cek_job",
        job: one,
        reply: [
          `🔎 *Detail Async Job \`${one.job_id}\`*`,
          `• *Judul:* ${one.title}`,
          `• *Status:* \`${one.status}\` (\`${one.progress_pct}%\` — ${one.progress_note})`,
          one.result_summary ? `• *Hasil:* \`${JSON.stringify(one.result_summary).slice(0, 220)}\`` : null,
          one.error ? `• *Error:* \`${one.error}\`` : null,
        ]
          .filter(Boolean)
          .join("\n"),
        inline_keyboard: [navFooter({ backTo: "uac:sub:system" })],
      };
    }

    return {
      ok: true,
      command: "jobs",
      jobs: allJobs,
      reply: [
        `⏳ *Daftar Pekerjaan Asinkron (Long-Running Jobs — ${allJobs.length})*`,
        ...(allJobs.length
          ? allJobs.map((j) => `• \`${j.job_id}\` [\`${j.status}\` ${j.progress_pct}%] — ${j.title}`)
          : ["• _(Belum ada riwayat job asinkron)_"]),
      ].join("\n"),
      inline_keyboard: [navFooter({ backTo: "uac:sub:system", refreshCb: "uac:sys:jobs" })],
    };
  }

  return buildStructuredError({
    correlationId,
    command: canonicalId,
    code: "UNHANDLED_COMMAND",
    status: 400,
    message: `Handler untuk \`/${canonicalId}\` belum diaktifkan.`,
  });
}

module.exports = {
  CORPORATE_AGENT_DIRECTORY,
  TELEGRAM_STATE_FILE,
  resolveLiveCorporateDirectory,
  loadTelegramControlState,
  saveTelegramControlState,
  resolveCorporateAgentEntry,
  parseNaturalTelegramIntent,
  getTelegramControlPublicState,
  executeTelegramControlCommand,
};
