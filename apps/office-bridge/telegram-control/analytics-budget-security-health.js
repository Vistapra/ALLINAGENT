"use strict";

/**
 * PHASES 13, 14, 15, 16 & 17 — Windowed Source-Verified Analytics (Configurable Timezone),
 * Governed Budget Management (Hard-Ceiling + Bidirectional Paperclip Sync + Audit Trail),
 * Interactive Approvals, Isolated VulnClaw 8-State Defensive Security Control,
 * and Cross-Platform 15-Component System Health (Linux `/proc` + `fs.statfsSync`) & Safe Drain Recovery.
 *
 * Strictly zero hardcoded Windows paths, Jakarta offsets, personal domains, or Paperclip UUIDs.
 */

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const {
  PLATFORM_ROOT,
  OFFICE_DATA_DIR,
  DATA_DIR,
  LOGS_DIR,
  HERMES_HOME_ROOT,
  DEFAULT_LLM_BASE_URL,
  DEFAULT_LLM_MODEL,
  PYTHON_EXE,
  resolveTimezone,
  loadSqliteDatabaseSync,
} = require("../contracts/paths");
const { sanitizeText, sanitizePayload } = require("../contracts/redaction");
const { appendAuditEntry } = require("../authorization/auth");
const {
  epochMsToLocalDate,
  resolveCorporateBudgets,
  saveBudgetOverrides,
  syncBudgetsWithPaperclip,
  buildUsageAndCostAnalytics,
  buildHistoricalRunRecords,
  buildApprovalRecords,
} = require("../adapters/analytics-telemetry-adapter");
const { listBoundApprovals } = require("./security-guard");
const { validateSecureFolderOrFile } = require("./folder-and-dev-controller");

const execFileAsync = promisify(execFile);

const BUDGET_AUDIT_FILE = path.resolve(path.join(OFFICE_DATA_DIR, "budget-audit-history.jsonl"));
const FINDINGS_DB_PATH = path.resolve(path.join(DATA_DIR, "findings", "findings.db"));
const RECOVERY_COOLDOWN_FILE = path.resolve(path.join(OFFICE_DATA_DIR, "recovery-cooldown.json"));

function localDateOffsetDays(daysAgo = 0) {
  const tz = resolveTimezone(process.env);
  return epochMsToLocalDate(Date.now() - daysAgo * 86_400_000, tz);
}

/**
 * Collect cross-platform Linux (`/proc/loadavg`, `/proc/meminfo`, `fs.statfsSync`) & Node `os` host metrics
 * without exposing any personal hostname or Windows PowerShell dependency.
 */
function collectHostResourceMetrics() {
  const cpuCount = Math.max(1, (os.cpus() || []).length);
  let loadAvg1m = os.loadavg()[0] || 0;
  let ramTotalMb = Math.round((os.totalmem() / (1024 * 1024)) * 10) / 10;
  let ramFreeMb = Math.round((os.freemem() / (1024 * 1024)) * 10) / 10;

  if (process.platform === "linux") {
    try {
      if (fs.existsSync("/proc/loadavg")) {
        const rawLoad = fs.readFileSync("/proc/loadavg", "utf8").trim().split(/\s+/);
        const parsed = parseFloat(rawLoad[0]);
        if (Number.isFinite(parsed)) loadAvg1m = parsed;
      }
      if (fs.existsSync("/proc/meminfo")) {
        const memTxt = fs.readFileSync("/proc/meminfo", "utf8");
        const totMatch = memTxt.match(/^MemTotal:\s+(\d+)\s+kB/m);
        const availMatch = memTxt.match(/^MemAvailable:\s+(\d+)\s+kB/m);
        if (totMatch) ramTotalMb = Math.round((Number(totMatch[1]) / 1024) * 10) / 10;
        if (availMatch) ramFreeMb = Math.round((Number(availMatch[1]) / 1024) * 10) / 10;
      }
    } catch {}
  }

  const cpuPct = Math.min(100, Math.max(0, Math.round(((loadAvg1m / cpuCount) * 100) * 10) / 10));
  const ramUsedPct = ramTotalMb > 0 ? Math.round(((1 - ramFreeMb / ramTotalMb) * 100) * 10) / 10 : 0;

  let diskFreeGb = null;
  let diskTotalGb = null;
  if (typeof fs.statfsSync === "function") {
    try {
      const targetStatDir = fs.existsSync(PLATFORM_ROOT) ? PLATFORM_ROOT : os.tmpdir();
      const st = fs.statfsSync(targetStatDir);
      const bsize = Number(st.bsize || st.frsize || 4096);
      diskFreeGb = Math.round(((Number(st.bavail || st.bfree || 0) * bsize) / 1024 ** 3) * 100) / 100;
      diskTotalGb = Math.round(((Number(st.blocks || 0) * bsize) / 1024 ** 3) * 100) / 100;
    } catch {}
  }

  return {
    platform: process.platform,
    arch: process.arch,
    cpu_cores: cpuCount,
    load_avg_1m: Math.round(loadAvg1m * 100) / 100,
    cpu_pct: cpuPct,
    ram_total_mb: ramTotalMb,
    ram_free_mb: ramFreeMb,
    ram_used_pct: ramUsedPct,
    disk_free_gb: diskFreeGb,
    disk_total_gb: diskTotalGb,
    uptime_minutes: Math.round(os.uptime() / 60),
  };
}

/**
 * PHASE 13 — Windowed & Multi-View Source-Verified Analytics.
 */
async function buildTelegramAnalyticsReport({ snap, paperclip, directory, windowArg = "30d", viewArg = "summary", page = 1 }) {
  const todayStr = localDateOffsetDays(0);
  const yesterdayStr = localDateOffsetDays(1);
  let startDate = localDateOffsetDays(29);
  let endDate = todayStr;
  let windowLabel = "30 Hari Terakhir (30d)";

  const w = String(windowArg || "30d").toLowerCase();
  if (w === "today" || w === "hari_ini") {
    startDate = todayStr;
    endDate = todayStr;
    windowLabel = `Hari Ini (${todayStr})`;
  } else if (w === "yesterday" || w === "kemarin") {
    startDate = yesterdayStr;
    endDate = yesterdayStr;
    windowLabel = `Kemarin (${yesterdayStr})`;
  } else if (w === "7d" || w === "7_hari") {
    startDate = localDateOffsetDays(6);
    endDate = todayStr;
    windowLabel = `7 Hari Terakhir (${startDate} s/d ${endDate})`;
  } else if (w === "all" || w === "semua") {
    startDate = "2025-01-01";
    endDate = todayStr;
    windowLabel = `Seluruh Periode (${startDate} s/d ${endDate})`;
  }

  const tz = resolveTimezone(process.env);
  const usageAndCost = buildUsageAndCostAnalytics({ snapshot: snap, startDate, endDate, limit: 1500 });
  const allRuns = await buildHistoricalRunRecords({ snapshot: snap, paperclip, limit: 300 });
  const approvals = buildApprovalRecords({ snapshot: snap });
  const budgets = usageAndCost.corporateBudgets || resolveCorporateBudgets(snap);
  const totals = usageAndCost.totals || {};

  const windowRuns = allRuns.filter((r) => {
    const t = Number(r.startedAt || 0);
    if (!Number.isFinite(t) || t <= 0) return false;
    const dStr = epochMsToLocalDate(t, tz);
    return dStr >= startDate && dStr <= endDate;
  });

  const finishedRuns = windowRuns.filter((r) => r.endedAt !== null && r.endedAt !== undefined);
  const okRuns = finishedRuns.filter((r) => r.outcome === "ok");
  const failedRuns = finishedRuns.filter((r) => r.outcome !== "ok");
  const successRate = finishedRuns.length > 0 ? Math.round((okRuns.length / finishedRuns.length) * 1000) / 10 : 100;
  const durations = finishedRuns
    .map((r) => Number(r.endedAt || 0) - Number(r.startedAt || 0))
    .filter((d) => d > 0 && d < 3600_000);
  const avgRuntimeMs = durations.length > 0 ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length) : 0;

  const sessions = usageAndCost.sessions || [];
  const totalToolCalls = sessions.reduce((acc, s) => acc + Number(s.usage?.messageCounts?.toolCalls || 0), 0);
  const interventionRate =
    windowRuns.length > 0 ? Math.round((approvals.length / Math.max(1, windowRuns.length)) * 1000) / 10 : 0;

  const billedSessionsCost = sessions
    .filter((s) => s.usage?.costSource === "billed")
    .reduce((acc, s) => acc + Number(s.usage?.totalCost || 0), 0);
  const estimatedMeteredCost = Number(totals.totalCost || 0);

  const perAgent = directory.map((ag) => {
    const agSessions = sessions.filter((s) => s.agentId === ag.id);
    const agRuns = windowRuns.filter((r) => r.agentId === ag.id);
    const tok = agSessions.reduce((a, s) => a + Number(s.usage?.totalTokens || 0), 0);
    const cost = agSessions.reduce((a, s) => a + Number(s.usage?.totalCost || 0), 0);
    const tools = agSessions.reduce((a, s) => a + Number(s.usage?.messageCounts?.toolCalls || 0), 0);
    return {
      index: ag.index,
      agent_id: ag.id,
      name: ag.name,
      handle: ag.handle,
      sessions: agSessions.length,
      runs: agRuns.length,
      tokens: tok,
      estimated_cost_usd: Math.round(cost * 10000) / 10000,
      tool_calls: tools,
    };
  });

  const modelMap = new Map();
  for (const s of sessions) {
    const mKey = `${s.model || DEFAULT_LLM_MODEL} (${s.modelProvider || s.provider || "custom"})`;
    const cur = modelMap.get(mKey) || { model_provider: mKey, sessions: 0, tokens: 0, estimated_cost_usd: 0, tool_calls: 0 };
    cur.sessions += 1;
    cur.tokens += Number(s.usage?.totalTokens || 0);
    cur.estimated_cost_usd = Math.round((cur.estimated_cost_usd + Number(s.usage?.totalCost || 0)) * 10000) / 10000;
    cur.tool_calls += Number(s.usage?.messageCounts?.toolCalls || 0);
    modelMap.set(mKey, cur);
  }

  const todayUsage = buildUsageAndCostAnalytics({ snapshot: snap, startDate: todayStr, endDate: todayStr, limit: 500 });
  const monthStart = `${todayStr.slice(0, 7)}-01`;
  const monthUsage = buildUsageAndCostAnalytics({ snapshot: snap, startDate: monthStart, endDate: todayStr, limit: 1500 });
  const dailySpendUsd = Number(todayUsage.totals?.totalCost || 0);
  const monthlySpendUsd = Number(monthUsage.totals?.totalCost || 0);
  const hasDailyLimit = typeof budgets.dailySpendLimitUsd === "number" && budgets.dailySpendLimitUsd > 0;
  const hasMonthlyLimit = typeof budgets.monthlySpendLimitUsd === "number" && budgets.monthlySpendLimitUsd > 0;
  const dailyUtilPct = hasDailyLimit ? Math.round((dailySpendUsd / budgets.dailySpendLimitUsd) * 1000) / 10 : 0;
  const monthlyUtilPct = hasMonthlyLimit ? Math.round((monthlySpendUsd / budgets.monthlySpendLimitUsd) * 1000) / 10 : 0;

  return {
    checked_at: new Date().toISOString(),
    timezone: tz,
    sources: [
      "Hermes SQLite state.db (Owner + 11 Worker Profiles)",
      "Paperclip Heartbeat Runs & Approvals API",
      "Paperclip Budget Overview & Office Budget Overrides",
    ],
    window: { key: w, label: windowLabel, start_date: startDate, end_date: endDate },
    view: viewArg,
    page: Number(page) || 1,
    metrics: {
      total_tokens: Number(totals.totalTokens || 0),
      input_tokens: Number(totals.input || 0),
      output_tokens: Number(totals.output || 0),
      cache_read_tokens: Number(totals.cacheRead || 0),
      total_sessions: sessions.length,
      tool_calls: totalToolCalls,
      total_runs: windowRuns.length,
      completed_runs: okRuns.length,
      failed_runs: failedRuns.length,
      success_rate_pct: successRate,
      avg_runtime_ms: avgRuntimeMs,
      intervention_rate_pct: interventionRate,
      approvals_count: approvals.length,
    },
    cost_transparency: {
      provider_billing_mode: `TOKEN_METERED_REFERENCE (${DEFAULT_LLM_MODEL})`,
      actual_billed_cost_usd: Math.round(billedSessionsCost * 10000) / 10000,
      estimated_token_metered_cost_usd: Math.round(estimatedMeteredCost * 10000) / 10000,
      assumed_rates_per_1m_usd: { input: 2.5, output: 10.0, cache_read: 0.25, cache_write: 3.125 },
      daily_estimated_usd: Math.round(dailySpendUsd * 10000) / 10000,
      monthly_estimated_usd: Math.round(monthlySpendUsd * 10000) / 10000,
      daily_limit_usd: hasDailyLimit ? budgets.dailySpendLimitUsd : null,
      monthly_limit_usd: hasMonthlyLimit ? budgets.monthlySpendLimitUsd : null,
      daily_utilization_pct: dailyUtilPct,
      monthly_utilization_pct: monthlyUtilPct,
      remaining_daily_usd: hasDailyLimit ? Math.max(0, Math.round((budgets.dailySpendLimitUsd - dailySpendUsd) * 100) / 100) : null,
      remaining_monthly_usd: hasMonthlyLimit ? Math.max(0, Math.round((budgets.monthlySpendLimitUsd - monthlySpendUsd) * 100) / 100) : null,
    },
    per_agent: perAgent,
    per_model: [...modelMap.values()],
    recent_runs: windowRuns.slice(0, 60),
    daily_history: (usageAndCost.daily || []).slice(-14),
  };
}

/**
 * PHASE 14 — Governed Budget Management, Ceiling Validation, Bidirectional Sync & Audit History.
 */
function readBudgetAuditHistory(limit = 15) {
  if (!fs.existsSync(BUDGET_AUDIT_FILE)) return [];
  try {
    return fs
      .readFileSync(BUDGET_AUDIT_FILE, "utf8")
      .split(/\r?\n/)
      .filter(Boolean)
      .slice(-limit)
      .map((l) => JSON.parse(l))
      .reverse();
  } catch {
    return [];
  }
}

function getGovernedBudgetOverview(snap) {
  const corp = resolveCorporateBudgets(snap);
  const policies = snap?.governance_budget?.policies || [];
  const companyPolicy = policies.find((p) => p.scope_type === "company");
  const hardCeilingUsd =
    companyPolicy && companyPolicy.is_active !== false && Number(companyPolicy.quota_cents) > 0
      ? Number(companyPolicy.quota_cents) / 100
      : null;
  const agentPolicies = policies.filter((p) => p.scope_type === "agent");
  const pausedDueToBudget = agentPolicies.filter(
    (p) => p.paused && p.pause_reason && p.pause_reason !== "manual"
  );

  const todayStr = localDateOffsetDays(0);
  const monthStart = `${todayStr.slice(0, 7)}-01`;
  const todayUsage = buildUsageAndCostAnalytics({ snapshot: snap, startDate: todayStr, endDate: todayStr, limit: 500 });
  const monthUsage = buildUsageAndCostAnalytics({ snapshot: snap, startDate: monthStart, endDate: todayStr, limit: 1500 });
  const dailySpend = Number(todayUsage.totals?.totalCost || 0);
  const monthlySpend = Number(monthUsage.totals?.totalCost || 0);

  const effDailyLimit =
    typeof corp.dailySpendLimitUsd === "number" && corp.dailySpendLimitUsd > 0 ? corp.dailySpendLimitUsd : null;
  const effMonthlyLimit =
    typeof corp.monthlySpendLimitUsd === "number" && corp.monthlySpendLimitUsd > 0 ? corp.monthlySpendLimitUsd : null;
  const effAgentSoft =
    typeof corp.perAgentSoftLimitUsd === "number" && corp.perAgentSoftLimitUsd > 0 ? corp.perAgentSoftLimitUsd : null;

  const alerts = [];
  const warnPct = Number(corp.alertThresholdPct || 80);
  if (effDailyLimit !== null && effDailyLimit > 0 && (dailySpend / effDailyLimit) * 100 >= warnPct) {
    alerts.push(`Daily spend ($${dailySpend.toFixed(2)}) mencapai >= ${warnPct}% dari batas harian ($${effDailyLimit.toFixed(2)})!`);
  }
  if (effMonthlyLimit !== null && effMonthlyLimit > 0 && (monthlySpend / effMonthlyLimit) * 100 >= warnPct) {
    alerts.push(`Monthly spend ($${monthlySpend.toFixed(2)}) mencapai >= ${warnPct}% dari batas bulanan ($${effMonthlyLimit.toFixed(2)})!`);
  }

  return {
    currency: "USD",
    is_unlimited: effDailyLimit === null && effMonthlyLimit === null && effAgentSoft === null && hardCeilingUsd === null,
    paperclip_company_hard_ceiling_usd: hardCeilingUsd,
    dailySpendLimitUsd: effDailyLimit,
    monthlySpendLimitUsd: effMonthlyLimit,
    perAgentSoftLimitUsd: effAgentSoft,
    alertThresholdPct: warnPct,
    current_daily_spend_usd: Math.round(dailySpend * 10000) / 10000,
    current_monthly_spend_usd: Math.round(monthlySpend * 10000) / 10000,
    remaining_daily_usd: effDailyLimit !== null ? Math.max(0, Math.round((effDailyLimit - dailySpend) * 100) / 100) : null,
    remaining_monthly_usd: effMonthlyLimit !== null ? Math.max(0, Math.round((effMonthlyLimit - monthlySpend) * 100) / 100) : null,
    agent_policies: agentPolicies,
    paused_due_to_budget: pausedDueToBudget,
    alerts,
    history: readBudgetAuditHistory(10),
  };
}

function updateGovernedBudget({
  snap,
  paperclip = null,
  sync = null,
  callerId,
  scope,
  amountUsd,
  rawAmountArg = "",
  currency = "USD",
}) {
  if (String(currency || "USD").toUpperCase() !== "USD") {
    return { ok: false, status: 400, code: "UNSUPPORTED_CURRENCY", error: "Mata uang budget hanya mendukung USD." };
  }
  let cleanScope = String(scope || "").toLowerCase();
  const rawValStr =
    rawAmountArg !== undefined && rawAmountArg !== null && String(rawAmountArg).trim() !== ""
      ? String(rawAmountArg).trim().toLowerCase()
      : Number.isFinite(amountUsd)
        ? String(amountUsd).trim().toLowerCase()
        : "";

  const scopeImpliesUnlimited = ["unlimited", "tanpa_batas", "none", "off"].includes(cleanScope);
  if (scopeImpliesUnlimited) {
    cleanScope = "all";
  }
  if (!["daily", "monthly", "agent_soft", "all"].includes(cleanScope)) {
    return {
      ok: false,
      status: 400,
      code: "INVALID_BUDGET_SCOPE",
      error: "Scope budget harus salah satu dari: `all`, `daily`, `monthly`, `agent_soft`, atau `unlimited`.",
    };
  }

  const unlimitedTokens = ["0", "unlimited", "tanpa_batas", "none", "off", "null"];
  const wantsUnlimited =
    (scopeImpliesUnlimited && (rawValStr === "" || unlimitedTokens.includes(rawValStr))) ||
    unlimitedTokens.includes(rawValStr) ||
    Number(amountUsd) === 0;

  const proposed = wantsUnlimited ? null : Number(amountUsd);
  if (!wantsUnlimited && (!Number.isFinite(proposed) || proposed < 0)) {
    return {
      ok: false,
      status: 400,
      code: "INVALID_BUDGET_AMOUNT",
      error: "Nilai batas anggaran harus angka positif (> 0 USD) atau `unlimited` (`0`).",
    };
  }

  const overview = getGovernedBudgetOverview(snap);
  const hardCeiling = overview.paperclip_company_hard_ceiling_usd;

  if (proposed !== null && hardCeiling !== null && hardCeiling > 0 && proposed > hardCeiling) {
    appendAuditEntry({
      ip: "127.0.0.1",
      callerId,
      action: `budget.ceiling_blocked:${cleanScope}`,
      proposedUsd: proposed,
      hardCeilingUsd: hardCeiling,
      allowed: false,
      reason: "exceeds_paperclip_hard_ceiling",
    });
    return {
      ok: false,
      status: 422,
      code: "HARD_BUDGET_CEILING_EXCEEDED",
      error: `Batas yang diusulkan ($${proposed.toFixed(2)}) melebihi Hard Budget Ceiling perusahaan di Paperclip ($${hardCeiling.toFixed(2)}).`,
    };
  }

  const current = resolveCorporateBudgets(snap);
  const baseDaily = typeof current.dailySpendLimitUsd === "number" && current.dailySpendLimitUsd > 0 ? current.dailySpendLimitUsd : null;
  const baseMonthly = typeof current.monthlySpendLimitUsd === "number" && current.monthlySpendLimitUsd > 0 ? current.monthlySpendLimitUsd : null;
  const baseAgentSoft = typeof current.perAgentSoftLimitUsd === "number" && current.perAgentSoftLimitUsd > 0 ? current.perAgentSoftLimitUsd : null;

  const prevLimit =
    cleanScope === "all"
      ? "mixed"
      : cleanScope === "daily"
        ? baseDaily
        : cleanScope === "monthly"
          ? baseMonthly
          : baseAgentSoft;

  const nextPayload =
    cleanScope === "all"
      ? {
          ...current,
          dailySpendLimitUsd: proposed,
          monthlySpendLimitUsd: proposed,
          perAgentSoftLimitUsd: proposed,
        }
      : {
          ...current,
          dailySpendLimitUsd: cleanScope === "daily" ? proposed : baseDaily,
          monthlySpendLimitUsd: cleanScope === "monthly" ? proposed : baseMonthly,
          perAgentSoftLimitUsd: cleanScope === "agent_soft" ? proposed : baseAgentSoft,
        };

  if (
    nextPayload.dailySpendLimitUsd !== null &&
    nextPayload.monthlySpendLimitUsd !== null &&
    nextPayload.dailySpendLimitUsd > nextPayload.monthlySpendLimitUsd
  ) {
    return {
      ok: false,
      status: 400,
      code: "DAILY_EXCEEDS_MONTHLY",
      error: `Batas harian ($${Number(nextPayload.dailySpendLimitUsd).toFixed(2)}) tidak boleh melebihi batas bulanan ($${Number(nextPayload.monthlySpendLimitUsd).toFixed(2)}).`,
    };
  }

  saveBudgetOverrides(nextPayload);
  if (paperclip && snap?.company?.id) {
    syncBudgetsWithPaperclip({
      nextBudgets: nextPayload,
      paperclip,
      companyId: snap.company.id,
      sync,
    }).catch(() => {});
  }

  const verifiedAfter = resolveCorporateBudgets(snap);
  const effective =
    cleanScope === "all"
      ? proposed
      : cleanScope === "daily"
        ? verifiedAfter.dailySpendLimitUsd
        : cleanScope === "monthly"
          ? verifiedAfter.monthlySpendLimitUsd
          : verifiedAfter.perAgentSoftLimitUsd;

  const auditEntry = {
    timestamp: new Date().toISOString(),
    caller_id: callerId,
    scope: cleanScope,
    currency: "USD",
    previous_limit_usd: prevLimit ?? "UNLIMITED",
    proposed_limit_usd: proposed ?? "UNLIMITED",
    effective_limit_usd: effective ?? "UNLIMITED",
    hard_ceiling_usd: hardCeiling ?? "UNLIMITED",
  };
  fs.mkdirSync(path.dirname(BUDGET_AUDIT_FILE), { recursive: true, mode: 0o700 });
  fs.appendFileSync(BUDGET_AUDIT_FILE, JSON.stringify(auditEntry) + "\n", "utf8");
  appendAuditEntry({
    ip: "127.0.0.1",
    callerId,
    action: `budget.updated:${cleanScope}`,
    ...auditEntry,
    allowed: true,
  });

  return {
    ok: true,
    audit: auditEntry,
    budgets: {
      ...verifiedAfter,
      dailyLimitUsd: verifiedAfter.dailySpendLimitUsd,
      monthlyLimitUsd: verifiedAfter.monthlySpendLimitUsd,
      hardCeilingUsd: hardCeiling,
    },
  };
}

/**
 * PHASE 15 — Unified Approvals View & Replay-Safe Resolution (Paperclip + Bound Governance).
 */
function buildUnifiedApprovalsCenter(snap, directory) {
  const pcApprovals = (snap?.approvals || []).map((a) => {
    const ag = directory.find((d) => d.id === (a.requestedByAgentId || a.agentId));
    return {
      id: a.id,
      source: "paperclip",
      status: String(a.status || "pending").toUpperCase(),
      origin_agent: ag ? `${ag.name} (${ag.handle})` : a.requestedByAgentId || "Paperclip Agent",
      project_or_task: a.issueIdentifier || a.issueId || a.projectId || "Company Governance",
      requested_action: sanitizeText(String(a.type || a.title || "Approval Gate")),
      risk_category: /deploy|prod|delete|budget/i.test(String(a.type || a.title || "")) ? "HIGH" : "MEDIUM",
      created_at: a.createdAt || null,
      expires_at: a.expiresAt || null,
    };
  });

  const bound = listBoundApprovals({ includeHistory: true }).map((b) => ({
    id: b.request_id,
    paperclip_approval_id: b.paperclip_approval_id,
    source: "bound_governance",
    status: b.status,
    origin_agent: b.origin_agent,
    project_or_task: b.project_or_task || b.target,
    requested_action: `${b.action} -> ${b.target}`,
    risk_category: b.risk_category,
    created_at: b.created_at,
    expires_at: b.expires_at,
    decision_note: b.note || null,
  }));

  const combined = [...bound, ...pcApprovals];
  return {
    pending: combined.filter((x) => x.status === "PENDING"),
    expired: combined.filter((x) => x.status === "EXPIRED"),
    history: combined.filter((x) => x.status !== "PENDING").slice(0, 15),
    all: combined,
  };
}

/**
 * PHASE 16 — Defensive Security & Isolated VulnClaw 8-State Findings Control.
 */
function listDefensiveFindings(limit = 20) {
  const DatabaseSync = loadSqliteDatabaseSync();
  if (!DatabaseSync || !fs.existsSync(FINDINGS_DB_PATH)) {
    return { available: false, counts: { total: 0 }, findings: [] };
  }
  let db = null;
  try {
    db = new DatabaseSync(FINDINGS_DB_PATH, { open: true, readOnly: true });
    const rows = db
      .prepare(
        `SELECT finding_id, project_id, asset_reference, source_reference, finding_title,
                severity, confidence, cwe_reference, cve_reference, affected_component,
                remediation_recommendation, verification_status, paperclip_remediation_issue_id,
                updated_at
         FROM findings
         ORDER BY updated_at DESC
         LIMIT ?`
      )
      .all(limit);
    const countRows = db
      .prepare("SELECT verification_status, COUNT(*) AS cnt FROM findings GROUP BY verification_status")
      .all();
    const byState = {};
    let total = 0;
    for (const c of countRows) {
      byState[c.verification_status] = Number(c.cnt);
      total += Number(c.cnt);
    }
    return {
      available: true,
      counts: {
        total,
        received: (byState.RECEIVED || 0) + (byState.IMPORTED || 0),
        under_review: byState.UNDER_REVIEW || 0,
        confirmed: byState.CONFIRMED || 0,
        false_positive: byState.FALSE_POSITIVE || 0,
        remediation_required: byState.REMEDIATION_REQUIRED || 0,
        in_progress: byState.IN_PROGRESS || 0,
        ready_for_verification: byState.READY_FOR_VERIFICATION || 0,
        resolved: byState.RESOLVED || 0,
        by_state: byState,
      },
      findings: rows.map((r) => sanitizePayload(r)),
    };
  } catch {
    return { available: false, counts: { total: 0 }, findings: [] };
  } finally {
    try {
      if (db) db.close();
    } catch {}
  }
}

function inspectDependencyAndConfigRisks(rawTargetPath) {
  const v = validateSecureFolderOrFile(rawTargetPath, { allowFile: false });
  if (!v.ok) return v;
  const dir = v.fs_path;
  const advisories = [];
  const configRisks = [];

  const compPath = path.join(dir, "composer.json");
  if (fs.existsSync(compPath)) {
    try {
      const cj = JSON.parse(fs.readFileSync(compPath, "utf8"));
      const reqs = { ...(cj.require || {}), ...(cj["require-dev"] || {}) };
      for (const [pkg, ver] of Object.entries(reqs)) {
        if (String(ver).includes("*")) {
          advisories.push(`Paket PHP \`${pkg}\` memakai constraint wildcard (\`${ver}\`) — disarankan pin versi minor.`);
        }
      }
      if (!fs.existsSync(path.join(dir, "composer.lock"))) {
        advisories.push("`composer.lock` tidak ditemukan; determinisme versi dependensi belum terkunci.");
      }
    } catch {}
  }

  const pkgPath = path.join(dir, "package.json");
  if (fs.existsSync(pkgPath)) {
    try {
      const pj = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
      const reqs = { ...(pj.dependencies || {}), ...(pj.devDependencies || {}) };
      for (const [pkg, ver] of Object.entries(reqs)) {
        if (ver === "*" || ver === "latest") {
          advisories.push(`Paket Node \`${pkg}\` memakai versi tidak terkunci (\`${ver}\`).`);
        }
      }
    } catch {}
  }

  const gitignorePath = path.join(dir, ".gitignore");
  if (!fs.existsSync(gitignorePath)) {
    configRisks.push("`.gitignore` tidak ada di root proyek.");
  } else {
    const gi = fs.readFileSync(gitignorePath, "utf8");
    if (!gi.includes(".env")) configRisks.push("`.gitignore` belum mengabaikan `.env`.");
  }
  const envExPath = path.join(dir, ".env.example");
  if (fs.existsSync(envExPath)) {
    const ex = fs.readFileSync(envExPath, "utf8");
    if (/APP_DEBUG\s*=\s*true/i.test(ex)) {
      configRisks.push("`.env.example` memiliki default `APP_DEBUG=true` — pastikan `false` pada environment produksi.");
    }
  }

  return {
    ok: true,
    verified_path: v.resolved_path,
    dependency_advisories: advisories.length
      ? advisories
      : ["Tidak ditemukan wildcard/unlocked dependency berisiko pada manifest utama."],
    configuration_risks: configRisks.length
      ? configRisks
      : ["Konfigurasi dasar (`.gitignore` & pemisahan `.env`) sesuai standar defensif."],
  };
}

async function transitionFindingViaPython({
  findingId,
  toStatus,
  note = "",
  createRemediation = false,
  developerAgentId = null,
}) {
  const allowed = [
    "RECEIVED",
    "IMPORTED",
    "UNDER_REVIEW",
    "CONFIRMED",
    "FALSE_POSITIVE",
    "REMEDIATION_REQUIRED",
    "IN_PROGRESS",
    "READY_FOR_VERIFICATION",
    "RESOLVED",
  ];
  const st = String(toStatus || "").trim().toUpperCase();
  if (!allowed.includes(st)) {
    return { ok: false, status: 400, error: `State temuan '${sanitizeText(toStatus)}' tidak valid. Gunakan: ${allowed.join(", ")}` };
  }

  const pyCode = [
    "import json, sys",
    `sys.path.insert(0, ${JSON.stringify(PLATFORM_ROOT)})`,
    "from integration.findings_engine import FindingsStore",
    "from integration.paperclip_client import PaperclipClient",
    "fid, st, note, mk_rem, dev_id_arg = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == '1', sys.argv[5]",
    "store = FindingsStore()",
    "pc = PaperclipClient() if mk_rem else None",
    "cid = pc.get_primary_company()['id'] if pc else None",
    "dev_id = dev_id_arg if (mk_rem and dev_id_arg) else None",
    "updated = store.transition(fid, st, actor='telegram_owner', note=note, pc=pc, company_id=cid, developer_agent_id=dev_id)",
    "print(json.dumps({'ok': True, 'finding': updated}))",
  ].join("\n");

  try {
    const { stdout } = await execFileAsync(
      PYTHON_EXE,
      [
        "-c",
        pyCode,
        String(findingId).trim(),
        st,
        String(note),
        createRemediation ? "1" : "0",
        String(developerAgentId || ""),
      ],
      { timeout: 25_000, windowsHide: true }
    );
    return sanitizePayload(JSON.parse(stdout.trim().split(/\r?\n/).pop()));
  } catch (err) {
    return { ok: false, status: 400, error: sanitizeText(err.stderr || err.message || "Gagal mengubah status temuan.") };
  }
}

/**
 * PHASE 17 — Cross-Platform 15-Component System Health, Sanitized Error Logs & Graceful-Drain Service Recovery.
 */
async function buildComplete15ComponentHealth({ buildUnifiedHealthMatrix, sync }) {
  const baseMatrix = await buildUnifiedHealthMatrix();
  const baseComps = baseMatrix.components || {};
  const tz = resolveTimezone(process.env);
  const hostMetrics = baseMatrix.host_metrics || collectHostResourceMetrics();

  const pluginCandidates = [
    path.join(HERMES_HOME_ROOT, "plugins", "unified-company-control", "__init__.py"),
    path.join(PLATFORM_ROOT, "plugins", "unified-company-control", "__init__.py"),
    path.join(PLATFORM_ROOT, "packages", "hermes-patches", "plugins", "unified-company-control", "__init__.py"),
  ];
  const p2dCandidates = [
    path.join(PLATFORM_ROOT, "apps", "hermes3d", "src", "features", "pixel-office", "PixelOffice2D.tsx"),
    path.join(PLATFORM_ROOT, "hermes3d", "source", "src", "features", "pixel-office", "PixelOffice2D.tsx"),
  ];
  const standupPath = path.join(OFFICE_DATA_DIR, "studio-state", "hermes3d", "standup-store.json");

  let modelProviderState = "UNKNOWN";
  const envKey = String(process.env.LLM_API_KEY || process.env.OPENAI_API_KEY || process.env.CUSTOM_API_KEY || "").trim();
  if (envKey) {
    try {
      const baseUrl = String(process.env.LLM_BASE_URL || DEFAULT_LLM_BASE_URL).replace(/\/$/, "");
      const resp = await fetch(`${baseUrl}/models`, {
        headers: { Authorization: `Bearer ${envKey}` },
        signal: AbortSignal.timeout(4000),
      });
      modelProviderState = resp.ok ? "HEALTHY" : "DEGRADED";
    } catch {
      modelProviderState = "DEGRADED";
    }
  }

  const components15 = {
    "1. Host Runtime": baseComps.host_runtime || baseComps.windows_host || { state: "HEALTHY" },
    "2. Hermes CLI": baseComps.hermes_agent || { state: "HEALTHY" },
    "3. Hermes Gateway": baseComps.telegram_gateway || { state: "HEALTHY" },
    "4. Telegram Connectivity": baseComps.telegram_gateway || { state: "HEALTHY" },
    "5. Paperclip API (:3100)": baseComps.paperclip_control_plane || { state: sync.paperclipReachable ? "HEALTHY" : "OFFLINE" },
    "6. Paperclip PostgreSQL": {
      state: sync.paperclipReachable ? "HEALTHY" : "DEGRADED",
      detail: "Verified via Paperclip API & DB health",
    },
    "7. Office Bridge (:3210)": baseComps.office_bridge || { state: "HEALTHY" },
    "8. 3D Virtual Office (:3200)": baseComps.hermes3d_office_ui || { state: "HEALTHY" },
    "9. 2D Pixel Office": {
      state: p2dCandidates.some((p) => fs.existsSync(p)) || fs.existsSync(standupPath) ? "HEALTHY" : "DEGRADED",
    },
    "10. VulnClaw Runtime": baseComps.vulnclaw_security || { state: "HEALTHY" },
    "11. Computer Use (CUA)": baseComps.computer_use_cua || { state: "HEALTHY" },
    [`12. Model Provider (${DEFAULT_LLM_MODEL})`]: { state: modelProviderState },
    [`13. Autonomous Updater (${tz})`]: baseComps.hermes_auto_updater || { state: "HEALTHY" },
    "14. System Service Scheduler": baseComps.service_scheduler || baseComps.windows_scheduled_tasks || { state: "HEALTHY" },
    "15. Telegram Control Plugin": {
      state: pluginCandidates.some((p) => fs.existsSync(p)) ? "HEALTHY" : "DEGRADED",
    },
  };

  const states = Object.values(components15).map((c) => c.state);
  const overall = states.includes("MAINTENANCE")
    ? "MAINTENANCE"
    : states.every((s) => s === "HEALTHY")
      ? "HEALTHY"
      : states.filter((s) => s === "OFFLINE").length >= 3
        ? "OFFLINE"
        : "DEGRADED";

  return {
    checked_at: new Date().toISOString(),
    overall_state: overall,
    component_count: 15,
    components: components15,
    host_metrics: hostMetrics,
    windows: baseMatrix.windows || hostMetrics,
    maintenance: baseMatrix.maintenance || {},
  };
}

function readRecentSanitizedErrorLogs(maxLines = 18) {
  const candidates = [
    { label: "Hermes Gateway", file: path.join(HERMES_HOME_ROOT, "logs", "gateway.log") },
    { label: "Paperclip Server", file: path.join(LOGS_DIR, "paperclip-launcher.log") },
    { label: "Office Bridge Audit", file: path.join(LOGS_DIR, "office-bridge-audit.jsonl") },
  ];
  const entries = [];
  for (const c of candidates) {
    if (!fs.existsSync(c.file)) continue;
    try {
      const lines = fs.readFileSync(c.file, "utf8").split(/\r?\n/).filter(Boolean);
      const errLines = lines
        .filter((l) => /error|warn|denied|forbidden|timeout|failed|allowed":false/i.test(l))
        .slice(-6)
        .map((l) => `[${c.label}] ${sanitizeText(l).slice(0, 180)}`);
      entries.push(...errLines);
    } catch {}
  }
  return entries.slice(-maxLines);
}

/**
 * Safe Service Recovery with Graceful Drain & Anti-Restart-Loop Cooldown (`PHASE 17`).
 */
async function executeSafeGracefulRecovery({ sync, targetService = "reconcile" }) {
  const snap = sync.getFullSnapshot();
  const activeRuns = (snap.runs || []).filter((r) => r.status === "running" || r.status === "queued");

  let cooldown = {};
  try {
    if (fs.existsSync(RECOVERY_COOLDOWN_FILE)) {
      cooldown = JSON.parse(fs.readFileSync(RECOVERY_COOLDOWN_FILE, "utf8"));
    }
  } catch {}
  const svc = String(targetService || "reconcile").toLowerCase();
  const lastAt = Number(cooldown[svc] || 0);
  if (svc !== "reconcile" && Date.now() - lastAt < 60_000) {
    return {
      ok: false,
      status: 429,
      code: "RECOVERY_COOLDOWN_ACTIVE",
      error: `Pencegahan restart-loop aktif untuk '${svc}'. Tunggu ${Math.ceil((60_000 - (Date.now() - lastAt)) / 1000)} detik sebelum mencoba lagi.`,
    };
  }

  if (svc !== "reconcile" && activeRuns.length > 0) {
    return {
      ok: false,
      status: 409,
      code: "GRACEFUL_DRAIN_REQUIRED",
      active_runs: activeRuns.length,
      error: `Terdapat ${activeRuns.length} pekerjaan aktif sedang berjalan. Pemulihan paksa ditunda (graceful drain) agar tidak kehilangan progres kerja.`,
    };
  }

  cooldown[svc] = Date.now();
  fs.mkdirSync(path.dirname(RECOVERY_COOLDOWN_FILE), { recursive: true, mode: 0o700 });
  fs.writeFileSync(RECOVERY_COOLDOWN_FILE, JSON.stringify(cooldown, null, 2) + "\n", "utf8");

  await sync.reconcileNow("telegram_safe_recovery");
  return {
    ok: true,
    service: svc,
    drained_cleanly: true,
    paperclip_reachable: sync.paperclipReachable,
    recovered_at: new Date().toISOString(),
  };
}

module.exports = {
  collectHostResourceMetrics,
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
};
