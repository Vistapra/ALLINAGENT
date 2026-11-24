"use strict";

/**
 * Official Cross-Platform Paperclip Runtime Adapter for ALLINAGENT Office Bridge.
 *
 * - Communicates with Paperclip exclusively via official REST API (`PAPERCLIP_BASE_URL/api/*`)
 *   and official Live Events WebSocket (`PAPERCLIP_WS_URL/api/companies/:companyId/events/ws`).
 * - Propagates `X-Correlation-Id` and enforces bounded fetch timeouts & retries.
 * - Preserves `cost_usd: null` honestly as `COST UNKNOWN` / `UNPRICED USAGE` (never `$0.00`).
 * - Supports projects CRUD, company skills inspection, and bidirectional budget sync.
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const {
  PLATFORM_ROOT,
  SECRETS_DIR,
  HERMES_PROFILES_DIR,
  PAPERCLIP_BASE_URL,
  PAPERCLIP_COMPANY_ID,
  DEFAULT_LLM_MODEL,
  deriveWsUrlFromHttp,
  loadSqliteDatabaseSync,
} = require("../contracts/paths");
const { mapPaperclipAgentIdentity, DEPARTMENTS } = require("../contracts/agent-identity");
const { sanitizePayload, sanitizeText } = require("../contracts/redaction");

const BOARD_KEY_PATH = path.resolve(path.join(SECRETS_DIR, "paperclip-board-key.json"));
const OBSERVER_KEY_CACHE_PATH = path.resolve(path.join(SECRETS_DIR, "paperclip-ws-observer-key.json"));
const CLEAR_ORPHAN_RUNS_SCRIPT = path.resolve(path.join(PLATFORM_ROOT, "scripts", "clear-orphan-cancelled-runs.cjs"));

function clearOrphanRunHoldsIfPresent() {
  if (process.platform !== "win32" || !fs.existsSync(CLEAR_ORPHAN_RUNS_SCRIPT)) return;
  try {
    execFileSync(process.execPath, [CLEAR_ORPHAN_RUNS_SCRIPT], {
      timeout: 6000,
      stdio: "ignore",
      windowsHide: true,
    });
  } catch {}
}

function loadBoardToken() {
  for (const key of ["PAPERCLIP_BOARD_TOKEN", "PAPERCLIP_BOARD_KEY", "PAPERCLIP_API_KEY"]) {
    if (process.env[key] && process.env[key].trim()) {
      return process.env[key].trim();
    }
  }
  if (!fs.existsSync(BOARD_KEY_PATH)) {
    return "";
  }
  try {
    const raw = JSON.parse(fs.readFileSync(BOARD_KEY_PATH, "utf8"));
    return String(raw.token || raw.apiKey || "").trim();
  } catch {
    return "";
  }
}

function inspectRunEvidenceText(rawText) {
  const text = String(rawText || "");
  if (!text.trim()) return { verifiedToolKind: null, verifiedTools: [] };

  const verifiedTools = [];
  if (/\b(write_file|edit_file|patch|git\s+commit|git\s+checkout\s+-b)\b/i.test(text)) {
    verifiedTools.push("code_edit");
  }
  if (/\b(unittest|pytest|vitest|npm\s+test|node\s+--test|Ran\s+\d+\s+tests?)\b/i.test(text)) {
    verifiedTools.push("test_execution");
  }
  if (/\b(py_compile|tsc\s+--noEmit|next\s+build|npm\s+run\s+build)\b/i.test(text)) {
    verifiedTools.push("build_verification");
  }
  if (/\b(codescan|search_files|grep|rg\s+|read_file)\b/i.test(text)) {
    verifiedTools.push("code_inspection");
  }

  let verifiedToolKind = null;
  const tail = text.slice(-1800);
  if (/\b(unittest|pytest|vitest|node\s+--test|Ran\s+\d+\s+tests?)\b/i.test(tail)) {
    verifiedToolKind = "testing";
  } else if (/\b(py_compile|tsc\s+--noEmit|next\s+build|npm\s+run\s+build)\b/i.test(tail)) {
    verifiedToolKind = "building";
  } else if (/\b(write_file|edit_file|patch|git\s+commit)\b/i.test(tail)) {
    verifiedToolKind = "coding";
  } else if (/\b(codescan|search_files|grep|read_file)\b/i.test(tail)) {
    verifiedToolKind = "researching";
  }

  return {
    verifiedToolKind,
    verifiedTestCommand: verifiedTools.includes("test_execution"),
    verifiedBuildCommand: verifiedTools.includes("build_verification"),
    verifiedTools,
  };
}

class PaperclipRuntimeAdapter {
  constructor(options = {}) {
    this.baseUrl = String(options.baseUrl || PAPERCLIP_BASE_URL)
      .trim()
      .replace(/\/$/, "");
    this.wsBaseUrl = deriveWsUrlFromHttp(
      options.wsBaseUrl || (options.baseUrl ? options.baseUrl : process.env.PAPERCLIP_WS_URL || this.baseUrl)
    );
    this.apiKey = options.apiKey !== undefined ? options.apiKey : loadBoardToken();
    this.timeoutMs = options.timeoutMs || 15_000;
    this.maxRetries = options.maxRetries !== undefined ? Number(options.maxRetries) : 2;
    this.preferredCompanyId = options.companyId || PAPERCLIP_COMPANY_ID || null;
    this.companyCache = null;
    this.runEvidenceCache = new Map();
  }

  async request(method, apiPath, body = undefined, extraHeaders = {}) {
    const upperMethod = String(method || "GET").toUpperCase();
    const isRetryableMethod =
      upperMethod === "GET" || upperMethod === "HEAD" || Boolean(extraHeaders["Idempotency-Key"]);
    const attempts = isRetryableMethod ? Math.max(1, this.maxRetries + 1) : 1;
    const correlationId =
      extraHeaders["X-Correlation-Id"] ||
      extraHeaders["x-correlation-id"] ||
      `pc-${crypto.randomUUID()}`;

    let lastErr = null;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const headers = {
          Accept: "application/json",
          Origin: this.baseUrl,
          "X-Correlation-Id": correlationId,
          ...(this.apiKey ? { Authorization: `Bearer ${this.apiKey}` } : {}),
          ...extraHeaders,
        };
        if (body !== undefined) {
          headers["Content-Type"] = "application/json";
        }
        const res = await fetch(`${this.baseUrl}${apiPath}`, {
          method: upperMethod,
          headers,
          body: body !== undefined ? JSON.stringify(body) : undefined,
          signal: controller.signal,
        });
        const text = await res.text();
        let parsed = null;
        if (text) {
          try {
            parsed = JSON.parse(text);
          } catch {
            parsed = text;
          }
        }
        if (
          isRetryableMethod &&
          attempt + 1 < attempts &&
          (res.status === 502 || res.status === 503 || res.status === 504)
        ) {
          await new Promise((r) => setTimeout(r, 150 * Math.pow(2, attempt)));
          continue;
        }
        return {
          ok: res.ok,
          status: res.status,
          data: parsed,
          correlationId: res.headers?.get("x-correlation-id") || correlationId,
        };
      } catch (err) {
        lastErr = err;
        if (attempt + 1 < attempts) {
          await new Promise((r) => setTimeout(r, 150 * Math.pow(2, attempt)));
          continue;
        }
      } finally {
        clearTimeout(timer);
      }
    }
    throw lastErr || new Error(`Paperclip ${upperMethod} ${apiPath} request failed.`);
  }

  async must(method, apiPath, body = undefined, extraHeaders = {}) {
    const res = await this.request(method, apiPath, body, extraHeaders);
    if (!res.ok) {
      const err = new Error(`Paperclip ${method} ${apiPath} failed with HTTP ${res.status}`);
      err.status = res.status;
      err.details = sanitizePayload(res.data);
      throw err;
    }
    return res.data;
  }

  async checkHealth(correlationId = null) {
    try {
      const hdrs = correlationId ? { "X-Correlation-Id": correlationId } : {};
      const data = await this.must("GET", "/api/health", undefined, hdrs);
      return { reachable: data?.status === "ok" || Boolean(data), health: sanitizePayload(data) };
    } catch (err) {
      return { reachable: false, error: sanitizeText(err.message) };
    }
  }

  async getPrimaryCompany() {
    const companies = (await this.must("GET", "/api/companies")) || [];
    const desiredId = this.preferredCompanyId || process.env.PAPERCLIP_COMPANY_ID || null;
    const desiredName = String(process.env.COMPANY_NAME || "").trim().toLowerCase();
    const found =
      (desiredId && companies.find((c) => c && String(c.id) === String(desiredId))) ||
      (desiredName && companies.find((c) => c && String(c.name || "").toLowerCase() === desiredName)) ||
      companies[0];
    if (!found) {
      throw new Error("Primary company not found in Paperclip.");
    }
    this.companyCache = found;
    return found;
  }

  async getOrganizationSnapshot() {
    const company = await this.getPrimaryCompany();
    const cid = company.id;
    const [orgTree, rawAgents, projects, issues, liveRuns, recentRuns, budgetOverview, approvals] = await Promise.all([
      this.must("GET", `/api/companies/${encodeURIComponent(cid)}/org`).catch(() => []),
      this.must("GET", `/api/companies/${encodeURIComponent(cid)}/agents`),
      this.must("GET", `/api/companies/${encodeURIComponent(cid)}/projects`).catch(() => []),
      this.must("GET", `/api/companies/${encodeURIComponent(cid)}/issues`).catch(() => []),
      this.must("GET", `/api/companies/${encodeURIComponent(cid)}/live-runs`).catch(() => []),
      this.must("GET", `/api/companies/${encodeURIComponent(cid)}/heartbeat-runs?limit=60`).catch(() => []),
      this.must("GET", `/api/companies/${encodeURIComponent(cid)}/budgets/overview`).catch(() => null),
      this.must("GET", `/api/companies/${encodeURIComponent(cid)}/approvals`).catch(() => []),
    ]);

    const seenIds = new Set();
    const uniqueRawAgents = [];
    for (const a of rawAgents || []) {
      if (a && a.id && !seenIds.has(a.id)) {
        seenIds.add(a.id);
        uniqueRawAgents.push(a);
      }
    }

    const mappedAgents = uniqueRawAgents.map((a, idx) => mapPaperclipAgentIdentity(a, uniqueRawAgents, idx));

    return {
      company: {
        id: company.id,
        name: company.name,
        issuePrefix: company.issuePrefix || "UNI",
        status: company.status || "active",
      },
      departments: Object.values(DEPARTMENTS),
      orgTree: sanitizePayload(orgTree),
      rawAgents: uniqueRawAgents,
      agents: mappedAgents,
      projects: sanitizePayload(projects || []),
      issues: sanitizePayload(issues || []),
      liveRuns: sanitizePayload(liveRuns || []),
      recentRuns: sanitizePayload(recentRuns || []),
      budgetOverview: this.formatBudgetGovernance(budgetOverview, recentRuns || [], mappedAgents),
      approvals: sanitizePayload(approvals || []),
      observedAt: new Date().toISOString(),
    };
  }

  formatBudgetGovernance(budgetOverview, recentRuns = [], mappedAgents = []) {
    const policies = Array.isArray(budgetOverview?.policies) ? budgetOverview.policies : [];
    const formattedPolicies = policies.map((pol) => {
      const unpricedCount = Number(pol.unpricedEventCount || 0);
      const observedCents = Number(pol.observedAmount || 0);
      const hasUnpricedOnly = unpricedCount > 0 && observedCents === 0;
      return {
        policy_id: pol.policyId,
        scope_type: pol.scopeType,
        scope_id: pol.scopeId,
        scope_name: pol.scopeName,
        quota_cents: pol.amount,
        observed_cents: observedCents,
        unpriced_event_count: unpricedCount,
        unpriced_usage_policy: pol.unpricedUsagePolicy || "unknown",
        cost_status: hasUnpricedOnly
          ? "COST UNKNOWN"
          : observedCents > 0
            ? "PRICED"
            : unpricedCount === 0
              ? "COST UNKNOWN"
              : "UNPRICED USAGE",
        usage_label:
          hasUnpricedOnly || observedCents === 0
            ? "UNPRICED USAGE"
            : `${(observedCents / 100).toFixed(2)} USD`,
        paused: Boolean(pol.paused),
        pause_reason: pol.pauseReason || null,
        is_active: pol.isActive !== false,
        hard_stop_enabled: Boolean(pol.hardStopEnabled),
        window_start: pol.windowStart,
        window_end: pol.windowEnd,
      };
    });

    const usageByAgent = {};
    let totalTokens = 0;
    let totalDurationMs = 0;
    for (const run of recentRuns) {
      const aid = run.agentId;
      if (!aid) continue;
      if (!usageByAgent[aid]) {
        usageByAgent[aid] = {
          agent_id: aid,
          run_count: 0,
          succeeded_runs: 0,
          failed_runs: 0,
          cancelled_runs: 0,
          input_tokens: 0,
          output_tokens: 0,
          total_tokens: 0,
          total_duration_ms: 0,
          cost_usd: null,
          cost_label: "COST UNKNOWN",
          usage_classification: "UNPRICED USAGE",
        };
      }
      const bucket = usageByAgent[aid];
      bucket.run_count += 1;
      const st = String(run.status || "").toLowerCase();
      if (st === "succeeded") bucket.succeeded_runs += 1;
      else if (st === "failed" || st === "timed_out") bucket.failed_runs += 1;
      else if (st === "cancelled" || st === "canceled") bucket.cancelled_runs += 1;

      const usage = run.usageJson || run.resultJson?.usage || {};
      const inTok = Number(usage.inputTokens ?? usage.prompt_tokens ?? 0) || 0;
      const outTok = Number(usage.outputTokens ?? usage.completion_tokens ?? 0) || 0;
      const totTok = Number(usage.totalTokens ?? usage.total_tokens ?? inTok + outTok) || 0;
      bucket.input_tokens += inTok;
      bucket.output_tokens += outTok;
      bucket.total_tokens += totTok;
      totalTokens += totTok;

      if (run.startedAt && run.finishedAt) {
        const dur = Math.max(0, Date.parse(run.finishedAt) - Date.parse(run.startedAt));
        if (Number.isFinite(dur)) {
          bucket.total_duration_ms += dur;
          totalDurationMs += dur;
        }
      }
    }

    const DatabaseSync = loadSqliteDatabaseSync();
    if (DatabaseSync && Array.isArray(mappedAgents) && mappedAgents.length > 0 && fs.existsSync(HERMES_PROFILES_DIR)) {
      try {
        let sqliteFleetTokens = 0;
        for (const ag of mappedAgents) {
          if (!ag?.runtime_profile_reference) continue;
          const dbFile = path.join(HERMES_PROFILES_DIR, ag.runtime_profile_reference, "state.db");
          if (!fs.existsSync(dbFile)) continue;
          const db = new DatabaseSync(dbFile, { open: true, readOnly: true });
          try {
            const agg = db
              .prepare(
                "SELECT COUNT(*) as c, COALESCE(SUM(input_tokens),0) as inp, COALESCE(SUM(output_tokens),0) as outp, COALESCE(SUM(cache_read_tokens),0) as cr, COALESCE(SUM(cache_write_tokens),0) as cw FROM sessions"
              )
              .get();
            const inT = Number(agg?.inp) || 0;
            const outT = Number(agg?.outp) || 0;
            const cacheT = (Number(agg?.cr) || 0) + (Number(agg?.cw) || 0);
            const sumT = inT + outT + cacheT;
            if (sumT > 0) {
              const aid = ag.paperclip_agent_id;
              if (!usageByAgent[aid]) {
                usageByAgent[aid] = {
                  agent_id: aid,
                  run_count: Number(agg?.c) || 0,
                  succeeded_runs: Number(agg?.c) || 0,
                  failed_runs: 0,
                  cancelled_runs: 0,
                  input_tokens: 0,
                  output_tokens: 0,
                  total_tokens: 0,
                  total_duration_ms: 0,
                  cost_usd: null,
                  cost_label: "COST UNKNOWN",
                  usage_classification: "UNPRICED USAGE",
                };
              }
              if (usageByAgent[aid].total_tokens < sumT) {
                usageByAgent[aid].input_tokens = inT;
                usageByAgent[aid].output_tokens = outT;
                usageByAgent[aid].total_tokens = sumT;
              }
              sqliteFleetTokens += sumT;
            }
          } finally {
            db.close();
          }
        }
        if (sqliteFleetTokens > totalTokens) {
          totalTokens = sqliteFleetTokens;
        }
      } catch {}
    }

    return {
      provider_model: DEFAULT_LLM_MODEL,
      cost_transparency_status: "COST UNKNOWN",
      usage_mode_label: "UNPRICED USAGE",
      total_observed_tokens: totalTokens,
      total_execution_duration_ms: totalDurationMs,
      paused_agent_count: budgetOverview?.pausedAgentCount ?? 0,
      pending_approval_count: budgetOverview?.pendingApprovalCount ?? 0,
      active_incidents: sanitizePayload(budgetOverview?.activeIncidents || []),
      policies: formattedPolicies,
      per_agent_usage: usageByAgent,
    };
  }

  async getVerifiedRunDetails(runId) {
    if (!runId) return { events: [], logExcerpt: "", evidence: { verifiedToolKind: null, verifiedTools: [] } };
    const cached = this.runEvidenceCache.get(runId);
    if (cached && Date.now() - cached.at < 2500) {
      return cached.value;
    }

    const [eventsRes, logRes] = await Promise.all([
      this.request("GET", `/api/heartbeat-runs/${encodeURIComponent(runId)}/events`),
      this.request("GET", `/api/heartbeat-runs/${encodeURIComponent(runId)}/log`),
    ]);

    const events = Array.isArray(eventsRes.data) ? eventsRes.data : eventsRes.data?.events || [];
    let logText = "";
    if (typeof logRes.data === "string") {
      logText = logRes.data;
    } else if (logRes.data && typeof logRes.data === "object") {
      logText = String(logRes.data.content || logRes.data.log || JSON.stringify(logRes.data));
    }
    const combinedForDetection = [
      logText,
      ...events.map((e) => (typeof e === "string" ? e : JSON.stringify(e))),
    ].join("\n");

    const sanitizedExcerpt = sanitizeText(combinedForDetection.slice(-4000));
    const evidence = inspectRunEvidenceText(sanitizedExcerpt);
    const value = {
      events: sanitizePayload(events.slice(-40)),
      logExcerpt: sanitizedExcerpt,
      evidence,
    };
    this.runEvidenceCache.set(runId, { at: Date.now(), value });
    if (this.runEvidenceCache.size > 200) {
      const firstKey = this.runEvidenceCache.keys().next().value;
      if (firstKey) this.runEvidenceCache.delete(firstKey);
    }
    return value;
  }

  async ensureLiveEventsWsToken(companyId, ceoAgentId) {
    if (fs.existsSync(OBSERVER_KEY_CACHE_PATH)) {
      try {
        const cached = JSON.parse(fs.readFileSync(OBSERVER_KEY_CACHE_PATH, "utf8"));
        if (cached && cached.companyId === companyId && typeof cached.token === "string" && cached.token.length > 10) {
          return cached.token;
        }
      } catch {}
    }
    if (!ceoAgentId) return null;
    const created = await this.must("POST", `/api/agents/${encodeURIComponent(ceoAgentId)}/keys`, {
      name: "office-bridge-live-ws-observer",
    });
    const token = created?.token || created?.key || null;
    if (token) {
      fs.mkdirSync(path.dirname(OBSERVER_KEY_CACHE_PATH), { recursive: true, mode: 0o700 });
      fs.writeFileSync(
        OBSERVER_KEY_CACHE_PATH,
        JSON.stringify(
          { companyId, agentId: ceoAgentId, keyId: created.id, token, createdAt: new Date().toISOString() },
          null,
          2
        ) + "\n",
        { encoding: "utf8", mode: 0o600 }
      );
    }
    return token;
  }

  // --- Projects & Skills ---

  async listProjects(companyId) {
    const list = await this.must("GET", `/api/companies/${encodeURIComponent(companyId)}/projects`);
    return sanitizePayload(Array.isArray(list) ? list : []);
  }

  async createProject(companyId, payload = {}) {
    const cleanName = sanitizeText(String(payload.name || "").trim()).slice(0, 120);
    if (!cleanName) {
      const err = new Error("Project name is required.");
      err.status = 400;
      throw err;
    }
    const cleanBody = {
      name: cleanName,
      status: payload.status || "in_progress",
      ...(payload.description !== undefined ? { description: sanitizeText(String(payload.description)) } : {}),
    };
    return sanitizePayload(
      await this.must("POST", `/api/companies/${encodeURIComponent(companyId)}/projects`, cleanBody)
    );
  }

  async ensureProject(companyId, projectName, extraPayload = {}) {
    const cleanName = sanitizeText(String(projectName || "").trim()).slice(0, 100);
    if (!cleanName) return null;
    const existing = (await this.listProjects(companyId).catch(() => [])) || [];
    const found = existing.find((p) => String(p.name || "").toLowerCase() === cleanName.toLowerCase());
    if (found) return sanitizePayload(found);
    return this.createProject(companyId, { ...extraPayload, name: cleanName });
  }

  async updateProject(projectId, patch = {}) {
    const cleanPatch = {};
    if (patch.name) cleanPatch.name = sanitizeText(String(patch.name)).slice(0, 120);
    if (patch.status) cleanPatch.status = String(patch.status);
    if (patch.description !== undefined) cleanPatch.description = sanitizeText(String(patch.description));
    const res = await this.request("PATCH", `/api/projects/${encodeURIComponent(projectId)}`, cleanPatch);
    if (!res.ok) {
      const err = new Error(`Paperclip PATCH /api/projects/${projectId} failed with HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return sanitizePayload(res.data);
  }

  async listCompanySkills(companyId) {
    if (!companyId) return [];
    const res = await this.request("GET", `/api/companies/${encodeURIComponent(companyId)}/skills`);
    if (!res.ok || !res.data) return [];
    const items = Array.isArray(res.data) ? res.data : Array.isArray(res.data.skills) ? res.data.skills : [];
    return sanitizePayload(items);
  }

  async syncCompanyBudget(companyId, budgetPayload = {}) {
    if (!companyId) return { synced: false };
    const monthlyUsd =
      typeof budgetPayload.monthlySpendLimitUsd === "number" && budgetPayload.monthlySpendLimitUsd > 0
        ? budgetPayload.monthlySpendLimitUsd
        : null;
    const amountCents = monthlyUsd !== null ? Math.round(monthlyUsd * 100) : 0;
    const body = {
      scopeType: "company",
      scopeId: companyId,
      amount: amountCents,
      isActive: monthlyUsd !== null,
      hardStopEnabled: false,
    };
    const res = await this.request("PUT", `/api/companies/${encodeURIComponent(companyId)}/budgets`, body).catch(
      () => ({ ok: false })
    );
    if (res.ok) {
      return { synced: true, data: sanitizePayload(res.data) };
    }
    const postRes = await this.request(
      "POST",
      `/api/companies/${encodeURIComponent(companyId)}/budgets/policies`,
      body
    ).catch(() => ({ ok: false }));
    return { synced: Boolean(postRes.ok), data: postRes.ok ? sanitizePayload(postRes.data) : null };
  }

  // --- Tasks, Agents, Runs & Approvals ---

  async createTask(companyId, payload, idempotencyKey = null, correlationId = null) {
    const hdrs = {};
    if (idempotencyKey) {
      hdrs["Idempotency-Key"] = crypto.createHash("sha256").update(String(idempotencyKey)).digest("hex").slice(0, 32);
    }
    if (correlationId) {
      hdrs["X-Correlation-Id"] = String(correlationId);
    }
    const cleanPayload = {
      title: sanitizeText(String(payload.title || "").trim()).slice(0, 200),
      description: sanitizeText(String(payload.description || "").trim()),
      status: payload.status || "todo",
      priority: ["critical", "high", "medium", "low"].includes(payload.priority) ? payload.priority : "medium",
    };
    if (payload.assigneeAgentId) cleanPayload.assigneeAgentId = String(payload.assigneeAgentId);
    if (payload.projectId) cleanPayload.projectId = String(payload.projectId);
    if (payload.parentId) cleanPayload.parentId = String(payload.parentId);
    if (cleanPayload.status === "blocked" && payload.unblockDescriptor) {
      cleanPayload.unblockDescriptor = payload.unblockDescriptor;
    }
    return sanitizePayload(
      await this.must("POST", `/api/companies/${encodeURIComponent(companyId)}/issues`, cleanPayload, hdrs)
    );
  }

  async updateTask(issueId, patch) {
    const cleanPatch = {};
    if (patch.status) cleanPatch.status = String(patch.status);
    if (patch.priority) cleanPatch.priority = String(patch.priority);
    if (patch.assigneeAgentId !== undefined) cleanPatch.assigneeAgentId = patch.assigneeAgentId;
    if (patch.title) cleanPatch.title = sanitizeText(String(patch.title)).slice(0, 200);
    if (patch.description !== undefined) cleanPatch.description = sanitizeText(String(patch.description));
    if (cleanPatch.status === "blocked") {
      cleanPatch.unblockDescriptor = patch.unblockDescriptor || {
        kind: "manual_gate",
        reason: sanitizeText(patch.blockReason || "Awaiting owner review or prerequisite completion"),
      };
    }
    return sanitizePayload(await this.must("PATCH", `/api/issues/${encodeURIComponent(issueId)}`, cleanPatch));
  }

  async addTaskComment(issueId, bodyText) {
    const safeBody = sanitizeText(String(bodyText || "").trim());
    return sanitizePayload(
      await this.must("POST", `/api/issues/${encodeURIComponent(issueId)}/comments`, { body: safeBody })
    );
  }

  async getTaskDetail(issueId) {
    const [issue, comments, runsRes] = await Promise.all([
      this.must("GET", `/api/issues/${encodeURIComponent(issueId)}`),
      this.must("GET", `/api/issues/${encodeURIComponent(issueId)}/comments`).catch(() => []),
      this.must("GET", `/api/issues/${encodeURIComponent(issueId)}/live-runs`).catch(() => []),
    ]);
    return {
      issue: sanitizePayload(issue),
      comments: sanitizePayload(comments),
      liveRuns: sanitizePayload(runsRes),
    };
  }

  async pauseAgent(agentId) {
    const res = await this.request("POST", `/api/agents/${encodeURIComponent(agentId)}/pause`, {});
    if (!res.ok && res.status !== 409) {
      throw new Error(`Pause agent failed (${res.status})`);
    }
    clearOrphanRunHoldsIfPresent();
    let latest = await this.must("GET", `/api/agents/${encodeURIComponent(agentId)}`);
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline && latest.lifecycleState === "pausing") {
      clearOrphanRunHoldsIfPresent();
      await new Promise((r) => setTimeout(r, 350));
      latest = await this.must("GET", `/api/agents/${encodeURIComponent(agentId)}`);
    }
    return sanitizePayload(latest);
  }

  async resumeAgent(agentId) {
    clearOrphanRunHoldsIfPresent();
    let cur = await this.must("GET", `/api/agents/${encodeURIComponent(agentId)}`);
    const waitSettle = Date.now() + 6000;
    while (Date.now() < waitSettle && cur.lifecycleState === "pausing") {
      clearOrphanRunHoldsIfPresent();
      await new Promise((r) => setTimeout(r, 350));
      cur = await this.must("GET", `/api/agents/${encodeURIComponent(agentId)}`);
    }
    const res = await this.request("POST", `/api/agents/${encodeURIComponent(agentId)}/resume`, {});
    if (!res.ok && res.status !== 409) {
      throw new Error(`Resume agent failed (${res.status})`);
    }
    let latest = await this.must("GET", `/api/agents/${encodeURIComponent(agentId)}`);
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline && (latest.status === "paused" || latest.lifecycleState === "pausing")) {
      clearOrphanRunHoldsIfPresent();
      await new Promise((r) => setTimeout(r, 350));
      await this.request("POST", `/api/agents/${encodeURIComponent(agentId)}/resume`, {}).catch(() => {});
      latest = await this.must("GET", `/api/agents/${encodeURIComponent(agentId)}`);
    }
    return sanitizePayload(latest);
  }

  async wakeAgent(agentId, reason = "office_dispatch", contextSnapshot = {}) {
    return sanitizePayload(
      await this.must("POST", `/api/agents/${encodeURIComponent(agentId)}/wakeup`, {
        source: "on_demand",
        triggerDetail: "manual",
        reason,
        contextSnapshot: sanitizePayload(contextSnapshot),
      })
    );
  }

  async cancelRun(runId) {
    const res = await this.request("POST", `/api/heartbeat-runs/${encodeURIComponent(runId)}/cancel`, {});
    if (!res.ok && res.status !== 409) {
      throw new Error(`Cancel run failed (${res.status})`);
    }
    clearOrphanRunHoldsIfPresent();
    return sanitizePayload(await this.must("GET", `/api/heartbeat-runs/${encodeURIComponent(runId)}`));
  }

  async resolveApproval(approvalId, decision, note = "") {
    const norm = String(decision || "").toLowerCase();
    const action = norm === "approve" || norm === "allow-once" || norm === "allow-always" ? "approve" : "reject";
    return sanitizePayload(
      await this.must("POST", `/api/approvals/${encodeURIComponent(approvalId)}/${action}`, {
        decisionNote: sanitizeText(note || `Resolved by Owner via ALLINAGENT Virtual Office (${action}).`),
      })
    );
  }
}

module.exports = {
  PaperclipRuntimeAdapter,
  inspectRunEvidenceText,
};
