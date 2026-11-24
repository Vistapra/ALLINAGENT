"use strict";

/**
 * ALLINAGENT — CROSS-PLATFORM & DOCKER-READY OFFICE BRIDGE SERVER (`:3210`)
 *
 * Responsibilities:
 *   1. Canonical Paperclip Runtime Provider & Normalized API (`/api/office-bridge/*`)
 *   2. Hermes3D Gateway WebSocket Protocol v3 (`ws://<host>:3210/ws`)
 *   3. Normalized Event Stream WebSocket v1.0 (`ws://<host>:3210/api/events/ws`)
 *   4. Custom Runtime HTTP Seam (`/health`, `/state`, `/registry`, `/v1/chat/completions`)
 *
 * Architecture & Security Invariants:
 *   - Paperclip (`PAPERCLIP_BASE_URL`) is the single source of truth for company, agents, projects, tasks, skills, approvals & budgets.
 *   - Hermes (`HERMES_PROFILES_DIR/pc*`) is the isolated execution runtime.
 *   - VulnClaw findings (`findings.db` / `VULNCLAW_WORKER_URL`) remain isolated, defensive, and sanitized.
 *   - Loopback by default; container bind `0.0.0.0` allowed ONLY when `OFFICE_BRIDGE_ALLOW_CONTAINER_BIND=1` or `/.dockerenv` is present.
 *   - Zero hardcoded personal identifiers, Windows drive paths, or Paperclip UUIDs.
 */

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const {
  OFFICE_DATA_DIR,
  DATA_DIR,
  REPORTS_DIR,
  HERMES_HOME_ROOT,
  PAPERCLIP_BASE_URL,
  PAPERCLIP_COMPANY_ID,
  HERMES3D_BASE_URL,
  DEFAULT_LLM_MODEL,
  TELEGRAM_BOT_USERNAME,
  resolveReportsDir,
  resolveAuthorizedOwnerId,
  resolveTimezone,
} = require("./contracts/paths");
const { loadWsModule } = require("./contracts/ws-loader");
const {
  sanitizePayload,
  sanitizeText,
  validateAuthorizedEvidencePath,
} = require("./contracts/redaction");
const { NormalizedEventBus } = require("./contracts/event-schema");
const {
  OfficeSecurityGuard,
  ensureOfficeBridgeSecrets,
  isContainerEnvironment,
} = require("./authorization/auth");
const { PaperclipRuntimeAdapter } = require("./adapters/paperclip-adapter");
const {
  inspectWorkspaceEvidence,
  invokePlatformCliJson,
  sendTelegramNotificationViaExistingBridge,
} = require("./adapters/vulnclaw-findings-adapter");
const {
  readAgentChatHistory,
  handleEmployeeChatTurn,
} = require("./adapters/agent-chat-engine");
const {
  isSensitiveFileName,
  getTargetFoldersStatus,
  mutateTargetFolders,
  browseLocalDirectory,
} = require("./adapters/target-folders-manager");
const {
  resolveCorporateBudgets,
  syncBudgetsWithPaperclip,
  buildUsageAndCostAnalytics,
  buildHistoricalRunRecords,
  buildApprovalRecords,
} = require("./adapters/analytics-telemetry-adapter");
const {
  buildStudioSkillsStatusPayload,
  buildRestSkillsCatalogPayload,
  buildGatewayAgentsSkillsConfigList,
  loadEnrichedAssignments,
  findAgentAssignment,
} = require("./adapters/agent-skills-bridge");
const {
  getTelegramControlPublicState,
  executeTelegramControlCommand,
} = require("./adapters/telegram-control-adapter");
const { consumeBoundApprovalRequest } = require("./telegram-control/security-guard");
const { collectHostResourceMetrics } = require("./telegram-control/analytics-budget-security-health");
const { RealtimeSynchronizer } = require("./events/realtime-synchronizer");

const PID_FILE = path.join(OFFICE_DATA_DIR, "office-bridge.pid");
const EVENT_HISTORY_FILE = path.join(OFFICE_DATA_DIR, "event-history", "recent-events.jsonl");
const LAYOUT_FILE = path.join(OFFICE_DATA_DIR, "layouts", "company-layout.json");
const MAX_HTTP_BODY_BYTES = 256 * 1024;
const WS_BACKPRESSURE_LIMIT_BYTES = 512 * 1024;

const REPORT_MIME_TYPES = Object.freeze({
  ".pdf": "application/pdf",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".md": "text/markdown; charset=utf-8",
});

function isPidRunning(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function acquireSingletonPidLock(pidFilePath = PID_FILE) {
  fs.mkdirSync(path.dirname(pidFilePath), { recursive: true, mode: 0o700 });
  if (fs.existsSync(pidFilePath)) {
    try {
      const existingPid = Number(fs.readFileSync(pidFilePath, "utf8").trim());
      if (existingPid && existingPid !== process.pid && isPidRunning(existingPid)) {
        const err = new Error(`Singleton lock held by active Office Bridge PID ${existingPid}`);
        err.code = "SINGLETON_ALREADY_RUNNING";
        throw err;
      }
    } catch (err) {
      if (err.code === "SINGLETON_ALREADY_RUNNING") throw err;
    }
  }
  fs.writeFileSync(pidFilePath, `${process.pid}\n`, "utf8");
}

function releaseSingletonPidLock(pidFilePath = PID_FILE) {
  try {
    if (fs.existsSync(pidFilePath)) {
      const recorded = Number(fs.readFileSync(pidFilePath, "utf8").trim());
      if (recorded === process.pid) {
        fs.unlinkSync(pidFilePath);
      }
    }
  } catch {}
}

function extractOrGenerateCorrelationId(req) {
  const incoming = req.headers?.["x-correlation-id"];
  if (typeof incoming === "string" && incoming.trim()) {
    const cleaned = incoming.trim().replace(/[^A-Za-z0-9._:-]/g, "").slice(0, 96);
    if (cleaned) return cleaned;
  }
  return `ob-${crypto.randomUUID().slice(0, 12)}`;
}

function sendJson(res, status, data, correlationId = "") {
  const payload = JSON.stringify(sanitizePayload(data));
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  };
  if (correlationId) {
    headers["X-Correlation-Id"] = correlationId;
  }
  if (status === 413) headers.Connection = "close";
  res.writeHead(status, headers);
  res.end(payload);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let overLimit = false;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > MAX_HTTP_BODY_BYTES) {
        overLimit = true;
        chunks.length = 0;
        return;
      }
      if (!overLimit) chunks.push(chunk);
    });
    req.on("end", () => {
      if (overLimit) {
        reject(Object.assign(new Error("Request payload too large (max 256 KB)."), { status: 413 }));
        return;
      }
      if (chunks.length === 0) {
        resolve({});
        return;
      }
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw.trim() ? JSON.parse(raw) : {});
      } catch {
        reject(Object.assign(new Error("Malformed JSON request body."), { status: 400 }));
      }
    });
    req.on("error", reject);
  });
}

function rejectSocketUpgrade(socket, statusCode, message) {
  try {
    const safe = String(message || "Unauthorized").replace(/[\r\n]+/g, " ");
    socket.end(`HTTP/1.1 ${statusCode} ${safe}\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n${safe}`);
  } catch {
    try {
      socket.destroy();
    } catch {}
  }
}

function getActiveReportRoots(env = process.env) {
  const primary = resolveReportsDir(env) || REPORTS_DIR;
  const roots = [path.resolve(primary)];
  if (
    process.platform !== "win32" &&
    !env.ALLINAGENT_REPORTS_ROOT &&
    !env.ALLINAGENT_REPORTS_DIR &&
    fs.existsSync("/var/lib/allinagent/reports") &&
    !roots.includes("/var/lib/allinagent/reports")
  ) {
    roots.unshift("/var/lib/allinagent/reports");
  }
  return roots;
}

function listAvailableReportArtifacts(env = process.env) {
  const reportRoots = getActiveReportRoots(env);
  const items = [];
  const seenNames = new Set();
  for (const rootDir of reportRoots) {
    if (!fs.existsSync(rootDir)) continue;
    try {
      for (const ent of fs.readdirSync(rootDir, { withFileTypes: true })) {
        if (!ent.isFile() || seenNames.has(ent.name)) continue;
        if (isSensitiveFileName(ent.name)) continue;
        const ext = path.extname(ent.name).toLowerCase();
        if (!REPORT_MIME_TYPES[ext]) continue;
        const fullPath = path.join(rootDir, ent.name);
        const check = validateAuthorizedEvidencePath(fullPath, {
          allowedRoots: reportRoots,
          includeTargetFolders: false,
        });
        if (!check.ok) continue;
        const stat = fs.statSync(check.resolvedPath);
        seenNames.add(ent.name);
        items.push({
          filename: ent.name,
          format: ext.slice(1),
          mime_type: REPORT_MIME_TYPES[ext],
          size_bytes: stat.size,
          mtime_iso: stat.mtime.toISOString(),
          download_path: `/api/office-bridge/reports/${encodeURIComponent(ent.name)}`,
        });
      }
    } catch {}
  }
  items.sort((a, b) => String(b.mtime_iso).localeCompare(String(a.mtime_iso)));
  return items;
}

async function createOfficeBridgeApp(options = {}) {
  const host = options.host || process.env.OFFICE_BRIDGE_HOST || "127.0.0.1";
  const port =
    options.port !== undefined && options.port !== null
      ? Number(options.port)
      : Number(process.env.OFFICE_BRIDGE_PORT || 3210);

  const isLoopbackHost = host === "127.0.0.1" || host === "localhost" || host === "::1";
  const isContainerBindHost = host === "0.0.0.0" || host === "::";
  const containerBindAllowed = options.allowContainerBind === true || isContainerEnvironment(process.env);

  if (!isLoopbackHost && !(isContainerBindHost && containerBindAllowed)) {
    throw new Error(
      `Security policy forbids binding Office Bridge to non-loopback host '${host}' unless OFFICE_BRIDGE_ALLOW_CONTAINER_BIND=1 or running inside a container.`
    );
  }

  const secrets = options.secrets || ensureOfficeBridgeSecrets(options.secretFilePath);
  const guard = new OfficeSecurityGuard({
    secrets,
    ownerId: options.ownerId,
    allowDockerNetwork: options.allowDockerNetwork,
    allowedOrigins: options.allowedOrigins,
    allowedOriginsEnv: options.allowedOriginsEnv,
  });
  const paperclip =
    options.paperclip ||
    new PaperclipRuntimeAdapter({
      baseUrl: options.paperclipUrl,
      wsBaseUrl: options.paperclipWsUrl,
      timeoutMs: options.paperclipTimeoutMs,
    });

  const initialCompany = await paperclip.getPrimaryCompany().catch(() => ({
    id: process.env.PAPERCLIP_COMPANY_ID || PAPERCLIP_COMPANY_ID || null,
    name: process.env.COMPANY_NAME || "ALLINAGENT Operations",
  }));

  const eventBus = new NormalizedEventBus({
    companyId: initialCompany.id || "pending-company",
    maxRetention: 500,
    historyFilePath: options.historyFilePath !== undefined ? options.historyFilePath : EVENT_HISTORY_FILE,
  });

  const sync = new RealtimeSynchronizer({
    paperclip,
    eventBus,
    pollIntervalMs: options.pollIntervalMs || 3000,
    enableUpstreamWs: options.enableUpstreamWs,
  });
  await sync.start();

  const commandIdempotencyCache = new Map();

  async function buildAgentInspectorPayload(agentId) {
    const snap = sync.getFullSnapshot();
    const agent = (snap.agents || []).find(
      (a) => a.paperclip_agent_id === agentId || a.role_slug === agentId
    );
    if (!agent) {
      const err = new Error(`Agent '${agentId}' not found in Paperclip organization.`);
      err.status = 404;
      throw err;
    }

    const resolvedAgentId = agent.paperclip_agent_id;
    const agentTasks = (snap.tasks || []).filter((t) => t.assigneeAgentId === resolvedAgentId);
    const agentRuns = (snap.runs || []).filter((r) => r.agentId === resolvedAgentId).slice(0, 20);
    const latestRun = agentRuns[0] || null;
    const runDetails = latestRun ? await paperclip.getVerifiedRunDetails(latestRun.id).catch(() => null) : null;

    const manager = agent.manager_id
      ? (snap.agents || []).find((a) => a.paperclip_agent_id === agent.manager_id) || null
      : null;
    const subordinates = (snap.agents || []).filter((a) =>
      (agent.subordinate_ids || []).includes(a.paperclip_agent_id)
    );
    const usage = snap.governance_budget?.per_agent_usage?.[resolvedAgentId] || {
      agent_id: resolvedAgentId,
      run_count: 0,
      succeeded_runs: 0,
      failed_runs: 0,
      cancelled_runs: 0,
      total_tokens: 0,
      total_duration_ms: 0,
      cost_usd: null,
      cost_label: "COST UNKNOWN",
      usage_classification: "UNPRICED USAGE",
    };
    const policy = (snap.governance_budget?.policies || []).find((p) => p.scope_id === resolvedAgentId) || null;
    const delegations = (snap.collaboration?.edges || []).filter(
      (e) => e.from_agent_id === resolvedAgentId || e.to_agent_id === resolvedAgentId
    );

    const retryRows = (sync.workflowSnapshot?.tasks || []).filter((r) => r.assigned_agent_id === resolvedAgentId);
    const totalRetries = retryRows.reduce((acc, r) => acc + (Number(r.retry_count) || 0), 0);

    return sanitizePayload({
      overview: agent,
      hierarchy: {
        manager: manager
          ? { paperclip_agent_id: manager.paperclip_agent_id, display_name: manager.display_name, role: manager.role }
          : null,
        subordinates: subordinates.map((s) => ({
          paperclip_agent_id: s.paperclip_agent_id,
          display_name: s.display_name,
          role: s.role,
          activation_status: s.activation_status,
        })),
      },
      current_task: agent.current_task,
      task_queue: agentTasks.filter((t) => t.status === "todo" || t.status === "backlog"),
      task_history: agentTasks.slice(0, 25),
      delegation_history: delegations,
      execution_history: agentRuns.map((r) => ({
        id: r.id,
        status: r.status,
        exit_code: r.exitCode ?? null,
        started_at: r.startedAt,
        finished_at: r.finishedAt,
        issue_id: r.contextSnapshot?.issueId || r.issueId || null,
      })),
      sanitized_logs: runDetails?.logExcerpt || "",
      verified_run_evidence: runDetails?.evidence || { verifiedToolKind: null, verifiedTools: [] },
      performance: {
        completed_tasks: agentTasks.filter((t) => t.status === "done").length,
        failed_runs: usage.failed_runs,
        succeeded_runs: usage.succeeded_runs,
        run_count: usage.run_count,
        total_execution_duration_ms: usage.total_duration_ms,
        retry_count: totalRetries,
        retry_rate: agentTasks.length > 0 ? Number((totalRetries / agentTasks.length).toFixed(2)) : 0,
      },
      budget: {
        policy,
        usage,
      },
      health: {
        connectivity_state: agent.state.connectivity_state,
        activation_state: agent.state.activation_state,
        execution_state: agent.state.execution_state,
        visual_state: agent.state.visual_state,
        last_activity_at: latestRun?.finishedAt || latestRun?.startedAt || agent.last_heartbeat_at || null,
      },
      allowed_settings: {
        can_pause: true,
        can_resume: true,
        can_assign_task: true,
        can_cancel_active_run: Boolean(agent.current_run),
        direct_shell_exposed: false,
      },
    });
  }

  let cachedCliHealth = null;
  let cachedCliHealthAtMs = 0;
  let cliHealthRefreshInFlight = null;

  function loadWatchdogHealthFile() {
    const watchdogSnapshotFile = path.join(DATA_DIR, "last-health-snapshot.json");
    try {
      if (fs.existsSync(watchdogSnapshotFile)) {
        const buf = fs.readFileSync(watchdogSnapshotFile);
        const rawSnap =
          buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe
            ? buf.subarray(2).toString("utf16le").trim()
            : buf.toString("utf8").replace(/^\uFEFF/, "").trim();
        return sanitizePayload(JSON.parse(rawSnap));
      }
    } catch {}
    return null;
  }

  function triggerAsyncHealthRefresh() {
    if (cliHealthRefreshInFlight) return cliHealthRefreshInFlight;
    cliHealthRefreshInFlight = invokePlatformCliJson(["status", "--json"], 25_000)
      .then((res) => {
        if (res && typeof res === "object" && res.hermes) {
          cachedCliHealth = res;
          cachedCliHealthAtMs = Date.now();
        }
      })
      .catch(() => {})
      .finally(() => {
        cliHealthRefreshInFlight = null;
      });
    return cliHealthRefreshInFlight;
  }

  async function buildUnifiedHealthMatrix() {
    if (!cachedCliHealth) {
      cachedCliHealth = loadWatchdogHealthFile();
      if (cachedCliHealth) cachedCliHealthAtMs = Date.now() - 60_000;
    }
    if (!cachedCliHealth || Date.now() - cachedCliHealthAtMs > 90_000) {
      triggerAsyncHealthRefresh();
      if (!cachedCliHealth && cliHealthRefreshInFlight) {
        await Promise.race([cliHealthRefreshInFlight, new Promise((r) => setTimeout(r, 1500))]);
      }
    }
    const cliHealth = cachedCliHealth || loadWatchdogHealthFile();

    let liveGwRunning = null;
    let liveTgConnected = null;
    let liveCodeSha = null;
    try {
      const gwStateFile = path.join(HERMES_HOME_ROOT, "gateway_state.json");
      if (fs.existsSync(gwStateFile)) {
        const gs = JSON.parse(fs.readFileSync(gwStateFile, "utf8").replace(/^\uFEFF/, ""));
        const gwPid = Number(gs?.pid || 0);
        if (gwPid > 0 && isPidRunning(gwPid) && gs?.gateway_state === "running") {
          liveGwRunning = true;
          liveTgConnected = gs?.platforms?.telegram?.state === "connected";
          liveCodeSha = gs?.code_sha || null;
        }
      }
    } catch {}

    const snap = sync.getFullSnapshot();
    const maintActive = snap.maintenance?.maintenance_active === true;
    const tz = resolveTimezone(process.env);
    const activeModel = String(process.env.LLM_MODEL || DEFAULT_LLM_MODEL);
    const h3dBase = String(process.env.HERMES3D_BASE_URL || HERMES3D_BASE_URL).replace(/\/$/, "");
    const hostMetrics = collectHostResourceMetrics();

    const mapComponentState = (ok, degraded = false) => {
      if (maintActive) return "MAINTENANCE";
      if (ok === true) return degraded ? "DEGRADED" : "HEALTHY";
      if (ok === false) return "OFFLINE";
      return "UNKNOWN";
    };

    const hermesHealthy =
      liveGwRunning === true ? true : cliHealth ? Boolean(cliHealth.hermes?.healthy) : null;
    const gatewayHealthy =
      liveGwRunning !== null ? liveGwRunning : cliHealth ? Boolean(cliHealth.hermes?.gateway_running) : null;
    const telegramHealthy =
      liveTgConnected !== null ? liveTgConnected : cliHealth ? Boolean(cliHealth.hermes?.telegram_connected) : null;

    const components = {
      host_runtime: {
        state: "HEALTHY",
        platform: hostMetrics.platform,
        arch: hostMetrics.arch,
      },
      paperclip: {
        state: mapComponentState(snap.paperclip_reachable),
        version: cliHealth?.paperclip?.version || "2026.1117.0",
        url: paperclip.baseUrl || PAPERCLIP_BASE_URL,
      },
      postgresql: {
        state: mapComponentState(
          cliHealth?.paperclip?.database_backup_status === "ok" || snap.paperclip_reachable
        ),
      },
      hermes_agent: {
        state: mapComponentState(hermesHealthy),
        commit: liveCodeSha || cliHealth?.hermes?.installed_commit || "unknown",
        model: activeModel,
      },
      hermes_gateway: {
        state: mapComponentState(gatewayHealthy),
      },
      telegram: {
        state: mapComponentState(telegramHealthy),
        bot: TELEGRAM_BOT_USERNAME,
        single_poller: true,
      },
      vulnclaw_defensive: {
        state: mapComponentState(
          cliHealth
            ? Boolean(cliHealth.vulnclaw?.healthy && cliHealth.vulnclaw?.isolation_verified)
            : snap.security_center?.available
        ),
        version: cliHealth?.vulnclaw?.version || "0.4.1",
        mode: "defensive_isolated",
      },
      computer_use: {
        state: mapComponentState(cliHealth ? cliHealth.hermes?.cua_status === "ready" : null),
      },
      office_bridge: {
        state: maintActive ? "MAINTENANCE" : snap.paperclip_reachable ? "HEALTHY" : "DEGRADED",
        endpoint: `http://${host}:${port}`,
        upstream_ws_connected: snap.upstream_ws_connected,
      },
      event_stream: {
        state: snap.paperclip_reachable ? "HEALTHY" : "DEGRADED",
        latest_sequence: snap.event_stream.latest_sequence,
        emitted: snap.event_stream.stats.emitted,
      },
      maintenance_coordinator: {
        state: maintActive ? "MAINTENANCE" : cliHealth?.maintenance ? "HEALTHY" : "UNKNOWN",
        schedule: `daily @ 03:00 (${tz})`,
        next_slot: cliHealth?.maintenance?.next_scheduled_slot || snap.maintenance?.state?.next_scheduled_slot || null,
      },
      auto_updater: {
        state: mapComponentState(cliHealth ? Boolean(cliHealth.services?.HermesAutoUpdate?.enabled) : null),
        schedule: `daily @ 03:00 (${tz})`,
      },
    };

    let hermes3dOk = null;
    try {
      const r = await fetch(`${h3dBase}/login`, { signal: AbortSignal.timeout(2000) });
      hermes3dOk = r.status === 200 || r.status === 307 || r.status === 302;
    } catch {
      hermes3dOk = false;
    }
    components.hermes3d = {
      state: mapComponentState(hermes3dOk),
      url: `${h3dBase}/office`,
    };

    const allStates = Object.values(components).map((c) => c.state);
    let overall = "HEALTHY";
    if (maintActive) overall = "MAINTENANCE";
    else if (allStates.includes("OFFLINE")) overall = "DEGRADED";
    else if (allStates.includes("UNKNOWN")) overall = "DEGRADED";

    return {
      overall_state: overall,
      checked_at: new Date().toISOString(),
      components,
      host_metrics: hostMetrics,
      windows: cliHealth?.windows || hostMetrics,
    };
  }

  async function handleCreateTaskAction(body, callerId, requestCorrelationId = "") {
    const idemKey = body.idempotency_key ? String(body.idempotency_key).trim() : null;
    if (idemKey && commandIdempotencyCache.has(idemKey)) {
      return { ...commandIdempotencyCache.get(idemKey), deduplicated: true };
    }

    const title = sanitizeText(String(body.title || "").trim());
    const description = sanitizeText(String(body.description || title).trim());
    if (!title || title.length < 3) {
      const err = new Error("Task title must be at least 3 characters.");
      err.status = 400;
      throw err;
    }

    const snap = sync.getFullSnapshot();
    const companyId = snap.company?.id;
    if (!companyId) throw new Error("Company unavailable.");

    let assigneeAgentId = body.assignee_agent_id || body.assigneeAgentId || null;
    if (!assigneeAgentId) {
      const ceo = (snap.agents || []).find((a) => a.role === "ceo");
      assigneeAgentId = ceo ? ceo.paperclip_agent_id : null;
    } else if (!(snap.agents || []).some((a) => a.paperclip_agent_id === assigneeAgentId)) {
      // Allow matching by role_slug when caller passes e.g. `backend_developer`
      const bySlug = (snap.agents || []).find((a) => a.role_slug === assigneeAgentId);
      if (bySlug) {
        assigneeAgentId = bySlug.paperclip_agent_id;
      } else {
        const err = new Error(`Unknown assignee_agent_id '${assigneeAgentId}'.`);
        err.status = 400;
        throw err;
      }
    }

    const preCorrelation = body.correlation_id || requestCorrelationId || "";
    const createdIssue = await paperclip.createTask(
      companyId,
      {
        title,
        description,
        assigneeAgentId,
        projectId: body.project_id || body.projectId || null,
        parentId: body.parent_id || body.parentId || null,
        priority: body.priority || "medium",
        status: body.status || "todo",
      },
      idemKey,
      preCorrelation
    );

    const correlationId =
      preCorrelation || `corr-${createdIssue.identifier || String(createdIssue.id).slice(0, 8)}`;
    sync.trackOfficeCreatedTask(createdIssue.id, correlationId, body.notify_telegram !== false);

    let wakeResult = null;
    const targetAgent = (snap.agents || []).find((a) => a.paperclip_agent_id === assigneeAgentId);
    if (body.force_manual_wake === true && assigneeAgentId && targetAgent?.activation_status === "ACTIVE") {
      wakeResult = await paperclip
        .wakeAgent(assigneeAgentId, "office_command_center_task", {
          issueId: createdIssue.id,
          taskId: createdIssue.id,
          correlationId,
          origin: "hermes3d_office",
        })
        .catch((e) => ({ warning: sanitizeText(e.message) }));
    }

    if (body.notify_telegram_immediately === true) {
      await sendTelegramNotificationViaExistingBridge(
        `[ALLINAGENT Virtual Office] Task baru dibuat: ${createdIssue.identifier || createdIssue.id} — ${createdIssue.title}`,
        correlationId
      ).catch(() => {});
    }

    await sync.reconcileNow("task_created_via_bridge");
    const responsePayload = {
      deduplicated: false,
      correlation_id: correlationId,
      task: createdIssue,
      wake: wakeResult,
    };

    if (idemKey) {
      commandIdempotencyCache.set(idemKey, responsePayload);
      if (commandIdempotencyCache.size > 500) {
        const k = commandIdempotencyCache.keys().next().value;
        if (k) commandIdempotencyCache.delete(k);
      }
    }
    return responsePayload;
  }

  // --- HTTP Request Router ---
  const server = http.createServer(async (req, res) => {
    const correlationId = extractOrGenerateCorrelationId(req);
    const urlObj = new URL(req.url || "/", `http://${host}:${port}`);
    const pathname = urlObj.pathname;
    const method = (req.method || "GET").toUpperCase();
    const respond = (status, data) => sendJson(res, status, data, correlationId);

    try {
      // 1. Minimal Public Health Liveness (/health and /healthz)
      if ((method === "GET" || method === "HEAD") && (pathname === "/health" || pathname === "/healthz")) {
        return respond(200, {
          ok: true,
          status: sync.paperclipReachable ? "healthy" : "degraded",
          service: "office-bridge",
          version: "1.0.0",
          correlation_id: correlationId,
          paperclip_reachable: sync.paperclipReachable,
          latest_sequence: eventBus.sequence,
        });
      }

      const isMutation = method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
      const auth = guard.authorizeHttp(req, urlObj, {
        requireMutationOwner: isMutation,
        actionName: `${method} ${pathname}`,
      });
      if (!auth.ok) {
        return respond(auth.status, { ok: false, error: auth.error, correlation_id: correlationId });
      }

      const activeModel = String(process.env.LLM_MODEL || DEFAULT_LLM_MODEL);

      // 2. Hermes3D CustomRuntimeProvider HTTP Seam
      if (method === "GET" && pathname === "/state") {
        const snap = sync.getFullSnapshot();
        const activeRoles = {};
        for (const a of snap.agents || []) {
          activeRoles[a.paperclip_agent_id] = [a.model_id || activeModel];
        }
        return respond(200, {
          profileName: "allinagent-company",
          active: activeRoles,
          identity: {
            name: snap.company?.name || "ALLINAGENT Operations",
            role: "orchestrator",
            lane: "paperclip",
            model_id: activeModel,
          },
          runtime: {
            name: "Paperclip × Hermes Unified Runtime",
            version: "2026.1117.0",
            vendor: "ALLINAGENT",
            status: snap.paperclip_reachable ? "healthy" : "degraded",
            active_model: activeModel,
            governance: "paperclip_enforced",
          },
        });
      }

      if (method === "GET" && pathname === "/registry") {
        return respond(200, {
          models: {
            [activeModel]: {
              id: activeModel,
              provider: "custom",
              pricing: "TOKEN_METERED_REFERENCE / COST UNKNOWN",
            },
          },
        });
      }

      if (method === "POST" && pathname === "/v1/chat/completions") {
        const body = await readJsonBody(req);
        const messages = Array.isArray(body.messages) ? body.messages : [];
        const lastUser = [...messages].reverse().find((m) => m && m.role === "user");
        const promptText = sanitizeText(String(lastUser?.content || "")).trim();
        if (!promptText) {
          return respond(400, { error: "User message is required." });
        }
        const snap = sync.getFullSnapshot();
        const targetAgent =
          (snap.agents || []).find((a) => a.paperclip_agent_id === body.agent_id) ||
          (snap.agents || []).find((a) => a.role === "ceo") ||
          (snap.agents || [])[0];
        const turn = await handleEmployeeChatTurn({
          agent: targetAgent,
          snapshot: snap,
          rawMessage: promptText,
          idempotencyKey: body.idempotency_key || null,
          createTaskFn: (b, c) => handleCreateTaskAction(b, c, correlationId),
          sync,
          paperclip,
          callerId: auth.callerId,
        });
        return respond(200, {
          id: `chatcmpl-${crypto.randomUUID().slice(0, 12)}`,
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: activeModel,
          choices: [
            {
              index: 0,
              message: { role: "assistant", content: turn.text },
              finish_reason: "stop",
            },
          ],
        });
      }

      // 3. Enterprise Office REST API (`/api/office-bridge/*`)
      if (method === "GET" && pathname === "/api/office-bridge/snapshot") {
        if (urlObj.searchParams.get("refresh") === "1") {
          await sync.reconcileNow("manual_snapshot_refresh");
        }
        return respond(200, sync.getFullSnapshot());
      }

      if (method === "GET" && pathname === "/api/office-bridge/events") {
        const sinceSeq = Number(urlObj.searchParams.get("sinceSeq") || 0);
        const limit = Math.min(500, Math.max(1, Number(urlObj.searchParams.get("limit") || 100)));
        return respond(200, {
          ok: true,
          latest_sequence: eventBus.sequence,
          events: eventBus.getEventsSince(sinceSeq, limit),
        });
      }

      if (method === "GET" && pathname === "/api/office-bridge/skills") {
        const snap = sync.getFullSnapshot();
        const reqAgentId = urlObj.searchParams.get("agentId") || urlObj.searchParams.get("agent") || null;
        const paperclipSkills = snap.company?.id
          ? await paperclip.listCompanySkills(snap.company.id).catch(() => [])
          : [];
        return respond(200, buildRestSkillsCatalogPayload(snap, reqAgentId, paperclipSkills));
      }

      if (pathname === "/api/office-bridge/projects") {
        const snap = sync.getFullSnapshot();
        const companyId = snap.company?.id;
        if (method === "GET") {
          const projects = companyId
            ? await paperclip.listProjects(companyId).catch(() => snap.projects || [])
            : snap.projects || [];
          return respond(200, {
            ok: true,
            company_id: companyId || null,
            total: projects.length,
            projects,
          });
        }
        if (method === "POST") {
          if (!companyId) return respond(503, { ok: false, error: "Company unavailable." });
          const body = await readJsonBody(req);
          const created = body.ensure
            ? await paperclip.ensureProject(companyId, body.name, body)
            : await paperclip.createProject(companyId, body);
          await sync.reconcileNow("project_created_via_bridge");
          return respond(201, { ok: true, project: created });
        }
        if (method === "PATCH") {
          const body = await readJsonBody(req);
          const projectId = String(body.id || body.project_id || "").trim();
          if (!projectId) {
            return respond(400, { ok: false, error: "Project id is required." });
          }
          const updated = await paperclip.updateProject(projectId, body);
          await sync.reconcileNow("project_patched_via_bridge");
          return respond(200, { ok: true, project: updated });
        }
      }

      const projectDetailMatch = pathname.match(/^\/api\/office-bridge\/projects\/([^/]+)$/);
      if (projectDetailMatch && method === "PATCH") {
        const projectId = decodeURIComponent(projectDetailMatch[1]);
        const body = await readJsonBody(req);
        const updated = await paperclip.updateProject(projectId, body);
        await sync.reconcileNow("project_patched_via_bridge");
        return respond(200, { ok: true, project: updated });
      }

      if (method === "GET" && pathname === "/api/office-bridge/reports") {
        const reports = listAvailableReportArtifacts();
        return respond(200, { ok: true, total: reports.length, reports });
      }

      const reportFileMatch = pathname.match(/^\/api\/office-bridge\/reports\/([^/]+)$/);
      if (method === "GET" && reportFileMatch) {
        const rawFilename = decodeURIComponent(reportFileMatch[1]);
        if (
          !rawFilename ||
          rawFilename.includes("\0") ||
          rawFilename.includes("/") ||
          rawFilename.includes("\\") ||
          rawFilename.includes("..") ||
          path.basename(rawFilename) !== rawFilename
        ) {
          return respond(403, { ok: false, error: "Invalid or traversal report filename rejected." });
        }
        if (isSensitiveFileName(rawFilename)) {
          return respond(403, { ok: false, error: "Sensitive filenames are strictly blocked." });
        }
        const ext = path.extname(rawFilename).toLowerCase();
        const mime = REPORT_MIME_TYPES[ext];
        if (!mime) {
          return respond(403, {
            ok: false,
            error: "Only .pdf, .docx, and .md report artifacts may be served.",
          });
        }
        const reportRoots = getActiveReportRoots(process.env);
        const existingCandidate =
          reportRoots
            .map((r) => path.join(r, rawFilename))
            .find((cand) => fs.existsSync(cand)) || path.join(reportRoots[0], rawFilename);
        const pathCheck = validateAuthorizedEvidencePath(existingCandidate, {
          allowedRoots: reportRoots,
          includeTargetFolders: false,
        });
        if (!pathCheck.ok || !pathCheck.resolvedPath) {
          return respond(403, { ok: false, error: pathCheck.reason || "Forbidden report path." });
        }
        if (!fs.existsSync(pathCheck.resolvedPath) || !fs.statSync(pathCheck.resolvedPath).isFile()) {
          return respond(404, { ok: false, error: `Report '${sanitizeText(rawFilename)}' not found.` });
        }

        const safeDispName = rawFilename.replace(/["\\\r\n]/g, "_");
        if (ext === ".md") {
          const cleanMarkdown = sanitizeText(fs.readFileSync(pathCheck.resolvedPath, "utf8"));
          const buf = Buffer.from(cleanMarkdown, "utf8");
          res.writeHead(200, {
            "Content-Type": mime,
            "Content-Length": String(buf.length),
            "Content-Disposition": `inline; filename="${safeDispName}"`,
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Correlation-Id": correlationId,
          });
          res.end(buf);
          return;
        }

        const binBuf = fs.readFileSync(pathCheck.resolvedPath);
        res.writeHead(200, {
          "Content-Type": mime,
          "Content-Length": String(binBuf.length),
          "Content-Disposition": `attachment; filename="${safeDispName}"`,
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
          "X-Correlation-Id": correlationId,
        });
        res.end(binBuf);
        return;
      }

      if (method === "GET" && pathname === "/api/office-bridge/agents") {
        const snap = sync.getFullSnapshot();
        return respond(200, {
          ok: true,
          company: snap.company,
          total: (snap.agents || []).length,
          agents: snap.agents || [],
        });
      }

      const agentDetailMatch = pathname.match(/^\/api\/office-bridge\/agents\/([^/]+)$/);
      if (method === "GET" && agentDetailMatch) {
        const payload = await buildAgentInspectorPayload(decodeURIComponent(agentDetailMatch[1]));
        return respond(200, { ok: true, inspector: payload });
      }

      const agentChatMatch = pathname.match(/^\/api\/office-bridge\/agents\/([^/]+)\/chat$/);
      if (agentChatMatch) {
        const agentId = decodeURIComponent(agentChatMatch[1]);
        const snap = sync.getFullSnapshot();
        const targetAgent = (snap.agents || []).find(
          (a) => a.paperclip_agent_id === agentId || a.role_slug === agentId
        );
        if (!targetAgent) return respond(404, { ok: false, error: `Unknown agent '${agentId}'.` });
        const resolvedId = targetAgent.paperclip_agent_id;
        if (method === "GET") {
          return respond(200, { ok: true, agent_id: resolvedId, messages: readAgentChatHistory(resolvedId, 40) });
        }
        if (method === "POST") {
          const body = await readJsonBody(req);
          const msg = String(body.message || "").trim();
          if (!msg) return respond(400, { ok: false, error: "Message is required." });
          const turn = await handleEmployeeChatTurn({
            agent: targetAgent,
            snapshot: snap,
            rawMessage: msg,
            idempotencyKey: body.idempotency_key || null,
            createTaskFn: (b, c) => handleCreateTaskAction(b, c, correlationId),
            sync,
            paperclip,
            callerId: auth.callerId,
          });
          return respond(200, {
            ok: true,
            agent_id: resolvedId,
            reply: turn.text,
            created_task: turn.createdTask,
            created_meeting: turn.createdMeeting || null,
          });
        }
      }

      const agentActionMatch = pathname.match(/^\/api\/office-bridge\/agents\/([^/]+)\/(pause|resume|wake)$/);
      if (method === "POST" && agentActionMatch) {
        const agentId = decodeURIComponent(agentActionMatch[1]);
        const action = agentActionMatch[2];
        const body = await readJsonBody(req);
        let result;
        if (action === "pause") result = await paperclip.pauseAgent(agentId);
        else if (action === "resume") result = await paperclip.resumeAgent(agentId);
        else result = await paperclip.wakeAgent(agentId, body.reason || "office_manual_wake", body.context || {});
        await sync.reconcileNow(`agent_${action}`);
        return respond(200, { ok: true, action, agent: result });
      }

      if (method === "GET" && pathname === "/api/office-bridge/tasks") {
        const snap = sync.getFullSnapshot();
        return respond(200, { ok: true, tasks: snap.tasks || [] });
      }

      if (method === "POST" && pathname === "/api/office-bridge/tasks") {
        const body = await readJsonBody(req);
        const result = await handleCreateTaskAction(body, auth.callerId, correlationId);
        return respond(result.deduplicated ? 200 : 201, { ok: true, ...result });
      }

      const taskMatch = pathname.match(/^\/api\/office-bridge\/tasks\/([^/]+)$/);
      if (taskMatch) {
        const issueId = decodeURIComponent(taskMatch[1]);
        if (method === "GET") {
          const detail = await paperclip.getTaskDetail(issueId);
          return respond(200, { ok: true, task: detail.issue || detail.task || null, ...detail });
        }
        if (method === "PATCH") {
          const body = await readJsonBody(req);
          const { comment: commentRaw, ...issuePatch } = body || {};
          let updated = null;
          if (
            issuePatch.status ||
            issuePatch.priority ||
            issuePatch.assigneeAgentId !== undefined ||
            issuePatch.title ||
            issuePatch.description !== undefined
          ) {
            updated = await paperclip.updateTask(issueId, issuePatch);
          }
          let comment = null;
          if (typeof commentRaw === "string" && commentRaw.trim()) {
            comment = await paperclip.addTaskComment(issueId, commentRaw);
          }
          if (!updated) {
            const det = await paperclip.getTaskDetail(issueId).catch(() => null);
            updated = det?.issue || det?.task || null;
          }
          await sync.reconcileNow("task_patched");
          return respond(200, { ok: true, task: updated, comment });
        }
      }

      const runCancelMatch = pathname.match(/^\/api\/office-bridge\/runs\/([^/]+)\/cancel$/);
      if (method === "POST" && runCancelMatch) {
        const runId = decodeURIComponent(runCancelMatch[1]);
        const cancelled = await paperclip.cancelRun(runId);
        await sync.reconcileNow("run_cancelled");
        return respond(200, { ok: true, run: cancelled });
      }

      if (method === "GET" && pathname === "/api/office-bridge/findings") {
        await sync.reconcileNow("findings_refresh");
        return respond(200, {
          ok: true,
          findings: sync.findingsSnapshot?.findings || [],
          security_center: sync.findingsSnapshot,
        });
      }

      if (method === "GET" && pathname === "/api/office-bridge/collaboration") {
        const snap = sync.getFullSnapshot();
        return respond(200, { ok: true, ...snap.collaboration });
      }

      if (method === "POST" && pathname === "/api/office-bridge/meetings") {
        const body = await readJsonBody(req);
        const mtg = await sync.createAuthorizedMeeting(body);
        return respond(201, { ok: true, meeting: mtg });
      }

      const mtgCompleteMatch = pathname.match(/^\/api\/office-bridge\/meetings\/([^/]+)\/complete$/);
      if (method === "POST" && mtgCompleteMatch) {
        const body = await readJsonBody(req);
        const mtg = await sync.completeAuthorizedMeeting(decodeURIComponent(mtgCompleteMatch[1]), body);
        return respond(200, { ok: true, meeting: mtg });
      }

      if (method === "GET" && pathname === "/api/office-bridge/analytics") {
        const snap = sync.getFullSnapshot();
        const startDate = urlObj.searchParams.get("startDate") || undefined;
        const endDate = urlObj.searchParams.get("endDate") || undefined;
        const usageAndCost = buildUsageAndCostAnalytics({
          snapshot: snap,
          startDate,
          endDate,
          limit: Number(urlObj.searchParams.get("limit") || 1000),
        });
        const runs = await buildHistoricalRunRecords({ snapshot: snap, paperclip, limit: 200 });
        const approvals = buildApprovalRecords({ snapshot: snap });
        return respond(200, {
          ok: true,
          ...usageAndCost,
          runs,
          approvals,
        });
      }

      if (method === "GET" && pathname === "/api/office-bridge/governance") {
        const snap = sync.getFullSnapshot();
        return respond(200, {
          ok: true,
          approvals: snap.approvals,
          budget: snap.governance_budget,
          agents: (snap.agents || []).map((a) => ({
            paperclip_agent_id: a.paperclip_agent_id,
            role_slug: a.role_slug,
            display_name: a.display_name,
            role: a.role,
            department: a.department,
            manager_id: a.manager_id,
            activation_status: a.activation_status,
            authorized_workspaces: a.authorized_workspaces,
            authorized_tools: a.authorized_tools,
            can_create_agents: a.can_create_agents,
          })),
        });
      }

      const approvalResolveMatch = pathname.match(/^\/api\/office-bridge\/approvals\/([^/]+)\/resolve$/);
      if (method === "POST" && approvalResolveMatch) {
        const body = await readJsonBody(req);
        if (!["approve", "reject"].includes(body.decision)) {
          return respond(400, { ok: false, error: "decision must be 'approve' or 'reject'." });
        }
        const rawApprovalId = decodeURIComponent(approvalResolveMatch[1]);
        if (rawApprovalId.startsWith("req_")) {
          const consumed = consumeBoundApprovalRequest({
            requestId: rawApprovalId,
            callerId: auth.callerId,
            decision: body.decision,
            note: body.note || "",
          });
          if (!consumed.ok) {
            return respond(consumed.status || 403, { ok: false, code: consumed.code, error: consumed.error });
          }
          return respond(200, { ok: true, approval: consumed.record });
        }
        const resolved = await paperclip.resolveApproval(rawApprovalId, body.decision, body.note || "");
        await sync.reconcileNow("approval_resolved");
        return respond(200, { ok: true, approval: resolved });
      }

      if (method === "POST" && pathname === "/api/office-bridge/emergency-stop") {
        const snap = sync.getFullSnapshot();
        const pausedIds = [];
        const cancelledRunIds = [];
        for (const r of snap.runs || []) {
          if (r.status === "running" || r.status === "queued") {
            await paperclip.cancelRun(r.id).catch(() => {});
            cancelledRunIds.push(r.id);
          }
        }
        for (const a of snap.agents || []) {
          if (a.activation_status === "ACTIVE" || a.raw_status !== "paused") {
            await paperclip.pauseAgent(a.paperclip_agent_id).catch(() => {});
            pausedIds.push(a.paperclip_agent_id);
          }
        }
        await sync.reconcileNow("emergency_stop");
        return respond(200, {
          ok: true,
          result: { action: "emergency_stop", cancelled_runs: cancelledRunIds, paused_agents: pausedIds },
        });
      }

      if (method === "POST" && pathname === "/api/office-bridge/resume-wave1") {
        const snap = sync.getFullSnapshot();
        const resumedIds = [];
        const standbyIds = [];
        for (const a of snap.agents || []) {
          if (a.wave === 1) {
            await paperclip.resumeAgent(a.paperclip_agent_id).catch(() => {});
            resumedIds.push(a.paperclip_agent_id);
          } else {
            if (a.raw_status !== "paused") {
              await paperclip.pauseAgent(a.paperclip_agent_id).catch(() => {});
            }
            standbyIds.push(a.paperclip_agent_id);
          }
        }
        await sync.reconcileNow("resume_wave1");
        return respond(200, {
          ok: true,
          result: { action: "resume_wave1", resumed_wave1: resumedIds, standby_wave2: standbyIds },
        });
      }

      if (method === "GET" && pathname === "/api/office-bridge/health") {
        const matrix = await buildUnifiedHealthMatrix();
        return respond(200, { ok: true, ...matrix });
      }

      if (method === "GET" && pathname === "/api/office-bridge/folders") {
        return respond(200, getTargetFoldersStatus());
      }

      if (method === "POST" && pathname === "/api/office-bridge/folders") {
        const body = await readJsonBody(req);
        const updated = mutateTargetFolders(body);
        return respond(200, updated);
      }

      if (method === "GET" && pathname === "/api/office-bridge/folders/browse") {
        const qPath = urlObj.searchParams.get("path") || "";
        const browsed = browseLocalDirectory(qPath);
        return respond(200, browsed);
      }

      if (method === "GET" && pathname === "/api/office-bridge/evidence") {
        const target = urlObj.searchParams.get("target") || "";
        const evidence = await inspectWorkspaceEvidence(target);
        return respond(200, { ok: true, evidence });
      }

      if (method === "GET" && pathname === "/api/office-bridge/telegram/state") {
        return respond(200, getTelegramControlPublicState(sync));
      }

      if (method === "POST" && pathname === "/api/office-bridge/telegram/command") {
        const body = await readJsonBody(req);
        const effectiveCallerId =
          body.caller_id !== undefined && body.caller_id !== null
            ? String(body.caller_id)
            : auth.callerId;
        const tgResult = await executeTelegramControlCommand(
          {
            sync,
            paperclip,
            eventBus,
            handleCreateTaskAction: (b, c) => handleCreateTaskAction(b, c, correlationId),
            buildAgentInspectorPayload,
            buildUnifiedHealthMatrix,
          },
          {
            ...body,
            correlation_id: body.correlation_id || correlationId,
            caller_id: effectiveCallerId,
          }
        );
        const httpCode = tgResult.ok === false ? Number(tgResult.status || 400) : 200;
        return respond(httpCode, tgResult);
      }

      if (pathname === "/api/office-bridge/layout") {
        if (method === "GET") {
          let saved = null;
          if (fs.existsSync(LAYOUT_FILE)) {
            try {
              saved = JSON.parse(fs.readFileSync(LAYOUT_FILE, "utf8"));
            } catch {}
          }
          return respond(200, { ok: true, departments: sync.departments, saved_layout: saved });
        }
        if (method === "PUT") {
          const body = await readJsonBody(req);
          fs.mkdirSync(path.dirname(LAYOUT_FILE), { recursive: true, mode: 0o700 });
          const clean = sanitizePayload({ updated_at: new Date().toISOString(), layout: body.layout || body });
          fs.writeFileSync(LAYOUT_FILE, JSON.stringify(clean, null, 2) + "\n", "utf8");
          return respond(200, { ok: true, saved_layout: clean });
        }
      }

      return respond(404, { ok: false, error: `Unknown Office Bridge endpoint: ${method} ${pathname}` });
    } catch (err) {
      const code = Number(err.status) || 500;
      return respond(code, {
        ok: false,
        correlation_id: correlationId,
        error: sanitizeText(err.message || "Internal Office Bridge error."),
      });
    }
  });

  // --- Dual WebSocket Servers (`/ws` for Hermes3D Gateway Protocol v3, `/api/events/ws` for Normalized Event Stream) ---
  const { WebSocketServer, WebSocket } = loadWsModule();
  const gatewayWss = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024 });
  const eventsWss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });

  // Normalized Event Stream (`/api/events/ws`)
  eventsWss.on("connection", (ws, req) => {
    const urlObj = new URL(req.url || "/api/events/ws", `http://${host}:${port}`);
    const sinceSeq = Number(urlObj.searchParams.get("sinceSeq") || 0);
    ws.isAlive = true;
    ws.on("pong", () => {
      ws.isAlive = true;
    });

    const safeSend = (obj) => {
      if (ws.readyState !== WebSocket.OPEN) return;
      if (typeof ws.bufferedAmount === "number" && ws.bufferedAmount > WS_BACKPRESSURE_LIMIT_BYTES) {
        if (!ws._backpressureFlagged) {
          ws._backpressureFlagged = true;
          try {
            ws.send(JSON.stringify({ type: "resync_required", latest_sequence: eventBus.sequence }));
          } catch {}
        }
        return;
      }
      ws._backpressureFlagged = false;
      ws.send(JSON.stringify(obj));
    };

    safeSend({
      type: "snapshot.reconcile",
      snapshot: sync.getFullSnapshot(),
      replay_events: sinceSeq > 0 ? eventBus.getEventsSince(sinceSeq, 200) : eventBus.getRecentEvents(40),
    });

    const unsub = eventBus.subscribe((evt) => {
      safeSend({ type: "office.event", event: evt });
    });

    ws.on("close", unsub);
    ws.on("error", unsub);
  });

  // Hermes3D Gateway Protocol v3 (`/ws`)
  gatewayWss.on("connection", (ws) => {
    let authenticated = false;
    let seq = 0;

    const sendFrame = (frame) => {
      if (ws.readyState !== WebSocket.OPEN) return;
      if (typeof ws.bufferedAmount === "number" && ws.bufferedAmount > WS_BACKPRESSURE_LIMIT_BYTES) return;
      if (frame.type === "event" && typeof frame.seq !== "number") {
        frame.seq = seq++;
      }
      ws.send(JSON.stringify(sanitizePayload(frame)));
    };

    ws._sendGatewayFrame = sendFrame;

    sendFrame({ type: "event", event: "connect.challenge", payload: { nonce: crypto.randomUUID().replace(/-/g, "") } });

    const unsubFrames = sync.onHermesGatewayFrame((frame) => {
      if (authenticated) sendFrame({ ...frame });
    });

    ws.on("message", async (raw) => {
      let frame;
      try {
        frame = JSON.parse(raw.toString("utf8"));
      } catch {
        return;
      }
      if (!frame || frame.type !== "req" || typeof frame.id !== "string" || typeof frame.method !== "string") {
        return;
      }
      const { id, method, params } = frame;
      const p = params && typeof params === "object" ? params : {};

      if (method === "connect") {
        const providedToken = p.auth?.token || "";
        if (!guard.verifyConnectFrameToken(providedToken)) {
          sendFrame({
            type: "res",
            id,
            ok: false,
            error: { code: "unauthorized", message: "Valid Office Bridge token required." },
          });
          ws.close(1008, "unauthorized");
          return;
        }
        authenticated = true;
        ws._authenticated = true;
        const snap = sync.getFullSnapshot();
        const defaultAgent = (snap.agents || []).find((a) => a.role === "ceo") || (snap.agents || [])[0];
        sendFrame({
          type: "res",
          id,
          ok: true,
          payload: {
            type: "hello-ok",
            protocol: 3,
            adapterType: "hermes",
            features: {
              methods: [
                "agents.list",
                "agents.files.get",
                "sessions.list",
                "sessions.preview",
                "sessions.usage",
                "usage.cost",
                "runs.list",
                "approvals.list",
                "budgets.get",
                "budgets.set",
                "chat.send",
                "chat.abort",
                "chat.history",
                "status",
                "config.get",
                "exec.approvals.get",
                "exec.approval.resolve",
                "skills.status",
                "models.list",
                "cron.list",
                "tasks.list",
                "tasks.create",
                "tasks.update",
              ],
              events: ["chat", "agent", "presence", "heartbeat", "exec.approval.requested", "exec.approval.resolved"],
            },
            snapshot: {
              health: {
                agents: (snap.agents || []).map((a) => ({
                  agentId: a.paperclip_agent_id,
                  name: a.display_name,
                  isDefault: a.paperclip_agent_id === defaultAgent?.paperclip_agent_id,
                })),
                defaultAgentId: defaultAgent?.paperclip_agent_id || "ceo",
              },
              sessionDefaults: { mainKey: "main" },
            },
            auth: { role: "operator", scopes: ["operator.admin"] },
            policy: { tickIntervalMs: 15000 },
          },
        });
        return;
      }

      if (!authenticated) {
        sendFrame({ type: "res", id, ok: false, error: { code: "not_connected", message: "Authenticate via connect first." } });
        return;
      }

      try {
        const snap = sync.getFullSnapshot();
        const defaultAgent = (snap.agents || []).find((a) => a.role === "ceo") || (snap.agents || [])[0];
        const defaultId = defaultAgent?.paperclip_agent_id || "ceo";
        const activeModel = String(process.env.LLM_MODEL || DEFAULT_LLM_MODEL);
        const tz = resolveTimezone(process.env);

        switch (method) {
          case "agents.list": {
            const list = (snap.agents || []).map((a) => ({
              id: a.paperclip_agent_id,
              roleSlug: a.role_slug,
              name: a.display_name,
              workspace: (a.authorized_workspaces || [])[0],
              identity: { name: a.display_name, emoji: a.badge_emoji || "🤖" },
              role: `${a.activation_status === "ACTIVE" ? "ACTIVE" : "STANDBY"} · ${a.department_short} · ${a.state.visual_state}`,
            }));
            sendFrame({ type: "res", id, ok: true, payload: { defaultId, mainKey: "main", agents: list } });
            break;
          }

          case "agents.create":
          case "agents.delete":
          case "agents.update": {
            sendFrame({
              type: "res",
              id,
              ok: false,
              error: {
                code: "governed_by_paperclip",
                message: "Agent roster lifecycle is governed centrally by Paperclip Control Plane.",
              },
            });
            break;
          }

          case "sessions.list": {
            const sessions = (snap.agents || []).map((a) => ({
              key: `agent:${a.paperclip_agent_id}:main`,
              agentId: a.paperclip_agent_id,
              updatedAt: a.last_heartbeat_at ? Date.parse(a.last_heartbeat_at) : null,
              displayName: a.department,
              origin: { label: a.display_name, provider: "paperclip" },
              model: a.model_id || activeModel,
              modelProvider: "custom",
            }));
            sendFrame({ type: "res", id, ok: true, payload: { sessions } });
            break;
          }

          case "sessions.preview": {
            const keys = Array.isArray(p.keys) ? p.keys : [];
            const previews = keys.map((key) => {
              const aid = String(key).startsWith("agent:") ? String(key).split(":")[1] : defaultId;
              const chatHist = readAgentChatHistory(aid, 6);
              if (chatHist.length > 0) {
                const items = chatHist.map((m) => ({
                  role: m.role,
                  text: m.content,
                  timestamp: m.timestamp || Date.now(),
                }));
                return { key, status: "ok", items };
              }
              const tasks = (snap.tasks || []).filter((t) => t.assigneeAgentId === aid).slice(0, 5);
              if (tasks.length === 0) return { key, status: "empty", items: [] };
              const items = tasks.map((t) => ({
                role: "assistant",
                text: `[${t.identifier || "TASK"} · ${t.status}] ${t.title}`,
                timestamp: Date.parse(t.updatedAt || t.createdAt || new Date().toISOString()),
              }));
              return { key, status: "ok", items };
            });
            sendFrame({ type: "res", id, ok: true, payload: { ts: Date.now(), previews } });
            break;
          }

          case "chat.history": {
            const sessionKey = typeof p.sessionKey === "string" ? p.sessionKey : `agent:${defaultId}:main`;
            const aid = sessionKey.startsWith("agent:") ? sessionKey.split(":")[1] : defaultId;
            const storedChat = readAgentChatHistory(aid, 40);
            const messages = [...storedChat];
            if (messages.length === 0) {
              const agentTasks = (snap.tasks || [])
                .filter((t) => t.assigneeAgentId === aid)
                .slice(0, 10)
                .reverse();
              for (const t of agentTasks) {
                const tsMs = Date.parse(t.updatedAt || t.createdAt || new Date().toISOString());
                messages.push({
                  role: "user",
                  content: `[Paperclip Task ${t.identifier || t.id}] ${t.title}`,
                  timestamp: tsMs - 1,
                });
                messages.push({
                  role: "assistant",
                  content: `Status: **${t.status}** | Priority: \`${t.priority}\`${t.parentId ? ` | Delegated under parent \`${String(t.parentId).slice(0, 8)}\`` : ""}`,
                  timestamp: tsMs,
                });
              }
            }
            sendFrame({ type: "res", id, ok: true, payload: { sessionKey, messages } });
            break;
          }

          case "chat.send": {
            const sessionKey = typeof p.sessionKey === "string" ? p.sessionKey : `agent:${defaultId}:main`;
            const aid = sessionKey.startsWith("agent:") ? sessionKey.split(":")[1] : defaultId;
            const message = sanitizeText(String(p.message || "").trim());
            const idem = typeof p.idempotencyKey === "string" && p.idempotencyKey ? p.idempotencyKey : crypto.randomUUID();
            if (!message) {
              sendFrame({ type: "res", id, ok: true, payload: { status: "no-op", runId: idem } });
              break;
            }

            const targetAgent = (snap.agents || []).find((a) => a.paperclip_agent_id === aid) || defaultAgent;
            const turn = await handleEmployeeChatTurn({
              agent: targetAgent,
              snapshot: snap,
              rawMessage: message,
              idempotencyKey: idem,
              createTaskFn: handleCreateTaskAction,
              sync,
              paperclip,
              callerId: resolveAuthorizedOwnerId(process.env) || "ws_operator",
            });

            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: {
                status: "completed",
                runId: idem,
                text: turn.text,
                createdTaskId: turn.createdTask?.id || null,
                createdMeetingId: turn.createdMeeting?.meeting_id || null,
              },
            });
            break;
          }

          case "chat.abort": {
            const runId = typeof p.runId === "string" ? p.runId.trim() : "";
            let aborted = 0;
            if (runId) {
              await paperclip.cancelRun(runId).catch(() => {});
              aborted = 1;
            }
            await sync.reconcileNow("ws_chat_abort");
            sendFrame({ type: "res", id, ok: true, payload: { ok: true, aborted } });
            break;
          }

          case "models.list": {
            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: { models: [{ id: activeModel, name: `${activeModel} (Custom Provider)`, provider: "custom" }] },
            });
            break;
          }

          case "skills.status": {
            const reqAgentId = typeof p?.agentId === "string" ? p.agentId : null;
            const paperclipSkills = snap.company?.id
              ? await paperclip.listCompanySkills(snap.company.id).catch(() => [])
              : [];
            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: buildStudioSkillsStatusPayload(snap, reqAgentId, paperclipSkills),
            });
            break;
          }

          case "cron.list": {
            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: {
                jobs: [
                  {
                    id: "platform-daily-maintenance-0300",
                    name: `Coordinated 03:00 (${tz}) Maintenance & Catch-Up`,
                    agentId: defaultId,
                    description: `Daily 03:00 ${tz} sequential maintenance with offline catch-up and active-task deferral.`,
                    enabled: true,
                    updatedAtMs: Date.now(),
                    schedule: { kind: "cron", expr: "0 3 * * *", tz },
                    sessionTarget: "isolated",
                    wakeMode: "next-heartbeat",
                    payload: { kind: "systemEvent", text: `Run daily 03:00 (${tz}) coordinated maintenance check.` },
                    state: { lastStatus: "ok" },
                  },
                ],
              },
            });
            break;
          }

          case "agents.files.get": {
            const reqAgentId = typeof p.agentId === "string" ? p.agentId : defaultId;
            const fileName = typeof p.name === "string" ? p.name : "IDENTITY.md";
            const ag = (snap.agents || []).find((a) => a.paperclip_agent_id === reqAgentId) || defaultAgent;
            const agSkillSpec = ag ? findAgentAssignment(ag.paperclip_agent_id, loadEnrichedAssignments(snap)) : null;
            const skillLines = agSkillSpec
              ? (agSkillSpec.skills || []).map(
                  (s) =>
                    `  - \`${s.pkg_id}\` (**${s.display_name}**) — \`${s.category}\` · \`${s.status}\` · commit \`${String(s.pinned_commit_sha).slice(0, 8)}\`${s.last_used ? ` · last used \`${s.last_used}\`` : ""}${s.last_result ? ` · _${s.last_result.slice(0, 80)}_` : ""}`
                )
              : [];
            const content = ag
              ? [
                  `# ${ag.display_name} (${ag.title})`,
                  `- **Paperclip ID:** \`${ag.paperclip_agent_id}\``,
                  `- **Department:** ${ag.department}`,
                  `- **Hermes Profile:** \`${agSkillSpec?.profile || ag.runtime_profile_reference || "pcworker"}\``,
                  `- **Model:** \`${ag.model_id || activeModel}\``,
                  `- **Activation:** \`${ag.activation_status}\``,
                  `- **Assigned Skills (${skillLines.length || (ag.skills || []).length}):** ${(ag.skills || []).join(", ")}`,
                  ...skillLines,
                  agSkillSpec?.latest_task_reference ? `- **Task Reference:** ${agSkillSpec.latest_task_reference}` : null,
                ]
                  .filter(Boolean)
                  .join("\n")
              : "# ALLINAGENT Employee";
            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: { file: { name: fileName, missing: false, content } },
            });
            break;
          }

          case "tasks.list": {
            const mapBoardStatus = (s) => {
              const st = String(s || "").toLowerCase();
              if (st === "done") return "done";
              if (st === "in_progress") return "working";
              if (st === "blocked" || st === "in_review") return "needs_attention";
              if (st === "backlog") return "scheduled";
              return "inbox";
            };
            const tasks = (snap.tasks || []).slice(0, 60).map((t) => ({
              id: `kanban:${t.id}`,
              title: `[${t.identifier || "TASK"}] ${t.title}`,
              description: t.description || "",
              status: mapBoardStatus(t.status),
              source: "hermes_event",
              sourceEventId: t.id,
              assignedAgentId: t.assigneeAgentId || null,
              createdAt: t.createdAt || new Date().toISOString(),
              updatedAt: t.updatedAt || t.createdAt || new Date().toISOString(),
              notes: [],
              archived: t.status === "cancelled" || t.status === "canceled",
            }));
            sendFrame({ type: "res", id, ok: true, payload: { tasks } });
            break;
          }

          case "tasks.create": {
            const configuredOwner = guard._effectiveOwnerId();
            if (!configuredOwner) {
              sendFrame({
                type: "res",
                id,
                ok: false,
                error: { code: "owner_id_not_configured", message: "OWNER_TELEGRAM_ID is not configured (fail-closed)." },
              });
              break;
            }
            const created = await handleCreateTaskAction(
              {
                title: String(p.title || "Kanban Task"),
                description: String(p.description || p.title || ""),
                assignee_agent_id: p.assignedAgentId || defaultId,
                wake_immediately: false,
              },
              configuredOwner
            );
            const t = created.task;
            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: {
                id: `kanban:${t.id}`,
                title: `[${t.identifier || "TASK"}] ${t.title}`,
                description: t.description || "",
                status: "inbox",
                source: "hermes3d_manual",
                assignedAgentId: t.assigneeAgentId || null,
                createdAt: t.createdAt || new Date().toISOString(),
                updatedAt: t.updatedAt || new Date().toISOString(),
                notes: [],
                archived: false,
              },
            });
            break;
          }

          case "tasks.update": {
            const configuredOwner = guard._effectiveOwnerId();
            if (!configuredOwner) {
              sendFrame({
                type: "res",
                id,
                ok: false,
                error: { code: "owner_id_not_configured", message: "OWNER_TELEGRAM_ID is not configured (fail-closed)." },
              });
              break;
            }
            const rawTaskId = String(p.id || "").replace(/^kanban:/, "");
            const statusMapReverse = {
              inbox: "todo",
              scheduled: "backlog",
              working: "in_progress",
              needs_attention: "in_review",
              done: "done",
            };
            const nextPcStatus = p.status ? statusMapReverse[p.status] || "todo" : undefined;
            const updated = await paperclip.updateTask(rawTaskId, {
              ...(nextPcStatus ? { status: nextPcStatus } : {}),
              ...(p.assignedAgentId !== undefined ? { assigneeAgentId: p.assignedAgentId } : {}),
              ...(p.title ? { title: String(p.title).replace(/^\[[^\]]+\]\s*/, "") } : {}),
            });
            await sync.reconcileNow("ws_kanban_update");
            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: {
                id: `kanban:${updated.id}`,
                title: `[${updated.identifier || "TASK"}] ${updated.title}`,
                description: updated.description || "",
                status: p.status || "inbox",
                assignedAgentId: updated.assigneeAgentId || null,
                createdAt: updated.createdAt || new Date().toISOString(),
                updatedAt: updated.updatedAt || new Date().toISOString(),
              },
            });
            break;
          }

          case "config.get": {
            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: {
                config: {
                  gateway: { reload: { mode: "hot" } },
                  agents: { list: buildGatewayAgentsSkillsConfigList(snap) },
                },
                hash: "office-bridge-v2-skills",
                exists: true,
                path: "paperclip://allinagent-company",
              },
            });
            break;
          }

          case "exec.approvals.get": {
            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: {
                path: "",
                exists: true,
                hash: "paperclip-approvals",
                file: { version: 1, defaults: { security: "governed", ask: "on-gate", autoAllowSkills: false }, agents: {} },
              },
            });
            break;
          }

          case "exec.approval.resolve": {
            const configuredOwner = guard._effectiveOwnerId();
            if (!configuredOwner) {
              sendFrame({
                type: "res",
                id,
                ok: false,
                error: { code: "owner_id_not_configured", message: "OWNER_TELEGRAM_ID is not configured (fail-closed)." },
              });
              break;
            }
            const approvalId = String(p.id || p.approvalId || p.requestId || "").trim();
            if (!approvalId) {
              sendFrame({
                type: "res",
                id,
                ok: false,
                error: { code: "invalid_params", message: "Approval id is required." },
              });
              break;
            }
            const rawDecision = String(p.decision || "approve").trim();
            const note = sanitizeText(String(p.note || "").trim());

            let resolvedApproval;
            if (approvalId.startsWith("req_")) {
              const consumed = consumeBoundApprovalRequest({
                requestId: approvalId,
                callerId: configuredOwner,
                decision: rawDecision,
                note,
              });
              if (!consumed.ok) {
                sendFrame({
                  type: "res",
                  id,
                  ok: false,
                  error: { code: consumed.code || "approval_error", message: consumed.error },
                });
                break;
              }
              resolvedApproval = consumed.record;
            } else {
              resolvedApproval = await paperclip.resolveApproval(approvalId, rawDecision, note);
              await sync.reconcileNow("ws_exec_approval_resolve");
            }

            const eventPayload = {
              id: approvalId,
              decision: rawDecision,
              resolvedBy: `owner:${configuredOwner}`,
              resolvedAtMs: Date.now(),
              approval: resolvedApproval,
            };

            eventBus.publish({
              event_type: "approval.resolved",
              source: "office_bridge",
              company_id: snap.company?.id || "company",
              dedupe_key: `ws_appr_res:${approvalId}:${Date.now()}`,
              payload: eventPayload,
            });

            for (const client of gatewayWss.clients) {
              if (client._authenticated && typeof client._sendGatewayFrame === "function") {
                client._sendGatewayFrame({
                  type: "event",
                  event: "exec.approval.resolved",
                  payload: eventPayload,
                });
              }
            }

            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: {
                ok: true,
                id: approvalId,
                decision: rawDecision,
                resolvedBy: `owner:${configuredOwner}`,
                approval: resolvedApproval,
              },
            });
            break;
          }

          case "sessions.usage": {
            const analytics = buildUsageAndCostAnalytics({
              snapshot: snap,
              startDate: typeof p.startDate === "string" ? p.startDate : undefined,
              endDate: typeof p.endDate === "string" ? p.endDate : undefined,
              limit: Number(p.limit || 1000),
            });
            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: {
                sessions: analytics.sessions,
                totals: analytics.totals,
                corporateBudgets: analytics.corporateBudgets,
                pricingModel: analytics.pricingModel,
              },
            });
            break;
          }

          case "usage.cost": {
            const analytics = buildUsageAndCostAnalytics({
              snapshot: snap,
              startDate: typeof p.startDate === "string" ? p.startDate : undefined,
              endDate: typeof p.endDate === "string" ? p.endDate : undefined,
            });
            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: {
                daily: analytics.daily,
              },
            });
            break;
          }

          case "runs.list": {
            const runs = await buildHistoricalRunRecords({
              snapshot: snap,
              paperclip,
              limit: Number(p.limit || 200),
            });
            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: { runs },
            });
            break;
          }

          case "approvals.list": {
            const records = buildApprovalRecords({ snapshot: snap });
            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: { records },
            });
            break;
          }

          case "budgets.get": {
            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: { budgets: resolveCorporateBudgets(snap) },
            });
            break;
          }

          case "budgets.set": {
            const configuredOwner = guard._effectiveOwnerId();
            if (!configuredOwner) {
              sendFrame({
                type: "res",
                id,
                ok: false,
                error: { code: "owner_id_not_configured", message: "OWNER_TELEGRAM_ID is not configured (fail-closed)." },
              });
              break;
            }
            const synced = await syncBudgetsWithPaperclip({
              nextBudgets: p.budgets || p,
              paperclip,
              companyId: snap.company?.id || null,
              sync,
            });
            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: { ok: true, budgets: synced, paperclip_synced: synced.paperclip_synced },
            });
            break;
          }

          case "status": {
            const activeAgents = (snap.agents || []).filter((a) => a.state.retro_status === "working");
            const now = Date.now();
            sendFrame({
              type: "res",
              id,
              ok: true,
              payload: {
                sessions: {
                  recent: activeAgents.map((a) => ({ key: `agent:${a.paperclip_agent_id}:main`, updatedAt: now })),
                  byAgent: (snap.agents || []).map((a) => ({
                    agentId: a.paperclip_agent_id,
                    recent: a.state.retro_status === "working" ? [{ key: `agent:${a.paperclip_agent_id}:main`, updatedAt: now }] : [],
                  })),
                },
              },
            });
            break;
          }

          default: {
            sendFrame({ type: "res", id, ok: true, payload: {} });
            break;
          }
        }
      } catch (err) {
        sendFrame({
          type: "res",
          id,
          ok: false,
          error: { code: "bridge_error", message: sanitizeText(err.message || "Bridge request failed.") },
        });
      }
    });

    ws.on("close", unsubFrames);
    ws.on("error", unsubFrames);
  });

  const wsPingInterval = setInterval(() => {
    for (const client of eventsWss.clients) {
      if (client.isAlive === false) {
        client.terminate();
        continue;
      }
      client.isAlive = false;
      try {
        client.ping();
      } catch {}
    }
  }, 25_000);
  if (wsPingInterval.unref) wsPingInterval.unref();

  server.on("upgrade", (req, socket, head) => {
    const urlObj = new URL(req.url || "/", `http://${host}:${port}`);
    if (urlObj.pathname === "/api/events/ws") {
      const check = guard.authorizeWsUpgrade(req, urlObj, { requireUpgradeToken: true });
      if (!check.ok) {
        rejectSocketUpgrade(socket, check.status, check.error);
        return;
      }
      eventsWss.handleUpgrade(req, socket, head, (ws) => {
        eventsWss.emit("connection", ws, req);
      });
      return;
    }

    if (urlObj.pathname === "/ws" || urlObj.pathname === "/") {
      const check = guard.authorizeWsUpgrade(req, urlObj, { requireUpgradeToken: false });
      if (!check.ok) {
        rejectSocketUpgrade(socket, check.status, check.error);
        return;
      }
      gatewayWss.handleUpgrade(req, socket, head, (ws) => {
        gatewayWss.emit("connection", ws, req);
      });
      return;
    }

    rejectSocketUpgrade(socket, 404, "Unknown WebSocket endpoint");
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });

  const address = server.address();
  const actualPort = typeof address === "object" && address ? address.port : port;

  async function close() {
    clearInterval(wsPingInterval);
    sync.stop();
    for (const c of eventsWss.clients) {
      try {
        c.terminate();
      } catch {}
    }
    for (const c of gatewayWss.clients) {
      try {
        c.terminate();
      } catch {}
    }
    if (typeof server.closeAllConnections === "function") {
      server.closeAllConnections();
    }
    await new Promise((resolve) => server.close(() => resolve()));
  }

  return {
    host,
    port: actualPort,
    server,
    sync,
    eventBus,
    guard,
    secrets,
    close,
  };
}

if (require.main === module) {
  acquireSingletonPidLock();
  createOfficeBridgeApp()
    .then((app) => {
      console.log(`[office-bridge] Listening on http://${app.host}:${app.port} (WS: /ws, /api/events/ws)`);
      const shutdown = async () => {
        console.log("[office-bridge] Graceful shutdown initiated...");
        await app.close().catch(() => {});
        releaseSingletonPidLock();
        process.exit(0);
      };
      process.on("SIGINT", shutdown);
      process.on("SIGTERM", shutdown);
      process.on("exit", () => releaseSingletonPidLock());
    })
    .catch((err) => {
      console.error("[office-bridge] Fatal startup error:", sanitizeText(err.message));
      if (err.code !== "SINGLETON_ALREADY_RUNNING") {
        releaseSingletonPidLock();
      }
      process.exit(1);
    });
}

module.exports = {
  createOfficeBridgeApp,
  acquireSingletonPidLock,
  releaseSingletonPidLock,
};
