"use strict";

/**
 * PHASES 18, 19 & 20 — Deduplicated Event Notifications, Long-Running Async Job Manager,
 * Deterministic Bahasa Indonesia Natural Language Router (POSIX + Win32 Path Aware),
 * and Reliability/Circuit-Breaker/Dead-Letter Engine.
 *
 * Cross-platform portable (`contracts/paths.js`), zero hardcoded Windows paths or project names.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { OFFICE_DATA_DIR, DATA_DIR } = require("../contracts/paths");
const { sanitizeText, sanitizePayload } = require("../contracts/redaction");
const { sendTelegramNotificationViaExistingBridge } = require("../adapters/vulnclaw-findings-adapter");

const ASYNC_JOBS_FILE = path.resolve(path.join(OFFICE_DATA_DIR, "telegram-async-jobs.json"));
const NOTIFICATIONS_LEDGER_FILE = path.resolve(path.join(OFFICE_DATA_DIR, "telegram-notifications-ledger.json"));
const DEAD_LETTER_FILE = path.resolve(path.join(OFFICE_DATA_DIR, "telegram-dead-letter.jsonl"));
const MAINT_LOCK_FILE = path.resolve(path.join(DATA_DIR, "maintenance", "maintenance.lock"));

const NOTIFICATION_SEVERITIES = Object.freeze({
  INFO: "ℹ️ INFO",
  SUCCESS: "✅ SUCCESS",
  WARNING: "⚠️ WARNING",
  ERROR: "❌ ERROR",
  ACTION_REQUIRED: "🚨 ACTION_REQUIRED",
});

// =============================================================================
// PHASE 20 — Circuit Breaker, Retry/Backoff, Singleton Lock & Dead-Letter Queue
// =============================================================================
const CIRCUIT_BREAKERS = new Map();
const SINGLETON_LOCKS = new Set();

function getBreaker(name, { failureThreshold = 4, openDurationMs = 20_000 } = {}) {
  if (!CIRCUIT_BREAKERS.has(name)) {
    CIRCUIT_BREAKERS.set(name, {
      name,
      state: "CLOSED",
      failures: 0,
      opened_at_ms: 0,
      failureThreshold,
      openDurationMs,
    });
  }
  return CIRCUIT_BREAKERS.get(name);
}

async function executeWithResilience(breakerName, fn, { maxRetries = 2, baseDelayMs = 300 } = {}) {
  const brk = getBreaker(breakerName);
  if (brk.state === "OPEN") {
    if (Date.now() - brk.opened_at_ms >= brk.openDurationMs) {
      brk.state = "HALF_OPEN";
    } else {
      const err = new Error(`Circuit breaker '${breakerName}' sedang OPEN sementara untuk melindungi stabilitas sistem.`);
      err.code = "CIRCUIT_OPEN";
      err.status = 503;
      throw err;
    }
  }

  let lastErr = null;
  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    try {
      const result = await fn(attempt);
      brk.failures = 0;
      brk.state = "CLOSED";
      return result;
    } catch (err) {
      lastErr = err;
      if (err && err.status && err.status >= 400 && err.status < 500 && err.status !== 429) {
        throw err;
      }
      brk.failures += 1;
      if (brk.failures >= brk.failureThreshold) {
        brk.state = "OPEN";
        brk.opened_at_ms = Date.now();
        break;
      }
      if (attempt < maxRetries) {
        const delay = baseDelayMs * Math.pow(2, attempt);
        await new Promise((r) => setTimeout(r, delay));
      }
    }
  }
  throw lastErr;
}

async function withSingletonLock(lockKey, fn) {
  if (SINGLETON_LOCKS.has(lockKey)) {
    const err = new Error(`Operasi '${lockKey}' sedang berjalan (singleton lock mencegah eksekusi ganda).`);
    err.code = "SINGLETON_BUSY";
    err.status = 409;
    throw err;
  }
  SINGLETON_LOCKS.add(lockKey);
  try {
    return await fn();
  } finally {
    SINGLETON_LOCKS.delete(lockKey);
  }
}

function isMaintenanceLockActive() {
  try {
    if (fs.existsSync(MAINT_LOCK_FILE)) {
      const ageMs = Date.now() - fs.statSync(MAINT_LOCK_FILE).mtimeMs;
      return ageMs < 5400_000;
    }
  } catch {}
  return false;
}

function recordDeadLetter(entry) {
  try {
    fs.mkdirSync(path.dirname(DEAD_LETTER_FILE), { recursive: true, mode: 0o700 });
    const rec = sanitizePayload({
      dead_letter_id: `dlq_${crypto.randomBytes(4).toString("hex")}`,
      timestamp: new Date().toISOString(),
      ...entry,
    });
    fs.appendFileSync(DEAD_LETTER_FILE, JSON.stringify(rec) + "\n", "utf8");
    return rec;
  } catch {
    return null;
  }
}

function listDeadLetters(limit = 10) {
  if (!fs.existsSync(DEAD_LETTER_FILE)) return [];
  try {
    return fs
      .readFileSync(DEAD_LETTER_FILE, "utf8")
      .split(/\r?\n/)
      .filter(Boolean)
      .slice(-limit)
      .map((l) => JSON.parse(l))
      .reverse();
  } catch {
    return [];
  }
}

function getCircuitBreakerSnapshot() {
  const out = {};
  for (const [k, v] of CIRCUIT_BREAKERS.entries()) {
    out[k] = { state: v.state, failures: v.failures };
  }
  return out;
}

// =============================================================================
// PHASE 18 — Deduplicated & Throttled Activity Notification Engine + Async Jobs
// =============================================================================
function loadNotificationsLedger() {
  try {
    if (fs.existsSync(NOTIFICATIONS_LEDGER_FILE)) {
      return JSON.parse(fs.readFileSync(NOTIFICATIONS_LEDGER_FILE, "utf8"));
    }
  } catch {}
  return { seen_keys: {}, last_sent_by_category: {}, recent_events: [] };
}

function saveNotificationsLedger(ledger) {
  const now = Date.now();
  const seen = Object.entries(ledger.seen_keys || {}).filter(([, ts]) => now - Number(ts) < 24 * 3600_000);
  ledger.seen_keys = Object.fromEntries(seen.slice(-500));
  ledger.recent_events = (ledger.recent_events || []).slice(-100);
  fs.mkdirSync(path.dirname(NOTIFICATIONS_LEDGER_FILE), { recursive: true, mode: 0o700 });
  fs.writeFileSync(NOTIFICATIONS_LEDGER_FILE, JSON.stringify(ledger, null, 2) + "\n", "utf8");
}

async function emitActivityNotification({
  eventType,
  severity = "INFO",
  dedupeKey,
  title,
  detail = "",
  deliverToTelegram = false,
  throttleCategoryMs = 8_000,
}) {
  const ledger = loadNotificationsLedger();
  const key = String(dedupeKey || `${eventType}:${title}`);
  if (ledger.seen_keys[key]) {
    return { ok: true, deduplicated: true, delivered: false };
  }

  const now = Date.now();
  const sevTag = NOTIFICATION_SEVERITIES[severity] || NOTIFICATION_SEVERITIES.INFO;
  const cat = String(eventType || "general").split(".")[0];
  const lastCatAt = Number((ledger.last_sent_by_category || {})[cat] || 0);
  const throttled =
    deliverToTelegram &&
    now - lastCatAt < throttleCategoryMs &&
    severity !== "ACTION_REQUIRED" &&
    severity !== "ERROR";

  ledger.seen_keys[key] = now;
  const eventRecord = sanitizePayload({
    event_id: `evt_${crypto.randomBytes(4).toString("hex")}`,
    event_type: eventType,
    severity,
    title: sanitizeText(title),
    detail: sanitizeText(detail).slice(0, 400),
    throttled,
    created_at: new Date(now).toISOString(),
  });
  ledger.recent_events = [...(ledger.recent_events || []), eventRecord];

  let delivered = false;
  if (deliverToTelegram && !throttled) {
    ledger.last_sent_by_category = ledger.last_sent_by_category || {};
    ledger.last_sent_by_category[cat] = now;
    saveNotificationsLedger(ledger);
    try {
      const msg = `${sevTag} — *${sanitizeText(title)}*\n${sanitizeText(detail)}`.trim();
      await sendTelegramNotificationViaExistingBridge(msg);
      delivered = true;
    } catch {}
    return { ok: true, deduplicated: false, throttled: false, delivered, event: eventRecord };
  }

  saveNotificationsLedger(ledger);
  return { ok: true, deduplicated: false, throttled, delivered: false, event: eventRecord };
}

function loadAsyncJobs() {
  try {
    if (fs.existsSync(ASYNC_JOBS_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(ASYNC_JOBS_FILE, "utf8"));
      if (Array.isArray(parsed)) return parsed;
    }
  } catch {}
  return [];
}

function saveAsyncJobs(jobs) {
  fs.mkdirSync(path.dirname(ASYNC_JOBS_FILE), { recursive: true, mode: 0o700 });
  const trimmed = (Array.isArray(jobs) ? jobs : []).slice(-120);
  fs.writeFileSync(ASYNC_JOBS_FILE, JSON.stringify(trimmed, null, 2) + "\n", "utf8");
  return trimmed;
}

const IN_MEMORY_JOB_CONTROLLERS = new Map();

function enqueueAsyncJob({
  title,
  command,
  target = null,
  idempotencyKey = null,
  notifyOnFinish = false,
  workerFn,
}) {
  const jobs = loadAsyncJobs();
  if (idempotencyKey) {
    const existing = jobs.find(
      (j) => j.idempotency_key === idempotencyKey && ["QUEUED", "RUNNING", "COMPLETED"].includes(j.status)
    );
    if (existing) {
      return { deduplicated: true, job: existing };
    }
  }

  const jobId = `job_${Date.now().toString(36)}_${crypto.randomBytes(3).toString("hex")}`;
  const nowIso = new Date().toISOString();
  const jobRecord = {
    job_id: jobId,
    idempotency_key: idempotencyKey || null,
    title: sanitizeText(title),
    command,
    target: target ? sanitizeText(target) : null,
    status: "RUNNING",
    progress_pct: 10,
    progress_note: "Pekerjaan diterima & mulai dieksekusi di latar belakang",
    result_summary: null,
    error: null,
    created_at: nowIso,
    updated_at: nowIso,
    finished_at: null,
  };

  jobs.push(jobRecord);
  saveAsyncJobs(jobs);

  const abortCtrl = new AbortController();
  IN_MEMORY_JOB_CONTROLLERS.set(jobId, abortCtrl);

  setImmediate(async () => {
    try {
      const out = await workerFn({
        signal: abortCtrl.signal,
        updateProgress: (pct, note) => {
          const cur = loadAsyncJobs();
          const idx = cur.findIndex((x) => x.job_id === jobId);
          if (idx >= 0 && cur[idx].status === "RUNNING") {
            cur[idx].progress_pct = Math.max(0, Math.min(99, Number(pct) || 50));
            cur[idx].progress_note = sanitizeText(String(note || ""));
            cur[idx].updated_at = new Date().toISOString();
            saveAsyncJobs(cur);
          }
        },
      });

      const cur = loadAsyncJobs();
      const idx = cur.findIndex((x) => x.job_id === jobId);
      if (idx >= 0 && cur[idx].status !== "CANCELLED") {
        cur[idx].status = "COMPLETED";
        cur[idx].progress_pct = 100;
        cur[idx].progress_note = "Selesai & terverifikasi";
        cur[idx].result_summary = sanitizePayload(out || { ok: true });
        cur[idx].finished_at = new Date().toISOString();
        cur[idx].updated_at = cur[idx].finished_at;
        saveAsyncJobs(cur);

        await emitActivityNotification({
          eventType: "agent.completed",
          severity: "SUCCESS",
          dedupeKey: `job_done:${jobId}`,
          title: `Pekerjaan Selesai (${jobId})`,
          detail: cur[idx].title,
          deliverToTelegram: notifyOnFinish,
        });
      }
    } catch (err) {
      const cur = loadAsyncJobs();
      const idx = cur.findIndex((x) => x.job_id === jobId);
      const isCancelled = abortCtrl.signal.aborted;
      if (idx >= 0) {
        cur[idx].status = isCancelled ? "CANCELLED" : "FAILED";
        cur[idx].error = sanitizeText(err.message || "Job failed");
        cur[idx].finished_at = new Date().toISOString();
        cur[idx].updated_at = cur[idx].finished_at;
        saveAsyncJobs(cur);
      }
      if (!isCancelled) {
        recordDeadLetter({ job_id: jobId, command, title, error: sanitizeText(err.message || "Unknown failure") });
        await emitActivityNotification({
          eventType: "task.blocked",
          severity: "ERROR",
          dedupeKey: `job_fail:${jobId}`,
          title: `Pekerjaan Gagal (${jobId})`,
          detail: sanitizeText(err.message || ""),
          deliverToTelegram: notifyOnFinish,
        });
      }
    } finally {
      IN_MEMORY_JOB_CONTROLLERS.delete(jobId);
    }
  });

  return { deduplicated: false, job: jobRecord };
}

function cancelAsyncJob(jobId) {
  const cleanId = String(jobId || "").trim();
  const jobs = loadAsyncJobs();
  const idx = jobs.findIndex((j) => j.job_id === cleanId);
  if (idx < 0) return { ok: false, status: 404, error: `Job '${sanitizeText(cleanId)}' tidak ditemukan.` };
  if (!["QUEUED", "RUNNING"].includes(jobs[idx].status)) {
    return { ok: true, already_terminal: true, job: jobs[idx] };
  }
  const ctrl = IN_MEMORY_JOB_CONTROLLERS.get(cleanId);
  if (ctrl) {
    try {
      ctrl.abort(new Error("Cancelled by Owner via Telegram"));
    } catch {}
    IN_MEMORY_JOB_CONTROLLERS.delete(cleanId);
  }
  jobs[idx].status = "CANCELLED";
  jobs[idx].progress_note = "Dibatalkan oleh Owner dari Telegram";
  jobs[idx].finished_at = new Date().toISOString();
  jobs[idx].updated_at = jobs[idx].finished_at;
  saveAsyncJobs(jobs);
  return { ok: true, job: jobs[idx] };
}

// =============================================================================
// PHASE 19 — Comprehensive Deterministic Bahasa Indonesia Natural Language Router
// =============================================================================
function routeIndonesianNaturalIntent(
  rawText,
  { tgState, folderStatus, resolveCorporateAgentEntry, extractTargetProjectPath }
) {
  const text = String(rawText || "").trim();
  const lower = text.toLowerCase();
  if (!text) return { kind: "passthrough" };

  // 1. Destructive ambiguity guard
  if (
    /\b(hapus\s+(?:semua|seluruh|folder|project|proyek|database|data)|(?:reset|drop|kosongkan|wipe)\s+database|format\s+drive|migrate:fresh|db:wipe|rm\s+-rf|del\s+\/s|git\s+reset\s+--hard|git\s+clean\s+-[a-z]*f)\b/i.test(
      lower
    )
  ) {
    return {
      kind: "destructive_blocked",
      reason: "Tindakan destruktif (penghapusan massal / reset database) memerlukan otorisasi eksplisit dengan target spesifik dan tidak dijalankan otomatis.",
    };
  }

  // 2. Local desktop GUI operational passthrough (when not targeting AI company)
  if (
    /\b(screenshot\s+desktop|buka\s+(vscode|vs\s*code|notepad|chrome|firefox|edge|file\s+explorer)|cua:|hermes-elevate)\b/i.test(lower) &&
    !/\b(kantor|office|3d|2d|agen|ceo|cto|backend|paperclip|meeting|rapat|vulnclaw)\b/i.test(lower)
  ) {
    return { kind: "passthrough" };
  }

  // 3. Screenshot 3D / 2D Virtual Office
  if (/\b(screenshot|tangkap\s+layar|foto)\b.*\b(kantor|office|3d|2d)\b/i.test(lower)) {
    const mode = /\b2d\b/i.test(lower) ? "2d" : "3d";
    return { kind: "command", command: "screenshot_kantor", args: mode };
  }

  // 4. Release direct-agent mode
  if (/^(lepas\s+(mode\s+)?agen|keluar\s+(dari\s+)?mode\s+agen|kembali\s+ke\s+hermes(\s+umum)?|mode\s+hermes(\s+umum)?)$/i.test(lower)) {
    return { kind: "command", command: "lepas", args: "" };
  }

  // 5. `@handle` addressing
  const atMatch = text.match(/^@([a-zA-Z0-9_-]+)(?:\s*[:,-]?\s*(.*))?$/s);
  if (atMatch) {
    const ag = resolveCorporateAgentEntry(atMatch[1]);
    if (ag) {
      const rem = (atMatch[2] || "").trim();
      if (!rem) return { kind: "command", command: "pilih", args: String(ag.index) };
      return { kind: "ask_agent", agentEntry: ag, message: rem };
    }
  }

  // 6. Agent selection
  const sw = text.match(
    /^(?:tolong\s+)?(?:pilih\s+agen|pilih\s+karyawan|ganti\s+(?:ke\s+)?agen|pindah\s+(?:ke\s+)?agen|gunakan\s+agen|bicara\s+(?:dengan|sama)(?:\s+agen)?)\s+([A-Za-z0-9_ @&.-]{2,35})[.!?]*$/i
  );
  if (sw) {
    const ag = resolveCorporateAgentEntry(sw[1].trim());
    if (ag) return { kind: "command", command: "pilih", args: String(ag.index) };
  }

  // 7. CEO Multi-Agent Delegation
  if (
    /\b(delegasikan|membagi\s+pekerjaan|bagi\s+pekerjaan|bagi\s+tugas)\b/i.test(lower) &&
    (/\bceo\b/i.test(lower) || tgState?.selected_agent_slug === "ceo_agent" || !tgState?.direct_agent_mode)
  ) {
    return { kind: "command", command: "delegasi", args: text };
  }

  // 8. Meeting conclude / minutes / discussion / gather
  if (/\b(selesaikan|akhiri|bubarkan|tutup|batalkan)\s+(meeting|rapat)\b/i.test(lower)) {
    const isCancel = /\bbatalkan\b/i.test(lower);
    return { kind: "command", command: "selesai_meeting", args: isCancel ? `--cancel ${text}` : text };
  }
  if (/\b(notulen|hasil\s+rapat|ringkasan\s+rapat|riwayat\s+(meeting|rapat))\b/i.test(lower)) {
    const isHist = /\briwayat\b/i.test(lower);
    return { kind: "command", command: "notulen", args: isHist ? "history" : "" };
  }
  if (
    /\b(kumpulkan\s+(?:semua\s+|seluruh\s+)?(?:\d+\s+|kesebelas\s+)?(?:agen|tim|karyawan)|(?:di|ke|diruang)\s*ruang\s*meet(?:ing)?|meeting\s+room|adakan\s+(?:meeting|rapat)|mulai\s+(?:meeting|rapat))\b/i.test(
      lower
    )
  ) {
    return { kind: "command", command: "meeting", args: text };
  }

  // 9. Folder selection & exploration (supports both POSIX `/workspaces/...` and Win32 `D:\workspaces\...`)
  if (/\b(jadikan\s+folder|setel\s+folder|pilih\s+folder|ganti\s+folder(?:\s+aktif)?)\b/i.test(lower)) {
    const ext = extractTargetProjectPath(text, { returnAttemptInfo: true });
    const p = ext.resolved || ext.explicitAttempt || folderStatus?.active_folder || "";
    if (p) return { kind: "command", command: "pilih_folder", args: p };
  }
  if (/^(?:tolong\s+)?(?:jelajahi|jelajah|lihat\s+subfolder|buka\s+daftar\s+folder)\s+(.+)$/i.test(text)) {
    const m = text.match(/^(?:tolong\s+)?(?:jelajahi|jelajah|lihat\s+subfolder|buka\s+daftar\s+folder)\s+(.+)$/i);
    return { kind: "command", command: "jelajah", args: m[1].trim() };
  }

  // 10. Real Source Code Analysis
  if (/\b(tampilkan|lihat)\s+hasil\s+audit\s+terbaru\b/i.test(lower)) {
    return { kind: "command", command: "analisis", args: "--latest" };
  }
  if (/^(?:tolong\s+)?(?:analisis|audit)\s+(?:folder|proyek|project|source\s+code|kode)\b/i.test(lower)) {
    const ext = extractTargetProjectPath(text, { returnAttemptInfo: true });
    const p = ext.resolved || ext.explicitAttempt || folderStatus?.active_folder || "";
    return { kind: "command", command: "analisis", args: p };
  }

  // 11. Token, Analytics & Budget queries
  if (/\b(berapa\s+(?:total\s+)?token|penggunaan\s+token|statistik\s+token|analytics\s+hari\s+ini)\b/i.test(lower)) {
    const win = /hari\s+ini|today/i.test(lower)
      ? "today"
      : /kemarin|yesterday/i.test(lower)
        ? "yesterday"
        : /7\s*hari|minggu/i.test(lower)
          ? "7d"
          : "30d";
    return { kind: "command", command: "analytics", args: win };
  }
  if (/\b(berapa\s+(?:sisa\s+)?budget|budget\s+(?:yang\s+)?tersisa|sisa\s+anggaran|pagu\s+budget)\b/i.test(lower)) {
    return { kind: "command", command: "budget", args: "" };
  }

  // 12. Health, Service & Diagnostics
  if (
    /\b(periksa\s+semua\s+(?:service|layanan)|cek\s+kesehatan|status\s+seluruh\s+sistem|kenapa\s+(?:paperclip|gateway|office|hermes)\s+(?:offline|error|mati))\b/i.test(
      lower
    )
  ) {
    return { kind: "command", command: "kesehatan", args: /kenapa|offline|error/i.test(lower) ? "diagnosa" : "" };
  }

  // 13. Security & VulnClaw
  if (/^(?:tolong\s+)?(?:tampilkan\s+temuan\s+(?:keamanan|vulnclaw)|cek\s+vulnclaw|laporan\s+keamanan\s+defensif)\b/i.test(lower)) {
    return { kind: "command", command: "keamanan", args: "" };
  }

  // 14. Create Task for specific agent
  const taskForMatch = text.match(
    /^(?:tolong\s+)?buat(?:kan)?\s+task\s+(?:untuk|ke|kepada)\s+([A-Za-z0-9_ @&.-]{2,28}?)(?:\s*[:|-]\s*|\s+untuk\s+|\s+)(.+)$/is
  );
  if (taskForMatch) {
    const ag = resolveCorporateAgentEntry(taskForMatch[1].trim());
    if (ag && taskForMatch[2]?.trim()) {
      return { kind: "command", command: "buat_task", args: `${ag.slug} | ${taskForMatch[2].trim()}` };
    }
  }

  // 15. Named Agent Instruction
  const leadAgentMatch = text.match(
    /^(?:tolong\s+)?(?:(?:ke|kepada|minta|suruh|tugaskan)\s+)?([A-Za-z0-9_ &/-]{2,32}?)(?:\s*[,:]\s+|\s+tolong\s+)(.+)$/is
  );
  if (leadAgentMatch) {
    const ag = resolveCorporateAgentEntry(leadAgentMatch[1].trim());
    if (ag && leadAgentMatch[2]?.trim()) {
      return { kind: "ask_agent", agentEntry: ag, message: leadAgentMatch[2].trim() };
    }
  }

  // 16. Notify when build/job finishes
  if (/\b(beritahu\s+saya|kabari\s+saya|kirim\s+notifikasi)\b.*\b(build|test|pekerjaan|job)\s+selesai\b/i.test(lower)) {
    return { kind: "command", command: "dev", args: "build --notify" };
  }

  // 17. Direct-Agent Mode conversation routing
  if (tgState?.direct_agent_mode && (tgState?.selected_agent_id || tgState?.selected_agent_slug)) {
    const resolvedEntry =
      (typeof resolveCorporateAgentEntry === "function" &&
        (resolveCorporateAgentEntry(tgState.selected_agent_id) ||
          resolveCorporateAgentEntry(tgState.selected_agent_slug))) || {
        id: tgState.selected_agent_id || "role:ceo_agent",
        slug: tgState.selected_agent_slug || "ceo_agent",
        name: tgState.selected_agent_name || "CEO Agent",
        emoji: "🤖",
        department: "Corporate",
      };
    return { kind: "direct_selected_agent", agentEntry: resolvedEntry, message: text };
  }

  return { kind: "passthrough" };
}

module.exports = {
  NOTIFICATION_SEVERITIES,
  executeWithResilience,
  withSingletonLock,
  isMaintenanceLockActive,
  recordDeadLetter,
  listDeadLetters,
  getCircuitBreakerSnapshot,
  emitActivityNotification,
  loadNotificationsLedger,
  loadAsyncJobs,
  enqueueAsyncJob,
  cancelAsyncJob,
  routeIndonesianNaturalIntent,
};
