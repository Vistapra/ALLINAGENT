"use strict";

/**
 * PHASE 03 — Telegram Owner Authentication (Fail-Closed), Private-DM Scope Enforcement,
 * Callback Replay & Tampering Protection, and Target-Bound Expiring One-Time Approvals.
 *
 * Cross-platform portable (`contracts/paths.js`), zero hardcoded paths or personal Owner IDs.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { OFFICE_DATA_DIR, resolveAuthorizedOwnerId } = require("../contracts/paths");
const { appendAuditEntry } = require("../authorization/auth");
const { sanitizeText, sanitizePayload } = require("../contracts/redaction");

const SECURITY_LEDGER_FILE = path.resolve(path.join(OFFICE_DATA_DIR, "telegram-security-ledger.json"));
const DEFAULT_APPROVAL_TTL_MS = 15 * 60 * 1000; // 15 minutes
const CALLBACK_REPLAY_TTL_MS = 30 * 60 * 1000; // 30 minutes

function loadSecurityLedger() {
  try {
    if (fs.existsSync(SECURITY_LEDGER_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(SECURITY_LEDGER_FILE, "utf8"));
      if (parsed && typeof parsed === "object") {
        return {
          secret_salt: parsed.secret_salt || crypto.randomBytes(24).toString("hex"),
          consumed_callbacks: parsed.consumed_callbacks || {},
          bound_approvals: parsed.bound_approvals || {},
        };
      }
    }
  } catch {}
  const fresh = {
    secret_salt: crypto.randomBytes(24).toString("hex"),
    consumed_callbacks: {},
    bound_approvals: {},
  };
  saveSecurityLedger(fresh);
  return fresh;
}

function saveSecurityLedger(ledger) {
  const now = Date.now();
  const cbEntries = Object.entries(ledger.consumed_callbacks || {}).filter(
    ([, ts]) => now - Number(ts || 0) < CALLBACK_REPLAY_TTL_MS
  );
  ledger.consumed_callbacks = Object.fromEntries(cbEntries.slice(-600));

  const appEntries = Object.entries(ledger.bound_approvals || {}).slice(-200);
  ledger.bound_approvals = Object.fromEntries(appEntries);

  fs.mkdirSync(path.dirname(SECURITY_LEDGER_FILE), { recursive: true, mode: 0o700 });
  fs.writeFileSync(SECURITY_LEDGER_FILE, JSON.stringify(ledger, null, 2) + "\n", {
    encoding: "utf8",
    mode: 0o600,
  });
}

function computeArgsDigest(action, target, argsObj) {
  const raw = JSON.stringify({
    action: String(action || ""),
    target: String(target || ""),
    args: argsObj ?? "",
  });
  return crypto.createHash("sha256").update(raw, "utf8").digest("hex").slice(0, 24);
}

function signCallbackToken(payloadStr) {
  const ledger = loadSecurityLedger();
  return crypto
    .createHmac("sha256", ledger.secret_salt)
    .update(String(payloadStr), "utf8")
    .digest("hex")
    .slice(0, 10);
}

/**
 * Validate Owner numeric ID (fail-closed when unset or placeholder owner ID),
 * DM-only chat context, chat_id match, callback anti-replay, and session ownership.
 */
function verifyTelegramRequestSecurity(envelope = {}) {
  const configuredOwnerId = resolveAuthorizedOwnerId(process.env);
  const callerId = String(envelope.caller_id || "").trim();
  const chatId = envelope.chat_id !== undefined && envelope.chat_id !== null ? String(envelope.chat_id).trim() : "";
  const chatType = String(envelope.chat_type || "private").trim().toLowerCase();
  const callbackSenderId =
    envelope.callback_sender_id !== undefined && envelope.callback_sender_id !== null
      ? String(envelope.callback_sender_id).trim()
      : "";
  const sessionOwnerId =
    envelope.session_owner_id !== undefined && envelope.session_owner_id !== null
      ? String(envelope.session_owner_id).trim()
      : configuredOwnerId;
  const actionLabel = String(envelope.command || "unknown").slice(0, 80);

  // 0. Fail-closed check: reject all Telegram control requests when OWNER_TELEGRAM_ID is unset or placeholder
  if (!configuredOwnerId) {
    appendAuditEntry({
      ip: "127.0.0.1",
      callerId: callerId || "anonymous",
      actorRole: "unauthorized",
      action: `telegram:${actionLabel}`,
      allowed: false,
      reason: "owner_id_not_configured_fail_closed",
    });
    return {
      ok: false,
      status: 403,
      code: "OWNER_ID_NOT_CONFIGURED",
      error: "Akses ditolak: OWNER_TELEGRAM_ID / AUTHORIZED_OWNER_ID belum dikonfigurasi (fail-closed).",
    };
  }

  // 1. Numeric Owner ID check
  if (!callerId || callerId !== configuredOwnerId) {
    appendAuditEntry({
      ip: "127.0.0.1",
      callerId: callerId || "anonymous",
      actorRole: "unauthorized",
      action: `telegram:${actionLabel}`,
      allowed: false,
      reason: "unauthorized_user_id",
    });
    return {
      ok: false,
      status: 403,
      code: "UNAUTHORIZED_USER",
      error: `Akses ditolak: User ID '${sanitizeText(callerId || "unknown")}' bukan Owner yang terotorisasi.`,
    };
  }

  // 2. Callback sender verification (if callback query)
  if (callbackSenderId && callbackSenderId !== configuredOwnerId) {
    appendAuditEntry({
      ip: "127.0.0.1",
      callerId: callbackSenderId,
      actorRole: "unauthorized",
      action: `telegram_callback:${actionLabel}`,
      allowed: false,
      reason: "unauthorized_callback_sender",
    });
    return {
      ok: false,
      status: 403,
      code: "UNAUTHORIZED_CALLBACK_SENDER",
      error: "Akses ditolak: Penekan tombol callback bukan Owner resmi.",
    };
  }

  // 3. Reject group / supergroup / channel contexts strictly
  if (chatType && !["private", "dm", "cli_internal"].includes(chatType)) {
    appendAuditEntry({
      ip: "127.0.0.1",
      callerId,
      chatType,
      chatId,
      action: `telegram:${actionLabel}`,
      allowed: false,
      reason: "non_private_chat_rejected",
    });
    return {
      ok: false,
      status: 403,
      code: "GROUP_OR_CHANNEL_FORBIDDEN",
      error: `Akses ditolak: Kontrol perusahaan AI hanya diizinkan melalui pesan pribadi (DM Owner), bukan '${sanitizeText(chatType)}'.`,
    };
  }

  // 4. Validate chat_id matches Owner DM when provided
  if (chatId && chatId !== configuredOwnerId) {
    appendAuditEntry({
      ip: "127.0.0.1",
      callerId,
      chatId,
      action: `telegram:${actionLabel}`,
      allowed: false,
      reason: "chat_id_mismatch",
    });
    return {
      ok: false,
      status: 403,
      code: "CHAT_ID_MISMATCH",
      error: "Akses ditolak: Chat ID tidak sesuai dengan DM Owner resmi.",
    };
  }

  // 5. Validate session ownership
  if (sessionOwnerId !== configuredOwnerId) {
    appendAuditEntry({
      ip: "127.0.0.1",
      callerId,
      sessionOwnerId,
      action: `telegram:${actionLabel}`,
      allowed: false,
      reason: "session_ownership_mismatch",
    });
    return {
      ok: false,
      status: 403,
      code: "SESSION_OWNERSHIP_MISMATCH",
      error: "Akses ditolak: Kepemilikan sesi tidak valid.",
    };
  }

  // 6. Callback Replay & Payload Tampering Protection
  const callbackQueryId = String(envelope.callback_query_id || "").trim();
  if (callbackQueryId) {
    const ledger = loadSecurityLedger();
    if (ledger.consumed_callbacks[callbackQueryId]) {
      appendAuditEntry({
        ip: "127.0.0.1",
        callerId,
        callbackQueryId,
        action: `telegram_callback:${actionLabel}`,
        allowed: false,
        reason: "replayed_callback_query_id",
      });
      return {
        ok: false,
        status: 409,
        code: "CALLBACK_REPLAY_DETECTED",
        error: "Tombol callback ini sudah pernah diproses (replay dicegah).",
      };
    }
    ledger.consumed_callbacks[callbackQueryId] = Date.now();
    saveSecurityLedger(ledger);
  }

  // 7. Signed callback token verification if `|sig=` is present
  const rawCmd = String(envelope.command || "");
  if (rawCmd.startsWith("uac:") && rawCmd.includes("|sig=")) {
    const [baseData, sigPart] = rawCmd.split("|sig=", 2);
    const expectedSig = signCallbackToken(baseData);
    if (sigPart !== expectedSig) {
      appendAuditEntry({
        ip: "127.0.0.1",
        callerId,
        action: `telegram_callback:${actionLabel}`,
        allowed: false,
        reason: "modified_callback_payload_signature",
      });
      return {
        ok: false,
        status: 403,
        code: "MODIFIED_CALLBACK_PAYLOAD",
        error: "Payload callback tidak valid atau telah dimodifikasi.",
      };
    }
  }

  appendAuditEntry({
    ip: "127.0.0.1",
    callerId,
    actorRole: "owner",
    action: `telegram:${actionLabel}`,
    allowed: true,
    reason: "owner_dm_verified",
  });

  return { ok: true, owner_id: configuredOwnerId };
}

/**
 * Create a Target-Bound, Expiring, One-Time Approval Request (`PHASE 03` & `PHASE 15`).
 */
function createBoundApprovalRequest({
  ownerId = undefined,
  action,
  target,
  args = "",
  riskCategory = "HIGH",
  originAgent = "System Governance",
  projectOrTask = null,
  paperclipApprovalId = null,
  ttlMs = DEFAULT_APPROVAL_TTL_MS,
}) {
  const effectiveOwner = String(ownerId !== undefined ? ownerId : resolveAuthorizedOwnerId(process.env)).trim();
  const ledger = loadSecurityLedger();
  const requestId = `req_${crypto.randomBytes(6).toString("hex")}`;
  const nowMs = Date.now();
  const expiresAtMs = nowMs + Math.max(1_000, Number(ttlMs) || DEFAULT_APPROVAL_TTL_MS);
  const argsDigest = computeArgsDigest(action, target, args);

  const record = {
    request_id: requestId,
    paperclip_approval_id: paperclipApprovalId || null,
    owner_id: effectiveOwner,
    action: String(action || "sensitive_action"),
    target: String(target || "platform"),
    args_preview: sanitizeText(typeof args === "string" ? args : JSON.stringify(args)).slice(0, 200),
    args_digest: argsDigest,
    risk_category: String(riskCategory || "HIGH"),
    origin_agent: String(originAgent || "System"),
    project_or_task: projectOrTask ? String(projectOrTask) : null,
    status: "PENDING",
    created_at: new Date(nowMs).toISOString(),
    expires_at: new Date(expiresAtMs).toISOString(),
    expires_at_ms: expiresAtMs,
    resolved_at: null,
    resolved_by: null,
    decision: null,
    note: null,
  };

  ledger.bound_approvals[requestId] = record;
  saveSecurityLedger(ledger);
  appendAuditEntry({
    ip: "127.0.0.1",
    callerId: effectiveOwner,
    action: `approval.created:${record.action}`,
    requestId,
    target: record.target,
    argsDigest,
    expiresAt: record.expires_at,
    allowed: true,
  });
  return sanitizePayload(record);
}

/**
 * Consume & verify a bound one-time approval request (`approve` or `reject`).
 * Strictly rejects: unset owner, non-owner, unknown ID, already-resolved (replay/duplicate), expired, or tampered args!
 */
function consumeBoundApprovalRequest({
  requestId,
  callerId,
  decision,
  expectedAction = null,
  expectedTarget = null,
  expectedArgs = undefined,
  note = "",
}) {
  const configuredOwnerId = resolveAuthorizedOwnerId(process.env);
  if (!configuredOwnerId || String(callerId || "").trim() !== configuredOwnerId) {
    appendAuditEntry({
      ip: "127.0.0.1",
      callerId: callerId || "anonymous",
      action: `approval.consume:${requestId}`,
      allowed: false,
      reason: "cross_user_approval_rejected",
    });
    return {
      ok: false,
      status: 403,
      code: "CROSS_USER_APPROVAL_FORBIDDEN",
      error: "Hanya Owner resmi yang dapat menyetujui atau menolak permintaan approval.",
    };
  }

  const ledger = loadSecurityLedger();
  const rec = ledger.bound_approvals[String(requestId || "").trim()];
  if (!rec) {
    return {
      ok: false,
      status: 404,
      code: "APPROVAL_NOT_FOUND",
      error: `Request approval '${sanitizeText(requestId)}' tidak ditemukan atau tidak valid.`,
    };
  }

  if (rec.owner_id !== configuredOwnerId) {
    return {
      ok: false,
      status: 403,
      code: "APPROVAL_OWNER_MISMATCH",
      error: "Request approval tidak terikat pada Owner ini.",
    };
  }

  if (rec.status !== "PENDING") {
    appendAuditEntry({
      ip: "127.0.0.1",
      callerId,
      requestId: rec.request_id,
      action: `approval.replay:${rec.action}`,
      allowed: false,
      reason: `already_${rec.status.toLowerCase()}`,
    });
    return {
      ok: false,
      status: 409,
      code: "DUPLICATE_OR_STALE_APPROVAL",
      error: `Request approval '${rec.request_id}' sudah berstatus '${rec.status}' dan tidak dapat digunakan ulang.`,
    };
  }

  if (Date.now() > Number(rec.expires_at_ms || 0)) {
    rec.status = "EXPIRED";
    saveSecurityLedger(ledger);
    appendAuditEntry({
      ip: "127.0.0.1",
      callerId,
      requestId: rec.request_id,
      action: `approval.expired:${rec.action}`,
      allowed: false,
      reason: "approval_expired",
    });
    return {
      ok: false,
      status: 410,
      code: "APPROVAL_EXPIRED",
      error: `Request approval '${rec.request_id}' telah kedaluwarsa pada ${rec.expires_at}.`,
    };
  }

  if (expectedAction && rec.action !== expectedAction) {
    return {
      ok: false,
      status: 403,
      code: "APPROVAL_ACTION_MISMATCH",
      error: `Approval ini terikat pada aksi '${rec.action}', tidak boleh dipakai untuk aksi '${expectedAction}'.`,
    };
  }

  if (expectedTarget && rec.target !== expectedTarget) {
    return {
      ok: false,
      status: 403,
      code: "APPROVAL_TARGET_MISMATCH",
      error: `Approval ini terikat pada target '${rec.target}', bukan '${expectedTarget}'.`,
    };
  }

  if (expectedArgs !== undefined) {
    const checkDigest = computeArgsDigest(rec.action, rec.target, expectedArgs);
    if (checkDigest !== rec.args_digest) {
      return {
        ok: false,
        status: 403,
        code: "APPROVAL_ARGS_TAMPERED",
        error: "Argumen eksekusi berubah dari yang disetujui (args_digest mismatch).",
      };
    }
  }

  const normDecision = String(decision || "").toLowerCase();
  const isApproved = normDecision === "approve" || normDecision === "allow-once" || normDecision === "allow-always";
  rec.status = isApproved ? "APPROVED" : "REJECTED";
  rec.decision = isApproved ? "approved" : "rejected";
  rec.resolved_at = new Date().toISOString();
  rec.resolved_by = callerId;
  rec.note = sanitizeText(String(note || "")).slice(0, 300);
  saveSecurityLedger(ledger);

  appendAuditEntry({
    ip: "127.0.0.1",
    callerId,
    requestId: rec.request_id,
    action: `approval.${rec.decision}:${rec.action}`,
    target: rec.target,
    argsDigest: rec.args_digest,
    allowed: true,
  });

  return { ok: true, record: sanitizePayload(rec) };
}

function listBoundApprovals({ includeHistory = true } = {}) {
  const ledger = loadSecurityLedger();
  const now = Date.now();
  let mutated = false;
  const all = Object.values(ledger.bound_approvals || {}).map((r) => {
    if (r.status === "PENDING" && now > Number(r.expires_at_ms || 0)) {
      r.status = "EXPIRED";
      mutated = true;
    }
    return sanitizePayload(r);
  });
  if (mutated) saveSecurityLedger(ledger);
  const sorted = all.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  return includeHistory ? sorted : sorted.filter((x) => x.status === "PENDING");
}

function buildSignedCallbackData(baseCallbackData) {
  const clean = String(baseCallbackData || "uac:menu").slice(0, 48);
  const sig = signCallbackToken(clean);
  return `${clean}|sig=${sig}`;
}

module.exports = {
  SECURITY_LEDGER_FILE,
  verifyTelegramRequestSecurity,
  createBoundApprovalRequest,
  consumeBoundApprovalRequest,
  listBoundApprovals,
  computeArgsDigest,
  signCallbackToken,
  buildSignedCallbackData,
};
