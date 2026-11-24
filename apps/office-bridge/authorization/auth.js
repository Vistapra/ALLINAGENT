"use strict";

/**
 * Office Bridge Authentication, Authorization, Container/Docker RFC1918 Network Guard,
 * WebSocket Origin Validation, Rate Limiting, and Audit Trail.
 *
 * Strictly zero sharing of TELEGRAM_BOT_TOKEN or CUSTOM_API_KEY, zero hardcoded usernames,
 * and fail-closed owner mutation authorization when AUTHORIZED_OWNER_ID is unset.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const {
  SECRETS_DIR,
  LOGS_DIR,
  HERMES3D_BASE_URL,
  AUTHORIZED_OWNER_ID,
  resolveSecretsDir,
  resolveInternalServiceToken,
  resolveAuthorizedOwnerId,
} = require("../contracts/paths");

function resolveSecretFilePath(env = process.env) {
  return path.resolve(path.join(resolveSecretsDir(env), "office-bridge-auth.json"));
}

const SECRET_FILE_PATH = path.resolve(path.join(SECRETS_DIR, "office-bridge-auth.json"));
const AUDIT_LOG_PATH = path.resolve(path.join(LOGS_DIR, "office-bridge-audit.jsonl"));

/**
 * Build internal service authentication headers for outbound calls to
 * `HERMES_REMOTE_EXEC_URL` (`http://hermes:8650`) and `VULNCLAW_WORKER_URL` (`http://vulnclaw:8660`).
 * Honors `ALLINAGENT_INTERNAL_TOKEN` falling back to `HERMES_EXEC_SHARED_SECRET` / `VULNCLAW_SCAN_TOKEN`.
 */
function buildInternalServiceAuthHeaders(target = "internal", env = process.env) {
  const token = resolveInternalServiceToken(target, env);
  if (!token) return {};
  if (target === "vulnclaw") {
    return {
      Authorization: `Bearer ${token}`,
      "X-Internal-Scan-Token": token,
      "X-Allinagent-Internal-Token": token,
      "X-Vulnclaw-Scan-Token": token,
      "X-Vulnclaw-Token": token,
    };
  }
  return {
    Authorization: `Bearer ${token}`,
    "X-Internal-Exec-Token": token,
    "X-Allinagent-Internal-Token": token,
    "X-Hermes-Exec-Secret": token,
  };
}

function normalizeOrigin(originStr) {
  return String(originStr || "")
    .trim()
    .toLowerCase()
    .replace(/\/$/, "");
}

function buildAllowedOriginsSet(extraOriginsRaw = process.env.OFFICE_BRIDGE_ALLOWED_ORIGINS, options = {}) {
  const env = (options && options.env) || process.env;
  const dockerAllowed =
    typeof options?.allowDockerNetwork === "boolean"
      ? options.allowDockerNetwork
      : String(env.OFFICE_BRIDGE_ALLOW_DOCKER_NETWORK || "").trim() === "1";

  const set = new Set([
    "http://127.0.0.1:3200",
    "http://localhost:3200",
    "http://127.0.0.1:3210",
    "http://localhost:3210",
    normalizeOrigin(env.HERMES3D_BASE_URL || HERMES3D_BASE_URL),
  ]);

  if (dockerAllowed) {
    set.add("http://office-bridge:3210");
    set.add("http://allinagent-office-bridge:3210");
    set.add("http://office:3200");
    set.add("http://allinagent-office:3200");
    set.add("http://127.0.0.1:8200");
    set.add("http://localhost:8200");
    set.add("http://127.0.0.1:8202");
    set.add("http://localhost:8202");
    const officePort = String(env.OFFICE_PORT || "").trim();
    if (officePort && /^\d+$/.test(officePort)) {
      set.add(`http://127.0.0.1:${officePort}`);
      set.add(`http://localhost:${officePort}`);
    }
  }

  if (extraOriginsRaw && String(extraOriginsRaw).trim()) {
    for (const part of String(extraOriginsRaw).split(/[,;\s]+/)) {
      const norm = normalizeOrigin(part);
      if (norm) set.add(norm);
    }
  }
  return set;
}

const DEFAULT_ALLOWED_ORIGINS = buildAllowedOriginsSet();

function timingSafeStringEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length === 0 || bufA.length !== bufB.length) {
    const dummy = Buffer.alloc(32, 0);
    crypto.timingSafeEqual(dummy, dummy);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function isContainerEnvironment(env = process.env) {
  if (String(env.OFFICE_BRIDGE_ALLOW_CONTAINER_BIND || "").trim() === "1") {
    return true;
  }
  try {
    if (fs.existsSync("/.dockerenv") || fs.existsSync("/run/.containerenv")) {
      return true;
    }
  } catch {}
  return false;
}

function normalizeIp(rawIp) {
  const ip = String(rawIp || "").trim();
  if (ip.toLowerCase().startsWith("::ffff:")) {
    return ip.slice(7);
  }
  return ip;
}

function isLoopbackIp(rawIp) {
  const ip = normalizeIp(rawIp);
  return ip === "127.0.0.1" || ip === "::1" || ip === "localhost";
}

/**
 * RFC1918 private IPv4 ranges for internal Docker bridge/overlay networks:
 *   - 10.0.0.0/8
 *   - 172.16.0.0/12
 *   - 192.168.0.0/16
 */
function isRfc1918PrivateIp(rawIp) {
  const ip = normalizeIp(rawIp);
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = octets;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

function lockSecretFilePermissions(filePath) {
  const dirPath = path.dirname(filePath);
  if (process.platform !== "win32") {
    try {
      fs.chmodSync(dirPath, 0o700);
    } catch {}
    try {
      fs.chmodSync(filePath, 0o600);
    } catch {}
    return;
  }

  try {
    let rawUser = String(process.env.USERNAME || "").trim();
    if (!rawUser) {
      try {
        rawUser = String(os.userInfo().username || "").trim();
      } catch {}
    }
    const domain = String(process.env.USERDOMAIN || process.env.COMPUTERNAME || "").trim();
    const principal = rawUser ? (domain ? `${domain}\\${rawUser}` : rawUser) : "";
    const icaclsArgs = [
      filePath,
      "/inheritance:r",
      "/grant:r",
      ...(principal ? [`${principal}:(F)`] : []),
      "NT AUTHORITY\\SYSTEM:(F)",
      "BUILTIN\\Administrators:(F)",
    ];
    execFileSync("icacls.exe", icaclsArgs, { stdio: "ignore", timeout: 8000, windowsHide: true });
  } catch {
    // Non-fatal best-effort ACL hardening on Windows
  }
}

/**
 * Load or generate isolated internal credentials for Office Bridge <-> Hermes3D Studio.
 * Honors `process.env.OFFICE_BRIDGE_TOKEN` and `process.env.STUDIO_ACCESS_TOKEN` directly
 * in addition to `office-bridge-auth.json`. Never reads or stores TELEGRAM_BOT_TOKEN or CUSTOM_API_KEY.
 */
function ensureOfficeBridgeSecrets(secretFilePath = undefined, env = process.env) {
  const effectivePath = secretFilePath || resolveSecretFilePath(env);
  const envBridgeToken = String(env.OFFICE_BRIDGE_TOKEN || "").trim();
  const envStudioToken = String(env.STUDIO_ACCESS_TOKEN || "").trim();

  let fileSecrets = null;
  if (fs.existsSync(effectivePath)) {
    try {
      const raw = JSON.parse(fs.readFileSync(effectivePath, "utf8"));
      if (
        raw &&
        typeof raw.bridgeToken === "string" &&
        raw.bridgeToken.length >= 16 &&
        typeof raw.studioAccessToken === "string"
      ) {
        lockSecretFilePermissions(effectivePath);
        fileSecrets = raw;
      }
    } catch {}
  }

  if (fileSecrets || (envBridgeToken && envStudioToken)) {
    return {
      createdAt: fileSecrets?.createdAt || new Date().toISOString(),
      bridgeToken: envBridgeToken || fileSecrets.bridgeToken,
      studioAccessToken: envStudioToken || fileSecrets.studioAccessToken,
      fileBridgeToken: fileSecrets?.bridgeToken || null,
      fileStudioAccessToken: fileSecrets?.studioAccessToken || null,
      allowedOwnerId: resolveAuthorizedOwnerId(env) || fileSecrets?.allowedOwnerId || null,
    };
  }

  const generated = {
    createdAt: new Date().toISOString(),
    bridgeToken: envBridgeToken || `${"ob_" + "tok_"}${crypto.randomBytes(32).toString("hex")}`,
    studioAccessToken: envStudioToken || `${"st_" + "tok_"}${crypto.randomBytes(24).toString("hex")}`,
    allowedOwnerId: resolveAuthorizedOwnerId(env) || null,
  };

  try {
    fs.mkdirSync(path.dirname(effectivePath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(effectivePath, JSON.stringify(generated, null, 2) + "\n", {
      encoding: "utf8",
      mode: 0o600,
    });
    lockSecretFilePermissions(effectivePath);
  } catch {
    // Allow read-only container rootfs operation when tokens are injected via env
  }
  return generated;
}

function resolveStudioAccessToken(secrets = null, env = process.env) {
  const envStudio = String(env.STUDIO_ACCESS_TOKEN || "").trim();
  if (envStudio) return envStudio;
  if (secrets && typeof secrets.studioAccessToken === "string" && secrets.studioAccessToken.trim()) {
    return secrets.studioAccessToken.trim();
  }
  const effectivePath = resolveSecretFilePath(env);
  if (fs.existsSync(effectivePath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(effectivePath, "utf8"));
      if (typeof parsed?.studioAccessToken === "string") {
        return parsed.studioAccessToken.trim();
      }
    } catch {}
  }
  return "";
}

function appendAuditEntry(entry) {
  try {
    fs.mkdirSync(path.dirname(AUDIT_LOG_PATH), { recursive: true, mode: 0o700 });
    const record = {
      timestamp: new Date().toISOString(),
      ...entry,
    };
    fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(record) + "\n", {
      encoding: "utf8",
      mode: 0o600,
    });
  } catch {
    // non-fatal
  }
}

function extractBearerOrHeaderToken(req, urlObj) {
  const authHeader = req.headers?.authorization;
  if (typeof authHeader === "string" && authHeader.toLowerCase().startsWith("bearer ")) {
    const t = authHeader.slice(7).trim();
    if (t) return t;
  }
  const customHeader = req.headers?.["x-office-bridge-token"];
  if (typeof customHeader === "string" && customHeader.trim()) {
    return customHeader.trim();
  }
  if (urlObj && urlObj.searchParams) {
    const qt = urlObj.searchParams.get("token");
    if (qt && qt.trim()) return qt.trim();
  }
  return "";
}

class OfficeSecurityGuard {
  constructor(options = {}) {
    this.secrets = options.secrets || ensureOfficeBridgeSecrets(options.secretFilePath);
    this.ownerId = options.ownerId;
    this.allowDockerNetwork = options.allowDockerNetwork;
    this.allowedOriginsEnv = options.allowedOriginsEnv;
    this.allowedOrigins =
      options.allowedOrigins ||
      buildAllowedOriginsSet(
        options.allowedOriginsEnv !== undefined
          ? options.allowedOriginsEnv
          : process.env.OFFICE_BRIDGE_ALLOWED_ORIGINS,
        { allowDockerNetwork: this._isDockerNetworkAllowed() }
      );
    this.maxFailuresPerMinute = options.maxFailuresPerMinute || 20;
    this.maxRequestsPerMinute = options.maxRequestsPerMinute || 600;
    this.failedAuthByIp = new Map();
    this.requestsByIp = new Map();
  }

  _clientIp(req) {
    return String(req.socket?.remoteAddress || "127.0.0.1");
  }

  _isDockerNetworkAllowed() {
    if (typeof this.allowDockerNetwork === "boolean") return this.allowDockerNetwork;
    return String(process.env.OFFICE_BRIDGE_ALLOW_DOCKER_NETWORK || "").trim() === "1";
  }

  _effectiveOwnerId() {
    if (this.ownerId !== undefined && this.ownerId !== null) {
      return resolveAuthorizedOwnerId({ AUTHORIZED_OWNER_ID: String(this.ownerId) });
    }
    return resolveAuthorizedOwnerId(process.env);
  }

  _matchesBridgeToken(tokenCandidate, env = process.env) {
    const clean = String(tokenCandidate || "").trim();
    if (!clean) return false;
    if (this.secrets?.bridgeToken && timingSafeStringEqual(clean, this.secrets.bridgeToken)) {
      return true;
    }
    if (this.secrets?.fileBridgeToken && timingSafeStringEqual(clean, this.secrets.fileBridgeToken)) {
      return true;
    }
    const envTok = String(env.OFFICE_BRIDGE_TOKEN || "").trim();
    if (envTok && timingSafeStringEqual(clean, envTok)) {
      return true;
    }
    return false;
  }

  _checkRateLimit(map, ip, maxCount, windowMs = 60_000) {
    const now = Date.now();
    const cur = map.get(ip);
    if (!cur || now - cur.start > windowMs) {
      map.set(ip, { count: 1, start: now });
      return true;
    }
    cur.count += 1;
    return cur.count <= maxCount;
  }

  validateOrigin(req, requireOrigin = false) {
    const origin = req.headers?.origin;
    if (!origin) {
      return !requireOrigin;
    }
    const norm = normalizeOrigin(origin);
    if (this.allowedOrigins.has(norm)) return true;
    // Dynamically honor runtime changes to OFFICE_BRIDGE_ALLOWED_ORIGINS and Docker network flag
    const dynamicSet = buildAllowedOriginsSet(
      this.allowedOriginsEnv !== undefined
        ? this.allowedOriginsEnv
        : process.env.OFFICE_BRIDGE_ALLOWED_ORIGINS,
      { allowDockerNetwork: this._isDockerNetworkAllowed() }
    );
    return dynamicSet.has(norm);
  }

  authorizeHttp(req, urlObj, opts = {}) {
    const ip = this._clientIp(req);
    const loopback = isLoopbackIp(ip);
    const dockerRfc1918 = this._isDockerNetworkAllowed() && isRfc1918PrivateIp(ip);

    if (!loopback && !dockerRfc1918) {
      appendAuditEntry({
        ip,
        action: opts.actionName || urlObj.pathname,
        allowed: false,
        reason: "non_loopback_or_disallowed_network_http",
      });
      return { ok: false, status: 403, error: "Client IP is outside allowed loopback/Docker network." };
    }

    if (!this._checkRateLimit(this.requestsByIp, ip, this.maxRequestsPerMinute)) {
      appendAuditEntry({ ip, action: opts.actionName || urlObj.pathname, allowed: false, reason: "rate_limited" });
      return { ok: false, status: 429, error: "Rate limit exceeded." };
    }

    const failEntry = this.failedAuthByIp.get(ip);
    if (failEntry && Date.now() - failEntry.start <= 60_000 && failEntry.count >= this.maxFailuresPerMinute) {
      return { ok: false, status: 429, error: "Too many failed authentication attempts." };
    }

    if (!this.validateOrigin(req, false)) {
      appendAuditEntry({
        ip,
        origin: req.headers?.origin,
        action: opts.actionName || urlObj.pathname,
        allowed: false,
        reason: "forbidden_origin",
      });
      return { ok: false, status: 403, error: "Forbidden Origin header." };
    }

    const token = extractBearerOrHeaderToken(req, null);
    if (!this._matchesBridgeToken(token)) {
      this._checkRateLimit(this.failedAuthByIp, ip, this.maxFailuresPerMinute);
      appendAuditEntry({
        ip,
        action: opts.actionName || urlObj.pathname,
        allowed: false,
        reason: "invalid_or_missing_token",
      });
      return { ok: false, status: 401, error: "Authentication required (valid Office Bridge Bearer token missing)." };
    }

    const configuredOwnerId = this._effectiveOwnerId();
    const rawCallerHeader = req.headers?.["x-office-caller-id"] || req.headers?.["x-office-owner-id"];
    const callerId = String(rawCallerHeader !== undefined ? rawCallerHeader : configuredOwnerId).trim();
    const actorRole = String(req.headers?.["x-office-actor-role"] || "owner").trim().toLowerCase();

    if (opts.requireMutationOwner) {
      if (!configuredOwnerId) {
        appendAuditEntry({
          ip,
          callerId: callerId || "unset",
          actorRole,
          action: opts.actionName || urlObj.pathname,
          allowed: false,
          reason: "owner_id_unconfigured_fail_closed",
        });
        return {
          ok: false,
          status: 403,
          error: "Forbidden: OWNER_TELEGRAM_ID / AUTHORIZED_OWNER_ID is not configured (fail-closed).",
        };
      }
      if (
        callerId !== configuredOwnerId ||
        actorRole === "viewer" ||
        actorRole === "unauthorized" ||
        actorRole === "guest"
      ) {
        appendAuditEntry({
          ip,
          callerId,
          actorRole,
          action: opts.actionName || urlObj.pathname,
          allowed: false,
          reason: "unauthorized_caller_or_role",
        });
        return {
          ok: false,
          status: 403,
          error: `Forbidden: caller '${callerId}' (role '${actorRole}') is not authorized to mutate company state.`,
        };
      }
      appendAuditEntry({
        ip,
        callerId,
        actorRole,
        action: opts.actionName || urlObj.pathname,
        allowed: true,
        reason: "owner_mutation_authorized",
      });
    }

    return { ok: true, status: 200, callerId, actorRole };
  }

  authorizeWsUpgrade(req, urlObj, { requireUpgradeToken = true } = {}) {
    const ip = this._clientIp(req);
    const loopback = isLoopbackIp(ip);
    const dockerRfc1918 = this._isDockerNetworkAllowed() && isRfc1918PrivateIp(ip);

    if (!loopback && !dockerRfc1918) {
      appendAuditEntry({ ip, action: `ws:${urlObj.pathname}`, allowed: false, reason: "non_loopback_ws" });
      return { ok: false, status: 403, error: "Loopback or authorized Docker network connections only." };
    }

    const token = extractBearerOrHeaderToken(req, urlObj);
    const hasValidBearer = this._matchesBridgeToken(token);

    // Valid Office Bridge Bearer token on WS upgrade bypasses browser Origin mismatch
    if (!hasValidBearer && !this.validateOrigin(req, false)) {
      appendAuditEntry({
        ip,
        origin: req.headers?.origin,
        action: `ws:${urlObj.pathname}`,
        allowed: false,
        reason: "forbidden_ws_origin",
      });
      return { ok: false, status: 403, error: "Untrusted WebSocket Origin." };
    }

    if (requireUpgradeToken) {
      if (!hasValidBearer) {
        this._checkRateLimit(this.failedAuthByIp, ip, this.maxFailuresPerMinute);
        appendAuditEntry({
          ip,
          action: `ws:${urlObj.pathname}`,
          allowed: false,
          reason: "missing_or_invalid_ws_token",
        });
        return { ok: false, status: 401, error: "Unauthorized WebSocket upgrade." };
      }
    } else if (!loopback && dockerRfc1918) {
      // On Docker internal RFC1918 networks, `/ws` upgrades require either a valid Bearer token
      // OR an explicit Origin matching OFFICE_BRIDGE_ALLOWED_ORIGINS (plus connect-frame auth).
      const hasTrustedExplicitOrigin = Boolean(req.headers?.origin) && this.validateOrigin(req, true);
      if (!hasValidBearer && !hasTrustedExplicitOrigin) {
        this._checkRateLimit(this.failedAuthByIp, ip, this.maxFailuresPerMinute);
        appendAuditEntry({
          ip,
          action: `ws:${urlObj.pathname}`,
          allowed: false,
          reason: "docker_ws_missing_token_and_origin",
        });
        return {
          ok: false,
          status: 401,
          error: "Docker network WebSocket upgrade requires valid Bearer token or trusted Origin.",
        };
      }
    }

    return { ok: true, status: 101 };
  }

  validateWebSocketUpgrade(req, urlObj, opts = {}) {
    return this.authorizeWsUpgrade(req, urlObj, opts);
  }

  verifyConnectFrameToken(tokenCandidate) {
    return this._matchesBridgeToken(tokenCandidate);
  }
}

function validateWebSocketUpgrade(req, urlObj, options = {}) {
  const guard = options.guard instanceof OfficeSecurityGuard ? options.guard : new OfficeSecurityGuard(options);
  return guard.authorizeWsUpgrade(req, urlObj, options);
}

module.exports = {
  AUTHORIZED_OWNER_ID,
  SECRET_FILE_PATH,
  AUDIT_LOG_PATH,
  DEFAULT_ALLOWED_ORIGINS,
  timingSafeStringEqual,
  isContainerEnvironment,
  isLoopbackIp,
  isRfc1918PrivateIp,
  buildAllowedOriginsSet,
  validateWebSocketUpgrade,
  resolveSecretFilePath,
  resolveStudioAccessToken,
  buildInternalServiceAuthHeaders,
  lockSecretFilePermissions,
  ensureOfficeBridgeSecrets,
  appendAuditEntry,
  OfficeSecurityGuard,
};
