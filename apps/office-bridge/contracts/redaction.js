"use strict";

/**
 * Defensive Secret Redaction, Prompt-Injection Directive Neutralization,
 * and Cross-Platform Workspace Trust-Boundary Path Validation for ALLINAGENT Office Bridge.
 */

const fs = require("node:fs");
const path = require("node:path");
const {
  USER_HOME,
  SECRETS_DIR,
  OFFICE_DATA_DIR,
  DATA_DIR,
  HERMES_HOME_ROOT,
  WORKSPACES_DIR,
  REPORTS_DIR,
  DOCS_DIR,
  AUTHORIZED_WORKSPACES,
  resolveSecretsDir,
  resolveWorkspacesDir,
  resolveReportsDir,
  resolveAuthorizedWorkspaces,
} = require("./paths");

const SECRET_PATTERNS = [
  { re: /\bob_tok_[A-Za-z0-9_-]{12,}\b/g, replacement: "[REDACTED_BRIDGE_TOKEN]" },
  { re: /\bst_tok_[A-Za-z0-9_-]{12,}\b/g, replacement: "[REDACTED_STUDIO_TOKEN]" },
  { re: /\bsk-[A-Za-z0-9_-]{12,}\b/g, replacement: "[REDACTED_API_KEY]" },
  { re: /\bpcp_(?:board|agent|live|sec|tok)_[A-Za-z0-9_-]{8,}\b/gi, replacement: "[REDACTED_PAPERCLIP_KEY]" },
  { re: /\b\d{8,12}:[A-Za-z0-9_-]{30,}\b/g, replacement: "[REDACTED_TELEGRAM_TOKEN]" },
  { re: /(Authorization\s*:\s*Bearer\s+)[^\s"',;]+/gi, replacement: "$1[REDACTED_BEARER]" },
  {
    re: /((?:api[_-]?key|bot[_-]?token|access[_-]?token|office[_-]?bridge[_-]?token|bridge[_-]?token|studio[_-]?access[_-]?token|allinagent[_-]?internal[_-]?token|hermes[_-]?exec[_-]?shared[_-]?secret|vulnclaw[_-]?scan[_-]?token|secret|password)\s*[=:]\s*["']?)[^\s"',;&]+/gi,
    replacement: "$1[REDACTED_SECRET]",
  },
];

const DIRECTIVE_PATTERN =
  /(\[embedded_directive:[^\]]*\]|ignore\s+previous\s+instructions|system\s*override\s*:|grant\s+admin\s+privileges\s*:)/gi;

/**
 * Redact secrets and neutralize embedded prompt-injection directives in untrusted strings.
 * @param {unknown} input
 * @returns {string}
 */
function sanitizeText(input) {
  if (input === null || input === undefined) return "";
  let text = typeof input === "string" ? input : String(input);
  for (const { re, replacement } of SECRET_PATTERNS) {
    text = text.replace(re, replacement);
  }
  text = text.replace(DIRECTIVE_PATTERN, "[DATA_LITERAL_DIRECTIVE_IGNORED]");
  return text;
}

const SENSITIVE_KEY_RE =
  /^(?:token|api_?key|apikey|secret|password|authorization|cookie|telegram_bot_token|custom_api_key|better_auth_secret|paperclip_board_key|paperclip_api_key|paperclip_agent_jwt_secret|office_?bridge_?token|bridge_?token|studio_?access_?token|allinagent_?internal_?token|hermes_?exec_?shared_?secret|vulnclaw_?scan_?token)$/i;

/**
 * Recursively sanitize an arbitrary JSON-compatible value so no secret or directive leaks.
 * @param {unknown} value
 * @param {number} depth
 * @returns {unknown}
 */
function sanitizePayload(value, depth = 0) {
  if (depth > 12) return "[TRUNCATED_DEPTH]";
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return sanitizeText(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) {
    return value.slice(0, 500).map((entry) => sanitizePayload(entry, depth + 1));
  }
  if (typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (SENSITIVE_KEY_RE.test(k)) {
        out[k] = "[REDACTED_SECRET]";
      } else {
        out[k] = sanitizePayload(v, depth + 1);
      }
    }
    return out;
  }
  return sanitizeText(String(value));
}

const LINUX_FORBIDDEN_ROOTS = Object.freeze([
  "/etc",
  "/proc",
  "/sys",
  "/dev",
  "/root",
  "/boot",
  "/run",
  "/var/run",
  "/var/lib/docker",
  "/var/lib/allinagent/secrets",
]);

const WINDOWS_FORBIDDEN_ROOTS = Object.freeze(
  [
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
    "C:\\$Recycle.Bin",
    "C:\\System Volume Information",
    "D:\\$RECYCLE.BIN",
    "D:\\System Volume Information",
    process.env.LOCALAPPDATA ? path.win32.join(process.env.LOCALAPPDATA, "hermes") : null,
  ].filter(Boolean)
);

const HOME_SECRET_SEGMENTS_RE =
  /(?:^|[\\/])(?:\.ssh|\.gnupg|\.aws|\.git-credentials|\.docker)(?:[\\/]|$)/;

const FORBIDDEN_ROOTS = Object.freeze(
  [
    ...LINUX_FORBIDDEN_ROOTS,
    ...WINDOWS_FORBIDDEN_ROOTS,
    path.join(USER_HOME, ".ssh"),
    path.join(USER_HOME, ".gnupg"),
    path.join(USER_HOME, ".aws"),
    path.join(USER_HOME, ".git-credentials"),
    path.join(USER_HOME, ".docker"),
    path.join(USER_HOME, ".hermes"),
    path.resolve(SECRETS_DIR),
    path.resolve(OFFICE_DATA_DIR),
    path.resolve(HERMES_HOME_ROOT),
    path.resolve(path.join(DATA_DIR, "vulnclaw")),
  ].filter(Boolean)
);

function resolveAllowedEvidenceRoots(env = process.env, platform = process.platform, existsFn = fs.existsSync) {
  const pathMod = platform === "win32" ? path.win32 : path.posix;
  const candidates = [
    resolveWorkspacesDir(env, platform, existsFn),
    resolveReportsDir(env, platform, existsFn),
    pathMod.resolve(WORKSPACES_DIR),
    pathMod.resolve(REPORTS_DIR),
    pathMod.resolve(DOCS_DIR),
    ...AUTHORIZED_WORKSPACES.map((p) => pathMod.resolve(p)),
    ...resolveAuthorizedWorkspaces(env, platform, existsFn).map((p) => pathMod.resolve(p)),
  ];
  const seen = new Set();
  const out = [];
  for (const c of candidates) {
    if (!c) continue;
    if (platform !== "win32" && /^[A-Za-z]:\\/.test(c)) continue;
    const key = platform === "win32" ? c.toLowerCase() : c;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(c);
    }
  }
  return out;
}

const ALLOWED_EVIDENCE_ROOTS = Object.freeze(resolveAllowedEvidenceRoots(process.env));

function isUnderRoot(targetPath, rootPath, isWin32) {
  const pathMod = isWin32 ? path.win32 : path.posix;
  const sep = pathMod.sep;
  const normTarget = isWin32 ? targetPath.toLowerCase() : targetPath;
  const normRoot = isWin32 ? rootPath.toLowerCase() : rootPath;
  if (normTarget === normRoot) return true;
  const prefix = normRoot.endsWith(sep) ? normRoot : normRoot + sep;
  return normTarget.startsWith(prefix);
}

function readPinnedFoldersSafe() {
  const tfFile = path.join(OFFICE_DATA_DIR, "target-folders.json");
  if (!fs.existsSync(tfFile)) return [];
  try {
    const parsed = JSON.parse(fs.readFileSync(tfFile, "utf8").replace(/^\uFEFF/, ""));
    const list = [];
    if (Array.isArray(parsed?.pinned_paths)) {
      for (const p of parsed.pinned_paths) {
        if (typeof p === "string" && p.trim()) list.push(p.trim());
      }
    }
    if (typeof parsed?.active_folder === "string" && parsed.active_folder.trim()) {
      list.push(parsed.active_folder.trim());
    }
    return list;
  } catch {
    return [];
  }
}

/**
 * Check if a candidate path falls inside any Linux, Windows, User-Home, or Platform forbidden zone.
 * Preserves strict case sensitivity on POSIX (`platform !== "win32"`).
 */
function isPathForbidden(resolvedOrRawPath, platform = process.platform) {
  const isWin32 = platform === "win32";
  const pathMod = isWin32 ? path.win32 : path.posix;

  if (HOME_SECRET_SEGMENTS_RE.test(resolvedOrRawPath)) {
    return true;
  }

  // Always enforce POSIX system root exclusions when path starts with `/`
  const posixCandidate = String(resolvedOrRawPath).replace(/\\/g, "/");
  if (posixCandidate.startsWith("/")) {
    const cleanPosix = path.posix.normalize(posixCandidate);
    for (const lf of LINUX_FORBIDDEN_ROOTS) {
      if (cleanPosix === lf || cleanPosix.startsWith(`${lf}/`)) {
        return true;
      }
    }
  }

  const abs = pathMod.resolve(resolvedOrRawPath);
  const dynamicSecretsDir =
    platform === process.platform || process.env.ALLINAGENT_SECRETS_DIR || process.env.SECRETS_DIR
      ? resolveSecretsDir(process.env, platform)
      : null;
  for (const f of [...FORBIDDEN_ROOTS, dynamicSecretsDir]) {
    if (!f) continue;
    // Skip POSIX-only literal roots during win32 drive resolution so "/root" does not map to "D:\root" unless on POSIX
    if (isWin32 && f.startsWith("/") && !resolvedOrRawPath.startsWith("/")) {
      continue;
    }
    if (!isWin32 && /^[A-Za-z]:\\/.test(f)) {
      continue;
    }
    const fResolved = pathMod.resolve(f);
    if (isUnderRoot(abs, fResolved, isWin32)) {
      return true;
    }
  }
  return false;
}

/**
 * Verify a requested evidence/workspace path stays strictly outside forbidden OS/secret zones
 * and within authorized workspace/evidence roots (`workspaces/`, `reports/`, `docs/`,
 * `AUTHORIZED_WORKSPACES`, and validated `target-folders.json` entries).
 *
 * @param {string} candidatePath
 * @param {{
 *   platform?: string,
 *   allowedRoots?: string[],
 *   includeTargetFolders?: boolean,
 * }} [options]
 * @returns {{ ok: boolean, resolvedPath: string | null, reason?: string }}
 */
function validateAuthorizedEvidencePath(candidatePath, options = {}) {
  if (typeof candidatePath !== "string" || !candidatePath.trim()) {
    return { ok: false, resolvedPath: null, reason: "Path is empty." };
  }
  let raw = candidatePath.trim();
  if (raw.includes("\0")) {
    return { ok: false, resolvedPath: null, reason: "Null byte in path." };
  }

  // Expand leading `~/` or `~\` to USER_HOME so `~/.ssh` is always resolved and blocked
  if (raw === "~" || raw.startsWith("~/") || raw.startsWith("~\\")) {
    raw = path.join(USER_HOME, raw.slice(1));
  }

  const platform = options.platform || process.platform;
  const isWin32 = platform === "win32";
  const pathMod = isWin32 ? path.win32 : path.posix;

  // Immediate check on raw input for POSIX forbidden roots (e.g. `/etc/passwd` even when tested on win32)
  if (raw.startsWith("/")) {
    const normPosix = path.posix.normalize(raw);
    for (const lf of LINUX_FORBIDDEN_ROOTS) {
      if (normPosix === lf || normPosix.startsWith(`${lf}/`)) {
        return { ok: false, resolvedPath: null, reason: "Access to restricted trust zone is forbidden." };
      }
    }
  }
  if (HOME_SECRET_SEGMENTS_RE.test(raw)) {
    return { ok: false, resolvedPath: null, reason: "Access to restricted credential directory is forbidden." };
  }

  const abs = pathMod.resolve(raw);
  let real = abs;
  if (platform === process.platform) {
    try {
      if (fs.existsSync(abs)) {
        real = fs.realpathSync(abs);
      } else {
        // Walk up to nearest existing ancestor to catch symlinked parent directories
        let cur = path.dirname(abs);
        let suffix = path.basename(abs);
        while (cur && cur !== path.dirname(cur)) {
          if (fs.existsSync(cur)) {
            const realParent = fs.realpathSync(cur);
            real = path.join(realParent, suffix);
            break;
          }
          suffix = path.join(path.basename(cur), suffix);
          cur = path.dirname(cur);
        }
      }
    } catch {
      return { ok: false, resolvedPath: null, reason: "Unable to resolve real path." };
    }
  }

  if (isPathForbidden(abs, platform) || isPathForbidden(real, platform)) {
    return { ok: false, resolvedPath: null, reason: "Access to restricted trust zone is forbidden." };
  }

  const dynamicAllowed = options.allowedRoots
    ? options.allowedRoots.map((r) => pathMod.resolve(r))
    : [
        ...ALLOWED_EVIDENCE_ROOTS.filter((r) => isWin32 || !/^[A-Za-z]:\\/.test(r)).map((r) => pathMod.resolve(r)),
        ...resolveAllowedEvidenceRoots(process.env, platform).map((r) => pathMod.resolve(r)),
      ];

  if (options.includeTargetFolders !== false && !options.allowedRoots) {
    for (const pinned of readPinnedFoldersSafe()) {
      const pRes = pathMod.resolve(pinned);
      if (!isPathForbidden(pRes, platform)) {
        // Verify pinned path is already under an authorized workspace root before trusting it
        if (dynamicAllowed.some((ar) => isUnderRoot(pRes, ar, isWin32))) {
          dynamicAllowed.push(pRes);
        }
      }
    }
  }

  for (const allowed of dynamicAllowed) {
    if (isUnderRoot(real, allowed, isWin32)) {
      return { ok: true, resolvedPath: real };
    }
  }

  return {
    ok: false,
    resolvedPath: null,
    reason: "Path is outside authorized workspace/evidence directories.",
  };
}

module.exports = {
  SECRET_PATTERNS,
  LINUX_FORBIDDEN_ROOTS,
  WINDOWS_FORBIDDEN_ROOTS,
  FORBIDDEN_ROOTS,
  ALLOWED_EVIDENCE_ROOTS,
  resolveAllowedEvidenceRoots,
  sanitizeText,
  sanitizePayload,
  isPathForbidden,
  validateAuthorizedEvidencePath,
};
