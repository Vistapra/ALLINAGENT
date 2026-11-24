"use strict";

/**
 * Cross-Platform Runtime Path, Endpoint & Governance Configuration Resolver
 * for ALLINAGENT Office Bridge (`apps/office-bridge/contracts/paths.js`).
 *
 * Strictly zero hardcoded Windows drive letters, private hostnames, personal usernames,
 * bot handles, or company/agent UUIDs.
 */

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const OFFICE_BRIDGE_ROOT = path.resolve(__dirname, "..");

function resolvePlatformRoot(env = process.env, platform = process.platform) {
  const pathMod = platform === "win32" ? path.win32 : path.posix;
  const configured =
    (env.ALLINAGENT_ROOT && env.ALLINAGENT_ROOT.trim()) ||
    (env.ALLAGENT_ROOT && env.ALLAGENT_ROOT.trim()) ||
    (env.PLATFORM_ROOT && env.PLATFORM_ROOT.trim());
  if (configured) {
    return pathMod.resolve(configured);
  }
  // apps/office-bridge/contracts -> 3 levels up to repository/platform root
  return path.resolve(__dirname, "..", "..", "..");
}

const PLATFORM_ROOT = resolvePlatformRoot(process.env);

// Optional non-overriding .env loader for bare-metal runs (disabled during hermetic tests)
if (process.env.NODE_ENV !== "test" && process.env.OFFICE_BRIDGE_LOAD_DOTENV !== "0") {
  const rootEnvFile = path.join(PLATFORM_ROOT, ".env");
  if (fs.existsSync(rootEnvFile)) {
    try {
      const raw = fs.readFileSync(rootEnvFile, "utf8").replace(/^\uFEFF/, "");
      for (const line of raw.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const eq = trimmed.indexOf("=");
        if (eq > 0) {
          const k = trimmed.slice(0, eq).trim();
          const v = trimmed.slice(eq + 1).trim().replace(/^["']|["']$/g, "");
          if (k && process.env[k] === undefined) {
            process.env[k] = v;
          }
        }
      }
    } catch {
      // non-fatal
    }
  }
}

const USER_HOME = os.homedir();

const OFFICE_DATA_DIR = path.resolve(
  process.env.OFFICE_DATA_DIR || path.join(PLATFORM_ROOT, "office-data")
);

function resolveSecretsDir(env = process.env, platform = process.platform, existsFn = fs.existsSync) {
  const configured =
    (env.ALLINAGENT_SECRETS_DIR && env.ALLINAGENT_SECRETS_DIR.trim()) ||
    (env.SECRETS_DIR && env.SECRETS_DIR.trim());
  const pathMod = platform === "win32" ? path.win32 : path.posix;
  if (configured) {
    return pathMod.resolve(configured);
  }
  if (platform !== "win32" && existsFn("/var/lib/allinagent/secrets")) {
    return "/var/lib/allinagent/secrets";
  }
  return pathMod.resolve(pathMod.join(resolvePlatformRoot(env, platform), "secrets"));
}

function resolveWorkspacesDir(env = process.env, platform = process.platform, existsFn = fs.existsSync) {
  const configured =
    (env.ALLINAGENT_WORKSPACE_ROOT && env.ALLINAGENT_WORKSPACE_ROOT.trim()) ||
    (env.ALLINAGENT_WORKSPACES_DIR && env.ALLINAGENT_WORKSPACES_DIR.trim());
  const pathMod = platform === "win32" ? path.win32 : path.posix;
  if (configured) {
    return pathMod.resolve(configured);
  }
  if (platform !== "win32" && existsFn("/var/lib/allinagent/workspaces")) {
    return "/var/lib/allinagent/workspaces";
  }
  return pathMod.resolve(pathMod.join(resolvePlatformRoot(env, platform), "workspaces"));
}

function resolveReportsDir(env = process.env, platform = process.platform, existsFn = fs.existsSync) {
  const configured =
    (env.ALLINAGENT_REPORTS_ROOT && env.ALLINAGENT_REPORTS_ROOT.trim()) ||
    (env.ALLINAGENT_REPORTS_DIR && env.ALLINAGENT_REPORTS_DIR.trim());
  const pathMod = platform === "win32" ? path.win32 : path.posix;
  if (configured) {
    return pathMod.resolve(configured);
  }
  if (platform !== "win32" && existsFn("/var/lib/allinagent/reports")) {
    return "/var/lib/allinagent/reports";
  }
  return pathMod.resolve(pathMod.join(resolvePlatformRoot(env, platform), "reports"));
}

const SECRETS_DIR = resolveSecretsDir(process.env);
const LOGS_DIR = path.resolve(
  process.env.ALLINAGENT_LOGS_DIR || path.join(PLATFORM_ROOT, "logs")
);
const DATA_DIR = path.resolve(
  process.env.ALLINAGENT_DATA_DIR || path.join(PLATFORM_ROOT, "data")
);
const WORKSPACES_DIR = resolveWorkspacesDir(process.env);
const REPORTS_DIR = resolveReportsDir(process.env);
const DOCS_DIR = path.resolve(
  process.env.ALLINAGENT_DOCS_DIR || path.join(PLATFORM_ROOT, "docs")
);
const SKILL_REGISTRY_DIR = path.resolve(
  process.env.SKILL_REGISTRY_DIR || path.join(PLATFORM_ROOT, "skill-registry")
);
const SKILLS_MANIFESTS_DIR = path.resolve(
  process.env.ALLINAGENT_SKILLS_MANIFESTS_DIR || path.join(PLATFORM_ROOT, "skills", "manifests")
);
const HERMES_UPDATER_DIR = path.resolve(
  process.env.HERMES_UPDATER_DIR || path.join(PLATFORM_ROOT, "scripts", "hermes-updater")
);

function resolveHermesHomeRoot(env = process.env) {
  const explicit = (env.HERMES_HOME_ROOT || env.HERMES_HOME || "").trim();
  if (explicit) {
    return path.resolve(explicit);
  }
  return path.resolve(path.join(DATA_DIR, "hermes"));
}

const HERMES_HOME_ROOT = resolveHermesHomeRoot(process.env);
const HERMES_HOME = HERMES_HOME_ROOT;
const HERMES_PROFILES_DIR = path.resolve(
  process.env.HERMES_PROFILES_DIR || path.join(HERMES_HOME_ROOT, "profiles")
);

function deriveWsUrlFromHttp(httpOrWsUrl) {
  const clean = String(httpOrWsUrl || "http://127.0.0.1:3100").trim().replace(/\/$/, "");
  if (/^wss?:\/\//i.test(clean)) return clean;
  if (/^https:\/\//i.test(clean)) return clean.replace(/^https:\/\//i, "wss://");
  if (/^http:\/\//i.test(clean)) return clean.replace(/^http:\/\//i, "ws://");
  return `ws://${clean}`;
}

const PAPERCLIP_BASE_URL = String(
  process.env.PAPERCLIP_BASE_URL || process.env.PAPERCLIP_URL || "http://127.0.0.1:3100"
)
  .trim()
  .replace(/\/$/, "");

const PAPERCLIP_WS_URL = deriveWsUrlFromHttp(
  process.env.PAPERCLIP_WS_URL || PAPERCLIP_BASE_URL
);

const PAPERCLIP_COMPANY_ID = (() => {
  const cid = String(process.env.PAPERCLIP_COMPANY_ID || "").trim();
  return cid || null;
})();

const HERMES3D_PORT = Number(process.env.HERMES3D_PORT || 3200);
const HERMES3D_BASE_URL = String(
  process.env.HERMES3D_BASE_URL || `http://127.0.0.1:${HERMES3D_PORT}`
)
  .trim()
  .replace(/\/$/, "");

function isLinuxContainerRuntime(env = process.env, platform = process.platform, existsFn = fs.existsSync) {
  if (platform === "win32") return false;
  if (String(env.OFFICE_BRIDGE_ALLOW_CONTAINER_BIND || "").trim() === "1") return true;
  try {
    return Boolean(existsFn("/.dockerenv") || existsFn("/run/.containerenv"));
  } catch {
    return false;
  }
}

function resolveVulnclawWorkerUrl(env = process.env, platform = process.platform, existsFn = fs.existsSync) {
  if (env.VULNCLAW_WORKER_URL !== undefined) {
    return String(env.VULNCLAW_WORKER_URL || "").trim().replace(/\/$/, "");
  }
  if (env.NODE_ENV !== "test" && isLinuxContainerRuntime(env, platform, existsFn)) {
    return "http://vulnclaw:8660";
  }
  return "";
}

function resolveHermesRemoteExecUrl(env = process.env, platform = process.platform, existsFn = fs.existsSync) {
  if (env.HERMES_REMOTE_EXEC_URL !== undefined) {
    return String(env.HERMES_REMOTE_EXEC_URL || "").trim().replace(/\/$/, "");
  }
  if (env.NODE_ENV !== "test" && isLinuxContainerRuntime(env, platform, existsFn)) {
    return "http://hermes:8650";
  }
  return "";
}

function resolveInternalServiceToken(target = "internal", env = process.env) {
  if (target === "vulnclaw") {
    return String(
      env.ALLINAGENT_INTERNAL_TOKEN ||
        env.VULNCLAW_SCAN_TOKEN ||
        env.HERMES_EXEC_SHARED_SECRET ||
        ""
    ).trim();
  }
  return String(
    env.ALLINAGENT_INTERNAL_TOKEN ||
      env.HERMES_EXEC_SHARED_SECRET ||
      env.VULNCLAW_SCAN_TOKEN ||
      ""
  ).trim();
}

const VULNCLAW_WORKER_URL = resolveVulnclawWorkerUrl(process.env);
const HERMES_REMOTE_EXEC_URL = resolveHermesRemoteExecUrl(process.env);
const ALLINAGENT_INTERNAL_TOKEN = resolveInternalServiceToken("internal", process.env);

const PLACEHOLDER_OWNER_ID = "1" + "0".repeat(9);

/**
 * Fail-closed Owner Telegram ID resolver:
 * Returns "" whenever unset, empty, placeholder 10-digit owner ID, "0", "unset", or "changeme".
 */
function resolveAuthorizedOwnerId(env = process.env) {
  const raw = String(env.AUTHORIZED_OWNER_ID || env.OWNER_TELEGRAM_ID || "").trim();
  if (
    !raw ||
    raw === PLACEHOLDER_OWNER_ID ||
    raw === "0" ||
    /^(unset|changeme|your_telegram_id|placeholder|null|undefined)$/i.test(raw)
  ) {
    return "";
  }
  return raw;
}

const AUTHORIZED_OWNER_ID = resolveAuthorizedOwnerId(process.env);

function resolveAuthorizedWorkspaces(env = process.env, platform = process.platform, existsFn = fs.existsSync) {
  const pathMod = platform === "win32" ? path.win32 : path.posix;
  const baseRoots = [
    resolveWorkspacesDir(env, platform, existsFn),
    resolveReportsDir(env, platform, existsFn),
    DOCS_DIR,
  ];
  for (const extraEnvKey of [
    "ALLINAGENT_WORKSPACE_ROOT",
    "ALLINAGENT_WORKSPACES_DIR",
    "ALLINAGENT_REPORTS_ROOT",
    "ALLINAGENT_REPORTS_DIR",
  ]) {
    const val = String(env[extraEnvKey] || "").trim();
    if (val) {
      baseRoots.push(pathMod.resolve(val));
    }
  }
  const rawExtra = String(
    env.AUTHORIZED_WORKSPACES || env.OFFICE_AUTHORIZED_WORKSPACES || ""
  ).trim();
  if (rawExtra) {
    for (const part of rawExtra.split(/[,;]/)) {
      const cleaned = part.trim();
      if (cleaned) {
        baseRoots.push(pathMod.resolve(cleaned));
      }
    }
  }
  const seen = new Set();
  const unique = [];
  for (const r of baseRoots) {
    const key = platform === "win32" ? r.toLowerCase() : r;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(r);
    }
  }
  return unique;
}

const AUTHORIZED_WORKSPACES = resolveAuthorizedWorkspaces(process.env);

function resolveTimezone(env = process.env) {
  const candidate = String(env.TIMEZONE || env.TZ || "UTC").trim() || "UTC";
  try {
    Intl.DateTimeFormat("en-CA", { timeZone: candidate });
    return candidate;
  } catch {
    return "UTC";
  }
}

const TIMEZONE = resolveTimezone(process.env);

const DEFAULT_LLM_BASE_URL = String(
  process.env.LLM_BASE_URL || process.env.CUSTOM_BASE_URL || "https://api.openai.com/v1"
)
  .trim()
  .replace(/\/$/, "");

const DEFAULT_LLM_MODEL = String(
  process.env.LLM_MODEL || process.env.DEFAULT_LLM_MODEL || "gpt-4o-mini"
).trim();

const TELEGRAM_BOT_USERNAME = String(
  process.env.TELEGRAM_BOT_USERNAME || "@allinagent_bot"
).trim();

function resolvePythonExe(env = process.env) {
  if (env.PYTHON_EXE && env.PYTHON_EXE.trim()) {
    return env.PYTHON_EXE.trim();
  }
  const venvPy = path.join(
    PLATFORM_ROOT,
    "runtime",
    "venv",
    process.platform === "win32" ? "Scripts/python.exe" : "bin/python3"
  );
  if (fs.existsSync(venvPy)) return venvPy;
  const toolsDir = path.join(HERMES_HOME_ROOT, "tools");
  if (fs.existsSync(toolsDir)) {
    try {
      for (const entry of fs.readdirSync(toolsDir)) {
        if (entry.toLowerCase().startsWith("python-")) {
          const cand = path.join(
            toolsDir,
            entry,
            process.platform === "win32" ? "python.exe" : "bin/python3"
          );
          if (fs.existsSync(cand)) return cand;
        }
      }
    } catch {}
  }
  return process.platform === "win32" ? "python" : "python3";
}

function resolveGitExe(env = process.env) {
  if (env.GIT_EXE && env.GIT_EXE.trim()) return env.GIT_EXE.trim();
  return "git";
}

function resolveNpmExe(env = process.env) {
  if (env.NPM_EXE && env.NPM_EXE.trim()) return env.NPM_EXE.trim();
  return process.platform === "win32" ? "npm.cmd" : "npm";
}

function resolveChromiumExe(env = process.env) {
  for (const key of ["CHROMIUM_BIN", "CHROME_BIN", "CHROMIUM_EXE", "PUPPETEER_EXECUTABLE_PATH"]) {
    if (env[key] && env[key].trim() && fs.existsSync(env[key].trim())) {
      return env[key].trim();
    }
  }
  if (process.platform !== "win32") {
    const linuxBins = [
      "/usr/bin/chromium",
      "/usr/bin/chromium-browser",
      "/usr/bin/google-chrome",
      "/usr/bin/google-chrome-stable",
      "/usr/bin/microsoft-edge",
    ];
    for (const bin of linuxBins) {
      if (fs.existsSync(bin)) return bin;
    }
    return "chromium";
  }
  const winBins = [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
  ];
  for (const bin of winBins) {
    if (fs.existsSync(bin)) return bin;
  }
  return "";
}

let cachedDatabaseSync = undefined;
function loadSqliteDatabaseSync() {
  if (cachedDatabaseSync !== undefined) return cachedDatabaseSync;
  try {
    const mod = require("node:sqlite");
    cachedDatabaseSync = mod && typeof mod.DatabaseSync === "function" ? mod.DatabaseSync : null;
  } catch {
    cachedDatabaseSync = null;
  }
  return cachedDatabaseSync;
}

const PYTHON_EXE = resolvePythonExe(process.env);
const GIT_EXE = resolveGitExe(process.env);
const NPM_EXE = resolveNpmExe(process.env);
const CHROMIUM_EXE = resolveChromiumExe(process.env);

module.exports = {
  OFFICE_BRIDGE_ROOT,
  PLATFORM_ROOT,
  USER_HOME,
  OFFICE_DATA_DIR,
  SECRETS_DIR,
  LOGS_DIR,
  DATA_DIR,
  WORKSPACES_DIR,
  REPORTS_DIR,
  DOCS_DIR,
  SKILL_REGISTRY_DIR,
  SKILLS_MANIFESTS_DIR,
  HERMES_UPDATER_DIR,
  HERMES_HOME_ROOT,
  HERMES_HOME,
  HERMES_PROFILES_DIR,
  PAPERCLIP_BASE_URL,
  PAPERCLIP_WS_URL,
  PAPERCLIP_COMPANY_ID,
  HERMES3D_PORT,
  HERMES3D_BASE_URL,
  VULNCLAW_WORKER_URL,
  HERMES_REMOTE_EXEC_URL,
  ALLINAGENT_INTERNAL_TOKEN,
  PLACEHOLDER_OWNER_ID,
  AUTHORIZED_WORKSPACES,
  AUTHORIZED_OWNER_ID,
  TIMEZONE,
  DEFAULT_LLM_BASE_URL,
  DEFAULT_LLM_MODEL,
  TELEGRAM_BOT_USERNAME,
  PYTHON_EXE,
  GIT_EXE,
  NPM_EXE,
  CHROMIUM_EXE,
  isLinuxContainerRuntime,
  resolvePlatformRoot,
  resolveSecretsDir,
  resolveWorkspacesDir,
  resolveReportsDir,
  resolveHermesHomeRoot,
  deriveWsUrlFromHttp,
  resolveVulnclawWorkerUrl,
  resolveHermesRemoteExecUrl,
  resolveInternalServiceToken,
  resolveAuthorizedOwnerId,
  resolveAuthorizedWorkspaces,
  resolveTimezone,
  resolvePythonExe,
  resolveGitExe,
  resolveNpmExe,
  resolveChromiumExe,
  loadSqliteDatabaseSync,
};
