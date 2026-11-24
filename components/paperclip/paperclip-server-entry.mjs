#!/usr/bin/env node
/**
 * ALLINAGENT — Cross-Platform Paperclip Server Production Entrypoint
 *
 * Configures production UI serving, non-interactive automatic DB migrations,
 * telemetry opt-out, low-memory PostgreSQL connection pool limits, and
 * cross-platform instance paths before invoking `@paperclipai/server`'s
 * `await mod.startServer()` with coordinated SIGTERM/SIGINT teardown.
 */

import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const requireFromHere = createRequire(import.meta.url);

function setDefaultEnv(key, value) {
  if (process.env[key] === undefined || process.env[key] === "") {
    process.env[key] = value;
  }
}

function loadEnvFileIfPresent(envFilePath) {
  if (!envFilePath || !fs.existsSync(envFilePath)) {
    return;
  }
  const rawContent = fs.readFileSync(envFilePath, "utf8");
  for (const rawLine of rawContent.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const normalized = line.startsWith("export ") ? line.slice(7).trim() : line;
    const eqIndex = normalized.indexOf("=");
    if (eqIndex <= 0) continue;
    const key = normalized.slice(0, eqIndex).trim();
    const rawValue = normalized.slice(eqIndex + 1).trim();
    const unquoted =
      (rawValue.startsWith('"') && rawValue.endsWith('"')) ||
      (rawValue.startsWith("'") && rawValue.endsWith("'"))
        ? rawValue.slice(1, -1)
        : rawValue;
    if (key && process.env[key] === undefined) {
      process.env[key] = unquoted;
    }
  }
}

function resolveDatabaseUrl() {
  const direct = (process.env.DATABASE_URL || process.env.PAPERCLIP_DATABASE_URL || "").trim();
  if (direct) {
    return direct;
  }
  const pgHost = (process.env.POSTGRES_HOST || process.env.PGHOST || "").trim();
  const pgUser = (process.env.POSTGRES_USER || process.env.PGUSER || "").trim();
  const pgPassword = process.env.POSTGRES_PASSWORD ?? process.env.PGPASSWORD ?? "";
  const pgDatabase = (process.env.POSTGRES_DB || process.env.PGDATABASE || "paperclip").trim();
  const pgPort = (process.env.POSTGRES_PORT || process.env.PGPORT || "5432").trim();

  if (pgHost && pgUser) {
    const credentials = pgPassword
      ? `${encodeURIComponent(pgUser)}:${encodeURIComponent(pgPassword)}`
      : encodeURIComponent(pgUser);
    return `postgresql://${credentials}@${pgHost}:${pgPort}/${encodeURIComponent(pgDatabase)}`;
  }
  return "";
}

function resolvePort() {
  const candidate = Number.parseInt(process.env.PORT || process.env.PAPERCLIP_PORT || "3100", 10);
  return Number.isInteger(candidate) && candidate > 0 && candidate <= 65535 ? String(candidate) : "3100";
}

function resolvePaperclipAppDir() {
  const envAppDir = (process.env.PAPERCLIP_APP_DIR || "").trim();
  if (envAppDir) {
    return path.resolve(envAppDir);
  }
  if (fs.existsSync("/opt/paperclip/node_modules") || fs.existsSync("/opt/paperclip/package.json")) {
    return "/opt/paperclip";
  }
  return __dirname;
}

function resolveServerModuleUrl(appDir) {
  const explicitEntry = (process.env.PAPERCLIP_SERVER_ENTRY || "").trim();
  if (explicitEntry) {
    return pathToFileURL(path.resolve(explicitEntry)).href;
  }

  const appPkgJson = path.join(appDir, "package.json");
  if (fs.existsSync(appPkgJson)) {
    try {
      const requireFromApp = createRequire(appPkgJson);
      const resolvedFromApp = requireFromApp.resolve("@paperclipai/server");
      return pathToFileURL(resolvedFromApp).href;
    } catch {
      // Fall through to direct path checks
    }
  }

  const directCandidates = [
    path.join(appDir, "node_modules", "@paperclipai", "server", "dist", "index.js"),
    path.join(__dirname, "node_modules", "@paperclipai", "server", "dist", "index.js"),
  ];
  for (const cand of directCandidates) {
    if (fs.existsSync(cand)) {
      return pathToFileURL(cand).href;
    }
  }

  try {
    const resolved = requireFromHere.resolve("@paperclipai/server");
    return pathToFileURL(resolved).href;
  } catch {
    throw new Error(
      `Unable to locate @paperclipai/server under PAPERCLIP_APP_DIR (${appDir}) or ${__dirname}. Run \`npm install\` first.`,
    );
  }
}

// ---------------------------------------------------------------------------
// 1. Resolve cross-platform paths & working directory
// ---------------------------------------------------------------------------
const paperclipAppDir = resolvePaperclipAppDir();
process.env.PAPERCLIP_APP_DIR = paperclipAppDir;

const allinagentRoot = process.env.ALLINAGENT_ROOT
  ? path.resolve(process.env.ALLINAGENT_ROOT)
  : path.resolve(__dirname, "..", "..");

const defaultPaperclipHome = fs.existsSync("/var/lib/allinagent")
  ? "/var/lib/allinagent/paperclip"
  : path.join(allinagentRoot, "data", "paperclip");
const paperclipHome = path.resolve(process.env.PAPERCLIP_HOME || defaultPaperclipHome);
const instanceId = (process.env.PAPERCLIP_INSTANCE_ID || "default").trim() || "default";
const instanceRoot = path.join(paperclipHome, "instances", instanceId);
const configPath = path.resolve(process.env.PAPERCLIP_CONFIG || path.join(instanceRoot, "config.json"));
const instanceEnvPath = process.env.PAPERCLIP_ENV_FILE
  ? path.resolve(process.env.PAPERCLIP_ENV_FILE)
  : path.join(path.dirname(configPath), ".env");

fs.mkdirSync(path.dirname(configPath), { recursive: true });

const workDir = path.resolve(process.env.PAPERCLIP_WORKDIR || paperclipAppDir);
if (fs.existsSync(workDir)) {
  process.chdir(workDir);
}

// Load optional instance .env without overriding explicit container/host env vars
loadEnvFileIfPresent(instanceEnvPath);

// ---------------------------------------------------------------------------
// 2. Configure production runtime & low-memory defaults
// ---------------------------------------------------------------------------
setDefaultEnv("NODE_ENV", "production");
process.env.PAPERCLIP_HOME = paperclipHome;
process.env.PAPERCLIP_INSTANCE_ID = instanceId;
process.env.PAPERCLIP_CONFIG = configPath;

setDefaultEnv("SERVE_UI", "true");
setDefaultEnv("PAPERCLIP_UI_DEV_MIDDLEWARE", "false");
setDefaultEnv("PAPERCLIP_MIGRATION_AUTO_APPLY", "true");
setDefaultEnv("PAPERCLIP_MIGRATION_PROMPT", "never");
setDefaultEnv("PAPERCLIP_TELEMETRY_DISABLED", "1");
setDefaultEnv("DO_NOT_TRACK", "1");
setDefaultEnv("PAPERCLIP_NO_BROWSER", "true");
setDefaultEnv("PAPERCLIP_OPEN_ON_LISTEN", "false");

// Low-memory PostgreSQL connection budget & Docker internal gateway allowlist
setDefaultEnv("PAPERCLIP_LOW_MEMORY", "1");
setDefaultEnv("PAPERCLIP_DB_POOL_MAX", "5");
setDefaultEnv("DATABASE_POOL_MAX", process.env.PAPERCLIP_DB_POOL_MAX);
setDefaultEnv("HERMES_GATEWAY_INTERNAL_HOSTS", "hermes,allinagent-hermes,hermes-gateway,host.docker.internal");
if (process.env.ALLINAGENT_DOCKER === "1") {
  setDefaultEnv("PAPERCLIP_DEPLOYMENT_MODE", "local_trusted");
  setDefaultEnv(
    "PAPERCLIP_ALLOWED_HOSTNAMES",
    "paperclip,allinagent-paperclip,localhost,127.0.0.1,host.docker.internal",
  );
}

process.env.PORT = resolvePort();
setDefaultEnv("HOST", process.env.PAPERCLIP_HOST || "127.0.0.1");

const resolvedDbUrl = resolveDatabaseUrl();
if (resolvedDbUrl) {
  process.env.DATABASE_URL = resolvedDbUrl;
}

// ---------------------------------------------------------------------------
// 3. Boot Paperclip Server & register graceful SIGTERM / SIGINT shutdown
// ---------------------------------------------------------------------------
const serverModuleUrl = resolveServerModuleUrl(paperclipAppDir);
const dbMode = process.env.DATABASE_URL ? "external-postgres" : "config-or-embedded";
process.stdout.write(
  `[allinagent-paperclip] Starting Paperclip server (host=${process.env.HOST}, port=${process.env.PORT}, db=${dbMode}, lowMemory=${process.env.PAPERCLIP_LOW_MEMORY}, poolMax=${process.env.PAPERCLIP_DB_POOL_MAX})\n`,
);

const mod = await import(serverModuleUrl);
if (typeof mod.startServer !== "function") {
  throw new Error(`Loaded module ${serverModuleUrl} does not export startServer().`);
}

const started = await mod.startServer();

let shuttingDown = false;
const shutdownTimeoutMs = Math.max(
  5000,
  Number.parseInt(process.env.PAPERCLIP_SHUTDOWN_TIMEOUT_MS || "25000", 10) || 25000,
);

async function handleStop(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  process.stdout.write(`[allinagent-paperclip] Received ${signal}; initiating graceful shutdown...\n`);

  const forceTimer = setTimeout(() => {
    process.stderr.write(`[allinagent-paperclip] Shutdown timed out after ${shutdownTimeoutMs}ms; forcing exit.\n`);
    process.exit(1);
  }, shutdownTimeoutMs);
  forceTimer.unref?.();

  try {
    await started?.shutdown?.(signal);
  } catch (err) {
    process.stderr.write(
      `[allinagent-paperclip] Error during shutdown: ${err instanceof Error ? err.message : String(err)}\n`,
    );
  } finally {
    clearTimeout(forceTimer);
    process.exit(0);
  }
}

process.on("SIGTERM", () => {
  void handleStop("SIGTERM");
});
process.on("SIGINT", () => {
  void handleStop("SIGINT");
});
