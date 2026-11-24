#!/usr/bin/env node
/**
 * ALLINAGENT — Idempotent Paperclip Runtime Patcher (paperclipai@2026.1117.0)
 *
 * Applies and verifies 4 production patches after `npm install paperclipai@2026.1117.0`:
 *   1. @paperclipai/hermes-paperclip-adapter/dist/server/execute.js
 *      - Uses --query-file for prompts > 6000 chars or on win32 (0o600 permissions)
 *      - Guarantees tempQueryFile cleanup via fs.rm(tempQueryFile, { force: true }) in finally {}
 *   2. @paperclipai/hermes-paperclip-adapter/dist/server/skills.js
 *      - Preserves skill-registry & `--` namespaced skill symlinks/junctions
 *      - Adds cross-platform junction/dir symlink + materializePaperclipSkillCopy fallback
 *   3. @paperclipai/hermes-paperclip-adapter/dist/gateway/server/transport-security.js
 *      - Allows internal Docker bridge hostnames from process.env.HERMES_GATEWAY_INTERNAL_HOSTS
 *   4. @paperclipai/db/dist/client.js
 *      - Caps DEFAULT_MAIN_POOL_CONNECTIONS via Number(process.env.PAPERCLIP_DB_POOL_MAX || 5)
 *      - Trims private & dedicated pool budgets when PAPERCLIP_LOW_MEMORY=1 (<= 12-15 PG conns vs 73)
 */

import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function resolvePaperclipAppDir(explicitAppDir = process.env.PAPERCLIP_APP_DIR) {
  const trimmed = String(explicitAppDir || "").trim();
  if (trimmed) {
    return path.resolve(trimmed);
  }
  if (fs.existsSync("/opt/paperclip/node_modules") || fs.existsSync("/opt/paperclip/package.json")) {
    return "/opt/paperclip";
  }
  return __dirname;
}

export function resolvePaperclipNodeModulesDir(options = {}) {
  if (options.nodeModulesDir) {
    return path.resolve(options.nodeModulesDir);
  }
  const envNm = String(process.env.PAPERCLIP_NODE_MODULES_DIR || "").trim();
  if (envNm) {
    return path.resolve(envNm);
  }
  const appDir = resolvePaperclipAppDir(options.appDir);
  const appNm = path.join(appDir, "node_modules");
  if (fs.existsSync(appNm)) {
    return appNm;
  }
  const localNm = path.join(__dirname, "node_modules");
  if (fs.existsSync(localNm)) {
    return localNm;
  }
  return appNm;
}

export const PATCH_MARKERS = {
  execute: "ALLINAGENT_PATCH_EXECUTE_QUERY_FILE_V1",
  skills: "ALLINAGENT_PATCH_SKILLS_RECONCILE_V1",
  transportSecurity: "ALLINAGENT_PATCH_TRANSPORT_SECURITY_V1",
  dbClient: "ALLINAGENT_PATCH_DB_LOW_MEMORY_POOL_V1",
};

function sha256(content) {
  return crypto.createHash("sha256").update(content, "utf8").digest("hex");
}

function normalizeLf(content) {
  return content.replace(/\r\n/g, "\n");
}

// ---------------------------------------------------------------------------
// Patch 1: @paperclipai/hermes-paperclip-adapter/dist/server/execute.js
// ---------------------------------------------------------------------------
export function patchHermesExecuteJs(rawSource) {
  let content = normalizeLf(rawSource);

  if (
    content.includes(PATCH_MARKERS.execute) &&
    content.includes("await fs.rm(tempQueryFile, { force: true }).catch(() => {});")
  ) {
    return { status: "already_patched", content };
  }

  // 1a. Ensure `import os from "node:os";` exists
  if (!/^import os from ["']node:os["'];$/m.test(content)) {
    const fsImportAnchor = 'import fs from "node:fs/promises";\n';
    if (!content.includes(fsImportAnchor)) {
      throw new Error("[execute.js] Missing expected `import fs from \"node:fs/promises\";` anchor.");
    }
    content = content.replace(fsImportAnchor, () => `${fsImportAnchor}import os from "node:os";\n`);
  }

  // 1b. Replace command args block (handles both pristine 2026.1117.0 and prior live-patched variant)
  const pristineArgsRe =
    /[ \t]*\/\/ ── Build command args ─+\n[ \t]*\/\/ Use -Q \(quiet\)[^\n]*\n[ \t]*const useQuiet = cfgBoolean\(config\.quiet\) === true;[^\n]*\n[ \t]*const args = \["chat", "-q", prompt\];\n[ \t]*if \(useQuiet\)\n[ \t]*args\.push\("-Q"\);/;

  const partialPatchedArgsRe =
    /[ \t]*\/\/ ── Build command args ─+\n(?:[ \t]*\/\/[^\n]*\n)*[ \t]*const useQuiet = cfgBoolean\(config\.quiet\) === true;[^\n]*\n[ \t]*let tempQueryFile = null;\n[ \t]*const args = \["chat"\];\n[ \t]*if \(process\.platform === "win32" \|\| prompt\.length > 6000\) \{[\s\S]*?\}\n[ \t]*else \{\n[ \t]*args\.push\("-q", prompt\);\n[ \t]*\}\n[ \t]*if \(useQuiet\)\n[ \t]*args\.push\("-Q"\);/;

  const patchedArgsBlock = [
    "    // ── Build command args ─────────────────────────────────────────────────",
    `    // ${PATCH_MARKERS.execute}`,
    "    // Use --query-file on Windows or large prompts (> 6000 chars) to avoid CLI arg limits",
    "    const useQuiet = cfgBoolean(config.quiet) === true; // default false",
    "    let tempQueryFile = null;",
    '    const args = ["chat"];',
    '    if (process.platform === "win32" || prompt.length > 6000) {',
    "        tempQueryFile = path.join(os.tmpdir(), `paperclip-hermes-query-${ctx.runId || Date.now()}-${Math.random().toString(36).slice(2, 8)}.txt`);",
    '        args.push("--query-file", tempQueryFile);',
    "    }",
    "    else {",
    '        args.push("-q", prompt);',
    "    }",
    "    if (useQuiet)",
    '        args.push("-Q");',
  ].join("\n");

  if (pristineArgsRe.test(content)) {
    content = content.replace(pristineArgsRe, () => patchedArgsBlock);
  } else if (partialPatchedArgsRe.test(content)) {
    content = content.replace(partialPatchedArgsRe, () => patchedArgsBlock);
  } else {
    throw new Error("[execute.js] Could not locate command args construction block to patch.");
  }

  // 1c. Replace runChildProcess invocation with try/finally + fs.rm(..., { force: true })
  const pristineRunRe =
    /[ \t]*const result = await runChildProcess\(ctx\.runId, hermesCmd, args, \{\n[ \t]*cwd,\n[ \t]*env,\n[ \t]*timeoutSec,\n[ \t]*graceSec,\n[ \t]*onLog: wrappedOnLog,\n[ \t]*onSpawn: ctx\.onSpawn,\n[ \t]*\}\);/;

  const partialRunRe =
    /[ \t]*let result;\n[ \t]*try \{\n(?:[ \t]*if \(tempQueryFile\) \{[\s\S]*?\}\n)?[ \t]*result = await runChildProcess\(ctx\.runId, hermesCmd, args, \{\n[ \t]*cwd,\n[ \t]*env,\n[ \t]*timeoutSec,\n[ \t]*graceSec,\n[ \t]*onLog: wrappedOnLog,\n[ \t]*onSpawn: ctx\.onSpawn,\n[ \t]*\}\);\n[ \t]*\}\n[ \t]*finally \{\n[ \t]*if \(tempQueryFile\) \{\n[ \t]*await fs\.(?:unlink|rm)\(tempQueryFile[^\n]*\n[ \t]*\}\n[ \t]*\}/;

  const patchedRunBlock = [
    "    let result;",
    "    try {",
    "        if (tempQueryFile) {",
    '            await fs.writeFile(tempQueryFile, prompt, { encoding: "utf-8", mode: 0o600 });',
    "        }",
    "        result = await runChildProcess(ctx.runId, hermesCmd, args, {",
    "            cwd,",
    "            env,",
    "            timeoutSec,",
    "            graceSec,",
    "            onLog: wrappedOnLog,",
    "            onSpawn: ctx.onSpawn,",
    "        });",
    "    }",
    "    finally {",
    "        if (tempQueryFile) {",
    "            await fs.rm(tempQueryFile, { force: true }).catch(() => {});",
    "        }",
    "    }",
  ].join("\n");

  if (pristineRunRe.test(content)) {
    content = content.replace(pristineRunRe, () => patchedRunBlock);
  } else if (partialRunRe.test(content)) {
    content = content.replace(partialRunRe, () => patchedRunBlock);
  } else {
    throw new Error("[execute.js] Could not locate runChildProcess block to patch.");
  }

  return { status: "patched", content };
}

// ---------------------------------------------------------------------------
// Patch 2: @paperclipai/hermes-paperclip-adapter/dist/server/skills.js
// ---------------------------------------------------------------------------
export function patchHermesSkillsJs(rawSource) {
  let content = normalizeLf(rawSource);

  if (content.includes(PATCH_MARKERS.skills)) {
    return { status: "already_patched", content };
  }

  // 2a. Ensure materializePaperclipSkillCopy is imported from @paperclipai/adapter-utils/server-utils
  if (!content.includes("materializePaperclipSkillCopy")) {
    const importRe = /import \{\s*ensurePaperclipSkillSymlink,\s*isPaperclipSkillSourceMissing,/;
    if (!importRe.test(content)) {
      throw new Error("[skills.js] Missing expected @paperclipai/adapter-utils/server-utils import block.");
    }
    content = content.replace(
      importRe,
      "import { ensurePaperclipSkillSymlink, isPaperclipSkillSourceMissing, materializePaperclipSkillCopy,",
    );
  }

  // 2b. Ensure scanHermesSkills follows directory symlinks/junctions (e.g. skill-registry `--` skills)
  const scanDirCheckOld = [
    "        for (const cat of categories) {",
    "            if (!cat.isDirectory())",
    "                continue;",
    "            const catPath = path.join(skillsHome, cat.name);",
  ].join("\n");

  const scanDirCheckNew = [
    "        for (const cat of categories) {",
    "            const catPath = path.join(skillsHome, cat.name);",
    "            if (!cat.isDirectory()) {",
    "                if (!cat.isSymbolicLink())",
    "                    continue;",
    "                const linkedStat = await fs.stat(catPath).catch(() => null);",
    "                if (!linkedStat || !linkedStat.isDirectory())",
    "                    continue;",
    "            }",
  ].join("\n");

  if (content.includes(scanDirCheckOld)) {
    content = content.replace(scanDirCheckOld, () => scanDirCheckNew);
  }

  // 2c. Replace reconcileHermesPaperclipSkills body
  const reconcileRe =
    /export async function reconcileHermesPaperclipSkills\(config, requestedDesiredSkills\) \{[\s\S]*?\n    return desiredSkills;\n\}/;

  if (!reconcileRe.test(content)) {
    throw new Error("[skills.js] Missing expected reconcileHermesPaperclipSkills function.");
  }

  const patchedReconcileFn = [
    "export async function reconcileHermesPaperclipSkills(config, requestedDesiredSkills) {",
    `    // ${PATCH_MARKERS.skills}`,
    "    const availableEntries = await readPaperclipRuntimeSkillEntries(config, __moduleDir);",
    "    const desiredSkills = requestedDesiredSkills",
    "        ? Array.from(new Set([",
    "            ...resolveLegacyPaperclipDesiredSkillNames({}, availableEntries),",
    "            ...requestedDesiredSkills,",
    "        ]))",
    "        : resolveLegacyPaperclipDesiredSkillNames(config, availableEntries);",
    "    const desiredSet = new Set(desiredSkills);",
    '    const skillsHome = path.join(resolveHermesHome(config), "skills");',
    "    await fs.mkdir(skillsHome, { recursive: true });",
    "    const installed = await readInstalledSkillTargets(skillsHome);",
    "    const availableByRuntimeName = new Map(availableEntries.map((entry) => [entry.runtimeName, entry]));",
    '    const symlinkType = process.platform === "win32" ? "junction" : "dir";',
    "    const isCopyFallbackError = (err) => Boolean(err && typeof err === \"object\" && (err.code === \"EPERM\" || err.code === \"ENOSYS\" || err.code === \"EXDEV\"));",
    "    const normalizeLinkPath = (p) => (p ? p.replace(/^\\\\\\\\\\?\\\\/, \"\").replace(/[\\\\/]+$/, \"\") : null);",
    "    const pathsEqual = (a, b) => {",
    "        if (!a || !b)",
    "            return false;",
    '        return process.platform === "win32"',
    "            ? path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase()",
    "            : path.resolve(a) === path.resolve(b);",
    "    };",
    "    for (const entry of availableEntries) {",
    "        if (!desiredSet.has(entry.key) || isPaperclipSkillSourceMissing(entry))",
    "            continue;",
    "        const target = path.join(skillsHome, entry.runtimeName);",
    "        try {",
    "            await ensurePaperclipSkillSymlink(entry.source, target, (s, t) => fs.symlink(s, t, symlinkType));",
    "        }",
    "        catch (err) {",
    "            if (isCopyFallbackError(err)) {",
    "                await materializePaperclipSkillCopy(entry.source, target);",
    "                continue;",
    "            }",
    "            throw err;",
    "        }",
    "        let linkedSource = await fs.readlink(target).catch(() => null);",
    "        let cleanLinked = normalizeLinkPath(linkedSource);",
    "        let resolvedSource = cleanLinked ? path.resolve(path.dirname(target), cleanLinked) : null;",
    "        let sameTarget = resolvedSource ? pathsEqual(resolvedSource, entry.source) : true;",
    "        if (resolvedSource && !sameTarget) {",
    "            const normLower = resolvedSource.toLowerCase();",
    "            const isManagedOrigin = normLower.includes(\"paperclip\") || normLower.includes(\"skill-registry\") || entry.runtimeName.includes(\"--\");",
    "            if (isManagedOrigin) {",
    "                await fs.unlink(target).catch(() => fs.rmdir(target).catch(() => {}));",
    "                try {",
    "                    await fs.symlink(entry.source, target, symlinkType);",
    "                }",
    "                catch (err) {",
    "                    if (isCopyFallbackError(err)) {",
    "                        await materializePaperclipSkillCopy(entry.source, target);",
    "                        continue;",
    "                    }",
    "                    throw err;",
    "                }",
    "                linkedSource = await fs.readlink(target).catch(() => null);",
    "                cleanLinked = normalizeLinkPath(linkedSource);",
    "                resolvedSource = cleanLinked ? path.resolve(path.dirname(target), cleanLinked) : null;",
    "                sameTarget = resolvedSource ? pathsEqual(resolvedSource, entry.source) : true;",
    "            }",
    "        }",
    "        if (resolvedSource && !sameTarget) {",
    "            throw new Error(`Cannot reconcile Hermes skill \"${entry.key}\" because ${target} is occupied by another installation.`);",
    "        }",
    "    }",
    "    for (const [name, installedEntry] of installed.entries()) {",
    "        // Preserve externally managed skill-registry / `--` namespaced role skills",
    "        const available = availableByRuntimeName.get(name);",
    "        if (!available || desiredSet.has(available.key))",
    "            continue;",
    "        const normInstalled = normalizeLinkPath(installedEntry.targetPath);",
    "        if (!normInstalled || !pathsEqual(normInstalled, available.source))",
    "            continue;",
    "        await fs.unlink(path.join(skillsHome, name)).catch(() => fs.rmdir(path.join(skillsHome, name)).catch(() => {}));",
    "    }",
    "    return desiredSkills;",
    "}",
  ].join("\n");

  content = content.replace(reconcileRe, () => patchedReconcileFn);
  return { status: "patched", content };
}

// ---------------------------------------------------------------------------
// Patch 3: @paperclipai/hermes-paperclip-adapter/dist/gateway/server/transport-security.js
// ---------------------------------------------------------------------------
export function patchTransportSecurityJs(rawSource) {
  let content = normalizeLf(rawSource);

  if (content.includes(PATCH_MARKERS.transportSecurity)) {
    return { status: "already_patched", content };
  }

  const loopbackFnOld = [
    "export function isLoopbackHostname(hostname) {",
    '    const value = hostname.toLowerCase().replace(/^\\[|\\]$/g, "");',
    '    return (value === "localhost" ||',
    '        value === "::1" ||',
    '        value === "0:0:0:0:0:0:0:1" ||',
    '        value === "127.0.0.1" ||',
    "        /^127(?:\\.\\d{1,3}){3}$/.test(value));",
    "}",
  ].join("\n");

  if (!content.includes(loopbackFnOld)) {
    throw new Error("[transport-security.js] Missing expected isLoopbackHostname implementation.");
  }

  const patchedLoopbackFn = [
    `// ${PATCH_MARKERS.transportSecurity}`,
    "export function parseInternalGatewayHosts(raw = process.env.HERMES_GATEWAY_INTERNAL_HOSTS) {",
    '    if (typeof raw !== "string" || raw.trim().length === 0)',
    "        return [];",
    "    return raw",
    '        .split(/[\\s,]+/)',
    '        .map((host) => host.trim().toLowerCase().replace(/^\\[|\\]$/g, ""))',
    "        .filter(Boolean);",
    "}",
    "export function isInternalGatewayHostname(hostname, raw = process.env.HERMES_GATEWAY_INTERNAL_HOSTS) {",
    '    const value = String(hostname || "").trim().toLowerCase().replace(/^\\[|\\]$/g, "");',
    "    if (!value)",
    "        return false;",
    "    return parseInternalGatewayHosts(raw).includes(value);",
    "}",
    "export function isLoopbackHostname(hostname) {",
    '    const value = hostname.toLowerCase().replace(/^\\[|\\]$/g, "");',
    '    return (value === "localhost" ||',
    '        value === "::1" ||',
    '        value === "0:0:0:0:0:0:0:1" ||',
    '        value === "127.0.0.1" ||',
    "        /^127(?:\\.\\d{1,3}){3}$/.test(value) ||",
    "        isInternalGatewayHostname(value));",
    "}",
  ].join("\n");

  content = content.replace(loopbackFnOld, () => patchedLoopbackFn);

  const deniedMsgOld =
    'return (`Hermes gateway apiBaseUrl uses remote plain HTTP for "${hostname}". ` +\n' +
    "        `Use HTTPS or set ${INSECURE_REMOTE_HTTP_ESCAPE_HATCH}=true only for unsafe local development.`);";
  const deniedMsgNew =
    'return (`Hermes gateway apiBaseUrl uses remote plain HTTP for "${hostname}". ` +\n' +
    "        `Use HTTPS, add trusted Docker service hostnames to HERMES_GATEWAY_INTERNAL_HOSTS, or set ${INSECURE_REMOTE_HTTP_ESCAPE_HATCH}=true only for unsafe local development.`);";
  if (content.includes(deniedMsgOld)) {
    content = content.replace(deniedMsgOld, () => deniedMsgNew);
  }

  return { status: "patched", content };
}

// ---------------------------------------------------------------------------
// Patch 4: @paperclipai/db/dist/client.js
// ---------------------------------------------------------------------------
export function patchDbClientJs(rawSource) {
  let content = normalizeLf(rawSource);

  if (content.includes(PATCH_MARKERS.dbClient)) {
    return { status: "already_patched", content };
  }

  // 4a. Add AsyncLocalStorage import for re-entrant dedicated connection tracking
  const cryptoImport = 'import { createHash } from "node:crypto";\n';
  if (!content.includes(cryptoImport)) {
    throw new Error("[client.js] Missing expected `import { createHash } from \"node:crypto\";` anchor.");
  }
  if (!content.includes('from "node:async_hooks"')) {
    content = content.replace(
      cryptoImport,
      `${cryptoImport}import { AsyncLocalStorage } from "node:async_hooks";\n`,
    );
  }

  // 4b. Add DEFAULT_MAIN_POOL_CONNECTIONS & low-memory helpers around DEFAULT_DATABASE_IDLE_TIMEOUT_SECONDS
  const idleConstAnchor = "export const DEFAULT_DATABASE_IDLE_TIMEOUT_SECONDS = 60;";
  if (!content.includes(idleConstAnchor)) {
    throw new Error("[client.js] Missing expected DEFAULT_DATABASE_IDLE_TIMEOUT_SECONDS constant.");
  }

  const lowMemHeader = [
    `// ${PATCH_MARKERS.dbClient}`,
    "function isPaperclipLowMemory(env = process.env) {",
    '    const raw = env.PAPERCLIP_LOW_MEMORY?.trim().toLowerCase();',
    '    return raw === "1" || raw === "true" || raw === "yes" || raw === "on";',
    "}",
    "function resolveDefaultMainPoolConnections(env = process.env) {",
    "    const parsed = Number(env.PAPERCLIP_DB_POOL_MAX || 5);",
    "    return Number.isFinite(parsed) && parsed >= 1 ? Math.floor(parsed) : 5;",
    "}",
    "function resolveDefaultDedicatedPoolConnections(env = process.env) {",
    "    const explicit = Number(env.PAPERCLIP_DEDICATED_POOL_MAX || 0);",
    "    if (Number.isFinite(explicit) && explicit >= 1)",
    "        return Math.floor(explicit);",
    "    return isPaperclipLowMemory(env) ? 2 : 6;",
    "}",
    "export const DEFAULT_MAIN_POOL_CONNECTIONS = resolveDefaultMainPoolConnections();",
    "export const LOW_MEMORY_IDLE_TIMEOUT_SECONDS = 20;",
    "export const DEFAULT_DATABASE_IDLE_TIMEOUT_SECONDS = isPaperclipLowMemory() ? LOW_MEMORY_IDLE_TIMEOUT_SECONDS : 60;",
  ].join("\n");

  content = content.replace(idleConstAnchor, () => lowMemHeader);

  // 4c. Support PAPERCLIP_DB_POOL_MAX fallback in databaseClientOptionsFromEnv
  const envPoolMaxOld = [
    '    const maxConnections = envPositiveInteger(env, "DATABASE_POOL_MAX");',
    "    if (maxConnections !== undefined)",
    "        options.maxConnections = maxConnections;",
  ].join("\n");
  const envPoolMaxNew = [
    '    const maxConnections = envPositiveInteger(env, "DATABASE_POOL_MAX") ?? envPositiveInteger(env, "PAPERCLIP_DB_POOL_MAX");',
    "    if (maxConnections !== undefined)",
    "        options.maxConnections = maxConnections;",
  ].join("\n");

  if (!content.includes(envPoolMaxOld)) {
    throw new Error("[client.js] Missing expected DATABASE_POOL_MAX block in databaseClientOptionsFromEnv.");
  }
  content = content.replace(envPoolMaxOld, () => envPoolMaxNew);

  // 4d. Cap main pool in resolveDatabaseClientOptions via DEFAULT_MAIN_POOL_CONNECTIONS (Number(process.env.PAPERCLIP_DB_POOL_MAX || 5))
  const resolveOptsOld = [
    "export function resolveDatabaseClientOptions(options) {",
    "    return {",
    "        ...options,",
    "        idleTimeoutSeconds: options.idleTimeoutSeconds ?? DEFAULT_DATABASE_IDLE_TIMEOUT_SECONDS,",
    "        applicationName: options.applicationName ?? DEFAULT_DATABASE_APPLICATION_NAME,",
    "    };",
    "}",
  ].join("\n");

  const resolveOptsNew = [
    "export function resolveDatabaseClientOptions(options) {",
    "    const mainPoolDefault = resolveDefaultMainPoolConnections();",
    "    const idleDefault = isPaperclipLowMemory() ? LOW_MEMORY_IDLE_TIMEOUT_SECONDS : 60;",
    "    return {",
    "        ...options,",
    "        maxConnections: options.maxConnections ?? mainPoolDefault,",
    "        idleTimeoutSeconds: options.idleTimeoutSeconds ?? idleDefault,",
    "        applicationName: options.applicationName ?? DEFAULT_DATABASE_APPLICATION_NAME,",
    "    };",
    "}",
  ].join("\n");

  if (!content.includes(resolveOptsOld)) {
    throw new Error("[client.js] Missing expected resolveDatabaseClientOptions function.");
  }
  content = content.replace(resolveOptsOld, () => resolveOptsNew);

  // 4e. Bound withDedicatedDbConnection with a re-entrant semaphore so bursts never open 50+ PG backends
  const dedicatedFnOld = [
    "export async function withDedicatedDbConnection(db, action) {",
    "    const factory = dedicatedDbFactories.get(db);",
    "    if (!factory)",
    '        throw new Error("dedicated_connection_requires_create_db");',
    "    const dedicated = factory();",
    "    try {",
    "        return await action(dedicated);",
    "    }",
    "    finally {",
    "        await dedicated.$client.end({ timeout: 1 });",
    "    }",
    "}",
  ].join("\n");

  const dedicatedFnNew = [
    "const dedicatedSemaphores = new WeakMap();",
    "const activeDedicatedOwners = new AsyncLocalStorage();",
    "export const DEFAULT_DEDICATED_CONNECTION_MAX = resolveDefaultDedicatedPoolConnections();",
    "function getDedicatedSemaphore(db) {",
    "    let sem = dedicatedSemaphores.get(db);",
    "    if (!sem) {",
    "        sem = { limit: resolveDefaultDedicatedPoolConnections(), inUse: 0, waiters: [] };",
    "        dedicatedSemaphores.set(db, sem);",
    "    }",
    "    return sem;",
    "}",
    "async function acquireDedicatedSlot(sem, bypassWait) {",
    "    if (bypassWait || (sem.inUse < sem.limit && sem.waiters.length === 0)) {",
    "        sem.inUse += 1;",
    "        return;",
    "    }",
    "    await new Promise((resolve) => {",
    "        const waiter = {",
    "            grant: () => {",
    "                clearTimeout(waiter.timer);",
    "                sem.inUse += 1;",
    "                resolve();",
    "            },",
    "            timer: setTimeout(() => {",
    "                const idx = sem.waiters.indexOf(waiter);",
    "                if (idx >= 0)",
    "                    sem.waiters.splice(idx, 1);",
    "                sem.inUse += 1;",
    "                resolve();",
    "            }, 30000),",
    "        };",
    "        waiter.timer.unref?.();",
    "        sem.waiters.push(waiter);",
    "    });",
    "}",
    "function releaseDedicatedSlot(sem) {",
    "    sem.inUse = Math.max(0, sem.inUse - 1);",
    "    while (sem.waiters.length > 0 && sem.inUse < sem.limit) {",
    "        const next = sem.waiters.shift();",
    "        next?.grant();",
    "    }",
    "}",
    "export async function withDedicatedDbConnection(db, action) {",
    "    const factory = dedicatedDbFactories.get(db);",
    "    if (!factory)",
    '        throw new Error("dedicated_connection_requires_create_db");',
    "    const sem = getDedicatedSemaphore(db);",
    "    const heldSet = activeDedicatedOwners.getStore();",
    "    const isNested = Boolean(heldSet?.has(db));",
    "    await acquireDedicatedSlot(sem, isNested);",
    "    let dedicated;",
    "    try {",
    "        dedicated = factory();",
    "        const nextHeld = new Set(heldSet ?? []);",
    "        nextHeld.add(db);",
    "        return await activeDedicatedOwners.run(nextHeld, () => action(dedicated));",
    "    }",
    "    finally {",
    "        try {",
    "            if (dedicated) {",
    "                await dedicated.$client.end({ timeout: 1 }).catch(() => {});",
    "            }",
    "        }",
    "        finally {",
    "            releaseDedicatedSlot(sem);",
    "        }",
    "    }",
    "}",
  ].join("\n");

  if (!content.includes(dedicatedFnOld)) {
    throw new Error("[client.js] Missing expected withDedicatedDbConnection function.");
  }
  content = content.replace(dedicatedFnOld, () => dedicatedFnNew);

  // 4f. Trim private pool constants & factories when PAPERCLIP_LOW_MEMORY=1 and expose databaseConnectionBudget
  const livenessConstOld = "const LIVENESS_POOL_MAX_CONNECTIONS = 2;";
  const livenessConstNew = "const LIVENESS_POOL_MAX_CONNECTIONS = isPaperclipLowMemory() ? 1 : 2;";
  if (!content.includes(livenessConstOld)) {
    throw new Error("[client.js] Missing expected LIVENESS_POOL_MAX_CONNECTIONS constant.");
  }
  content = content.replace(livenessConstOld, () => livenessConstNew);

  const checkpointConstOld = "const CHECKPOINT_POOL_MAX_CONNECTIONS = 3;";
  const checkpointConstNew = [
    "const CHECKPOINT_POOL_MAX_CONNECTIONS = isPaperclipLowMemory() ? 1 : 3;",
    "const FILE_STORAGE_POOL_MAX_CONNECTIONS = isPaperclipLowMemory() ? 1 : 2;",
    "export function databaseConnectionBudget(options = {}, env = process.env) {",
    "    const lowMem = isPaperclipLowMemory(env);",
    "    const main = options.maxConnections ?? resolveDefaultMainPoolConnections(env);",
    "    const liveness = lowMem ? 1 : 2;",
    "    const checkpoint = lowMem ? 1 : 3;",
    "    const fileStorage = lowMem ? 1 : 2;",
    "    const privatePools = liveness + checkpoint + fileStorage;",
    "    const listeners = 2;",
    "    const dedicated = resolveDefaultDedicatedPoolConnections(env);",
    "    return {",
    "        lowMemory: lowMem,",
    "        main,",
    "        privatePools,",
    "        listeners,",
    "        dedicated,",
    "        total: main + privatePools + listeners + dedicated,",
    "    };",
    "}",
  ].join("\n");
  if (!content.includes(checkpointConstOld)) {
    throw new Error("[client.js] Missing expected CHECKPOINT_POOL_MAX_CONNECTIONS constant.");
  }
  content = content.replace(checkpointConstOld, () => checkpointConstNew);

  const factoriesOld = [
    "    livenessDbFactories.set(db, () => createDbClient(url, {",
    '        ...resolved, maxConnections: LIVENESS_POOL_MAX_CONNECTIONS, applicationName: "paperclip-controller-lease",',
    "    }, db));",
    "    checkpointDbFactories.set(db, () => createDbClient(url, {",
    '        ...resolved, maxConnections: CHECKPOINT_POOL_MAX_CONNECTIONS, applicationName: "paperclip-runner-checkpoint",',
    "    }, db));",
    "    fileStorageDbFactories.set(db, () => createDbClient(url, {",
    '        ...resolved, maxConnections: 2, applicationName: "paperclip-file-storage",',
    "    }, db));",
  ].join("\n");

  const factoriesNew = [
    "    livenessDbFactories.set(db, () => createDbClient(url, {",
    '        ...resolved, maxConnections: isPaperclipLowMemory() ? 1 : LIVENESS_POOL_MAX_CONNECTIONS, applicationName: "paperclip-controller-lease",',
    "    }, db));",
    "    checkpointDbFactories.set(db, () => createDbClient(url, {",
    '        ...resolved, maxConnections: isPaperclipLowMemory() ? 1 : CHECKPOINT_POOL_MAX_CONNECTIONS, applicationName: "paperclip-runner-checkpoint",',
    "    }, db));",
    "    fileStorageDbFactories.set(db, () => createDbClient(url, {",
    '        ...resolved, maxConnections: isPaperclipLowMemory() ? 1 : FILE_STORAGE_POOL_MAX_CONNECTIONS, applicationName: "paperclip-file-storage",',
    "    }, db));",
  ].join("\n");

  if (!content.includes(factoriesOld)) {
    throw new Error("[client.js] Missing expected private pool factory registrations in createDbClient.");
  }
  content = content.replace(factoriesOld, () => factoriesNew);

  // Also export DEFAULT_MAIN_POOL_CONNECTIONS and databaseConnectionBudget from @paperclipai/db/dist/index.js if sibling exists
  return { status: "patched", content };
}

export function patchDbIndexJs(rawSource) {
  const content = normalizeLf(rawSource);
  if (content.includes("DEFAULT_MAIN_POOL_CONNECTIONS") && content.includes("databaseConnectionBudget")) {
    return { status: "already_patched", content };
  }
  const anchor = "export { createDb,";
  if (!content.includes(anchor)) {
    return { status: "skipped", content };
  }
  const updated = content.replace(
    anchor,
    "export { createDb, DEFAULT_MAIN_POOL_CONNECTIONS, DEFAULT_DEDICATED_CONNECTION_MAX, databaseConnectionBudget,",
  );
  return { status: "patched", content: updated };
}

export function patchSharedNetworkBindJs(rawSource) {
  const content = normalizeLf(rawSource);
  const marker = "ALLINAGENT_PATCH_DOCKER_LOCAL_TRUSTED_BIND_V1";
  if (content.includes(marker)) {
    return { status: "already_patched", content };
  }
  const targetCheck = '    if (input.deploymentMode === "local_trusted" && bind !== "loopback") {\n        errors.push("local_trusted requires server.bind=loopback");\n    }';
  if (!content.includes(targetCheck)) {
    return { status: "skipped", content };
  }
  const replacementCheck = [
    `    // ${marker}: allow container 0.0.0.0 listener when isolated behind host 127.0.0.1 port mapping`,
    '    if (input.deploymentMode === "local_trusted" && bind !== "loopback" && process.env.ALLINAGENT_DOCKER !== "1") {',
    '        errors.push("local_trusted requires server.bind=loopback");',
    "    }",
  ].join("\n");
  return { status: "patched", content: content.replace(targetCheck, () => replacementCheck) };
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------
export async function applyPaperclipPatches(options = {}) {
  const nodeModulesDir = resolvePaperclipNodeModulesDir(options);
  const dryRun = Boolean(options.dryRun);
  const verifyOnly = Boolean(options.verifyOnly);

  const patchSpecs = [
    {
      id: "hermes-execute-query-file",
      marker: PATCH_MARKERS.execute,
      relPath: "@paperclipai/hermes-paperclip-adapter/dist/server/execute.js",
      transform: patchHermesExecuteJs,
    },
    {
      id: "hermes-skills-reconcile",
      marker: PATCH_MARKERS.skills,
      relPath: "@paperclipai/hermes-paperclip-adapter/dist/server/skills.js",
      transform: patchHermesSkillsJs,
    },
    {
      id: "hermes-gateway-internal-hosts",
      marker: PATCH_MARKERS.transportSecurity,
      relPath: "@paperclipai/hermes-paperclip-adapter/dist/gateway/server/transport-security.js",
      transform: patchTransportSecurityJs,
    },
    {
      id: "db-low-memory-connection-pool",
      marker: PATCH_MARKERS.dbClient,
      relPath: "@paperclipai/db/dist/client.js",
      transform: patchDbClientJs,
    },
  ];

  const results = [];

  for (const spec of patchSpecs) {
    const filePath = path.join(nodeModulesDir, ...spec.relPath.split("/"));
    if (!fs.existsSync(filePath)) {
      throw new Error(`Cannot apply patch "${spec.id}": file not found at ${filePath}`);
    }

    const beforeContent = normalizeLf(await fsp.readFile(filePath, "utf8"));
    const beforeHash = sha256(beforeContent);

    if (verifyOnly) {
      const hasMarker = beforeContent.includes(spec.marker);
      if (!hasMarker) {
        throw new Error(`Patch verification failed for "${spec.id}": marker ${spec.marker} missing in ${filePath}`);
      }
      results.push({
        id: spec.id,
        relPath: spec.relPath,
        status: "verified",
        sha256: beforeHash,
      });
      continue;
    }

    const { status, content: afterContent } = spec.transform(beforeContent);
    const afterHash = sha256(afterContent);

    if (!afterContent.includes(spec.marker)) {
      throw new Error(`Internal patch error for "${spec.id}": marker ${spec.marker} missing after transform`);
    }

    if (!dryRun && status === "patched" && afterHash !== beforeHash) {
      await fsp.writeFile(filePath, afterContent, "utf8");
    }

    results.push({
      id: spec.id,
      relPath: spec.relPath,
      status: dryRun && status === "patched" ? "would_patch" : status,
      beforeSha256: beforeHash,
      afterSha256: afterHash,
    });
  }

  // Optional barrel re-export patch on @paperclipai/db/dist/index.js
  const dbIndexPath = path.join(nodeModulesDir, "@paperclipai", "db", "dist", "index.js");
  if (fs.existsSync(dbIndexPath) && !verifyOnly) {
    const beforeIdx = normalizeLf(await fsp.readFile(dbIndexPath, "utf8"));
    const { status, content: afterIdx } = patchDbIndexJs(beforeIdx);
    if (!dryRun && status === "patched") {
      await fsp.writeFile(dbIndexPath, afterIdx, "utf8");
    }
    results.push({
      id: "db-index-exports",
      relPath: "@paperclipai/db/dist/index.js",
      status: dryRun && status === "patched" ? "would_patch" : status,
      beforeSha256: sha256(beforeIdx),
      afterSha256: sha256(afterIdx),
    });
  }

  // Allow container-namespace 0.0.0.0 bind in local_trusted mode when ALLINAGENT_DOCKER=1
  const networkBindPath = path.join(nodeModulesDir, "@paperclipai", "shared", "dist", "network-bind.js");
  if (fs.existsSync(networkBindPath) && !verifyOnly) {
    const beforeBind = normalizeLf(await fsp.readFile(networkBindPath, "utf8"));
    const { status, content: afterBind } = patchSharedNetworkBindJs(beforeBind);
    if (!dryRun && status === "patched") {
      await fsp.writeFile(networkBindPath, afterBind, "utf8");
    }
    results.push({
      id: "docker-local-trusted-bind",
      relPath: "@paperclipai/shared/dist/network-bind.js",
      status: dryRun && status === "patched" ? "would_patch" : status,
      beforeSha256: sha256(beforeBind),
      afterSha256: sha256(afterBind),
    });
  }

  return {
    nodeModulesDir,
    dryRun,
    verifyOnly,
    results,
  };
}

function parseCliArgs(argv) {
  const opts = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--dry-run") opts.dryRun = true;
    else if (arg === "--verify-only") opts.verifyOnly = true;
    else if (arg === "--json") opts.json = true;
    else if (arg === "--node-modules" && argv[i + 1]) opts.nodeModulesDir = argv[++i];
    else if (arg.startsWith("--node-modules=")) opts.nodeModulesDir = arg.slice("--node-modules=".length);
    else if (arg === "--app-dir" && argv[i + 1]) opts.appDir = argv[++i];
    else if (arg.startsWith("--app-dir=")) opts.appDir = arg.slice("--app-dir=".length);
  }
  return opts;
}

const isDirectRun =
  process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;

if (isDirectRun) {
  const cliOpts = parseCliArgs(process.argv.slice(2));
  applyPaperclipPatches(cliOpts)
    .then((report) => {
      if (cliOpts.json) {
        process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
        return;
      }
      for (const item of report.results) {
        process.stdout.write(`[paperclip-patch] ${item.id}: ${item.status} (${item.relPath})\n`);
      }
    })
    .catch((err) => {
      process.stderr.write(`[paperclip-patch] ERROR: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(1);
    });
}
