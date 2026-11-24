#!/usr/bin/env node
/**
 * ALLINAGENT — Paperclip Production Bloat Pruner & License Sanitizer
 *
 * Removes proprietary / unused third-party agent CLIs & SDKs, optional
 * embedded-postgres native binaries (when PRUNE_EMBEDDED_POSTGRES=1),
 * foreign-OS/arch paperclip-runnerd daemons, and dead test/sourcemap files
 * while keeping @paperclipai/server, ui-dist, @paperclipai/db,
 * @paperclipai/skills-catalog, and @paperclipai/hermes-paperclip-adapter
 * 100% intact.
 */

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

function parseBoolEnv(val, defaultValue = false) {
  if (val === undefined || val === null || String(val).trim() === "") {
    return defaultValue;
  }
  const norm = String(val).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(norm)) return true;
  if (["0", "false", "no", "off"].includes(norm)) return false;
  return defaultValue;
}

function measureTreeSync(targetPath) {
  let bytes = 0;
  let files = 0;
  let stat;
  try {
    stat = fs.lstatSync(targetPath);
  } catch {
    return { bytes: 0, files: 0 };
  }
  if (stat.isSymbolicLink()) {
    return { bytes: 0, files: 0 };
  }
  if (stat.isFile()) {
    return { bytes: stat.size, files: 1 };
  }
  if (!stat.isDirectory()) {
    return { bytes: 0, files: 0 };
  }

  const stack = [targetPath];
  while (stack.length > 0) {
    const current = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile()) {
        try {
          bytes += fs.statSync(fullPath).size;
          files += 1;
        } catch {
          // Ignore transient stat races
        }
      }
    }
  }
  return { bytes, files };
}

function detectBinaryTarget(filePath) {
  try {
    const fd = fs.openSync(filePath, "r");
    const header = Buffer.alloc(128);
    const bytesRead = fs.readSync(fd, header, 0, 128, 0);
    fs.closeSync(fd);
    if (bytesRead < 20) return null;

    // ELF64 little-endian
    if (
      header[0] === 0x7f &&
      header[1] === 0x45 &&
      header[2] === 0x4c &&
      header[3] === 0x46 &&
      header[4] === 2 &&
      header[5] === 1
    ) {
      const machine = header.readUInt16LE(18);
      if (machine === 62) return "linux-x64";
      if (machine === 183) return "linux-arm64";
      return `linux-elf-${machine}`;
    }

    // Mach-O 64-bit
    if (header.readUInt32LE(0) === 0xfeedfacf) {
      const cpu = header.readUInt32LE(4);
      if (cpu === 0x01000007) return "darwin-x64";
      if (cpu === 0x0100000c) return "darwin-arm64";
      return `darwin-macho-${cpu}`;
    }

    // Windows PE/COFF
    if (bytesRead >= 64 && header[0] === 0x4d && header[1] === 0x5a) {
      const peOffset = header.readUInt32LE(60);
      if (peOffset >= 0 && peOffset <= bytesRead - 6 && header.readUInt32LE(peOffset) === 0x00004550) {
        const machine = header.readUInt16LE(peOffset + 4);
        if (machine === 0x8664) return "win32-x64";
        if (machine === 0xaa64) return "win32-arm64";
        return `win32-pe-${machine}`;
      }
    }
  } catch {
    return null;
  }
  return null;
}

function embeddedPostgresPlatformPrefix(platform, arch) {
  const osPrefix = platform === "win32" ? "windows" : platform;
  return `${osPrefix}-${arch}`;
}

function isForeignPlatformPackage(scope, pkgName, targetPlatform, targetArch) {
  const targetKey = `${targetPlatform}-${targetArch}`;
  if (scope === "@esbuild") {
    return pkgName !== targetKey;
  }
  if (scope === "@cursor" && pkgName.startsWith("sdk-")) {
    const suffix = pkgName.slice("sdk-".length);
    return !suffix.startsWith(targetKey);
  }
  if (scope === "@img" && (pkgName.startsWith("sharp-") || pkgName.startsWith("sharp-libvips-"))) {
    // Keep wasm fallbacks if any, remove explicit foreign OS/arch native builds
    if (pkgName.includes("wasm")) return false;
    const knownOs = ["darwin-", "linux-", "linuxmusl-", "win32-"];
    const matchesKnownOs = knownOs.some((prefix) => pkgName.includes(prefix));
    if (!matchesKnownOs) return false;
    if (targetPlatform === "linux") {
      // On Linux (glibc or musl Alpine), keep both linux-<arch> and linuxmusl-<arch>
      return !(pkgName.endsWith(`linux-${targetArch}`) || pkgName.endsWith(`linuxmusl-${targetArch}`));
    }
    return !pkgName.endsWith(targetKey);
  }
  return false;
}

function classifyPackageForRemoval(scope, pkgName, opts) {
  // 1. Proprietary / unused third-party agent CLIs & SDKs
  if (scope === "@anthropic-ai") {
    if (pkgName.startsWith("claude-code") || pkgName.startsWith("claude-agent-sdk")) {
      return "agent_cli_bloat";
    }
    return null;
  }
  if (scope === "@github" && pkgName.startsWith("copilot")) {
    return "agent_cli_bloat";
  }
  if (scope === "@openai" && pkgName.startsWith("codex")) {
    return "agent_cli_bloat";
  }
  if (!scope && pkgName.startsWith("opencode-")) {
    return "agent_cli_bloat";
  }

  // 2. Embedded Postgres native binaries
  if (scope === "@embedded-postgres") {
    if (opts.pruneEmbeddedPostgres) {
      return "embedded_postgres";
    }
    const hostPkg = embeddedPostgresPlatformPrefix(opts.targetPlatform, opts.targetArch);
    if (pkgName !== hostPkg) {
      return "foreign_arch_binaries";
    }
    return null;
  }

  // 3. Foreign-OS/arch optional native packages
  if (scope && isForeignPlatformPackage(scope, pkgName, opts.targetPlatform, opts.targetArch)) {
    return "foreign_arch_binaries";
  }

  return null;
}

function collectNodeModulesDirs(rootNodeModules) {
  const found = [];
  if (!fs.existsSync(rootNodeModules)) return found;

  const stack = [rootNodeModules];
  while (stack.length > 0) {
    const nmDir = stack.pop();
    found.push(nmDir);

    let entries;
    try {
      entries = fs.readdirSync(nmDir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (!entry.isDirectory() || entry.isSymbolicLink() || entry.name === ".bin") {
        continue;
      }
      if (entry.name.startsWith("@")) {
        const scopeDir = path.join(nmDir, entry.name);
        let scopedEntries;
        try {
          scopedEntries = fs.readdirSync(scopeDir, { withFileTypes: true });
        } catch {
          continue;
        }
        for (const sub of scopedEntries) {
          if (!sub.isDirectory() || sub.isSymbolicLink()) continue;
          const nestedNm = path.join(scopeDir, sub.name, "node_modules");
          if (fs.existsSync(nestedNm)) {
            stack.push(nestedNm);
          }
        }
      } else {
        const nestedNm = path.join(nmDir, entry.name, "node_modules");
        if (fs.existsSync(nestedNm)) {
          stack.push(nestedNm);
        }
      }
    }
  }
  return found;
}

export function verifyRequiredPaperclipPackages(nodeModulesDir) {
  const requiredPaths = [
    path.join(nodeModulesDir, "@paperclipai", "server", "package.json"),
    path.join(nodeModulesDir, "@paperclipai", "server", "dist", "index.js"),
    path.join(nodeModulesDir, "@paperclipai", "server", "ui-dist", "index.html"),
    path.join(nodeModulesDir, "@paperclipai", "db", "package.json"),
    path.join(nodeModulesDir, "@paperclipai", "db", "dist", "client.js"),
    path.join(nodeModulesDir, "@paperclipai", "db", "dist", "migrations"),
    path.join(nodeModulesDir, "@paperclipai", "skills-catalog", "package.json"),
    path.join(nodeModulesDir, "@paperclipai", "hermes-paperclip-adapter", "package.json"),
    path.join(nodeModulesDir, "@paperclipai", "hermes-paperclip-adapter", "dist", "server", "execute.js"),
    path.join(nodeModulesDir, "@paperclipai", "hermes-paperclip-adapter", "dist", "server", "skills.js"),
    path.join(
      nodeModulesDir,
      "@paperclipai",
      "hermes-paperclip-adapter",
      "dist",
      "gateway",
      "server",
      "transport-security.js",
    ),
  ];

  const missing = requiredPaths.filter((candidate) => !fs.existsSync(candidate));
  if (missing.length > 0) {
    throw new Error(
      `Paperclip runtime integrity check failed; missing required path(s):\n  - ${missing.join("\n  - ")}`,
    );
  }
  return requiredPaths.length;
}

export async function prunePaperclipBloat(options = {}) {
  const nodeModulesDir = resolvePaperclipNodeModulesDir(options);
  const dryRun = Boolean(options.dryRun);
  const targetPlatform = options.targetPlatform || process.env.TARGET_PLATFORM || process.platform;
  const targetArch = options.targetArch || process.env.TARGET_ARCH || process.arch;
  const pruneEmbeddedPostgres =
    options.pruneEmbeddedPostgres !== undefined
      ? Boolean(options.pruneEmbeddedPostgres)
      : parseBoolEnv(process.env.PRUNE_EMBEDDED_POSTGRES, false);
  const pruneMapsAndTests =
    options.pruneMapsAndTests !== undefined
      ? Boolean(options.pruneMapsAndTests)
      : parseBoolEnv(process.env.PRUNE_MAPS_AND_TESTS, true);

  if (!fs.existsSync(nodeModulesDir)) {
    throw new Error(`Target node_modules directory does not exist: ${nodeModulesDir}`);
  }

  const before = measureTreeSync(nodeModulesDir);
  const categories = {
    agent_cli_bloat: { bytes: 0, files: 0, targets: [] },
    embedded_postgres: { bytes: 0, files: 0, targets: [] },
    foreign_runnerd: { bytes: 0, files: 0, targets: [] },
    foreign_arch_binaries: { bytes: 0, files: 0, targets: [] },
    tests_and_sourcemaps: { bytes: 0, files: 0, targets: [] },
  };

  const removalQueue = [];
  const queuedPaths = new Set();
  const queuedDirs = [];

  function isUnderQueuedDir(resolvedPath) {
    for (let i = 0; i < queuedDirs.length; i += 1) {
      const existingDir = queuedDirs[i];
      if (resolvedPath === existingDir || resolvedPath.startsWith(existingDir + path.sep)) {
        return true;
      }
    }
    return false;
  }

  function enqueueRemoval(fullPath, category, isKnownFile = false) {
    const resolved = path.resolve(fullPath);
    if (queuedPaths.has(resolved) || isUnderQueuedDir(resolved)) {
      return;
    }
    if (isKnownFile) {
      let sz = 0;
      try {
        sz = fs.statSync(resolved).size;
      } catch {
        return;
      }
      queuedPaths.add(resolved);
      categories[category].bytes += sz;
      categories[category].files += 1;
      if (categories[category].targets.length < 40) {
        categories[category].targets.push(path.relative(nodeModulesDir, resolved).replace(/\\/g, "/"));
      }
      removalQueue.push({ fullPath: resolved, category, bytes: sz, files: 1 });
      return;
    }

    let st;
    try {
      st = fs.lstatSync(resolved);
    } catch {
      return;
    }
    queuedPaths.add(resolved);
    if (st.isDirectory()) {
      queuedDirs.push(resolved);
    }
    const stats = measureTreeSync(resolved);
    categories[category].bytes += stats.bytes;
    categories[category].files += stats.files;
    if (categories[category].targets.length < 40) {
      categories[category].targets.push(path.relative(nodeModulesDir, resolved).replace(/\\/g, "/"));
    }
    removalQueue.push({ fullPath: resolved, category, ...stats });
  }

  // 1. Scan all node_modules directories (top-level + nested) for removable packages
  const allNmDirs = collectNodeModulesDirs(nodeModulesDir);
  for (const nmDir of allNmDirs) {
    let entries;
    try {
      entries = fs.readdirSync(nmDir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (!entry.isDirectory() || entry.isSymbolicLink() || entry.name === ".bin") {
        continue;
      }
      if (entry.name.startsWith("@")) {
        const scopeDir = path.join(nmDir, entry.name);
        let subEntries;
        try {
          subEntries = fs.readdirSync(scopeDir, { withFileTypes: true });
        } catch {
          continue;
        }
        for (const sub of subEntries) {
          if (!sub.isDirectory() || sub.isSymbolicLink()) continue;
          const cat = classifyPackageForRemoval(entry.name, sub.name, {
            pruneEmbeddedPostgres,
            targetPlatform,
            targetArch,
          });
          if (cat) {
            enqueueRemoval(path.join(scopeDir, sub.name), cat);
          }
        }
      } else {
        const cat = classifyPackageForRemoval(null, entry.name, {
          pruneEmbeddedPostgres,
          targetPlatform,
          targetArch,
        });
        if (cat) {
          enqueueRemoval(path.join(nmDir, entry.name), cat);
        }
      }
    }
  }

  // 2. Materialized proprietary GitHub Copilot assets inside @paperclipai/server
  const copilotAssetsDir = path.join(nodeModulesDir, "@paperclipai", "server", "provider-assets", "copilot");
  if (fs.existsSync(copilotAssetsDir)) {
    enqueueRemoval(copilotAssetsDir, "agent_cli_bloat");
  }

  // 3. Foreign-OS/arch paperclip-runnerd binaries
  const targetRunnerKey = `${targetPlatform}-${targetArch}`;
  const runnerExecName = targetPlatform === "win32" ? "paperclip-runnerd.exe" : "paperclip-runnerd";
  const runnerBinDirs = [
    path.join(nodeModulesDir, "@paperclipai", "server", "dist", "vendor", "paperclip-runner", "bin"),
    path.join(nodeModulesDir, "@paperclipai", "paperclip-runner", "dist", "bin"),
  ];

  for (const binRoot of runnerBinDirs) {
    if (!fs.existsSync(binRoot)) continue;
    let entries;
    try {
      entries = fs.readdirSync(binRoot, { withFileTypes: true });
    } catch {
      continue;
    }

    const matchingTargetBin = path.join(binRoot, targetRunnerKey, runnerExecName);
    const hasMatchingTargetSubdir = fs.existsSync(matchingTargetBin);

    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const fullPath = path.join(binRoot, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== targetRunnerKey) {
          enqueueRemoval(fullPath, "foreign_runnerd");
        }
      } else if (entry.isFile() && entry.name.startsWith("paperclip-runnerd")) {
        // Top-level bin/paperclip-runnerd: remove if redundant (target subdir already present)
        // or if its binary header is for a foreign OS/architecture.
        const detectedTarget = detectBinaryTarget(fullPath);
        if (hasMatchingTargetSubdir || (detectedTarget && detectedTarget !== targetRunnerKey)) {
          enqueueRemoval(fullPath, "foreign_runnerd");
        }
      }
    }
  }

  // 4. Compiled test files (*.test.js / __tests__) and source maps (*.map) outside protected UI/skill dirs
  const protectedDirNames = new Set(["ui-dist", "skills", "skills-catalog", "catalog", "migrations"]);
  if (pruneMapsAndTests) {
    const walkForArtifacts = (dir) => {
      const resolvedDir = path.resolve(dir);
      if (isUnderQueuedDir(resolvedDir)) {
        return;
      }
      let entries;
      try {
        entries = fs.readdirSync(resolvedDir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        if (entry.isSymbolicLink()) continue;
        const full = path.join(resolvedDir, entry.name);
        if (entry.isDirectory()) {
          if (protectedDirNames.has(entry.name)) continue;
          if (entry.name === "__tests__" || entry.name === "__fixtures__") {
            enqueueRemoval(full, "tests_and_sourcemaps", false);
          } else {
            walkForArtifacts(full);
          }
        } else if (entry.isFile()) {
          if (
            /\.(?:test|spec)\.(?:m?js|cjs|d\.ts)(?:\.map)?$/.test(entry.name) ||
            /\.(?:m?js|cjs|d\.ts|d\.mts|d\.cts)\.map$/.test(entry.name)
          ) {
            enqueueRemoval(full, "tests_and_sourcemaps", true);
          }
        }
      }
    };
    walkForArtifacts(nodeModulesDir);
  }

  // Execute removals (when not dryRun)
  if (!dryRun) {
    for (const item of removalQueue) {
      await fsp.rm(item.fullPath, { recursive: true, force: true });
    }

    // Clean up empty @scope directories and dangling CLI shims in .bin
    const prunedCliNames = new Set(["claude", "claude-code", "codex", "copilot", "opencode"]);
    for (const nmDir of allNmDirs) {
      if (!fs.existsSync(nmDir)) continue;
      for (const entry of fs.readdirSync(nmDir, { withFileTypes: true })) {
        if (entry.isDirectory() && entry.name.startsWith("@")) {
          const scopePath = path.join(nmDir, entry.name);
          const remaining = fs.readdirSync(scopePath);
          if (remaining.length === 0) {
            await fsp.rmdir(scopePath).catch(() => {});
          }
        }
      }

      const binDir = path.join(nmDir, ".bin");
      if (fs.existsSync(binDir)) {
        for (const binEntry of fs.readdirSync(binDir)) {
          const baseName = binEntry.replace(/\.(?:cmd|ps1|exe)$/i, "");
          const binFullPath = path.join(binDir, binEntry);
          if (prunedCliNames.has(baseName)) {
            await fsp.rm(binFullPath, { force: true }).catch(() => {});
            continue;
          }
          try {
            const st = fs.lstatSync(binFullPath);
            if (st.isSymbolicLink() && !fs.existsSync(binFullPath)) {
              await fsp.unlink(binFullPath).catch(() => {});
            }
          } catch {
            // Ignore
          }
        }
      }
    }
  }

  const verifiedCount = verifyRequiredPaperclipPackages(nodeModulesDir);
  const removedBytes = Object.values(categories).reduce((acc, c) => acc + c.bytes, 0);
  const removedFiles = Object.values(categories).reduce((acc, c) => acc + c.files, 0);
  const after = dryRun
    ? { bytes: Math.max(0, before.bytes - removedBytes), files: Math.max(0, before.files - removedFiles) }
    : measureTreeSync(nodeModulesDir);
  const actualSavedBytes = before.bytes - after.bytes;
  const reductionPct = before.bytes > 0 ? Number(((actualSavedBytes / before.bytes) * 100).toFixed(2)) : 0;

  return {
    dryRun,
    nodeModulesDir,
    target: `${targetPlatform}-${targetArch}`,
    pruneEmbeddedPostgres,
    pruneMapsAndTests,
    beforeBytes: before.bytes,
    beforeMiB: Number((before.bytes / 1048576).toFixed(2)),
    beforeGiB: Number((before.bytes / 1073741824).toFixed(2)),
    beforeFiles: before.files,
    removedBytes: actualSavedBytes,
    removedMiB: Number((actualSavedBytes / 1048576).toFixed(2)),
    removedFiles: before.files - after.files,
    afterBytes: after.bytes,
    afterMiB: Number((after.bytes / 1048576).toFixed(2)),
    afterGiB: Number((after.bytes / 1073741824).toFixed(2)),
    afterFiles: after.files,
    reductionPercent: reductionPct,
    verifiedRequiredPaths: verifiedCount,
    categories: Object.fromEntries(
      Object.entries(categories).map(([key, val]) => [
        key,
        {
          bytes: val.bytes,
          mib: Number((val.bytes / 1048576).toFixed(2)),
          files: val.files,
          sampleTargets: val.targets.slice(0, 12),
        },
      ]),
    ),
  };
}

function parseCliArgs(argv) {
  const opts = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--dry-run") {
      opts.dryRun = true;
    } else if (arg === "--prune-embedded-postgres") {
      opts.pruneEmbeddedPostgres = true;
    } else if (arg.startsWith("--prune-embedded-postgres=")) {
      opts.pruneEmbeddedPostgres = parseBoolEnv(arg.slice("--prune-embedded-postgres=".length), true);
    } else if (arg === "--keep-embedded-postgres") {
      opts.pruneEmbeddedPostgres = false;
    } else if (arg === "--keep-maps") {
      opts.pruneMapsAndTests = false;
    } else if (arg === "--node-modules" && argv[i + 1]) {
      opts.nodeModulesDir = argv[++i];
    } else if (arg.startsWith("--node-modules=")) {
      opts.nodeModulesDir = arg.slice("--node-modules=".length);
    } else if (arg === "--app-dir" && argv[i + 1]) {
      opts.appDir = argv[++i];
    } else if (arg.startsWith("--app-dir=")) {
      opts.appDir = arg.slice("--app-dir=".length);
    } else if (arg === "--target-platform" && argv[i + 1]) {
      opts.targetPlatform = argv[++i];
    } else if (arg.startsWith("--target-platform=")) {
      opts.targetPlatform = arg.slice("--target-platform=".length);
    } else if (arg === "--target-arch" && argv[i + 1]) {
      opts.targetArch = argv[++i];
    } else if (arg.startsWith("--target-arch=")) {
      opts.targetArch = arg.slice("--target-arch=".length);
    } else if (arg === "--json") {
      opts.json = true;
    }
  }
  return opts;
}

const isDirectRun =
  process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;

if (isDirectRun) {
  const cliOpts = parseCliArgs(process.argv.slice(2));
  prunePaperclipBloat(cliOpts)
    .then((summary) => {
      if (cliOpts.json) {
        process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
        return;
      }
      const modeLabel = summary.dryRun ? "DRY-RUN" : "APPLIED";
      process.stdout.write(
        `[paperclip-prune:${modeLabel}] target=${summary.target} pruneEmbeddedPostgres=${summary.pruneEmbeddedPostgres}\n` +
          `  Before:  ${summary.beforeMiB} MiB (${summary.beforeGiB} GiB, ${summary.beforeFiles} files)\n` +
          `  Removed: ${summary.removedMiB} MiB (${summary.removedFiles} files, -${summary.reductionPercent}%)\n` +
          `  After:   ${summary.afterMiB} MiB (${summary.afterGiB} GiB, ${summary.afterFiles} files)\n` +
          `  Verified intact core paths: ${summary.verifiedRequiredPaths}\n`,
      );
    })
    .catch((err) => {
      process.stderr.write(`[paperclip-prune] ERROR: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(1);
    });
}
