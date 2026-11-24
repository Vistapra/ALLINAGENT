"use strict";

/**
 * Cross-Platform Target Folder Registry, Directory Browser & Deep Safe File/Folder Inspector
 * for ALLINAGENT Office Bridge.
 *
 * Strictly preserves POSIX `/` paths and case sensitivity on Linux (zero `/` -> `\` corruption),
 * and enforces `ALLOWED_EVIDENCE_ROOTS` + `FORBIDDEN_ROOTS` trust boundaries.
 */

const fs = require("node:fs");
const path = require("node:path");
const {
  OFFICE_DATA_DIR,
  WORKSPACES_DIR,
  REPORTS_DIR,
  DOCS_DIR,
  resolveAuthorizedWorkspaces,
} = require("../contracts/paths");
const {
  sanitizeText,
  isPathForbidden,
  validateAuthorizedEvidencePath,
} = require("../contracts/redaction");
const { inspectProjectMetadataSummary } = require("./vulnclaw-findings-adapter");

const TARGET_FOLDERS_FILE = path.resolve(path.join(OFFICE_DATA_DIR, "target-folders.json"));

function toPosix(p) {
  return String(p || "").replace(/\\/g, "/");
}

function normalizePathKey(p) {
  const resolved = path.resolve(String(p || ""));
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

function isSensitiveFileName(fileName) {
  const base = String(fileName || "").trim();
  if (!base) return false;
  if (/^\.env$/i.test(base)) return true;
  if (/^\.env\./i.test(base) && !/^\.env\.example$/i.test(base)) return true;
  if (/^(auth\.json|office-bridge-auth\.json)$/i.test(base)) return true;
  if (/\.local\./i.test(base)) return true;
  if (/secret|private[_-]?key|id_rsa|id_ed25519|\.pem$|\.pfx$|\.key$/i.test(base)) return true;
  return false;
}

function isForbiddenDirectory(fullPath) {
  return isPathForbidden(fullPath, process.platform);
}

function listAvailableWorkspaceRoots() {
  const roots = resolveAuthorizedWorkspaces(process.env);
  const existing = roots.filter((r) => {
    try {
      return fs.existsSync(r);
    } catch {
      return false;
    }
  });
  const base = existing.length > 0 ? existing : [WORKSPACES_DIR, REPORTS_DIR, DOCS_DIR];
  return base.map(toPosix);
}

function loadTargetFoldersStore() {
  let raw = null;
  try {
    if (fs.existsSync(TARGET_FOLDERS_FILE)) {
      raw = JSON.parse(fs.readFileSync(TARGET_FOLDERS_FILE, "utf8").replace(/^\uFEFF/, ""));
    }
  } catch {
    raw = null;
  }

  const defaultSeeds = [WORKSPACES_DIR, REPORTS_DIR, DOCS_DIR, ...resolveAuthorizedWorkspaces(process.env)];
  const candidatePaths = Array.isArray(raw?.pinned_paths)
    ? raw.pinned_paths
    : defaultSeeds.filter((p) => fs.existsSync(p));

  const uniqueValid = [];
  const seen = new Set();
  for (const p of candidatePaths) {
    const check = validateAuthorizedEvidencePath(String(p || ""), { includeTargetFolders: false });
    if (!check.ok || !check.resolvedPath) continue;
    const key = normalizePathKey(check.resolvedPath);
    if (seen.has(key)) continue;
    seen.add(key);
    uniqueValid.push(check.resolvedPath);
  }

  let activeFolder = null;
  if (raw?.active_folder) {
    const actCheck = validateAuthorizedEvidencePath(String(raw.active_folder), { includeTargetFolders: false });
    if (actCheck.ok && actCheck.resolvedPath && fs.existsSync(actCheck.resolvedPath)) {
      activeFolder = actCheck.resolvedPath;
    }
  }

  return {
    active_folder: activeFolder ? toPosix(activeFolder) : null,
    pinned_paths: uniqueValid,
  };
}

function saveTargetFoldersStore(store) {
  fs.mkdirSync(path.dirname(TARGET_FOLDERS_FILE), { recursive: true, mode: 0o700 });
  const payload = {
    active_folder: store.active_folder || null,
    pinned_paths: store.pinned_paths || [],
    updated_at: new Date().toISOString(),
  };
  fs.writeFileSync(TARGET_FOLDERS_FILE, JSON.stringify(payload, null, 2) + "\n", "utf8");
}

function getTargetFoldersStatus() {
  const store = loadTargetFoldersStore();
  const pinnedFolders = store.pinned_paths.map((absPath) => {
    const exists = fs.existsSync(absPath);
    const meta = exists ? inspectProjectMetadataSummary(absPath) : null;
    return {
      path: toPosix(absPath),
      name: path.basename(absPath) || toPosix(absPath),
      exists,
      stack: meta?.stack || [],
    };
  });

  const roots = listAvailableWorkspaceRoots();
  return {
    ok: true,
    active_folder: store.active_folder,
    pinned_folders: pinnedFolders,
    drives: roots,
    quick_roots: roots,
  };
}

function mutateTargetFolders(body = {}) {
  const action = String(body.action || "add").toLowerCase();
  const rawPath = typeof body.path === "string" ? body.path.trim() : "";
  const store = loadTargetFoldersStore();

  if (action === "clear" || (action === "select" && !rawPath)) {
    store.active_folder = null;
    saveTargetFoldersStore(store);
    return getTargetFoldersStatus();
  }

  if (action === "remove") {
    if (rawPath) {
      const targetKey = normalizePathKey(rawPath);
      store.pinned_paths = store.pinned_paths.filter((p) => normalizePathKey(p) !== targetKey);
      if (store.active_folder && normalizePathKey(store.active_folder) === targetKey) {
        store.active_folder = null;
      }
      saveTargetFoldersStore(store);
    }
    return getTargetFoldersStatus();
  }

  const check = validateAuthorizedEvidencePath(rawPath);
  if (!check.ok || !check.resolvedPath) {
    const err = new Error(check.reason || "Folder tersebut berada di zona sistem terlarang.");
    err.status = 403;
    throw err;
  }
  if (!fs.existsSync(check.resolvedPath)) {
    const err = new Error(`Folder atau file tidak ditemukan: ${rawPath}`);
    err.status = 404;
    throw err;
  }

  const resolved = check.resolvedPath;
  const resolvedDir = fs.statSync(resolved).isDirectory() ? resolved : path.dirname(resolved);
  const resolvedKey = normalizePathKey(resolvedDir);
  const existsInPinned = store.pinned_paths.some((p) => normalizePathKey(p) === resolvedKey);
  if (!existsInPinned) {
    store.pinned_paths = [resolvedDir, ...store.pinned_paths].slice(0, 30);
  }
  store.active_folder = toPosix(resolved);
  saveTargetFoldersStore(store);
  return getTargetFoldersStatus();
}

/**
 * Normalize a browse query path without corrupting `/` into `\` on POSIX systems!
 */
function normalizeBrowseInputPath(rawQueryPath, platform = process.platform) {
  const trimmed = String(rawQueryPath || "").trim();
  if (!trimmed) return "";
  if (platform === "win32") {
    const winStr = trimmed.replace(/\//g, "\\");
    return /^[a-zA-Z]:$/.test(winStr) ? `${winStr}\\` : winStr;
  }
  // POSIX: NEVER replace `/` with `\`!
  return path.posix.normalize(trimmed);
}

function browseLocalDirectory(rawQueryPath) {
  const trimmed = String(rawQueryPath || "").trim();
  const roots = listAvailableWorkspaceRoots();
  if (!trimmed) {
    return {
      ok: true,
      current_path: "",
      parent_path: null,
      drives: roots,
      directories: roots.map((r) => ({
        name: path.basename(r) || r,
        path: r,
      })),
      files: [],
    };
  }

  const normalizedCandidate = normalizeBrowseInputPath(trimmed, process.platform);
  const check = validateAuthorizedEvidencePath(normalizedCandidate);
  if (!check.ok || !check.resolvedPath) {
    const err = new Error(check.reason || "Folder ini dibatasi oleh kebijakan keamanan sistem.");
    err.status = 403;
    throw err;
  }
  if (!fs.existsSync(check.resolvedPath)) {
    const err = new Error(`Direktori tidak ditemukan: ${trimmed}`);
    err.status = 404;
    throw err;
  }

  const stat = fs.statSync(check.resolvedPath);
  const dirPath = stat.isDirectory() ? check.resolvedPath : path.dirname(check.resolvedPath);
  const parentCandidate = path.dirname(dirPath);
  const parentCheck =
    parentCandidate && parentCandidate !== dirPath
      ? validateAuthorizedEvidencePath(parentCandidate)
      : { ok: false };
  const parentPath = parentCheck.ok && parentCheck.resolvedPath ? toPosix(parentCheck.resolvedPath) : "";

  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  const directories = [];
  const files = [];

  for (const entry of entries) {
    if (entry.name.startsWith("$")) continue;
    const full = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      if (isForbiddenDirectory(full)) continue;
      directories.push({
        name: entry.name,
        path: toPosix(full),
      });
    } else if (entry.isFile()) {
      if (isSensitiveFileName(entry.name)) continue;
      let sizeBytes = 0;
      try {
        sizeBytes = fs.statSync(full).size;
      } catch {}
      files.push({
        name: entry.name,
        path: toPosix(full),
        size_bytes: sizeBytes,
      });
    }
  }

  directories.sort((a, b) => a.name.localeCompare(b.name));
  files.sort((a, b) => a.name.localeCompare(b.name));

  return {
    ok: true,
    current_path: toPosix(dirPath),
    parent_path: parentPath,
    drives: roots,
    directories: directories.slice(0, 120),
    files: files.slice(0, 100),
  };
}

function inspectLocalTargetDeep(targetPath) {
  const check = validateAuthorizedEvidencePath(targetPath);
  if (!check.ok || !check.resolvedPath) {
    return {
      ok: false,
      blocked: true,
      reason: check.reason || "Path berada di zona terlarang sistem.",
    };
  }
  if (!fs.existsSync(check.resolvedPath)) {
    return {
      ok: false,
      notFound: true,
      reason: `Path tidak ditemukan: ${targetPath}`,
    };
  }

  const resolved = check.resolvedPath;
  const stat = fs.statSync(resolved);

  if (stat.isFile()) {
    if (isSensitiveFileName(path.basename(resolved))) {
      return {
        ok: false,
        blocked: true,
        reason: "Membaca file .env / kunci rahasia diblokir demi keamanan kredensial.",
      };
    }
    let excerpt = "";
    try {
      excerpt = sanitizeText(fs.readFileSync(resolved, "utf8").slice(0, 8000));
    } catch {
      excerpt = "[Binary atau file tidak dapat dibaca sebagai teks UTF-8]";
    }
    return {
      ok: true,
      kind: "file",
      resolved_path: toPosix(resolved),
      name: path.basename(resolved),
      size_bytes: stat.size,
      excerpt,
    };
  }

  const meta = inspectProjectMetadataSummary(resolved);
  const topEntries = fs.readdirSync(resolved, { withFileTypes: true });
  const directories = [];
  const files = [];
  let hiddenSecretCount = 0;

  for (const e of topEntries) {
    if (e.name === ".git") continue;
    if (e.isDirectory()) {
      if (isForbiddenDirectory(path.join(resolved, e.name))) continue;
      directories.push(e.name);
    } else if (e.isFile()) {
      if (isSensitiveFileName(e.name)) {
        hiddenSecretCount += 1;
        continue;
      }
      let sz = 0;
      try {
        sz = fs.statSync(path.join(resolved, e.name)).size;
      } catch {}
      files.push({ name: e.name, size: sz });
    }
  }

  const extCounts = {};
  const sampledSourceFiles = [];
  const skipHeavy = new Set([
    "node_modules",
    "vendor",
    ".git",
    ".next",
    "dist",
    "build",
    "storage",
    "__pycache__",
    ".venv",
    "venv",
  ]);

  function walkShallow(dir, depth) {
    if (depth > 2) return;
    let list = [];
    try {
      list = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const item of list) {
      if (skipHeavy.has(item.name) || item.name.startsWith("$")) continue;
      const full = path.join(dir, item.name);
      if (item.isDirectory()) {
        if (!isForbiddenDirectory(full)) walkShallow(full, depth + 1);
      } else if (item.isFile() && !isSensitiveFileName(item.name)) {
        const ext = (path.extname(item.name) || "no_ext").toLowerCase();
        extCounts[ext] = (extCounts[ext] || 0) + 1;
        if (sampledSourceFiles.length < 30) {
          sampledSourceFiles.push(toPosix(path.relative(resolved, full)));
        }
      }
    }
  }
  walkShallow(resolved, 0);

  const keyFileCandidates = [
    "README.md",
    "composer.json",
    "package.json",
    "modules_statuses.json",
    "pyproject.toml",
    "requirements.txt",
    "Cargo.toml",
    "go.mod",
    "routes/api.php",
    "routes/web.php",
  ];
  const keyExcerpts = [];
  for (const rel of keyFileCandidates) {
    const fp = path.join(resolved, rel);
    if (fs.existsSync(fp) && fs.statSync(fp).isFile() && !isSensitiveFileName(path.basename(fp))) {
      try {
        const content = sanitizeText(fs.readFileSync(fp, "utf8").slice(0, 1400)).trim();
        if (content) {
          keyExcerpts.push({ file: rel, excerpt: content });
        }
      } catch {}
    }
    if (keyExcerpts.length >= 4) break;
  }

  const topExtSummary = Object.entries(extCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([ext, cnt]) => `${ext}: ${cnt}`)
    .join(", ");

  return {
    ok: true,
    kind: "directory",
    resolved_path: toPosix(resolved),
    folder_name: path.basename(resolved) || toPosix(resolved),
    stack: meta?.stack || ["Local Directory"],
    modules: meta?.modules || [],
    has_test_suite: Boolean(meta?.has_test_suite),
    directories: directories.slice(0, 40),
    files: files.slice(0, 40),
    hidden_secret_files_protected: hiddenSecretCount,
    extension_summary: topExtSummary,
    sampled_paths: sampledSourceFiles,
    key_excerpts: keyExcerpts,
  };
}

module.exports = {
  isSensitiveFileName,
  normalizeBrowseInputPath,
  loadTargetFoldersStore,
  getTargetFoldersStatus,
  mutateTargetFolders,
  browseLocalDirectory,
  inspectLocalTargetDeep,
};
