"use strict";

/**
 * PHASE 09, PHASE 10 & PHASE 11 — Cross-Platform Safe Workspace Explorer
 * (Reparse/Symlink/ACL Guarded, POSIX Case-Sensitive), Real Source Code Analyzer,
 * and End-to-End Software Development Controller.
 *
 * Zero hardcoded Windows drive letters, local stack paths, or personal directories.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const {
  REPORTS_DIR,
  GIT_EXE,
  PYTHON_EXE,
  NPM_EXE,
  resolveAuthorizedWorkspaces,
} = require("../contracts/paths");
const {
  sanitizeText,
  isPathForbidden,
  validateAuthorizedEvidencePath,
} = require("../contracts/redaction");
const {
  isSensitiveFileName,
  normalizeBrowseInputPath,
  loadTargetFoldersStore,
  inspectLocalTargetDeep,
} = require("../adapters/target-folders-manager");

const execFileAsync = promisify(execFile);
const NODE_EXE = process.execPath;
const MAX_READ_BYTES = 256 * 1024; // 256 KB per file safety limit

function isInsideForbiddenZone(candidatePath) {
  return isPathForbidden(candidatePath, process.platform);
}

/**
 * PHASE 09 Mandatory Path Security Validator:
 *  - Cross-platform canonical resolution without corrupting `/` into `\` on POSIX
 *  - Symlink / Junction / Reparse-point realpath check (`fs.lstatSync` + `fs.realpathSync.native`)
 *  - Read/Write permission verification (`fs.accessSync`)
 *  - Sensitive credential file blocking (`.env`, `auth.json`, private keys, secrets)
 *  - Protected OS & credential directory blocking + `ALLOWED_EVIDENCE_ROOTS` enforcement
 */
function validateSecureFolderOrFile(rawInputPath, { allowFile = true, requireWrite = false } = {}) {
  const raw = String(rawInputPath || "").trim().replace(/^["']|["']$/g, "");
  if (!raw) {
    return { ok: false, status: 400, code: "EMPTY_PATH", error: "Path folder/file tidak boleh kosong." };
  }
  if (raw.includes("\0")) {
    return { ok: false, status: 400, code: "NULL_BYTE_PATH", error: "Path mengandung karakter tidak valid." };
  }

  const normalizedInput = normalizeBrowseInputPath(raw, process.platform);
  const resolvedNominal = path.resolve(normalizedInput);

  if (isInsideForbiddenZone(resolvedNominal)) {
    return {
      ok: false,
      status: 403,
      code: "PROTECTED_SYSTEM_ZONE",
      error: `Akses ditolak: '${sanitizeText(resolvedNominal)}' berada di zona sistem/kredensial terproteksi.`,
    };
  }

  const baseName = path.basename(resolvedNominal);
  if (isSensitiveFileName(baseName) || /^(auth\.json|.*credentials.*\.json|.*board-key.*\.json)$/i.test(baseName)) {
    return {
      ok: false,
      status: 403,
      code: "SENSITIVE_FILE_BLOCKED",
      error: `Akses ditolak: Berkas sensitif '${sanitizeText(baseName)}' dilindungi dari pembacaan/pengiriman.`,
    };
  }

  const baseCheck = validateAuthorizedEvidencePath(resolvedNominal);
  if (!baseCheck.ok) {
    return {
      ok: false,
      status: 403,
      code: "UNAUTHORIZED_PATH",
      error: sanitizeText(baseCheck.reason || baseCheck.error || "Path tidak berada di dalam workspace terotorisasi."),
    };
  }

  if (!fs.existsSync(resolvedNominal)) {
    return {
      ok: false,
      status: 404,
      code: "PATH_NOT_FOUND",
      error: `Path tidak ditemukan: ${sanitizeText(raw)}`,
    };
  }

  let lstat;
  let realResolved;
  try {
    lstat = fs.lstatSync(resolvedNominal);
    realResolved = fs.realpathSync.native ? fs.realpathSync.native(resolvedNominal) : fs.realpathSync(resolvedNominal);
  } catch (err) {
    return {
      ok: false,
      status: 403,
      code: "REPARSE_OR_ACL_DENIED",
      error: `Gagal memverifikasi realpath/izin pada '${sanitizeText(raw)}': ${sanitizeText(err.message)}`,
    };
  }

  if (isInsideForbiddenZone(realResolved)) {
    return {
      ok: false,
      status: 403,
      code: "SYMLINK_ESCAPE_BLOCKED",
      error: "Akses ditolak: Symlink/junction mengarah ke zona sistem atau kredensial terlarang!",
    };
  }

  const realBaseName = path.basename(realResolved);
  if (isSensitiveFileName(realBaseName) || /^(auth\.json|.*credentials.*\.json)$/i.test(realBaseName)) {
    return {
      ok: false,
      status: 403,
      code: "SYMLINK_TO_SECRET_BLOCKED",
      error: "Akses ditolak: Symlink mengarah ke berkas kredensial rahasia!",
    };
  }

  try {
    const mode = requireWrite ? fs.constants.R_OK | fs.constants.W_OK : fs.constants.R_OK;
    fs.accessSync(realResolved, mode);
  } catch {
    return {
      ok: false,
      status: 403,
      code: "ACL_PERMISSION_DENIED",
      error: `Izin sistem berkas menolak akses ${requireWrite ? "baca/tulis" : "baca"} pada path tersebut.`,
    };
  }

  const stat = fs.statSync(realResolved);
  if (!allowFile && !stat.isDirectory()) {
    return {
      ok: false,
      status: 400,
      code: "NOT_A_DIRECTORY",
      error: "Path yang dipilih adalah berkas, bukan direktori.",
    };
  }

  const symlinkDiffers =
    process.platform === "win32"
      ? realResolved.toLowerCase() !== resolvedNominal.toLowerCase()
      : realResolved !== resolvedNominal;

  return {
    ok: true,
    nominal_path: resolvedNominal.replace(/\\/g, "/"),
    resolved_path: realResolved.replace(/\\/g, "/"),
    fs_path: realResolved,
    win_path: realResolved, // retained alias for backward caller compatibility
    is_directory: stat.isDirectory(),
    is_symlink_or_reparse: lstat.isSymbolicLink() || symlinkDiffers,
    size_bytes: stat.size,
    mtime_iso: stat.mtime.toISOString(),
  };
}

/**
 * Paginated & stack-annotated directory explorer (`PHASE 09`).
 */
function exploreDirectoryPaginated(rawPath, { page = 1, perPage = 10 } = {}) {
  const trimmed = String(rawPath || "").trim();
  if (!trimmed || trimmed === "drives" || trimmed === "roots") {
    const roots = resolveAuthorizedWorkspaces(process.env)
      .filter((r) => fs.existsSync(r))
      .map((r) => r.replace(/\\/g, "/"));
    return {
      ok: true,
      current_path: "",
      parent_path: null,
      page: 1,
      total_pages: 1,
      total_directories: roots.length,
      total_files: 0,
      directories: roots.map((d) => ({ name: path.basename(d) || d, path: d, markers: ["workspace-root"] })),
      files: [],
    };
  }

  const check = validateSecureFolderOrFile(trimmed, { allowFile: true });
  if (!check.ok) return check;

  const targetDir = check.is_directory ? check.fs_path : path.dirname(check.fs_path);
  const parentCandidate = path.dirname(targetDir);
  const parentAllowed =
    parentCandidate &&
    parentCandidate !== targetDir &&
    !isInsideForbiddenZone(parentCandidate) &&
    validateAuthorizedEvidencePath(parentCandidate).ok;
  const parentPath = parentAllowed ? parentCandidate.replace(/\\/g, "/") : "drives";

  let dirents = [];
  try {
    dirents = fs.readdirSync(targetDir, { withFileTypes: true });
  } catch (err) {
    return { ok: false, status: 403, code: "READDIR_DENIED", error: sanitizeText(err.message) };
  }

  const allDirs = [];
  const allFiles = [];
  for (const ent of dirents) {
    if (ent.name.startsWith("$")) continue;
    const full = path.join(targetDir, ent.name);
    if (isInsideForbiddenZone(full)) continue;
    try {
      if (ent.isSymbolicLink()) {
        const real = fs.realpathSync(full);
        if (
          isInsideForbiddenZone(real) ||
          isSensitiveFileName(path.basename(real)) ||
          !validateAuthorizedEvidencePath(real).ok
        ) {
          continue;
        }
      }
    } catch {
      continue;
    }

    if (ent.isDirectory()) {
      const markers = [];
      for (const [f, tag] of [
        ["composer.json", "Laravel/PHP"],
        ["package.json", "Node/JS"],
        ["pyproject.toml", "Python"],
        ["requirements.txt", "Python"],
        ["Cargo.toml", "Rust"],
        ["go.mod", "Go"],
        [".git", "Git"],
      ]) {
        if (fs.existsSync(path.join(full, f))) markers.push(tag);
      }
      allDirs.push({
        name: ent.name,
        path: full.replace(/\\/g, "/"),
        markers: [...new Set(markers)],
      });
    } else if (ent.isFile()) {
      if (isSensitiveFileName(ent.name) || /^(auth\.json|.*credentials.*\.json)$/i.test(ent.name)) continue;
      let sz = 0;
      try {
        sz = fs.statSync(full).size;
      } catch {}
      allFiles.push({
        name: ent.name,
        path: full.replace(/\\/g, "/"),
        size_bytes: sz,
      });
    }
  }

  allDirs.sort((a, b) => a.name.localeCompare(b.name));
  allFiles.sort((a, b) => a.name.localeCompare(b.name));

  const totalPages = Math.max(1, Math.ceil(allDirs.length / perPage));
  const safePage = Math.max(1, Math.min(totalPages, Number(page) || 1));
  const start = (safePage - 1) * perPage;

  return {
    ok: true,
    current_path: targetDir.replace(/\\/g, "/"),
    parent_path: parentPath,
    page: safePage,
    total_pages: totalPages,
    total_directories: allDirs.length,
    total_files: allFiles.length,
    directories: allDirs.slice(start, start + perPage),
    files: allFiles.slice(0, 12),
  };
}

/**
 * Bounded safe directory search (`PHASE 09`, max depth = 2) within `AUTHORIZED_WORKSPACES`.
 */
function searchDirectoriesSafe(query, baseRoot = "") {
  const q = String(query || "").trim().toLowerCase();
  if (!q) return { ok: false, status: 400, error: "Kata kunci pencarian folder wajib diisi." };

  const roots = baseRoot
    ? [baseRoot]
    : resolveAuthorizedWorkspaces(process.env).filter((p) => fs.existsSync(p));

  const matches = [];
  function walk(dir, depth) {
    if (depth > 2 || matches.length >= 20) return;
    if (isInsideForbiddenZone(dir)) return;
    let ents = [];
    try {
      ents = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of ents) {
      if (matches.length >= 20) break;
      if (
        !e.isDirectory() ||
        e.name.startsWith(".") ||
        e.name.startsWith("$") ||
        e.name === "node_modules" ||
        e.name === "vendor"
      ) {
        continue;
      }
      const full = path.join(dir, e.name);
      if (isInsideForbiddenZone(full)) continue;
      if (e.name.toLowerCase().includes(q)) {
        matches.push(full.replace(/\\/g, "/"));
      }
      if (depth < 2) walk(full, depth + 1);
    }
  }

  for (const r of roots) {
    const v = validateSecureFolderOrFile(r, { allowFile: false });
    if (v.ok) walk(v.fs_path, 0);
  }
  return { ok: true, query, count: matches.length, matches };
}

function readSafeSourceSnippet(filePath, maxBytes = MAX_READ_BYTES) {
  const check = validateSecureFolderOrFile(filePath, { allowFile: true });
  if (!check.ok || check.is_directory) return null;
  if (check.size_bytes > maxBytes) {
    const fd = fs.openSync(check.fs_path, "r");
    try {
      const buf = Buffer.alloc(maxBytes);
      const read = fs.readSync(fd, buf, 0, maxBytes, 0);
      const content = sanitizeText(buf.slice(0, read).toString("utf8"));
      return {
        path: check.resolved_path,
        size_bytes: check.size_bytes,
        truncated: true,
        sha256_prefix: crypto.createHash("sha256").update(buf.slice(0, read)).digest("hex").slice(0, 16),
        line_count: content.split(/\r?\n/).length,
        content,
      };
    } finally {
      fs.closeSync(fd);
    }
  }
  const rawBuf = fs.readFileSync(check.fs_path);
  const content = sanitizeText(rawBuf.toString("utf8"));
  return {
    path: check.resolved_path,
    size_bytes: check.size_bytes,
    truncated: false,
    sha256_prefix: crypto.createHash("sha256").update(rawBuf).digest("hex").slice(0, 16),
    line_count: content.split(/\r?\n/).length,
    content,
  };
}

/**
 * PHASE 10 — Real Source Code Analysis & Persistent Evidence Report Generator.
 */
function performRealSourceCodeAnalysis(rawTargetPath, { agentName = "Backend Developer", customFocus = "" } = {}) {
  const v = validateSecureFolderOrFile(rawTargetPath, { allowFile: true });
  if (!v.ok) return v;

  const projectDir = v.is_directory ? v.fs_path : path.dirname(v.fs_path);
  const deep = inspectLocalTargetDeep(projectDir);
  const projectName = path.basename(projectDir) || projectDir;

  const examinedFiles = [];
  const dependencies = { runtime: [], dev: [] };
  const entryPoints = [];
  const buildAndTestCommands = [];
  const findingsAndRisks = [];
  const recommendations = [];
  let appModules = [];

  const composerFile = path.join(projectDir, "composer.json");
  if (fs.existsSync(composerFile)) {
    const sn = readSafeSourceSnippet(composerFile);
    if (sn) {
      examinedFiles.push({ file: "composer.json", lines: sn.line_count, sha256: sn.sha256_prefix, bytes: sn.size_bytes });
      try {
        const cj = JSON.parse(fs.readFileSync(composerFile, "utf8"));
        dependencies.runtime.push(...Object.entries(cj.require || {}).map(([k, ver]) => `${k}:${ver}`));
        dependencies.dev.push(...Object.entries(cj["require-dev"] || {}).map(([k, ver]) => `${k}:${ver}`));
        if (cj.scripts) {
          for (const [sk, sv] of Object.entries(cj.scripts)) {
            if (/test|lint|stan|pint|analyse/i.test(sk)) {
              buildAndTestCommands.push(`composer ${sk} (${Array.isArray(sv) ? sv.join(" && ") : sv})`);
            }
          }
        }
      } catch {}
    }
  }

  const modStatusFile = path.join(projectDir, "modules_statuses.json");
  if (fs.existsSync(modStatusFile)) {
    const sn = readSafeSourceSnippet(modStatusFile);
    if (sn) {
      examinedFiles.push({ file: "modules_statuses.json", lines: sn.line_count, sha256: sn.sha256_prefix, bytes: sn.size_bytes });
      try {
        const mj = JSON.parse(fs.readFileSync(modStatusFile, "utf8"));
        appModules = Object.entries(mj).map(([m, active]) => `${m} (${active ? "enabled" : "disabled"})`);
      } catch {}
    }
  }

  const pkgFile = path.join(projectDir, "package.json");
  if (fs.existsSync(pkgFile)) {
    const sn = readSafeSourceSnippet(pkgFile);
    if (sn) {
      examinedFiles.push({ file: "package.json", lines: sn.line_count, sha256: sn.sha256_prefix, bytes: sn.size_bytes });
      try {
        const pj = JSON.parse(fs.readFileSync(pkgFile, "utf8"));
        dependencies.runtime.push(...Object.entries(pj.dependencies || {}).map(([k, ver]) => `${k}:${ver}`));
        dependencies.dev.push(...Object.entries(pj.devDependencies || {}).map(([k, ver]) => `${k}:${ver}`));
        for (const [sk, sv] of Object.entries(pj.scripts || {})) {
          buildAndTestCommands.push(`npm run ${sk} -> ${sv}`);
        }
      } catch {}
    }
  }

  for (const pyf of ["pyproject.toml", "requirements.txt"]) {
    const fp = path.join(projectDir, pyf);
    if (fs.existsSync(fp)) {
      const sn = readSafeSourceSnippet(fp);
      if (sn) {
        examinedFiles.push({ file: pyf, lines: sn.line_count, sha256: sn.sha256_prefix, bytes: sn.size_bytes });
      }
    }
  }

  const candidateEntries = [
    "artisan",
    "public/index.php",
    "bootstrap/app.php",
    "routes/api.php",
    "routes/web.php",
    "phpunit.xml",
    "server.js",
    "index.js",
    "src/index.js",
    "src/index.ts",
    "src/app/page.tsx",
    "README.md",
  ];
  const routeHighlights = [];
  for (const rel of candidateEntries) {
    const fp = path.join(projectDir, rel);
    if (fs.existsSync(fp) && fs.statSync(fp).isFile()) {
      entryPoints.push(rel);
      const sn = readSafeSourceSnippet(fp, 64 * 1024);
      if (sn) {
        examinedFiles.push({ file: rel, lines: sn.line_count, sha256: sn.sha256_prefix, bytes: sn.size_bytes });
        if (rel.startsWith("routes/")) {
          const routeLines = sn.content
            .split(/\r?\n/)
            .filter((l) => /Route::(get|post|put|patch|delete|prefix|middleware|group|apiResource|resource)/i.test(l))
            .slice(0, 10)
            .map((l) => l.trim().slice(0, 110));
          routeHighlights.push(...routeLines);
        }
      }
    }
  }

  const modulesDir = path.join(projectDir, "Modules");
  if (fs.existsSync(modulesDir) && fs.statSync(modulesDir).isDirectory()) {
    try {
      const modDirs = fs.readdirSync(modulesDir, { withFileTypes: true }).filter((d) => d.isDirectory()).slice(0, 5);
      for (const md of modDirs) {
        for (const subRel of [`Modules/${md.name}/Routes/api.php`, `Modules/${md.name}/routes/api.php`]) {
          const mfp = path.join(projectDir, subRel);
          if (fs.existsSync(mfp)) {
            entryPoints.push(subRel);
            const sn = readSafeSourceSnippet(mfp, 32 * 1024);
            if (sn) {
              examinedFiles.push({ file: subRel, lines: sn.line_count, sha256: sn.sha256_prefix, bytes: sn.size_bytes });
            }
            break;
          }
        }
      }
    } catch {}
  }

  if (buildAndTestCommands.length === 0) {
    if (fs.existsSync(path.join(projectDir, "phpunit.xml")) || fs.existsSync(path.join(projectDir, "vendor", "bin", "phpunit"))) {
      buildAndTestCommands.push("php artisan test / vendor/bin/phpunit");
    }
    if (fs.existsSync(path.join(projectDir, "pytest.ini")) || fs.existsSync(path.join(projectDir, "tests"))) {
      buildAndTestCommands.push("pytest / node --test");
    }
  }

  const hasEnvExample = fs.existsSync(path.join(projectDir, ".env.example"));
  const hasEnvReal = fs.existsSync(path.join(projectDir, ".env")); // existence check ONLY — NEVER read!
  const hasTestsDir = fs.existsSync(path.join(projectDir, "tests")) || fs.existsSync(path.join(projectDir, "__tests__"));
  const hasGitignore = fs.existsSync(path.join(projectDir, ".gitignore"));

  if (!hasTestsDir) {
    findingsAndRisks.push("Direktori `tests/` tingkat root belum terdeteksi; cakupan pengujian regresi perlu diperkuat.");
  }
  if (!hasGitignore) {
    findingsAndRisks.push("Berkas `.gitignore` belum ditemukan di root proyek; risiko berkas lokal ikut ter-commit.");
  } else {
    const gi = readSafeSourceSnippet(path.join(projectDir, ".gitignore"), 16 * 1024);
    if (gi && !gi.content.includes(".env")) {
      findingsAndRisks.push("`.gitignore` belum mencantumkan `.env` secara eksplisit.");
    }
  }
  if (dependencies.runtime.length > 25) {
    findingsAndRisks.push(`Jumlah dependensi runtime cukup besar (${dependencies.runtime.length} paket); disarankan audit berkala \`composer audit\` / \`npm audit\`.`);
  }
  if (findingsAndRisks.length === 0) {
    findingsAndRisks.push("Struktur konfigurasi dasar (`.gitignore`, pemisahan modul, dan direktori pengujian) terdeteksi rapi.");
  }

  recommendations.push(
    "Jalankan pengujian terisolasi pada branch fitur khusus sebelum menggabungkan perubahan ke `main`.",
    "Pastikan validasi request/input dan middleware otorisasi diterapkan konsisten pada seluruh endpoint publik.",
    hasEnvExample
      ? "Pertahankan sinkronisasi kunci konfigurasi baru pada `.env.example` tanpa menyalin nilai rahasia `.env`."
      : "Tambahkan `.env.example` untuk mendokumentasikan variabel lingkungan tanpa nilai rahasia."
  );

  fs.mkdirSync(REPORTS_DIR, { recursive: true, mode: 0o755 });
  const slug = projectName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "project";
  const reportFileName = `telegram-code-analysis-${slug}-${Date.now()}.md`;
  const reportFullPath = path.join(REPORTS_DIR, reportFileName);

  const stackList = Array.isArray(deep?.stack) && deep.stack.length > 0 ? deep.stack : ["Detected Source Tree"];
  const topDirs = (deep?.directories || []).slice(0, 20);

  const reportMarkdown = [
    `# Laporan Analisis Source Code Terverifikasi — \`${projectName}\``,
    ``,
    `- **Waktu Analisis:** \`${new Date().toISOString()}\``,
    `- **Agen Pelaksana:** \`${sanitizeText(agentName)}\``,
    `- **Path Terverifikasi:** \`${projectDir.replace(/\\/g, "/")}\``,
    `- **Proteksi Berkas Sensitif:** \`.env\` ${hasEnvReal ? "terdeteksi ada di disk & **TIDAK DIBACA** (dilindungi otomatis)" : "tidak ditemukan"}`,
    customFocus ? `- **Fokus Khusus Owner:** ${sanitizeText(customFocus)}` : null,
    ``,
    `## 1. Technology Stack & Struktur Aplikasi`,
    `- **Stack Terdeteksi:** ${stackList.join(", ")}`,
    `- **Subdirektori Utama (${topDirs.length}):** ${topDirs.map((d) => `\`${d}\``).join(", ") || "(root)"}`,
    appModules.length > 0 ? `- **Modul Aplikasi (${appModules.length}):** ${appModules.slice(0, 18).join(", ")}` : null,
    `- **Entry Points Terverifikasi:** ${entryPoints.map((e) => `\`${e}\``).join(", ") || "(standar direktori)"}`,
    ``,
    `## 2. Ikhtisar Dependensi (${dependencies.runtime.length} Runtime, ${dependencies.dev.length} Dev)`,
    `- **Runtime Utama:** ${dependencies.runtime.slice(0, 16).map((d) => `\`${d}\``).join(", ") || "(tidak menggunakan manifest standar)"}`,
    `- **Dev / Testing:** ${dependencies.dev.slice(0, 10).map((d) => `\`${d}\``).join(", ") || "-"}`,
    ``,
    routeHighlights.length > 0 ? `## 3. Cuplikan Definisi Route Nyata\n` + routeHighlights.map((r) => `- \`${r}\``).join("\n") + `\n` : null,
    `## 4. Perintah Build & Testing Terdeteksi`,
    ...(buildAndTestCommands.length > 0 ? buildAndTestCommands.map((c) => `- \`${c}\``) : ["- `(Gunakan runner sesuai stack proyek)`"]),
    ``,
    `## 5. Temuan Potensial & Rekomendasi Teknis`,
    `### Potensi Masalah / Perhatian`,
    ...findingsAndRisks.map((f) => `- ${f}`),
    `### Rekomendasi Peningkatan`,
    ...recommendations.map((r) => `- ${r}`),
    ``,
    `## 6. Bukti Berkas yang Diperiksa (${examinedFiles.length} Berkas)`,
    `| Berkas | Jumlah Baris | Ukuran (Bytes) | SHA-256 Prefix |`,
    `|---|---:|---:|---|`,
    ...examinedFiles.map((e) => `| \`${e.file}\` | ${e.lines} | ${e.bytes} | \`${e.sha256}\` |`),
  ]
    .filter(Boolean)
    .join("\n");

  fs.writeFileSync(reportFullPath, reportMarkdown + "\n", "utf8");

  return {
    ok: true,
    project_name: projectName,
    verified_path: projectDir.replace(/\\/g, "/"),
    stack: stackList,
    top_directories: topDirs,
    modules: appModules,
    entry_points: entryPoints,
    runtime_dependencies_count: dependencies.runtime.length,
    dev_dependencies_count: dependencies.dev.length,
    sample_dependencies: dependencies.runtime.slice(0, 10),
    build_test_commands: buildAndTestCommands,
    potential_issues: findingsAndRisks,
    recommendations,
    examined_files: examinedFiles,
    env_protected: true,
    report_path: reportFullPath.replace(/\\/g, "/"),
  };
}

/**
 * PHASE 11 — Cross-Platform Safe Software Development Operations from Telegram
 * (`git`, `node`, `npm`, `python3`, `php` resolved portably).
 */
async function executeSafeDevOperation({ action, targetPath, args = "" }) {
  const folderStore = loadTargetFoldersStore();
  const effectivePath = targetPath || folderStore.active_folder || "";
  const v = validateSecureFolderOrFile(effectivePath, { allowFile: false });
  if (!v.ok) return v;
  const cwd = v.fs_path;

  const op = String(action || "git_status").toLowerCase();

  if (op === "git_status") {
    if (!fs.existsSync(path.join(cwd, ".git"))) {
      return { ok: true, is_git: false, path: v.resolved_path, summary: "Direktori ini bukan repositori Git." };
    }
    const { stdout: branchOut } = await execFileAsync(GIT_EXE, ["-C", cwd, "rev-parse", "--abbrev-ref", "HEAD"], { timeout: 10_000 });
    const { stdout: commitOut } = await execFileAsync(GIT_EXE, ["-C", cwd, "log", "-3", "--oneline"], { timeout: 10_000 });
    const { stdout: statusOut } = await execFileAsync(GIT_EXE, ["-C", cwd, "status", "--short"], { timeout: 10_000 });
    return {
      ok: true,
      is_git: true,
      path: v.resolved_path,
      branch: branchOut.trim(),
      recent_commits: sanitizeText(commitOut.trim()).split(/\r?\n/).filter(Boolean),
      changed_files: sanitizeText(statusOut.trim()).split(/\r?\n/).filter(Boolean),
      exit_code: 0,
    };
  }

  if (op === "git_diff" || op === "cek_diff") {
    if (!fs.existsSync(path.join(cwd, ".git"))) {
      return { ok: false, status: 400, error: "Direktori aktif bukan repositori Git." };
    }
    const { stdout: statOut } = await execFileAsync(GIT_EXE, ["-C", cwd, "diff", "--stat"], { timeout: 10_000 });
    const { stdout: diffOut } = await execFileAsync(
      GIT_EXE,
      ["-C", cwd, "diff", "--", ".", ":!.env", ":!*.env.*", ":!*secret*"],
      { timeout: 10_000, maxBuffer: 2 * 1024 * 1024 }
    );
    return {
      ok: true,
      path: v.resolved_path,
      diff_stat: sanitizeText(statOut.trim()) || "(Tidak ada perubahan unstaged)",
      diff_preview: sanitizeText(diffOut.trim()).slice(0, 1800) || "(Working tree bersih)",
      exit_code: 0,
    };
  }

  if (op === "buat_branch" || op === "create_branch") {
    if (!fs.existsSync(path.join(cwd, ".git"))) {
      return { ok: false, status: 400, error: "Direktori aktif bukan repositori Git." };
    }
    const rawBranch = String(args || "").trim().replace(/[^a-zA-Z0-9._/-]/g, "-");
    if (!rawBranch || /^(main|master|production|prod)$/i.test(rawBranch)) {
      return {
        ok: false,
        status: 400,
        error: "Nama branch kerja harus spesifik (mis. `feat/audit-helper`) dan tidak boleh branch produksi (`main`/`master`).",
      };
    }
    let cmdUsed = "";
    try {
      await execFileAsync(GIT_EXE, ["-C", cwd, "rev-parse", "--verify", rawBranch], { timeout: 8000 });
      await execFileAsync(GIT_EXE, ["-C", cwd, "checkout", rawBranch], { timeout: 10_000 });
      cmdUsed = `git checkout ${rawBranch}`;
    } catch {
      await execFileAsync(GIT_EXE, ["-C", cwd, "checkout", "-b", rawBranch], { timeout: 10_000 });
      cmdUsed = `git checkout -b ${rawBranch}`;
    }
    return {
      ok: true,
      path: v.resolved_path,
      branch: rawBranch,
      command_executed: cmdUsed,
      exit_code: 0,
    };
  }

  if (op === "build" || op === "build_project" || op === "test" || op === "jalankan_test") {
    let cmdBin = "";
    let cmdArgs = [];
    let cmdDisplay = "";

    if (fs.existsSync(path.join(cwd, "package.json"))) {
      const pj = JSON.parse(fs.readFileSync(path.join(cwd, "package.json"), "utf8"));
      if (op.includes("test") && pj.scripts?.test && !pj.scripts.test.includes("no test specified")) {
        const testsDir = path.join(cwd, "tests");
        if (fs.existsSync(testsDir)) {
          const testFiles = fs.readdirSync(testsDir).filter((f) => f.endsWith(".test.js") || f.endsWith(".spec.js"));
          if (testFiles.length > 0) {
            cmdBin = NODE_EXE;
            cmdArgs = ["--test", ...testFiles.map((f) => path.join(testsDir, f))];
            cmdDisplay = "node --test tests/*.test.js";
          }
        }
        if (!cmdBin) {
          if (process.platform === "win32" && NPM_EXE.toLowerCase().endsWith(".cmd")) {
            cmdBin = "cmd.exe";
            cmdArgs = ["/d", "/s", "/c", NPM_EXE, "test"];
          } else {
            cmdBin = NPM_EXE;
            cmdArgs = ["test"];
          }
          cmdDisplay = "npm test";
        }
      } else if (op.includes("build") && pj.scripts?.build) {
        if (process.platform === "win32" && NPM_EXE.toLowerCase().endsWith(".cmd")) {
          cmdBin = "cmd.exe";
          cmdArgs = ["/d", "/s", "/c", NPM_EXE, "run", "build"];
        } else {
          cmdBin = NPM_EXE;
          cmdArgs = ["run", "build"];
        }
        cmdDisplay = "npm run build";
      } else {
        let entry = ["src/index.js", "index.js", "server.js"].find((f) => fs.existsSync(path.join(cwd, f)));
        if (!entry && fs.existsSync(path.join(cwd, "src"))) {
          const srcJs = fs.readdirSync(path.join(cwd, "src")).find((f) => f.endsWith(".js") || f.endsWith(".cjs") || f.endsWith(".mjs"));
          if (srcJs) entry = `src/${srcJs}`;
        }
        if (!entry) {
          const rootJs = fs.readdirSync(cwd).find((f) => f.endsWith(".js") || f.endsWith(".cjs") || f.endsWith(".mjs"));
          if (rootJs) entry = rootJs;
        }
        if (entry) {
          cmdBin = NODE_EXE;
          cmdArgs = ["--check", path.join(cwd, entry)];
          cmdDisplay = `node --check ${entry}`;
        }
      }
    }

    if (!cmdBin && fs.existsSync(path.join(cwd, "composer.json"))) {
      const phpBin = (process.env.PHP_EXE && process.env.PHP_EXE.trim()) || "php";
      const targetPhp = ["public/index.php", "artisan", "routes/api.php"].find((f) => fs.existsSync(path.join(cwd, f)));
      if (targetPhp) {
        cmdBin = phpBin;
        cmdArgs = ["-l", path.join(cwd, targetPhp)];
        cmdDisplay = `php -l ${targetPhp}`;
      }
    }

    if (!cmdBin) {
      const pyFiles = fs.readdirSync(cwd).filter((f) => f.endsWith(".py")).slice(0, 6);
      if (pyFiles.length > 0) {
        cmdBin = PYTHON_EXE;
        cmdArgs = ["-m", "py_compile", ...pyFiles.map((f) => path.join(cwd, f))];
        cmdDisplay = `${path.basename(PYTHON_EXE)} -m py_compile ${pyFiles.join(" ")}`;
      }
    }

    if (!cmdBin) {
      return {
        ok: false,
        status: 400,
        error: `Tidak ditemukan runner test/build otomatis yang aman pada '${v.resolved_path}'.`,
      };
    }

    const t0 = Date.now();
    try {
      const { stdout, stderr } = await execFileAsync(cmdBin, cmdArgs, {
        cwd,
        timeout: 45_000,
        windowsHide: true,
      });
      return {
        ok: true,
        path: v.resolved_path,
        command_executed: cmdDisplay,
        exit_code: 0,
        duration_ms: Date.now() - t0,
        output: sanitizeText((stdout || stderr || "OK (exit code 0)").trim()).slice(0, 1800),
      };
    } catch (err) {
      return {
        ok: false,
        status: 422,
        path: v.resolved_path,
        command_executed: cmdDisplay,
        exit_code: Number(err.code) || 1,
        duration_ms: Date.now() - t0,
        error: `Perintah \`${cmdDisplay}\` mengembalikan exit code ${Number(err.code) || 1}.`,
        output: sanitizeText(String(err.stdout || err.stderr || err.message || "")).slice(0, 1800),
      };
    }
  }

  return { ok: false, status: 400, error: `Operasi development '${sanitizeText(op)}' tidak dikenali.` };
}

module.exports = {
  isInsideForbiddenZone,
  validateSecureFolderOrFile,
  exploreDirectoryPaginated,
  searchDirectoriesSafe,
  readSafeSourceSnippet,
  performRealSourceCodeAnalysis,
  executeSafeDevOperation,
};
