"use strict";

/**
 * Defensive Security Findings Reader, On-Demand VulnClaw HTTP Worker Client,
 * Workflow Ledger Reader, Authorized Evidence & Binary Report Metadata Inspector,
 * and Platform CLI / Telegram Notification Bridge.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const {
  PLATFORM_ROOT,
  DATA_DIR,
  WORKSPACES_DIR,
  REPORTS_DIR,
  DOCS_DIR,
  VULNCLAW_WORKER_URL,
  HERMES_REMOTE_EXEC_URL,
  PYTHON_EXE,
  GIT_EXE,
  resolveWorkspacesDir,
  resolveReportsDir,
  resolveVulnclawWorkerUrl,
  resolveHermesRemoteExecUrl,
  loadSqliteDatabaseSync,
} = require("../contracts/paths");
const { buildInternalServiceAuthHeaders } = require("../authorization/auth");
const {
  sanitizePayload,
  sanitizeText,
  validateAuthorizedEvidencePath,
} = require("../contracts/redaction");

const execFileAsync = promisify(execFile);

const FINDINGS_DB_PATH = path.join(DATA_DIR, "findings", "findings.db");
const WORKFLOW_DB_PATH = path.join(DATA_DIR, "workflow-ledger.db");
const MAINT_STATE_PATH = path.join(DATA_DIR, "maintenance", "state.json");
const MAINT_LOCK_PATH = path.join(DATA_DIR, "maintenance", "maintenance.lock");
const PLATFORM_PY_SCRIPT = path.join(PLATFORM_ROOT, "integration", "platform_cli.py");

function readFindingsSnapshot(dbPath = FINDINGS_DB_PATH) {
  const DatabaseSync = loadSqliteDatabaseSync();
  if (!DatabaseSync || !fs.existsSync(dbPath)) {
    return {
      available: false,
      summary: { total: 0, open: 0, resolved: 0, false_positives: 0, accepted_risks: 0 },
      findings: [],
      timeline: [],
    };
  }
  const db = new DatabaseSync(dbPath, { open: true, readOnly: true });
  try {
    const findingsRows = db
      .prepare("SELECT * FROM findings ORDER BY updated_at DESC LIMIT 200")
      .all();
    const eventsRows = db
      .prepare("SELECT * FROM finding_events ORDER BY event_id DESC LIMIT 250")
      .all();

    const byStatus = {};
    let openCount = 0;
    let resolvedCount = 0;
    let fpCount = 0;
    let acceptedCount = 0;

    const findings = findingsRows.map((row) => {
      const st = String(row.verification_status || "UNKNOWN");
      byStatus[st] = (byStatus[st] || 0) + 1;
      if (st === "RESOLVED") resolvedCount += 1;
      else if (st === "FALSE_POSITIVE") fpCount += 1;
      else if (st === "ACCEPTED_RISK") acceptedCount += 1;
      else openCount += 1;

      return sanitizePayload({
        finding_id: row.finding_id,
        project_id: row.project_id,
        asset_reference: row.asset_reference,
        source_reference: row.source_reference,
        finding_title: row.finding_title,
        finding_description: row.finding_description,
        severity: row.severity,
        confidence: row.confidence,
        cwe_reference: row.cwe_reference,
        cve_reference: row.cve_reference,
        affected_component: row.affected_component,
        sanitized_evidence: row.sanitized_evidence,
        remediation_recommendation: row.remediation_recommendation,
        verification_status: st,
        occurrence_count: row.occurrence_count,
        assigned_reviewer: row.owner || "security_reviewer",
        paperclip_review_issue_id: row.paperclip_review_issue_id,
        paperclip_remediation_issue_id: row.paperclip_remediation_issue_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
      });
    });

    const timeline = eventsRows.map((ev) => {
      let detail = {};
      try {
        detail = JSON.parse(ev.detail_json || "{}");
      } catch {
        detail = { raw: String(ev.detail_json || "") };
      }
      return sanitizePayload({
        event_id: ev.event_id,
        finding_id: ev.finding_id,
        event_type: ev.event_type,
        from_status: ev.from_status,
        to_status: ev.to_status,
        actor: ev.actor,
        detail,
        created_at: ev.created_at,
      });
    });

    return {
      available: true,
      trust_boundary: "ISOLATED_DEFENSIVE_READONLY",
      summary: {
        total: findings.length,
        open: openCount,
        resolved: resolvedCount,
        false_positives: fpCount,
        accepted_risks: acceptedCount,
        by_status: byStatus,
      },
      findings,
      timeline,
    };
  } finally {
    db.close();
  }
}

function readWorkflowLedgerSnapshot(dbPath = WORKFLOW_DB_PATH) {
  const DatabaseSync = loadSqliteDatabaseSync();
  if (!DatabaseSync || !fs.existsSync(dbPath)) {
    return { available: false, tasks: [], byIssueId: {} };
  }
  const db = new DatabaseSync(dbPath, { open: true, readOnly: true });
  try {
    const rows = db.prepare("SELECT * FROM task_ledger ORDER BY updated_at DESC LIMIT 300").all();
    const byIssueId = {};
    const tasks = rows.map((r) => {
      let deps = [];
      let evidence = {};
      try {
        deps = JSON.parse(r.dependencies_json || "[]");
      } catch {}
      try {
        evidence = JSON.parse(r.evidence_json || "{}");
      } catch {}
      const item = sanitizePayload({
        task_uuid: r.task_uuid,
        paperclip_issue_id: r.paperclip_issue_id,
        paperclip_identifier: r.paperclip_identifier,
        idempotency_key: r.idempotency_key,
        parent_issue_id: r.parent_issue_id,
        delegation_depth: r.delegation_depth,
        assigned_role: r.assigned_role,
        assigned_agent_id: r.assigned_agent_id,
        priority: r.priority,
        scope_path: r.scope_path,
        dependencies: deps,
        acceptance_criteria: r.acceptance_criteria,
        workflow_stage: r.workflow_stage,
        retry_count: r.retry_count,
        last_run_id: r.last_run_id,
        evidence,
        created_at: r.created_at,
        updated_at: r.updated_at,
      });
      byIssueId[r.paperclip_issue_id] = item;
      return item;
    });
    return { available: true, tasks, byIssueId };
  } finally {
    db.close();
  }
}

function readMaintenanceSnapshot() {
  const lockActive = fs.existsSync(MAINT_LOCK_PATH);
  let state = { state: "UNKNOWN" };
  try {
    if (fs.existsSync(MAINT_STATE_PATH)) {
      state = JSON.parse(fs.readFileSync(MAINT_STATE_PATH, "utf8").replace(/^\uFEFF/, ""));
    }
  } catch {
    state = { state: "UNKNOWN" };
  }
  return {
    lock_active: lockActive,
    draining: state.state === "DRAINING",
    maintenance_active: lockActive || ["UPDATING", "POST_UPDATE_TEST", "PRECHECK"].includes(String(state.state || "")),
    state: sanitizePayload(state),
  };
}

function isSensitiveProjectFilename(fileName) {
  const base = String(fileName || "").trim();
  if (!base) return false;
  if (/^\.env$/i.test(base)) return true;
  if (/^\.env\./i.test(base) && !/^\.env\.example$/i.test(base)) return true;
  if (/^(auth\.json|office-bridge-auth\.json)$/i.test(base)) return true;
  if (/\.local\./i.test(base)) return true;
  if (/secret|private[_-]?key|id_rsa|id_ed25519|\.pem$|\.pfx$|\.key$/i.test(base)) return true;
  return false;
}

/**
 * Inspect binary `.pdf` or `.docx` report/evidence files safely without binary UTF-8 corruption.
 */
function inspectBinaryDocumentMetadata(filePath, stat) {
  const ext = path.extname(filePath).toLowerCase();
  const buf = fs.readFileSync(filePath);
  const sha256 = crypto.createHash("sha256").update(buf).digest("hex");

  if (ext === ".pdf") {
    const headerAscii = buf.subarray(0, Math.min(buf.length, 64)).toString("latin1");
    const pdfVerMatch = headerAscii.match(/^%PDF-(\d+\.\d+)/);
    const latinSample = buf.subarray(0, Math.min(buf.length, 512 * 1024)).toString("latin1");
    const pageMatches = latinSample.match(/\/Type\s*\/Page\b/g);
    return {
      kind: "document_metadata",
      format: "pdf",
      mime_type: "application/pdf",
      path: filePath.replace(/\\/g, "/"),
      filename: path.basename(filePath),
      size_bytes: stat.size,
      mtime_iso: stat.mtime.toISOString(),
      sha256,
      valid_signature: Boolean(pdfVerMatch),
      pdf_version: pdfVerMatch ? pdfVerMatch[1] : null,
      estimated_pages: pageMatches ? pageMatches.length : null,
    };
  }

  // .docx (OOXML ZIP container starting with PK\x03\x04)
  const validZipSig = buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b;
  const latinStr = buf.subarray(0, Math.min(buf.length, 512 * 1024)).toString("latin1");
  const hasWordDocXml = latinStr.includes("word/document.xml");
  return {
    kind: "document_metadata",
    format: "docx",
    mime_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    path: filePath.replace(/\\/g, "/"),
    filename: path.basename(filePath),
    size_bytes: stat.size,
    mtime_iso: stat.mtime.toISOString(),
    sha256,
    valid_signature: validZipSig,
    has_word_document_xml: hasWordDocXml,
  };
}

/**
 * Inspect Git, source, or `.pdf`/`.docx`/`.md` report evidence inside an authorized workspace/report path.
 */
async function inspectWorkspaceEvidence(workspaceNameOrPath) {
  const rawInput = String(workspaceNameOrPath || "").trim();
  let candidate = rawInput;
  if (rawInput && !path.isAbsolute(rawInput) && !rawInput.startsWith("~")) {
    const dynWsCand = path.join(resolveWorkspacesDir(process.env), rawInput);
    const dynRepCand = path.join(resolveReportsDir(process.env), rawInput);
    const wsCand = path.join(WORKSPACES_DIR, rawInput);
    const repCand = path.join(REPORTS_DIR, rawInput);
    const docCand = path.join(DOCS_DIR, rawInput);
    if (fs.existsSync(dynWsCand)) candidate = dynWsCand;
    else if (fs.existsSync(dynRepCand)) candidate = dynRepCand;
    else if (fs.existsSync(wsCand)) candidate = wsCand;
    else if (fs.existsSync(repCand)) candidate = repCand;
    else if (fs.existsSync(docCand)) candidate = docCand;
    else candidate = dynWsCand;
  }

  const check = validateAuthorizedEvidencePath(candidate);
  if (!check.ok || !check.resolvedPath) {
    const err = new Error(check.reason || "Unauthorized evidence path.");
    err.status = 403;
    throw err;
  }
  const target = check.resolvedPath;
  if (!fs.existsSync(target)) {
    const err = new Error("Requested workspace or artifact does not exist.");
    err.status = 404;
    throw err;
  }

  const stat = fs.statSync(target);
  if (stat.isFile()) {
    if (isSensitiveProjectFilename(path.basename(target))) {
      const err = new Error("Reading environment/secret files is forbidden by security policy.");
      err.status = 403;
      throw err;
    }
    const ext = path.extname(target).toLowerCase();
    if (ext === ".pdf" || ext === ".docx") {
      return inspectBinaryDocumentMetadata(target, stat);
    }
    const allowedExts = [
      ".json", ".md", ".txt", ".py", ".ts", ".tsx", ".js", ".jsx", ".cjs", ".mjs",
      ".php", ".vue", ".yaml", ".yml", ".xml", ".sql", ".html", ".css", ".sarif", ".example",
    ];
    if (!allowedExts.includes(ext)) {
      const err = new Error("Unsupported artifact file extension.");
      err.status = 403;
      throw err;
    }
    const raw = fs.readFileSync(target, "utf8").slice(0, 16_000);
    return {
      kind: "file",
      path: target.replace(/\\/g, "/"),
      size_bytes: stat.size,
      mtime_iso: stat.mtime.toISOString(),
      content_excerpt: sanitizeText(raw),
    };
  }

  const gitDir = path.join(target, ".git");
  let currentBranch = null;
  let branches = [];
  let recentCommits = [];
  let changedFiles = [];

  if (fs.existsSync(gitDir)) {
    try {
      const br = await execFileAsync(GIT_EXE, ["-C", target, "rev-parse", "--abbrev-ref", "HEAD"], { timeout: 6000 });
      currentBranch = br.stdout.trim();
    } catch {}
    try {
      const allBr = await execFileAsync(GIT_EXE, ["-C", target, "branch", "--list"], { timeout: 6000 });
      branches = allBr.stdout
        .split(/\r?\n/)
        .map((l) => l.replace(/^\*?\s+/, "").trim())
        .filter(Boolean);
    } catch {}
    try {
      const logOut = await execFileAsync(
        GIT_EXE,
        ["-C", target, "log", "--all", "-n", "10", "--pretty=format:%h|%an|%ad|%s", "--date=iso"],
        { timeout: 6000 }
      );
      recentCommits = logOut.stdout
        .split(/\r?\n/)
        .filter(Boolean)
        .map((line) => {
          const [hash, author, date, ...msg] = line.split("|");
          return { hash, author, date, subject: sanitizeText(msg.join("|")) };
        });
    } catch {}
    try {
      const diffFiles = await execFileAsync(GIT_EXE, ["-C", target, "status", "--short"], { timeout: 6000 });
      changedFiles = diffFiles.stdout
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);
      if (changedFiles.length === 0 && branches.includes("main") && currentBranch && currentBranch !== "main") {
        const branchDiff = await execFileAsync(
          GIT_EXE,
          ["-C", target, "diff", "--name-status", `main..${currentBranch}`],
          { timeout: 6000 }
        );
        changedFiles = branchDiff.stdout
          .split(/\r?\n/)
          .map((s) => s.trim())
          .filter(Boolean);
      }
    } catch {}
  }

  const filesListing = fs
    .readdirSync(target, { withFileTypes: true })
    .filter((d) => !d.name.startsWith(".git") && !isSensitiveProjectFilename(d.name))
    .slice(0, 60)
    .map((d) => ({ name: d.name, type: d.isDirectory() ? "directory" : "file" }));

  return {
    kind: "workspace",
    path: target.replace(/\\/g, "/"),
    current_branch: currentBranch,
    branches,
    recent_commits: recentCommits,
    changed_files: changedFiles,
    entries: filesListing,
  };
}

function inspectProjectMetadataSummary(projectPath) {
  const check = validateAuthorizedEvidencePath(projectPath);
  if (!check.ok || !check.resolvedPath || !fs.existsSync(check.resolvedPath)) return null;
  const dir = check.resolvedPath;
  if (!fs.statSync(dir).isDirectory()) return null;

  const projectName = path.basename(dir);
  const stack = [];
  let packageName = null;
  let modulesList = [];

  const composerPath = path.join(dir, "composer.json");
  if (fs.existsSync(composerPath)) {
    stack.push("PHP / Composer");
    try {
      const comp = JSON.parse(fs.readFileSync(composerPath, "utf8"));
      packageName = comp.name || packageName;
      const reqs = { ...(comp.require || {}), ...(comp["require-dev"] || {}) };
      if (reqs["laravel/framework"]) {
        stack.push(`Laravel (${reqs["laravel/framework"]})`);
      }
      if (reqs["nwidart/laravel-modules"]) {
        stack.push("Modular Laravel (nwidart/laravel-modules)");
      }
    } catch {}
  }

  const pkgPath = path.join(dir, "package.json");
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
      packageName = packageName || pkg.name || null;
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      if (deps.next) stack.push(`Next.js (${deps.next})`);
      else if (deps.react) stack.push("React");
      else if (deps.vue) stack.push("Vue.js");
      else if (deps.express) stack.push("Express.js");
      else stack.push("Node.js / NPM");
    } catch {}
  }

  if (fs.existsSync(path.join(dir, "pyproject.toml")) || fs.existsSync(path.join(dir, "requirements.txt"))) {
    stack.push("Python");
  }

  const modulesDir = path.join(dir, "Modules");
  if (fs.existsSync(modulesDir) && fs.statSync(modulesDir).isDirectory()) {
    try {
      modulesList = fs
        .readdirSync(modulesDir, { withFileTypes: true })
        .filter((d) => d.isDirectory() && !d.name.startsWith("."))
        .map((d) => d.name)
        .slice(0, 20);
    } catch {}
  }

  const topDirs = fs
    .readdirSync(dir, { withFileTypes: true })
    .filter((d) => d.isDirectory() && !d.name.startsWith(".") && d.name !== "node_modules" && d.name !== "vendor")
    .map((d) => d.name)
    .slice(0, 18);

  const hasTests = fs.existsSync(path.join(dir, "tests")) || fs.existsSync(path.join(dir, "phpunit.xml"));

  return {
    project_name: projectName,
    resolved_path: dir.replace(/\\/g, "/"),
    package_name: packageName,
    stack: stack.length > 0 ? stack : ["General Source Repository"],
    modules: modulesList,
    top_directories: topDirs,
    has_test_suite: hasTests,
  };
}

/**
 * Execute an on-demand defensive scan via `VULNCLAW_WORKER_URL` HTTP worker if configured,
 * falling back cleanly to `platform_cli.py` or read-only local findings summary.
 */
async function runDefensiveVulnclawScan(targetPath, { callerId = "", workerUrl = undefined, timeoutMs = 45_000 } = {}) {
  const check = validateAuthorizedEvidencePath(targetPath);
  if (!check.ok || !check.resolvedPath) {
    const err = new Error(check.reason || "Unauthorized scan path.");
    err.status = 403;
    throw err;
  }

  const effectiveWorkerUrl = String(
    workerUrl !== undefined ? workerUrl : resolveVulnclawWorkerUrl(process.env) || VULNCLAW_WORKER_URL || ""
  )
    .trim()
    .replace(/\/$/, "");

  if (effectiveWorkerUrl) {
    try {
      const resp = await fetch(`${effectiveWorkerUrl}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Correlation-Id": `vc-${crypto.randomUUID()}`,
          ...buildInternalServiceAuthHeaders("vulnclaw", process.env),
        },
        body: JSON.stringify({
          path: check.resolvedPath,
          target_path: check.resolvedPath,
          mode: "defensive",
          caller_id: callerId,
        }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (resp.ok) {
        const json = await resp.json();
        return sanitizePayload({
          ok: true,
          transport: "vulnclaw_http_worker",
          target_path: check.resolvedPath.replace(/\\/g, "/"),
          ...json,
        });
      }
    } catch {
      // Fall through to CLI fallback when on-demand container is scaled to zero
    }
  }

  if (fs.existsSync(PLATFORM_PY_SCRIPT)) {
    return invokePlatformCliJson(
      ["telegram-cmd", "security_report", "--args", check.resolvedPath, "--caller-id", callerId],
      timeoutMs
    );
  }

  const snap = readFindingsSnapshot();
  return sanitizePayload({
    ok: true,
    transport: "local_findings_store_fallback",
    target_path: check.resolvedPath.replace(/\\/g, "/"),
    summary: snap.summary,
    findings: snap.findings.slice(0, 10),
    reply: `Defensive scan fallback completed for \`${check.resolvedPath.replace(/\\/g, "/")}\` (open findings: ${snap.summary?.open ?? 0}).`,
  });
}

async function invokePlatformCliJson(args, timeoutMs = 30_000) {
  const remoteExec = String(resolveHermesRemoteExecUrl(process.env) || HERMES_REMOTE_EXEC_URL || "")
    .trim()
    .replace(/\/$/, "");
  if (remoteExec) {
    try {
      const resp = await fetch(`${remoteExec}/api/cli`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...buildInternalServiceAuthHeaders("hermes", process.env),
        },
        body: JSON.stringify({ args }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (resp.ok) {
        const body = await resp.json();
        if (body && typeof body === "object" && body.parsed && typeof body.parsed === "object") {
          return sanitizePayload({
            ...body.parsed,
            ok: body.parsed.ok !== undefined ? body.parsed.ok : body.ok,
            exit_code: body.exit_code,
          });
        }
        return sanitizePayload(body);
      }
    } catch {
      // Fall back to local platform_cli.py if present
    }
  }
  if (!fs.existsSync(PLATFORM_PY_SCRIPT)) {
    return { ok: true, available: false, reason: "platform_cli_not_present" };
  }
  const { stdout } = await execFileAsync(PYTHON_EXE, [PLATFORM_PY_SCRIPT, ...args], {
    cwd: PLATFORM_ROOT,
    timeout: timeoutMs,
    maxBuffer: 4 * 1024 * 1024,
    windowsHide: true,
  });
  const trimmed = stdout.trim();
  const firstBrace = trimmed.indexOf("{");
  if (firstBrace >= 0) {
    return sanitizePayload(JSON.parse(trimmed.slice(firstBrace)));
  }
  return { raw: sanitizeText(trimmed) };
}

async function sendTelegramNotificationViaExistingBridge(
  messageText,
  correlationId = "",
  { remoteExecUrl = undefined, documentPath = undefined, caption = undefined } = {}
) {
  const safeMsg = sanitizeText(String(messageText || "").trim()).slice(0, 3200);
  const remoteExec = String(
    remoteExecUrl !== undefined ? remoteExecUrl : resolveHermesRemoteExecUrl(process.env) || HERMES_REMOTE_EXEC_URL || ""
  )
    .trim()
    .replace(/\/$/, "");

  if (remoteExec) {
    try {
      const resp = await fetch(`${remoteExec}/api/telegram/notify`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(correlationId ? { "X-Correlation-Id": String(correlationId) } : {}),
          ...buildInternalServiceAuthHeaders("hermes", process.env),
        },
        body: JSON.stringify({
          text: safeMsg,
          message: safeMsg,
          ...(documentPath ? { document_path: String(documentPath) } : {}),
          ...(caption ? { caption: sanitizeText(String(caption)).slice(0, 950) } : {}),
          correlation_id: correlationId,
        }),
        signal: AbortSignal.timeout(15_000),
      });
      if (resp.ok) {
        return sanitizePayload(await resp.json());
      }
    } catch {}
  }

  const pyCode = [
    "import json, sys",
    `sys.path.insert(0, ${JSON.stringify(PLATFORM_ROOT)})`,
    "from integration.workflow_engine import send_owner_telegram_notification",
    "msg = sys.argv[1]",
    "res = send_owner_telegram_notification(msg)",
    "print(json.dumps(res))",
  ].join("; ");

  const { stdout } = await execFileAsync(PYTHON_EXE, ["-c", pyCode, safeMsg], {
    cwd: PLATFORM_ROOT,
    timeout: 20_000,
    windowsHide: true,
  });
  return sanitizePayload(JSON.parse(stdout.trim()));
}

module.exports = {
  FINDINGS_DB_PATH,
  WORKFLOW_DB_PATH,
  readFindingsSnapshot,
  readWorkflowLedgerSnapshot,
  readMaintenanceSnapshot,
  isSensitiveProjectFilename,
  inspectBinaryDocumentMetadata,
  inspectWorkspaceEvidence,
  inspectProjectMetadataSummary,
  runDefensiveVulnclawScan,
  invokePlatformCliJson,
  sendTelegramNotificationViaExistingBridge,
};
