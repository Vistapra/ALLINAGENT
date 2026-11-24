"use strict";

/**
 * PHASE 06 & PHASE 12 — Agent Lifecycle, Dispatch Gate, Real CEO Multi-Agent Delegation
 * (Parent + Specialist Child Subtasks), and Paperclip Project/Kanban Read-After-Write Controller.
 *
 * Cross-platform portable (`contracts/paths.js`), dynamic `role_slug` specialist resolution.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { OFFICE_DATA_DIR } = require("../contracts/paths");
const { sanitizeText } = require("../contracts/redaction");
const { performRealSourceCodeAnalysis, validateSecureFolderOrFile } = require("./folder-and-dev-controller");

const DISPATCH_STATE_FILE = path.resolve(path.join(OFFICE_DATA_DIR, "dispatch-control.json"));
const ACTIVE_PROJECT_FILE = path.resolve(path.join(OFFICE_DATA_DIR, "telegram-active-project.json"));

function loadDispatchControl() {
  try {
    if (fs.existsSync(DISPATCH_STATE_FILE)) {
      return JSON.parse(fs.readFileSync(DISPATCH_STATE_FILE, "utf8"));
    }
  } catch {}
  return { dispatch_paused: false, updated_at: null, reason: null };
}

function setDispatchPaused(paused, reason = "") {
  const next = {
    dispatch_paused: Boolean(paused),
    updated_at: new Date().toISOString(),
    reason: sanitizeText(String(reason || (paused ? "Paused by Owner via Telegram" : "Resumed by Owner via Telegram"))),
  };
  fs.mkdirSync(path.dirname(DISPATCH_STATE_FILE), { recursive: true, mode: 0o700 });
  fs.writeFileSync(DISPATCH_STATE_FILE, JSON.stringify(next, null, 2) + "\n", "utf8");
  return next;
}

function loadActiveProjectSelection() {
  try {
    if (fs.existsSync(ACTIVE_PROJECT_FILE)) {
      return JSON.parse(fs.readFileSync(ACTIVE_PROJECT_FILE, "utf8"));
    }
  } catch {}
  return { project_id: null, project_name: null };
}

function saveActiveProjectSelection(projectId, projectName) {
  const next = { project_id: projectId, project_name: projectName, updated_at: new Date().toISOString() };
  fs.mkdirSync(path.dirname(ACTIVE_PROJECT_FILE), { recursive: true, mode: 0o700 });
  fs.writeFileSync(ACTIVE_PROJECT_FILE, JSON.stringify(next, null, 2) + "\n", "utf8");
  return next;
}

/**
 * Verify a Paperclip issue mutation via official REST API (`Read-After-Write Verification` — Phase 12).
 */
async function readAfterWriteVerifyIssue(paperclip, issueId, expectedCheckFn = null) {
  const detail = await paperclip.getTaskDetail(issueId);
  const issue = detail?.issue || detail?.task || detail;
  if (!issue || !issue.id) {
    throw new Error(`Read-after-write gagal: Issue '${issueId}' tidak ditemukan di Paperclip API.`);
  }
  if (typeof expectedCheckFn === "function" && !expectedCheckFn(issue)) {
    throw new Error(`Read-after-write mismatch pada issue '${issue.identifier || issue.id}'.`);
  }
  return { issue, comments: detail?.comments || [] };
}

/**
 * Gracefully cancel a Paperclip task AND any active/queued runs belonging to it (`PHASE 06` & `PHASE 12`).
 */
async function cancelTaskWithActiveRuns({ paperclip, sync, taskId }) {
  const preDetail = await paperclip.getTaskDetail(taskId);
  const liveRunList = Array.isArray(preDetail?.liveRuns) ? preDetail.liveRuns : [];
  const snap = sync.getFullSnapshot();
  const candidateRunIds = new Set();

  for (const lr of liveRunList) {
    if (lr && lr.id && (lr.status === "running" || lr.status === "queued")) {
      candidateRunIds.add(lr.id);
    }
  }
  for (const r of snap.runs || []) {
    if (
      r &&
      r.id &&
      (r.status === "running" || r.status === "queued") &&
      (r.issueId === taskId || r.taskId === taskId)
    ) {
      candidateRunIds.add(r.id);
    }
  }

  const cancelledRunIds = [];
  for (const rid of candidateRunIds) {
    await paperclip.cancelRun(rid).catch(() => {});
    cancelledRunIds.push(rid);
  }

  await paperclip.updateTask(taskId, { status: "cancelled" });

  const midDetail = await paperclip.getTaskDetail(taskId);
  for (const lr of midDetail?.liveRuns || []) {
    if (lr && lr.id && (lr.status === "running" || lr.status === "queued")) {
      await paperclip.cancelRun(lr.id).catch(() => {});
      if (!cancelledRunIds.includes(lr.id)) cancelledRunIds.push(lr.id);
    }
  }
  if (midDetail?.issue?.status !== "cancelled" && midDetail?.issue?.status !== "canceled") {
    await paperclip.updateTask(taskId, { status: "cancelled" });
  }

  const verified = await readAfterWriteVerifyIssue(
    paperclip,
    taskId,
    (iss) => iss.status === "cancelled" || iss.status === "canceled"
  );
  await sync.reconcileNow("telegram_cancel_task_graceful");
  return {
    issue: verified.issue,
    cancelled_runs: cancelledRunIds,
  };
}

/**
 * Extract requested specialist agents from an Owner/CEO delegation sentence.
 */
function parseDelegationSpecialists(instructionText, directory) {
  const lower = String(instructionText || "").toLowerCase();
  const matched = [];
  for (const entry of directory) {
    if (entry.slug === "ceo_agent") continue;
    const hit =
      lower.includes(entry.handle.toLowerCase()) ||
      lower.includes(entry.name.toLowerCase()) ||
      (entry.aliases || []).some((al) => {
        const esc = al.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        return new RegExp(`(?:^|\\b)${esc}(?:\\b|$)`, "i").test(lower);
      });
    if (hit) matched.push(entry);
  }
  if (matched.length > 0) return matched;

  return directory.filter((d) =>
    ["cto_agent", "backend_developer", "qa_engineer", "security_reviewer"].includes(d.slug)
  );
}

/**
 * PHASE 06 — Real CEO Multi-Agent Delegation Orchestrator.
 */
async function orchestrateCeoMultiAgentDelegation({
  instruction,
  targetPath = null,
  sync,
  paperclip,
  handleCreateTaskAction,
  directory,
  callerId,
  idempotencyKey = null,
}) {
  const disp = loadDispatchControl();
  if (disp.dispatch_paused) {
    return {
      ok: false,
      status: 409,
      code: "DISPATCH_PAUSED",
      error: "Pengiriman task baru sedang ditahan (`dispatch_paused = true`). Gunakan `/pause_dispatch resume` untuk membuka kembali.",
    };
  }

  const snap = sync.getFullSnapshot();
  const companyId = snap.company?.id;
  const ceoEntry = directory[0];
  const specialists = parseDelegationSpecialists(instruction, directory).slice(0, 6);

  let verifiedFolder = null;
  let codeAudit = null;
  if (targetPath) {
    const v = validateSecureFolderOrFile(targetPath, { allowFile: false });
    if (!v.ok) return v;
    verifiedFolder = v.resolved_path;
    codeAudit = performRealSourceCodeAnalysis(verifiedFolder, {
      agentName: "CEO Multi-Agent Audit Squad",
      customFocus: instruction,
    });
  }

  const projectName = verifiedFolder ? path.basename(verifiedFolder) : "Executive Delegated Initiative";
  const project = companyId ? await paperclip.ensureProject(companyId, projectName).catch(() => null) : null;

  const baseIdem =
    idempotencyKey ||
    `ceo-del:${crypto.createHash("sha256").update(`${callerId}:${verifiedFolder || ""}:${instruction}`).digest("hex").slice(0, 20)}`;

  const liveCeo = (snap.agents || []).find((a) => a.paperclip_agent_id === ceoEntry.id);
  if (liveCeo && liveCeo.activation_status !== "ACTIVE") {
    await paperclip.resumeAgent(ceoEntry.id).catch(() => {});
  }

  const parentTitle = verifiedFolder
    ? `[CEO Delegation] Orkestrasi Multi-Agen: ${projectName}`
    : `[CEO Delegation] ${sanitizeText(instruction).slice(0, 100)}`;

  const parentCreated = await handleCreateTaskAction(
    {
      title: parentTitle,
      description: [
        `## Instruksi Delegasi Eksekutif Owner (${callerId})`,
        `- **Tujuan:** ${sanitizeText(instruction)}`,
        verifiedFolder ? `- **Target Workspace:** \`${verifiedFolder}\`` : null,
        `- **Spesialis Ditugaskan (${specialists.length}):** ${specialists.map((s) => `${s.name} (${s.handle})`).join(", ")}`,
        codeAudit?.report_path ? `- **Laporan Analisis Kode Awal:** \`${codeAudit.report_path}\`` : null,
      ]
        .filter(Boolean)
        .join("\n"),
      project_id: project?.id || null,
      assignee_agent_id: ceoEntry.id,
      priority: "high",
      status: "in_progress",
      wake_immediately: false,
      idempotency_key: `${baseIdem}:parent`,
      notify_telegram: false,
    },
    callerId
  );

  const parentIssue = parentCreated.task;
  const awakenedAgents = [];
  const childTasks = [];

  const specialistBriefs = {
    cto_agent: "Evaluasi arsitektur sistem, pemisahan modul, dan skalabilitas komponen.",
    backend_developer: "Analisis mendalam struktur source code, endpoint API, model data, dan dependensi runtime.",
    frontend_developer: "Evaluasi komponen UI, integrasi API klien, dan responsivitas antarmuka.",
    devops_engineer: "Tinjau kesiapan runtime, konfigurasi build/deployment, dan reliabilitas layanan.",
    qa_engineer: "Tinjau kualitas kode, skenario pengujian unit/integrasi, dan risiko regresi.",
    security_lead: "Tinjau postur keamanan arsitektur, kontrol akses, dan kebijakan tata kelola.",
    security_reviewer: "Lakukan review keamanan defensif terhadap validasi input, autentikasi, dan risiko konfigurasi.",
    findings_analyst: "Triase temuan analisis statis VulnClaw dan klasifikasi tingkat keparahan.",
    remediation_reviewer: "Susun rekomendasi patch perbaikan yang aman tanpa regresi.",
    compliance_reporter: "Susun laporan kepatuhan dan rekapitulasi audit manajemen.",
  };

  for (const sp of specialists) {
    const liveSp = (snap.agents || []).find((a) => a.paperclip_agent_id === sp.id);
    if (!liveSp || liveSp.activation_status !== "ACTIVE" || liveSp.raw_status === "paused") {
      await paperclip.resumeAgent(sp.id).catch(() => {});
      awakenedAgents.push(sp.name);
    }

    const roleBrief = specialistBriefs[sp.slug] || `Laksanakan bagian ${sp.department} sesuai instruksi CEO.`;
    const subCreated = await handleCreateTaskAction(
      {
        title: `[Subtask -> ${sp.name}] ${projectName}: ${roleBrief.slice(0, 58)}`,
        description: [
          `Subtask resmi di bawah koordinasi **CEO Agent** (Parent: \`${parentIssue.identifier || String(parentIssue.id).slice(0, 8)}\`).`,
          `- **Penanggung Jawab:** ${sp.name} (\`${sp.handle}\`)`,
          verifiedFolder ? `- **Target Folder:** \`${verifiedFolder}\`` : null,
          `- **Fokus Spesialis:** ${roleBrief}`,
          codeAudit?.report_path ? `- **Referensi Bukti Awal:** \`${codeAudit.report_path}\`` : null,
        ]
          .filter(Boolean)
          .join("\n"),
        project_id: project?.id || null,
        parent_id: parentIssue.id,
        assignee_agent_id: sp.id,
        priority: "high",
        status: "todo",
        wake_immediately: true,
        idempotency_key: `${baseIdem}:sub:${sp.slug}`,
        notify_telegram: false,
      },
      callerId
    );

    const verifiedSub = await readAfterWriteVerifyIssue(
      paperclip,
      subCreated.task.id,
      (iss) => iss.assigneeAgentId === sp.id
    );

    if (codeAudit?.ok) {
      const domainSummary =
        sp.slug === "cto_agent"
          ? `Arsitektur terverifikasi: Stack \`${codeAudit.stack.join(", ")}\`, Modul=${codeAudit.modules.length || codeAudit.top_directories.length}, Entry=${codeAudit.entry_points.join(", ")}.`
          : sp.slug === "qa_engineer"
            ? `Review Kualitas: Perintah test terdeteksi=${codeAudit.build_test_commands.join("; ") || "perlu penambahan suite"}; Berkas diperiksa=${codeAudit.examined_files.length}.`
            : sp.slug.includes("security")
              ? `Review Defensif: Berkas \`.env\` terlindungi otomatis; Temuan struktur: ${codeAudit.potential_issues.join(" | ")}.`
              : `Analisis Teknis (${sp.name}): ${codeAudit.runtime_dependencies_count} dependensi runtime, laporan bukti: \`${codeAudit.report_path}\`.`;
      await paperclip.addTaskComment(verifiedSub.issue.id, `✅ **[Verified Initial Pass — ${sp.name}]**\n${domainSummary}`).catch(() => {});
    }

    childTasks.push({
      agent_index: sp.index,
      agent_id: sp.id,
      agent_name: sp.name,
      handle: sp.handle,
      task_id: verifiedSub.issue.id,
      identifier: verifiedSub.issue.identifier || String(verifiedSub.issue.id).slice(0, 8),
      status: verifiedSub.issue.status,
      deduplicated: Boolean(subCreated.deduplicated),
    });
  }

  const rollupComment = [
    `### 📊 Ringkasan Delegasi Multi-Agen CEO`,
    `- **Parent Task:** \`${parentIssue.identifier || String(parentIssue.id).slice(0, 8)}\``,
    project ? `- **Project:** \`${project.name}\` (\`${String(project.id).slice(0, 8)}\`)` : null,
    awakenedAgents.length > 0 ? `- **Agen Dibangunkan dari Standby:** ${awakenedAgents.join(", ")}` : `- **Status Agen:** Seluruh spesialis aktif`,
    `- **Subtasks Terverifikasi (${childTasks.length}):**`,
    ...childTasks.map((c) => `  - \`${c.identifier}\` → **${c.agent_name}** (\`${c.handle}\`) [\`${c.status}\`]`),
    codeAudit?.report_path ? `- **Laporan Bukti Terpadu:** \`${codeAudit.report_path}\`` : null,
  ]
    .filter(Boolean)
    .join("\n");
  await paperclip.addTaskComment(parentIssue.id, rollupComment).catch(() => {});
  await sync.reconcileNow("telegram_ceo_delegation");

  return {
    ok: true,
    deduplicated: Boolean(parentCreated.deduplicated),
    project: project ? { id: project.id, name: project.name } : null,
    parent_task: {
      id: parentIssue.id,
      identifier: parentIssue.identifier || String(parentIssue.id).slice(0, 8),
      title: parentIssue.title,
      status: parentIssue.status,
    },
    awakened_agents: awakenedAgents,
    subtasks: childTasks,
    code_audit: codeAudit,
  };
}

module.exports = {
  loadDispatchControl,
  setDispatchPaused,
  loadActiveProjectSelection,
  saveActiveProjectSelection,
  readAfterWriteVerifyIssue,
  cancelTaskWithActiveRuns,
  parseDelegationSpecialists,
  orchestrateCeoMultiAgentDelegation,
};
