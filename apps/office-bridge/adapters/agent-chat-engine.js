"use strict";

/**
 * Cross-Platform Governed Per-Agent Conversational, Multi-Agent Meeting,
 * Workspace Inspector & Owner Action Engine for all 11 Paperclip Employees.
 *
 * Supports BOTH POSIX (`/workspaces/...`, `/opt/...`) and Windows (`C:\...`, `D:/...`)
 * path extraction and strictly enforces `ALLOWED_EVIDENCE_ROOTS` + `FORBIDDEN_ROOTS`.
 */

const fs = require("node:fs");
const path = require("node:path");
const {
  OFFICE_DATA_DIR,
  REPORTS_DIR,
  DEFAULT_LLM_BASE_URL,
  DEFAULT_LLM_MODEL,
  TELEGRAM_BOT_USERNAME,
  resolveAuthorizedOwnerId,
  resolveAuthorizedWorkspaces,
} = require("../contracts/paths");
const { sanitizeText, validateAuthorizedEvidencePath } = require("../contracts/redaction");
const {
  inspectProjectMetadataSummary,
  sendTelegramNotificationViaExistingBridge,
} = require("./vulnclaw-findings-adapter");
const {
  loadTargetFoldersStore,
  mutateTargetFolders,
  inspectLocalTargetDeep,
} = require("./target-folders-manager");
const { selectAndExecuteAgentSkillForTurn } = require("./agent-skills-bridge");

const CHAT_HISTORY_DIR = path.resolve(path.join(OFFICE_DATA_DIR, "chat-history"));

const FALSE_REFUSAL_RE =
  /(tidak memiliki akses|tidak punya akses|bukan agen di komputer lokal|tidak dapat melihat\s+isi\s+folder|tidak bisa melihat\s+isi\s+folder|tidak bisa mengakses|tidak dapat mengakses|hanya dapat bekerja berdasarkan data|copy[‑-]paste\s+daftar\s+file|upload\s+arsip\s+zip|tidak bisa memindahkan|bukan sistem meeting-room|belum berhasil membuat task|tidak terhubung\s+(?:dengan|ke)\s+(?:akun\s+)?telegram|tidak memiliki\s+["']?browser|tidak punya\s+["']?browser)/i;

function loadWorkerApiKey() {
  for (const envKey of ["CUSTOM_API_KEY", "LLM_API_KEY", "OPENAI_API_KEY"]) {
    if (process.env[envKey] && process.env[envKey].trim()) {
      return process.env[envKey].trim();
    }
  }
  throw new Error("Worker LLM API key not configured in environment.");
}

function historyFileForAgent(agentId) {
  const safeId = String(agentId || "default").replace(/[^a-zA-Z0-9_-]/g, "_");
  return path.join(CHAT_HISTORY_DIR, `${safeId}.json`);
}

function readAgentChatHistory(agentId, limit = 40) {
  const file = historyFileForAgent(agentId);
  if (!fs.existsSync(file)) return [];
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    if (!Array.isArray(parsed)) return [];
    return parsed.slice(-limit);
  } catch {
    return [];
  }
}

function appendAgentChatMessages(agentId, newMessages) {
  fs.mkdirSync(CHAT_HISTORY_DIR, { recursive: true, mode: 0o700 });
  const existing = readAgentChatHistory(agentId, 60);
  const combined = [...existing, ...newMessages].slice(-60);
  fs.writeFileSync(historyFileForAgent(agentId), JSON.stringify(combined, null, 2) + "\n", "utf8");
  return combined;
}

function clearAgentChatHistory(agentId) {
  const file = historyFileForAgent(agentId);
  if (fs.existsSync(file)) {
    try {
      fs.unlinkSync(file);
    } catch {}
  }
}

function stripStudioInstructionWrapper(rawMessage) {
  const text = String(rawMessage || "").trim();
  return text.replace(/^\[Studio Context[^\]]*\]\s*/i, "").trim();
}

/**
 * Extract an authorized project/folder/file path from:
 *   1. Quoted POSIX or Windows paths (`"/workspaces/my app"`, `"D:\\Work\\My Folder"`, `"~/.ssh/id_rsa"`)
 *   2. Trailing path after `path:` / `folder:` / `direktori:` / `lokasi:`
 *   3. Unquoted POSIX paths (`/workspaces/project-a`, `/opt/allinagent/workspaces/demo`, `/etc/passwd`)
 *      and Windows drive paths (`D:\workspaces\demo`, `@D:/workspaces/demo`)
 *   4. Natural-language folder names matching pinned folders or `AUTHORIZED_WORKSPACES`
 *   5. Active Target Folder from `target-folders.json`
 */
function extractTargetProjectPath(textCombined, options = {}) {
  const wrap = (resolved, explicitAttempt = null) =>
    options.returnAttemptInfo ? { resolved, explicitAttempt } : resolved;
  const text = String(textCombined || "");
  const lower = text.toLowerCase();
  const candidates = [];

  // 1. Quoted POSIX, home (`~/`), or Windows paths (supports spaces)
  for (const m of text.matchAll(/["'`]((?:[A-Za-z]:[\\/]|~[\\/]|\/[A-Za-z0-9._-]+)[^"'`<>|*?\r\n]*)["'`]/g)) {
    candidates.push(m[1].trim());
  }

  // 2. Trailing path after colon/equals (`folder: /workspaces/app` or `lokasi = D:\workspaces\app`)
  for (const m of text.matchAll(
    /(?:path\s*(?:nya)?|folder(?:\s+berikut)?|direktori|lokasi)\s*[:=]\s*((?:[A-Za-z]:[\\/]|~[\\/]|\/)[^\r\n"'`<>|*?]+)/gi
  )) {
    candidates.push(m[1].trim().replace(/[.,;!?)]+$/, ""));
  }

  // 3a. Unquoted Windows drive paths (`D:\workspaces\foo` or `@D:/workspaces/foo`)
  for (const m of text.matchAll(/(?:^|[\s(@])([A-Za-z]:[\\/](?:[^\s"'`<>|*?]+))/g)) {
    candidates.push(m[1].trim().replace(/[.,;:!?)]+$/, ""));
  }

  // 3b. Unquoted POSIX / `~/` paths (requires >=2 segments `/a/b` OR known POSIX root so slash commands like `/task` are never misclassified)
  for (const m of text.matchAll(
    /(?:^|[\s(@])((?:~\/[^\s"'`<>|*?]+|\/(?:workspaces|reports|docs|etc|proc|sys|dev|root|boot|run|var|opt|srv|home|app|data|mnt|tmp)(?:\/[^\s"'`<>|*?]+)*|\/[A-Za-z0-9._-]+\/[A-Za-z0-9._/-]+))/g
  )) {
    candidates.push(m[1].trim().replace(/[.,;:!?)]+$/, ""));
  }

  let lastExplicitAttempt = null;
  for (let i = candidates.length - 1; i >= 0; i -= 1) {
    const cleaned = candidates[i];
    lastExplicitAttempt = cleaned;
    const v = validateAuthorizedEvidencePath(cleaned);
    if (v.ok && v.resolvedPath && fs.existsSync(v.resolvedPath)) {
      return wrap(v.resolvedPath, cleaned);
    }
  }

  if (lastExplicitAttempt) {
    return wrap(null, lastExplicitAttempt);
  }

  const store = loadTargetFoldersStore();

  // 4. Explicit reference to "folder ini" / "proyek ini"
  if (
    store.active_folder &&
    /\b(folder\s+ini|proyek\s+ini|project\s+ini|direktori\s+ini)\b/i.test(lower)
  ) {
    const activeCheck = validateAuthorizedEvidencePath(store.active_folder);
    if (activeCheck.ok && activeCheck.resolvedPath && fs.existsSync(activeCheck.resolvedPath)) {
      return wrap(activeCheck.resolvedPath);
    }
  }

  // 5. Natural-language match across pinned folders & configured AUTHORIZED_WORKSPACES
  for (const pinned of store.pinned_paths || []) {
    const base = path.basename(pinned).toLowerCase();
    if (base.length >= 4 && lower.includes(base) && fs.existsSync(pinned)) {
      return wrap(pinned);
    }
  }

  const rootsToScan = resolveAuthorizedWorkspaces(process.env);
  const genericNames = new Set(["public", "source", "config", "reports", "docs", "workspaces", "tests"]);
  for (const rootDir of rootsToScan) {
    if (!fs.existsSync(rootDir)) continue;
    try {
      const dirs = fs
        .readdirSync(rootDir, { withFileTypes: true })
        .filter((d) => d.isDirectory() && !d.name.startsWith(".") && !d.name.startsWith("$"));
      for (const d of dirs) {
        const dLower = d.name.toLowerCase();
        if (dLower.length >= 4 && !genericNames.has(dLower) && lower.includes(dLower)) {
          const full = path.join(rootDir, d.name);
          const v = validateAuthorizedEvidencePath(full);
          if (v.ok && v.resolvedPath) return wrap(v.resolvedPath);
        }
      }
    } catch {}
  }

  // 6. Fallback to Active Target Folder when user asks to inspect/analyze files or folders
  if (store.active_folder) {
    const activeCheck = validateAuthorizedEvidencePath(store.active_folder);
    if (activeCheck.ok && activeCheck.resolvedPath && fs.existsSync(activeCheck.resolvedPath)) {
      const fileMatch = text.match(/\b([A-Za-z0-9_./-]+\.(?:json|md|php|ts|tsx|js|jsx|py|vue|yaml|yml|xml|sql|txt))\b/i);
      if (fileMatch) {
        const subCandidate = path.join(activeCheck.resolvedPath, fileMatch[1]);
        const subCheck = validateAuthorizedEvidencePath(subCandidate);
        if (subCheck.ok && subCheck.resolvedPath && fs.existsSync(subCheck.resolvedPath)) {
          return wrap(subCheck.resolvedPath);
        }
      }
      if (
        /\b(isi\s+folder|struktur\s+folder|analisis|menganalisis|audit|mengaudit|review|periksa|lihat\s+isi|apa\s+isi)\b/i.test(
          lower
        )
      ) {
        return wrap(activeCheck.resolvedPath);
      }
    }
  }

  return wrap(null, null);
}

function isPureConversationalQuestion(msg) {
  const lower = String(msg || "").trim().toLowerCase();
  if (/^\/(task|create_task|meet|meeting)\b/i.test(lower)) return false;
  if (
    /(kumpulkan|kelompokkan|mengelompokkan|ruang\s*meet|meeting\s*room|meet\s*sekarang|meeting\s*sekarang|adakan\s*(rapat|meeting)|mulai\s*(rapat|meeting)|buatkan\s*task|buat\s*task|kerjakan|lakukan\s*sekarang|jalankan\s*sekarang|audit\s+|analisis\s+|menganalisis|mengaudit|[a-z]:[\\/]|\/workspaces\/)/i.test(
      lower
    )
  ) {
    return false;
  }
  if (
    /^(halo|hallo|hi|hello|hai|selamat|siapa\b|apa\b|apakah\b|bisakah\b|bisa\b|bagaimana\b|jelaskan\b|sebutkan\b|tampilkan status|cek status|who\b|what\b|can you\b|how\b)/i.test(
      lower
    )
  ) {
    return true;
  }
  return false;
}

function shouldCreatePaperclipTask(messageText) {
  const raw = String(messageText || "").trim();
  if (/^\/(task|create_task)\b/i.test(raw)) return true;
  const lower = raw.toLowerCase();
  if (
    /^(bisakah|bisa|coba)?\s*(kamu\s+)?(melihat|lihat|tampilkan|cek)\s+(isi\s+)?(folder|direktori|file)\b/i.test(lower) &&
    !/\b(audit|analisis|task|laporan|perbaiki)\b/i.test(lower)
  ) {
    return false;
  }
  return /(buatkan task|buat task|kerjakan|analisis|menganalisis|audit|mengaudit|periksa kode|review proyek|review kode|review folder|perbaiki kode|perbaiki bug|implementasikan|delegasikan|jalankan pengujian|buatkan laporan|create a task|assign task)/i.test(
    lower
  );
}

function analyzeOwnerActionIntent(cleanUserMsg, priorHistory) {
  const lower = cleanUserMsg.toLowerCase().trim();
  const recentUserTexts = priorHistory
    .filter((m) => m && m.role === "user" && typeof m.content === "string")
    .slice(-4)
    .map((m) => m.content);
  const recentAssistantTexts = priorHistory
    .filter((m) => m && m.role === "assistant" && typeof m.content === "string")
    .slice(-2)
    .map((m) => m.content);

  const isShortConfirmation =
    /^(ya|iya|ok|oke|lanjut|lanjutkan|setuju|gas|silakan|jalankan|lakukan)(\b|\s|$)/i.test(lower) ||
    /\b(ya\s+lakukan\s+sekarang|lakukan\s+sekarang|jalankan\s+sekarang|buatkan\s+sekarang|mulai\s+sekarang|segera\s+lakukan)\b/i.test(
      lower
    );

  const recentContextText = [...recentUserTexts, cleanUserMsg].join("\n");
  const assistantProposedAction = recentAssistantTexts.some((t) =>
    /(apakah anda ingin|buatkan task|membuat task|ruang meeting|agenda|path lengkap)/i.test(t)
  );

  const isConcludeMeeting =
    /\b(selesaikan\s+(meeting|rapat)|akhiri\s+(meeting|rapat)|tutup\s+(meeting|rapat)|selesai\s+(meeting|rapat)|kembali\s+ke\s+meja|bubarkan\s+rapat|end\s+meeting|conclude\s+meeting)\b/i.test(
      lower
    );

  const directMeetingMention =
    !isConcludeMeeting &&
    !isPureConversationalQuestion(cleanUserMsg) &&
    (/^\/(meet|meeting|standup)\b/i.test(lower) ||
      /\b(kumpulkan\s+(semua|seluruh|tim|agen|orang)|mengelompokkan\s+(semua|seluruh|agen)|kelompokkan\s+(semua|seluruh|agen)|ke\s+ruang\s+meet|diruang\s+meet|di\s+ruang\s+meet|meeting\s+room|meet\s+sekarang|meeting\s+sekarang|untuk\s+meetingnya|adakan\s+(meeting|rapat)|mulai\s+(meeting|rapat)|standup\s+meeting|scrum\s+meeting|let'?s\s+have\s+a\s+meeting)\b/i.test(
        lower
      ));

  const contextHadMeetingRequest = recentUserTexts.some((u) =>
    /\b(kumpulkan|mengelompokkan|ruang\s*meet|meeting|meet\s+sekarang|rapat)\b/i.test(u)
  );

  const directExtract = extractTargetProjectPath(cleanUserMsg, { returnAttemptInfo: true });
  const contextExtract = extractTargetProjectPath(recentContextText, { returnAttemptInfo: true });

  function isMeetingRequestCandidate() {
    return (
      directMeetingMention ||
      (isShortConfirmation && contextHadMeetingRequest) ||
      (contextHadMeetingRequest && Boolean(directExtract.resolved) && !isPureConversationalQuestion(cleanUserMsg))
    );
  }

  const targetPath =
    directExtract.resolved || (isMeetingRequestCandidate() || isShortConfirmation ? contextExtract.resolved : null);
  const explicitBlockedOrMissingPath = directExtract.resolved ? null : directExtract.explicitAttempt;

  const isMeetingRequest = isMeetingRequestCandidate();
  const directTaskMention = shouldCreatePaperclipTask(cleanUserMsg);
  const contextHadTaskTopic = recentUserTexts.some(
    (u) => shouldCreatePaperclipTask(u) || /\b(membahas|bahas|review|audit|analisis)\b/i.test(u)
  );

  const isTaskRequest =
    directTaskMention || (isShortConfirmation && (assistantProposedAction || contextHadTaskTopic));

  const isSendTelegram =
    /\b(kirim\s+(ke\s+)?telegram|laporkan\s+ke\s+telegram|notifikasi\s+telegram)\b/i.test(lower);

  const isApproveAll =
    /\b(setujui\s+semua|approve\s+all|setujui\s+approval|acc\s+semua)\b/i.test(lower);

  const isActivateAllAgents =
    /\b(aktifkan\s+(semua|seluruh)\s+agen|nyalakan\s+(semua|seluruh)\s+agen|resume\s+all\s+agents)\b/i.test(lower);

  const wantsAllAgents =
    /\b(semua\s+(agen|orang|karyawan|tim)|seluruh\s+(agen|orang|karyawan|tim)|11\s+agen|all\s+agents|everyone)\b/i.test(
      recentContextText
    );

  let topic = cleanUserMsg.replace(/^\/(task|create_task|meet|meeting|standup)\s*/i, "").trim();
  if (isShortConfirmation || topic.length < 18) {
    const meaningfulPrior = [...recentUserTexts]
      .reverse()
      .find((u) => u.trim().length >= 15 && !/^(ya|oke|ok|halo|hallo)/i.test(u.trim()));
    if (meaningfulPrior) {
      topic = `${meaningfulPrior.trim()} (${cleanUserMsg.trim()})`;
    }
  }

  return {
    isMeetingRequest,
    isConcludeMeeting,
    isTaskRequest,
    isSendTelegram,
    isApproveAll,
    isActivateAllAgents,
    wantsAllAgents,
    targetPath,
    explicitBlockedOrMissingPath,
    topic,
  };
}

function formatDeepInspectionContext(deep) {
  if (!deep || !deep.ok) return "";
  if (deep.kind === "file") {
    return [
      `=== HASIL PEMBACAAN LANGSUNG FILE WORKSPACE ===`,
      `- Path File: \`${deep.resolved_path}\` (${deep.size_bytes} bytes)`,
      `- Cuplikan Isi File (Sanitized):`,
      "```",
      deep.excerpt.slice(0, 4500),
      "```",
    ].join("\n");
  }

  const lines = [
    `=== HASIL PEMBACAAN LANGSUNG FOLDER WORKSPACE (TERVERIFIKASI) ===`,
    `- Path Folder: \`${deep.resolved_path}\``,
    `- Nama Folder: **${deep.folder_name}**`,
    `- Tech Stack Terdeteksi: ${deep.stack.join(", ")}`,
    deep.modules.length > 0 ? `- Modul (${deep.modules.length}): ${deep.modules.join(", ")}` : null,
    `- Sub-folder Utama (${deep.directories.length}): ${deep.directories.length > 0 ? deep.directories.join(", ") : "(tidak ada sub-folder)"}`,
    `- File di Root (${deep.files.length}): ${deep.files.length > 0 ? deep.files.map((f) => `${f.name} (${f.size}B)`).join(", ") : "(kosong)"}`,
    deep.hidden_secret_files_protected > 0
      ? `- Proteksi Keamanan: ${deep.hidden_secret_files_protected} file rahasia (.env/secret) disembunyikan otomatis demi keamanan.`
      : null,
    deep.extension_summary ? `- Distribusi Tipe File: ${deep.extension_summary}` : null,
    deep.sampled_paths.length > 0
      ? `- Contoh Path Sumber: ${deep.sampled_paths.slice(0, 18).join(", ")}`
      : null,
  ].filter(Boolean);

  for (const kf of deep.key_excerpts || []) {
    lines.push(`- Cuplikan \`${kf.file}\`:\n\`\`\`\n${kf.excerpt.slice(0, 900)}\n\`\`\``);
  }
  return lines.join("\n");
}

function buildDeterministicFolderReply(agent, deep, executionReceipts = []) {
  if (!deep || !deep.ok) {
    return [
      `Siap, instruksi Anda telah dijalankan oleh **${agent.display_name}**:`,
      ...executionReceipts.map((r) => `- ${r}`),
    ].join("\n");
  }

  if (deep.kind === "file") {
    return [
      `Berikut hasil pembacaan langsung file **\`${deep.resolved_path}\`** (${deep.size_bytes.toLocaleString()} bytes) oleh **${agent.display_name}**:`,
      "",
      "```",
      deep.excerpt.slice(0, 2500),
      "```",
      ...(executionReceipts.length > 0 ? ["", ...executionReceipts.map((r) => `- ${r}`)] : []),
    ].join("\n");
  }

  return [
    `Saya telah membaca dan menganalisis langsung folder workspace **\`${deep.resolved_path}\`**:`,
    "",
    `- **Tech Stack:** ${deep.stack.join(", ")}`,
    deep.modules.length > 0 ? `- **Modul (${deep.modules.length}):** ${deep.modules.join(", ")}` : null,
    `- **Sub-folder Utama (${deep.directories.length}):** ${deep.directories.slice(0, 25).map((d) => `\`${d}/\``).join(", ") || "*(tidak ada)*"}`,
    `- **File Utama di Root (${deep.files.length}):** ${deep.files.slice(0, 20).map((f) => `\`${f.name}\``).join(", ") || "*(tidak ada)*"}`,
    deep.extension_summary ? `- **Komposisi Kode:** ${deep.extension_summary}` : null,
    deep.hidden_secret_files_protected > 0
      ? `- **Keamanan Defensif:** \`${deep.hidden_secret_files_protected}\` berkas kredensial (\`.env\`/rahasia) dilindungi otomatis dan tidak diekspos.`
      : null,
    ...(executionReceipts.length > 0
      ? ["", "**Tindakan Orkestrasi yang Dijalankan:**", ...executionReceipts.map((r) => `- ${r}`)]
      : [
          "",
          "Silakan beri tahu bagian spesifik mana yang ingin dianalisis lebih dalam, diperbaiki, atau dibahas bersama 11 agen di Ruang Meeting!",
        ]),
  ]
    .filter((x) => x !== null)
    .join("\n");
}

async function callLlmCompletion(systemPrompt, historyMessages, userMessage, options = {}) {
  const maxAttempts = options.fastActionReply ? 1 : 2;
  const perAttemptMs = options.fastActionReply ? 11_000 : 14_000;
  const apiKey = loadWorkerApiKey();
  const baseUrl = String(process.env.LLM_BASE_URL || DEFAULT_LLM_BASE_URL).replace(/\/$/, "");
  const model = String(process.env.LLM_MODEL || DEFAULT_LLM_MODEL);

  const messages = [{ role: "system", content: systemPrompt }];
  for (const h of historyMessages.slice(-8)) {
    if ((h.role === "user" || h.role === "assistant") && typeof h.content === "string" && h.content.trim()) {
      messages.push({ role: h.role, content: h.content });
    }
  }
  messages.push({ role: "user", content: userMessage });

  let lastErr = null;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const resp = await fetch(`${baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model,
          messages,
          temperature: 0.2,
          max_tokens: 2048,
          stream: false,
        }),
        signal: AbortSignal.timeout(perAttemptMs),
      });

      if (!resp.ok) {
        throw new Error(`Model provider HTTP ${resp.status}`);
      }
      const rawBody = await resp.text();
      let content = "";
      if (rawBody.trimStart().startsWith("data:")) {
        const pieces = [];
        for (const line of rawBody.split(/\r?\n/)) {
          const trimmed = line.trim();
          if (!trimmed.startsWith("data:")) continue;
          const jsonStr = trimmed.slice(5).trim();
          if (!jsonStr || jsonStr === "[DONE]") continue;
          try {
            const chunk = JSON.parse(jsonStr);
            const delta = chunk?.choices?.[0]?.delta?.content ?? chunk?.choices?.[0]?.message?.content;
            if (typeof delta === "string" && delta) pieces.push(delta);
          } catch {}
        }
        content = pieces.join("");
      } else {
        const data = JSON.parse(rawBody);
        content = data?.choices?.[0]?.message?.content || "";
      }
      const cleaned = typeof content === "string" ? sanitizeText(content.trim()) : "";
      if (!cleaned) {
        throw new Error("Empty model response.");
      }
      if (/is no longer available/i.test(cleaned)) {
        throw new Error("Transient upstream model slot unavailable.");
      }
      if (options.rejectFalseRefusal && FALSE_REFUSAL_RE.test(cleaned)) {
        throw new Error("Model emitted hallucinated generic refusal despite real workspace access.");
      }
      return cleaned;
    } catch (err) {
      lastErr = err;
      if (attempt < maxAttempts) {
        await new Promise((r) => setTimeout(r, 350 * attempt));
      }
    }
  }
  throw lastErr || new Error("Model completion failed.");
}

async function handleEmployeeChatTurn({
  agent,
  snapshot,
  rawMessage,
  idempotencyKey,
  createTaskFn,
  sync,
  paperclip,
  callerId,
}) {
  const cleanUserMsg = sanitizeText(stripStudioInstructionWrapper(rawMessage));
  if (/^\/(reset|new)(\s|$)/i.test(cleanUserMsg)) {
    clearAgentChatHistory(agent.paperclip_agent_id);
    return {
      text: `Sesi percakapan untuk **${agent.display_name}** telah direset. Data organisasi dan task di Paperclip tetap utuh.`,
      createdTask: null,
      createdMeeting: null,
    };
  }

  const effectiveOwnerId = String(callerId || resolveAuthorizedOwnerId() || "owner").trim();
  const priorHistory = readAgentChatHistory(agent.paperclip_agent_id, 10);
  const allAgents = snapshot.agents || [];
  const companyId = snapshot.company?.id;
  const intent = analyzeOwnerActionIntent(cleanUserMsg, priorHistory);

  let explicitPathWarning = null;
  if (!intent.targetPath && intent.explicitBlockedOrMissingPath) {
    const check = inspectLocalTargetDeep(intent.explicitBlockedOrMissingPath);
    if (!check.ok) {
      explicitPathWarning = check.reason;
    }
  }

  const deepInspection = intent.targetPath ? inspectLocalTargetDeep(intent.targetPath) : null;
  if (deepInspection && deepInspection.ok) {
    try {
      mutateTargetFolders({ action: "add", path: intent.targetPath });
    } catch {}
  }

  const targetDirForProject =
    intent.targetPath && fs.existsSync(intent.targetPath)
      ? fs.statSync(intent.targetPath).isDirectory()
        ? intent.targetPath
        : path.dirname(intent.targetPath)
      : null;
  const projectSummary = targetDirForProject ? inspectProjectMetadataSummary(targetDirForProject) : null;

  let ensuredProject = null;
  let createdMeeting = null;
  let createdTask = null;
  let concludedMeetingsCount = 0;
  let approvedCount = 0;
  let resumedAgentsCount = 0;
  const executionReceipts = [];

  if (projectSummary && paperclip && companyId && (intent.isTaskRequest || intent.isMeetingRequest)) {
    ensuredProject = await paperclip.ensureProject(companyId, projectSummary.project_name).catch(() => null);
    executionReceipts.push(
      `Folder proyek terverifikasi: \`${projectSummary.resolved_path}\` (Stack: ${projectSummary.stack.join(", ")}${
        projectSummary.modules.length > 0 ? `; Modul: ${projectSummary.modules.join(", ")}` : ""
      }; Sub-folder: ${projectSummary.top_directories.join(", ")})` +
        (ensuredProject ? ` -> Terdaftar di Paperclip Project **${ensuredProject.name}** (\`${String(ensuredProject.id).slice(0, 8)}\`).` : ".")
    );
  }

  if (intent.isApproveAll && paperclip) {
    const pendingApprovals = (snapshot.approvals || []).filter((a) => a.status === "pending");
    for (const ap of pendingApprovals) {
      await paperclip.resolveApproval(ap.id, "approve", "Disetujui langsung oleh Owner melalui Chat Virtual Office.").catch(() => {});
      approvedCount += 1;
    }
    if (approvedCount > 0) {
      executionReceipts.push(`${approvedCount} permintaan persetujuan (Approval) berstatus pending telah disetujui otomatis atas perintah Owner.`);
    }
  }

  if (intent.isActivateAllAgents && paperclip) {
    for (const ag of allAgents) {
      if (ag.activation_status !== "ACTIVE") {
        await paperclip.resumeAgent(ag.paperclip_agent_id).catch(() => {});
        resumedAgentsCount += 1;
      }
    }
    if (sync) await sync.reconcileNow("owner_activate_all_agents").catch(() => {});
    executionReceipts.push(`Seluruh 11 agen kini diaktifkan (ACTIVE) di Paperclip (${resumedAgentsCount} agen dibangunkan dari STANDBY).`);
  }

  if (intent.isConcludeMeeting && sync) {
    const activeMtgs = (snapshot.collaboration?.meetings || []).filter((m) => m.status === "ACTIVE");
    for (const m of activeMtgs) {
      await sync
        .completeAuthorizedMeeting(m.meeting_id, {
          summary: `Rapat ditutup oleh Owner melalui ${agent.display_name}. Seluruh agen kembali ke meja departemen masing-masing.`,
          decisions: ["Melanjutkan eksekusi tugas sesuai pembagian departemen"],
        })
        .catch(() => {});
      concludedMeetingsCount += 1;
    }
    executionReceipts.push(`Rapat aktif telah diselesaikan (${concludedMeetingsCount} sesi ditutup) dan seluruh avatar kembali ke meja kerja departemen.`);
  }

  if (intent.isMeetingRequest && sync) {
    const ceoObj = allAgents.find((a) => a.role === "ceo") || agent;
    const orderedAllIds = [
      agent.paperclip_agent_id,
      ceoObj.paperclip_agent_id,
      ...allAgents.map((a) => a.paperclip_agent_id),
    ];
    const uniqueAllIds = [...new Set(orderedAllIds)].filter(Boolean);

    let participantIds = uniqueAllIds;
    if (!intent.wantsAllAgents) {
      const matchedSpecific = allAgents
        .filter((a) => cleanUserMsg.toLowerCase().includes(a.display_name.toLowerCase()))
        .map((a) => a.paperclip_agent_id);
      if (matchedSpecific.length >= 2) {
        participantIds = [...new Set([agent.paperclip_agent_id, ...matchedSpecific])];
      }
    }

    const meetingTitle = projectSummary
      ? `All-Hands Sync & Audit: ${projectSummary.project_name}`
      : `Executive Multi-Agent Coordination Sync`;
    const meetingAgenda = projectSummary
      ? `Pembahasan lintas-departemen (${participantIds.length} agen) untuk proyek ${projectSummary.project_name} di ${projectSummary.resolved_path} (${projectSummary.stack.join(", ")}). Fokus: arsitektur, API/database, keamanan defensif, cakupan testing, & laporan eksekutif.`
      : intent.topic.slice(0, 500);

    createdMeeting = await sync.createAuthorizedMeeting({
      title: meetingTitle,
      agenda: meetingAgenda,
      target_path: projectSummary ? projectSummary.resolved_path : intent.targetPath || null,
      project_id: ensuredProject?.id || null,
      participant_agent_ids: participantIds,
      max_turns: 3,
      timeout_sec: 240,
      priority: "high",
      wake_immediately: false,
      idempotency_key: idempotencyKey ? `mtg-${idempotencyKey}` : undefined,
    });

    executionReceipts.push(
      `BERHASIL MENGUMPULKAN AGEN KE RUANG MEETING (3D & 2D): Meeting resmi **${createdMeeting.meeting_id}** (Paperclip Issue **${createdMeeting.paperclip_identifier}**) berstatus \`ACTIVE\` dengan **${participantIds.length}/11 agen** berkumpul di **Meeting Room**.`
    );
  }

  if ((intent.isTaskRequest || (intent.isMeetingRequest && projectSummary)) && typeof createTaskFn === "function") {
    if (paperclip && agent.activation_status !== "ACTIVE") {
      await paperclip.resumeAgent(agent.paperclip_agent_id).catch(() => {});
      if (sync) await sync.reconcileNow("auto_resume_chat_assignee").catch(() => {});
    }

    const reportSlug = projectSummary
      ? `audit-${projectSummary.project_name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}.md`
      : `owner-task-${Date.now()}.md`;
    const reportOutPath = path.join(REPORTS_DIR, reportSlug).replace(/\\/g, "/");

    const taskTitle = projectSummary
      ? `[Owner Approved] Audit & Analisis Multi-Departemen: ${projectSummary.project_name}`
      : intent.topic.slice(0, 130);

    const taskDescription = projectSummary
      ? [
          `Instruksi langsung yang telah disetujui Owner:`,
          `- Folder Target: \`${projectSummary.resolved_path}\` (${projectSummary.stack.join(", ")})`,
          createdMeeting ? `- Terkait Rapat Koordinasi: **${createdMeeting.meeting_id}** (${createdMeeting.paperclip_identifier})` : null,
          `- Permintaan Owner: ${intent.topic}`,
          ``,
          `Langkah Eksekusi Wajib (Efisien, Non-Destruktif & Aman — Maksimal 4 Pembacaan File):`,
          `1. Gunakan \`read_file\` HANYA pada file utama di \`${projectSummary.resolved_path}\` (mis. \`composer.json\` / \`package.json\`, \`README.md\`). JANGAN membaca file \`.env\` atau file kredensial/rahasia apa pun.`,
          `2. Susun laporan analisis/audit lengkap Bahasa Indonesia.`,
          `3. Simpan laporan Markdown ke \`${reportOutPath}\`, lalu balas ringkas 2 kalimat konfirmasi.`,
        ]
          .filter(Boolean)
          .join("\n")
      : intent.topic;

    const res = await createTaskFn(
      {
        title: taskTitle,
        description: taskDescription,
        project_id: ensuredProject?.id || null,
        parent_id: createdMeeting?.paperclip_issue_id || null,
        assignee_agent_id: agent.paperclip_agent_id,
        priority: "high",
        status: "todo",
        wake_immediately: true,
        idempotency_key: idempotencyKey ? `task-${idempotencyKey}` : undefined,
      },
      effectiveOwnerId
    );
    createdTask = res.task || null;
    if (createdTask) {
      executionReceipts.push(
        `BERHASIL MEMBUAT & MENJALANKAN TASK EKSEKUSI PAPERCLIP: Task **${createdTask.identifier || createdTask.id}** (\`${createdTask.title}\`) ditugaskan ke **${agent.display_name}**, output laporan: \`${reportOutPath}\`.`
      );
    }
  }

  if (intent.isSendTelegram) {
    try {
      const tgSummary = deepInspection?.ok
        ? `[${agent.display_name}] Ringkasan Analisis Folder ${deepInspection.resolved_path}: Stack=${(deepInspection.stack || []).join(", ")}, Subfolder=${(deepInspection.directories || []).slice(0, 8).join(", ")}.`
        : `[${agent.display_name}] Laporan status dari Virtual Office: ${cleanUserMsg.slice(0, 300)}`;
      await sendTelegramNotificationViaExistingBridge(tgSummary);
      executionReceipts.push(`Notifikasi ringkasan telah dikirim langsung ke Telegram Owner (\`${TELEGRAM_BOT_USERNAME}\`).`);
    } catch {}
  }

  const manager = allAgents.find((a) => a.paperclip_agent_id === agent.manager_id);
  const subordinates = allAgents.filter((a) => (agent.subordinate_ids || []).includes(a.paperclip_agent_id));
  const agentTasks = (snapshot.tasks || []).filter((t) => t.assigneeAgentId === agent.paperclip_agent_id).slice(0, 6);
  const teamSummary = allAgents
    .map((a) => `${a.display_name} (${a.department_short}, ${a.activation_status})`)
    .join("; ");
  const folderStore = loadTargetFoldersStore();
  const deepContextBlock = formatDeepInspectionContext(deepInspection);
  const skillTurn = selectAndExecuteAgentSkillForTurn({
    agent,
    userMessage: cleanUserMsg,
    targetPath: intent.targetPath || folderStore.active_folder || null,
    surface: String(rawMessage || "").startsWith("[Telegram") ? "telegram" : "office_chat",
    snapshot,
  });

  const systemPrompt = [
    `Anda adalah **${agent.display_name}** (${agent.title}), karyawan AI nyata pada perusahaan **${snapshot.company?.name || "ALLINAGENT Operations"}** di dalam Kantor Virtual 3D & 2D Hermes3D.`,
    `Data identitas & kapabilitas NYATA platform Anda (JANGAN PERNAH MENYANGKAL KAPABILITAS INI):`,
    `- Agent ID: ${agent.paperclip_agent_id} | Departemen: ${agent.department} (${agent.department_short})`,
    `- Runtime: ${agent.runtime_type} (\`${agent.runtime_profile_reference || "pcworker"}\`) · Model: \`${agent.model_id || DEFAULT_LLM_MODEL}\` · Status: ${agent.activation_status}`,
    skillTurn
      ? `- SPECIALIZED ROLE SKILLS TERPASANG: ${(skillTurn.agentAssignment.skills || []).map((s) => `\`${s.pkg_id}\` [${s.category}:${s.status}]`).join(", ")} (Skill aktif: **${skillTurn.chosenSkill.display_name}** \`${skillTurn.chosenSkill.pkg_id}\`)`
      : null,
    `- Atasan: ${manager ? `${manager.display_name} (${manager.title})` : "Human Owner / Board"}`,
    `- Bawahan: ${subordinates.length > 0 ? subordinates.map((s) => s.display_name).join(", ") : "Spesialis Eksekusi"}`,
    `- AKSES WORKSPACE TEROTORISASI: AKTIF & TEROTORISASI untuk membaca/menganalisis folder & file proyek di dalam direktori workspace terotorisasi (zona terlarang OS, \`config/secrets\`, dan file \`.env\`/kunci rahasia diblokir otomatis).`,
    folderStore.active_folder ? `- Folder Target Aktif Saat Ini: \`${folderStore.active_folder}\`` : null,
    `- INTEGRASI TELEGRAM OWNER: TERHUBUNG AKTIF melalui bot resmi \`${TELEGRAM_BOT_USERNAME}\`.`,
    `- Rekan 11 Agen: ${teamSummary}`,
    agentTasks.length > 0
      ? `- Riwayat Task Paperclip Anda: ${agentTasks.map((t) => `${t.identifier || String(t.id).slice(0, 8)} [${t.status}] "${t.title}"`).join(" | ")}`
      : null,
    explicitPathWarning
      ? `\nPERINGATAN PATH DARI SISTEM: Path yang diminta pengguna tidak dapat diakses karena: ${explicitPathWarning}. Jelaskan alasan tersebut secara sopan.`
      : null,
    skillTurn && skillTurn.skillExcerpt
      ? `\n=== METODOLOGI SKILL RESMI YANG DIMUAT (${skillTurn.chosenSkill.display_name} — ${skillTurn.chosenSkill.pkg_id}) ===\n${skillTurn.skillExcerpt}\n${skillTurn.scriptOutput || ""}\nINSTRUKSI SKILL: Terapkan kerangka metodologi sesuai batas peran Anda (${skillTurn.chosenSkill.known_limitations}).`
      : null,
    deepContextBlock
      ? `\n${deepContextBlock}\nINSTRUKSI WAJIB: Data folder/file di atas adalah hasil pembacaan NYATA langsung dari disk! Sajikan isi folder, sub-folder, file utama, stack teknologi, dan analisis arsitekturnya secara rinci dan akurat.`
      : null,
    executionReceipts.length > 0
      ? [
          ``,
          `=== BUKTI EKSEKUSI SISTEM NYATA PADA GILIRAN INI ===`,
          ...executionReceipts.map((r, idx) => `${idx + 1}. ${r}`),
          `INSTRUKSI PENTING: Seluruh tindakan di atas SUDAH BERHASIL DIEKSEKUSI SECARA NYATA sekarang juga! Laporkan secara jelas dan terstruktur kepada Owner.`,
        ].join("\n")
      : null,
    `Aturan wajib: Jawab secara jelas, membantu, dan profesional dalam bahasa pengguna. Jangan pernah membocorkan kredensial/API key.`,
  ]
    .filter(Boolean)
    .join("\n");

  const cleanHistoryForPrompt = priorHistory.filter(
    (m) => !(m.role === "assistant" && FALSE_REFUSAL_RE.test(String(m.content || "")))
  );

  let replyText;
  try {
    replyText = await callLlmCompletion(systemPrompt, cleanHistoryForPrompt, cleanUserMsg, {
      fastActionReply: executionReceipts.length > 0,
      rejectFalseRefusal: Boolean(deepInspection?.ok || executionReceipts.length > 0 || !explicitPathWarning),
    });
    if (deepInspection?.ok) {
      const sampleMarkers =
        deepInspection.kind === "file"
          ? [deepInspection.name]
          : [
              ...(deepInspection.directories || []).slice(0, 5),
              ...(deepInspection.files || []).slice(0, 5).map((f) => f.name),
            ];
      const matchCount = sampleMarkers.filter(
        (m) => m && replyText.toLowerCase().includes(String(m).toLowerCase())
      ).length;
      const neededMatches = Math.min(2, sampleMarkers.length);
      if (
        matchCount < neededMatches ||
        /(saya akan segera memeriksa|saya akan menjalankan perintah untuk melihat)/i.test(replyText)
      ) {
        replyText = buildDeterministicFolderReply(agent, deepInspection, executionReceipts);
      }
    }
  } catch {
    if (deepInspection?.ok || executionReceipts.length > 0) {
      replyText = buildDeterministicFolderReply(agent, deepInspection, executionReceipts);
    } else if (explicitPathWarning) {
      replyText = `Folder atau file tersebut tidak dapat dibuka: **${explicitPathWarning}**.\n\nSilakan pilih folder proyek yang berada di dalam direktori workspace terotorisasi (\`workspaces/\`, \`reports/\`, \`docs/\`) melalui tombol **📁 Folder Target**.`;
    } else {
      replyText = `Halo, saya **${agent.display_name}** (${agent.title} — ${agent.department}). Saya terhubung penuh ke workspace terotorisasi, Paperclip Control Plane, dan Telegram Gateway (\`${TELEGRAM_BOT_USERNAME}\`). Silakan pilih folder melalui tombol **📁 Folder Target** atau kirim path proyek untuk kita analisis bersama!`;
    }
  }

  const nowMs = Date.now();
  appendAgentChatMessages(agent.paperclip_agent_id, [
    { role: "user", content: cleanUserMsg, timestamp: nowMs - 1 },
    { role: "assistant", content: replyText, timestamp: nowMs },
  ]);

  return {
    text: replyText,
    createdTask,
    createdMeeting,
    ensuredProject,
    inspectedTarget: deepInspection?.ok ? deepInspection.resolved_path : null,
    executionReceipts,
  };
}

module.exports = {
  readAgentChatHistory,
  appendAgentChatMessages,
  clearAgentChatHistory,
  extractTargetProjectPath,
  shouldCreatePaperclipTask,
  analyzeOwnerActionIntent,
  handleEmployeeChatTurn,
};
