"use strict";

/**
 * PHASE 04 — CODEXE — AI COMPANY Interactive Telegram Command Center UI
 *
 * Implements all 13 target submenus, context summary header, pagination,
 * Back / Home / Refresh navigation, and <=64-byte callback payload enforcement.
 * Zero hardcoded URLs, bot handles, or project names.
 */

const path = require("node:path");
const { HERMES3D_BASE_URL, TELEGRAM_BOT_USERNAME, resolveTimezone } = require("../contracts/paths");
const { sanitizeText } = require("../contracts/redaction");

function clampCallback(cb) {
  const s = String(cb || "uac:home");
  return s.length <= 64 ? s : s.slice(0, 64);
}

function btn(text, callbackData) {
  return {
    text: String(text || "Action").slice(0, 38),
    callback_data: clampCallback(callbackData),
  };
}

function navFooter({ backTo = "uac:home", refreshCb = null } = {}) {
  const row = [];
  if (backTo && backTo !== "uac:home") {
    row.push(btn("⬅️ Back", backTo));
  }
  if (refreshCb) {
    row.push(btn("🔄 Refresh", refreshCb));
  }
  row.push(btn("🏠 Home", "uac:home"));
  return row;
}

function paginationRow({ prefix, page, totalPages, extraParam = "" }) {
  if (totalPages <= 1) return null;
  const p = Math.max(1, Math.min(totalPages, Number(page) || 1));
  const suffix = extraParam ? `:${extraParam}` : "";
  const row = [];
  if (p > 1) {
    row.push(btn(`◀ Prev (${p - 1}/${totalPages})`, `${prefix}:${p - 1}${suffix}`));
  }
  row.push(btn(`📄 Hal ${p}/${totalPages}`, `uac:noop`));
  if (p < totalPages) {
    row.push(btn(`Next (${p + 1}/${totalPages}) ▶`, `${prefix}:${p + 1}${suffix}`));
  }
  return row;
}

function paginateItems(items, page = 1, perPage = 6) {
  const arr = Array.isArray(items) ? items : [];
  const total = arr.length;
  const totalPages = Math.max(1, Math.ceil(total / perPage));
  const safePage = Math.max(1, Math.min(totalPages, Number(page) || 1));
  const start = (safePage - 1) * perPage;
  return {
    slice: arr.slice(start, start + perPage),
    page: safePage,
    totalPages,
    total,
    start,
  };
}

function buildContextHeader({ tgState, snap, folderStatus, activeMeeting, runningJobsCount = 0 }) {
  const agents = snap?.agents || [];
  const activeCount = agents.filter((a) => a.activation_status === "ACTIVE").length;
  const runningTasks = (snap?.tasks || []).filter((t) => t.status === "in_progress" || t.status === "todo").length;
  const pendingApps = (snap?.approvals || []).filter((a) => a.status === "pending").length;

  const agentIndicator = tgState?.direct_agent_mode
    ? `🎯 *${tgState.selected_agent_name}* (\`LOCKED ON\`)`
    : `👤 *${tgState?.selected_agent_name || "CEO Agent"}* (\`Mode Umum\`)`;
  const folderIndicator = folderStatus?.active_folder
    ? `\`${folderStatus.active_folder}\``
    : "`(belum dipilih)`";
  const meetingIndicator = activeMeeting
    ? `🟢 \`${activeMeeting.lifecycle_state || activeMeeting.status}\` — *${sanitizeText(activeMeeting.title).slice(0, 34)}* (\`${(activeMeeting.participants || []).length}/11\`)`
    : "⚪ `IDLE` (di meja departemen)";

  return [
    `🏢 *CODEXE — AI COMPANY*`,
    `────────────────────────`,
    `• *Agen:* ${agentIndicator} • \`${activeCount}/11 ACTIVE\``,
    `• *Folder Aktif:* ${folderIndicator}`,
    `• *Meeting 3D/2D:* ${meetingIndicator}`,
    `• *Antrean Kerja:* \`${runningTasks} task aktif\` • \`${runningJobsCount} async job\` • \`${pendingApps} approval\``,
  ].join("\n");
}

function buildCodexeHomeKeyboard(tgState, hasActiveMeeting) {
  const agentBtnLabel = tgState?.direct_agent_mode
    ? `👥 AGENTS (${tgState.selected_agent_name.split(" ")[0]} ✓)`
    : "👥 AGENTS (11)";
  const meetBtnLabel = hasActiveMeeting ? "🗣 MEETING (🟢 AKTIF)" : "🗣 MEETING";
  return [
    [btn(agentBtnLabel, "uac:sub:agents"), btn("🧠 CEO / TASKS", "uac:sub:ceo")],
    [btn("🏢 OFFICE 3D / 2D", "uac:sub:office"), btn(meetBtnLabel, "uac:sub:meeting")],
    [btn("📁 LOCAL FOLDERS", "uac:sub:folders"), btn("💻 DEVELOPMENT", "uac:sub:dev")],
    [btn("📋 PAPERCLIP", "uac:sub:paperclip"), btn("📊 ANALYTICS", "uac:sub:analytics")],
    [btn("💰 BUDGETS", "uac:sub:budgets"), btn("🛡 SECURITY", "uac:sub:security")],
    [btn("✅ APPROVALS", "uac:sub:approvals"), btn("🩺 HEALTH", "uac:sub:health")],
    [btn("⚙ SYSTEM", "uac:sub:system"), btn("🔄 REFRESH", "uac:home")],
  ];
}

function buildSubmenuView(submenuId, context) {
  const { tgState, snap, folderStatus, activeMeeting, runningJobsCount = 0, dispatchPaused = false } = context;
  const header = buildContextHeader({ tgState, snap, folderStatus, activeMeeting, runningJobsCount });
  const key = String(submenuId || "").toLowerCase();
  const tz = resolveTimezone(process.env);
  const officeUrl = `${HERMES3D_BASE_URL}/office`;

  switch (key) {
    case "ceo": {
      const dispatchBadge = dispatchPaused ? "🔴 PAUSED" : "🟢 OPEN";
      return {
        reply: [
          header,
          ``,
          `🧠 *SUBMENU: CEO & MULTI-AGENT ORCHESTRATION*`,
          `• *Status Dispatch:* \`${dispatchBadge}\``,
          `• *Cara Delegasi CEO:*`,
          `  \`/delegasi Audit folder workspace aktif ke CTO, Backend, QA, dan Security\``,
          `  atau ketik bahasa alami langsung ke CEO!`,
        ].join("\n"),
        inline_keyboard: [
          [btn("👔 Pilih CEO Agent (Chat)", "uac:pick:1"), btn("🚀 Delegasi Audit Folder Aktif", "uac:ceo_del_active")],
          [btn("⚡ Bangunkan Semua 11 Agen", "uac:wake_all"), btn("🔄 Formasi Standar Wave-1", "uac:wave1")],
          [
            btn(dispatchPaused ? "▶️ Buka Dispatch Baru" : "⏸️ Tahan Dispatch Baru", dispatchPaused ? "uac:disp:resume" : "uac:disp:pause"),
            btn("🛑 Emergency Stop (Confirm)", "uac:stop_ask"),
          ],
          navFooter({ backTo: "uac:home", refreshCb: "uac:sub:ceo" }),
        ],
      };
    }

    case "office": {
      return {
        reply: [
          header,
          ``,
          `🏢 *SUBMENU: VIRTUAL OFFICE 3D & 2D REMOTE CONTROL*`,
          `• *URL Office:* \`${officeUrl}\` (3D Three.js & 2D Pixel Phaser)`,
          `• *Kontrol Penuh:* Lihat 8 ruangan departemen, posisi 11 agen, status render 3D/2D, atau minta tangkapan layar (screenshot) live ke Telegram.`,
        ].join("\n"),
        inline_keyboard: [
          [btn("🏛️ Daftar 8 Ruangan & Okupansi", "uac:off:rooms"), btn("📍 Posisi Live 11 Agen", "uac:off:locs")],
          [btn("🖥️ Cek Status Render 3D & 2D", "uac:off:render"), btn("🔗 Info Link & Akses Lokal", "uac:off:link")],
          [btn("📸 Screenshot 3D Office", "uac:shot:3d"), btn("📸 Screenshot 2D Pixel", "uac:shot:2d")],
          [
            btn(activeMeeting ? "🏁 Bubarkan Ruang Meeting" : "🗣 Kumpulkan 11 Agen ke Meeting", activeMeeting ? "uac:meet_end" : "uac:meet_all"),
          ],
          navFooter({ backTo: "uac:home", refreshCb: "uac:sub:office" }),
        ],
      };
    }

    case "meeting": {
      const fBase = folderStatus?.active_folder ? path.basename(folderStatus.active_folder) : null;
      return {
        reply: [
          header,
          ``,
          `🗣 *SUBMENU: 11-AGENT MEETING LIFECYCLE (3D & 2D)*`,
          activeMeeting
            ? `• *Rapat Aktif:* \`${activeMeeting.meeting_id}\` (\`${activeMeeting.lifecycle_state || activeMeeting.status}\`)\n• *Agenda:* ${sanitizeText(activeMeeting.agenda || activeMeeting.title).slice(0, 180)}`
            : `• Saat ini tidak ada rapat aktif. Seluruh 11 agen siap dikumpulkan ke Ruang Meeting 3D & 2D.`,
          `• Perintah cepat: \`/meeting <topik>\`, \`/status_meeting\`, \`/diskusi_rapat <topik>\`, \`/tanya_rapat <agen> | <tanya>\`, \`/notulen\`, \`/selesai_meeting\`.`,
        ].join("\n"),
        inline_keyboard: [
          [
            btn("🗣 Mulai Rapat 11 Agen", "uac:meet_all"),
            ...(fBase ? [btn(`📁 Rapat ${fBase.slice(0, 16)}`, "uac:meet_active_folder")] : [btn("📋 Status Kehadiran", "uac:meet:status")]),
          ],
          [btn("💬 Jalankan Diskusi Bahasa Indonesia", "uac:meet:discuss"), btn("📝 Buat Notulen & Action Items", "uac:meet:minutes")],
          [btn("📜 Riwayat Sesi Meeting", "uac:meet:history"), btn("🏁 Selesaikan Rapat", "uac:meet_end")],
          navFooter({ backTo: "uac:home", refreshCb: "uac:sub:meeting" }),
        ],
      };
    }

    case "dev": {
      const fPath = folderStatus?.active_folder || "(pilih folder dulu)";
      return {
        reply: [
          header,
          ``,
          `💻 *SUBMENU: SOFTWARE DEVELOPMENT CONTROL*`,
          `• *Workspace Target:* \`${fPath}\``,
          `• *Kebijakan Aman:* Operasi tulis memakai branch kerja terisolasi, tidak pernah mengubah \`.env\` atau menghapus perubahan uncommitted pengguna.`,
          `• Perintah: \`/git_status\`, \`/cek_diff\`, \`/buat_branch <nama>\`, \`/jalankan_test\`, \`/dev_task <instruksi>\`, \`/review_kode\`.`,
        ].join("\n"),
        inline_keyboard: [
          [btn("🌿 Git Status & Branch", "uac:dev:git"), btn("📄 Lihat Git Diff", "uac:dev:diff")],
          [btn("🔍 Analisis Struktur & Kode", "uac:anl_active"), btn("🧪 Jalankan Test Suite", "uac:dev:test")],
          [btn("🛠️ Cek Build / Syntax", "uac:dev:build"), btn("✅ Minta Review QA & CTO", "uac:dev:review")],
          navFooter({ backTo: "uac:home", refreshCb: "uac:sub:dev" }),
        ],
      };
    }

    case "paperclip": {
      const tasks = snap?.tasks || [];
      const todo = tasks.filter((t) => t.status === "todo" || t.status === "backlog").length;
      const prog = tasks.filter((t) => t.status === "in_progress" || t.status === "in_review").length;
      const blk = tasks.filter((t) => t.status === "blocked").length;
      const done = tasks.filter((t) => t.status === "done").length;
      return {
        reply: [
          header,
          ``,
          `📋 *SUBMENU: PAPERCLIP PROJECTS & KANBAN*`,
          `• *Projects:* \`${(snap?.projects || []).length}\` | *Total Issues:* \`${tasks.length}\``,
          `• *Kanban:* Todo \`${todo}\` • Running \`${prog}\` • Blocked \`${blk}\` • Done \`${done}\``,
          `• Perintah: \`/projects\`, \`/buat_project <nama>\`, \`/buat_task <agen> | <judul> | <desk>\`, \`/daftar_task\`, \`/cek_task <UNI-XX>\`.`,
        ].join("\n"),
        inline_keyboard: [
          [btn("📁 Daftar Projects & Progress", "uac:pc:projects"), btn("📋 Semua Task (Hal 1)", "uac:tasks:all:1")],
          [btn("⏳ Task Todo / Running", "uac:tasks:active:1"), btn("🚧 Task Blocked", "uac:tasks:blocked:1")],
          [btn("✅ Task Selesai (Done)", "uac:tasks:done:1"), btn("➕ Buat Task Audit Folder Aktif", "uac:pc:quick_audit")],
          navFooter({ backTo: "uac:home", refreshCb: "uac:sub:paperclip" }),
        ],
      };
    }

    case "analytics": {
      return {
        reply: [
          header,
          ``,
          `📊 *SUBMENU: ANALYTICS & PERFORMANCE INTELLIGENCE*`,
          `Pilih rentang waktu atau dimensi metrik (100% bersumber dari SQLite \`state.db\` + Paperclip Runs + Budgets):`,
        ].join("\n"),
        inline_keyboard: [
          [btn("📅 Hari Ini (Today)", "uac:anx:today"), btn("⏮️ Kemarin (Yesterday)", "uac:anx:yesterday")],
          [btn("📆 7 Hari Terakhir", "uac:anx:7d"), btn("🗓️ 30 Hari Terakhir", "uac:anx:30d")],
          [btn("👥 Per Agen (1..11)", "uac:anx:agents:1"), btn("🤖 Per Model & Provider", "uac:anx:models")],
          [btn("💵 Rincian Biaya & Tarif", "uac:anx:cost"), btn("⚡ Riwayat Runs (Hal 1)", "uac:anx:runs:1")],
          [btn("📈 Tren Historis Harian", "uac:anx:history"), btn("💰 Ringkasan Budget", "uac:sub:budgets")],
          navFooter({ backTo: "uac:home", refreshCb: "uac:sub:analytics" }),
        ],
      };
    }

    case "budgets": {
      return {
        reply: [
          header,
          ``,
          `💰 *SUBMENU: BUDGET MANAGEMENT & COST GOVERNANCE*`,
          `Mode aktif: *♾️ UNLIMITED (Tanpa Batas Harian, Bulanan & Per-Agen)*.\nAnda dapat mempertahankan mode Unlimited atau mengatur batas opsional kapan saja:`,
        ].join("\n"),
        inline_keyboard: [
          [btn("📊 Lihat Status & Utilisasi Budget", "uac:bdg:overview"), btn("👥 Status 11 Agen (Unlimited)", "uac:bdg:agents")],
          [btn("♾️ Set UNLIMITED Semua (Aktif)", "uac:bdg:set:all:unlimited")],
          [btn("💵 Opsional: Daily $25", "uac:bdg:set:daily:25"), btn("🏦 Opsional: Monthly $100", "uac:bdg:set:monthly:100")],
          [btn("🚨 Cek Agen Paused & Alerts", "uac:bdg:alerts"), btn("📜 Riwayat Audit Budget", "uac:bdg:history")],
          navFooter({ backTo: "uac:home", refreshCb: "uac:sub:budgets" }),
        ],
      };
    }

    case "security": {
      return {
        reply: [
          header,
          ``,
          `🛡 *SUBMENU: DEFENSIVE SECURITY & VULNCLAW SOC*`,
          `Pemeriksaan keamanan statis terisolasi (tanpa eksploitasi / tanpa kebocoran token):`,
        ].join("\n"),
        inline_keyboard: [
          [btn("📊 Ringkasan Temuan VulnClaw", "uac:sec:summary"), btn("🔎 Daftar Semua Temuan", "uac:sec:list:1")],
          [btn("🛡️ Scan Kode Folder Aktif", "uac:sec:scan_active"), btn("📦 Cek Risiko Dependensi & Config", "uac:sec:deps")],
          [btn("🩹 Buat Task Remediasi Temuan", "uac:sec:remediate"), btn("✅ Minta Verifikasi Security", "uac:sec:verify")],
          navFooter({ backTo: "uac:home", refreshCb: "uac:sub:security" }),
        ],
      };
    }

    case "system": {
      return {
        reply: [
          header,
          ``,
          `⚙ *SUBMENU: SYSTEM, SCHEDULER, AUTO-UPDATE & ASYNC JOBS*`,
          `• *Hermes Auto-Updater:* Harian \`03:00 (${tz})\`, \`origin/main\`, \`--no-backup\``,
          `• *Single Telegram Poller:* \`Hermes Gateway\` (\`${TELEGRAM_BOT_USERNAME}\`)`,
        ].join("\n"),
        inline_keyboard: [
          [btn(`🕒 Status Auto-Update (${tz})`, "uac:sys:updates"), btn("📅 Cek System Scheduler", "uac:sys:sched")],
          [btn("⏳ Antrean Async Jobs", "uac:sys:jobs"), btn("📜 Log Error Terbaru", "uac:sys:logs")],
          [btn("🩺 Pemeriksaan 15 Komponen", "uac:health"), btn("🔧 Pemulihan Aman (Graceful)", "uac:sys:recover")],
          navFooter({ backTo: "uac:home", refreshCb: "uac:sub:system" }),
        ],
      };
    }

    default:
      return null;
  }
}

module.exports = {
  clampCallback,
  btn,
  navFooter,
  paginationRow,
  paginateItems,
  buildContextHeader,
  buildCodexeHomeKeyboard,
  buildSubmenuView,
};
