"use strict";

/**
 * PHASE 02 — Unified Telegram Command Architecture, Canonical Registry,
 * Parameter Schema Validator, Idempotency Store, Cancellation Tokens & Execution Receipts.
 *
 * Cross-platform portable (`contracts/paths.js`) with all 13 CODEXE categories and 159 command/alias slugs.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { OFFICE_DATA_DIR } = require("../contracts/paths");
const { sanitizeText, sanitizePayload } = require("../contracts/redaction");

const IDEMPOTENCY_FILE = path.resolve(path.join(OFFICE_DATA_DIR, "telegram-idempotency.json"));
const STATE_VERSION_FILE = path.resolve(path.join(OFFICE_DATA_DIR, "telegram-state-version.json"));

/**
 * Canonical 13 Command Center Categories (`CODEXE — AI COMPANY`)
 */
const MENU_CATEGORIES = Object.freeze({
  AGENTS: { id: "agents", label: "👥 AGENTS", description: "11 Agen AI, Pemilihan, Chat & Inspector" },
  CEO_TASKS: { id: "ceo", label: "🧠 CEO / TASKS", description: "Instruksi CEO & Delegasi Multi-Agen" },
  OFFICE: { id: "office", label: "🏢 OFFICE 3D / 2D", description: "Ruangan, Lokasi Agen, Render & Screenshot" },
  MEETING: { id: "meeting", label: "🗣 MEETING", description: "Lifecycle Rapat 11 Agen, Diskusi & Notulen" },
  FOLDERS: { id: "folders", label: "📁 LOCAL FOLDERS", description: "Explorer Workspace, Pilih Target & Analisis Kode" },
  DEVELOPMENT: { id: "dev", label: "💻 DEVELOPMENT", description: "Coding, Git Branch, Build, Test & Diff" },
  PAPERCLIP: { id: "paperclip", label: "📋 PAPERCLIP", description: "Projects, Kanban UNI-*, Subtasks & Progress" },
  ANALYTICS: { id: "analytics", label: "📊 ANALYTICS", description: "Token, Biaya, Performa & Riwayat Run" },
  BUDGETS: { id: "budgets", label: "💰 BUDGETS", description: "Batas Harian/Bulanan, Alert & Governance" },
  SECURITY: { id: "security", label: "🛡 SECURITY", description: "VulnClaw Defensif, Triage & Remediasi" },
  APPROVALS: { id: "approvals", label: "✅ APPROVALS", description: "Persetujuan Owner, Risiko & Riwayat" },
  HEALTH: { id: "health", label: "🩺 HEALTH", description: "15 Komponen, Error Logs & Pemulihan Aman" },
  SYSTEM: { id: "system", label: "⚙ SYSTEM", description: "Auto-Update Terjadwal, Scheduler & Jobs" },
});

/**
 * Canonical Command Definitions (Single Source of Truth for Slash, Callback & Natural Language)
 */
const CANONICAL_COMMANDS = Object.freeze([
  // --- Control Center & Navigation ---
  {
    id: "kantor",
    aliases: ["menu", "menu_kantor", "help_platform", "home", "dashboard"],
    category: "SYSTEM",
    description: "Pusat kendali utama CODEXE — AI COMPANY (13 submenu interaktif)",
    args_schema: { required: false, max_len: 120 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "low",
  },
  {
    id: "submenu",
    aliases: ["nav_menu"],
    category: "SYSTEM",
    description: "Buka salah satu dari 13 submenu pusat kendali Telegram",
    args_schema: { required: true, max_len: 80 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "low",
  },

  // --- Agents (Phase 05) ---
  {
    id: "agen",
    aliases: ["agents", "daftar_agen"],
    category: "AGENTS",
    description: "Daftar lengkap 11 agen AI beserta status aktivasi, lokasi 3D/2D & task",
    args_schema: { required: false, max_len: 60 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "low",
  },
  {
    id: "pilih",
    aliases: ["select_agent", "ganti_agen"],
    category: "AGENTS",
    description: "Pilih/ganti agen aktif di Telegram (1..11, @handle, slug, atau nama)",
    args_schema: { required: false, max_len: 80 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "normal",
  },
  {
    id: "lepas",
    aliases: ["release_agent", "umum"],
    category: "AGENTS",
    description: "Keluar dari kunci chat agen kembali ke mode Hermes umum",
    args_schema: { required: false, max_len: 40 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 10_000,
    risk_level: "low",
  },
  {
    id: "info_agen",
    aliases: ["agent_detail", "profil_agen", "inspector"],
    category: "AGENTS",
    description: "Detail lengkap profil, model, kapabilitas, sesi & antrean agen",
    args_schema: { required: false, max_len: 80 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "low",
  },
  {
    id: "chat",
    aliases: ["chat_agent", "bicara"],
    category: "AGENTS",
    description: "Kirim pesan atau instruksi ke agen yang sedang dipilih",
    args_schema: { required: true, min_len: 1, max_len: 4000 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 85_000,
    risk_level: "normal",
    idempotent: true,
  },
  {
    id: "ke",
    aliases: ["ask_agent", "kirim_agen"],
    category: "AGENTS",
    description: "Kirim pesan/tugas langsung ke agen tertentu tanpa mengubah agen aktif permanen",
    args_schema: { required: true, min_len: 3, max_len: 4000 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 85_000,
    risk_level: "normal",
    idempotent: true,
  },
  {
    id: "reset_sesi",
    aliases: ["reset_chat", "resume_sesi", "sesi_agen"],
    category: "AGENTS",
    description: "Lihat atau bersihkan riwayat sesi percakapan terisolasi per agen",
    args_schema: { required: false, max_len: 80 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 10_000,
    risk_level: "normal",
  },
  {
    id: "daftar_skill",
    aliases: ["skills", "skill_agen", "agen_skills"],
    category: "AGENTS",
    description: "Daftar skills spesialisasi seluruh 11 agen atau agen tertentu (read-only)",
    args_schema: { required: false, max_len: 120 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "low",
  },
  {
    id: "skill_info",
    aliases: ["info_skill", "detail_skill"],
    category: "AGENTS",
    description: "Detail lengkap sumber GitHub, commit SHA, lisensi, dependensi & penggunaan skill agen",
    args_schema: { required: true, min_len: 2, max_len: 160 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "low",
  },
  {
    id: "skill_status",
    aliases: ["status_skill", "skills_status"],
    category: "AGENTS",
    description: "Status global registry skill, security gate Sentry, dan ringkasan 11 agen",
    args_schema: { required: false, max_len: 80 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "low",
  },

  // --- Lifecycle & CEO Delegation (Phase 06) ---
  {
    id: "bangunkan",
    aliases: ["aktifkan", "wake_agent"],
    category: "CEO_TASKS",
    description: "Aktifkan agen Standby (1..11, nama, atau semua)",
    args_schema: { required: false, max_len: 80 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 30_000,
    risk_level: "normal",
  },
  {
    id: "istirahatkan",
    aliases: ["pause_agen", "pause_agent"],
    category: "CEO_TASKS",
    description: "Pindahkan agen ke mode Standby (graceful)",
    args_schema: { required: false, max_len: 80 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 25_000,
    risk_level: "normal",
  },
  {
    id: "standar_wave1",
    aliases: ["resume_wave1", "wave1"],
    category: "CEO_TASKS",
    description: "Pulihkan formasi standar 4 agen Wave-1 ACTIVE dan 7 agen Wave-2 STANDBY",
    args_schema: { required: false, max_len: 40 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 30_000,
    risk_level: "normal",
  },
  {
    id: "stop_semua",
    aliases: ["emergency_stop"],
    category: "CEO_TASKS",
    description: "Hentikan terkendali seluruh run aktif & pindahkan agen ke Standby",
    args_schema: { required: false, max_len: 80 },
    permission: "owner_critical",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 35_000,
    risk_level: "sensitive",
  },
  {
    id: "pause_dispatch",
    aliases: ["tahan_dispatch", "resume_dispatch"],
    category: "CEO_TASKS",
    description: "Tahan atau buka pengiriman pekerjaan baru tanpa mematikan run yang sedang berjalan",
    args_schema: { required: false, max_len: 40 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "normal",
  },
  {
    id: "delegasi",
    aliases: ["ceo_delegasi", "bagi_tugas"],
    category: "CEO_TASKS",
    description: "Instruksikan CEO membagi pekerjaan ke beberapa agen spesialis (parent + child subtasks)",
    args_schema: { required: true, min_len: 5, max_len: 3000 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "async",
    timeout_ms: 60_000,
    risk_level: "normal",
    idempotent: true,
  },

  // --- 3D & 2D Office Remote Control (Phase 07) ---
  {
    id: "status_kantor",
    aliases: ["office_status", "ruangan", "lokasi_agen", "cek_render"],
    category: "OFFICE",
    description: "Status live 3D & 2D Office, daftar ruangan, posisi 11 agen & kesiapan render",
    args_schema: { required: false, max_len: 120 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 20_000,
    risk_level: "low",
  },
  {
    id: "screenshot_kantor",
    aliases: ["office_screenshot", "foto_kantor"],
    category: "OFFICE",
    description: "Ambil screenshot nyata tampilan 3D atau 2D Virtual Office dan kirim ke Telegram",
    args_schema: { required: false, max_len: 40 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "async",
    timeout_ms: 45_000,
    risk_level: "low",
  },

  // --- Full 11-Agent Meeting Lifecycle (Phase 08) ---
  {
    id: "meeting_menu",
    aliases: ["menu_rapat"],
    category: "MEETING",
    description: "Submenu kontrol Ruang Meeting 11 Agen (3D & 2D)",
    args_schema: { required: false, max_len: 80 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 10_000,
    risk_level: "low",
  },
  {
    id: "meeting",
    aliases: ["meeting_start", "mulai_rapat", "rapat"],
    category: "MEETING",
    description: "Buat & jalankan meeting 11 agen (atau terpilih) di Ruang Meeting 3D & 2D",
    args_schema: { required: false, max_len: 1500 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 45_000,
    risk_level: "normal",
    idempotent: true,
  },
  {
    id: "status_meeting",
    aliases: ["cek_meeting", "kehadiran_rapat"],
    category: "MEETING",
    description: "Lihat lifecycle state rapat, kehadiran 11/11 agen, antrean bicara & agenda",
    args_schema: { required: false, max_len: 80 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "low",
  },
  {
    id: "diskusi_rapat",
    aliases: ["tanya_rapat", "bahas_rapat"],
    category: "MEETING",
    description: "Jalankan diskusi Bahasa Indonesia atau tanya agen tertentu di dalam rapat aktif",
    args_schema: { required: false, max_len: 2000 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 60_000,
    risk_level: "normal",
  },
  {
    id: "notulen",
    aliases: ["ringkasan_rapat", "riwayat_meeting", "tindak_lanjut_rapat"],
    category: "MEETING",
    description: "Hasilkan/lihat notulen rapat, keputusan, action items & riwayat meeting",
    args_schema: { required: false, max_len: 200 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 35_000,
    risk_level: "low",
  },
  {
    id: "selesai_meeting",
    aliases: ["meeting_end", "tutup_rapat", "batal_meeting"],
    category: "MEETING",
    description: "Selesaikan atau batalkan rapat & kembalikan 11 agen ke workstation 3D/2D",
    args_schema: { required: false, max_len: 500 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 25_000,
    risk_level: "normal",
  },

  // --- Workspace Explorer & Source Code Analysis (Phases 09 & 10) ---
  {
    id: "folder",
    aliases: ["folders_status"],
    category: "FOLDERS",
    description: "Status folder target aktif, daftar folder tersimpan & akses cepat workspace",
    args_schema: { required: false, max_len: 500 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "low",
  },
  {
    id: "jelajah",
    aliases: ["folder_browse"],
    category: "FOLDERS",
    description: "Telusuri direktori workspace dengan pagination, parent nav & deteksi stack",
    args_schema: { required: false, max_len: 500 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "low",
  },
  {
    id: "cari_folder",
    aliases: ["folder_search", "meta_folder"],
    category: "FOLDERS",
    description: "Cari subfolder proyek atau lihat struktur & metadata file secara aman",
    args_schema: { required: true, min_len: 1, max_len: 300 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "low",
  },
  {
    id: "pilih_folder",
    aliases: ["folder_select", "tambah_folder"],
    category: "FOLDERS",
    description: "Tambahkan & jadikan folder workspace sebagai folder target aktif",
    args_schema: { required: true, min_len: 2, max_len: 500 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "normal",
  },
  {
    id: "analisis",
    aliases: ["analisis_folder", "folder_analyze", "audit_kode"],
    category: "FOLDERS",
    description: "Analisis source code nyata, arsitektur, dependensi & simpan laporan terverifikasi",
    args_schema: { required: false, max_len: 1500 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "async",
    timeout_ms: 85_000,
    risk_level: "normal",
    idempotent: true,
  },

  // --- Software Development Control (Phase 11) ---
  {
    id: "dev",
    aliases: ["dev_task", "git_status", "buat_branch", "jalankan_test", "cek_diff", "review_kode", "build_project"],
    category: "DEVELOPMENT",
    description: "Kontrol development end-to-end (branch, coding, build, testing, git diff & QA review)",
    args_schema: { required: false, max_len: 2500 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "async",
    timeout_ms: 85_000,
    risk_level: "normal",
    idempotent: true,
  },

  // --- Paperclip Project & Kanban Control (Phase 12) ---
  {
    id: "projects",
    aliases: ["buat_project", "pilih_project", "progress_project"],
    category: "PAPERCLIP",
    description: "Kelola project Paperclip (daftar, buat baru, pilih project aktif & progress %)",
    args_schema: { required: false, max_len: 400 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 25_000,
    risk_level: "normal",
  },
  {
    id: "buat_task",
    aliases: ["create_task"],
    category: "PAPERCLIP",
    description: "Buat task baru di Paperclip lengkap dengan agen, prioritas & verifikasi read-after-write",
    args_schema: { required: true, min_len: 3, max_len: 2500 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 30_000,
    risk_level: "normal",
    idempotent: true,
  },
  {
    id: "daftar_task",
    aliases: ["tasks"],
    category: "PAPERCLIP",
    description: "Daftar task Kanban Paperclip dengan filter status & pagination",
    args_schema: { required: false, max_len: 120 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "low",
  },
  {
    id: "cek_task",
    aliases: ["task_status", "subtasks"],
    category: "PAPERCLIP",
    description: "Detail task Paperclip, subtasks, komentar aktivitas & run eksekusi",
    args_schema: { required: true, min_len: 2, max_len: 120 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "low",
  },
  {
    id: "ubah_task",
    aliases: ["pause_task", "resume_task", "cancel_task", "selesai_task", "done_task", "assign_task", "prioritas_task"],
    category: "PAPERCLIP",
    description: "Perbarui status, penugasan, atau prioritas task Paperclip (read-after-write verified)",
    args_schema: { required: true, min_len: 2, max_len: 500 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 25_000,
    risk_level: "normal",
  },

  // --- Analytics & Budgets (Phases 13 & 14) ---
  {
    id: "analytics",
    aliases: ["biaya", "statistik"],
    category: "ANALYTICS",
    description: "Analytics valid (Today, Yesterday, 7d, 30d, Per-Agent, Per-Model, Cost, Runs, History)",
    args_schema: { required: false, max_len: 120 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 20_000,
    risk_level: "low",
  },
  {
    id: "budget",
    aliases: ["budgets", "info_budget"],
    category: "BUDGETS",
    description: "Lihat pagu anggaran perusahaan, harian, bulanan, per-agen, alert & riwayat keputusan",
    args_schema: { required: false, max_len: 120 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "low",
  },
  {
    id: "set_budget",
    aliases: ["atur_budget"],
    category: "BUDGETS",
    description: "Atur batas anggaran harian/bulanan/per-agen dengan validasi ceiling & audit trail",
    args_schema: { required: true, min_len: 3, max_len: 160 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "sensitive",
  },

  // --- Governance Approvals (Phase 15) ---
  {
    id: "persetujuan",
    aliases: ["approvals", "detail_persetujuan"],
    category: "APPROVALS",
    description: "Daftar & detail permintaan approval Paperclip/Hermes beserta kategori risiko",
    args_schema: { required: false, max_len: 120 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "low",
  },
  {
    id: "setujui",
    aliases: ["approve_id"],
    category: "APPROVALS",
    description: "Setujui permintaan approval spesifik dengan validasi state & anti-replay",
    args_schema: { required: true, min_len: 3, max_len: 300 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 20_000,
    risk_level: "sensitive",
  },
  {
    id: "tolak",
    aliases: ["reject_id"],
    category: "APPROVALS",
    description: "Tolak permintaan approval spesifik dengan catatan audit",
    args_schema: { required: true, min_len: 3, max_len: 300 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 20_000,
    risk_level: "sensitive",
  },

  // --- Defensive Security & VulnClaw (Phase 16) ---
  {
    id: "keamanan",
    aliases: ["security_report", "triage_temuan", "remediasi_temuan"],
    category: "SECURITY",
    description: "Kontrol pemeriksaan keamanan defensif VulnClaw, 8-state triage & task remediasi",
    args_schema: { required: false, max_len: 500 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "async",
    timeout_ms: 60_000,
    risk_level: "normal",
  },

  // --- Health, Recovery, Maintenance & Async Jobs (Phases 17 & 18) ---
  {
    id: "kesehatan",
    aliases: ["platform_status", "health_kantor", "diagnosa"],
    category: "HEALTH",
    description: "Pemeriksaan kesehatan aktual 15 komponen, resource host & scheduler",
    args_schema: { required: false, max_len: 120 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 25_000,
    risk_level: "low",
  },
  {
    id: "log_error",
    aliases: ["cek_log", "pulihkan_layanan"],
    category: "HEALTH",
    description: "Lihat log error terbaru (tersanitasi) atau jalankan pemulihan layanan aman (graceful drain)",
    args_schema: { required: false, max_len: 120 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 35_000,
    risk_level: "sensitive",
  },
  {
    id: "update_status",
    aliases: ["jadwal_update", "maintenance_status"],
    category: "SYSTEM",
    description: "Status pembaruan otomatis Hermes terjadwal & jadwal maintenance platform",
    args_schema: { required: false, max_len: 80 },
    permission: "owner_read",
    mutates_state: false,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "low",
  },
  {
    id: "jobs",
    aliases: ["cek_job", "batal_job"],
    category: "SYSTEM",
    description: "Pantau progress pekerjaan berdurasi panjang atau batalkan job aktif secara aman",
    args_schema: { required: false, max_len: 120 },
    permission: "owner_mutate",
    mutates_state: true,
    execution_mode: "sync",
    timeout_ms: 15_000,
    risk_level: "normal",
  },
]);

const COMMAND_LOOKUP = new Map();
for (const spec of CANONICAL_COMMANDS) {
  COMMAND_LOOKUP.set(spec.id, spec);
  for (const al of spec.aliases || []) {
    COMMAND_LOOKUP.set(al, spec);
  }
}

function normalizeCommandSlug(rawCommand) {
  return String(rawCommand || "")
    .trim()
    .toLowerCase()
    .replace(/^\/+/, "")
    .replace(/@[a-z0-9_]+$/i, "")
    .replace(/-/g, "_");
}

function resolveCanonicalCommand(rawCommand) {
  const norm = normalizeCommandSlug(rawCommand);
  const spec = COMMAND_LOOKUP.get(norm) || null;
  return {
    invoked_as: norm,
    canonical_id: spec ? spec.id : null,
    spec,
  };
}

function validateCommandArguments(spec, rawArgs) {
  const args = String(rawArgs || "").trim();
  if (!spec) {
    return { ok: false, code: "UNKNOWN_COMMAND", error: "Perintah tidak terdaftar pada Canonical Command Registry." };
  }
  const schema = spec.args_schema || {};
  if (schema.required && !args) {
    return {
      ok: false,
      code: "MISSING_REQUIRED_ARGUMENT",
      error: `Perintah '/${spec.id}' memerlukan parameter argumen.`,
    };
  }
  if (schema.min_len && args.length > 0 && args.length < schema.min_len) {
    return {
      ok: false,
      code: "ARGUMENT_TOO_SHORT",
      error: `Parameter untuk '/${spec.id}' terlalu pendek (minimal ${schema.min_len} karakter).`,
    };
  }
  if (schema.max_len && args.length > schema.max_len) {
    return {
      ok: false,
      code: "ARGUMENT_TOO_LONG",
      error: `Parameter untuk '/${spec.id}' melebihi batas aman (${schema.max_len} karakter).`,
    };
  }
  if (args.includes("\0")) {
    return { ok: false, code: "NULL_BYTE_REJECTED", error: "Karakter null-byte tidak diizinkan." };
  }
  return { ok: true, normalized_args: args };
}

function nextStateVersion(mutated = false) {
  let current = 1;
  try {
    if (fs.existsSync(STATE_VERSION_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(STATE_VERSION_FILE, "utf8"));
      current = Number(parsed.version) || 1;
    }
  } catch {}
  if (mutated) {
    current += 1;
    try {
      fs.mkdirSync(path.dirname(STATE_VERSION_FILE), { recursive: true, mode: 0o700 });
      fs.writeFileSync(
        STATE_VERSION_FILE,
        JSON.stringify({ version: current, updated_at: new Date().toISOString() }, null, 2) + "\n",
        "utf8"
      );
    } catch {}
  }
  return current;
}

function generateCorrelationId(prefix = "uac") {
  return `${prefix}-${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}`;
}

function loadIdempotencyStore() {
  try {
    if (fs.existsSync(IDEMPOTENCY_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(IDEMPOTENCY_FILE, "utf8"));
      if (parsed && typeof parsed.entries === "object") return parsed;
    }
  } catch {}
  return { entries: {} };
}

function checkIdempotency(key, ttlMs = 10 * 60 * 1000) {
  if (!key) return null;
  const store = loadIdempotencyStore();
  const entry = store.entries[key];
  if (!entry) return null;
  if (Date.now() - Number(entry.stored_at_ms || 0) > ttlMs) {
    return null;
  }
  return entry.response || null;
}

function saveIdempotency(key, response) {
  if (!key || !response || response.ok === false) return;
  try {
    const store = loadIdempotencyStore();
    const now = Date.now();
    const entries = Object.entries(store.entries || {}).filter(([, v]) => now - Number(v.stored_at_ms || 0) < 3600_000);
    const trimmed = Object.fromEntries(entries.slice(-300));
    trimmed[key] = {
      stored_at_ms: now,
      response: sanitizePayload(response),
    };
    fs.mkdirSync(path.dirname(IDEMPOTENCY_FILE), { recursive: true, mode: 0o700 });
    fs.writeFileSync(IDEMPOTENCY_FILE, JSON.stringify({ entries: trimmed }, null, 2) + "\n", "utf8");
  } catch {}
}

const ACTIVE_CANCELLATIONS = new Map();

function registerCancellableOperation(operationId) {
  const controller = new AbortController();
  ACTIVE_CANCELLATIONS.set(operationId, {
    controller,
    started_at: new Date().toISOString(),
  });
  return controller;
}

function cancelOperation(operationId) {
  const item = ACTIVE_CANCELLATIONS.get(operationId);
  if (!item) return false;
  try {
    item.controller.abort(new Error(`Cancelled by Owner: ${operationId}`));
  } catch {}
  ACTIVE_CANCELLATIONS.delete(operationId);
  return true;
}

function finishCancellableOperation(operationId) {
  ACTIVE_CANCELLATIONS.delete(operationId);
}

function buildExecutionReceipt({
  correlationId,
  command,
  invokedAs,
  mutated = false,
  executionStatus = "COMPLETED",
  exitCode = 0,
  taskId = null,
  runId = null,
  meetingId = null,
  agentId = null,
  targetWorkspace = null,
  evidenceRef = null,
  stateVersion = null,
}) {
  const ver = stateVersion !== null ? stateVersion : nextStateVersion(mutated);
  return sanitizePayload({
    correlation_id: correlationId || generateCorrelationId(),
    command,
    invoked_as: invokedAs || command,
    execution_status: executionStatus,
    exit_code: exitCode,
    state_version: ver,
    timestamp: new Date().toISOString(),
    task_id: taskId,
    run_id: runId,
    meeting_id: meetingId,
    agent_id: agentId,
    target_workspace: targetWorkspace,
    evidence_ref: evidenceRef,
  });
}

function buildStructuredError({
  correlationId,
  command,
  code = "EXECUTION_ERROR",
  status = 400,
  message = "Terjadi kesalahan saat memproses perintah.",
  inlineKeyboard = undefined,
}) {
  const cleanMsg = sanitizeText(String(message));
  return {
    ok: false,
    status,
    error_code: code,
    error: cleanMsg,
    correlation_id: correlationId || generateCorrelationId("err"),
    timestamp: new Date().toISOString(),
    reply: `⚠️ *${code}*\n${cleanMsg}`,
    ...(inlineKeyboard ? { inline_keyboard: inlineKeyboard } : {}),
  };
}

module.exports = {
  MENU_CATEGORIES,
  CANONICAL_COMMANDS,
  COMMAND_LOOKUP,
  normalizeCommandSlug,
  resolveCanonicalCommand,
  validateCommandArguments,
  nextStateVersion,
  generateCorrelationId,
  checkIdempotency,
  saveIdempotency,
  registerCancellableOperation,
  cancelOperation,
  finishCancellableOperation,
  buildExecutionReceipt,
  buildStructuredError,
};
