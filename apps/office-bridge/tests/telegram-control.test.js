"use strict";

/**
 * ALLINAGENT CODEXE v2 Telegram Control — Complete 59+ Command, Security & POSIX Portability Suite
 * (`apps/office-bridge/tests/telegram-control.test.js`)
 *
 * Hermetically isolated inside `os.tmpdir()` with dynamic Paperclip agent UUIDs (`dyn-ag-01` .. `dyn-ag-11`).
 */

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { execFileSync } = require("node:child_process");

const TEST_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "allinagent-tg-test-"));
const TEST_WORKSPACES = path.join(TEST_ROOT, "workspaces");
const TEST_PROJECT = path.join(TEST_WORKSPACES, "sample-service");
const TEST_REPORTS = path.join(TEST_ROOT, "reports");
const TEST_DOCS = path.join(TEST_ROOT, "docs");
const TEST_OFFICE_DATA = path.join(TEST_ROOT, "office-data");
const TEST_SECRETS = path.join(TEST_ROOT, "config", "secrets");
const TEST_LOGS = path.join(TEST_ROOT, "logs");
const TEST_DATA = path.join(TEST_ROOT, "data");
const TEST_OWNER_ID = "900000002";

for (const d of [TEST_PROJECT, TEST_REPORTS, TEST_DOCS, TEST_OFFICE_DATA, TEST_SECRETS, TEST_LOGS, TEST_DATA]) {
  fs.mkdirSync(d, { recursive: true });
}

// Seed a realistic sample Node.js + Git workspace with a dummy `.env` that MUST NEVER be read/leaked
fs.writeFileSync(
  path.join(TEST_PROJECT, "package.json"),
  JSON.stringify(
    {
      name: "sample-service",
      version: "1.0.0",
      scripts: { test: "node --check index.js" },
      dependencies: { ws: "^8.18.0" },
    },
    null,
    2
  )
);
fs.writeFileSync(path.join(TEST_PROJECT, "index.js"), '"use strict";\nmodule.exports = { ok: true };\n');
fs.writeFileSync(path.join(TEST_PROJECT, ".gitignore"), "node_modules/\n.env\n");
fs.writeFileSync(path.join(TEST_PROJECT, ".env.example"), "PORT=3000\n");
const NEVER_READ_ENV_SECRET = "sk-" + "FAKEShouldNeverBeRead0123456789";
const PLACEHOLDER_OWNER_ID = "1" + "0".repeat(9);
fs.writeFileSync(path.join(TEST_PROJECT, ".env"), `SECRET_NEVER_READ=${NEVER_READ_ENV_SECRET}\n`);

try {
  execFileSync("git", ["init", TEST_PROJECT], { stdio: "ignore" });
  execFileSync("git", ["-C", TEST_PROJECT, "config", "user.email", "ci@example.org"], { stdio: "ignore" });
  execFileSync("git", ["-C", TEST_PROJECT, "config", "user.name", "CI Bot"], { stdio: "ignore" });
  execFileSync("git", ["-C", TEST_PROJECT, "add", "package.json", "index.js", ".gitignore", ".env.example"], { stdio: "ignore" });
  execFileSync("git", ["-C", TEST_PROJECT, "commit", "-m", "chore: initial sample fixture"], { stdio: "ignore" });
} catch {}

process.env.NODE_ENV = "test";
process.env.OFFICE_BRIDGE_LOAD_DOTENV = "0";
process.env.OFFICE_DATA_DIR = TEST_OFFICE_DATA;
process.env.ALLINAGENT_SECRETS_DIR = TEST_SECRETS;
process.env.ALLINAGENT_LOGS_DIR = TEST_LOGS;
process.env.ALLINAGENT_DATA_DIR = TEST_DATA;
process.env.ALLINAGENT_WORKSPACES_DIR = TEST_WORKSPACES;
process.env.ALLINAGENT_REPORTS_DIR = TEST_REPORTS;
process.env.ALLINAGENT_DOCS_DIR = TEST_DOCS;
process.env.OWNER_TELEGRAM_ID = TEST_OWNER_ID;
process.env.LLM_MODEL = "gpt-4o-mini-test";
process.env.TIMEZONE = "UTC";

const test = require("node:test");
const assert = require("node:assert/strict");

const { normalizeBrowseInputPath } = require("../adapters/target-folders-manager");
const { extractTargetProjectPath } = require("../adapters/agent-chat-engine");
const {
  CORPORATE_AGENT_DIRECTORY,
  resolveLiveCorporateDirectory,
  resolveCorporateAgentEntry,
  parseNaturalTelegramIntent,
} = require("../adapters/telegram-control-adapter");
const {
  MENU_CATEGORIES,
  CANONICAL_COMMANDS,
  COMMAND_LOOKUP,
  resolveCanonicalCommand,
  validateCommandArguments,
  nextStateVersion,
  generateCorrelationId,
  checkIdempotency,
  saveIdempotency,
  registerCancellableOperation,
  cancelOperation,
  buildExecutionReceipt,
  buildStructuredError,
} = require("../telegram-control/command-registry");
const {
  verifyTelegramRequestSecurity,
  createBoundApprovalRequest,
  consumeBoundApprovalRequest,
  buildSignedCallbackData,
} = require("../telegram-control/security-guard");
const { createOfficeBridgeApp } = require("../server");

test.after(() => {
  try {
    fs.rmSync(TEST_ROOT, { recursive: true, force: true });
  } catch {}
});

test("1. CORPORATE_AGENT_DIRECTORY Has Zero Hardcoded UUIDs & Binds Dynamically via role_slug", () => {
  assert.equal(CORPORATE_AGENT_DIRECTORY.length, 11);
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  for (const ag of CORPORATE_AGENT_DIRECTORY) {
    assert.equal(uuidRegex.test(ag.id), false, `Agent ${ag.slug} must not have a hardcoded UUID`);
    assert.ok(ag.id.startsWith("role:"), `Expected portable 'role:<slug>' default ID on ${ag.slug}`);
  }

  // Simulate dynamic Paperclip snapshot with fresh runtime UUIDs
  const mockSnap = {
    agents: CORPORATE_AGENT_DIRECTORY.map((ag, idx) => ({
      paperclip_agent_id: `dyn-uuid-${String(idx + 1).padStart(2, "0")}`,
      role_slug: ag.slug,
      runtime_profile_reference: ag.profile,
      display_name: ag.name,
    })),
  };
  const liveDir = resolveLiveCorporateDirectory(mockSnap);
  assert.equal(liveDir.length, 11);
  assert.equal(liveDir[0].id, "dyn-uuid-01");
  assert.equal(liveDir[2].id, "dyn-uuid-03");
  assert.equal(liveDir[10].id, "dyn-uuid-11");

  // Resolve by index, @handle, slug, dynamic UUID, and Indonesian alias
  assert.equal(resolveCorporateAgentEntry("1", mockSnap)?.id, "dyn-uuid-01");
  assert.equal(resolveCorporateAgentEntry("@cto", mockSnap)?.id, "dyn-uuid-02");
  assert.equal(resolveCorporateAgentEntry("backend_developer", mockSnap)?.id, "dyn-uuid-03");
  assert.equal(resolveCorporateAgentEntry("dyn-uuid-06", mockSnap)?.name, "QA Engineer");
  assert.equal(resolveCorporateAgentEntry("kepala keamanan", mockSnap)?.name, "Security Lead");
  assert.equal(resolveCorporateAgentEntry("Security Reviewer", mockSnap)?.name, "Security Reviewer");
  assert.equal(resolveCorporateAgentEntry("10", mockSnap)?.name, "Remediation Reviewer");
  assert.equal(resolveCorporateAgentEntry("11", mockSnap)?.name, "Report & Compliance Agent");
  assert.equal(resolveCorporateAgentEntry("99", mockSnap), null);
});

test("2. Canonical Registry Resolves All 59 CODEXE Commands + All 159 Canonical/Alias Slugs Without Collision", () => {
  assert.equal(Object.keys(MENU_CATEGORIES).length, 13);
  assert.equal(CANONICAL_COMMANDS.length, 48);
  assert.ok(COMMAND_LOOKUP.size >= 159, `Expected >=159 registered command/alias slugs, got ${COMMAND_LOOKUP.size}`);

  // Explicit 59+ CODEXE BotFather & delegated command list
  const codexe59Commands = [
    "kantor", "menu", "menu_kantor", "submenu",
    "agen", "pilih", "lepas", "info_agen", "chat", "ke", "reset_sesi",
    "daftar_skill", "skill_info", "skill_status",
    "bangunkan", "aktifkan", "istirahatkan", "standar_wave1", "stop_semua", "pause_dispatch", "resume_dispatch", "delegasi",
    "status_kantor", "ruangan", "lokasi_agen", "screenshot_kantor",
    "meeting_menu", "meeting", "status_meeting", "diskusi_rapat", "tanya_rapat", "notulen", "riwayat_meeting", "selesai_meeting",
    "folder", "jelajah", "cari_folder", "meta_folder", "pilih_folder", "analisis",
    "dev", "dev_task", "git_status", "buat_branch", "jalankan_test", "cek_diff", "review_kode", "build_project",
    "projects", "buat_project", "pilih_project", "buat_task", "daftar_task", "cek_task", "subtasks",
    "ubah_task", "pause_task", "resume_task", "cancel_task", "selesai_task",
    "analytics", "biaya", "budget", "set_budget",
    "persetujuan", "setujui", "tolak",
    "keamanan", "triage_temuan", "remediasi_temuan",
    "kesehatan", "diagnosa", "log_error", "pulihkan_layanan", "update_status", "jobs", "cek_job", "batal_job",
  ];
  assert.ok(codexe59Commands.length >= 59);
  for (const cmd of codexe59Commands) {
    const res = resolveCanonicalCommand(cmd);
    assert.ok(res.spec && res.canonical_id, `CODEXE command '/${cmd}' failed to resolve`);
  }

  // Verify every single entry in COMMAND_LOOKUP resolves deterministically & validates schema
  for (const [slug, spec] of COMMAND_LOOKUP.entries()) {
    const resolved = resolveCanonicalCommand(`/${slug}@allinagent_bot`);
    assert.equal(resolved.canonical_id, spec.id);
    assert.equal(validateCommandArguments(spec, "bad\0null").ok, false);
  }

  // State version, idempotency & cancellation
  const v0 = nextStateVersion(false);
  assert.equal(nextStateVersion(true), v0 + 1);
  const corr = generateCorrelationId("tgtest");
  saveIdempotency("idem-1", { ok: true, receipt: buildExecutionReceipt({ correlationId: corr, command: "kantor" }) });
  assert.equal(checkIdempotency("idem-1").receipt.correlation_id, corr);

  const opCtrl = registerCancellableOperation("op-cancel-1");
  assert.equal(cancelOperation("op-cancel-1"), true);
  assert.equal(opCtrl.signal.aborted, true);

  const synLeakKey = "sk-" + "FAKE1234567890abcdefghij";
  const structuredErr = buildStructuredError({ command: "chat", message: `Leaked ${synLeakKey}` });
  assert.ok(!structuredErr.reply.includes(synLeakKey));
});

test("3. POSIX & Win32 Path Handling + Bahasa Indonesia Natural Language Intent Router", () => {
  // Verify NO `/` -> `\` corruption on Linux!
  assert.equal(normalizeBrowseInputPath("/opt/allinagent/workspaces/app", "linux"), "/opt/allinagent/workspaces/app");
  assert.equal(normalizeBrowseInputPath("/workspaces/service/../app", "linux"), "/workspaces/app");
  assert.equal(normalizeBrowseInputPath("D:", "win32"), "D:\\");

  // POSIX path candidate extraction
  const posixAttempt = extractTargetProjectPath("Tolong analisis folder /etc/passwd sekarang", { returnAttemptInfo: true });
  assert.equal(posixAttempt.resolved, null);
  assert.equal(posixAttempt.explicitAttempt, "/etc/passwd");

  const realExtract = extractTargetProjectPath(`Analisis folder ${TEST_PROJECT.replace(/\\/g, "/")}`, { returnAttemptInfo: true });
  assert.ok(realExtract.resolved);

  const idleState = {
    selected_agent_id: CORPORATE_AGENT_DIRECTORY[0].id,
    selected_agent_slug: "ceo_agent",
    selected_agent_name: "CEO Agent",
    direct_agent_mode: false,
  };

  assert.equal(parseNaturalTelegramIntent("ambil screenshot desktop sekarang", idleState).kind, "passthrough");
  assert.equal(parseNaturalTelegramIntent("hapus semua database sekarang", idleState).kind, "destructive_blocked");

  const mBackend = parseNaturalTelegramIntent("@backend cek endpoint login", idleState);
  assert.equal(mBackend.kind, "ask_agent");
  assert.equal(mBackend.agentEntry.slug, "backend_developer");

  const sw = parseNaturalTelegramIntent("pilih agen Remediation Reviewer", idleState);
  assert.equal(sw.command, "pilih");
  assert.equal(sw.args, "10");

  const mtg = parseNaturalTelegramIntent(`Kumpulkan semua 11 agen di ruang meeting bahas ${TEST_PROJECT}`, idleState);
  assert.equal(mtg.command, "meeting");
});

test("4. Phase 03 Mandatory Security Guards: Fail-Closed Unset Owner, Group Block, Callback Replay & Bound Approvals", async () => {
  // 0. Fail-closed when OWNER_TELEGRAM_ID is unset or <PLACEHOLDER_OWNER_ID>
  const prevOwner = process.env.OWNER_TELEGRAM_ID;
  try {
    process.env.OWNER_TELEGRAM_ID = PLACEHOLDER_OWNER_ID;
    const failClosed = verifyTelegramRequestSecurity({ caller_id: PLACEHOLDER_OWNER_ID, chat_type: "private", command: "kantor" });
    assert.equal(failClosed.ok, false);
    assert.equal(failClosed.code, "OWNER_ID_NOT_CONFIGURED");
  } finally {
    process.env.OWNER_TELEGRAM_ID = prevOwner;
  }

  // 1. Unauthorized caller rejected
  assert.equal(
    verifyTelegramRequestSecurity({ caller_id: "999999999", chat_type: "private", command: "kantor" }).code,
    "UNAUTHORIZED_USER"
  );

  // 2. Group / supergroup rejected even for Owner
  assert.equal(
    verifyTelegramRequestSecurity({
      caller_id: TEST_OWNER_ID,
      chat_id: "-100123456",
      chat_type: "supergroup",
      command: "kantor",
    }).code,
    "GROUP_OR_CHANNEL_FORBIDDEN"
  );

  // 3. Valid signed callback accepted once, replay rejected (409), tampered payload rejected (403)
  const cbId = `cbq-${Date.now()}`;
  const signed = buildSignedCallbackData("uac:menu");
  assert.equal(
    verifyTelegramRequestSecurity({
      caller_id: TEST_OWNER_ID,
      chat_id: TEST_OWNER_ID,
      chat_type: "private",
      callback_query_id: cbId,
      command: signed,
    }).ok,
    true
  );
  assert.equal(
    verifyTelegramRequestSecurity({
      caller_id: TEST_OWNER_ID,
      chat_id: TEST_OWNER_ID,
      chat_type: "private",
      callback_query_id: cbId,
      command: signed,
    }).code,
    "CALLBACK_REPLAY_DETECTED"
  );
  assert.equal(
    verifyTelegramRequestSecurity({
      caller_id: TEST_OWNER_ID,
      chat_id: TEST_OWNER_ID,
      chat_type: "private",
      command: signed.replace("uac:menu", "uac:stop_all"),
    }).code,
    "MODIFIED_CALLBACK_PAYLOAD"
  );

  // 4. Bound approval expiration, cross-user block, args tampering block & replay block
  const expReq = createBoundApprovalRequest({ action: "stop_semua", target: "all", ttlMs: 1000 });
  await new Promise((r) => setTimeout(r, 1100));
  assert.equal(
    consumeBoundApprovalRequest({ requestId: expReq.request_id, callerId: TEST_OWNER_ID, decision: "approve" }).code,
    "APPROVAL_EXPIRED"
  );

  const bound = createBoundApprovalRequest({ action: "set_budget", target: "monthly", args: { usd: 80 } });
  assert.equal(
    consumeBoundApprovalRequest({ requestId: bound.request_id, callerId: "777", decision: "approve" }).code,
    "CROSS_USER_APPROVAL_FORBIDDEN"
  );
  assert.equal(
    consumeBoundApprovalRequest({
      requestId: bound.request_id,
      callerId: TEST_OWNER_ID,
      decision: "approve",
      expectedArgs: { usd: 9999 },
    }).code,
    "APPROVAL_ARGS_TAMPERED"
  );
  assert.equal(
    consumeBoundApprovalRequest({
      requestId: bound.request_id,
      callerId: TEST_OWNER_ID,
      decision: "approve",
      expectedArgs: { usd: 80 },
    }).ok,
    true
  );
  assert.equal(
    consumeBoundApprovalRequest({ requestId: bound.request_id, callerId: TEST_OWNER_ID, decision: "approve" }).code,
    "DUPLICATE_OR_STALE_APPROVAL"
  );
});

test("5. End-to-End Execution of All 13 CODEXE Categories via /api/office-bridge/telegram/command", async () => {
  const companyId = "00000000-0000-4000-8000-000000000101";
  const mockAgents = CORPORATE_AGENT_DIRECTORY.map((d, idx) => ({
    id: `dyn-ag-${String(idx + 1).padStart(2, "0")}`,
    name: d.name,
    role: idx === 0 ? "ceo" : idx === 1 ? "cto" : "engineer",
    status: d.wave === 1 ? "idle" : "paused",
  }));
  const mockProjects = [];
  const mockIssues = [];
  const mockApprovals = [{ id: "appr-tg-01", type: "release_gate", status: "pending", requestedByAgentId: "dyn-ag-05", createdAt: new Date().toISOString() }];
  let budgetSyncedCount = 0;

  const mockPaperclip = http.createServer(async (req, res) => {
    res.setHeader("Content-Type", "application/json");
    const u = req.url || "/";
    let bodyObj = {};
    if (req.method !== "GET") {
      const chunks = [];
      for await (const ch of req) chunks.push(ch);
      const raw = Buffer.concat(chunks).toString("utf8");
      if (raw.trim()) bodyObj = JSON.parse(raw);
    }

    if (u === "/api/companies") {
      res.end(JSON.stringify([{ id: companyId, name: "CODEXE Test Corp", issuePrefix: "CDX", status: "active" }]));
    } else if (u.endsWith("/agents")) {
      res.end(JSON.stringify(mockAgents));
    } else if (u.startsWith("/api/agents/") && (u.endsWith("/pause") || u.endsWith("/resume") || u.endsWith("/wakeup"))) {
      const aid = decodeURIComponent(u.split("/")[3]);
      const ag = mockAgents.find((a) => a.id === aid);
      if (ag) {
        if (u.endsWith("/pause")) ag.status = "paused";
        if (u.endsWith("/resume")) ag.status = "idle";
      }
      res.end(JSON.stringify(ag || { id: aid, status: "idle" }));
    } else if (u.startsWith("/api/agents/")) {
      const aid = decodeURIComponent(u.split("/")[3]);
      res.end(JSON.stringify(mockAgents.find((a) => a.id === aid) || mockAgents[0]));
    } else if (u.endsWith("/projects") && req.method === "GET") {
      res.end(JSON.stringify(mockProjects));
    } else if (u.endsWith("/projects") && req.method === "POST") {
      const p = { id: `proj-${mockProjects.length + 1}`, name: bodyObj.name, status: "in_progress" };
      mockProjects.push(p);
      res.statusCode = 201;
      res.end(JSON.stringify(p));
    } else if (u.endsWith("/issues") && req.method === "GET") {
      res.end(JSON.stringify(mockIssues));
    } else if (u.endsWith("/issues") && req.method === "POST") {
      const iss = {
        id: `iss-${mockIssues.length + 1}`,
        identifier: `CDX-${mockIssues.length + 1}`,
        title: bodyObj.title,
        description: bodyObj.description || "",
        status: bodyObj.status || "todo",
        priority: bodyObj.priority || "medium",
        assigneeAgentId: bodyObj.assigneeAgentId || null,
        projectId: bodyObj.projectId || null,
        parentId: bodyObj.parentId || null,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      mockIssues.push(iss);
      res.statusCode = 201;
      res.end(JSON.stringify(iss));
    } else if (u.startsWith("/api/issues/") && u.endsWith("/comments")) {
      res.end(JSON.stringify(req.method === "POST" ? { id: "c1", body: bodyObj.body } : []));
    } else if (u.startsWith("/api/issues/") && u.endsWith("/live-runs")) {
      res.end(JSON.stringify([]));
    } else if (u.startsWith("/api/issues/") && req.method === "GET") {
      const iid = decodeURIComponent(u.split("/")[3]);
      res.end(JSON.stringify(mockIssues.find((x) => x.id === iid) || mockIssues[0]));
    } else if (u.startsWith("/api/issues/") && req.method === "PATCH") {
      const iid = decodeURIComponent(u.split("/")[3]);
      const found = mockIssues.find((x) => x.id === iid);
      if (found) Object.assign(found, bodyObj, { updatedAt: new Date().toISOString() });
      res.end(JSON.stringify(found || { id: iid, ...bodyObj }));
    } else if (u.endsWith("/approvals")) {
      res.end(JSON.stringify(mockApprovals));
    } else if (u.startsWith("/api/approvals/") && req.method === "POST") {
      const parts = u.split("/");
      const aid = decodeURIComponent(parts[3]);
      const act = parts[4];
      const ap = mockApprovals.find((x) => x.id === aid);
      if (ap) ap.status = act === "approve" ? "approved" : "rejected";
      res.end(JSON.stringify(ap || { id: aid, status: "approved" }));
    } else if (u.endsWith("/budgets") && req.method === "PUT") {
      budgetSyncedCount += 1;
      res.end(JSON.stringify({ ok: true }));
    } else if (u.endsWith("/budgets/overview")) {
      res.end(JSON.stringify({ policies: [] }));
    } else {
      res.end(JSON.stringify([]));
    }
  });
  await new Promise((resolve) => mockPaperclip.listen(0, "127.0.0.1", resolve));
  const pcPort = mockPaperclip.address().port;

  const app = await createOfficeBridgeApp({
    host: "127.0.0.1",
    port: 0,
    paperclipUrl: `http://127.0.0.1:${pcPort}`,
    historyFilePath: null,
    pollIntervalMs: 60_000,
    enableUpstreamWs: false,
  });

  async function tgCmd(command, args = "", extra = {}) {
    const resp = await fetch(`http://127.0.0.1:${app.port}/api/office-bridge/telegram/command`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${app.secrets.bridgeToken}`,
        "Content-Type": "application/json",
        "X-Office-Caller-Id": TEST_OWNER_ID,
      },
      body: JSON.stringify({ command, args, caller_id: TEST_OWNER_ID, chat_type: "private", ...extra }),
    });
    return { status: resp.status, json: await resp.json() };
  }

  try {
    // 1. Control Center & Submenus
    assert.equal((await tgCmd("kantor")).json.ok, true);
    for (const sub of ["ceo", "office", "meeting", "dev", "paperclip", "analytics", "budgets", "security", "system"]) {
      const sRes = await tgCmd("submenu", sub);
      assert.equal(sRes.json.ok, true, `Submenu ${sub}`);
    }

    // 2. Agents & Skills (verifying dynamic UUID binding!)
    const agList = await tgCmd("agen");
    assert.equal(agList.json.count, 11);
    assert.equal(agList.json.agents[0].id, "dyn-ag-01");

    const pickRes = await tgCmd("pilih", "3");
    assert.equal(pickRes.json.ok, true);
    assert.equal(pickRes.json.selected_agent.id, "dyn-ag-03");

    assert.equal((await tgCmd("info_agen", "3")).json.ok, true);
    assert.equal((await tgCmd("daftar_skill")).json.ok, true);
    assert.equal((await tgCmd("daftar_skill", "cto")).json.agent_id, "dyn-ag-02");
    assert.equal((await tgCmd("skill_info", "cto cto-advisor")).json.skill.commons_clause, true);
    const skStatus = (await tgCmd("skill_status")).json.summary;
    assert.equal(skStatus.total_skills, 33);
    assert.equal(skStatus.osi_permissive_count, 20);
    assert.equal(skStatus.fetch_from_upstream_only_count, 13);
    assert.equal(skStatus.commons_clause_count, 10);
    assert.equal(skStatus.quarantined_files, 11);
    assert.equal((await tgCmd("reset_sesi", "3 --clear")).json.ok, true);
    const pickZeroCb = await tgCmd("uac:pick:0", "", { callback_query_id: `cbq-pick0-${Date.now()}` });
    assert.equal(pickZeroCb.status, 200);
    assert.equal(pickZeroCb.json.ok, true);
    assert.equal(pickZeroCb.json.direct_agent_mode, false);
    assert.equal((await tgCmd("lepas")).json.direct_agent_mode, false);

    // 3. Folders & Real Source Code Analysis (.env never leaked!)
    assert.equal((await tgCmd("folder")).json.ok, true);
    assert.equal((await tgCmd("jelajah", "drives")).json.ok, true);
    assert.equal((await tgCmd("cari_folder", "sample")).json.search.count, 1);
    assert.equal((await tgCmd("pilih_folder", TEST_PROJECT)).json.ok, true);

    const anl = await tgCmd("analisis", TEST_PROJECT);
    assert.equal(anl.json.ok, true);
    assert.equal(anl.json.analysis.env_protected, true);
    const reportText = fs.readFileSync(anl.json.analysis.report_path, "utf8");
    assert.ok(!reportText.includes(NEVER_READ_ENV_SECRET));

    // 4. Development Control (Git status, branch, diff, test)
    assert.equal((await tgCmd("git_status")).json.ok, true);
    assert.equal((await tgCmd("buat_branch", "feat/phase12-portable")).json.ok, true);
    assert.equal((await tgCmd("cek_diff")).json.ok, true);
    assert.equal((await tgCmd("jalankan_test")).json.ok, true);

    // 5. Lifecycle & CEO Multi-Agent Delegation (Parent + 4 Specialist Subtasks with Dynamic UUIDs!)
    assert.equal((await tgCmd("bangunkan", "2")).json.agent_id, "dyn-ag-02");
    assert.equal((await tgCmd("istirahatkan", "2")).json.agent_id, "dyn-ag-02");
    assert.equal((await tgCmd("standar_wave1")).json.ok, true);
    assert.equal((await tgCmd("pause_dispatch", "pause")).json.dispatch.dispatch_paused, true);
    assert.equal((await tgCmd("pause_dispatch", "resume")).json.dispatch.dispatch_paused, false);

    const delRes = await tgCmd("delegasi", `Audit layanan ${TEST_PROJECT} ke CTO, Backend, QA, dan Security Reviewer`);
    assert.equal(delRes.json.ok, true);
    assert.equal(delRes.json.delegation.subtasks.length, 4);
    assert.equal(delRes.json.delegation.subtasks[0].agent_id, "dyn-ag-02");

    // 6. 3D/2D Office, Lightweight PNG Screenshot Fallback & Full 10-State Meeting Lifecycle
    assert.equal((await tgCmd("status_kantor")).json.ok, true);
    assert.equal((await tgCmd("ruangan")).json.ok, true);
    assert.equal((await tgCmd("lokasi_agen")).json.ok, true);

    const prevChromeBin = process.env.CHROMIUM_BIN;
    try {
      process.env.CHROMIUM_BIN = "none";
      const shotRes = await tgCmd("screenshot_kantor", "3d");
      assert.equal(shotRes.status, 200);
      assert.equal(shotRes.json.ok, true);
      assert.equal(shotRes.json.renderer, "lightweight_png_card");
      assert.ok(typeof shotRes.json.photo_base64 === "string" && shotRes.json.photo_base64.length > 200);
      const pngBytes = Buffer.from(shotRes.json.photo_base64, "base64");
      assert.deepEqual(pngBytes.subarray(0, 8), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
      assert.equal(pngBytes.readUInt32BE(16), 800);
      assert.equal(pngBytes.readUInt32BE(20), 460);
    } finally {
      if (prevChromeBin === undefined) delete process.env.CHROMIUM_BIN;
      else process.env.CHROMIUM_BIN = prevChromeBin;
    }

    const mtgStart = await tgCmd("meeting", "Bahas kesiapan rilis lintas-platform");
    assert.equal(mtgStart.json.ok, true);
    assert.equal((await tgCmd("status_meeting")).json.ok, true);
    assert.equal((await tgCmd("diskusi_rapat", "Status portabilitas Docker")).json.ok, true);

    const notulenRes = await tgCmd("notulen", "--tasks");
    assert.equal(notulenRes.json.ok, true);
    assert.equal(notulenRes.json.minutes.action_items[0].owner_id, "dyn-ag-03");
    assert.equal(notulenRes.json.created_followups.length, 3);
    assert.equal((await tgCmd("selesai_meeting")).json.ok, true);

    // 7. Paperclip Projects & Kanban
    assert.equal((await tgCmd("buat_project", "Portable Core")).json.ok, true);
    assert.equal((await tgCmd("projects")).json.ok, true);
    const createdTask = await tgCmd("buat_task", "backend_developer | Hardening API | Validasi input endpoint");
    assert.equal(createdTask.json.ok, true);
    const taskIdent = createdTask.json.submission.task.identifier;
    assert.equal((await tgCmd("daftar_task")).json.ok, true);
    assert.equal((await tgCmd("cek_task", taskIdent)).json.ok, true);
    assert.equal((await tgCmd("selesai_task", taskIdent)).json.task.status, "done");

    // 8. Analytics, Bidirectional Budgets, Approvals, Security, Health & Jobs
    assert.equal((await tgCmd("analytics", "today")).json.ok, true);
    assert.equal((await tgCmd("budget")).json.ok, true);
    const bdgSet = await tgCmd("set_budget", "monthly 200");
    assert.equal(bdgSet.json.ok, true);
    assert.equal(bdgSet.json.paperclip_synced, true);
    assert.ok(budgetSyncedCount >= 1);

    assert.equal((await tgCmd("persetujuan")).json.pending_count >= 1, true);
    assert.equal((await tgCmd("setujui", "appr-tg-01")).json.ok, true);

    assert.equal((await tgCmd("keamanan")).json.ok, true);
    assert.equal((await tgCmd("keamanan", `deps ${TEST_PROJECT}`)).json.ok, true);

    const healthRes = await tgCmd("kesehatan");
    assert.equal(healthRes.json.ok, true);
    assert.equal(healthRes.json.health.component_count, 15);
    assert.equal(typeof healthRes.json.health.host_metrics.ram_free_mb, "number");

    assert.equal((await tgCmd("log_error")).json.ok, true);
    assert.equal((await tgCmd("pulihkan_layanan", "reconcile")).json.ok, true);
    assert.equal((await tgCmd("update_status")).json.ok, true);

    const jobEnq = await tgCmd("jobs", `--start-audit ${TEST_PROJECT}`);
    assert.equal(jobEnq.json.ok, true);
    const jid = jobEnq.json.queued_job.job_id;
    assert.equal((await tgCmd("cek_job", jid)).json.ok, true);
    assert.equal((await tgCmd("batal_job", jid)).json.ok, true);
  } finally {
    await app.close();
    await new Promise((resolve) => mockPaperclip.close(resolve));
  }
});
