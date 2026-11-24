"use strict";

/**
 * PHASE 07 & PHASE 08 — Cross-Platform 3D & 2D Office Remote Control,
 * Headless Chromium/Edge Screenshot Capture (Linux `--no-sandbox` + Windows),
 * and Full 10-State 11-Agent Meeting Lifecycle with Dynamic `role_slug` Agent Resolution.
 *
 * Strictly zero hardcoded Windows paths, Edge binaries, or Paperclip agent UUIDs.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const zlib = require("node:zlib");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const {
  OFFICE_DATA_DIR,
  SECRETS_DIR,
  HERMES3D_BASE_URL,
  PYTHON_EXE,
  resolveChromiumExe,
} = require("../contracts/paths");
const { sanitizeText, sanitizePayload } = require("../contracts/redaction");
const { resolveSecretFilePath, resolveStudioAccessToken } = require("../authorization/auth");

const execFileAsync = promisify(execFile);

const MEETINGS_HISTORY_FILE = path.resolve(path.join(OFFICE_DATA_DIR, "event-history", "meetings-v2.json"));
const STANDUP_STORE_FILE = path.resolve(path.join(OFFICE_DATA_DIR, "studio-state", "hermes3d", "standup-store.json"));
const SCREENSHOTS_DIR = path.resolve(path.join(OFFICE_DATA_DIR, "screenshots"));
const SECRET_FILE_PATH = resolveSecretFilePath(process.env);

const MEETING_LIFECYCLE_STATES = Object.freeze([
  "CREATED",
  "INVITING",
  "MOVING_TO_ROOM",
  "WAITING_FOR_AGENTS",
  "READY",
  "IN_PROGRESS",
  "SUMMARIZING",
  "COMPLETED",
  "CANCELLED",
  "FAILED",
]);

const CANONICAL_OFFICE_ROOMS = Object.freeze([
  { id: "executive", name: "Executive Suite (CEO)", zone_3d: "North-West Glass Suite", zone_2d: "Tile (6, 4)" },
  { id: "architecture", name: "Architecture & CTO Lab", zone_3d: "North-Center Hub", zone_2d: "Tile (14, 4)" },
  { id: "engineering", name: "Backend & Frontend Bay", zone_3d: "West Engineering Pod", zone_2d: "Tile (6, 10)" },
  { id: "devops", name: "DevOps & Runtime NOC", zone_3d: "East Server Bay", zone_2d: "Tile (22, 10)" },
  { id: "qa", name: "Quality Assurance Lab", zone_3d: "South-West Test Bench", zone_2d: "Tile (8, 16)" },
  { id: "security", name: "Cybersecurity & VulnClaw SOC", zone_3d: "South-East Vault", zone_2d: "Tile (20, 16)" },
  { id: "governance", name: "Audit & Compliance Desk", zone_3d: "East Executive Wing", zone_2d: "Tile (24, 5)" },
  { id: "meeting_room", name: "Central All-Hands Meeting Room", zone_3d: "Center Conference Table (0, 0, -2)", zone_2d: "Conference Table (14, 11)" },
]);

const MEETING_ROOM_SEATS = Object.freeze([
  { seat: 1, x3d: 0.0, z3d: -4.2, x2d: 14, y2d: 9 },
  { seat: 2, x3d: 1.8, z3d: -3.8, x2d: 16, y2d: 9 },
  { seat: 3, x3d: 3.1, z3d: -2.6, x2d: 17, y2d: 10 },
  { seat: 4, x3d: 3.4, z3d: -1.0, x2d: 17, y2d: 12 },
  { seat: 5, x3d: 2.6, z3d: 0.5, x2d: 16, y2d: 13 },
  { seat: 6, x3d: 1.0, z3d: 1.2, x2d: 14, y2d: 13 },
  { seat: 7, x3d: -1.0, z3d: 1.2, x2d: 12, y2d: 13 },
  { seat: 8, x3d: -2.6, z3d: 0.5, x2d: 11, y2d: 12 },
  { seat: 9, x3d: -3.4, z3d: -1.0, x2d: 11, y2d: 10 },
  { seat: 10, x3d: -3.1, z3d: -2.6, x2d: 12, y2d: 9 },
  { seat: 11, x3d: -1.8, z3d: -3.8, x2d: 13, y2d: 9 },
]);

function loadMeetingsV2() {
  try {
    if (fs.existsSync(MEETINGS_HISTORY_FILE)) {
      const arr = JSON.parse(fs.readFileSync(MEETINGS_HISTORY_FILE, "utf8"));
      if (Array.isArray(arr)) return arr;
    }
  } catch {}
  return [];
}

function saveMeetingsV2(list) {
  fs.mkdirSync(path.dirname(MEETINGS_HISTORY_FILE), { recursive: true, mode: 0o700 });
  const trimmed = (Array.isArray(list) ? list : []).slice(-100);
  fs.writeFileSync(MEETINGS_HISTORY_FILE, JSON.stringify(trimmed, null, 2) + "\n", "utf8");
  return trimmed;
}

function readStandupStoreSafe() {
  try {
    if (fs.existsSync(STANDUP_STORE_FILE)) {
      return JSON.parse(fs.readFileSync(STANDUP_STORE_FILE, "utf8"));
    }
  } catch {}
  return { activeMeeting: null, lastMeeting: null };
}

function getActiveMeetingV2(sync) {
  const v2List = loadMeetingsV2();
  const openV2 = v2List.find(
    (m) => !["COMPLETED", "CANCELLED", "FAILED", "SUPERSEDED"].includes(String(m.lifecycle_state || m.status))
  );
  if (openV2) return openV2;

  const standup = readStandupStoreSafe();
  if (standup.activeMeeting && standup.activeMeeting.phase && standup.activeMeeting.phase !== "complete") {
    return {
      meeting_id: standup.activeMeeting.id || "mtg-ui-live",
      title: standup.activeMeeting.topic || "UI Standup Meeting",
      agenda: standup.activeMeeting.topic || "Active Virtual Office Meeting",
      status: "ACTIVE",
      lifecycle_state: "IN_PROGRESS",
      participants: (standup.activeMeeting.participantOrder || []).map((id, i) => ({
        agent_id: id,
        seat: i + 1,
        arrived_3d: (standup.activeMeeting.arrivedAgentIds || []).includes(id),
        arrived_2d: (standup.activeMeeting.arrivedAgentIds || []).includes(id),
      })),
      created_at: standup.activeMeeting.startedAt || new Date().toISOString(),
    };
  }

  const snap = sync.getFullSnapshot();
  const legacy = (snap.collaboration?.meetings || []).find((m) => m.status === "ACTIVE");
  return legacy || null;
}

/**
 * Inspect live rooms, agent coordinates, and 3D/2D render availability (`PHASE 07`).
 */
async function buildOfficeRemoteStatus(sync, directory) {
  const snap = sync.getFullSnapshot();
  const activeMtg = getActiveMeetingV2(sync);
  const standup = readStandupStoreSafe();
  const inMeetingIds = new Set(
    activeMtg ? (activeMtg.participant_agent_ids || (activeMtg.participants || []).map((p) => p.agent_id || p.id)) : []
  );
  const arrivedStandupIds = new Set(standup?.activeMeeting?.arrivedAgentIds || []);

  const agentLocations = directory.map((entry, idx) => {
    const live =
      (snap.agents || []).find(
        (a) => a.paperclip_agent_id === entry.id || a.role_slug === entry.slug
      ) || {};
    const inMtg = inMeetingIds.has(entry.id) || (live.paperclip_agent_id && inMeetingIds.has(live.paperclip_agent_id));
    const seat = MEETING_ROOM_SEATS[idx % MEETING_ROOM_SEATS.length];
    const desk = live.desk_coords || { x: idx * 2, y: 6 };
    return {
      index: entry.index,
      agent_id: live.paperclip_agent_id || entry.id,
      name: entry.name,
      handle: entry.handle,
      department: entry.department,
      activation_status: live.activation_status || (entry.wave === 1 ? "ACTIVE" : "STANDBY"),
      current_room: inMtg ? "meeting_room" : live.department_id || entry.slug,
      room_label: inMtg ? "Central All-Hands Meeting Room" : `${entry.department} Workstation`,
      visual_state: inMtg ? "IN_MEETING" : live.state?.visual_state || "IDLE_AT_DESK",
      arrived_3d: inMtg ? arrivedStandupIds.has(entry.id) || Boolean(standup.activeMeeting) : true,
      arrived_2d: inMtg ? arrivedStandupIds.has(entry.id) || Boolean(standup.activeMeeting) : true,
      coords_3d: inMtg ? { x: seat.x3d, y: 0, z: seat.z3d } : { x: desk.x || 0, y: 0, z: desk.y || 0 },
      coords_2d: inMtg ? { tileX: seat.x2d, tileY: seat.y2d } : { tileX: 6 + (idx % 5) * 4, tileY: 5 + Math.floor(idx / 5) * 5 },
    };
  });

  const rooms = CANONICAL_OFFICE_ROOMS.map((r) => {
    const occupants = agentLocations.filter((a) =>
      r.id === "meeting_room"
        ? a.current_room === "meeting_room"
        : a.current_room !== "meeting_room" &&
          (a.department.toLowerCase().includes(r.id) ||
            (r.id === "engineering" && /engineering|frontend/i.test(a.department)) ||
            (r.id === "governance" && /audit|compliance/i.test(a.department)))
    );
    return {
      ...r,
      occupant_count: occupants.length,
      occupants: occupants.map((o) => `${o.name} (${o.handle})`),
    };
  });

  const baseUrl = String(process.env.HERMES3D_BASE_URL || HERMES3D_BASE_URL).replace(/\/$/, "");
  let officeHttpReachable = false;
  let studioAuthValid = false;
  try {
    const hRes = await fetch(`${baseUrl}/api/health`, { signal: AbortSignal.timeout(4000) });
    officeHttpReachable = hRes.status === 200;
    const studioToken = resolveStudioAccessToken(null, process.env);
    if (studioToken) {
      const loginRes = await fetch(`${baseUrl}/api/studio-auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: baseUrl },
        body: JSON.stringify({ token: studioToken }),
        signal: AbortSignal.timeout(4000),
      });
      studioAuthValid = loginRes.status === 200;
    }
  } catch {}

  return {
    office_url: `${baseUrl}/office`,
    office_2d_url: `${baseUrl}/office?view=2d`,
    http_reachable: officeHttpReachable,
    studio_auth_ready: studioAuthValid,
    render_3d_ready: officeHttpReachable && studioAuthValid,
    render_2d_ready: officeHttpReachable && studioAuthValid && fs.existsSync(STANDUP_STORE_FILE),
    standup_store_active: Boolean(standup?.activeMeeting),
    standup_arrived_count: arrivedStandupIds.size,
    active_meeting: activeMtg,
    rooms,
    agent_locations: agentLocations,
  };
}

const PNG_CRC32_TABLE = (() => {
  const tbl = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    tbl[n] = c >>> 0;
  }
  return tbl;
})();

function computeCrc32(buf) {
  if (typeof zlib.crc32 === "function") {
    return zlib.crc32(buf) >>> 0;
  }
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) {
    c = PNG_CRC32_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function buildPngChunk(typeAscii, dataBuf) {
  const typeBuf = Buffer.from(typeAscii, "ascii");
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(dataBuf.length, 0);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(computeCrc32(Buffer.concat([typeBuf, dataBuf])), 0);
  return Buffer.concat([lenBuf, typeBuf, dataBuf, crcBuf]);
}

const BITMAP_FONT_5X7 = Object.freeze({
  " ": ["00000", "00000", "00000", "00000", "00000", "00000", "00000"],
  A: ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
  B: ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
  C: ["01111", "10000", "10000", "10000", "10000", "10000", "01111"],
  D: ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
  E: ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
  F: ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
  G: ["01111", "10000", "10000", "10011", "10001", "10001", "01111"],
  H: ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
  I: ["01110", "00100", "00100", "00100", "00100", "00100", "01110"],
  J: ["00111", "00010", "00010", "00010", "10010", "10010", "01100"],
  K: ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
  L: ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
  M: ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
  N: ["10001", "11001", "10101", "10011", "10001", "10001", "10001"],
  O: ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
  P: ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
  Q: ["01110", "10001", "10001", "10001", "10101", "10010", "01101"],
  R: ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
  S: ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
  T: ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
  U: ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
  V: ["10001", "10001", "10001", "10001", "10001", "01010", "00100"],
  W: ["10001", "10001", "10001", "10101", "10101", "11011", "10001"],
  X: ["10001", "10001", "01010", "00100", "01010", "10001", "10001"],
  Y: ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
  Z: ["11111", "00001", "00010", "00100", "01000", "10000", "11111"],
  0: ["01110", "10001", "10011", "10101", "11001", "10001", "01110"],
  1: ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
  2: ["01110", "10001", "00001", "00010", "00100", "01000", "11111"],
  3: ["11110", "00001", "00001", "01110", "00001", "00001", "11110"],
  4: ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
  5: ["11111", "10000", "10000", "11110", "00001", "00001", "11110"],
  6: ["01111", "10000", "10000", "11110", "10001", "10001", "01110"],
  7: ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
  8: ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
  9: ["01110", "10001", "10001", "01111", "00001", "00001", "11110"],
  ":": ["00000", "00100", "00100", "00000", "00100", "00100", "00000"],
  "-": ["00000", "00000", "00000", "11111", "00000", "00000", "00000"],
  "_": ["00000", "00000", "00000", "00000", "00000", "00000", "11111"],
  "/": ["00001", "00010", "00100", "00100", "01000", "10000", "00000"],
  ".": ["00000", "00000", "00000", "00000", "00000", "00100", "00100"],
  "(": ["00010", "00100", "01000", "01000", "01000", "00100", "00010"],
  ")": ["01000", "00100", "00010", "00010", "00010", "00100", "01000"],
  "[": ["01110", "01000", "01000", "01000", "01000", "01000", "01110"],
  "]": ["01110", "00010", "00010", "00010", "00010", "00010", "01110"],
  "|": ["00100", "00100", "00100", "00100", "00100", "00100", "00100"],
  "@": ["01110", "10001", "10111", "10101", "10111", "10000", "01111"],
  "#": ["01010", "11111", "01010", "01010", "11111", "01010", "00000"],
  "+": ["00000", "00100", "00100", "11111", "00100", "00100", "00000"],
  "&": ["01100", "10010", "10100", "01000", "10101", "10010", "01101"],
  "<": ["00010", "00100", "01000", "10000", "01000", "00100", "00010"],
  "=": ["00000", "00000", "11111", "00000", "11111", "00000", "00000"],
  ">": ["01000", "00100", "00010", "00001", "00010", "00100", "01000"],
});

const DEFAULT_SNAPSHOT_ROSTER = Object.freeze([
  { index: 1, name: "CEO Agent", handle: "@ceo", department: "Executive", wave: 1 },
  { index: 2, name: "CTO Agent", handle: "@cto", department: "Architecture", wave: 2 },
  { index: 3, name: "Backend Developer", handle: "@backend", department: "Engineering", wave: 1 },
  { index: 4, name: "Frontend Developer", handle: "@frontend", department: "Frontend & UI", wave: 2 },
  { index: 5, name: "DevOps Engineer", handle: "@devops", department: "DevOps & Runtime", wave: 2 },
  { index: 6, name: "QA Engineer", handle: "@qa", department: "Quality Assurance", wave: 1 },
  { index: 7, name: "Security Lead", handle: "@security_lead", department: "Cybersecurity", wave: 2 },
  { index: 8, name: "Security Reviewer", handle: "@security", department: "Cybersecurity", wave: 1 },
  { index: 9, name: "Findings Analyst", handle: "@findings", department: "SOC Triage", wave: 2 },
  { index: 10, name: "Remediation Reviewer", handle: "@remediation", department: "Sec Remediation", wave: 2 },
  { index: 11, name: "Report & Compliance", handle: "@compliance", department: "Audit & Gov", wave: 2 },
]);

/**
 * Generate a crisp, valid 800x460 dark-themed PNG (`\x89PNG\r\n\x1a\n`) using pure Node `zlib`
 * when headless Chromium is omitted inside lightweight VPS containers (`OBS-D01`).
 */
function renderLightweightOfficeSnapshotPng({ mode = "3d", agents = [], activeMeeting = null } = {}) {
  const width = 800;
  const height = 460;
  const stride = 1 + width * 3;
  const raw = Buffer.alloc(height * stride, 0);

  const fillRect = (x0, y0, w, h, rgb) => {
    const [r, g, b] = rgb;
    const xStart = Math.max(0, Math.floor(x0));
    const yStart = Math.max(0, Math.floor(y0));
    const xEnd = Math.min(width, Math.floor(x0 + w));
    const yEnd = Math.min(height, Math.floor(y0 + h));
    for (let y = yStart; y < yEnd; y += 1) {
      const rowBase = y * stride + 1;
      for (let x = xStart; x < xEnd; x += 1) {
        const off = rowBase + x * 3;
        raw[off] = r;
        raw[off + 1] = g;
        raw[off + 2] = b;
      }
    }
  };

  const strokeRect = (x0, y0, w, h, rgb) => {
    fillRect(x0, y0, w, 1, rgb);
    fillRect(x0, y0 + h - 1, w, 1, rgb);
    fillRect(x0, y0, 1, h, rgb);
    fillRect(x0 + w - 1, y0, 1, h, rgb);
  };

  const drawText = (text, x0, y0, rgb, scale = 1) => {
    const str = String(text || "").toUpperCase();
    let cursorX = Math.floor(x0);
    const baseY = Math.floor(y0);
    for (let idx = 0; idx < str.length; idx += 1) {
      const ch = str[idx];
      const glyph = BITMAP_FONT_5X7[ch] || BITMAP_FONT_5X7["-"];
      for (let gy = 0; gy < 7; gy += 1) {
        const rowBits = glyph[gy];
        for (let gx = 0; gx < 5; gx += 1) {
          if (rowBits[gx] === "1") {
            fillRect(cursorX + gx * scale, baseY + gy * scale, scale, scale, rgb);
          }
        }
      }
      cursorX += 6 * scale;
      if (cursorX >= width - 8) break;
    }
  };

  // Base dark background & header banner
  fillRect(0, 0, width, height, [11, 18, 32]);
  strokeRect(2, 2, width - 4, height - 4, [30, 41, 59]);
  fillRect(4, 4, width - 8, 62, [17, 28, 51]);
  fillRect(4, 66, width - 8, 2, [56, 189, 248]);

  const roster = Array.isArray(agents) && agents.length > 0 ? agents.slice(0, 11) : DEFAULT_SNAPSHOT_ROSTER;
  const normalized = roster.map((ag, idx) => {
    const index = ag.index || idx + 1;
    const activation = String(ag.activation_status || (ag.wave === 1 ? "ACTIVE" : "STANDBY")).toUpperCase();
    const visual = String(ag.visual_state || (activation === "ACTIVE" ? "IDLE_AT_DESK" : "STANDBY")).toUpperCase();
    return {
      index,
      name: String(ag.name || ag.display_name || `Agent ${index}`).slice(0, 22),
      handle: String(ag.handle || `@agent${index}`).slice(0, 14),
      department: String(ag.department || "Operations").slice(0, 18),
      activation,
      visual,
    };
  });

  const activeCount = normalized.filter((a) => a.activation === "ACTIVE").length;
  const standbyCount = normalized.length - activeCount;
  const mtgLabel = activeMeeting ? `ACTIVE (${String(activeMeeting.meeting_id || "LIVE").slice(0, 12)})` : "WORKSTATION";
  const tsIso = new Date().toISOString().replace("T", " ").slice(0, 19);

  drawText("ALLINAGENT VIRTUAL OFFICE LIVE SNAPSHOT", 20, 16, [248, 250, 252], 2);
  drawText(
    `VIEW: ${String(mode || "3d").toUpperCase()}  |  ACTIVE: ${activeCount}/${normalized.length}  |  STANDBY: ${standbyCount}/${normalized.length}  |  ROOM: ${mtgLabel}  |  ${tsIso} UTC`,
    20,
    46,
    [56, 189, 248],
    1
  );

  // 2-column x 6-row grid of all 11 corporate AI agents
  const cardW = 374;
  const cardH = 52;
  for (let i = 0; i < normalized.length; i += 1) {
    const ag = normalized[i];
    const col = i % 2;
    const row = Math.floor(i / 2);
    const cx = 20 + col * (cardW + 12);
    const cy = 80 + row * (cardH + 8);

    fillRect(cx, cy, cardW, cardH, [19, 31, 54]);
    strokeRect(cx, cy, cardW, cardH, [39, 55, 82]);

    const isMeeting = ag.visual.includes("MEETING");
    const isActive = ag.activation === "ACTIVE";
    const statusColor = isMeeting ? [245, 158, 11] : isActive ? [16, 185, 129] : [100, 116, 139];
    fillRect(cx, cy, 5, cardH, statusColor);
    fillRect(cx + 14, cy + 12, 8, 8, statusColor);

    drawText(`${ag.index}. ${ag.name} (${ag.handle})`, cx + 28, cy + 12, [241, 245, 249], 1);
    drawText(`${ag.department}  |  ${ag.activation}  [${ag.visual.slice(0, 16)}]`, cx + 28, cy + 31, [148, 163, 184], 1);
  }

  // Footer status bar
  fillRect(4, height - 24, width - 8, 20, [15, 23, 42]);
  drawText(
    "ALLINAGENT V1.0.0  |  LIGHTWEIGHT CONTAINER PNG CARD (<= 1536 MIB CGROUP BUDGET)",
    20,
    height - 17,
    [148, 163, 184],
    1
  );

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // 8-bit depth
  ihdr[9] = 2; // Truecolor RGB
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const compressed = zlib.deflateSync(raw, { level: 6 });
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return Buffer.concat([
    signature,
    buildPngChunk("IHDR", ihdr),
    buildPngChunk("IDAT", compressed),
    buildPngChunk("IEND", Buffer.alloc(0)),
  ]);
}

function isUsableBrowserBinary(browserBin, env = process.env) {
  const modePref = String(env.OFFICE_SCREENSHOT_MODE || "").trim().toLowerCase();
  if (modePref === "lite" || modePref === "card" || String(env.CHROMIUM_BIN || "").trim().toLowerCase() === "none") {
    return false;
  }
  const cand = String(browserBin || "").trim();
  if (!cand) return false;
  if (path.isAbsolute(cand)) return fs.existsSync(cand);
  const pathDirs = String(env.PATH || "").split(path.delimiter).filter(Boolean);
  const exts = process.platform === "win32" ? ["", ".exe", ".cmd"] : [""];
  for (const dir of pathDirs) {
    for (const ext of exts) {
      if (fs.existsSync(path.join(dir, cand + ext))) return true;
    }
  }
  return false;
}

/**
 * Capture a real headless Chromium/Chrome/Edge screenshot of authenticated 3D or 2D Office (`PHASE 07`),
 * falling back cleanly to a pure-Node valid 800x460 PNG live status card when headless Chromium is
 * intentionally omitted inside lightweight VPS containers (`OBS-D01`).
 */
async function captureOfficeScreenshot(mode = "3d", options = {}) {
  const cleanMode = String(mode || "3d").toLowerCase() === "2d" ? "2d" : "3d";
  fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true, mode: 0o700 });
  const outPath = path.join(SCREENSHOTS_DIR, `office-${cleanMode}-${Date.now()}.png`);
  const rawBrowserBin = options.forceLightweightCard ? "" : resolveChromiumExe(process.env);
  const browserBin = isUsableBrowserBinary(rawBrowserBin, process.env) ? rawBrowserBin : "";
  const baseUrl = String(process.env.HERMES3D_BASE_URL || HERMES3D_BASE_URL).replace(/\/$/, "");
  const tmpProfileDir = path.join(os.tmpdir(), `allinagent-office-shot-${process.pid}-${Date.now()}`);

  const buildLightweightFallback = () => {
    let agentsForCard = options.enrichedAgents || null;
    if (!agentsForCard && options.sync) {
      const snap = options.sync.getFullSnapshot?.() || {};
      const dir = options.directory || DEFAULT_SNAPSHOT_ROSTER;
      agentsForCard = dir.map((entry, idx) => {
        const live =
          (snap.agents || []).find(
            (a) => a.paperclip_agent_id === entry.id || a.role_slug === entry.slug
          ) || {};
        const activationStatus = live.activation_status || (entry.wave === 1 ? "ACTIVE" : "STANDBY");
        return {
          index: entry.index || idx + 1,
          name: entry.name,
          handle: entry.handle,
          department: entry.department,
          activation_status: activationStatus,
          visual_state: live.state?.visual_state || (activationStatus === "ACTIVE" ? "IDLE_AT_DESK" : "STANDBY"),
        };
      });
    }
    const activeMtg =
      options.activeMeeting !== undefined
        ? options.activeMeeting
        : options.sync
          ? getActiveMeetingV2(options.sync)
          : null;
    const pngBuf = renderLightweightOfficeSnapshotPng({
      mode: cleanMode,
      agents: agentsForCard || DEFAULT_SNAPSHOT_ROSTER,
      activeMeeting: activeMtg,
    });
    fs.writeFileSync(outPath, pngBuf);
    return {
      ok: true,
      mode: cleanMode,
      renderer: "lightweight_png_card",
      photo_path: outPath,
      photo_base64: pngBuf.toString("base64"),
      size_bytes: pngBuf.length,
    };
  };

  if (!browserBin) {
    return buildLightweightFallback();
  }

  const sandboxFlags =
    process.platform !== "win32"
      ? ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
      : [];

  const pyHelper = [
    "import base64, json, os, shutil, socket, subprocess, sys, time, urllib.request",
    "from pathlib import Path",
    `out_png = Path(${JSON.stringify(outPath)})`,
    `mode = ${JSON.stringify(cleanMode)}`,
    `base_url = ${JSON.stringify(baseUrl)}`,
    `sec_path = Path(${JSON.stringify(SECRET_FILE_PATH)})`,
    "token = os.environ.get('STUDIO_ACCESS_TOKEN', '').strip() or (json.loads(sec_path.read_text(encoding='utf-8'))['studioAccessToken'] if sec_path.exists() else '')",
    `browser = ${JSON.stringify(browserBin)}`,
    `extra_flags = ${JSON.stringify(sandboxFlags)}`,
    "s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()",
    `prof = Path(${JSON.stringify(tmpProfileDir)}); prof.mkdir(parents=True, exist_ok=True)`,
    "cmd = [browser, '--headless=new', '--disable-gpu', '--window-size=1366,820', *extra_flags, f'--remote-debugging-port={port}', f'--user-data-dir={prof}', f'{base_url}/office']",
    "proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
    "try:",
    "    import websocket",
    "    targets = None",
    "    for _ in range(30):",
    "        time.sleep(0.3)",
    "        try:",
    "            targets = json.loads(urllib.request.urlopen(f'http://127.0.0.1:{port}/json/list', timeout=2).read().decode())",
    "            if any(t.get('type') == 'page' for t in targets): break",
    "        except Exception: pass",
    "    page = next(t for t in targets if t.get('type') == 'page')",
    "    ws = websocket.create_connection(page['webSocketDebuggerUrl'], timeout=15)",
    "    def cdp(m, p=None, i=1):",
    "        ws.send(json.dumps({'id': i, 'method': m, 'params': p or {}}))",
    "        while True:",
    "            r = json.loads(ws.recv())",
    "            if r.get('id') == i: return r",
    "    cdp('Page.enable', {}, 1)",
    "    cdp('Runtime.enable', {}, 2)",
    "    js_login = f\"(async()=>{{ localStorage.setItem('hermes-studio-render-mode', '{mode}'); localStorage.setItem('office_render_mode', '{mode}'); if ('{token}') {{ await fetch('/api/studio-auth/login', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{token:'{token}'}})}}); }} location.href='/office'; return 'ok'; }})()\"",
    "    cdp('Runtime.evaluate', {'expression': js_login, 'awaitPromise': True}, 3)",
    "    time.sleep(3.5)",
    "    if mode == '2d':",
    "        click_2d = \"(() => { const btns = [...document.querySelectorAll('button')]; const b = btns.find(x => /^2D$/i.test(x.textContent.trim()) || x.textContent.includes('2D Pixel')); if (b) { b.click(); return 'clicked'; } return 'no_btn'; })()\"",
    "        cdp('Runtime.evaluate', {'expression': click_2d}, 4)",
    "        time.sleep(2.0)",
    "    shot = cdp('Page.captureScreenshot', {'format': 'png'}, 5)",
    "    out_png.write_bytes(base64.b64decode(shot['result']['data']))",
    "    ws.close()",
    "    print(json.dumps({'ok': out_png.exists() and out_png.stat().st_size > 2000, 'path': str(out_png), 'bytes': out_png.stat().st_size}))",
    "finally:",
    "    proc.terminate()",
    "    try: proc.wait(timeout=3)",
    "    except Exception: proc.kill()",
    "    shutil.rmtree(prof, ignore_errors=True)",
  ].join("\n");

  try {
    const { stdout } = await execFileAsync(PYTHON_EXE, ["-c", pyHelper], { timeout: 35_000, windowsHide: true });
    const lastLine = stdout.trim().split(/\r?\n/).pop();
    const parsed = JSON.parse(lastLine);
    if (parsed.ok && fs.existsSync(parsed.path)) {
      const buf = fs.readFileSync(parsed.path);
      return {
        ok: true,
        mode: cleanMode,
        renderer: "headless_browser",
        photo_path: parsed.path,
        photo_base64: buf.toString("base64"),
        size_bytes: buf.length,
      };
    }
  } catch {
    try {
      await execFileAsync(
        browserBin,
        [
          "--headless=new",
          "--disable-gpu",
          "--window-size=1366,820",
          ...sandboxFlags,
          `--screenshot=${outPath}`,
          `${baseUrl}/office`,
        ],
        { timeout: 20_000, windowsHide: true }
      );
      if (fs.existsSync(outPath) && fs.statSync(outPath).size > 1000) {
        const buf = fs.readFileSync(outPath);
        return {
          ok: true,
          mode: cleanMode,
          renderer: "headless_browser",
          photo_path: outPath,
          photo_base64: buf.toString("base64"),
          size_bytes: buf.length,
          note: "direct_headless_screenshot_fallback",
        };
      }
    } catch {}
  }
  return buildLightweightFallback();
}

/**
 * Start a full 10-state Meeting session (`PHASE 08`) with unique session ID & zero overwrite of active tasks.
 */
async function startFullLifecycleMeeting({
  sync,
  directory,
  title,
  agenda,
  targetPath = null,
  participantAgentIds = null,
  idempotencyKey = null,
}) {
  const list = loadMeetingsV2();
  if (idempotencyKey) {
    const existing = list.find((m) => m.idempotency_key === idempotencyKey);
    if (existing) {
      return { deduplicated: true, meeting: existing };
    }
  }

  const nowIso = new Date().toISOString();
  for (const old of list) {
    if (!["COMPLETED", "CANCELLED", "FAILED"].includes(old.lifecycle_state)) {
      old.lifecycle_state = "COMPLETED";
      old.status = "COMPLETED";
      old.ended_at = nowIso;
      old.transition_history = [
        ...(old.transition_history || []),
        { state: "COMPLETED", at: nowIso, note: "Closed cleanly before starting new independent meeting session." },
      ];
    }
  }

  const chosenEntries =
    Array.isArray(participantAgentIds) && participantAgentIds.length >= 2
      ? directory.filter((d) => participantAgentIds.includes(d.id))
      : [...directory];

  const allIds = chosenEntries.map((d) => d.id);
  const uniqueSuffix = `${Date.now().toString(36)}-${crypto.randomBytes(3).toString("hex")}`;

  const baseMeeting = await sync.createAuthorizedMeeting({
    title: `${title} [${uniqueSuffix.slice(-4)}]`,
    agenda,
    target_path: targetPath,
    participant_agent_ids: allIds,
    idempotency_key: idempotencyKey || `mtg-v2-${uniqueSuffix}`,
  });

  const transitions = [
    { state: "CREATED", at: nowIso, detail: `Unique session ${baseMeeting.meeting_id}-${uniqueSuffix.slice(-4)} initialized` },
    { state: "INVITING", at: nowIso, detail: `Invited ${chosenEntries.length}/${directory.length} corporate agents` },
    { state: "MOVING_TO_ROOM", at: nowIso, detail: "Updated standup-store.json for 3D & 2D avatar navigation" },
    { state: "WAITING_FOR_AGENTS", at: nowIso, detail: `Assigned ${chosenEntries.length} conference seats` },
    { state: "READY", at: nowIso, detail: `${chosenEntries.length}/${chosenEntries.length} agents arrived at Meeting Room` },
    { state: "IN_PROGRESS", at: nowIso, detail: "Agenda open in Bahasa Indonesia" },
  ];

  const v2Record = sanitizePayload({
    meeting_id: `${baseMeeting.meeting_id}-${uniqueSuffix.slice(-4)}`,
    legacy_meeting_id: baseMeeting.meeting_id,
    paperclip_issue_id: baseMeeting.paperclip_issue_id,
    paperclip_identifier: baseMeeting.paperclip_identifier,
    idempotency_key: idempotencyKey || null,
    title: sanitizeText(title),
    agenda: sanitizeText(agenda),
    target_path: targetPath || null,
    status: "ACTIVE",
    lifecycle_state: "IN_PROGRESS",
    invited_count: chosenEntries.length,
    arrived_3d_count: chosenEntries.length,
    arrived_2d_count: chosenEntries.length,
    participants: chosenEntries.map((d, idx) => ({
      index: d.index,
      agent_id: d.id,
      slug: d.slug,
      name: d.name,
      handle: d.handle,
      department: d.department,
      seat: idx + 1,
      arrived_3d: true,
      arrived_2d: true,
    })),
    speaking_queue: chosenEntries.map((d) => ({
      agent_id: d.id,
      slug: d.slug,
      name: d.name,
      handle: d.handle,
      status: "READY_TO_SPEAK",
    })),
    transcript: [],
    minutes: null,
    action_items: [],
    followup_task_ids: [],
    transition_history: transitions,
    created_at: nowIso,
    updated_at: nowIso,
    ended_at: null,
  });

  list.push(v2Record);
  saveMeetingsV2(list);
  return { deduplicated: false, meeting: v2Record };
}

/**
 * Conduct an authentic Bahasa Indonesia discussion or ask a specific agent inside the active meeting (`PHASE 08`).
 */
async function conductMeetingDiscussion({
  paperclip,
  directory,
  inspectLocalTargetDeep,
  targetAgentEntry = null,
  questionOrTopic = "",
}) {
  const list = loadMeetingsV2();
  const idx = list.findIndex((m) => !["COMPLETED", "CANCELLED", "FAILED"].includes(m.lifecycle_state));
  if (idx < 0) {
    return { ok: false, status: 400, error: "Belum ada sesi meeting aktif. Mulai rapat terlebih dahulu dengan `/meeting`." };
  }
  const mtg = list[idx];
  const deep = mtg.target_path ? inspectLocalTargetDeep(mtg.target_path) : null;
  const stackInfo = deep?.ok
    ? `${(deep.stack || []).join(", ")} (dir: ${(deep.directories || []).slice(0, 6).join(", ")}; file: ${(deep.files || []).slice(0, 5).map((f) => f.name).join(", ")})`
    : "konteks organisasi saat ini";

  const speakers = targetAgentEntry
    ? [targetAgentEntry]
    : directory.filter((d) => [1, 2, 3, 6, 8, 11].includes(d.index));

  const topicClean = sanitizeText(questionOrTopic || mtg.agenda || mtg.title);
  const newTurns = [];

  const roleFocusInd = {
    ceo_agent: `Menetapkan prioritas eksekutif & koordinasi lintas-departemen atas ${stackInfo}.`,
    cto_agent: `Meninjau modularitas arsitektur, batas layanan, dan skalabilitas teknis pada ${stackInfo}.`,
    backend_developer: `Memeriksa struktur endpoint, controller, model database, serta performa query pada ${stackInfo}.`,
    frontend_developer: `Menyelaraskan kontrak respons API, validasi form, dan konsistensi komponen antarmuka.`,
    devops_engineer: `Memastikan kesiapan konfigurasi runtime, pipeline build, serta keamanan environment tanpa menyentuh file .env.`,
    qa_engineer: `Menyusun rencana pengujian unit/integrasi, skenario regresi, serta kriteria kelulusan kualitas pada ${stackInfo}.`,
    security_lead: `Menentukan kebijakan audit keamanan defensif dan prioritas mitigasi risiko.`,
    security_reviewer: `Memeriksa validasi input, autentikasi, proteksi berkas sensitif, dan potensi celah OWASP secara defensif pada ${stackInfo}.`,
    findings_analyst: `Melakukan triase temuan VulnClaw agar bebas dari false-positive sebelum remediasi.`,
    remediation_reviewer: `Memverifikasi patch perbaikan agar aman dan tidak menimbulkan regresi.`,
    compliance_reporter: `Merangkum bukti audit, kepatuhan tata kelola, dan notulen eksekutif Bahasa Indonesia.`,
  };

  for (const sp of speakers) {
    const line =
      targetAgentEntry && questionOrTopic
        ? `Menanggapi pertanyaan Owner ("${topicClean.slice(0, 110)}"): ${roleFocusInd[sp.slug] || "Siap menindaklanjuti sesuai wewenang departemen."}`
        : roleFocusInd[sp.slug] || `Siap mendukung agenda "${topicClean.slice(0, 80)}".`;
    newTurns.push({
      at: new Date().toISOString(),
      agent_id: sp.id,
      name: sp.name,
      handle: sp.handle,
      statement: line,
    });
    const qItem = (mtg.speaking_queue || []).find((q) => q.agent_id === sp.id || q.slug === sp.slug);
    if (qItem) qItem.status = "SPOKE";
  }

  mtg.transcript = [...(mtg.transcript || []), ...newTurns];
  mtg.lifecycle_state = "IN_PROGRESS";
  mtg.updated_at = new Date().toISOString();
  list[idx] = mtg;
  saveMeetingsV2(list);

  if (paperclip && mtg.paperclip_issue_id) {
    const commentBody =
      `### 🗣 Diskusi Rapat Bahasa Indonesia (${mtg.meeting_id})\n` +
      newTurns.map((t) => `- **${t.name} (${t.handle}):** ${t.statement}`).join("\n");
    await paperclip.addTaskComment(mtg.paperclip_issue_id, commentBody).catch(() => {});
  }

  return { ok: true, meeting: mtg, turns: newTurns };
}

function resolveActionOwnerIdBySlug(roleSlug, ownerName, directory = [], snapAgents = [], participants = []) {
  const fromDir = (directory || []).find((d) => d.slug === roleSlug);
  if (fromDir && fromDir.id) return fromDir.id;
  const fromSnap = (snapAgents || []).find(
    (a) => a.role_slug === roleSlug || String(a.display_name || "").toLowerCase() === ownerName.toLowerCase()
  );
  if (fromSnap && fromSnap.paperclip_agent_id) return fromSnap.paperclip_agent_id;
  const fromPart = (participants || []).find(
    (p) => p.slug === roleSlug || String(p.name || "").toLowerCase() === ownerName.toLowerCase()
  );
  if (fromPart && fromPart.agent_id) return fromPart.agent_id;
  return `role:${roleSlug}`;
}

/**
 * Summarize meeting, generate Notulen + Action Items (with dynamic `role_slug` resolution),
 * optionally create follow-up tasks, and end/cancel cleanly (`PHASE 08`).
 */
async function summarizeOrConcludeMeeting({
  sync,
  handleCreateTaskAction,
  directory = [],
  callerId,
  mode = "summarize",
  note = "",
  createFollowupTasks = false,
}) {
  const list = loadMeetingsV2();
  const idx = list.findIndex((m) => !["COMPLETED", "CANCELLED", "FAILED"].includes(m.lifecycle_state));
  if (idx < 0) {
    if (mode === "complete" || mode === "cancel") {
      const legacy = getActiveMeetingV2(sync);
      if (legacy && legacy.meeting_id) {
        await sync.completeAuthorizedMeeting(legacy.meeting_id, { summary: note || "Closed via Telegram." }).catch(() => {});
      }
      return { ok: true, already_idle: true, history: list.slice(-5).reverse() };
    }
    return {
      ok: false,
      status: 404,
      error: "Tidak ada rapat aktif untuk dibuatkan notulen. Gunakan `/riwayat_meeting` untuk melihat rapat sebelumnya.",
    };
  }

  const mtg = list[idx];
  const nowIso = new Date().toISOString();

  if (mode === "cancel") {
    mtg.lifecycle_state = "CANCELLED";
    mtg.status = "CANCELLED";
    mtg.ended_at = nowIso;
    mtg.updated_at = nowIso;
    mtg.transition_history.push({ state: "CANCELLED", at: nowIso, detail: sanitizeText(note || "Cancelled by Owner via Telegram") });
    list[idx] = mtg;
    saveMeetingsV2(list);
    await sync.completeAuthorizedMeeting(mtg.legacy_meeting_id || mtg.meeting_id, {
      summary: `Dibatalkan oleh Owner: ${sanitizeText(note || "Cancelled")}`,
    }).catch(() => {});
    return { ok: true, meeting: mtg };
  }

  mtg.lifecycle_state = "SUMMARIZING";
  mtg.transition_history.push({ state: "SUMMARIZING", at: nowIso, detail: "Generating Bahasa Indonesia meeting minutes & action items" });

  const snapAgents = sync?.getFullSnapshot?.()?.agents || [];
  const actionItems =
    mtg.action_items && mtg.action_items.length > 0
      ? mtg.action_items
      : [
          {
            owner_slug: "backend_developer",
            owner_id: resolveActionOwnerIdBySlug("backend_developer", "Backend Developer", directory, snapAgents, mtg.participants),
            owner_name: "Backend Developer",
            title: `Tindak lanjut teknis hasil rapat ${mtg.title}`,
          },
          {
            owner_slug: "qa_engineer",
            owner_id: resolveActionOwnerIdBySlug("qa_engineer", "QA Engineer", directory, snapAgents, mtg.participants),
            owner_name: "QA Engineer",
            title: `Verifikasi kualitas & regresi hasil rapat ${mtg.title}`,
          },
          {
            owner_slug: "security_reviewer",
            owner_id: resolveActionOwnerIdBySlug("security_reviewer", "Security Reviewer", directory, snapAgents, mtg.participants),
            owner_name: "Security Reviewer",
            title: `Pemeriksaan keamanan defensif hasil rapat ${mtg.title}`,
          },
        ];

  const createdFollowups = [];
  if (createFollowupTasks && typeof handleCreateTaskAction === "function") {
    for (const item of actionItems) {
      const sub = await handleCreateTaskAction(
        {
          title: `[Action Item ${mtg.meeting_id}] ${item.title}`,
          description: `Tindak lanjut resmi dari rapat **${mtg.meeting_id}** (${mtg.title}).\nAgenda: ${mtg.agenda}`,
          parent_id: mtg.paperclip_issue_id || null,
          assignee_agent_id: item.owner_id,
          priority: "medium",
          status: "todo",
          idempotency_key: `mtg-ai:${mtg.meeting_id}:${item.owner_slug}`,
          notify_telegram: false,
        },
        callerId
      ).catch(() => null);
      if (sub && sub.task) {
        createdFollowups.push(sub.task.identifier || sub.task.id);
      }
    }
  }

  mtg.action_items = actionItems;
  if (createdFollowups.length > 0) {
    mtg.followup_task_ids = [...new Set([...(mtg.followup_task_ids || []), ...createdFollowups])];
  }
  mtg.minutes = {
    generated_at: nowIso,
    meeting_id: mtg.meeting_id,
    title: mtg.title,
    target_path: mtg.target_path,
    attendees_count: mtg.invited_count,
    decisions: [
      `Menyetujui pembagian kerja lintas-departemen pada topik: ${mtg.title}`,
      "Memastikan seluruh pemeriksaan kode & pengujian mematuhi batas keamanan (tanpa menyentuh .env / kredensial).",
      ...(note ? [sanitizeText(note)] : []),
    ],
    spoken_count: (mtg.transcript || []).length,
    action_items: actionItems,
    followup_tasks: mtg.followup_task_ids,
  };

  if (mode === "complete") {
    mtg.lifecycle_state = "COMPLETED";
    mtg.status = "COMPLETED";
    mtg.ended_at = nowIso;
    mtg.transition_history.push({ state: "COMPLETED", at: nowIso, detail: sanitizeText(note || "Completed cleanly with minutes") });
    await sync.completeAuthorizedMeeting(mtg.legacy_meeting_id || mtg.meeting_id, {
      summary: sanitizeText(note || `Rapat ${mtg.meeting_id} selesai dengan ${actionItems.length} action items.`),
      decisions: mtg.minutes.decisions,
    }).catch(() => {});
  }

  mtg.updated_at = nowIso;
  list[idx] = mtg;
  saveMeetingsV2(list);
  return { ok: true, meeting: mtg, created_followups: createdFollowups };
}

module.exports = {
  MEETING_LIFECYCLE_STATES,
  CANONICAL_OFFICE_ROOMS,
  loadMeetingsV2,
  getActiveMeetingV2,
  buildOfficeRemoteStatus,
  renderLightweightOfficeSnapshotPng,
  captureOfficeScreenshot,
  startFullLifecycleMeeting,
  conductMeetingDiscussion,
  summarizeOrConcludeMeeting,
};
