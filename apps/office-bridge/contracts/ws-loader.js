"use strict";

/**
 * Cross-platform `ws` module loader for ALLINAGENT Office Bridge.
 * Resolves `ws` from local `node_modules`, monorepo `node_modules`, or sibling app `node_modules`.
 */

const fs = require("node:fs");
const path = require("node:path");
const { OFFICE_BRIDGE_ROOT, PLATFORM_ROOT } = require("./paths");

function loadWsModule() {
  const candidates = [];
  if (process.env.OFFICE_BRIDGE_WS_PATH && process.env.OFFICE_BRIDGE_WS_PATH.trim()) {
    candidates.push(path.resolve(process.env.OFFICE_BRIDGE_WS_PATH.trim()));
  }
  candidates.push(
    path.join(OFFICE_BRIDGE_ROOT, "node_modules", "ws"),
    path.join(PLATFORM_ROOT, "node_modules", "ws"),
    path.join(PLATFORM_ROOT, "apps", "hermes3d", "node_modules", "ws"),
    path.join(PLATFORM_ROOT, "hermes3d", "node_modules", "ws"),
    path.join(PLATFORM_ROOT, "hermes3d", "source", "node_modules", "ws"),
    path.join(PLATFORM_ROOT, "apps", "paperclip", "node_modules", "ws"),
    path.join(PLATFORM_ROOT, "paperclip", "node_modules", "ws")
  );

  if (process.env.NODE_PATH && process.env.NODE_PATH.trim()) {
    for (const rawDir of process.env.NODE_PATH.split(path.delimiter)) {
      const nmDir = rawDir.trim();
      if (!nmDir) continue;
      const resolvedNm = path.resolve(nmDir);
      candidates.push(
        path.join(resolvedNm, "ws"),
        path.resolve(resolvedNm, "..", "node_modules", "ws"),
        path.resolve(resolvedNm, "..", "..", "node_modules", "ws"),
        path.resolve(resolvedNm, "..", "..", "hermes3d", "node_modules", "ws"),
        path.resolve(resolvedNm, "..", "..", "hermes3d", "source", "node_modules", "ws")
      );
    }
  }

  for (const pnpmDir of [
    path.join(PLATFORM_ROOT, "node_modules", ".pnpm"),
    path.join(PLATFORM_ROOT, "apps", "paperclip", "node_modules", ".pnpm"),
    path.join(PLATFORM_ROOT, "paperclip", "node_modules", ".pnpm"),
  ]) {
    if (fs.existsSync(pnpmDir)) {
      try {
        for (const entry of fs.readdirSync(pnpmDir)) {
          if (entry.startsWith("ws@")) {
            candidates.push(path.join(pnpmDir, entry, "node_modules", "ws"));
          }
        }
      } catch {}
    }
  }

  for (const c of candidates) {
    if (fs.existsSync(c)) {
      return require(c);
    }
  }
  return require("ws");
}

module.exports = { loadWsModule };
