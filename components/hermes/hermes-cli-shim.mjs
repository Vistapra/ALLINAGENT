#!/usr/bin/env node
/**
 * ALLINAGENT Cross-Container Hermes CLI Shim (`/usr/local/bin/hermes`).
 *
 * Installed inside `allinagent-paperclip` and `allinagent-office-bridge` Node.js
 * containers so `@paperclipai/hermes-paperclip-adapter` (`hermes_local`) and Office
 * Bridge invoke `hermes` 100% natively without duplicating Python, uv, or Hermes
 * dependencies inside Node containers.
 *
 * Behavior:
 *   - Reads `HERMES_REMOTE_EXEC_URL` first, falling back to `HERMES_EXEC_URL`
 *     (default `http://hermes:8650`, unless `HERMES_REAL_BIN` is explicitly set with
 *     no remote URL configured).
 *   - Reads shared secret from `ALLINAGENT_INTERNAL_TOKEN` first, falling back to
 *     `HERMES_EXEC_SHARED_SECRET`.
 *   - Restricts `PAPERCLIP_*` env passthrough strictly to the 8 safe worker keys so
 *     server-only secrets (`PAPERCLIP_AGENT_JWT_SECRET`, `PAPERCLIP_TOOL_ACTION_SIGNING_SECRET`,
 *     etc.) are NEVER forwarded into child agent runs.
 */

import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_REMOTE_EXEC_URL = "http://hermes:8650";

const FORBIDDEN_ENV_KEYS = new Set([
  "TELEGRAM_BOT_TOKEN",
  "OWNER_TELEGRAM_ID",
  "ALLINAGENT_INTERNAL_TOKEN",
  "HERMES_EXEC_SHARED_SECRET",
  "OFFICE_BRIDGE_TOKEN",
  "OFFICE_BRIDGE_AUTH_TOKEN",
  "PAPERCLIP_BOARD_API_KEY",
  "PAPERCLIP_AGENT_JWT_SECRET",
  "PAPERCLIP_TOOL_ACTION_SIGNING_SECRET",
  "PAPERCLIP_WAKE_PAYLOAD_JSON",
  "DATABASE_URL",
  "POSTGRES_PASSWORD",
  "HERMES_REMOTE_EXEC_URL",
  "HERMES_EXEC_URL",
  "STUDIO_ACCESS_PASSWORD",
  "BETTER_AUTH_SECRET",
]);

const SAFE_PAPERCLIP_ENV_KEYS = new Set([
  "PAPERCLIP_API_URL",
  "PAPERCLIP_API_KEY",
  "PAPERCLIP_RUN_ID",
  "PAPERCLIP_TASK_ID",
  "PAPERCLIP_AGENT_ID",
  "PAPERCLIP_COMPANY_ID",
  "PAPERCLIP_WAKE_REASON",
  "PAPERCLIP_WAKE_COMMENT_ID",
]);

const SAFE_HERMES_ENV_KEYS = new Set([
  "HERMES_HOME",
  "HERMES_PROFILE",
  "HERMES_EPHEMERAL_SYSTEM_PROMPT",
  "HERMES_QUIET",
  "HERMES_MODEL",
  "HERMES_PROVIDER",
  "HERMES_MAX_TURNS",
  "HERMES_TOOLSETS",
]);

function writeStream(stream, text) {
  return new Promise((resolve) => {
    if (!text) {
      resolve();
      return;
    }
    if (stream.write(text)) {
      resolve();
    } else {
      stream.once("drain", resolve);
    }
  });
}

function readStdinUtf8() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", reject);
  });
}

async function extractQueryFileContent(argv) {
  let qPath = null;
  for (let i = 0; i < argv.length; i += 1) {
    const tok = argv[i];
    if (tok === "--query-file") {
      if (i + 1 >= argv.length) {
        throw { exitCode: 2, message: "Error: --query-file requires a file path argument" };
      }
      qPath = argv[i + 1];
      break;
    }
    if (tok.startsWith("--query-file=")) {
      qPath = tok.slice("--query-file=".length);
      break;
    }
  }

  if (qPath === null) {
    return null;
  }

  let content = "";
  try {
    if (qPath === "-") {
      content = await readStdinUtf8();
    } else {
      content = fs.readFileSync(qPath, "utf8");
    }
  } catch (err) {
    const detail = err && err.message ? err.message : String(err);
    throw { exitCode: 2, message: `Error: cannot read --query-file ${qPath}: ${detail}` };
  }

  if (!content.trim()) {
    throw { exitCode: 2, message: `Error: --query-file ${qPath} is empty` };
  }
  return content;
}

function collectSafeEnv(envObj) {
  const out = {};
  for (const [key, val] of Object.entries(envObj || {})) {
    if (typeof val !== "string" || !key || FORBIDDEN_ENV_KEYS.has(key)) {
      continue;
    }
    if (SAFE_PAPERCLIP_ENV_KEYS.has(key)) {
      out[key] = val;
    } else if (SAFE_HERMES_ENV_KEYS.has(key)) {
      out[key] = val;
    }
  }
  return out;
}

function postExecRequest(remoteBaseUrl, token, bodyObj, timeoutMs) {
  return new Promise((resolve, reject) => {
    let parsedUrl;
    try {
      const normalized = remoteBaseUrl.replace(/\/+$/, "");
      parsedUrl = new URL(
        normalized.endsWith("/v1/exec") || normalized.endsWith("/exec")
          ? normalized
          : `${normalized}/v1/exec`,
      );
    } catch (err) {
      reject(new Error(`Invalid HERMES_REMOTE_EXEC_URL "${remoteBaseUrl}": ${err.message}`));
      return;
    }

    const bodyBuf = Buffer.from(JSON.stringify(bodyObj), "utf8");
    const transport = parsedUrl.protocol === "https:" ? https : http;

    const req = transport.request(
      {
        protocol: parsedUrl.protocol,
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === "https:" ? 443 : 80),
        path: `${parsedUrl.pathname}${parsedUrl.search}`,
        method: "POST",
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Content-Length": bodyBuf.length,
          "X-Internal-Exec-Token": token,
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(Buffer.from(c)));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          let parsed = null;
          try {
            parsed = JSON.parse(raw);
          } catch {
            reject(
              new Error(
                `Malformed JSON from hermes-exec-daemon (HTTP ${res.statusCode}): ${raw.slice(0, 240)}`,
              ),
            );
            return;
          }
          resolve({ statusCode: res.statusCode || 500, data: parsed });
        });
      },
    );

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Remote Hermes execution timed out after ${Math.round(timeoutMs / 1000)}s`));
    });

    req.on("error", (err) => reject(err));

    const abortSignalHandler = () => {
      req.destroy(new Error("Shim terminated by signal"));
    };
    process.once("SIGTERM", abortSignalHandler);
    process.once("SIGINT", abortSignalHandler);
    req.on("close", () => {
      process.removeListener("SIGTERM", abortSignalHandler);
      process.removeListener("SIGINT", abortSignalHandler);
    });

    req.write(bodyBuf);
    req.end();
  });
}

function runLocalFallback(argv) {
  const realBin = (process.env.HERMES_REAL_BIN || "").trim();
  if (!realBin) {
    process.stderr.write(
      "Error: Neither HERMES_REMOTE_EXEC_URL nor HERMES_REAL_BIN is configured for hermes-cli-shim.\n",
    );
    process.exit(127);
  }

  try {
    const selfReal = fs.realpathSync(fileURLToPath(import.meta.url));
    const targetReal = fs.realpathSync(realBin);
    if (selfReal === targetReal) {
      process.stderr.write("Error: HERMES_REAL_BIN points to hermes-cli-shim itself (loop prevented).\n");
      process.exit(78);
    }
  } catch (err) {
    process.stderr.write(`Error: Cannot resolve HERMES_REAL_BIN "${realBin}": ${err.message}\n`);
    process.exit(127);
  }

  const child = spawn(realBin, argv, { stdio: "inherit", env: process.env });
  child.on("error", (err) => {
    process.stderr.write(`Error: Failed to spawn ${realBin}: ${err.message}\n`);
    process.exit(127);
  });
  child.on("exit", (code, sig) => {
    if (sig) {
      process.kill(process.pid, sig);
      return;
    }
    process.exit(typeof code === "number" ? code : 1);
  });
}

function resolveRemoteExecUrl(envObj = process.env) {
  const explicit = (envObj.HERMES_REMOTE_EXEC_URL || envObj.HERMES_EXEC_URL || "").trim();
  if (explicit) {
    const lower = explicit.toLowerCase();
    if (lower === "local" || lower === "off" || lower === "none") {
      return "";
    }
    return explicit;
  }
  if ((envObj.HERMES_REAL_BIN || "").trim()) {
    return "";
  }
  return DEFAULT_REMOTE_EXEC_URL;
}

function resolveSharedExecSecret(envObj = process.env) {
  return (envObj.ALLINAGENT_INTERNAL_TOKEN || envObj.HERMES_EXEC_SHARED_SECRET || "").trim();
}

async function main() {
  const argv = process.argv.slice(2);
  const remoteUrl = resolveRemoteExecUrl(process.env);

  if (!remoteUrl) {
    runLocalFallback(argv);
    return;
  }

  const token = resolveSharedExecSecret(process.env);
  if (!token) {
    await writeStream(
      process.stderr,
      "Error: ALLINAGENT_INTERNAL_TOKEN (or HERMES_EXEC_SHARED_SECRET) is required for remote Hermes execution.\n",
    );
    process.exit(78);
  }

  let queryFileContent = null;
  try {
    queryFileContent = await extractQueryFileContent(argv);
  } catch (qErr) {
    await writeStream(process.stderr, `${qErr.message || String(qErr)}\n`);
    process.exit(typeof qErr.exitCode === "number" ? qErr.exitCode : 2);
  }

  const workerTimeoutSec = Number.parseInt(process.env.HERMES_WORKER_TIMEOUT_SEC || "420", 10) || 420;
  // Allow extra HTTP client slack for FIFO queue waiting when HEAVY_WORKER_CONCURRENCY=1
  const httpTimeoutMs =
    Number.parseInt(process.env.HERMES_SHIM_TIMEOUT_MS || "", 10) ||
    Math.max((workerTimeoutSec + 540) * 1000, 960_000);

  const payload = {
    argv,
    query_file_content: queryFileContent,
    cwd: process.cwd(),
    env: collectSafeEnv(process.env),
    timeout_sec: workerTimeoutSec,
  };

  try {
    const { data } = await postExecRequest(remoteUrl, token, payload, httpTimeoutMs);
    if (typeof data?.stdout === "string" && data.stdout.length > 0) {
      await writeStream(process.stdout, data.stdout);
    }
    if (typeof data?.stderr === "string" && data.stderr.length > 0) {
      await writeStream(process.stderr, data.stderr);
    } else if (data?.error && data?.exit_code !== 0) {
      await writeStream(process.stderr, `${data.error}\n`);
    }
    const exitCode = typeof data?.exit_code === "number" ? data.exit_code : 1;
    process.exit(exitCode);
  } catch (err) {
    const msg = err && err.message ? err.message : String(err);
    await writeStream(process.stderr, `[hermes-cli-shim] Remote execution failed: ${msg}\n`);
    process.exit(70);
  }
}

main();
