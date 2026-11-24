const http = require("node:http");
const https = require("node:https");
const next = require("next");

const { createAccessGate } = require("./access-gate");
const { createGatewayProxy } = require("./gateway-proxy");
const { assertPublicHostAllowed, resolveHosts } = require("./network-policy");
const { loadUpstreamGatewaySettings } = require("./studio-settings");

const resolvePort = () => {
  const raw = process.env.PORT?.trim() || "3000";
  const port = Number(raw);
  if (!Number.isFinite(port) || port <= 0) return 3000;
  return port;
};

const resolvePathname = (url) => {
  const raw = typeof url === "string" ? url : "";
  const idx = raw.indexOf("?");
  return (idx === -1 ? raw : raw.slice(0, idx)) || "/";
};

const resolveSecretFileCandidates = (env = process.env) => {
  const path = require("node:path");
  const secretsDir = String(env.ALLINAGENT_SECRETS_DIR || "/var/lib/allinagent/secrets").trim();
  const explicitRoot = String(
    env.ALLINAGENT_ROOT || env.ALLAGENT_ROOT || env.PLATFORM_ROOT || ""
  ).trim();
  const rootCandidates = [
    ...(explicitRoot ? [path.resolve(explicitRoot)] : []),
    path.resolve(__dirname, "..", "..", ".."),
    path.resolve(__dirname, "..", ".."),
    path.resolve(__dirname, ".."),
  ];
  const candidates = [
    path.resolve(secretsDir || "/var/lib/allinagent/secrets", "office-bridge-auth.json"),
  ];
  for (const rootDir of new Set(rootCandidates)) {
    candidates.push(path.resolve(rootDir, "config", "secrets", "office-bridge-auth.json"));
    candidates.push(path.resolve(rootDir, "data", "secrets", "office-bridge-auth.json"));
  }
  return Array.from(new Set(candidates));
};

const resolveOfficeBridgeToken = (env = process.env) => {
  const envToken = String(
    env.OFFICE_BRIDGE_TOKEN || env.HERMES3D_GATEWAY_TOKEN || env.STUDIO_ACCESS_TOKEN || ""
  ).trim();
  if (envToken) return envToken;

  const fs = require("node:fs");
  for (const secretFile of resolveSecretFileCandidates(env)) {
    try {
      if (!fs.existsSync(secretFile)) continue;
      const sec = JSON.parse(fs.readFileSync(secretFile, "utf8"));
      const tok = String(sec?.bridgeToken || sec?.token || sec?.studioAccessToken || "").trim();
      if (tok) return tok;
    } catch {}
  }
  return "";
};

const resolveStudioAccessToken = (env = process.env) => {
  const envToken = String(env.STUDIO_ACCESS_TOKEN || env.OFFICE_BRIDGE_TOKEN || "").trim();
  if (envToken) return envToken;

  const fs = require("node:fs");
  for (const secretFile of resolveSecretFileCandidates(env)) {
    try {
      if (!fs.existsSync(secretFile)) continue;
      const sec = JSON.parse(fs.readFileSync(secretFile, "utf8"));
      const tok = String(sec?.studioAccessToken || sec?.token || sec?.bridgeToken || "").trim();
      if (tok) return tok;
    } catch {}
  }
  return "";
};

const resolveOfficeBridgeWsBase = (env = process.env) => {
  const rawWs = String(env.OFFICE_BRIDGE_WS_URL || "").trim();
  const rawHttp = String(env.OFFICE_BRIDGE_HTTP_URL || "").trim();
  const base = rawWs || (rawHttp ? rawHttp.replace(/^http/i, "ws") : "ws://127.0.0.1:3210");
  return base.replace(/\/+(?:api\/events\/ws|ws)?\/?$/i, "");
};

const CERT_DIR = require("node:path").join(__dirname, "..", ".certs");
const CERT_PATH = require("node:path").join(CERT_DIR, "localhost.crt");
const KEY_PATH = require("node:path").join(CERT_DIR, "localhost.key");

const generateHttpsCert = async () => {
  const fs = require("node:fs");

  // Re-use a saved cert so the browser only needs to trust it once.
  if (fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH)) {
    return {
      key: fs.readFileSync(KEY_PATH, "utf8"),
      cert: fs.readFileSync(CERT_PATH, "utf8"),
    };
  }

  const selfsigned = require("selfsigned");
  const attrs = [{ name: "commonName", value: "localhost" }];
  const pems = await selfsigned.generate(attrs, {
    days: 825,
    keySize: 2048,
    algorithm: "sha256",
    extensions: [
      {
        name: "subjectAltName",
        altNames: [
          { type: 2, value: "localhost" },
          { type: 7, ip: "127.0.0.1" },
        ],
      },
    ],
  });

  fs.mkdirSync(CERT_DIR, { recursive: true });
  fs.writeFileSync(CERT_PATH, pems.cert);
  fs.writeFileSync(KEY_PATH, pems.private);

  console.info(`\nCert saved to ${CERT_DIR}`);
  console.info("To make browsers trust it (macOS), run:");
  console.info(`  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "${CERT_PATH}"\n`);

  return { key: pems.private, cert: pems.cert };
};

async function main() {
  const dev = process.argv.includes("--dev");
  const useHttps = process.argv.includes("--https") || process.env.HTTPS === "true";
  const hostnames = Array.from(new Set(resolveHosts(process.env)));
  const hostname = hostnames[0] ?? "127.0.0.1";
  const port = resolvePort();
  const studioAccessToken = resolveStudioAccessToken(process.env);
  for (const host of hostnames) {
    assertPublicHostAllowed({
      host,
      studioAccessToken,
    });
  }

  const app = next({
    dev,
    hostname,
    port,
    ...(dev ? { webpack: true } : null),
  });
  const handle = app.getRequestHandler();

  const accessGate = createAccessGate({
    token: studioAccessToken,
  });

  const proxy = createGatewayProxy({
    loadUpstreamSettings: async () => {
      const settings = loadUpstreamGatewaySettings(process.env);
      return { url: settings.url, token: settings.token, adapterType: settings.adapterType };
    },
    log: (message) => console.info(message),
    logError: (message, error) => console.error(message, error),
    allowWs: (req) => {
      if (resolvePathname(req.url) !== "/api/gateway/ws") return false;
      return true;
    },
    verifyClient: (info) => accessGate.allowUpgrade(info.req),
  });

  await app.prepare();
  const handleUpgrade = app.getUpgradeHandler();
  const { WebSocket, WebSocketServer } = require("ws");
  const companyEventsWss = new WebSocketServer({ noServer: true, maxPayload: 128 * 1024 });

  companyEventsWss.on("connection", (browserWs, req) => {
    const bridgeToken = resolveOfficeBridgeToken(process.env);
    const qsIdx = String(req.url || "").indexOf("?");
    const qs = qsIdx >= 0 ? String(req.url).slice(qsIdx) : "";
    const bridgeBase = resolveOfficeBridgeWsBase(process.env);
    const upstreamWs = new WebSocket(`${bridgeBase}/api/events/ws${qs}`, {
      headers: bridgeToken ? { Authorization: `Bearer ${bridgeToken}` } : {},
    });

    upstreamWs.on("message", (data) => {
      if (browserWs.readyState === WebSocket.OPEN) {
        browserWs.send(data.toString("utf8"));
      }
    });
    upstreamWs.on("close", () => {
      try {
        browserWs.close();
      } catch {}
    });
    upstreamWs.on("error", () => {
      try {
        browserWs.close(1011, "upstream unavailable");
      } catch {}
    });
    browserWs.on("close", () => {
      try {
        upstreamWs.close();
      } catch {}
    });
    browserWs.on("error", () => {
      try {
        upstreamWs.close();
      } catch {}
    });
  });

  const handleServerUpgrade = (req, socket, head) => {
    const pathname = resolvePathname(req.url);
    if (pathname === "/api/gateway/ws") {
      proxy.handleUpgrade(req, socket, head);
      return;
    }
    if (pathname === "/api/company/events/ws") {
      if (!accessGate.allowUpgrade(req)) {
        try {
          socket.end("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\nUnauthorized");
        } catch {
          socket.destroy();
        }
        return;
      }
      companyEventsWss.handleUpgrade(req, socket, head, (ws) => {
        companyEventsWss.emit("connection", ws, req);
      });
      return;
    }
    handleUpgrade(req, socket, head);
  };

  const httpsCert = useHttps ? await generateHttpsCert() : null;

  const createServer = () =>
    useHttps
      ? https.createServer(httpsCert, (req, res) => {
          if (accessGate.handleHttp(req, res)) return;
          handle(req, res);
        })
      : http.createServer((req, res) => {
          if (accessGate.handleHttp(req, res)) return;
          handle(req, res);
        });

  const servers = hostnames.map(() => createServer());

  const attachUpgradeHandlers = (server) => {
    server.on("upgrade", handleServerUpgrade);
    server.on("newListener", (eventName, listener) => {
      if (eventName !== "upgrade") return;
      if (listener === handleServerUpgrade) return;
      process.nextTick(() => {
        server.removeListener("upgrade", listener);
      });
    });
  };

  for (const server of servers) {
    attachUpgradeHandlers(server);
  }

  const listenOnHost = (server, host) =>
    new Promise((resolve, reject) => {
      const onError = (err) => {
        server.off("error", onError);
        reject(err);
      };
      server.once("error", onError);
      server.listen(port, host, () => {
        server.off("error", onError);
        resolve();
      });
    });

  const closeServer = (server) =>
    new Promise((resolve) => {
      if (!server.listening) return resolve();
      server.close(() => resolve());
    });

  try {
    await Promise.all(servers.map((server, index) => listenOnHost(server, hostnames[index])));
  } catch (err) {
    await Promise.all(servers.map((server) => closeServer(server)));
    throw err;
  }

  const hostForBrowser = hostnames.some((value) => value === "127.0.0.1" || value === "::1")
    ? "localhost"
    : hostname === "0.0.0.0" || hostname === "::"
      ? "localhost"
      : hostname;

  const protocol = useHttps ? "https" : "http";
  const browserUrl = `${protocol}://${hostForBrowser}:${port}`;
  console.info(`Open in browser: ${browserUrl}`);
  if (useHttps) {
    console.info("HTTPS mode: self-signed cert in use. You may need to accept a browser security warning once.");
    console.info(`Spotify redirect URI: ${browserUrl}/office`);
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
  });
}

module.exports = {
  resolveOfficeBridgeToken,
  resolveStudioAccessToken,
  resolveOfficeBridgeWsBase,
};
