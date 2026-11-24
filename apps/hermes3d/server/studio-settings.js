const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const STATE_DIRNAME = ".hermes";

const resolveUserPath = (input) => {
  const trimmed = String(input ?? "").trim();
  if (!trimmed) return trimmed;
  if (trimmed.startsWith("~")) {
    const expanded = trimmed.replace(/^~(?=$|[\\/])/, os.homedir());
    return path.resolve(expanded);
  }
  return path.resolve(trimmed);
};

const resolveDefaultHomeDir = () => {
  const home = os.homedir();
  if (home) {
    try {
      if (fs.existsSync(home)) return home;
    } catch {}
  }
  return os.tmpdir();
};

const resolveStateDir = (env = process.env) => {
  const override = env.HERMES_STATE_DIR?.trim();
  if (override) return resolveUserPath(override);
  return path.join(resolveDefaultHomeDir(), STATE_DIRNAME);
};

const resolveStudioSettingsPath = (env = process.env) => {
  return path.join(resolveStateDir(env), "hermes3d", "settings.json");
};

const readJsonFile = (filePath) => {
  if (!fs.existsSync(filePath)) return null;
  const raw = fs.readFileSync(filePath, "utf8");
  return JSON.parse(raw);
};

const DEFAULT_GATEWAY_URL = "ws://localhost:18789";
const HERMES_CONFIG_FILENAME = "hermes.json";

const isRecord = (value) => Boolean(value && typeof value === "object");

const readHermesGatewayDefaults = (env = process.env) => {
  try {
    const stateDir = resolveStateDir(env);
    const configPath = path.join(stateDir, HERMES_CONFIG_FILENAME);
    const parsed = readJsonFile(configPath);
    if (!isRecord(parsed)) return null;
    const gateway = isRecord(parsed.gateway) ? parsed.gateway : null;
    if (!gateway) return null;
    const auth = isRecord(gateway.auth) ? gateway.auth : null;
    const token = typeof auth?.token === "string" ? auth.token.trim() : "";
    const port =
      typeof gateway.port === "number" && Number.isFinite(gateway.port) ? gateway.port : null;
    if (!token) return null;
    const url = port ? `ws://localhost:${port}` : "";
    if (!url) return null;
    return { url, token, adapterType: "hermes" };
  } catch {
    return null;
  }
};

const normalizeBridgeGatewayWsUrl = (raw) => {
  const trimmed = typeof raw === "string" ? raw.trim() : "";
  if (!trimmed) return "";
  const wsCandidate = trimmed.replace(/^http/i, "ws");
  try {
    const parsed = new URL(wsCandidate);
    if (!parsed.pathname || parsed.pathname === "/") {
      parsed.pathname = "/ws";
    }
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return wsCandidate;
  }
};

const resolveEnvBridgeGatewayUrl = (env = process.env) => {
  const gatewayUrl = typeof env.HERMES3D_GATEWAY_URL === "string" ? env.HERMES3D_GATEWAY_URL.trim() : "";
  if (gatewayUrl) return gatewayUrl;
  const bridgeWs = typeof env.OFFICE_BRIDGE_WS_URL === "string" ? env.OFFICE_BRIDGE_WS_URL.trim() : "";
  if (bridgeWs) return normalizeBridgeGatewayWsUrl(bridgeWs);
  const bridgeHttp =
    typeof env.OFFICE_BRIDGE_HTTP_URL === "string" ? env.OFFICE_BRIDGE_HTTP_URL.trim() : "";
  if (bridgeHttp) return normalizeBridgeGatewayWsUrl(bridgeHttp);
  return "";
};

const isStaleLoopbackBridgeUrl = (url) => {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    return (host === "127.0.0.1" || host === "localhost" || host === "::1") && parsed.port === "3210";
  } catch {
    return /^wss?:\/\/(?:127\.0\.0\.1|localhost):3210(?:\/|$)/i.test(url);
  }
};

const resolveSecretFileBridgeToken = (env = process.env) => {
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
  const secretCandidates = [
    path.resolve(secretsDir || "/var/lib/allinagent/secrets", "office-bridge-auth.json"),
  ];
  for (const rootDir of new Set(rootCandidates)) {
    secretCandidates.push(path.resolve(rootDir, "config", "secrets", "office-bridge-auth.json"));
    secretCandidates.push(path.resolve(rootDir, "data", "secrets", "office-bridge-auth.json"));
  }
  for (const secretPath of new Set(secretCandidates)) {
    try {
      if (!fs.existsSync(secretPath)) continue;
      const parsed = readJsonFile(secretPath);
      const rawTok = parsed?.bridgeToken || parsed?.token || parsed?.studioAccessToken;
      const tok = typeof rawTok === "string" ? rawTok.trim() : "";
      if (tok) return tok;
    } catch {}
  }
  return "";
};

const loadUpstreamGatewaySettings = (env = process.env) => {
  const settingsPath = resolveStudioSettingsPath(env);
  const parsed = readJsonFile(settingsPath);
  const gateway = parsed && typeof parsed === "object" ? parsed.gateway : null;
  const savedUrl = typeof gateway?.url === "string" ? gateway.url.trim() : "";
  const savedToken = typeof gateway?.token === "string" ? gateway.token.trim() : "";
  const envBridgeUrl = resolveEnvBridgeGatewayUrl(env);
  const envToken = String(
    env.OFFICE_BRIDGE_TOKEN || env.HERMES3D_GATEWAY_TOKEN || env.STUDIO_ACCESS_TOKEN || ""
  ).trim();

  const url =
    envBridgeUrl && (!savedUrl || isStaleLoopbackBridgeUrl(savedUrl))
      ? envBridgeUrl
      : savedUrl;

  const adapterType =
    typeof gateway?.adapterType === "string" && gateway.adapterType.trim()
      ? gateway.adapterType.trim()
      : typeof env.HERMES3D_GATEWAY_ADAPTER_TYPE === "string" &&
          env.HERMES3D_GATEWAY_ADAPTER_TYPE.trim()
        ? env.HERMES3D_GATEWAY_ADAPTER_TYPE.trim()
        : "hermes";

  let token =
    savedToken ||
    envToken ||
    (envBridgeUrl || isStaleLoopbackBridgeUrl(url) ? resolveSecretFileBridgeToken(env) : "");

  if (!token && adapterType === "hermes") {
    const defaults = readHermesGatewayDefaults(env);
    if (defaults) {
      return {
        url: url || defaults.url,
        token: defaults.token,
        adapterType,
        settingsPath,
      };
    }
  }
  if (!token) {
    token = resolveSecretFileBridgeToken(env);
  }
  return {
    url: url || envBridgeUrl || DEFAULT_GATEWAY_URL,
    token,
    adapterType,
    settingsPath,
  };
};

module.exports = {
  resolveStateDir,
  resolveStudioSettingsPath,
  loadUpstreamGatewaySettings,
  isStaleLoopbackBridgeUrl,
  resolveEnvBridgeGatewayUrl,
};
