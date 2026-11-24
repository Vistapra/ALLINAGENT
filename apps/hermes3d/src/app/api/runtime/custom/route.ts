import { NextResponse } from "next/server";
import fs from "node:fs";
import path from "node:path";

export const runtime = "nodejs";

const resolveSecretFileCandidates = (): string[] => {
  const secretsDir = (
    process.env.ALLINAGENT_SECRETS_DIR || "/var/lib/allinagent/secrets"
  ).trim();
  const explicit = (
    process.env.ALLINAGENT_ROOT ||
    process.env.ALLAGENT_ROOT ||
    process.env.PLATFORM_ROOT ||
    ""
  ).trim();
  const roots = [
    ...(explicit ? [path.resolve(explicit)] : []),
    path.resolve(process.cwd(), "..", ".."),
    path.resolve(process.cwd(), ".."),
    path.resolve(process.cwd()),
  ];
  const candidates = [
    path.resolve(secretsDir || "/var/lib/allinagent/secrets", "office-bridge-auth.json"),
  ];
  for (const rootDir of new Set(roots)) {
    candidates.push(path.join(rootDir, "config", "secrets", "office-bridge-auth.json"));
    candidates.push(path.join(rootDir, "data", "secrets", "office-bridge-auth.json"));
  }
  return Array.from(new Set(candidates));
};

const loadServerBridgeAuthHeader = (): Record<string, string> => {
  const envToken = (
    process.env.OFFICE_BRIDGE_TOKEN ||
    process.env.HERMES3D_GATEWAY_TOKEN ||
    process.env.STUDIO_ACCESS_TOKEN ||
    ""
  ).trim();
  if (envToken) {
    return { Authorization: `Bearer ${envToken}` };
  }
  for (const secretPath of resolveSecretFileCandidates()) {
    try {
      if (!fs.existsSync(secretPath)) continue;
      const parsed = JSON.parse(fs.readFileSync(secretPath, "utf8")) as {
        token?: string;
        bridgeToken?: string;
        studioAccessToken?: string;
      };
      const tok = String(
        parsed.bridgeToken || parsed.token || parsed.studioAccessToken || ""
      ).trim();
      if (tok) return { Authorization: `Bearer ${tok}` };
    } catch {}
  }
  return {};
};

const isTrustedSameOrigin = (request: Request): boolean => {
  const origin = request.headers.get("origin");
  if (!origin) {
    const secFetch = request.headers.get("sec-fetch-site");
    if (secFetch && secFetch !== "same-origin" && secFetch !== "none") {
      return false;
    }
    return true;
  }
  const normalized = origin.trim().toLowerCase().replace(/\/$/, "");
  const hostHeader = (request.headers.get("host") || "").trim().toLowerCase();
  let urlHost = "";
  try {
    urlHost = new URL(request.url).host.toLowerCase();
  } catch {}
  const effectiveHost = hostHeader || urlHost;
  return (
    (effectiveHost !== "" &&
      (normalized === `http://${effectiveHost}` || normalized === `https://${effectiveHost}`)) ||
    normalized === "http://127.0.0.1:3200" ||
    normalized === "http://localhost:3200" ||
    normalized === "http://127.0.0.1:8200" ||
    normalized === "http://localhost:8200"
  );
};

type CustomRuntimeRequestBody = {
  runtimeUrl?: string;
  pathname?: string;
  method?: string;
  body?: unknown;
};

const isRuntimeUrlAllowed = (runtimeUrl: string): boolean => {
  try {
    const parsed = new URL(runtimeUrl);
    const hostLower = parsed.hostname.toLowerCase();
    const effectivePort = parsed.port || (parsed.protocol === "https:" ? "443" : "80");
    const hostPortLower = parsed.port ? `${hostLower}:${parsed.port}` : hostLower;

    const rawAllowlist = (
      process.env.CUSTOM_RUNTIME_ALLOWLIST ||
      process.env.UPSTREAM_ALLOWLIST ||
      ""
    ).trim();
    const allowed = rawAllowlist
      .split(",")
      .map((entry) => entry.trim().toLowerCase())
      .filter(Boolean);

    const configuredBridgeUrl = (process.env.OFFICE_BRIDGE_HTTP_URL || "").trim();
    const defaultBridgeUrl = configuredBridgeUrl || "http://127.0.0.1:3210";
    let bridgeOrigin = "http://127.0.0.1:3210";
    let bridgePort = "3210";
    try {
      const parsedBridge = new URL(defaultBridgeUrl);
      bridgeOrigin = parsedBridge.origin;
      bridgePort = parsedBridge.port || (parsedBridge.protocol === "https:" ? "443" : "80");
    } catch {}

    if (process.env.UNIFIED_COMPANY_GOVERNANCE === "1") {
      // Permit exact configured Office Bridge origin, loopback/bridge container on bridgePort,
      // or explicit allowlist entries on safe ports while blocking SSRF to Paperclip (3100) / DB (5432/54329).
      if (parsed.origin === bridgeOrigin) return true;
      if (
        (hostLower === "127.0.0.1" ||
          hostLower === "localhost" ||
          hostLower === "office-bridge" ||
          hostLower === "allinagent-office-bridge") &&
        effectivePort === bridgePort
      ) {
        return true;
      }
      if (allowed.includes(`${hostLower}:${effectivePort}`)) {
        return !["3100", "5432", "54329"].includes(effectivePort);
      }
      if (allowed.includes(hostLower) && effectivePort === bridgePort) {
        return true;
      }
      return false;
    }

    if (configuredBridgeUrl && parsed.origin === bridgeOrigin) {
      return true;
    }
    if (!rawAllowlist) {
      return process.env.NODE_ENV !== "production";
    }
    return allowed.includes(hostLower) || allowed.includes(hostPortLower);
  } catch {
    return false;
  }
};

const normalizeRuntimeUrl = (value: string): string => {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error("runtimeUrl is required.");
  }
  const parsed = new URL(trimmed);
  if (parsed.protocol === "ws:") {
    parsed.protocol = "http:";
  } else if (parsed.protocol === "wss:") {
    parsed.protocol = "https:";
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("runtimeUrl must use http, https, ws, or wss.");
  }
  parsed.username = "";
  parsed.password = "";
  const normalized = parsed.toString().replace(/\/$/, "");
  if (!isRuntimeUrlAllowed(normalized)) {
    throw new Error("runtimeUrl is not in the allowed hosts list.");
  }
  return normalized;
};

const normalizePathname = (value: unknown): string => {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error("pathname is required.");
  }
  const trimmed = value.trim();
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
};

const normalizeMethod = (value: unknown): "GET" | "POST" => {
  if (typeof value !== "string") return "GET";
  const upper = value.trim().toUpperCase();
  if (upper === "POST") return "POST";
  return "GET";
};

export async function POST(request: Request) {
  if (!isTrustedSameOrigin(request)) {
    return NextResponse.json(
      { ok: false, error: "CSRF validation failed: untrusted Origin." },
      { status: 403 }
    );
  }

  let payload;
  try {
    payload = (await request.json()) as CustomRuntimeRequestBody;
  } catch (error) {
    console.error("[runtime/custom] Invalid JSON request body.", error);
    return NextResponse.json(
      { error: "Invalid JSON request body." },
      { status: 400 }
    );
  }

  try {
    const runtimeUrl = normalizeRuntimeUrl(payload.runtimeUrl ?? "");
    const pathname = normalizePathname(payload.pathname);
    const method = normalizeMethod(payload.method);
    // Propagate the browser abort signal so that cancelling the client-side fetch
    // (e.g. hitting Stop) also cancels the upstream runtime request.
    const response = await fetch(`${runtimeUrl}${pathname}`, {
      method,
      headers: {
        Accept: "application/json",
        ...loadServerBridgeAuthHeader(),
        ...(method === "POST" ? { "Content-Type": "application/json" } : null),
      },
      body: method === "POST" ? JSON.stringify(payload.body ?? {}) : undefined,
      cache: "no-store",
      signal: request.signal,
    });
    const text = await response.text();
    return new NextResponse(text, {
      status: response.status,
      headers: {
        "Content-Type": response.headers.get("content-type") ?? "application/json",
        "Cache-Control": "no-store",
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Custom runtime proxy failed.";
    const status =
      message === "runtimeUrl is required." ||
      message === "pathname is required." ||
      message === "runtimeUrl must use http, https, ws, or wss." ||
      message === "runtimeUrl is not in the allowed hosts list."
        ? 400
        : 502;
    console.error("[runtime/custom] Proxy request failed.", error);
    return NextResponse.json(
      {
        error:
          status === 400
            ? message
            : "Custom runtime proxy failed.",
      },
      { status }
    );
  }
}
