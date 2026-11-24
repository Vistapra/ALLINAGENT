import { NextResponse } from "next/server";
import fs from "node:fs";
import path from "node:path";

export const runtime = "nodejs";

function resolveSecretFileCandidates(): string[] {
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
}

function resolveBridgeBaseUrl(): string {
  return (process.env.OFFICE_BRIDGE_HTTP_URL || "http://127.0.0.1:3210").trim().replace(/\/$/, "");
}

function loadBridgeToken(): string {
  const envToken = (
    process.env.OFFICE_BRIDGE_TOKEN ||
    process.env.HERMES3D_GATEWAY_TOKEN ||
    process.env.STUDIO_ACCESS_TOKEN ||
    ""
  ).trim();
  if (envToken) return envToken;

  for (const secretPath of resolveSecretFileCandidates()) {
    try {
      if (!fs.existsSync(secretPath)) continue;
      const raw = JSON.parse(fs.readFileSync(secretPath, "utf8")) as {
        token?: string;
        bridgeToken?: string;
        studioAccessToken?: string;
      };
      const token = String(raw.bridgeToken || raw.token || raw.studioAccessToken || "").trim();
      if (token) return token;
    } catch {}
  }
  throw new Error("Office Bridge token unavailable.");
}

function isTrustedSameOrigin(request: Request): boolean {
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
}

async function forwardToOfficeBridge(
  request: Request,
  context: { params: Promise<{ slug: string[] }> }
): Promise<Response> {
  const method = request.method.toUpperCase();
  const isMutation = method !== "GET" && method !== "HEAD";

  if (isMutation && !isTrustedSameOrigin(request)) {
    return NextResponse.json(
      { ok: false, error: "CSRF validation failed: untrusted Origin." },
      { status: 403 }
    );
  }

  try {
    const { slug } = await context.params;
    const cleanSegments = (slug || []).map((s) => encodeURIComponent(s));
    const urlObj = new URL(request.url);
    const targetUrl = `${resolveBridgeBaseUrl()}/api/office-bridge/${cleanSegments.join("/")}${urlObj.search}`;

    const bridgeToken = loadBridgeToken();
    const headers: Record<string, string> = {
      Accept: "application/json",
      Authorization: `Bearer ${bridgeToken}`,
    };

    const roleHeader = request.headers.get("x-office-actor-role");
    if (roleHeader) headers["X-Office-Actor-Role"] = roleHeader;
    const callerHeader = request.headers.get("x-office-caller-id");
    if (callerHeader) headers["X-Office-Caller-Id"] = callerHeader;

    let bodyText: string | undefined;
    if (isMutation) {
      headers["Content-Type"] = "application/json";
      bodyText = await request.text();
    }

    const upstream = await fetch(targetUrl, {
      method,
      headers,
      body: isMutation ? bodyText || "{}" : undefined,
      cache: "no-store",
      signal: request.signal,
    });

    const responseText = await upstream.text();
    return new NextResponse(responseText, {
      status: upstream.status,
      headers: {
        "Content-Type": upstream.headers.get("content-type") || "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Office Bridge proxy unavailable.";
    return NextResponse.json(
      { ok: false, error: msg.includes("ECONNREFUSED") ? "Office Bridge offline." : "Proxy error." },
      { status: 502, headers: { "Cache-Control": "no-store" } }
    );
  }
}

export const GET = forwardToOfficeBridge;
export const POST = forwardToOfficeBridge;
export const PATCH = forwardToOfficeBridge;
export const PUT = forwardToOfficeBridge;
export const DELETE = forwardToOfficeBridge;
