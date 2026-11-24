import { NextResponse } from "next/server";

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { resolveUserPath } from "@/lib/hermes/paths";

export const runtime = "nodejs";

type PathAutocompleteEntry = {
  name: string;
  fullPath: string;
  displayPath: string;
  isDirectory: boolean;
};

type PathAutocompleteResult = {
  query: string;
  directory: string;
  entries: PathAutocompleteEntry[];
};

type PathAutocompleteOptions = {
  query: string;
  maxResults?: number;
  homedir?: () => string;
  allowMissingDirectory?: boolean;
};

const normalizeQuery = (query: string): string => {
  const trimmed = query.trim();
  if (!trimmed) {
    throw new Error("Query is required.");
  }
  if (trimmed === "~") {
    return "~/";
  }
  if (trimmed.startsWith("~")) {
    return trimmed;
  }
  const withoutLeading = trimmed.replace(/^[\\/]+/, "");
  return `~/${withoutLeading}`;
};

const resolveRealPath = (value: string): string => {
  const absolutePath = path.resolve(value);
  try {
    return fs.realpathSync(absolutePath);
  } catch {
    const missingSegments: string[] = [];
    let currentPath = absolutePath;
    while (true) {
      if (fs.existsSync(currentPath)) {
        try {
          return path.join(fs.realpathSync(currentPath), ...missingSegments.reverse());
        } catch {
          return path.join(currentPath, ...missingSegments.reverse());
        }
      }
      const parentPath = path.dirname(currentPath);
      if (parentPath === currentPath) {
        return absolutePath;
      }
      missingSegments.push(path.basename(currentPath));
      currentPath = parentPath;
    }
  }
};

const isWithinHome = (target: string, home: string): boolean => {
  const resolvedTarget = resolveRealPath(target);
  const resolvedHome = resolveRealPath(home);
  const relative = path.relative(resolvedHome, resolvedTarget);
  if (!relative) return true;
  return !relative.startsWith("..") && !path.isAbsolute(relative);
};

const listPathAutocompleteEntries = ({
  query,
  maxResults = 10,
  homedir = os.homedir,
  allowMissingDirectory = false,
}: PathAutocompleteOptions): PathAutocompleteResult => {
  const normalized = normalizeQuery(query);
  const resolvedHome = path.resolve(homedir());
  const resolvedQuery = resolveUserPath(normalized, homedir);
  if (!isWithinHome(resolvedQuery, resolvedHome)) {
    throw new Error("Path must stay within the home directory.");
  }

  const endsWithSlash = normalized.endsWith("/") || normalized.endsWith(path.sep);
  const directoryPath = endsWithSlash ? resolvedQuery : path.dirname(resolvedQuery);
  const prefix = endsWithSlash ? "" : path.basename(resolvedQuery);

  if (!isWithinHome(directoryPath, resolvedHome)) {
    throw new Error("Path must stay within the home directory.");
  }
  if (!fs.existsSync(directoryPath)) {
    if (allowMissingDirectory) {
      return { query: normalized, directory: directoryPath, entries: [] };
    }
    throw new Error(`Directory does not exist: ${directoryPath}`);
  }
  let stat: fs.Stats;
  try {
    stat = fs.statSync(directoryPath);
  } catch {
    if (allowMissingDirectory) {
      return { query: normalized, directory: directoryPath, entries: [] };
    }
    throw new Error(`Directory does not exist: ${directoryPath}`);
  }
  if (!stat.isDirectory()) {
    throw new Error(`Path is not a directory: ${directoryPath}`);
  }

  const limit = Number.isFinite(maxResults) && maxResults > 0 ? Math.floor(maxResults) : 10;

  let rawEntries: fs.Dirent[] = [];
  try {
    rawEntries = fs.readdirSync(directoryPath, { withFileTypes: true });
  } catch {
    return { query: normalized, directory: directoryPath, entries: [] };
  }

  const entries = rawEntries
    .filter((entry) => !entry.name.startsWith("."))
    .filter((entry) => entry.name.startsWith(prefix))
    .map((entry) => {
      const fullPath = path.join(directoryPath, entry.name);
      const relative = path.relative(resolvedHome, fullPath);
      const normalizedRelative = relative.split(path.sep).join("/");
      const displayBase = `~/${normalizedRelative}`;
      return {
        name: entry.name,
        fullPath,
        displayPath: entry.isDirectory() ? `${displayBase}/` : displayBase,
        isDirectory: entry.isDirectory(),
      } satisfies PathAutocompleteEntry;
    })
    .sort((a, b) => {
      if (a.isDirectory !== b.isDirectory) {
        return a.isDirectory ? -1 : 1;
      }
      return a.name.localeCompare(b.name);
    })
    .slice(0, limit);

  return { query: normalized, directory: directoryPath, entries };
};

const resolvePlatformRoot = (): string => {
  const explicit = (
    process.env.ALLINAGENT_ROOT ||
    process.env.ALLAGENT_ROOT ||
    process.env.PLATFORM_ROOT ||
    ""
  ).trim();
  if (explicit) return path.resolve(explicit);
  const twoUp = path.resolve(process.cwd(), "..", "..");
  const oneUp = path.resolve(process.cwd(), "..");
  if (
    fs.existsSync(path.join(twoUp, "config")) ||
    fs.existsSync(path.join(twoUp, "workspaces")) ||
    path.basename(oneUp).toLowerCase() === "apps"
  ) {
    return twoUp;
  }
  return oneUp;
};

export function resolveAuthorizedWorkspaceRoots(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform
): string[] {
  const isWin = platform === "win32";
  const rawAuthorized = (env.AUTHORIZED_WORKSPACES || "").trim();
  const defaultWorkspaceRoot = (
    env.ALLINAGENT_WORKSPACE_ROOT || "/var/lib/allinagent/workspaces"
  ).trim();

  const rawItems = rawAuthorized
    ? rawAuthorized
        .split(isWin ? new RegExp(`[${path.win32.delimiter}]+`) : new RegExp(`[${path.delimiter}:]+`))
        .map((entry) => entry.trim())
        .filter(Boolean)
    : [defaultWorkspaceRoot || "/var/lib/allinagent/workspaces"];

  const resolved = rawItems
    .map((entry) => (isWin ? path.win32.resolve(entry) : path.posix.resolve(entry)))
    .filter(Boolean);

  if (resolved.length > 0) {
    return Array.from(new Set(resolved));
  }
  return [
    isWin
      ? path.win32.resolve("/var/lib/allinagent/workspaces")
      : "/var/lib/allinagent/workspaces",
  ];
}

const LINUX_SENSITIVE_POSIX_PREFIXES = [
  "/etc",
  "/proc",
  "/sys",
  "/dev",
  "/root",
  "/var/run",
  "/run",
  "/var/lib/allinagent/secrets",
  "/var/lib/allinagent/studio-state",
] as const;

const HOME_SENSITIVE_SEGMENTS = [
  ".hermes",
  ".ssh",
  ".aws",
  ".git-credentials",
  ".gnupg",
  ".docker",
] as const;

const normalizeForPlatformCompare = (value: string, isWin = process.platform === "win32"): string =>
  isWin ? value.toLowerCase() : value;

export function isForbiddenSuggestionPath(
  candidate: string,
  options?: { homedir?: () => string; platform?: NodeJS.Platform }
): boolean {
  const rawTrimmed = candidate.trim();
  if (!rawTrimmed) return false;
  const platform = options?.platform ?? process.platform;
  const isWin = platform === "win32";
  const home = (options?.homedir ?? os.homedir)();

  // Block raw tilde/POSIX sensitive paths regardless of host OS
  const slashNorm = rawTrimmed.replace(/\\/g, "/");
  for (const seg of HOME_SENSITIVE_SEGMENTS) {
    if (slashNorm === `~/${seg}` || slashNorm.startsWith(`~/${seg}/`)) {
      return true;
    }
  }
  for (const posixPrefix of LINUX_SENSITIVE_POSIX_PREFIXES) {
    if (slashNorm === posixPrefix || slashNorm.startsWith(`${posixPrefix}/`)) {
      return true;
    }
  }

  const platformRoot = resolvePlatformRoot();
  const extraSecretsDir = (process.env.ALLINAGENT_SECRETS_DIR || "").trim();
  const extraStudioStateDir = (process.env.HERMES_STATE_DIR || "").trim();
  const dynamicForbidden = [
    ...HOME_SENSITIVE_SEGMENTS.map((seg) => path.join(home, seg)),
    path.join(platformRoot, "config", "secrets"),
    path.join(platformRoot, "data", "secrets"),
    path.join(platformRoot, "data", "studio-state"),
    path.join(platformRoot, "data", "vulnclaw"),
    "/var/lib/allinagent/secrets",
    "/var/lib/allinagent/studio-state",
    ...(extraSecretsDir ? [extraSecretsDir] : []),
    ...(extraStudioStateDir ? [extraStudioStateDir] : []),
    ...(isWin
      ? [
          process.env.SystemRoot,
          process.env.ProgramFiles,
          process.env["ProgramFiles(x86)"],
          process.env.ProgramData,
          process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, "hermes") : undefined,
        ].filter((v): v is string => Boolean(v && v.trim()))
      : LINUX_SENSITIVE_POSIX_PREFIXES),
  ];

  const resolvedCandidate = normalizeForPlatformCompare(
    isWin ? path.win32.resolve(rawTrimmed) : path.posix.resolve(slashNorm),
    isWin
  );
  const sep = isWin ? "\\" : "/";

  return dynamicForbidden.some((rawPrefix) => {
    const prefix = normalizeForPlatformCompare(
      isWin ? path.win32.resolve(rawPrefix) : path.posix.resolve(rawPrefix.replace(/\\/g, "/")),
      isWin
    );
    return resolvedCandidate === prefix || resolvedCandidate.startsWith(`${prefix}${sep}`);
  });
}

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const rawQuery = searchParams.get("q");
    let query = rawQuery && rawQuery.trim() ? rawQuery.trim() : "~/";
    if (isForbiddenSuggestionPath(query)) {
      return NextResponse.json(
        { error: "Access to restricted system/secrets directory is forbidden." },
        { status: 400 }
      );
    }
    let governedRoot: (() => string) | undefined;
    const isGoverned = process.env.UNIFIED_COMPANY_GOVERNANCE === "1";
    if (isGoverned) {
      if (query.includes("..")) {
        return NextResponse.json(
          { error: "Path traversal (..) is not allowed." },
          { status: 400 }
        );
      }
      const allowedRoots = resolveAuthorizedWorkspaceRoots();
      const driveMatch =
        process.platform === "win32" ? query.match(/^([a-zA-Z]):(?:[\\/](.*))?$/) : null;

      if (driveMatch) {
        const driveRoot = `${driveMatch[1].toUpperCase()}:\\`;
        const subRaw = (driveMatch[2] || "").replace(/\//g, "\\");
        const candidateAbs = path.resolve(driveRoot, subRaw);
        if (isForbiddenSuggestionPath(candidateAbs)) {
          return NextResponse.json(
            { error: "Access to restricted system/secrets directory is forbidden." },
            { status: 400 }
          );
        }
        const matchedRoot = allowedRoots.find((root) => isWithinHome(candidateAbs, root));
        if (!matchedRoot) {
          return NextResponse.json(
            { error: "Path must stay within authorized workspaces." },
            { status: 400 }
          );
        }
        const relPosix = path
          .relative(resolveRealPath(matchedRoot), resolveRealPath(candidateAbs))
          .split(path.sep)
          .join("/");
        const trailingSlash = /[\\/]$/.test(query);
        governedRoot = () => matchedRoot;
        query = relPosix
          ? `~/${relPosix}${trailingSlash && !relPosix.endsWith("/") ? "/" : ""}`
          : "~/";
      } else if (process.platform !== "win32" && query.startsWith("/")) {
        const candidateAbs = path.posix.resolve(query);
        if (isForbiddenSuggestionPath(candidateAbs)) {
          return NextResponse.json(
            { error: "Access to restricted system/secrets directory is forbidden." },
            { status: 400 }
          );
        }
        const matchedRoot = allowedRoots.find((root) => isWithinHome(candidateAbs, root));
        if (!matchedRoot) {
          return NextResponse.json(
            { error: "Path must stay within authorized workspaces." },
            { status: 400 }
          );
        }
        const relPosix = path
          .relative(resolveRealPath(matchedRoot), resolveRealPath(candidateAbs))
          .split(path.sep)
          .join("/");
        const trailingSlash = query.endsWith("/");
        governedRoot = () => matchedRoot;
        query = relPosix
          ? `~/${relPosix}${trailingSlash && !relPosix.endsWith("/") ? "/" : ""}`
          : "~/";
      } else {
        const primaryWorkspaceRoot = allowedRoots[0];
        if (isForbiddenSuggestionPath(primaryWorkspaceRoot)) {
          return NextResponse.json(
            { error: "Access to restricted system/secrets directory is forbidden." },
            { status: 400 }
          );
        }
        governedRoot = () => primaryWorkspaceRoot;
      }
    }
    const result = listPathAutocompleteEntries({
      query,
      maxResults: 15,
      ...(governedRoot ? { homedir: governedRoot, allowMissingDirectory: true } : null),
    });
    const safeEntries = result.entries.filter(
      (entry) => !isForbiddenSuggestionPath(entry.fullPath)
    );
    return NextResponse.json({ ...result, entries: safeEntries });
  } catch (err) {
    const message =
      err instanceof Error ? err.message : "Failed to list path suggestions.";
    console.error(message);
    const status = message.includes("does not exist") ? 404 : 400;
    return NextResponse.json({ error: message }, { status });
  }
}
