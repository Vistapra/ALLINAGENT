// @vitest-environment node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { isForbiddenSuggestionPath } from "@/app/api/path-suggestions/route";
import { POST as postCustomRuntime } from "@/app/api/runtime/custom/route";
import { GET as getCompanyProxy } from "@/app/api/company/[...slug]/route";
import {
  enrichOfficeAgentWithEnterprise,
  matchEnterpriseAgent,
  resolveTelegramHealthIndicator,
} from "@/features/enterprise-company/enrichOfficeAgent";
import type { EnterpriseAgent } from "@/features/enterprise-company/types";

describe("Phase 11 — Hermes3D Portability, Security & Corporate Avatar Enrichment", () => {
  const originalEnv = { ...process.env };
  let tempDir: string | null = null;

  afterEach(() => {
    process.env = { ...originalEnv };
    vi.restoreAllMocks();
    if (tempDir) {
      fs.rmSync(tempDir, { recursive: true, force: true });
      tempDir = null;
    }
  });

  it("resolves bridgeToken and OFFICE_BRIDGE_WS_URL portably in server/index.js", async () => {
    const serverIndex = await import("../../server/index.js");
    expect(
      serverIndex.resolveOfficeBridgeToken({
        NODE_ENV: "test",
        OFFICE_BRIDGE_TOKEN: "env-bridge-tok",
      })
    ).toBe("env-bridge-tok");

    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "allinagent-root-"));
    const secDir = path.join(tempDir, "config", "secrets");
    fs.mkdirSync(secDir, { recursive: true });
    fs.writeFileSync(
      path.join(secDir, "office-bridge-auth.json"),
      JSON.stringify({ bridgeToken: "file-bridge-tok" }),
      "utf8"
    );
    expect(
      serverIndex.resolveOfficeBridgeToken({
        NODE_ENV: "test",
        ALLINAGENT_ROOT: tempDir,
      })
    ).toBe("file-bridge-tok");

    expect(
      serverIndex.resolveOfficeBridgeWsBase({
        NODE_ENV: "test",
        OFFICE_BRIDGE_HTTP_URL: "http://office-bridge:3210",
      })
    ).toBe("ws://office-bridge:3210");

    expect(
      serverIndex.resolveOfficeBridgeWsBase({
        NODE_ENV: "test",
        OFFICE_BRIDGE_WS_URL: "ws://allinagent-office-bridge:3210/ws",
      })
    ).toBe("ws://allinagent-office-bridge:3210");
  });

  it("allows internal bridge hosts in production gateway-proxy and overrides stale 127.0.0.1:3210 in studio-settings", async () => {
    const { isUpstreamAllowed } = await import("../../server/gateway-proxy");
    expect(
      isUpstreamAllowed("ws://office-bridge:3210/ws", {
        NODE_ENV: "production",
      })
    ).toBe(true);
    expect(
      isUpstreamAllowed("ws://custom-bridge.internal:3210/ws", {
        NODE_ENV: "production",
        OFFICE_BRIDGE_WS_URL: "ws://custom-bridge.internal:3210/ws",
      })
    ).toBe(true);
    expect(
      isUpstreamAllowed("ws://untrusted.external.example:9999/ws", {
        NODE_ENV: "production",
      })
    ).toBe(false);

    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "studio-stale-override-"));
    fs.mkdirSync(path.join(tempDir, "hermes3d"), { recursive: true });
    fs.writeFileSync(
      path.join(tempDir, "hermes3d", "settings.json"),
      JSON.stringify({ gateway: { url: "ws://127.0.0.1:3210/ws", token: "" } }),
      "utf8"
    );
    const { loadUpstreamGatewaySettings } = await import("../../server/studio-settings");
    const resolved = loadUpstreamGatewaySettings({
      NODE_ENV: "production",
      HERMES_STATE_DIR: tempDir,
      OFFICE_BRIDGE_WS_URL: "ws://office-bridge:3210/ws",
      OFFICE_BRIDGE_TOKEN: "docker-tok",
    });
    expect(resolved.url).toBe("ws://office-bridge:3210/ws");
    expect(resolved.token).toBe("docker-tok");
  });

  it("permits OFFICE_BRIDGE_HTTP_URL and office-bridge:3210 under UNIFIED_COMPANY_GOVERNANCE=1 while blocking port 3100/5432", async () => {
    process.env.UNIFIED_COMPANY_GOVERNANCE = "1";
    process.env.OFFICE_BRIDGE_HTTP_URL = "http://office-bridge:3210";
    process.env.OFFICE_BRIDGE_TOKEN = "gov-tok";

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(
      async () =>
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
    );

    const okBridge = await postCustomRuntime(
      new Request("http://localhost:3200/api/runtime/custom", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          runtimeUrl: "http://office-bridge:3210",
          pathname: "/state",
          method: "GET",
        }),
      })
    );
    expect(okBridge.status).toBe(200);
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://office-bridge:3210/state",
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: "Bearer gov-tok" }),
      })
    );

    const blockedPaperclip = await postCustomRuntime(
      new Request("http://localhost:3200/api/runtime/custom", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          runtimeUrl: "http://office-bridge:3100",
          pathname: "/api/companies",
          method: "GET",
        }),
      })
    );
    expect(blockedPaperclip.status).toBe(400);

    const companyRes = await getCompanyProxy(
      new Request("http://localhost:3200/api/company/health"),
      { params: Promise.resolve({ slug: ["health"] }) }
    );
    expect(companyRes.status).toBe(200);
  });

  it("blocks Linux sensitive paths and preserves POSIX case sensitivity in path-suggestions", () => {
    const fakeHome = () => "/home/operator";
    for (const forbidden of [
      "/etc",
      "/etc/passwd",
      "/proc/self/environ",
      "/sys/kernel",
      "/dev/sda",
      "/root/.bashrc",
      "/var/run/docker.sock",
      "~/.ssh",
      "~/.ssh/id_ed25519",
      "~/.aws/credentials",
      "~/.git-credentials",
      "/home/operator/.ssh/authorized_keys",
      "/home/operator/.aws/config",
    ]) {
      expect(
        isForbiddenSuggestionPath(forbidden, { homedir: fakeHome, platform: "linux" }),
        `Expected ${forbidden} to be blocked`
      ).toBe(true);
    }

    // POSIX case sensitivity: /ETC or /Workspaces/Project is not /etc
    expect(
      isForbiddenSuggestionPath("/workspaces/ETC-demo", { homedir: fakeHome, platform: "linux" })
    ).toBe(false);
  });

  it("enriches 3D/2D OfficeAgent with color, badge_emoji, desk_coords, and visual_profile_id and resolves Telegram health indicator", () => {
    const sampleEnterpriseAgent = {
      paperclip_agent_id: "uuid-ceo-001",
      company_id: "comp-1",
      display_name: "CEO Agent",
      department_id: "executive",
      department: "Executive Office",
      department_short: "EXEC",
      role: "ceo",
      role_slug: "ceo_agent",
      title: "Chief Executive Officer",
      manager_id: null,
      subordinate_ids: [],
      runtime_type: "hermes_local",
      runtime_profile_reference: "pcceoagent",
      model_id: "combo/X",
      visual_profile_id: "vp-ceo-01",
      avatar_id: "avatar-ceo",
      color: "#f59e0b",
      badge_emoji: "👑",
      wave: 1,
      office_location_id: "dept-executive-desk-1",
      desk_coords: { x: 220, y: 190, facing: 90 },
      authorized_workspaces: ["/workspaces"],
      authorized_tools: [],
      skills: [],
      can_create_agents: true,
      activation_status: "ACTIVE",
      raw_status: "idle",
      lifecycle_state: "ready",
      last_heartbeat_at: null,
      current_task: null,
      current_run: null,
      queued_task_count: 0,
      completed_task_count: 5,
      state: {
        activation_state: "ACTIVE",
        connectivity_state: "ONLINE",
        execution_state: "IDLE",
        task_state: "NONE",
        maintenance_state: "NORMAL",
        visual_state: "AT_DESK",
        retro_status: "idle",
        state_reason: "ready",
        stale: false,
        updated_at: "2026-11-24T00:00:00Z",
      },
    } satisfies EnterpriseAgent;

    expect(
      matchEnterpriseAgent({ agentId: "ceo_agent", name: "Executive" }, [sampleEnterpriseAgent])
    ).toBe(sampleEnterpriseAgent);
    expect(
      matchEnterpriseAgent({ agentId: "other-id", name: "CEO Agent" }, [sampleEnterpriseAgent])
    ).toBe(sampleEnterpriseAgent);

    const enriched = enrichOfficeAgentWithEnterprise(
      {
        id: "uuid-ceo-001",
        name: "CEO Agent",
        subtitle: "Executive",
        status: "working",
        color: "#888888",
        item: "laptop",
        avatarProfile: null,
      },
      sampleEnterpriseAgent
    );

    expect(enriched.color).toBe("#f59e0b");
    expect(enriched.badgeEmoji).toBe("👑");
    expect(enriched.subtitle).toBe("👑 Executive");
    expect(enriched.visualProfileId).toBe("vp-ceo-01");
    expect(enriched.avatarProfile?.seed).toBe("vp-ceo-01");
    expect(enriched.avatarProfile?.clothing.topColor).toBe("#f59e0b");
    expect(enriched.deskCoords?.x).toBe(220);
    expect(enriched.deskCoords?.y).toBe(190);
    expect(enriched.deskCoords?.facing).toBeCloseTo(Math.PI / 2, 5);

    expect(
      resolveTelegramHealthIndicator({
        components: { telegram: { state: "HEALTHY" } },
      }).label
    ).toBe("Telegram Synced");
    expect(
      resolveTelegramHealthIndicator({
        components: { telegram: { state: "DEGRADED" } },
      }).label
    ).toBe("Telegram Standby");
  });

  it("verifies multiavatar vendor removal, offline font config, source maps disabled, and ATTRIBUTION.md", () => {
    const appRoot = path.resolve(__dirname, "..", "..");
    expect(fs.existsSync(path.join(appRoot, "src", "lib", "avatars", "vendor"))).toBe(false);
    expect(
      fs.existsSync(path.join(appRoot, "public", "office-assets", "ATTRIBUTION.md"))
    ).toBe(true);
    const attribution = fs.readFileSync(
      path.join(appRoot, "public", "office-assets", "ATTRIBUTION.md"),
      "utf8"
    );
    expect(attribution).toContain("iamlukethedev/Hermes3D");
    expect(attribution).toContain("Kenney Furniture Kit");
    expect(attribution).toContain("office_env_1k.hdr");

    const nextConfigText = fs.readFileSync(path.join(appRoot, "next.config.mjs"), "utf8");
    expect(nextConfigText).toContain("productionBrowserSourceMaps: false");

    const layoutText = fs.readFileSync(path.join(appRoot, "src", "app", "layout.tsx"), "utf8");
    expect(layoutText).not.toContain("next/font/google");
  });
});
