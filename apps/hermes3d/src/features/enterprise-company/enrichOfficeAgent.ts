import {
  createDefaultAgentAvatarProfile,
  type AgentAvatarProfile,
} from "@/lib/avatars/profile";
import type { FacingPoint, OfficeAgent } from "@/features/retro-office/core/types";
import type { EnterpriseAgent, EnterpriseSnapshot } from "./types";

const normalizeAgentSlug = (value: string | null | undefined): string =>
  (value ?? "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");

const ROLE_SLUG_ALIASES: Record<string, string[]> = {
  compliance_reporter: ["report_compliance_agent", "compliance_reporter", "pccompliancereporter"],
  report_compliance_agent: ["compliance_reporter", "report_compliance_agent", "pccompliancereporter"],
  ceo_agent: ["ceo", "ceo_agent", "pcceoagent"],
  cto_agent: ["cto", "cto_agent", "pcctoagent"],
  backend_developer: ["backend_developer", "pcbackenddeveloper"],
  frontend_developer: ["frontend_developer", "pcfrontenddeveloper"],
  devops_engineer: ["devops_engineer", "pcdevopsengineer"],
  qa_engineer: ["qa_engineer", "pcqaengineer"],
  security_lead: ["security_lead", "pcsecuritylead"],
  security_reviewer: ["security_reviewer", "pcsecurityreviewer"],
  findings_analyst: ["findings_analyst", "pcfindingsanalyst"],
  remediation_reviewer: ["remediation_reviewer", "pcremediationreviewer"],
};

const expandCandidateKeys = (values: Array<string | null | undefined>): Set<string> => {
  const keys = new Set<string>();
  for (const raw of values) {
    const trimmed = (raw ?? "").trim().toLowerCase();
    if (trimmed) keys.add(trimmed);
    const slug = normalizeAgentSlug(raw);
    if (slug) {
      keys.add(slug);
      for (const alias of ROLE_SLUG_ALIASES[slug] ?? []) {
        keys.add(alias);
      }
    }
  }
  return keys;
};

export function matchEnterpriseAgent(
  agent: { agentId: string; name?: string | null; role?: string | null },
  enterpriseAgents: readonly EnterpriseAgent[] | null | undefined
): EnterpriseAgent | null {
  if (!enterpriseAgents || enterpriseAgents.length === 0) return null;

  // 1. Exact canonical Paperclip ID match first
  const exactId = enterpriseAgents.find((ea) => ea.paperclip_agent_id === agent.agentId);
  if (exactId) return exactId;

  const targetKeys = expandCandidateKeys([agent.agentId, agent.name]);
  const roleKey = normalizeAgentSlug(agent.role);

  // 2. Match by normalized agentId / role_slug / runtime_profile_reference / display_name
  for (const ea of enterpriseAgents) {
    const eaKeys = expandCandidateKeys([
      ea.paperclip_agent_id,
      ea.role_slug,
      ea.runtime_profile_reference,
      ea.display_name,
    ]);
    for (const key of targetKeys) {
      if (eaKeys.has(key)) return ea;
    }
  }

  // 3. Fallback match by explicit role_slug / role if unambiguous
  if (roleKey) {
    const roleMatches = enterpriseAgents.filter((ea) => {
      const eaRoleSlug = normalizeAgentSlug(ea.role_slug || ea.role);
      return eaRoleSlug === roleKey || (ROLE_SLUG_ALIASES[roleKey] ?? []).includes(eaRoleSlug);
    });
    if (roleMatches.length === 1) return roleMatches[0];
  }

  return null;
}

const normalizeFacingRadians = (facing: number | undefined): number => {
  if (typeof facing !== "number" || !Number.isFinite(facing)) return 0;
  if (Math.abs(facing) > Math.PI * 2) {
    return (facing * Math.PI) / 180;
  }
  return facing;
};

export function enrichOfficeAgentWithEnterprise(
  base: OfficeAgent,
  enterpriseAgent: EnterpriseAgent | null | undefined
): OfficeAgent {
  if (!enterpriseAgent) return base;

  const badgeEmoji = enterpriseAgent.badge_emoji?.trim() || null;
  const baseSubtitle = base.subtitle?.trim() || enterpriseAgent.title?.trim() || null;
  const subtitle = badgeEmoji
    ? baseSubtitle
      ? baseSubtitle.includes(badgeEmoji)
        ? baseSubtitle
        : `${badgeEmoji} ${baseSubtitle}`
      : badgeEmoji
    : baseSubtitle;

  const visualProfileId = enterpriseAgent.visual_profile_id?.trim() || null;
  const corporateColor = enterpriseAgent.color?.trim() || base.color;

  let avatarProfile: AgentAvatarProfile | null = base.avatarProfile ?? null;
  if (visualProfileId && (!avatarProfile || avatarProfile.seed === base.id)) {
    const seeded = createDefaultAgentAvatarProfile(visualProfileId);
    avatarProfile = {
      ...seeded,
      clothing: {
        ...seeded.clothing,
        topColor: corporateColor || seeded.clothing.topColor,
      },
    };
  }

  const deskCoords: FacingPoint | null =
    enterpriseAgent.desk_coords &&
    Number.isFinite(enterpriseAgent.desk_coords.x) &&
    Number.isFinite(enterpriseAgent.desk_coords.y)
      ? {
          x: enterpriseAgent.desk_coords.x,
          y: enterpriseAgent.desk_coords.y,
          facing: normalizeFacingRadians(enterpriseAgent.desk_coords.facing),
        }
      : base.deskCoords ?? null;

  return {
    ...base,
    subtitle,
    color: corporateColor,
    avatarProfile,
    badgeEmoji,
    visualProfileId,
    deskCoords,
  };
}

export function resolveTelegramHealthIndicator(
  healthMatrix: Record<string, unknown> | null | undefined,
  snapshot?: EnterpriseSnapshot | null
): { synced: boolean; label: "Telegram Synced" | "Telegram Standby"; state: string } {
  const components =
    healthMatrix && typeof healthMatrix === "object" && "components" in healthMatrix
      ? (healthMatrix.components as Record<string, { state?: string; connected?: boolean }> | undefined)
      : undefined;
  const tgFromHealth = components?.telegram;
  const snapAny = snapshot as
    | (EnterpriseSnapshot & {
        telegram?: { state?: string; connected?: boolean };
        health?: { components?: { telegram?: { state?: string; connected?: boolean } } };
      })
    | null
    | undefined;
  const tgFromSnap = snapAny?.telegram ?? snapAny?.health?.components?.telegram;

  const rawState = String(tgFromHealth?.state ?? tgFromSnap?.state ?? "").trim().toUpperCase();
  const explicitConnected = tgFromHealth?.connected ?? tgFromSnap?.connected;
  const synced =
    explicitConnected === true ||
    rawState === "HEALTHY" ||
    rawState === "CONNECTED" ||
    rawState === "ONLINE" ||
    rawState === "OK";

  return {
    synced,
    label: synced ? "Telegram Synced" : "Telegram Standby",
    state: rawState || (synced ? "HEALTHY" : "STANDBY"),
  };
}
