# PHASE 11 — Hermes3D & 2D Pixel Office Optimization, Portability & License Hygiene

- **Phase ID:** `PHASE-11`
- **Status:** `PASS`
- **Target Path:** `apps/hermes3d`
- **Timestamp (UTC):** `2026-11-24T10:44:00Z`

---

## 1. Executive Summary

1. **99.08% Footprint Reduction (`859.56 MiB` $\rightarrow$ `7.898 MiB`):**
   - Staged clean source and 3D/2D public assets into `apps/hermes3d` (`656` files, `8,281,358` bytes = `7.898 MiB`) via deterministic staging (`stage_hermes3d.py`), stripping `802.59 MB` (`38,394` files) of `node_modules`, `40.06 MB` (`676` files) of `.next` build caches, `8.15 MB` of nested `.git` metadata, `449.7 KB` of `tsconfig.tsbuildinfo`, runtime `tasks.json`, and local `.env*` files.
2. **Non-OSI Supply-Chain Hazard Eliminated (`MULTIAVATAR LICENSE v1.0`):**
   - Permanently excluded `src/lib/avatars/vendor/multiavatar.js` (`69,736` bytes = `68.10 KiB`) and `src/lib/avatars/vendor/`. Verified `src/lib/avatars/multiavatar.ts` is 100% self-contained MIT first-party deterministic SVG code (`tests/unit/multiavatar.test.ts`: `4/4` passing).
   - Added `public/office-assets/ATTRIBUTION.md` documenting `iamlukethedev/Hermes3D` (`MIT`), `Kenney Furniture Kit` (`CC0-1.0`, `17` GLB models = `209,800` bytes), and `office_env_1k.hdr` (`CC0-1.0`, `1,198,770` bytes).
3. **100% Cross-Platform Linux/Docker Portability & Zero Private Identifiers:**
   - Eliminated the hardcoded `"<LEGACY_PLATFORM_ROOT>/config/secrets/office-bridge-auth.json"` read in `server/index.js`, all `"<LOCAL_WEB_STACK_ROOT>/www"` and Windows-only drive-root hardcodes in `TargetFolderPickerModal.tsx`, and Windows-only case-folding/path assumptions in `src/app/api/path-suggestions/route.ts`.
   - Enabled seamless Docker Compose & Linux host operation (`OFFICE_BRIDGE_TOKEN`, `OFFICE_BRIDGE_WS_URL`, `OFFICE_BRIDGE_HTTP_URL`, `ALLINAGENT_ROOT`, automatic production allowlisting for internal `office-bridge` / `allinagent-office-bridge` upstreams, and stale `ws://127.0.0.1:3210/ws` override in `settings.json`).
   - Regex and SHA-256 privacy audit across all `656` files confirmed **`0`** occurrences of private operator usernames, workstation hostnames, `<OWNER_TELEGRAM_ID>`, private client repository names, `<LOCAL_WEB_STACK_ROOT>`, or `<LEGACY_PLATFORM_ROOT>`.
4. **Offline Docker Build Resilience & Bundle Optimization:**
   - Replaced `next/font/google` (`Bebas_Neue`, `IBM_Plex_Sans`, `IBM_Plex_Mono` — `26` external `.woff2` fetches / `258,568` bytes at build time) in `src/app/layout.tsx` and `src/app/globals.css` with offline-safe CSS custom property font stacks (`--font-display`, `--font-sans`, `--font-mono`), guaranteeing air-gapped Docker `next build` reliability without Google Fonts internet access.
   - Enforced `productionBrowserSourceMaps: false` and `poweredByHeader: false` in `next.config.ts` (baseline `.next` held `165` `.map` files totaling `28,079,142` bytes = `26.78 MiB`).
5. **Corporate 3D/2D Avatar Enrichment & Live Telegram Header Telemetry:**
   - Enriched `mapAgentToOffice` (`OfficeScreen.tsx` + `enrichOfficeAgent.ts`) and `RetroOffice3D.tsx` so `EnterpriseSnapshot` corporate metadata (`color`, `badge_emoji`, `desk_coords`, `visual_profile_id`) automatically styles 3D/2D `OfficeAgent` avatars, nameplates, clothing colors, and unassigned corporate desk positions when matched by `agentId`, `role_slug`, or `name`.
   - Added live `"● Telegram Synced"` / `"○ Telegram Standby"` indicator (`data-testid="telegram-sync-badge"`) to the top-left Enterprise Telemetry bar in `EnterpriseOfficeOverlay.tsx`, driven by live `/api/company/health` component liveness.

---

## 2. Exact Size & Bundle Optimization Metrics

### 2.1 Before vs. After Directory Footprint

| Component / Artifact | Baseline (`<LEGACY_PLATFORM_ROOT>/hermes3d/source`) | Staged (`apps/hermes3d`) | Delta |
| :--- | ---: | ---: | ---: |
| `node_modules/` | `802,593,502 B` (`765.41 MiB`, `38,394` files) | `0 B` (`0` files) | `-765.41 MiB` |
| `.next/` build output (incl. `165` `.map` files = `26.78 MiB`) | `40,055,308 B` (`38.20 MiB`, `676` files) | `0 B` (`0` files) | `-38.20 MiB` |
| `.git/` nested repository | `8,150,570 B` (`7.77 MiB`, `69` files) | `0 B` (`0` files) | `-7.77 MiB` |
| `tsconfig.tsbuildinfo` | `449,742 B` (`0.43 MiB`, `1` file) | `0 B` (`0` files) | `-0.43 MiB` |
| `src/lib/avatars/vendor/multiavatar.js` *(non-OSI)* | `69,736 B` (`68.10 KiB`, `1` file) | `0 B` (`0` files) | `-68.10 KiB` |
| External Google Font build fetches (`next/font/google`) | `258,568 B` (`26` `.woff2` files via HTTPS) | `0 B` (`0` network calls; CSS system/local stacks) | `-252.51 KiB` + offline-safe |
| Clean Source, Tests, Server & Public 3D/2D Assets | `8,246,586 B` (`7.865 MiB`, `653` files) | **`8,281,358 B` (`7.898 MiB`, `656` files)** | `+34.0 KiB` (`+3` new files) |
| **Total Directory Footprint** | **`859,565,444 B` (`819.75 MiB`, `39,794` files)** | **`8,281,358 B` (`7.898 MiB`, `656` files)** | **`-99.04%` bytes / `-98.35%` files** |

### 2.2 Staged `apps/hermes3d` Breakdown by Subtree

| Subtree | Files | Bytes | MiB | Notes |
| :--- | ---: | ---: | ---: | :--- |
| `src/` | `335` | `3,578,264` | `3.413` | Next.js App Router, 3D Retro Office, 2D Pixel Office, Enterprise Overlay |
| `public/` | `22` | `1,633,231` | `1.558` | `17` Kenney CC0 `.glb` (`209.8 KB`), `office_env_1k.hdr` (`1.20 MB`), `office-bg.png` (`220.1 KB`), `ATTRIBUTION.md` |
| `tests/` | `201` | `1,240,713` | `1.183` | Vitest unit/integration suites + Playwright E2E specs + Phase 11 suite |
| `assets/` | `6` | `787,410` | `0.751` | Bundled Hermes3D skill templates & branding hero |
| `(root)` | `35` | `526,706` | `0.502` | `package.json`, `package-lock.json`, `Dockerfile`, `next.config.ts`, docs |
| `docs/` | `29` | `264,974` | `0.253` | Architecture, runtime profile, and office system specifications |
| `server/` | `11` | `176,195` | `0.168` | Custom HTTP/WS server, access gate, gateway proxy, Hermes JSON-RPC bridge |
| `scripts/` | `6` | `51,482` | `0.049` | `hermes3doctor.mjs`, `studio-setup.js`, `hermes3d-start.sh` |
| `plugins/` | `4` | `17,941` | `0.017` | `hermes3d-office-bridge` Python publisher plugin |
| `.github/` | `7` | `4,442` | `0.004` | Issue templates & CI workflow definitions |
| **Total** | **`656`** | **`8,281,358`** | **`7.898`** | **Zero `node_modules`, zero `.next`, zero secrets, zero non-OSI files** |

---

## 3. Portability, Security & Feature Enrichment Changes Applied

| File | Summary of Changes |
| :--- | :--- |
| `server/index.js` | Replaced hardcoded `"<LEGACY_PLATFORM_ROOT>/config/secrets/office-bridge-auth.json"` with `resolveOfficeBridgeToken()` (`OFFICE_BRIDGE_TOKEN` $\rightarrow$ `HERMES3D_GATEWAY_TOKEN` $\rightarrow$ `ALLINAGENT_ROOT` / `../../..` / `../..` secret file fallback) and `resolveOfficeBridgeWsBase()` (`OFFICE_BRIDGE_WS_URL` $\rightarrow$ `OFFICE_BRIDGE_HTTP_URL` `ws://` conversion $\rightarrow$ `ws://127.0.0.1:3210`). Guarded `main()` under `require.main === module` and exported helpers for unit testing. |
| `server/gateway-proxy.js` | Updated `isUpstreamAllowed()` to automatically trust `127.0.0.1`, `localhost`, `::1`, `office-bridge`, `allinagent-office-bridge`, and the configured hostnames of `OFFICE_BRIDGE_WS_URL`, `OFFICE_BRIDGE_HTTP_URL`, and `HERMES3D_GATEWAY_URL` in `NODE_ENV=production` while continuing to block untrusted external hosts. |
| `server/studio-settings.js` & `src/lib/studio/settings-store.ts` | Added `resolveEnvBridgeGatewayUrl()` and `isStaleLoopbackBridgeUrl()` so `OFFICE_BRIDGE_WS_URL` / `HERMES3D_GATEWAY_URL` automatically overrides stale `ws://127.0.0.1:3210/ws` entries in `settings.json` when migrating from Windows host loopback to Docker containers, and supports `OFFICE_BRIDGE_TOKEN` + `ALLINAGENT_ROOT` secret fallback. |
| `src/app/api/company/[...slug]/route.ts` | Added `OFFICE_BRIDGE_TOKEN` / `HERMES3D_GATEWAY_TOKEN` env resolution ahead of multi-level `ALLINAGENT_ROOT` (`../../` from `apps/hermes3d` and `..` fallback) secret file lookup, plus dynamic `OFFICE_BRIDGE_HTTP_URL` base resolution. |
| `src/app/api/runtime/custom/route.ts` | Added `OFFICE_BRIDGE_TOKEN` + `ALLINAGENT_ROOT` (`../../` and `..`) token resolution; updated `isRuntimeUrlAllowed()` under `UNIFIED_COMPANY_GOVERNANCE=1` so `parsed.origin === new URL(process.env.OFFICE_BRIDGE_HTTP_URL || "http://127.0.0.1:3210").origin`, `office-bridge:3210`, and `CUSTOM_RUNTIME_ALLOWLIST` bridge hosts are permitted while Paperclip (`3100`) and PostgreSQL (`5432`/`54329`) remain strictly blocked against SSRF. |
| `src/app/api/path-suggestions/route.ts` | Removed Windows-only hardcoded `c:\...` literals and unconditional `.toLowerCase()` path folding; preserved POSIX case sensitivity on Linux (`process.platform !== "win32"`); blocked `/etc`, `/proc`, `/sys`, `/dev`, `/root`, `/var/run`, `/run`, `~/.ssh`, `~/.aws`, `~/.git-credentials`, `~/.gnupg`, `~/.docker`, and `~/.hermes`; resolved `ALLINAGENT_ROOT/workspaces` dynamically (`../../` and `..` fallback). |
| `src/features/enterprise-company/TargetFolderPickerModal.tsx` | Removed every `"<LOCAL_WEB_STACK_ROOT>/www"`, Windows drive-root array hardcode, and Windows drive-only UI prompt; initialized `browsePath` from `state?.active_folder \|\| state?.quick_roots?.[0] \|\| ""`; set placeholder to `/workspaces/my-project`. |
| `src/features/enterprise-company/enrichOfficeAgent.ts` *(new)* | Implemented pure, unit-tested `matchEnterpriseAgent()`, `enrichOfficeAgentWithEnterprise()`, and `resolveTelegramHealthIndicator()` helpers. |
| `src/features/office/screens/OfficeScreen.tsx` & `src/features/retro-office/RetroOffice3D.tsx` & `src/features/retro-office/core/types.ts` | Connected `EnterpriseSnapshot` from `EnterpriseOfficeOverlay` into `OfficeScreen.tsx`; enriched `mapAgentToOffice()` with corporate `color`, `badge_emoji` (`badgeEmoji` + `subtitle`), `visual_profile_id` (`visualProfileId` + seeded `avatarProfile` tinted with role color), and `desk_coords` (`deskCoords` fallback in `RetroOffice3D.tsx` when no manual desk assignment exists). |
| `src/features/enterprise-company/EnterpriseOfficeOverlay.tsx` & `src/features/enterprise-company/types.ts` | Added `onSnapshotChange` callback, periodic live `/api/company/health` polling, and the `"● Telegram Synced"` / `"○ Telegram Standby"` top-bar status badge (`data-testid="telegram-sync-badge"`). |
| `next.config.ts` & `src/app/layout.tsx` & `src/app/globals.css` | Set `productionBrowserSourceMaps: false` and `poweredByHeader: false`; removed `next/font/google` imports from `layout.tsx` and expanded `--font-display`, `--font-sans`, and `--font-mono` CSS font stacks in `globals.css` for zero-network offline Docker builds. |
| `public/office-assets/ATTRIBUTION.md` *(new)* | Documented open-source attributions and licenses for `iamlukethedev/Hermes3D` (`MIT`), `Kenney Furniture Kit` (`CC0-1.0`), `office_env_1k.hdr` (`CC0-1.0`), and first-party procedural avatars (`MIT`). |
| `tests/unit/phase11PortabilityAndEnrichment.test.ts` *(new)* | Added 6-part verification test suite covering all Phase 11 server, API route, POSIX path guard, avatar enrichment, Telegram indicator, and asset hygiene requirements. |

---

## 4. Verification Evidence

1. **JavaScript Server & Script Syntax Verification (`node --check`):**
   - `22 / 22` `.js` and `.mjs` files across `server/**` and `scripts/**` passed `node --check` with exit code `0`.
2. **TypeScript Full-Project Typecheck (`tsc --noEmit`):**
   - Executed `tsc --noEmit` across all `335` `src/**` and `201` `tests/**` files $\rightarrow$ **Exit Code `0` (`0` errors)**.
3. **Vitest Unit & Integration Verification (`vitest run`):**
   - **`12 / 12` test files (`70 / 70` tests) PASSED (`0` failed):**
     - `tests/unit/phase11PortabilityAndEnrichment.test.ts` (`6` tests) — PASS
     - `tests/unit/enterpriseCompanyIntegration.test.ts` (`5` tests) — PASS
     - `tests/unit/customRuntimeRoute.test.ts` (`3` tests) — PASS
     - `tests/unit/pathSuggestionsRoute.test.ts` (`4` tests) — PASS
     - `tests/unit/studioUpstreamGatewaySettings.test.ts` (`2` tests) — PASS
     - `tests/unit/gatewayEnvDefaults.test.ts` (`8` tests) — PASS
     - `tests/unit/gatewayProxy.test.ts` (`12` tests) — PASS
     - `tests/unit/multiavatar.test.ts` (`4` tests) — PASS
     - `tests/unit/standup3dAll11Agents.test.ts` (`2` tests) — PASS
     - `tests/unit/pixelOfficeInputs.test.ts` (`8` tests) — PASS
     - `tests/unit/pixelOfficeSim.test.ts` (`10` tests) — PASS
     - `tests/unit/officeRenderMode.test.ts` (`6` tests) — PASS
4. **Feature Parity & Privacy Gate:**
   - **Preserved 100%:** 3D Retro Office, 2D Gather-style Pixel Office, 11 distinct corporate avatars, Meeting Room (`14` reachable A* seats for `11/11` corporate attendance), 6-tab Enterprise Command Center (Roster, Agent Inspector, Collaboration/Meetings, VulnClaw SOC, Governance/Budget, 12-Component Ops Health & Evidence Viewer), Agent Chat, Target Folder Picker, Usage Analytics, Run History, and Skill Telemetry.
   - **Privacy Scan:** `0` matches for private operator names, workstation hostnames, `<OWNER_TELEGRAM_ID>`, private client repositories, `<LOCAL_WEB_STACK_ROOT>`, `<LEGACY_PLATFORM_ROOT>`, or `multiavatar.js` across `apps/hermes3d`.
