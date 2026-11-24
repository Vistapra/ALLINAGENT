# ALLINAGENT — Open-Source License Inventory & Supply-Chain Classification

This document is the comprehensive human-readable companion to [`LICENSE-INVENTORY.json`](./LICENSE-INVENTORY.json), [`components.lock.json`](./components.lock.json), [`skills/manifests/skills.lock.json`](./skills/manifests/skills.lock.json), and [`THIRD-PARTY-NOTICES.md`](./THIRD-PARTY-NOTICES.md).

**Root Distribution License:** [`MIT`](./LICENSE) (`Copyright (c) 2026 ALLINAGENT Contributors`).

---

## 1. Compliance Policy & Zero-Contamination Guarantees

`ALLINAGENT` enforces a fail-closed open-source compliance policy verified continuously by [`scripts/audit-public-release.py`](./scripts/audit-public-release.py) and [`scripts/generate-sbom.py`](./scripts/generate-sbom.py):

1. **Zero Strong Copyleft in Distributed Artifacts:** `AGPL-3.0`, `GPL-2.0`, `GPL-3.0`, `SSPL-1.0`, and `BUSL-1.1` packages are strictly blocked from the repository and container images (`copyleft_violations: 0`). In particular, optional copyleft PDF packages (`pymupdf` under `AGPL-3.0` and `marker-pdf` under `GPL`) are explicitly stripped and blocked in `hermes` container builds.
2. **Zero Bundling of Commons-Clause, Unlicensed, or Third-Party Schema Blobs:** None of the `13` `FETCH_FROM_UPSTREAM_ONLY` skill packages are vendored in the `ALLINAGENT` Git repository or baked into published GHCR container images (`restricted_files_bundled: 0`).
3. **Immutable 40-Character Commit SHA Pinning:** Every upstream core repository and all `10` external skill repositories are pinned to exact 40-character Git commit SHAs (`allow_floating_git_refs: false`).
4. **Non-OSI Vendor Code Removed Prior to Release:** Non-OSI third-party artifacts present in upstream or transitive trees — notably `vendor/multiavatar.js` (`MULTIAVATAR LICENSE v1.0`) and proprietary CLI SDK tarballs inside transitive `node_modules` — are permanently stripped.

---

## 2. First-Party `ALLINAGENT` Modules (`MIT`)

| Module Group | Repository Paths | SPDX License | Copyright Holder |
| :--- | :--- | :--- | :--- |
| **Core Manifests, CLI & Containers** | `allinagent*`, `package.json`, `components.lock.json`, `config/`, `scripts/`, `deploy/`, `patches/` | `MIT` | `ALLINAGENT Contributors` |
| **Unified Office Bridge & CODEXE** | `apps/office-bridge/` | `MIT` | `ALLINAGENT Contributors` |
| **Control Center, Agents & Integrations** | `apps/control-center/`, `integrations/`, `agents/`, `skills/policies/`, `skills/manifests/` | `MIT` | `ALLINAGENT Contributors` |
| **Enterprise 3D/2D Office Extensions** | `apps/hermes3d/src/features/enterprise-company/`, `apps/hermes3d/src/app/api/company/` | `MIT` | `ALLINAGENT Contributors` |
| **Synthetic Test & Benchmark Fixtures** | `workspaces/sample-project/`, `tests/fixtures/synthetic-order-api/`, `tests/` | `MIT` | `ALLINAGENT Contributors` |

---

## 3. Core Upstream Platform & Runtime Components

| Component / Runtime | Upstream Source / Package | Pinned Version & Commit SHA | SPDX License | Bundled in Git | Integration & Distribution Mode |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **Hermes Agent** | `NousResearch/hermes-agent` | `v0.23.3` (`eb49b8920a25ffa7bb2fadf548fe819221ca79d7`) | `MIT` | `No` | Shallow checkout at setup/build + declarative 1-line classifier patch (`patches/hermes-agent/`) |
| **Paperclip** | `paperclipai/paperclip` (`npm:paperclipai`) | `2026.1117.0` (`c0f132898d2a2677312d8c72096187b27a3d9a38`) | `MIT` | `No` | Locked npm install (`--omit=optional`) + 4 adapter/DB patches + `prune-paperclip-bloat.mjs` |
| **VulnClaw** | `psyrk0/VulnClaw` / `Netw0rkNoob/VulnClaw` | `v0.4.1` (`0b34878f84b089b21fcf85ecd445315f14df0672`) | `MIT` | `No` | Isolated on-demand defensive static-analysis checkout (`0` upstream patches, `0` secrets) |
| **Hermes3D** | `iamlukethedev/Hermes3D` | `v1.0.0` (`beb76292747b816ef317aa6f9a3992e0014f81d9`) | `MIT` | `Yes` (`apps/hermes3d`) | Extended subtree with preserved upstream `MIT` copyright notice and `ATTRIBUTION.md` |
| **THREE.js** | `mrdoob/three.js` (`npm:three`, `@react-three/*`) | Locked in `apps/hermes3d/package-lock.json` | `MIT` | `No` | Installed at build time for client-browser WebGL 3D Virtual Office rendering |
| **Next.js & React** | `vercel/next.js` (`npm:next`, `react`, `react-dom`) | Locked in `apps/hermes3d/package-lock.json` | `MIT` | `No` | Installed at build time (`output: "standalone"`, `productionBrowserSourceMaps: false`) |
| **Phaser** | `phaserjs/phaser` (`npm:phaser`) | Locked in `apps/hermes3d/package-lock.json` | `MIT` | `No` | Installed at build time for 2D Pixel Office HTML5 Canvas rendering |
| **PostgreSQL 16** | `postgres:16-alpine` (PostgreSQL Global Dev Group) | `16-alpine` | `PostgreSQL` | `No` | Official OCI database image running on internal `allinagent_data` network |
| **Node.js & Python Base** | `node:22-alpine` / `24-slim`, `python:3.12-slim` / `3.14` | Official OCI Base Images | `MIT` / `PSF-2.0` | `No` | Container runtime base layers for Node.js and Python services |
| **3D Office Models & HDRI** | `Kenney Furniture Kit` (`17` `.glb`) + `office_env_1k.hdr` | Tracked in `apps/hermes3d/public/office-assets/` | `CC0-1.0` | `Yes` | Public-domain (`CC0-1.0`) 3D low-poly furniture assets and environment lighting |

---

## 4. Complete 33 Agent Skills Classification (`20` OSI-Permissive vs. `13` `FETCH_FROM_UPSTREAM_ONLY`)

All **33 agent skill packages** across **10 GitHub repositories** are pinned by 40-character commit SHA and per-file SHA-256 checksums in [`skills/manifests/skills.lock.json`](./skills/manifests/skills.lock.json).

> [!NOTE]
> **Repository vs. Per-Package Count Reconciliation:** At the repository level ([`LICENSE-INVENTORY.json`](./LICENSE-INVENTORY.json)), `8` repositories (`22` packages) carry OSI-approved root licenses (`MIT` or `Apache-2.0`) and `2` repositories (`11` packages) carry restricted or missing root licenses. At the stricter per-package lockfile level ([`skills/manifests/skills.lock.json`](./skills/manifests/skills.lock.json)), **`2` packages (`docx` and `pdf`) inside `anthropics/skills`** are additionally elevated to **`FETCH_FROM_UPSTREAM_ONLY`** because their subdirectories bundle third-party ECMA / ISO-IEC 29500 Office Open XML `.xsd` schemas (`Complete terms in LICENSE.txt`). This yields **`20` pure OSI-permissive redistributable packages** and **`13` `FETCH_FROM_UPSTREAM_ONLY` packages** (`10 + 1 + 2 = 13`). Zero upstream skill files of either class are vendored in Git.

### 4.1 `20` Pure OSI-Permissive Redistributable Skills (`ALLOW_WITH_ATTRIBUTION_OR_FETCH`)

| # | Skill Package ID | Upstream Repository | Pinned Commit SHA (40-char) | SPDX License | Runtime Tier / Role Assignment |
| :---: | :--- | :--- | :--- | :--- | :--- |
| `01` | `skill-scanner` | `getsentry/skills` | `a582c51ee29d0f35e6ac321340796f77d43da733` | `Apache-2.0` | Stage-1 Supply-Chain Security Gate |
| `02` | `c-level-skills` | `alirezarezvani/claude-skills` | `5909a72e62b5fbb809935fb6a55b58bdbe175074` | `MIT` | `@ceo` (`SPECIALIST`) |
| `03` | `ceo-advisor` | `alirezarezvani/claude-skills` | `5909a72e62b5fbb809935fb6a55b58bdbe175074` | `MIT` | `@ceo` (`PRIMARY`) |
| `04` | `ciso-advisor` | `alirezarezvani/claude-skills` | `5909a72e62b5fbb809935fb6a55b58bdbe175074` | `MIT` | `@security_lead` (`PRIMARY`) |
| `05` | `compliance-os` | `alirezarezvani/claude-skills` | `5909a72e62b5fbb809935fb6a55b58bdbe175074` | `MIT` | `@compliance` (`PRIMARY`) |
| `06` | `cto-review` | `alirezarezvani/claude-skills` | `5909a72e62b5fbb809935fb6a55b58bdbe175074` | `MIT` | `@cto` (`PRIMARY`) |
| `07` | `pw` | `alirezarezvani/claude-skills` | `5909a72e62b5fbb809935fb6a55b58bdbe175074` | `MIT` | `@qa` (`PRIMARY`) |
| `08` | `pw-coverage` | `alirezarezvani/claude-skills` | `5909a72e62b5fbb809935fb6a55b58bdbe175074` | `MIT` | `@qa` (`ON_DEMAND`) |
| `09` | `pw-fix` | `alirezarezvani/claude-skills` | `5909a72e62b5fbb809935fb6a55b58bdbe175074` | `MIT` | `@qa` (`ON_DEMAND`) |
| `10` | `pw-generate` | `alirezarezvani/claude-skills` | `5909a72e62b5fbb809935fb6a55b58bdbe175074` | `MIT` | `@qa` (`SPECIALIST`) |
| `11` | `pw-report` | `alirezarezvani/claude-skills` | `5909a72e62b5fbb809935fb6a55b58bdbe175074` | `MIT` | `@qa` (`ON_DEMAND`) |
| `12` | `pw-review` | `alirezarezvani/claude-skills` | `5909a72e62b5fbb809935fb6a55b58bdbe175074` | `MIT` | `@qa` (`SPECIALIST`) |
| `13` | `frontend-design` | `anthropics/skills` | `e4bb5d960d87126ff3b3a8af1a104b7db67560ba` | `Apache-2.0` | `@frontend` (`SPECIALIST`) |
| `14` | `anthropic-patch` | `anthropics/defending-code-reference-harness` | `d3bea6b5793b5f3d59a75ebe69a58efa88383145` | `Apache-2.0` | `@remediation` (`REFERENCE_ONLY`) |
| `15` | `anthropic-triage` | `anthropics/defending-code-reference-harness` | `d3bea6b5793b5f3d59a75ebe69a58efa88383145` | `Apache-2.0` | `@findings` (`REFERENCE_ONLY`) |
| `16` | `threat-model` | `anthropics/defending-code-reference-harness` | `d3bea6b5793b5f3d59a75ebe69a58efa88383145` | `Apache-2.0` | `@security_lead` (`REFERENCE_ONLY`; `bootstrap.md` quarantined) |
| `17` | `terraform-skill` | `antonbabenko/terraform-skill` | `f5a195992d84c8fb075b0176d666967cd07d2081` | `Apache-2.0` | `@devops` (`SPECIALIST`) |
| `18` | `security-vuln-remediation` | `stacklok/toolhive-studio` | `4d87c91d49b881ccc7dc64667c1dce5a84c535d6` | `Apache-2.0` | `@remediation` (`SPECIALIST`) |
| `19` | `cve-triage` | `fedius01/cve-triage` | `3517c8fb10531103c403f09143966d62b2a0790f` | `MIT` | `@findings` (`EXPERIMENTAL` — opt-in) |
| `20` | `secondsky-cybersecurity-ref` | `secondsky/claude-skills` | `14966c3024f48eea0386eb970b230ea0f4bebd33` | `MIT` | `@security` (`REFERENCE_ONLY`; `10` offensive test files quarantined) |

### 4.2 `13` Non-Redistributed Skills (`FETCH_FROM_UPSTREAM_ONLY`)

These `13` packages are **never bundled** in the `ALLINAGENT` Git repository or GHCR container images. Only commit SHAs and SHA-256 digests appear in lock manifests; operators fetch them directly into their local host volume during `./allinagent setup`:

| # | Skill Package ID | Upstream Repository | Pinned Commit SHA (40-char) | License / SPDX Classification | Non-Bundling Rationale |
| :---: | :--- | :--- | :--- | :--- | :--- |
| `21` | `api-design-reviewer` | `borghei/Claude-Skills` | `25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3` | `MIT-Commons-Clause-1.0` | Commons Clause v1.0 restricts commercial sale/resale |
| `22` | `ci-cd-pipeline-builder` | `borghei/Claude-Skills` | `25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3` | `MIT-Commons-Clause-1.0` | Commons Clause v1.0 restricts commercial sale/resale |
| `23` | `cto-advisor` | `borghei/Claude-Skills` | `25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3` | `MIT-Commons-Clause-1.0` | Commons Clause v1.0 restricts commercial sale/resale |
| `24` | `focused-fix` | `borghei/Claude-Skills` | `25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3` | `MIT-Commons-Clause-1.0` | Commons Clause v1.0 restricts commercial sale/resale |
| `25` | `security-audit` | `borghei/Claude-Skills` | `25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3` | `MIT-Commons-Clause-1.0` | Commons Clause v1.0 restricts commercial sale/resale |
| `26` | `senior-architect` | `borghei/Claude-Skills` | `25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3` | `MIT-Commons-Clause-1.0` | Commons Clause v1.0 restricts commercial sale/resale |
| `27` | `senior-backend` | `borghei/Claude-Skills` | `25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3` | `MIT-Commons-Clause-1.0` | Commons Clause v1.0 restricts commercial sale/resale |
| `28` | `senior-devops` | `borghei/Claude-Skills` | `25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3` | `MIT-Commons-Clause-1.0` | Commons Clause v1.0 restricts commercial sale/resale |
| `29` | `senior-qa` | `borghei/Claude-Skills` | `25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3` | `MIT-Commons-Clause-1.0` | Commons Clause v1.0 restricts commercial sale/resale |
| `30` | `senior-security` | `borghei/Claude-Skills` | `25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3` | `MIT-Commons-Clause-1.0` | Commons Clause v1.0 restricts commercial sale/resale |
| `31` | `react-best-practices` | `vercel-labs/agent-skills` | `5a37a6329fbad3666c3207392a6a7c0110e92efb` | `NOASSERTION` (`LicenseRef-Missing-Root-License`) | Upstream repo lacks a standalone root `LICENSE` file |
| `32` | `docx` | `anthropics/skills` | `e4bb5d960d87126ff3b3a8af1a104b7db67560ba` | `Apache-2.0` + Third-Party Schemas (`LICENSE.txt`) | Bundles third-party ECMA / ISO-IEC 29500 OOXML `.xsd` schemas |
| `33` | `pdf` | `anthropics/skills` | `e4bb5d960d87126ff3b3a8af1a104b7db67560ba` | `Apache-2.0` + Third-Party Assets (`LICENSE.txt`) | Bundles third-party PDF specification notices (`LICENSE.txt`) |

### 4.3 `--strict-oss` and `--offline` Nous Research `MIT` Fallbacks

When operators provision skills with `--strict-oss` (pure OSI-approved open-source mode) or `--offline` (air-gapped environments without GitHub egress), `ALLINAGENT` skips all `13` `FETCH_FROM_UPSTREAM_ONLY` packages and automatically activates pure **MIT-licensed Nous Research** fallbacks for executive reporting:

- **`docx` Fallback:** Maps to **`productivity/microsoft-office`** (`MIT`, Nous Research bundled Hermes skill) backed by `python-docx` (`MIT`) and pure-stdlib OpenXML generation in `apps/control-center/control_center/report_exporter.py`.
- **`pdf` Fallback:** Maps to **`productivity/pdf`** (`MIT`, Nous Research bundled Hermes skill) backed by `reportlab` (`BSD-3-Clause`), `pypdf` (`BSD-3-Clause`), `pdfplumber` (`MIT`), and deterministic `%PDF-1.4` generation in `report_exporter.py`.

---

## 5. Documented Non-OSI Removals & Remediation Ledger

During Phase 06, Phase 09, and Phase 11 supply-chain audits, the following non-OSI artifacts were identified and permanently eliminated:

1. **Removal of `vendor/multiavatar.js` (`MULTIAVATAR LICENSE v1.0`):**
   - **Finding:** Upstream `Hermes3D` included `src/lib/avatars/vendor/multiavatar.js` (`69,736` bytes) governed by the custom `MULTIAVATAR LICENSE v1.0` (non-OSI license imposing custom attribution/redistribution conditions).
   - **Remediation:** Permanently deleted `apps/hermes3d/src/lib/avatars/vendor/multiavatar.js` and the `vendor/` directory. Verified via unit tests (`tests/unit/multiavatar.test.ts`, `4/4` passing) that `apps/hermes3d/src/lib/avatars/multiavatar.ts` is 100% self-contained, first-party `MIT` deterministic SVG avatar code with zero dependency on the removed vendor script.
2. **Pruning of Non-OSI Nested Agent SDKs in Paperclip (`prune-paperclip-bloat.mjs`):**
   - **Finding:** Unpruned `paperclipai@2026.1117.0` transitive `node_modules` pulled `1,648.48 MiB` of unused third-party CLI tarballs including `@anthropic-ai/claude-code*`, `@anthropic-ai/claude-agent-sdk*` (`"SEE LICENSE IN README.md"`), and `@github/copilot*`.
   - **Remediation:** `components/paperclip/prune-paperclip-bloat.mjs` deterministically strips all proprietary/unused CLI SDKs during `postinstall` and container builds (`0` bytes retained in published images) while preserving the `MIT`-licensed `@anthropic-ai/sdk` client library.

---

## 6. Direct npm & PyPI Ecosystem Dependencies

All direct JavaScript/TypeScript and Python runtime packages carry OSI-approved permissive licenses:

| Ecosystem | Packages | SPDX License(s) |
| :--- | :--- | :--- |
| **npm (MIT)** | `@noble/ed25519`, `@react-three/drei`, `@react-three/fiber`, `@react-three/postprocessing`, `clsx`, `next`, `paperclipai`, `phaser`, `react`, `react-dom`, `react-markdown`, `react-mentions-ts`, `remark-gfm`, `tailwind-merge`, `tailwindcss`, `three`, `vitest`, `ws` | `MIT` |
| **npm (ISC / Apache-2.0)** | `canvas-confetti`, `lucide-react` (`ISC`); `class-variance-authority`, `typescript` (`Apache-2.0`) | `ISC` / `Apache-2.0` |
| **PyPI (MIT)** | `beautifulsoup4`, `croniter`, `jsonschema`, `mcp`, `pydantic`, `pydantic-settings`, `pyjwt`, `pyyaml`, `rich`, `ruamel-yaml`, `toml`, `tomli-w`, `truststore`, `typer` | `MIT` |
| **PyPI (Apache-2.0 / BSD / MPL)** | `fire`, `openai`, `packaging`, `requests` (`Apache-2.0`); `httpx`, `jinja2`, `lxml`, `markdown`, `prompt-toolkit`, `python-dotenv`, `snowballstemmer`, `reportlab`, `pypdf` (`BSD-3-Clause`); `pycryptodome` (`BSD-2-Clause`); `certifi` (`MPL-2.0` unmodified file-level) | `Apache-2.0` / `BSD` / `MPL-2.0` |

---

## 7. Automated Verification Commands

```bash
# Validate CycloneDX 1.5 SBOM generation & zero copyleft/restricted bundling
python3 scripts/generate-sbom.py --validate --output data/reports/sbom.cdx.json

# Run fail-closed public release & license hygiene auditor
python3 scripts/audit-public-release.py --self-test
python3 scripts/audit-public-release.py
```
