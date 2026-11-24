# Third-Party Notices & Upstream Attributions

**ALLINAGENT** first-party orchestration, Office Bridge (`apps/office-bridge/`), Control Center (`apps/control-center/`), Telegram Control Center (`integrations/telegram/`), Connected Device Runner (`integrations/connected-device/`), defensive security wrappers (`components/vulnclaw/`), installer tooling, and container configurations (`deploy/`) are released under the **MIT License** (see [`LICENSE`](./LICENSE)).

ALLINAGENT integrates, extends, or fetches at install/build time the following open-source components, pinned by immutable commit SHA or package version in [`components.lock.json`](./components.lock.json) and [`LICENSE-INVENTORY.json`](./LICENSE-INVENTORY.json). Each upstream project retains its original copyright and license terms.

---

## 1. Core Upstream Platform Components

### 1.1 Hermes Agent
- **Upstream Repository:** `https://github.com/NousResearch/hermes-agent.git`
- **Pinned Version / Commit:** `v0.23.3` (`eb49b8920a25ffa7bb2fadf548fe819221ca79d7`)
- **License:** `MIT`
- **Copyright:** `Copyright (c) 2025 Nous Research`
- **Integration Model:** Shallow-cloned at container build / setup time (`vendored_in_repo: false`, `deploy/docker/hermes.Dockerfile`) with declarative 1-line error-classification patch (`patches/hermes-agent/0001-error-classifier-integrator.patch`).

### 1.2 Paperclip AI
- **Upstream Repository:** `https://github.com/paperclipai/paperclip.git`
- **Pinned Package / Commit:** `paperclipai@2026.1117.0` (`c0f132898d2a2677312d8c72096187b27a3d9a38`)
- **License:** `MIT`
- **Copyright:** `Copyright (c) 2025 Paperclip AI`
- **Integration Model:** Installed from locked npm artifact (`vendored_in_repo: false`, `deploy/docker/paperclip.Dockerfile`) with declarative patch series (`patches/paperclip/patch-manifest.json`: `0001-hermes-adapter-query-file-cleanup.patch`, `0002-hermes-adapter-skills-reconcile.patch`, `0003-hermes-gateway-internal-hosts.patch`, `0004-db-low-memory-connection-pool.patch`).

### 1.3 VulnClaw (Defensive-Only Runtime)
- **Upstream Repository:** `https://github.com/Netw0rkNoob/VulnClaw.git`
- **Pinned Tag / Commit:** `v0.4.1` (`0b34878f84b089b21fcf85ecd445315f14df0672`)
- **License:** `MIT`
- **Copyright:** `Copyright (c) 2026 UncleC`
- **Integration Model:** Fetched on demand into an isolated runtime (`vendored_in_repo: false`, `deploy/docker/vulnclaw.Dockerfile`) governed strictly by [`config/vulnclaw.defensive.yaml`](./config/vulnclaw.defensive.yaml) with external MCP servers, `python_execute`, and offensive capabilities disabled.

### 1.4 Hermes3D
- **Upstream Repository:** `https://github.com/iamlukethedev/Hermes3D.git`
- **Base Version / Commit:** `v1.0.0` (`beb76292747b816ef317aa6f9a3992e0014f81d9`)
- **License:** `MIT`
- **Copyright:** `Copyright (c) 2026 Luke The Dev`
- **Integration Model:** Tracked under `./apps/hermes3d` (`vendored_in_repo: true`, `deploy/docker/office.Dockerfile`) and extended with first-party 11-agent 3D/2D Meeting Room orchestration, Enterprise Command Center Overlay, live Office Bridge WebSocket telemetry, and workspace folder management.
- **Bundled Public Domain (`CC0-1.0`) Assets:** `Kenney Furniture Kit` (`17` `.glb` models in `apps/hermes3d/public/office-assets/models/`) and `office_env_1k.hdr` (`apps/hermes3d/public/office-assets/env/office_env_1k.hdr`).
- **Removed / Excluded Non-OSI Vendor File (`0` Files in Repository):** Upstream `src/lib/avatars/vendor/multiavatar.js` (governed by custom non-OSI `MULTIAVATAR LICENSE v1.0`) has been **permanently removed and excluded** from ALLINAGENT and replaced by first-party MIT procedural SVG avatar generation in `apps/hermes3d/src/lib/avatars/multiavatar.ts`.

### Shared MIT Permission Notice (Applicable to Hermes Agent, Paperclip AI, VulnClaw, and Hermes3D)

```text
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 2. Direct Runtime Libraries & Base Container Images

All direct JavaScript/TypeScript, Python, and container runtime dependencies use OSI-approved permissive open-source licenses compatible with MIT distribution:

| Ecosystem | Package / Image | License (SPDX) | Role in ALLINAGENT |
| :--- | :--- | :--- | :--- |
| Container | `postgres:16-alpine` | `PostgreSQL` | Relational persistence for Paperclip control plane |
| Container | `node:22-alpine` | `MIT` | Node.js runtime for Paperclip, Office Bridge, and Hermes3D |
| Container | `python:3.12-slim` / `3.14` | `PSF-2.0` | Shared Python runtime for Hermes Gateway & defensive worker |
| npm | `next`, `react`, `react-dom` | `MIT` | Hermes3D web application framework & rendering |
| npm | `three`, `@react-three/fiber`, `@react-three/drei` | `MIT` | 3D Virtual Office WebGL scene & agent avatars |
| npm | `phaser` | `MIT` | 2D Pixel Office interactive canvas |
| npm | `ws` | `MIT` | WebSocket transport for Office Bridge & Hermes3D |
| npm | `@noble/ed25519`, `lucide-react`, `tailwindcss` | `MIT` / `ISC` | Cryptographic primitives, icons, and UI styling |
| PyPI | `openai` | `Apache-2.0` | OpenAI-compatible LLM client SDK |
| PyPI | `pydantic`, `pyyaml`, `rich`, `typer`, `prompt_toolkit` | `MIT` / `BSD-3-Clause` | Typed configuration validation and CLI tooling |
| PyPI | `httpx`, `jinja2`, `pypdf`, `reportlab`, `python-docx` | `BSD-3-Clause` / `MIT` | HTTP client and structured PDF/DOCX report generation |

---

## 3. Role-Specific Agent Skill Repositories (Pinned GitHub Provenance — 33 Skills)

Role-specific agent skill manifests ([`skills/manifests/skills.lock.json`](./skills/manifests/skills.lock.json) and [`skills/policies/skill-policy.json`](./skills/policies/skill-policy.json)) lock immutable 40-character Git commit SHAs and SHA-256 package digests across **10 upstream repositories (33 skill packages)**, partitioned strictly into **20 OSI-permissive redistributable skills** and **13 `FETCH_FROM_UPSTREAM_ONLY` skills**.

### 3.1 OSI-Permissive Redistributable Skill Sources (`MIT` / `Apache-2.0` — 20 Skills)

1. **Sentry Skills** (`https://github.com/getsentry/skills`, commit `a582c51ee29d0f35e6ac321340796f77d43da733`) — `Apache-2.0` (`1` skill: `skill-scanner` supply-chain security gate).
2. **Alireza Rezvani Claude Skills** (`https://github.com/alirezarezvani/claude-skills`, commit `5909a72e62b5fbb809935fb6a55b58bdbe175074`) — `MIT` (`11` skills: `ceo-advisor`, `c-level-skills`, `cto-review`, `ciso-advisor`, `compliance-os`, `pw`, `pw-coverage`, `pw-fix`, `pw-generate`, `pw-report`, `pw-review`).
3. **Anthropic Agent Skills (Permissive Subset)** (`https://github.com/anthropics/skills`, commit `e4bb5d960d87126ff3b3a8af1a104b7db67560ba`) — `Apache-2.0` (`1` skill: `frontend-design`).
4. **Anthropic Defending Code Reference Harness** (`https://github.com/anthropics/defending-code-reference-harness`, commit `d3bea6b5793b5f3d59a75ebe69a58efa88383145`) — `Apache-2.0` (`3` skills: `anthropic-patch`, `anthropic-triage`, `threat-model` — defensive methodology references only).
5. **Terraform Skill** (`https://github.com/antonbabenko/terraform-skill`, commit `f5a195992d84c8fb075b0176d666967cd07d2081`) — `Apache-2.0` (`1` skill: `terraform-skill`).
6. **Stacklok ToolHive Studio** (`https://github.com/stacklok/toolhive-studio`, commit `4d87c91d49b881ccc7dc64667c1dce5a84c535d6`) — `Apache-2.0` (`1` skill: `security-vuln-remediation`).
7. **CVE Triage** (`https://github.com/fedius01/cve-triage`, commit `3517c8fb10531103c403f09143966d62b2a0790f`) — `MIT` (`1` skill: `cve-triage`).
8. **SecondSky Claude Skills** (`https://github.com/secondsky/claude-skills`, commit `14966c3024f48eea0386eb970b230ea0f4bebd33`) — `MIT` (`1` skill: `secondsky-cybersecurity-ref`).

### 3.2 Non-Bundled `FETCH_FROM_UPSTREAM_ONLY` Skill Sources (13 Skills — Zero Repo / Image Redistribution)

Source files for the following **13 skill packages** are **strictly excluded** from the ALLINAGENT Git repository and GHCR container images (`.gitignore`, `.dockerignore`, and `scripts/audit-public-release.py` block `skills/upstream/`, `skills/staging/`, `skills/reviewed/`, and `skill-registry/`). Only metadata pointers and SHA-256 verification digests appear in lock manifests; operators who opt in fetch them directly from GitHub at install time via `skills/install_agent_skills.py` under the upstream authors' terms:

1. **Borghei Claude Skills** (`https://github.com/borghei/Claude-Skills`, commit `25bf86b89c6c1e63f433a5b65e8cfcb6cf0b7ad3`) — **`Commons Clause License Condition v1.0 + MIT`** (`MIT-Commons-Clause-1.0` / `LicenseRef-MIT-Commons-Clause-1.0`). Covers **`10` skills**: `api-design-reviewer`, `ci-cd-pipeline-builder`, `cto-advisor`, `focused-fix`, `security-audit`, `senior-architect`, `senior-backend`, `senior-devops`, `senior-qa`, `senior-security`. Because Commons Clause adds a commercial-sale restriction atop MIT, ALLINAGENT never vendors or redistributes these files.
2. **Vercel Labs Agent Skills** (`https://github.com/vercel-labs/agent-skills`, commit `5a37a6329fbad3666c3207392a6a7c0110e92efb`) — **`NOASSERTION`** (individual skill header metadata only; no standalone root `LICENSE` file in upstream repository). Covers **`1` skill**: `react-best-practices`, kept strictly `FETCH_FROM_UPSTREAM_ONLY`.
3. **Anthropic Agent Skills (OOXML Schema-Bundled Subset)** (`https://github.com/anthropics/skills`, commit `e4bb5d960d87126ff3b3a8af1a104b7db67560ba`) — `Apache-2.0` skill scripts bundling third-party OOXML `.xsd` schema definitions under separate non-OSI terms. Covers **`2` skills**: `docx` and `pdf`, kept strictly `FETCH_FROM_UPSTREAM_ONLY`.
   - **`--strict-oss` / `--offline` MIT Fallbacks:** When `skills/install_agent_skills.py` is invoked with `--strict-oss` or `--offline`, ALLINAGENT automatically provisions the **Nous Research MIT** `microsoft-office` and `pdf` skills bundled in `NousResearch/hermes-agent` (`MIT`) as 100% OSI-compliant drop-in fallbacks for `compliance_reporter`.
