# PHASE 22 & 23 — Public GitHub Repository, GHCR Release & Provenance Evidence

- **Phase ID:** `PHASE-22` & `PHASE-23`
- **Status:** `PASS`
- **Repository:** `https://github.com/Vistapra/ALLINAGENT` (`visibility: public`)
- **Release Tag:** `v1.0.0-rc.8` (`https://github.com/Vistapra/ALLINAGENT/releases/tag/v1.0.0-rc.8`)
- **Release Commit (`v1.0.0-rc.8`):** `7535c40f6d5e8212547897c924f315ff149cbe4f`

---

## 1. Public GitHub Repository & Clean-Tree Verification (`PHASE-22`)

- **Repository URL:** `https://github.com/Vistapra/ALLINAGENT`
- **Clone URL:** `https://github.com/Vistapra/ALLINAGENT.git` (clean HTTPS remote, zero embedded credentials)
- **Commit Author Identity:** `Vistapra <Vistapra@users.noreply.github.com>` (local repository scope)
- **Repository Metadata:** `private: false`, `visibility: "public"`, `has_issues: true`, `has_projects: true`, `has_wiki: false`
- **Configured Topics (8):**
  `ai-agents`, `multi-agent-systems`, `hermes-agent`, `autonomous-company`, `telegram-bot`, `3d-office`, `docker`, `security-automation`
- **Strict Clean-Tree Audit (`scripts/audit-public-release.py --strict-clean-tree`):**
  - `ok: true`
  - `findings_count: 0`
  - Zero `__pycache__`, `node_modules`, `.next`, `.env` (other than `.env.example`), `*.db`, `*.sqlite*`, or binary secrets tracked.

---

## 2. GitHub Actions CI & GHCR Release Verification (`PHASE-23`)

Both workflows completed `100%` green (`conclusion: "success"`) on release commit `7535c40f6d5e8212547897c924f315ff149cbe4f` and tag `v1.0.0-rc.8`:

### 2.1 `ALLINAGENT CI` (`ci.yml`)
- **Workflow Run:** [`45413826116`](https://github.com/Vistapra/ALLINAGENT/actions/runs/45413826116) — **`success`**

| Job | Job ID | Status / Conclusion |
| :--- | :--- | :--- |
| `Python Syntax, Skill Manifest & CI Regression Suite` | [`138514511324`](https://github.com/Vistapra/ALLINAGENT/actions/runs/45413826116/job/138514511324) | `completed` / `success` |
| `Node 24 & TypeScript Verification (office-bridge, hermes3d)` | [`138514511862`](https://github.com/Vistapra/ALLINAGENT/actions/runs/45413826116/job/138514511862) | `completed` / `success` |
| `Secret Hygiene, Manifest & Deterministic CycloneDX SBOM Gate` | [`138514512238`](https://github.com/Vistapra/ALLINAGENT/actions/runs/45413826116/job/138514512238) | `completed` / `success` |
| `Multi-Stage Docker Build & Live Container Smoke Gate` | [`138515925686`](https://github.com/Vistapra/ALLINAGENT/actions/runs/45413826116/job/138515925686) | `completed` / `success` |

### 2.2 `GHCR Release & Provenance` (`ghcr-release.yml`)
- **Workflow Run:** [`45413834658`](https://github.com/Vistapra/ALLINAGENT/actions/runs/45413834658) — **`success`**

| Job | Job ID | Status / Conclusion |
| :--- | :--- | :--- |
| `Release Hygiene, SBOM & Version Metadata` | [`138514539403`](https://github.com/Vistapra/ALLINAGENT/actions/runs/45413834658/job/138514539403) | `completed` / `success` |
| `Build & Push allinagent-paperclip` (+ SBOM & SLSA Provenance) | [`138514684387`](https://github.com/Vistapra/ALLINAGENT/actions/runs/45413834658/job/138514684387) | `completed` / `success` |
| `Build & Push allinagent-office-bridge` (+ SBOM & SLSA Provenance) | [`138514684393`](https://github.com/Vistapra/ALLINAGENT/actions/runs/45413834658/job/138514684393) | `completed` / `success` |
| `Build & Push allinagent-office` (+ SBOM & SLSA Provenance) | [`138514684395`](https://github.com/Vistapra/ALLINAGENT/actions/runs/45413834658/job/138514684395) | `completed` / `success` |
| `Build & Push allinagent-vulnclaw` (+ SBOM & SLSA Provenance) | [`138514684492`](https://github.com/Vistapra/ALLINAGENT/actions/runs/45413834658/job/138514684492) | `completed` / `success` |
| `Build & Push allinagent-hermes` (+ SBOM & SLSA Provenance) | [`138514684969`](https://github.com/Vistapra/ALLINAGENT/actions/runs/45413834658/job/138514684969) | `completed` / `success` |
| `Container Smoke Verification Against Published GHCR Images` | [`138519419292`](https://github.com/Vistapra/ALLINAGENT/actions/runs/45413834658/job/138519419292) | `completed` / `success` |
| `Assemble release-manifest.json, sbom.cdx.json, SHA256SUMS.txt & GitHub Release` | [`138520304711`](https://github.com/Vistapra/ALLINAGENT/actions/runs/45413834658/job/138520304711) | `completed` / `success` |

---

## 3. Immutable GHCR Container Image Digests (`linux/amd64`)

All 5 production images were built, attested via `actions/attest-build-provenance`, smoke-tested together in a 6-container stack (`postgres` + 5 GHCR images within the `1,536 MiB` production budget), and verified for **unauthenticated/anonymous GHCR pull** (`GET https://ghcr.io/token` + `GET https://ghcr.io/v2/vistapra/allinagent-<service>/manifests/1.0.0-rc.8` -> `HTTP 200 OK`, `visibility: public`):

| Service | GHCR Repository | Tag | Immutable Digest (`@sha256:...`) | Anonymous Pull |
| :--- | :--- | :--- | :--- | :--- |
| `hermes` | `ghcr.io/vistapra/allinagent-hermes` | `1.0.0-rc.8` | `sha256:f0b6f55e3bb0f3549c0943eeaabe351299ec7df68ec122ec7d08fddfbf10c3c0` | `HTTP 200` (`public`) |
| `paperclip` | `ghcr.io/vistapra/allinagent-paperclip` | `1.0.0-rc.8` | `sha256:ab9856ff5cb1d51cf5562081faa1e1aff8a308bd6bc69897249a1459a06bf0c7` | `HTTP 200` (`public`) |
| `office-bridge` | `ghcr.io/vistapra/allinagent-office-bridge` | `1.0.0-rc.8` | `sha256:e171fbfa4f9a3ea73c4832c63f44a01680090d42ec1b1ae38ab8cdb0e28a0ef7` | `HTTP 200` (`public`) |
| `office` | `ghcr.io/vistapra/allinagent-office` | `1.0.0-rc.8` | `sha256:2d8cc1bd08e3341da88ecaf69a0bfe7af4a2ae5b91d6b2d3fdfbcfa517605677` | `HTTP 200` (`public`) |
| `vulnclaw` | `ghcr.io/vistapra/allinagent-vulnclaw` | `1.0.0-rc.8` | `sha256:408589a84b05c6dc9261c43eb16523598ffe5d9f0a64660c32aad7426c0d9ac6` | `HTTP 200` (`public`) |

### Full Immutable Image References
- `ghcr.io/vistapra/allinagent-hermes:1.0.0-rc.8@sha256:f0b6f55e3bb0f3549c0943eeaabe351299ec7df68ec122ec7d08fddfbf10c3c0`
- `ghcr.io/vistapra/allinagent-paperclip:1.0.0-rc.8@sha256:ab9856ff5cb1d51cf5562081faa1e1aff8a308bd6bc69897249a1459a06bf0c7`
- `ghcr.io/vistapra/allinagent-office-bridge:1.0.0-rc.8@sha256:e171fbfa4f9a3ea73c4832c63f44a01680090d42ec1b1ae38ab8cdb0e28a0ef7`
- `ghcr.io/vistapra/allinagent-office:1.0.0-rc.8@sha256:2d8cc1bd08e3341da88ecaf69a0bfe7af4a2ae5b91d6b2d3fdfbcfa517605677`
- `ghcr.io/vistapra/allinagent-vulnclaw:1.0.0-rc.8@sha256:408589a84b05c6dc9261c43eb16523598ffe5d9f0a64660c32aad7426c0d9ac6`

---

## 4. Published GitHub Release Assets & `SHA256SUMS.txt`

Release URL: `https://github.com/Vistapra/ALLINAGENT/releases/tag/v1.0.0-rc.8` (`published_at: 2026-11-24T14:33:54Z`)

| Asset | Size (Bytes) | SHA-256 Checksum |
| :--- | ---: | :--- |
| `release-manifest.json` | `2,198` | `93c36eddd4ef6e58d1f04f112fd538f993fa0d1bb033cd30b2067997b1c7e6bb` |
| `sbom.cdx.json` | `92,455` | `e45096458186c2b44ccfe5523447ee7e9bb0a8ac81777c5e390f6e4358505a3a` |
| `compose.yaml` | `13,215` | `4c36f5c002316501a7b8ba445b2a8694d6284e4b6fc8b61042e8fcd44fb9c107` |
| `compose.production.yaml` | `5,238` | `47010391cdbbb9eecdd8d2890cafdf179c8ecc96b8a6536664e8838722267ecf` |
| `SHA256SUMS.txt` | `337` | *(detached checksum manifest covering the 4 assets above)* |

### Pinned Upstream Supply-Chain Manifest (`release-manifest.json`)
- `hermes_agent`: `eb49b8920a25ffa7bb2fadf548fe819221ca79d7`
- `paperclipai`: `2026.1117.0`
- `vulnclaw`: `0b34878f84b089b21fcf85ecd445315f14df0672`
