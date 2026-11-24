# PHASE 21 — GitHub Actions Build, Test, SBOM & GHCR Release CI/CD

- **Phase ID:** `PHASE-21` (with `PHASE-22` GHCR Release Pipeline)
- **Status:** `PASS`
- **Scope:** `.github/workflows/ci.yml`, `.github/workflows/ghcr-release.yml`

---

## 1. Supply-Chain Security & Action Pinning

Both workflows enforce `permissions: contents: read` at the workflow root and pin **100% of GitHub Actions** (`22 / 22` `uses:` steps) to verified 40-character upstream commit SHAs with explicit version comments:

| Action | Immutable Commit SHA | Tag Comment |
| :--- | :--- | :--- |
| `actions/checkout` | `11bd71901bbe5b1630ceea73d27597364c9af683` | `# v4.2.2` |
| `actions/setup-python` | `42375524e23c412d93fb67b49958b491fce71c38` | `# v5.4.0` |
| `actions/setup-node` | `1d0ff469b7ec7b3cb9d8673fde0c81c44821de2a` | `# v4.2.0` |
| `actions/upload-artifact` | `65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08` | `# v4.6.0` |
| `actions/download-artifact` | `fa0a91b85d4f404e444e00e005971372dc801d16` | `# v4.1.8` |
| `docker/setup-buildx-action` | `f7ce87c1d6bead3e36075b2ce75da1f6cc28aaca` | `# v3.9.0` |
| `docker/login-action` | `9780b0c442fbb1117ed29e0efdff1e18412f7567` | `# v3.3.0` |
| `docker/build-push-action` | `ca877d9245402d1537745e0e356eab47c3520991` | `# v6.13.0` |
| `actions/attest-build-provenance` | `520d128f165991a6c774bcb264f323e3d70747f4` | `# v2.2.0` |

---

## 2. Continuous Integration Pipeline (`.github/workflows/ci.yml`)

1. **`hygiene-and-security-gate`:**
   - Validates `compose.yaml`, `compose.production.yaml`, and `.github/workflows/*.yml` via `yaml.safe_load`.
   - Executes `scripts/audit-public-release.py` and blocks any tracked `.env*` (except `.env.example`), `auth.json`, or `*.local.*` files.
2. **`python-and-skills-gate`:**
   - Runs `py_compile` / `compileall` across `scripts/`, `apps/`, `components/`, and `tests/`.
   - Verifies `./allinagent setup --yes --config-only` enforces `0600` file permissions on `.env`.
   - Runs Sentry `skill-scanner` (`cisco-ai-defense-skill-scanner`), skill manifest SHA verification, and Python unit tests.
3. **`node-and-typescript-tests`:**
   - Runs `apps/office-bridge` unit tests (`npm test`) and `apps/hermes3d` `tsc --noEmit`, `vitest run`, and `next build` on Node.js 24.
4. **`sbom-generation`:**
   - Generates a CycloneDX 1.5 JSON SBOM (`allinagent-repo.cdx.json`) via Anchore `syft` and uploads it as a build artifact.
5. **`docker-smoke-test`:**
   - Builds all 5 production Dockerfiles on `ubuntu-latest`, launches the full production stack (`./allinagent --production up`), verifies HTTP 200 across `:8200/api/health`, `:8201/api/health`, and `:8202/health`, asserts `postgres`/`hermes`/`vulnclaw` expose **zero** host ports (`docker port`), and tears down cleanly.

---

## 3. GHCR Release & Provenance Pipeline (`.github/workflows/ghcr-release.yml`)

- Triggered on `v*` tags or `workflow_dispatch`.
- Builds and pushes `ghcr.io/<owner>/allinagent-{hermes,paperclip,office-bridge,office,vulnclaw}:<version>` (`linux/amd64`) using `GITHUB_TOKEN` (`packages: write`, `contents: write`, `attestations: write`, `id-token: write`).
- Generates SLSA build provenance attestations (`actions/attest-build-provenance`), aggregates all 5 immutable `@sha256:...` digests into `release-manifest.json`, generates CycloneDX SBOM + `SHA256SUMS.txt`, and publishes all assets to the GitHub Release.
