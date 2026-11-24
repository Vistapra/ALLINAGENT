# ALLINAGENT License & Supply-Chain Compliance Directory

This directory documents how **ALLINAGENT** governs open-source licenses, upstream attributions, and supply-chain provenance across source releases and container images.

## Canonical License Artifacts

| File | Purpose |
| :--- | :--- |
| [`../LICENSE`](../LICENSE) | OSI-approved **MIT License** governing all first-party ALLINAGENT code, manifests, patches, and documentation. |
| [`../THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md) | Human-readable copyright notices and license attributions for all core upstream components, runtime libraries, excluded non-OSI artifacts, and pinned role-skill repositories. |
| [`../LICENSE-INVENTORY.json`](../LICENSE-INVENTORY.json) | Machine-readable SPDX license classification, redistribution policies (`20` OSI-permissive + `13` `FETCH_FROM_UPSTREAM_ONLY`), and compliance matrix. |
| [`../components.lock.json`](../components.lock.json) | Immutable 40-character Git commit SHAs, patch manifests, Dockerfiles, and exact package versions for `hermes-agent`, `paperclip`, `vulnclaw`, and `hermes3d`. |
| [`../skills/manifests/skills.lock.json`](../skills/manifests/skills.lock.json) | Canonical SHA-pinned lockfile for all `33` role-specific GitHub skill packages (`20` OSI-permissive + `13` `FETCH_FROM_UPSTREAM_ONLY`). |
| [`../scripts/generate-sbom.py`](../scripts/generate-sbom.py) | Generates and validates a CycloneDX 1.5 Software Bill of Materials from all repository manifests. |
| [`../scripts/audit-public-release.py`](../scripts/audit-public-release.py) | Automated fail-closed pre-release gate verifying zero secret leaks, zero private host/owner tokens (built-in SHA-256 denylist), zero runtime state, and zero restricted-license bundling. |

## Redistribution Rules Enforced in CI

1. **Core Upstream Projects (`MIT`):**
   - `hermes-agent`, `paperclip`, `vulnclaw`, and `hermes3d` are all licensed under **MIT**.
   - Only `hermes3d` is tracked as an extended source subtree (`./apps/hermes3d`), preserving its upstream `LICENSE` notice (`Copyright (c) 2026 Luke The Dev`) and `CC0-1.0` 3D/HDR assets while permanently excluding `src/lib/avatars/vendor/multiavatar.js` (`MULTIAVATAR LICENSE v1.0`, `0` files in repo — replaced by first-party MIT `src/lib/avatars/multiavatar.ts`).
   - `hermes-agent`, `paperclip`, and `vulnclaw` are fetched at exact pinned commits/versions during build/setup and retain their upstream `LICENSE` files inside their respective runtime directories.

2. **33-Skill Classification (`20` Permissive vs. `13` `FETCH_FROM_UPSTREAM_ONLY`):**
   - **`20` OSI-Permissive Redistributable Skills (`MIT` / `Apache-2.0`):** `skill-scanner` (`1`), `alirezarezvani/claude-skills` (`11`), `anthropics/skills` `frontend-design` (`1`), `anthropics/defending-code-reference-harness` (`3`), `terraform-skill` (`1`), `security-vuln-remediation` (`1`), `cve-triage` (`1`), and `secondsky-cybersecurity-ref` (`1`).
   - **`13` `FETCH_FROM_UPSTREAM_ONLY` Skills (`0` Files in Git or GHCR Images):**
     - `10` `borghei/Claude-Skills` packages under `MIT-Commons-Clause-1.0`
     - `1` `vercel-labs/agent-skills` package (`react-best-practices`) under `NOASSERTION`
     - `2` `anthropics/skills` packages (`docx` & `pdf`) bundling third-party OOXML `.xsd` schemas, with Nous Research MIT `microsoft-office` & `pdf` (`NousResearch/hermes-agent`) documented and wired as `--strict-oss` / `--offline` fallbacks.
   - `.gitignore`, `.dockerignore`, and `scripts/audit-public-release.py` block `skills/upstream/`, `skills/staging/`, `skills/reviewed/`, and `skill-registry/` from entering tracked files or image build contexts.

3. **Verification Commands:**
   ```bash
   python3 scripts/generate-sbom.py --validate
   python3 scripts/audit-public-release.py --self-test
   python3 scripts/audit-public-release.py --strict-clean-tree
   ```
