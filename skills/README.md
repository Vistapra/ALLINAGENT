# ALLINAGENT Verified Skill Registry (`skills/`)

Immutable manifests, governance policies, and the two-stage security-gated installer for the **33 pinned GitHub skill packages** across **10 upstream repositories** serving ALLINAGENT's **11 corporate AI agents**.

## Directory Structure

- `manifests/skills.lock.json` — Sanitized lockfile pinning all 33 packages to 40-char commit SHAs, per-file SHA-256 checksums, `upstream_package_sha256`, `FETCH_FROM_UPSTREAM_ONLY` redistribution boundaries (13 packages), 11 `quarantined_excluded_files`, and `strict_oss_fallback` mappings (`docx` -> `productivity/microsoft-office`, `pdf` -> `productivity/pdf`).
- `manifests/skill-security-results.json` — Sanitized security scan baseline for Stage-1 gate verification.
- `policies/skill-policy.json` — Runtime enforcement policy (`locked: true, pinned: true`, blocks arbitrary remote installs, keeps `cve-triage` `EXPERIMENTAL` unless `--enable-experimental` is passed, and keeps `threat-model`, `secondsky-cybersecurity-ref`, `anthropic-triage`, and `anthropic-patch` `REFERENCE_ONLY`).
- `install_agent_skills.py` — Standalone Stage-1 + Stage-2 CLI invoked during `./allinagent setup` and CI validation.

## CLI Usage

```bash
# Offline manifest & policy integrity check (CI gate)
python3 skills/install_agent_skills.py --verify-manifest

# Preview 11-agent assignments without network calls
python3 skills/install_agent_skills.py --dry-run

# Full Stage-1 + Stage-2 installation across all 11 agent profiles
python3 skills/install_agent_skills.py --agent all

# Strict OSS / offline mode (uses permissive MIT bundled fallbacks)
python3 skills/install_agent_skills.py --agent all --strict-oss --offline
```
