#!/usr/bin/env python3
"""Unit tests for ALLINAGENT supply-chain locks, license inventory, 33-skill lockfile, and 11 role manifests.

Cross-platform (Linux + Windows), hermetic, and standard-library only.
"""
from __future__ import annotations

import json
import os
import re
import sys
import unittest
from pathlib import Path
from typing import Any

os.environ.setdefault("ALLINAGENT_SKIP_DOTENV", "1")

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_CENTER_PKG_ROOT = REPO_ROOT / "apps" / "control-center"
if str(CONTROL_CENTER_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_CENTER_PKG_ROOT))

HEX_40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
UUID_V4_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)

EXPECTED_BORGHEI_PACKAGES = frozenset({
    "api-design-reviewer",
    "ci-cd-pipeline-builder",
    "cto-advisor",
    "focused-fix",
    "security-audit",
    "senior-architect",
    "senior-backend",
    "senior-devops",
    "senior-qa",
    "senior-security",
})

EXPECTED_FETCH_ONLY_PACKAGES = EXPECTED_BORGHEI_PACKAGES | frozenset({
    "react-best-practices",
    "docx",
    "pdf",
})

EXPECTED_11_ROLES: dict[str, tuple[str, ...]] = {
    "ceo_agent": ("file", "terminal", "skills"),
    "cto_agent": ("file", "terminal", "skills"),
    "backend_developer": ("file", "terminal", "skills"),
    "frontend_developer": ("file", "terminal", "skills"),
    "devops_engineer": ("file", "terminal", "skills"),
    "qa_engineer": ("file", "terminal", "skills"),
    "security_lead": ("file", "skills"),
    "security_reviewer": ("file", "skills"),
    "findings_analyst": ("file", "skills"),
    "remediation_reviewer": ("file", "skills"),
    "compliance_reporter": ("file", "terminal", "skills"),
}

SOC_READONLY_ROLES = frozenset({
    "security_lead",
    "security_reviewer",
    "findings_analyst",
    "remediation_reviewer",
})


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    assert isinstance(data, dict), f"Expected JSON object in {path}"
    return data


class TestComponentsLock(unittest.TestCase):
    """Verifies `components.lock.json` upstream commit pins and non-vendoring policies."""

    def setUp(self) -> None:
        self.lock_path = REPO_ROOT / "components.lock.json"
        self.assertTrue(self.lock_path.is_file(), f"Missing {self.lock_path}")
        self.doc = _load_json(self.lock_path)

    def test_policy_invariants(self) -> None:
        self.assertEqual(self.doc.get("product"), "ALLINAGENT")
        policy = self.doc.get("policy") or {}
        self.assertIs(policy.get("allow_floating_git_refs"), False)
        self.assertIs(policy.get("require_40_char_commit_sha"), True)
        self.assertIs(policy.get("vendor_monolithic_upstreams_in_git"), False)
        self.assertIs(policy.get("bundle_noncommercial_or_unlicensed_skills"), False)

    def test_all_core_components_have_40_char_commits_and_mit_license(self) -> None:
        components = self.doc.get("components") or {}
        expected_ids = {"hermes-agent", "paperclip", "vulnclaw", "hermes3d"}
        self.assertEqual(set(components.keys()), expected_ids)

        for comp_id, info in components.items():
            commit = str(info.get("commit") or "")
            self.assertRegex(
                commit,
                HEX_40_RE,
                f"Component '{comp_id}' must have an exact 40-char lowercase hex commit SHA",
            )
            self.assertEqual(info.get("license"), "MIT", f"Component '{comp_id}' must declare MIT license")
            repo_url = str(info.get("upstream_repo") or "")
            self.assertTrue(
                repo_url.startswith("https://github.com/"),
                f"Component '{comp_id}' must reference an official https://github.com/ repository",
            )
            if comp_id in {"hermes-agent", "paperclip", "vulnclaw"}:
                self.assertIs(
                    info.get("vendored_in_repo"),
                    False,
                    f"Monolithic upstream '{comp_id}' must not be vendored in git",
                )

    def test_hermes_patch_file_exists(self) -> None:
        hermes_patches = (self.doc["components"]["hermes-agent"].get("patches") or [])
        self.assertGreaterEqual(len(hermes_patches), 1)
        first_patch = REPO_ROOT / hermes_patches[0]
        self.assertTrue(first_patch.is_file(), f"Missing declared patch file: {first_patch}")


class TestLicenseInventory(unittest.TestCase):
    """Verifies `LICENSE-INVENTORY.json` SPDX compliance and upstream commit alignment."""

    def setUp(self) -> None:
        self.inv_path = REPO_ROOT / "LICENSE-INVENTORY.json"
        self.assertTrue(self.inv_path.is_file(), f"Missing {self.inv_path}")
        self.inv = _load_json(self.inv_path)
        self.comp_lock = _load_json(REPO_ROOT / "components.lock.json")

    def test_compliance_policy_and_zero_violations(self) -> None:
        self.assertEqual(self.inv.get("product"), "ALLINAGENT")
        self.assertEqual(self.inv.get("root_license_spdx"), "MIT")

        policy = self.inv.get("compliance_policy") or {}
        self.assertIs(policy.get("allow_strong_copyleft_in_distributed_artifacts"), False)
        self.assertIs(policy.get("allow_commons_clause_bundling_in_git_or_ghcr"), False)
        self.assertIs(policy.get("allow_unlicensed_repo_bundling_in_git_or_ghcr"), False)
        self.assertIs(policy.get("require_40_char_git_commit_pins"), True)
        self.assertIn("AGPL-3.0-only", policy.get("blocked_spdx_families") or [])
        self.assertIn("GPL-3.0-only", policy.get("blocked_spdx_families") or [])

        counts = self.inv.get("summary_counts") or {}
        self.assertEqual(counts.get("core_upstreams_total"), 4)
        self.assertEqual(counts.get("skill_repos_total"), 10)
        self.assertEqual(counts.get("skill_packages_total"), 33)
        self.assertEqual(counts.get("copyleft_violations"), 0)
        self.assertEqual(counts.get("restricted_files_bundled"), 0)

    def test_core_upstreams_match_components_lock(self) -> None:
        lock_comps = self.comp_lock["components"]
        inv_comps = {entry["id"]: entry for entry in (self.inv.get("core_upstream_components") or [])}
        self.assertEqual(set(inv_comps.keys()), set(lock_comps.keys()))

        for cid, linfo in lock_comps.items():
            iinfo = inv_comps[cid]
            inv_commit = str(iinfo.get("commit") or iinfo.get("base_commit") or "")
            self.assertEqual(
                inv_commit,
                linfo["commit"],
                f"Commit mismatch between LICENSE-INVENTORY.json and components.lock.json for '{cid}'",
            )
            self.assertEqual(iinfo.get("license_spdx"), "MIT")

    def test_skill_repositories_pinned_and_unbundled(self) -> None:
        repos = self.inv.get("agent_skill_repositories") or []
        self.assertEqual(len(repos), 10)
        total_pkgs = 0
        by_repo: dict[str, dict[str, Any]] = {}
        for repo_entry in repos:
            repo_name = str(repo_entry.get("repo") or "")
            by_repo[repo_name] = repo_entry
            self.assertRegex(str(repo_entry.get("commit") or ""), HEX_40_RE)
            self.assertIs(repo_entry.get("bundled_in_git"), False)
            pkgs = repo_entry.get("packages") or []
            self.assertEqual(len(pkgs), repo_entry.get("packages_count"))
            total_pkgs += len(pkgs)

        self.assertEqual(total_pkgs, 33)
        self.assertEqual(by_repo["borghei/Claude-Skills"].get("redistribution_policy"), "FETCH_FROM_UPSTREAM_ONLY")
        self.assertEqual(set(by_repo["borghei/Claude-Skills"]["packages"]), EXPECTED_BORGHEI_PACKAGES)
        self.assertEqual(by_repo["vercel-labs/agent-skills"].get("redistribution_policy"), "FETCH_FROM_UPSTREAM_ONLY")


class TestSkillsLockAndPolicy(unittest.TestCase):
    """Verifies `skills/manifests/skills.lock.json` across all 33 packages and 11 roles."""

    def setUp(self) -> None:
        self.skills_lock_path = REPO_ROOT / "skills" / "manifests" / "skills.lock.json"
        self.policy_path = REPO_ROOT / "skills" / "policies" / "skill-policy.json"
        self.sec_results_path = REPO_ROOT / "skills" / "manifests" / "skill-security-results.json"

        self.assertTrue(self.skills_lock_path.is_file(), f"Missing {self.skills_lock_path}")
        self.assertTrue(self.policy_path.is_file(), f"Missing {self.policy_path}")
        self.assertTrue(self.sec_results_path.is_file(), f"Missing {self.sec_results_path}")

        self.lock = _load_json(self.skills_lock_path)
        self.policy = _load_json(self.policy_path)
        self.sec_results = _load_json(self.sec_results_path)

    def test_all_33_packages_have_40_char_shas_and_upstream_package_sha256(self) -> None:
        packages = self.lock.get("packages") or {}
        self.assertEqual(self.lock.get("packages_count"), 33)
        self.assertEqual(len(packages), 33)
        self.assertEqual(self.lock.get("security_gate_skill"), "skill-scanner")
        self.assertIn("skill-scanner", packages)

        for pkg_id, meta in packages.items():
            self.assertEqual(meta.get("pkg_id"), pkg_id)
            commit_sha = str(meta.get("pinned_commit_sha") or "")
            self.assertRegex(
                commit_sha,
                HEX_40_RE,
                f"Skill package '{pkg_id}' missing 40-char hex pinned_commit_sha",
            )
            pkg_sha256 = str(meta.get("upstream_package_sha256") or "")
            self.assertRegex(
                pkg_sha256,
                HEX_64_RE,
                f"Skill package '{pkg_id}' missing 64-char hex upstream_package_sha256",
            )

            files = meta.get("files") or []
            self.assertGreater(len(files), 0, f"Skill package '{pkg_id}' has empty files list")
            self.assertIn("SKILL.md", files, f"Skill package '{pkg_id}' must include SKILL.md")

            file_sha256s = meta.get("file_sha256s") or {}
            for rel_file in files:
                self.assertIn(
                    rel_file,
                    file_sha256s,
                    f"Skill package '{pkg_id}' missing file_sha256s digest for '{rel_file}'",
                )
                self.assertRegex(
                    str(file_sha256s[rel_file]),
                    HEX_64_RE,
                    f"Invalid SHA-256 digest for '{pkg_id}/{rel_file}'",
                )

    def test_zero_quarantined_files_in_package_files(self) -> None:
        packages = self.lock["packages"]
        quarantined_entries = self.lock.get("quarantined_excluded_files") or []
        self.assertEqual(len(quarantined_entries), 11)
        self.assertEqual(self.lock.get("quarantined_excluded_files_count"), 11)

        policy_quarantined = self.policy.get("quarantined_excluded_files") or []
        self.assertEqual(
            {(q["pkg_id"], q["file"]) for q in quarantined_entries},
            {(q["pkg_id"], q["file"]) for q in policy_quarantined},
        )

        # Verify all 10 secondsky offensive files + threat-model bootstrap.md areabsent from `files` & `file_sha256s`
        for entry in quarantined_entries:
            pkg_id = entry["pkg_id"]
            rel_file = entry["file"]
            self.assertIn(pkg_id, packages)
            pkg_files = set(packages[pkg_id].get("files") or [])
            pkg_hashes = set((packages[pkg_id].get("file_sha256s") or {}).keys())
            self.assertNotIn(
                rel_file,
                pkg_files,
                f"Quarantined file '{rel_file}' MUST NOT appear in '{pkg_id}' files list",
            )
            self.assertNotIn(
                rel_file,
                pkg_hashes,
                f"Quarantined file '{rel_file}' MUST NOT appear in '{pkg_id}' file_sha256s",
            )

    def test_fetch_from_upstream_only_on_borghei_react_docx_pdf(self) -> None:
        packages = self.lock["packages"]

        borghei_found = {
            pkg_id
            for pkg_id, meta in packages.items()
            if meta.get("repo_owner_name") == "borghei/Claude-Skills"
        }
        self.assertEqual(borghei_found, EXPECTED_BORGHEI_PACKAGES)
        self.assertEqual(len(borghei_found), 10)

        actual_fetch_only = {
            pkg_id
            for pkg_id, meta in packages.items()
            if meta.get("redistribution_policy") == "FETCH_FROM_UPSTREAM_ONLY"
        }
        self.assertTrue(
            EXPECTED_FETCH_ONLY_PACKAGES.issubset(actual_fetch_only),
            f"Missing FETCH_FROM_UPSTREAM_ONLY on: {EXPECTED_FETCH_ONLY_PACKAGES - actual_fetch_only}",
        )
        self.assertEqual(actual_fetch_only, EXPECTED_FETCH_ONLY_PACKAGES)

        policy_fetch_only = set(
            ((self.policy.get("classifications") or {}).get("fetch_from_upstream_only") or {}).get("packages") or []
        )
        self.assertEqual(policy_fetch_only, EXPECTED_FETCH_ONLY_PACKAGES)

        # Verify strict_oss_fallback exists on docx and pdf
        for doc_pkg in ("docx", "pdf"):
            fb = packages[doc_pkg].get("strict_oss_fallback") or {}
            self.assertEqual(fb.get("license_spdx"), "MIT")
            self.assertIn("--strict-oss", fb.get("modes") or [])
            self.assertIn("--offline", fb.get("modes") or [])

        # Verify zero upstream skill directories are bundled in repository skills/
        for forbidden_dir in ("upstream", "staging", "reviewed", "quarantine", "agents"):
            cand = REPO_ROOT / "skills" / forbidden_dir
            self.assertFalse(cand.exists(), f"Unbundled runtime directory must not exist in repo: {cand}")

    def test_control_center_manifest_verifier_agrees(self) -> None:
        try:
            from control_center.agent_skills_manager import verify_manifest
        except ImportError:
            return
        res = verify_manifest(self.lock, self.policy)
        self.assertTrue(res.get("ok"), f"control_center.agent_skills_manager.verify_manifest failed: {res}")


class TestRoleManifests(unittest.TestCase):
    """Verifies all 11 `agents/*/role-manifest.json` files and least-privilege toolsets."""

    def setUp(self) -> None:
        agents_root = REPO_ROOT / "agents"
        self.assertTrue(agents_root.is_dir(), f"Missing {agents_root}")
        self.manifest_paths = sorted(
            p
            for p in agents_root.glob("*/role-manifest.json")
            if p.parent.name != "hermes-extensions"
        )

    def test_all_11_role_manifests_present_and_sanitized(self) -> None:
        self.assertEqual(
            len(self.manifest_paths),
            11,
            f"Expected exactly 11 agents/*/role-manifest.json files, found {len(self.manifest_paths)}",
        )

        by_slug: dict[str, dict[str, Any]] = {}
        seen_profiles: set[str] = set()
        seen_handles: set[str] = set()

        for mpath in self.manifest_paths:
            raw_txt = mpath.read_text(encoding="utf-8")
            self.assertIsNone(
                UUID_V4_RE.search(raw_txt),
                f"Hardcoded UUID detected in {mpath}",
            )
            data = json.loads(raw_txt)
            slug = str(data.get("role_slug") or "")
            self.assertIn(slug, EXPECTED_11_ROLES, f"Unexpected role_slug '{slug}' in {mpath}")
            by_slug[slug] = data

            prof = str(data.get("profile_id") or "")
            self.assertTrue(prof.startswith("pc"), f"Profile ID '{prof}' must start with 'pc'")
            self.assertNotIn(prof, seen_profiles, f"Duplicate profile_id '{prof}'")
            seen_profiles.add(prof)

            handle = str(data.get("handle") or "")
            self.assertTrue(handle.startswith("@"), f"Handle '{handle}' must start with '@'")
            self.assertNotIn(handle, seen_handles, f"Duplicate handle '{handle}'")
            seen_handles.add(handle)

        self.assertEqual(set(by_slug.keys()), set(EXPECTED_11_ROLES.keys()))

    def test_compliance_has_terminal_and_soc_reviewers_are_readonly(self) -> None:
        by_slug = {
            _load_json(p)["role_slug"]: _load_json(p)
            for p in self.manifest_paths
        }

        # Verify compliance_reporter (`agents/compliance/role-manifest.json`)
        comp = by_slug["compliance_reporter"]
        comp_tools = tuple(comp.get("toolsets") or [])
        self.assertEqual(comp_tools, ("file", "terminal", "skills"))
        self.assertEqual(tuple(comp.get("allowed_toolsets") or []), ("file", "terminal", "skills"))
        self.assertEqual(comp.get("toolsets_csv"), "file,terminal,skills")
        comp_skills = comp.get("skills") or {}
        self.assertEqual(comp_skills.get("primary"), ["compliance-os"])
        self.assertEqual(sorted(comp_skills.get("specialist") or []), ["docx", "pdf"])
        self.assertIn("productivity/pdf", comp_skills.get("disabled_bundled") or [])

        # Verify all 4 SOC reviewers have read-only `file,skills` (zero terminal access)
        for soc_slug in SOC_READONLY_ROLES:
            soc = by_slug[soc_slug]
            soc_tools = tuple(soc.get("toolsets") or [])
            self.assertEqual(
                soc_tools,
                ("file", "skills"),
                f"SOC role '{soc_slug}' must be strictly read-only ('file', 'skills')",
            )
            self.assertNotIn(
                "terminal",
                soc_tools,
                f"SOC role '{soc_slug}' must NEVER include 'terminal' toolset",
            )
            self.assertEqual(soc.get("toolsets_csv"), "file,skills")

        # Verify all 11 roles match canonical toolset matrix and skills.lock.json role_assignments
        skills_lock = _load_json(REPO_ROOT / "skills" / "manifests" / "skills.lock.json")
        lock_roles = {r["role_slug"]: r for r in (skills_lock.get("role_assignments") or [])}
        self.assertEqual(set(lock_roles.keys()), set(EXPECTED_11_ROLES.keys()))

        for slug, expected_tuple in EXPECTED_11_ROLES.items():
            manifest = by_slug[slug]
            self.assertEqual(tuple(manifest.get("toolsets") or []), expected_tuple)
            self.assertEqual(lock_roles[slug].get("toolsets"), ",".join(expected_tuple))


if __name__ == "__main__":
    unittest.main(verbosity=2)
