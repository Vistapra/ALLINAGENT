#!/usr/bin/env python3
"""Two-Stage Security-Gated Role Skill Installer CLI for ALLINAGENT (`./allinagent setup`).

Stage 1:
- Fetches `getsentry/skills` `skill-scanner` @ `a582c51ee29d0f35e6ac321340796f77d43da733` first
  and verifies its cryptographic SHA-256 against `skills/manifests/skills.lock.json`.
- Downloads pinned packages, excludes all 11 quarantined files, verifies per-file & package
  SHA-256 digests, runs `scan_skill.py` + recursive Python AST dangerous-pattern scan, and
  promotes passing packages to `<registry>/reviewed/` (quarantining any tampered/failing package).

Stage 2:
- Ensures `UPSTREAM_LICENSE` in every installed skill folder.
- Normalizes `SKILL.md` YAML frontmatter (ISO date quoting, 5 mismatched `name:` rewrites,
  `c-level-skills` `disable-model-invocation` stripping, and Apache-2.0 §4(b) modification comment).
- Writes local adaptation files (`c-level-skills/references/paperclip-11-agent-routing.md` &
  `LARAVEL-COMPATIBILITY.md`).
- Creates POSIX symlinks (or Windows NTFS junctions) into `<HERMES_HOME>/profiles/pc*/skills/`,
  locks `.usage.json`, resolves `productivity/pdf` conflict (or `--strict-oss` / `--offline`
  fallbacks), and syncs with Paperclip Skills Store API when reachable.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTROL_CENTER_SRC = REPO_ROOT / "apps" / "control-center"
if str(CONTROL_CENTER_SRC) not in sys.path:
    sys.path.insert(0, str(CONTROL_CENTER_SRC))

from control_center.agent_skills_manager import (  # noqa: E402
    build_agent_skill_specs,
    install_agent_skills,
    install_all_agents_skills,
    load_lock_and_policy,
    stage1_and_stage2_prepare_packages,
    verify_manifest,
)
from control_center.paths import PROFILES_ROOT, SKILL_REGISTRY_DIR  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Install and verify pinned, security-gated GitHub skills for ALLINAGENT's 11 corporate agents."
    )
    parser.add_argument(
        "--verify-manifest",
        action="store_true",
        help="Validate skills.lock.json, 40-char commit SHAs, quarantine exclusions, and skill-policy.json offline.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned 11-agent skill sets, redistribution policies, and fallback behavior without downloading.",
    )
    parser.add_argument(
        "--stage1-only",
        action="store_true",
        help="Download, SHA-256 verify, security-scan, and stage packages into reviewed/ without mutating profiles.",
    )
    parser.add_argument(
        "--agent",
        default="all",
        help="Target agent role_slug or 'all' (default: 'all').",
    )
    parser.add_argument(
        "--enable-experimental",
        action="store_true",
        help="Explicitly activate experimental skills (`cve-triage`) in runtime profile.",
    )
    parser.add_argument(
        "--strict-oss",
        action="store_true",
        help="Skip Commons-Clause / non-OSI FETCH_FROM_UPSTREAM_ONLY packages and activate MIT strict_oss_fallback skills.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Operate strictly offline using cached reviewed/ packages and bundled MIT fallbacks.",
    )
    parser.add_argument(
        "--registry-dir",
        default=str(SKILL_REGISTRY_DIR),
        help="Target local skill-registry directory (defaults to <ALLINAGENT_ROOT>/data/skill-registry).",
    )
    parser.add_argument(
        "--hermes-home",
        default=None,
        help="Override root HERMES_HOME containing profiles/pc*.",
    )
    args = parser.parse_args()

    lock_doc, policy_doc = load_lock_and_policy()
    check = verify_manifest(lock_doc, policy_doc)
    if args.verify_manifest:
        print(json.dumps(check, indent=2))
        return 0 if check["ok"] else 1
    if not check["ok"]:
        raise SystemExit(f"Manifest/policy verification failed: {json.dumps(check, indent=2)}")

    reg_root = Path(args.registry_dir).resolve()
    prof_root = (Path(args.hermes_home).resolve() / "profiles") if args.hermes_home else PROFILES_ROOT

    if args.dry_run:
        specs = build_agent_skill_specs(registry_root=reg_root)
        pkgs = lock_doc["packages"]
        roles_preview = {}
        for s in specs:
            roles_preview[s["role_slug"]] = {
                "profile": s["profile"],
                "toolsets": s["toolsets"],
                "primary": s["primary"],
                "specialist": s["specialist"],
                "on_demand": s["on_demand"],
                "reference_only": s["reference_only"],
                "experimental": s["experimental"],
                "experimental_runtime_active": bool(args.enable_experimental and s["experimental"]),
                "strict_oss_fallbacks": {
                    p: pkgs[p]["strict_oss_fallback"]
                    for p in (*s["primary"], *s["specialist"], *s["on_demand"])
                    if args.strict_oss and pkgs[p].get("strict_oss_fallback")
                },
            }
        print(
            json.dumps(
                {
                    "dry_run": True,
                    "manifest_check": check,
                    "strict_oss": args.strict_oss,
                    "offline": args.offline,
                    "enable_experimental": args.enable_experimental,
                    "registry_dir": str(reg_root),
                    "profiles_dir": str(prof_root),
                    "roles": roles_preview,
                },
                indent=2,
            )
        )
        return 0

    if args.stage1_only:
        all_pkgs = sorted(lock_doc["packages"].keys())
        prep = stage1_and_stage2_prepare_packages(
            all_pkgs,
            registry_root=reg_root,
            offline=args.offline,
            strict_oss=args.strict_oss,
            lock_doc=lock_doc,
            policy_doc=policy_doc,
        )
        print(
            json.dumps(
                {
                    "stage1_only": True,
                    "gated_count": len(prep["gated_packages"]),
                    "skipped_count": len(prep["skipped_packages"]),
                    "local_adaptation_files": prep["local_adaptation_files"],
                },
                indent=2,
            )
        )
        return 0

    if args.agent == "all":
        res = install_all_agents_skills(
            registry_root=reg_root,
            profiles_root=prof_root,
            enable_experimental=args.enable_experimental,
            strict_oss=args.strict_oss,
            offline=args.offline,
        )
        print(
            json.dumps(
                {
                    "ok": True,
                    "installed_agents": res["installed_agents"],
                    "stage1_summary": res["stage1_summary"],
                    "registry_dir": str(reg_root),
                    "profiles_dir": str(prof_root),
                },
                indent=2,
            )
        )
        return 0

    single = install_agent_skills(
        args.agent,
        registry_root=reg_root,
        profiles_root=prof_root,
        enable_experimental=args.enable_experimental,
        strict_oss=args.strict_oss,
        offline=args.offline,
    )
    print(json.dumps(single, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
