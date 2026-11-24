#!/usr/bin/env python3
"""ALLINAGENT CycloneDX 1.5 Software Bill of Materials (SBOM) Generator.

Generates and validates a deterministic CycloneDX 1.5 JSON SBOM (`sbom.cdx.json`)
from:
  1. `components.lock.json` (core upstream components & 40-char Git commit pins)
  2. `skills/manifests/skills.lock.json` / `config/portable-skill-manifest.json`
     (or `LICENSE-INVENTORY.json` skill provenance fallback)
  3. `package.json` & `package-lock.json` manifests across first-party/extended packages
  4. Python `pyproject.toml` & `requirements*.txt` manifests

Pure Python 3.11+ standard library implementation (zero third-party dependencies).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tomllib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

SBOM_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

VALID_SPDX_IDS = frozenset({
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "CC0-1.0",
    "ISC",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MIT",
    "MPL-2.0",
    "PostgreSQL",
    "PSF-2.0",
    "Python-2.0",
    "Unlicense",
    "Zlib",
})

BLOCKED_BUNDLED_LICENSE_TOKENS = (
    "AGPL",
    "GPL-2.0",
    "GPL-3.0",
    "SSPL",
    "BUSL",
    "COMMONS-CLAUSE",
    "COMMONS CLAUSE",
)

SKIP_DIR_NAMES = frozenset({
    ".git",
    "node_modules",
    ".pnpm-store",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".turbo",
    "dist",
    "out",
    "coverage",
    "data",
    "office-data",
    "logs",
    "reports",
    "skill-registry",
    "runtime",
    "vendor-cache",
    ".upstream-cache",
})

PEP508_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9,._\s-]+\])?\s*"
    r"(?:(==|~=|>=|<=|>|<|!=)\s*([A-Za-z0-9.*+!_-]+))?"
)
COMMIT_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
URN_UUID_RE = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def _should_skip_dir(rel_parts: tuple[str, ...], dir_name: str) -> bool:
    if dir_name in SKIP_DIR_NAMES or "venv" in dir_name.lower() or dir_name.endswith("-worktrees"):
        return True
    if len(rel_parts) >= 1 and rel_parts[0] == "workspaces" and dir_name != "sample-project":
        return True
    if len(rel_parts) >= 1 and rel_parts[0] == "skills" and dir_name in {
        "upstream",
        "staging",
        "reviewed",
        "quarantine",
        "agents",
        "cache",
    }:
        return True
    return False


def _iter_manifest_files(root: Path, filenames: set[str], glob_patterns: tuple[str, ...] = ()) -> list[Path]:
    discovered: list[Path] = []
    for cur_root, dirs, files in os.walk(root, topdown=True, followlinks=False):
        cur_path = Path(cur_root)
        rel_parts = cur_path.relative_to(root).parts if cur_path != root else ()
        dirs[:] = sorted(d for d in dirs if not _should_skip_dir(rel_parts, d))
        for fname in sorted(files):
            if fname.startswith(".env") or "secret" in fname.lower() or "token" in fname.lower() or "auth" in fname.lower():
                continue
            matched = fname in filenames or any(Path(fname).match(pat) for pat in glob_patterns)
            if matched:
                discovered.append(cur_path / fname)
    return sorted(discovered)


def _format_cyclonedx_license(spdx_or_name: str | None) -> list[dict[str, Any]]:
    if not spdx_or_name:
        return []
    cleaned = str(spdx_or_name).strip()
    if not cleaned:
        return []
    if cleaned in VALID_SPDX_IDS:
        return [{"license": {"id": cleaned}}]
    return [{"license": {"name": cleaned}}]


def _normalize_npm_purl(pkg_name: str, version: str) -> str:
    clean_ver = re.sub(r"^[\^~>=<\s]+", "", version.strip()) or "0.0.0"
    if pkg_name.startswith("@") and "/" in pkg_name:
        scope, name = pkg_name.split("/", 1)
        return f"pkg:npm/{quote(scope, safe='')}/{quote(name, safe='')}@{quote(clean_ver, safe='.-_+')}"
    return f"pkg:npm/{quote(pkg_name, safe='')}@{quote(clean_ver, safe='.-_+')}"


def _normalize_pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def _normalize_pypi_purl(name: str, version: str) -> str:
    norm = _normalize_pypi_name(name)
    clean_ver = version.strip() if version else "unspecified"
    return f"pkg:pypi/{quote(norm, safe='-')}@{quote(clean_ver, safe='.*+-_')}"


def _parse_pep508(spec: str) -> tuple[str, str] | None:
    base = spec.split(";", 1)[0].strip()
    if not base or base.startswith(("#", "-", "git+", "http://", "https://")):
        return None
    m = PEP508_RE.match(base)
    if not m:
        return None
    pkg_name = m.group(1)
    op = m.group(2) or ""
    ver = m.group(3) or ""
    resolved_ver = ver if op == "==" and ver else (f"{op}{ver}" if ver else "unspecified")
    return pkg_name, resolved_ver


def _load_json_if_exists(path: Path) -> dict[str, Any]:
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}


def build_sbom(repo_root: Path, *, deterministic_timestamp: str | None = None) -> dict[str, Any]:
    root_pkg = _load_json_if_exists(repo_root / "package.json")
    comp_lock = _load_json_if_exists(repo_root / "components.lock.json")
    lic_inv = _load_json_if_exists(repo_root / "LICENSE-INVENTORY.json")

    known_npm_licenses: dict[str, str] = lic_inv.get("known_package_licenses", {}).get("npm", {})
    known_pypi_licenses: dict[str, str] = lic_inv.get("known_package_licenses", {}).get("pypi", {})

    product_name = str(root_pkg.get("name") or comp_lock.get("product") or "allinagent").lower()
    product_version = str(root_pkg.get("version") or comp_lock.get("product_version") or "1.0.0")
    root_license = str(root_pkg.get("license") or lic_inv.get("root_license_spdx") or "MIT")
    root_bom_ref = f"pkg:generic/{product_name}@{product_version}"

    components_by_ref: dict[str, dict[str, Any]] = {}
    deps_by_ref: dict[str, set[str]] = {root_bom_ref: set()}

    def register_component(comp: dict[str, Any], parent_ref: str | None = root_bom_ref) -> str:
        bref = comp["bom-ref"]
        if bref not in components_by_ref:
            components_by_ref[bref] = comp
        deps_by_ref.setdefault(bref, set())
        if parent_ref:
            deps_by_ref.setdefault(parent_ref, set()).add(bref)
        return bref

    # 1. Core Upstream Components from `components.lock.json`
    for comp_id, cinfo in sorted((comp_lock.get("components") or {}).items()):
        commit = str(cinfo.get("commit") or cinfo.get("base_commit") or "")
        version = str(cinfo.get("version") or commit[:12] or "0.0.0")
        purl = str(cinfo.get("purl") or f"pkg:generic/{comp_id}@{version}")
        bref = f"core:{comp_id}@{version}"
        vendored = bool(cinfo.get("vendored_in_repo", False))
        ext_refs: list[dict[str, str]] = []
        if cinfo.get("upstream_repo"):
            ext_refs.append({
                "type": "vcs",
                "url": str(cinfo["upstream_repo"]),
                "comment": f"Pinned commit {commit}" if commit else "Upstream VCS",
            })
        if cinfo.get("homepage"):
            ext_refs.append({"type": "website", "url": str(cinfo["homepage"])})

        comp_entry: dict[str, Any] = {
            "type": "framework" if comp_id in {"hermes-agent", "paperclip"} else "application",
            "bom-ref": bref,
            "name": str(cinfo.get("name") or comp_id),
            "version": version,
            "purl": purl,
            "scope": "required" if comp_id != "vulnclaw" else "optional",
            "licenses": _format_cyclonedx_license(cinfo.get("license")),
            "externalReferences": ext_refs,
            "properties": [
                {"name": "allinagent:category", "value": "core-upstream"},
                {"name": "allinagent:commit", "value": commit},
                {"name": "allinagent:acquisition_mode", "value": str(cinfo.get("acquisition_mode", ""))},
                {"name": "allinagent:bundled_in_git", "value": "true" if vendored else "false"},
            ],
        }
        if cinfo.get("copyright"):
            comp_entry["copyright"] = str(cinfo["copyright"])
        register_component(comp_entry, root_bom_ref)

    # 2. Pinned GitHub Agent Skills (`skills/manifests/skills.lock.json` or fallbacks)
    skill_manifest_candidates = [
        repo_root / "skills" / "manifests" / "skills.lock.json",
        repo_root / "config" / "portable-skill-manifest.json",
        repo_root / "skill-registry" / "manifests" / "skill-lock.json",
    ]
    loaded_skill_pkgs: dict[str, dict[str, Any]] = {}
    for sm_path in skill_manifest_candidates:
        if sm_path.is_file():
            sm_data = _load_json_if_exists(sm_path)
            pkgs = sm_data.get("packages") or {}
            if isinstance(pkgs, dict):
                for pid, pinfo in pkgs.items():
                    if pid not in loaded_skill_pkgs and isinstance(pinfo, dict):
                        loaded_skill_pkgs[pid] = pinfo

    if loaded_skill_pkgs:
        for pkg_id, sinfo in sorted(loaded_skill_pkgs.items()):
            repo_url = str(sinfo.get("repo_url") or "").rstrip("/")
            commit = str(sinfo.get("pinned_commit_sha") or sinfo.get("commit") or "")
            subpath = str(sinfo.get("subpath") or "").strip("/")
            lic = str(sinfo.get("license_spdx") or sinfo.get("license") or "")
            policy = str(
                sinfo.get("redistribution_policy")
                or sinfo.get("redistribution_allagent")
                or "FETCH_FROM_UPSTREAM_ONLY"
            )
            sha256_hex = str(
                sinfo.get("package_sha256")
                or sinfo.get("upstream_package_sha256")
                or ""
            )
            owner_repo = repo_url.replace("https://github.com/", "").replace(".git", "")
            purl = f"pkg:github/{owner_repo}@{commit}" + (f"#{subpath}" if subpath else "")
            bref = f"skill:{pkg_id}@{commit[:12] or 'pinned'}"
            comp_entry = {
                "type": "data",
                "bom-ref": bref,
                "group": "github-agent-skill",
                "name": pkg_id,
                "version": commit[:12] if commit else "0.0.0",
                "purl": purl,
                "scope": "optional",
                "licenses": _format_cyclonedx_license(lic),
                "externalReferences": [{"type": "vcs", "url": repo_url}] if repo_url else [],
                "properties": [
                    {"name": "allinagent:category", "value": "agent-skill"},
                    {"name": "allinagent:commit", "value": commit},
                    {"name": "allinagent:subpath", "value": subpath},
                    {"name": "allinagent:redistribution_policy", "value": policy},
                    {"name": "allinagent:bundled_in_git", "value": "false"},
                ],
            }
            if re.fullmatch(r"[0-9a-f]{64}", sha256_hex):
                comp_entry["hashes"] = [{"alg": "SHA-256", "content": sha256_hex}]
            register_component(comp_entry, root_bom_ref)
    else:
        # Fallback to repository-level skill inventory in `LICENSE-INVENTORY.json`
        for srepo in lic_inv.get("agent_skill_repositories") or []:
            repo_slug = str(srepo.get("repo") or "")
            repo_url = str(srepo.get("url") or "")
            commit = str(srepo.get("commit") or "")
            lic = str(srepo.get("license_spdx") or "")
            policy = str(srepo.get("redistribution_policy") or "FETCH_FROM_UPSTREAM_ONLY")
            bundled = bool(srepo.get("bundled_in_git", False))
            for pkg_id in sorted(srepo.get("packages") or []):
                purl = f"pkg:github/{repo_slug}@{commit}#{pkg_id}"
                bref = f"skill:{pkg_id}@{commit[:12] or 'pinned'}"
                register_component(
                    {
                        "type": "data",
                        "bom-ref": bref,
                        "group": "github-agent-skill",
                        "name": pkg_id,
                        "version": commit[:12] if commit else "0.0.0",
                        "purl": purl,
                        "scope": "optional",
                        "licenses": _format_cyclonedx_license(lic),
                        "externalReferences": [{"type": "vcs", "url": repo_url}] if repo_url else [],
                        "properties": [
                            {"name": "allinagent:category", "value": "agent-skill"},
                            {"name": "allinagent:commit", "value": commit},
                            {"name": "allinagent:redistribution_policy", "value": policy},
                            {"name": "allinagent:bundled_in_git", "value": "true" if bundled else "false"},
                        ],
                    },
                    root_bom_ref,
                )

    # 3. Node.js `package.json` & `package-lock.json` Manifests
    for pkg_json_path in _iter_manifest_files(repo_root, {"package.json"}):
        rel_dir = pkg_json_path.parent.relative_to(repo_root).as_posix()
        pdata = _load_json_if_exists(pkg_json_path)
        if not pdata:
            continue

        parent_ref = root_bom_ref
        if pkg_json_path.parent != repo_root:
            sub_name = str(pdata.get("name") or rel_dir)
            sub_ver = str(pdata.get("version") or "1.0.0")
            sub_lic = str(pdata.get("license") or root_license)
            parent_ref = register_component(
                {
                    "type": "application",
                    "bom-ref": f"subproject:npm:{rel_dir}@{sub_ver}",
                    "name": sub_name,
                    "version": sub_ver,
                    "scope": "required",
                    "licenses": _format_cyclonedx_license(sub_lic),
                    "properties": [
                        {"name": "allinagent:category", "value": "workspace-package"},
                        {"name": "allinagent:manifest_path", "value": f"{rel_dir}/package.json"},
                        {"name": "allinagent:bundled_in_git", "value": "true"},
                    ],
                },
                root_bom_ref,
            )

        lock_pkgs = _load_json_if_exists(pkg_json_path.parent / "package-lock.json").get("packages") or {}

        for dep_section, scope_val in (("dependencies", "required"), ("devDependencies", "optional")):
            deps_dict = pdata.get(dep_section) or {}
            if not isinstance(deps_dict, dict):
                continue
            for dep_name, dep_spec in sorted(deps_dict.items()):
                lock_entry = lock_pkgs.get(f"node_modules/{dep_name}") or {}
                resolved_ver = str(
                    lock_entry.get("version")
                    or re.sub(r"^[\^~>=<\s]+", "", str(dep_spec))
                    or "0.0.0"
                )
                purl = _normalize_npm_purl(dep_name, resolved_ver)
                dep_lic = str(lock_entry.get("license") or known_npm_licenses.get(dep_name) or "")
                dep_comp: dict[str, Any] = {
                    "type": "library",
                    "bom-ref": purl,
                    "name": dep_name,
                    "version": resolved_ver,
                    "purl": purl,
                    "scope": scope_val,
                    "properties": [
                        {"name": "allinagent:ecosystem", "value": "npm"},
                        {"name": "allinagent:bundled_in_git", "value": "false"},
                    ],
                }
                if dep_lic:
                    dep_comp["licenses"] = _format_cyclonedx_license(dep_lic)
                register_component(dep_comp, parent_ref)

    # 4. Python `pyproject.toml` & `requirements*.txt` Manifests
    for pyproj_path in _iter_manifest_files(repo_root, {"pyproject.toml"}):
        rel_path = pyproj_path.relative_to(repo_root).as_posix()
        try:
            tdata = tomllib.loads(pyproj_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        proj = tdata.get("project") or {}
        if not proj:
            continue
        py_parent_ref = root_bom_ref
        if pyproj_path.parent != repo_root:
            py_name = str(proj.get("name") or pyproj_path.parent.name)
            py_ver = str(proj.get("version") or "0.1.0")
            raw_lic = proj.get("license")
            lic_str = raw_lic.get("text", "") if isinstance(raw_lic, dict) else str(raw_lic or root_license)
            py_parent_ref = register_component(
                {
                    "type": "application",
                    "bom-ref": f"subproject:python:{pyproj_path.parent.relative_to(repo_root).as_posix()}@{py_ver}",
                    "name": py_name,
                    "version": py_ver,
                    "scope": "required",
                    "licenses": _format_cyclonedx_license(lic_str),
                    "properties": [
                        {"name": "allinagent:category", "value": "python-package"},
                        {"name": "allinagent:manifest_path", "value": rel_path},
                        {"name": "allinagent:bundled_in_git", "value": "true"},
                    ],
                },
                root_bom_ref,
            )

        for req_str in proj.get("dependencies") or []:
            parsed = _parse_pep508(str(req_str))
            if not parsed:
                continue
            dep_name, dep_ver = parsed
            norm_name = _normalize_pypi_name(dep_name)
            purl = _normalize_pypi_purl(norm_name, dep_ver)
            dep_lic = known_pypi_licenses.get(norm_name, "")
            dep_comp = {
                "type": "library",
                "bom-ref": purl,
                "name": norm_name,
                "version": dep_ver,
                "purl": purl,
                "scope": "required",
                "properties": [
                    {"name": "allinagent:ecosystem", "value": "pypi"},
                    {"name": "allinagent:bundled_in_git", "value": "false"},
                ],
            }
            if dep_lic:
                dep_comp["licenses"] = _format_cyclonedx_license(dep_lic)
            register_component(dep_comp, py_parent_ref)

    for req_path in _iter_manifest_files(repo_root, set(), ("requirements*.txt",)):
        rel_req = req_path.relative_to(repo_root).as_posix()
        for line in req_path.read_text(encoding="utf-8", errors="replace").splitlines():
            parsed = _parse_pep508(line)
            if not parsed:
                continue
            dep_name, dep_ver = parsed
            norm_name = _normalize_pypi_name(dep_name)
            purl = _normalize_pypi_purl(norm_name, dep_ver)
            dep_lic = known_pypi_licenses.get(norm_name, "")
            dep_comp = {
                "type": "library",
                "bom-ref": purl,
                "name": norm_name,
                "version": dep_ver,
                "purl": purl,
                "scope": "required",
                "properties": [
                    {"name": "allinagent:ecosystem", "value": "pypi"},
                    {"name": "allinagent:manifest_path", "value": rel_req},
                    {"name": "allinagent:bundled_in_git", "value": "false"},
                ],
            }
            if dep_lic:
                dep_comp["licenses"] = _format_cyclonedx_license(dep_lic)
            register_component(dep_comp, root_bom_ref)

    sorted_components = [components_by_ref[k] for k in sorted(components_by_ref.keys())]
    sorted_dependencies = [
        {"ref": ref_key, "dependsOn": sorted(deps_by_ref[ref_key])}
        for ref_key in sorted(deps_by_ref.keys())
    ]

    fingerprint = hashlib.sha256(
        json.dumps(sorted_components, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    serial_uuid = uuid.uuid5(SBOM_NAMESPACE, f"allinagent-sbom:{product_version}:{fingerprint}")

    timestamp = deterministic_timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial_uuid}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "bom-ref": "tool:allinagent-sbom-generator@1.0.0",
                        "name": "allinagent-sbom-generator",
                        "version": "1.0.0",
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": root_bom_ref,
                "name": product_name,
                "version": product_version,
                "licenses": _format_cyclonedx_license(root_license),
            },
            "licenses": _format_cyclonedx_license(root_license),
        },
        "components": sorted_components,
        "dependencies": sorted_dependencies,
    }


def validate_sbom(bom: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if bom.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat must equal 'CycloneDX'")
    if bom.get("specVersion") != "1.5":
        errors.append("specVersion must equal '1.5'")
    if not URN_UUID_RE.match(str(bom.get("serialNumber") or "")):
        errors.append(f"Invalid serialNumber URN UUID: {bom.get('serialNumber')!r}")
    if not isinstance(bom.get("version"), int) or bom["version"] < 1:
        errors.append("version must be an integer >= 1")

    meta_comp = (bom.get("metadata") or {}).get("component") or {}
    root_ref = meta_comp.get("bom-ref")
    if not root_ref:
        errors.append("metadata.component.bom-ref is missing")

    seen_refs: set[str] = {str(root_ref)} if root_ref else set()
    core_commits_checked = 0

    for idx, comp in enumerate(bom.get("components") or []):
        bref = comp.get("bom-ref")
        if not bref:
            errors.append(f"components[{idx}] missing bom-ref")
            continue
        if bref in seen_refs:
            errors.append(f"Duplicate bom-ref detected: {bref}")
        seen_refs.add(str(bref))

        props = {p["name"]: p["value"] for p in (comp.get("properties") or []) if "name" in p and "value" in p}
        if props.get("allinagent:category") == "core-upstream":
            core_commits_checked += 1
            commit = props.get("allinagent:commit", "")
            if not COMMIT_SHA40_RE.match(commit):
                errors.append(f"Core upstream {comp.get('name')} lacks 40-char commit SHA: {commit!r}")

        for lic_item in comp.get("licenses") or []:
            lic_obj = lic_item.get("license") or {}
            if "id" in lic_obj and lic_obj["id"] not in VALID_SPDX_IDS:
                errors.append(f"Component {bref} uses non-SPDX license.id {lic_obj['id']!r} (must use license.name)")
            lic_label = str(lic_obj.get("id") or lic_obj.get("name") or "").upper()
            if props.get("allinagent:bundled_in_git") == "true":
                if any(tok in lic_label for tok in BLOCKED_BUNDLED_LICENSE_TOKENS):
                    errors.append(f"Restricted/copyleft component {bref} ({lic_label}) cannot be bundled in Git")

    if core_commits_checked < 4:
        errors.append(f"Expected >= 4 core upstream components in SBOM, found {core_commits_checked}")

    for dep_node in bom.get("dependencies") or []:
        dref = dep_node.get("ref")
        if dref not in seen_refs:
            errors.append(f"dependencies.ref {dref!r} does not match any known component bom-ref")
        for target in dep_node.get("dependsOn") or []:
            if target not in seen_refs:
                errors.append(f"dependencies[{dref!r}] references unknown bom-ref {target!r}")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate CycloneDX 1.5 SBOM for ALLINAGENT.")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repository root directory (defaults to parent of scripts/).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output path for CycloneDX JSON (defaults to <root>/reports/sbom.cdx.json).",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print generated CycloneDX JSON to stdout instead of writing a file.",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate CycloneDX 1.5 structure, commit pins, and license bundling rules.",
    )
    args = parser.parse_args(argv)

    repo_root = args.root.resolve()
    bom = build_sbom(repo_root)
    validation_errors = validate_sbom(bom) if args.validate else []

    if args.stdout:
        sys.stdout.write(json.dumps(bom, indent=2) + "\n")
    else:
        out_path = args.output if args.output is not None else (repo_root / "reports" / "sbom.cdx.json")
        if not out_path.is_absolute():
            out_path = (repo_root / out_path).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")
        summary = {
            "ok": len(validation_errors) == 0,
            "bomFormat": bom["bomFormat"],
            "specVersion": bom["specVersion"],
            "serialNumber": bom["serialNumber"],
            "components_count": len(bom["components"]),
            "dependencies_count": len(bom["dependencies"]),
            "output_path": str(out_path),
            "validation_errors": validation_errors,
        }
        print(json.dumps(summary, indent=2))

    if validation_errors:
        for err in validation_errors:
            print(f"[SBOM-ERROR] {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
