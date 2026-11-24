#!/usr/bin/env python3
"""Contract tests for ALLINAGENT Telegram 59-command suite, 11-agent dynamic identity,
PDF/DOCX report exporter, and Docker Compose production resource/network invariants.

Cross-platform (Linux + Windows), hermetic, and zero personal/private identifiers.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any

os.environ.setdefault("ALLINAGENT_SKIP_DOTENV", "1")
os.environ.setdefault("OFFICE_BRIDGE_LOAD_DOTENV", "0")
os.environ.setdefault("NODE_ENV", "test")

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_CENTER_PKG_ROOT = REPO_ROOT / "apps" / "control-center"
if str(CONTROL_CENTER_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_CENTER_PKG_ROOT))

NODE_BIN = shutil.which("node")

from control_center import report_exporter

UUID_LITERAL_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)

CANONICAL_11_AGENTS = [
    ("CEO Agent", "ceo", "ceo_agent", "pcceoagent", 1, None),
    ("CTO Agent", "cto", "cto_agent", "pcctoagent", 2, "ceo_agent"),
    ("Backend Developer", "engineer", "backend_developer", "pcbackenddeveloper", 1, "ceo_agent"),
    ("Frontend Developer", "designer", "frontend_developer", "pcfrontenddeveloper", 2, "cto_agent"),
    ("DevOps Engineer", "devops", "devops_engineer", "pcdevopsengineer", 2, "cto_agent"),
    ("QA Engineer", "qa", "qa_engineer", "pcqaengineer", 1, "ceo_agent"),
    ("Security Lead", "security", "security_lead", "pcsecuritylead", 2, "ceo_agent"),
    ("Security Reviewer", "security", "security_reviewer", "pcsecurityreviewer", 1, "ceo_agent"),
    ("Findings Analyst", "researcher", "findings_analyst", "pcfindingsanalyst", 2, "security_lead"),
    ("Remediation Reviewer", "security", "remediation_reviewer", "pcremediationreviewer", 2, "security_lead"),
    ("Report & Compliance Agent", "pm", "compliance_reporter", "pccompliancereporter", 2, "ceo_agent"),
]


def _run_node_json(js_code: str) -> Any:
    if not NODE_BIN:
        raise unittest.SkipTest("Node.js runtime not found on PATH")
    env = dict(os.environ)
    env["NODE_ENV"] = "test"
    env["OFFICE_BRIDGE_LOAD_DOTENV"] = "0"
    proc = subprocess.run(
        [NODE_BIN, "-e", js_code],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"Node contract probe exited with {proc.returncode}:\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
        )
    lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    assert lines, "Node contract probe returned empty stdout"
    return json.loads(lines[-1])


def _parse_mem_mib(raw_val: str | int | float) -> float:
    s = str(raw_val).strip().lower().strip("'\"")
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(b|k|kb|kib|m|mb|mib|g|gb|gib)?", s)
    if not m:
        raise ValueError(f"Unrecognized Compose memory limit: {raw_val!r}")
    val = float(m.group(1))
    unit = m.group(2) or "b"
    if unit in ("g", "gb", "gib"):
        return val * 1024.0
    if unit in ("m", "mb", "mib"):
        return val
    if unit in ("k", "kb", "kib"):
        return val / 1024.0
    return val / (1024.0 * 1024.0)


def _parse_compose_services_and_networks(compose_path: Path) -> dict[str, Any]:
    """Parse Compose `services` and `networks` blocks using PyYAML when installed, or stdlib indentation parser."""
    text = compose_path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore[import-untyped]

        loaded = yaml.safe_load(text)
        if isinstance(loaded, dict):
            return loaded
    except ImportError:
        pass

    # Deterministic stdlib indentation parser for Compose services & networks blocks
    doc: dict[str, Any] = {"services": {}, "networks": {}, "x-production-resource-budget": {}}
    section: str | None = None
    cur_item: str | None = None
    cur_list_key: str | None = None

    for raw_line in text.splitlines():
        stripped_comment = re.sub(r"\s+#.*$", "", raw_line) if not raw_line.lstrip().startswith("#") else ""
        if not stripped_comment.strip():
            continue
        indent = len(stripped_comment) - len(stripped_comment.lstrip(" "))
        line = stripped_comment.strip()

        if indent == 0 and line.endswith(":"):
            key0 = line[:-1].strip()
            section = key0 if key0 in doc else None
            cur_item = None
            cur_list_key = None
            continue

        if section == "x-production-resource-budget" and indent == 2 and ":" in line:
            k, v = line.split(":", 1)
            val_s = v.strip().strip("'\"")
            doc[section][k.strip()] = int(val_s) if val_s.isdigit() else val_s
            continue

        if section in ("services", "networks"):
            if indent == 2 and line.endswith(":"):
                cur_item = line[:-1].strip()
                doc[section][cur_item] = {}
                cur_list_key = None
            elif indent == 4 and cur_item is not None:
                if line.endswith(":"):
                    cur_list_key = line[:-1].strip()
                    doc[section][cur_item].setdefault(cur_list_key, [])
                elif ":" in line:
                    cur_list_key = None
                    k, v = line.split(":", 1)
                    vs = v.strip().strip("'\"")
                    if vs in ("true", "false"):
                        doc[section][cur_item][k.strip()] = vs == "true"
                    elif vs.isdigit():
                        doc[section][cur_item][k.strip()] = int(vs)
                    else:
                        doc[section][cur_item][k.strip()] = vs
            elif indent == 6 and cur_item is not None and cur_list_key is not None:
                if line.startswith("- "):
                    item_val = line[2:].strip().strip("'\"")
                    lst = doc[section][cur_item].get(cur_list_key)
                    if isinstance(lst, list):
                        lst.append(item_val)
    return doc


class TestDummyPluginContext:
    def __init__(self) -> None:
        self.profile_name = "default"
        self.commands: dict[str, dict[str, Any]] = {}
        self.hooks: dict[str, Any] = {}
        self.tools: dict[str, Any] = {}
        self.telegram_handlers: list[Any] = []

    def register_command(self, name: str, handler: Any = None, description: str = "", args_hint: str = "", **_: Any) -> None:
        self.commands[name] = {
            "handler": handler,
            "description": description,
            "args_hint": args_hint,
        }

    def register_hook(self, name: str, handler: Any, **_: Any) -> None:
        self.hooks[name] = handler

    def register_tool(self, name: str = "", **kw: Any) -> None:
        self.tools[name or kw.get("name", "tool")] = kw

    def register_telegram_handler(self, handler: Any, **_: Any) -> None:
        self.telegram_handlers.append(handler)


class TestTelegram59SlashCommandsContract(unittest.TestCase):
    """Verifies all 59 slash commands across `command_catalog.json` and `unified-company-control`."""

    def setUp(self) -> None:
        self.catalog_path = REPO_ROOT / "integrations" / "telegram" / "command_catalog.json"
        self.assertTrue(self.catalog_path.is_file(), f"Missing {self.catalog_path}")
        self.catalog = json.loads(self.catalog_path.read_text(encoding="utf-8"))

        self.plugin_paths = [
            REPO_ROOT / "integrations" / "telegram" / "unified-company-control" / "__init__.py",
            REPO_ROOT / "agents" / "hermes-extensions" / "plugins" / "unified-company-control" / "__init__.py",
        ]
        for p in self.plugin_paths:
            self.assertTrue(p.is_file(), f"Missing unified-company-control plugin at {p}")

    def test_catalog_has_exact_59_slash_commands_and_13_submenus(self) -> None:
        counts = self.catalog.get("counts") or {}
        slash_cmds = self.catalog.get("slash_commands") or []
        submenus = self.catalog.get("submenus") or []
        canonical_cmds = self.catalog.get("canonical_commands") or []

        self.assertEqual(counts.get("slash_commands"), 59)
        self.assertEqual(len(slash_cmds), 59)
        self.assertEqual(counts.get("submenus"), 13)
        self.assertEqual(len(submenus), 13)

        # Verify unique slugs, sequential indices 1..59, zero /approvals collision, and valid canonical_id refs
        canonical_ids = {c["id"] for c in canonical_cmds}
        slugs = [c["slug"] for c in slash_cmds]
        self.assertEqual(len(set(slugs)), 59, "Duplicate slash command slugs in command_catalog.json")
        self.assertEqual([c["index"] for c in slash_cmds], list(range(1, 60)))
        self.assertNotIn("approvals", slugs, "Native Hermes /approvals must not be overridden")
        for gov_slug in ("persetujuan", "setujui", "tolak"):
            self.assertIn(gov_slug, slugs)

        for entry in slash_cmds:
            slug = entry["slug"]
            self.assertEqual(entry["slash"], f"/{slug}")
            self.assertEqual(entry["bridge_command"], slug.replace("-", "_"))
            self.assertIn(entry["canonical_id"], canonical_ids)

        # Verify all 13 submenu callback payloads fit within Telegram's 64-byte limit
        for sm in submenus:
            cb = str(sm.get("callback_data") or "")
            self.assertTrue(cb.startswith("uac:sub:"))
            self.assertLessEqual(len(cb.encode("utf-8")), 64)

    def test_unified_company_control_registers_all_59_commands_identically(self) -> None:
        expected_slugs = [c["slug"] for c in self.catalog["slash_commands"]]

        for idx, plugin_file in enumerate(self.plugin_paths):
            spec = importlib.util.spec_from_file_location(f"ucc_contract_{idx}", str(plugin_file))
            assert spec and spec.loader
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            self.assertEqual(
                len(mod._SLASH_COMMANDS),
                59,
                f"{plugin_file} must declare exactly 59 _SLASH_COMMANDS",
            )
            plugin_slugs = [slug for slug, _, _ in mod._SLASH_COMMANDS]
            self.assertEqual(
                plugin_slugs,
                expected_slugs,
                f"Slash command list mismatch between {plugin_file} and command_catalog.json",
            )

            ctx = TestDummyPluginContext()
            mod.register(ctx)
            self.assertEqual(len(ctx.commands), 59)
            self.assertEqual(list(ctx.commands.keys()), expected_slugs)
            self.assertNotIn("approvals", ctx.commands)
            self.assertIn("post_gateway_admission", ctx.hooks)
            self.assertIn("unified_company_control", ctx.tools)
            self.assertEqual(len(ctx.telegram_handlers), 1)

            # Non-default worker profiles must NOT register owner gateway commands
            worker_ctx = TestDummyPluginContext()
            worker_ctx.profile_name = "pcbackenddeveloper"
            mod.register(worker_ctx)
            self.assertEqual(len(worker_ctx.commands), 0)

        # If Office Bridge command-registry.js is present, verify all 59 bridge_commands resolve
        cmd_reg_js = REPO_ROOT / "apps" / "office-bridge" / "telegram-control" / "command-registry.js"
        if cmd_reg_js.is_file() and NODE_BIN:
            bridge_cmds = [c["bridge_command"] for c in self.catalog["slash_commands"]]
            js_probe = _run_node_json(
                "const reg = require('./apps/office-bridge/telegram-control/command-registry');"
                f"const cmds = {json.dumps(bridge_cmds)};"
                "const cats = Object.keys(reg.MENU_CATEGORIES || {}).length;"
                "const canList = reg.CANONICAL_COMMANDS || [];"
                "const known = new Set();"
                "for (const c of canList) { known.add(c.id); for (const a of (c.aliases || [])) known.add(a); }"
                "const missing = cmds.filter(x => !known.has(x));"
                "console.log(JSON.stringify({ cats, missing }));"
            )
            self.assertEqual(js_probe["cats"], 13)
            self.assertEqual(js_probe["missing"], [])


class TestDynamic11AgentIdentityContract(unittest.TestCase):
    """Verifies 11-agent dynamic `role_slug` resolution without hardcoded UUIDs."""

    def test_zero_hardcoded_uuids_in_identity_and_provisioning_modules(self) -> None:
        checked_paths = [
            REPO_ROOT / "apps" / "office-bridge" / "contracts" / "agent-identity.js",
            REPO_ROOT / "apps" / "office-bridge" / "adapters" / "agent-skills-bridge.js",
            REPO_ROOT / "apps" / "control-center" / "control_center" / "org_provisioner.py",
            REPO_ROOT / "apps" / "control-center" / "control_center" / "agent_skills_manager.py",
            REPO_ROOT / "agents" / "organization-roster.template.json",
            *sorted((REPO_ROOT / "agents").glob("*/role-manifest.json")),
        ]
        found_uuids: list[str] = []
        for fpath in checked_paths:
            if not fpath.is_file():
                continue
            txt = fpath.read_text(encoding="utf-8")
            m = UUID_LITERAL_RE.search(txt)
            if m:
                found_uuids.append(f"{fpath.relative_to(REPO_ROOT).as_posix()} -> {m.group(0)}")

        self.assertEqual(found_uuids, [], f"Hardcoded UUIDs found in dynamic identity/provisioning files: {found_uuids}")

    def test_dynamic_11_agent_role_slug_resolution_across_random_uuid_generations(self) -> None:
        for round_idx in (1, 2):
            company_id = str(uuid.uuid4())
            slug_to_uuid = {slug: str(uuid.uuid4()) for _, _, slug, _, _, _ in CANONICAL_11_AGENTS}

            synthetic_paperclip_agents = []
            for name, role, slug, _prof, wave, parent_slug in CANONICAL_11_AGENTS:
                synthetic_paperclip_agents.append({
                    "id": slug_to_uuid[slug],
                    "companyId": company_id,
                    "name": name,
                    "role": role,
                    "title": f"{name} Title",
                    "reportsTo": slug_to_uuid[parent_slug] if parent_slug else None,
                    "status": "idle" if wave == 1 else "paused",
                    "lifecycleState": "ready" if wave == 1 else "paused",
                    "adapterType": "hermes_local",
                    "adapterConfig": {},
                })

            mapped = _run_node_json(
                "const { mapPaperclipAgentIdentity } = require('./apps/office-bridge/contracts/agent-identity');"
                f"const raw = {json.dumps(synthetic_paperclip_agents)};"
                "const out = raw.map((a, idx) => mapPaperclipAgentIdentity(a, raw, idx));"
                "console.log(JSON.stringify(out));"
            )
            self.assertEqual(len(mapped), 11, f"Round {round_idx}: expected 11 mapped agents")

            by_slug = {entry["role_slug"]: entry for entry in mapped}
            self.assertEqual(len(by_slug), 11)

            wave1_count = sum(1 for entry in mapped if entry["wave"] == 1 and entry["activation_status"] == "ACTIVE")
            wave2_count = sum(1 for entry in mapped if entry["wave"] == 2 and entry["activation_status"] == "STANDBY")
            self.assertEqual(wave1_count, 4)
            self.assertEqual(wave2_count, 7)

            for name, _role, slug, expected_profile, expected_wave, parent_slug in CANONICAL_11_AGENTS:
                ident = by_slug[slug]
                self.assertEqual(ident["paperclip_agent_id"], slug_to_uuid[slug])
                self.assertEqual(ident["company_id"], company_id)
                self.assertEqual(ident["display_name"], name)
                self.assertEqual(ident["runtime_profile_reference"], expected_profile)
                self.assertEqual(ident["wave"], expected_wave)
                expected_mgr = slug_to_uuid[parent_slug] if parent_slug else None
                self.assertEqual(ident["manager_id"], expected_mgr)

            # Verify CEO dynamic subordinate_ids match exact random UUIDs of direct reports
            ceo_subordinates = set(by_slug["ceo_agent"]["subordinate_ids"])
            expected_ceo_directs = {
                slug_to_uuid[slug]
                for _, _, slug, _, _, parent_slug in CANONICAL_11_AGENTS
                if parent_slug == "ceo_agent"
            }
            self.assertEqual(ceo_subordinates, expected_ceo_directs)


class TestReportExporterPdfAndDocxContract(unittest.TestCase):
    """Verifies `report_exporter.py` generates valid `%PDF-` and `.docx` ZIP/`word/document.xml` artifacts."""

    def _verify_pdf_and_docx_pair(self, force_stdlib: bool) -> None:
        synth_secret = "sk" + "-" + "TESTEXPORTERSECRET1234567890"
        sample_md = (
            "# ALLINAGENT Compliance Readiness Report\n\n"
            "> Automated technical control readiness summary (non-certification notice).\n\n"
            "## 1. Control Mapping Summary\n\n"
            "| Control ID | Framework | Status | Notes |\n"
            "| --- | --- | --- | --- |\n"
            "| A.8.28 | ISO 27001 | PASS | Defensive code review verified |\n"
            "| CC6.1 | SOC 2 | PASS | Fail-closed Owner DM authorization |\n\n"
            "## 2. Diagnostic Evidence\n\n"
            f"- Redacted credential sample: `{synth_secret}`\n"
            "- Export mode: deterministic cross-platform\n\n"
            "```json\n"
            '{"overall": "PASS", "controls_verified": 2}\n'
            "```\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            md_file = tmp_dir / "compliance-audit.md"
            md_file.write_text(sample_md, encoding="utf-8")

            res = report_exporter.export_markdown_to_pdf_and_docx(
                md_file,
                tmp_dir / "out",
                base_name="audit-deliverable",
                force_stdlib=force_stdlib,
            )
            self.assertTrue(res.get("ok"))

            pdf_path = Path(res["pdf_path"])
            docx_path = Path(res["docx_path"])
            self.assertTrue(pdf_path.is_file())
            self.assertTrue(docx_path.is_file())

            # 1. Verify PDF magic header, EOF marker, SHA-256, and secret redaction
            pdf_bytes = pdf_path.read_bytes()
            self.assertGreater(len(pdf_bytes), 400)
            self.assertTrue(pdf_bytes.startswith(b"%PDF-"), f"PDF missing %PDF- header: {pdf_bytes[:16]!r}")
            self.assertIn(b"%%EOF", pdf_bytes[-64:])
            self.assertEqual(hashlib.sha256(pdf_bytes).hexdigest(), res["pdf_sha256"])
            self.assertNotIn(synth_secret.encode("utf-8"), pdf_bytes)

            # 2. Verify DOCX is a valid OpenXML ZIP containing parseable `word/document.xml`
            self.assertTrue(zipfile.is_zipfile(docx_path), "Generated .docx is not a valid ZIP archive")
            docx_bytes = docx_path.read_bytes()
            self.assertEqual(hashlib.sha256(docx_bytes).hexdigest(), res["docx_sha256"])

            with zipfile.ZipFile(docx_path, "r") as zf:
                names = set(zf.namelist())
                self.assertIn("[Content_Types].xml", names)
                self.assertIn("_rels/.rels", names)
                self.assertIn("word/document.xml", names)

                doc_xml_bytes = zf.read("word/document.xml")
                self.assertNotIn(synth_secret.encode("utf-8"), doc_xml_bytes)

                root = ET.fromstring(doc_xml_bytes)
                all_text = "".join(root.itertext())
                self.assertIn("ALLINAGENT Compliance Readiness Report", all_text)
                self.assertIn("ISO 27001", all_text)
                self.assertIn("[REDACTED", all_text)

    def test_export_pdf_and_docx_default_engine(self) -> None:
        self._verify_pdf_and_docx_pair(force_stdlib=False)

    def test_export_pdf_and_docx_stdlib_fallback_engine(self) -> None:
        self._verify_pdf_and_docx_pair(force_stdlib=True)

    def test_report_exporter_cli_entrypoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            md_file = tmp_dir / "cli-report.md"
            md_file.write_text("# CLI Export Test\n\n1. Verified PDF\n2. Verified DOCX\n", encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "control_center.report_exporter",
                    str(md_file),
                    "--out-dir",
                    str(tmp_dir / "exports"),
                    "--force-stdlib",
                ],
                cwd=str(REPO_ROOT),
                env={**os.environ, "PYTHONPATH": str(CONTROL_CENTER_PKG_ROOT)},
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=20,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, f"CLI failed: {proc.stderr}")
            payload = json.loads(proc.stdout)
            self.assertTrue(Path(payload["pdf_path"]).read_bytes().startswith(b"%PDF-"))
            self.assertTrue(zipfile.is_zipfile(payload["docx_path"]))


class TestComposeProductionBudgetAndPortIsolation(unittest.TestCase):
    """Verifies `compose.production.yaml` <= 1,536 MiB budget and zero published DB/internal ports."""

    def setUp(self) -> None:
        self.base_path = REPO_ROOT / "compose.yaml"
        self.prod_path = REPO_ROOT / "compose.production.yaml"
        self.assertTrue(self.base_path.is_file(), f"Missing {self.base_path}")
        self.assertTrue(self.prod_path.is_file(), f"Missing {self.prod_path}")
        self.base_doc = _parse_compose_services_and_networks(self.base_path)
        self.prod_doc = _parse_compose_services_and_networks(self.prod_path)

    def test_production_mem_limit_budget_within_1536_mib_ceiling(self) -> None:
        services = self.prod_doc.get("services") or {}
        expected_services = {"postgres", "paperclip", "hermes", "office-bridge", "office", "vulnclaw"}
        self.assertEqual(set(services.keys()), expected_services)

        limits_mib: dict[str, float] = {}
        reservations_mib: dict[str, float] = {}
        for svc_name, cfg in services.items():
            self.assertIn("mem_limit", cfg, f"Service '{svc_name}' missing mem_limit in compose.production.yaml")
            lim = _parse_mem_mib(cfg["mem_limit"])
            limits_mib[svc_name] = lim
            if "memswap_limit" in cfg:
                self.assertEqual(
                    _parse_mem_mib(cfg["memswap_limit"]),
                    lim,
                    f"Service '{svc_name}' memswap_limit should equal mem_limit to prevent swap thrashing",
                )
            if "mem_reservation" in cfg:
                reservations_mib[svc_name] = _parse_mem_mib(cfg["mem_reservation"])

        core_always_on = ("postgres", "paperclip", "hermes", "office-bridge", "office")
        core_sum_mib = sum(limits_mib[s] for s in core_always_on)
        self.assertLessEqual(
            core_sum_mib,
            1536.0,
            f"Core 5 always-on mem_limit sum ({core_sum_mib} MiB) exceeds 1,536 MiB ceiling",
        )

        # Steady concurrent ceiling = core 5 mem_limit sum + on-demand vulnclaw idle reservation <= 1,536 MiB
        steady_ceiling_mib = core_sum_mib + reservations_mib.get("vulnclaw", 0.0)
        self.assertLessEqual(
            steady_ceiling_mib,
            1536.0,
            f"Steady concurrent ceiling ({steady_ceiling_mib} MiB) exceeds 1,536 MiB ceiling",
        )

        meta_budget = self.prod_doc.get("x-production-resource-budget") or {}
        if "steady_concurrent_ceiling_mib" in meta_budget:
            self.assertLessEqual(float(meta_budget["steady_concurrent_ceiling_mib"]), 1536.0)

    def test_zero_published_db_or_internal_ports_and_loopback_only_bindings(self) -> None:
        internal_only_services = ("postgres", "hermes", "vulnclaw")
        loopback_services = ("paperclip", "office-bridge", "office")
        forbidden_host_ports = {"5432", "3306", "6379"}

        for label, doc in (("compose.yaml", self.base_doc), ("compose.production.yaml", self.prod_doc)):
            services = doc.get("services") or {}
            for int_svc in internal_only_services:
                ports = (services.get(int_svc) or {}).get("ports") or []
                self.assertEqual(
                    ports,
                    [],
                    f"{label}: internal service '{int_svc}' MUST NOT publish any host ports (found {ports})",
                )

            for lb_svc in loopback_services:
                ports = (services.get(lb_svc) or {}).get("ports") or []
                for p_spec in ports:
                    p_str = str(p_spec).strip().strip("'\"")
                    self.assertTrue(
                        p_str.startswith("127.0.0.1:"),
                        f"{label}: service '{lb_svc}' port '{p_str}' must bind strictly to 127.0.0.1",
                    )
                    for bad_port in forbidden_host_ports:
                        self.assertFalse(
                            f":{bad_port}:" in p_str or p_str.endswith(f":{bad_port}"),
                            f"{label}: forbidden DB port {bad_port} exposed in '{p_str}'",
                        )

        # Verify air-gapped internal data network and hardened vulnclaw sandbox
        networks = self.base_doc.get("networks") or {}
        self.assertIn("allinagent_data", networks)
        self.assertIs((networks["allinagent_data"] or {}).get("internal"), True)

        for doc in (self.base_doc, self.prod_doc):
            vc = (doc.get("services") or {}).get("vulnclaw") or {}
            self.assertIs(vc.get("read_only"), True)
            self.assertIn("ALL", vc.get("cap_drop") or [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
