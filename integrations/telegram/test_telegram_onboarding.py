#!/usr/bin/env python3
"""Unit tests for Phase 15 Telegram Onboarding, Command Catalog & Unified Portable Plugin."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from integrations.telegram import BUNDLED_PLUGIN_DIR, COMMAND_CATALOG_PATH
from integrations.telegram.telegram_onboarding import (
    check_deployment_onboarding,
    configure_telegram_onboarding,
    main as cli_main,
    mask_bot_token,
    redact_secrets,
    run_self_checks,
    validate_bot_token_syntax,
    validate_command_catalog,
    validate_owner_telegram_id,
    verify_single_poller,
)


def _load_bundled_plugin_module():
    spec = importlib.util.spec_from_file_location(
        "allinagent_unified_company_control",
        BUNDLED_PLUGIN_DIR / "__init__.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TelegramOnboardingUnitTests(unittest.TestCase):
    SYNTHETIC_TOKEN = "123456789" + ":" + ("A" * 35)
    SYNTHETIC_OWNER = "2345678901"
    DENYLIST_OWNER = "1" + ("0" * 9)

    def test_builtin_self_checks(self) -> None:
        res = run_self_checks()
        self.assertTrue(res["ok"])
        self.assertGreaterEqual(res["total_checks"], 15)

    def test_plugin_copies_are_byte_identical(self) -> None:
        repo_root = COMMAND_CATALOG_PATH.parents[2]
        ext_init = repo_root / "agents" / "hermes-extensions" / "plugins" / "unified-company-control" / "__init__.py"
        int_init = BUNDLED_PLUGIN_DIR / "__init__.py"
        self.assertTrue(ext_init.is_file())
        self.assertTrue(int_init.is_file())
        ext_sha = hashlib.sha256(ext_init.read_bytes()).hexdigest()
        int_sha = hashlib.sha256(int_init.read_bytes()).hexdigest()
        self.assertEqual(ext_sha, int_sha)

    def test_command_catalog_structure_and_59_command_parity(self) -> None:
        cat = json.loads(COMMAND_CATALOG_PATH.read_text(encoding="utf-8"))
        self.assertEqual(cat["counts"]["slash_commands"], 59)
        self.assertEqual(len(cat["slash_commands"]), 59)
        self.assertEqual(cat["counts"]["indonesian_nl_intent_rules"], 17)
        self.assertEqual(len(cat["indonesian_nl_intent_rules"]), 17)
        self.assertEqual(cat["counts"]["submenus"], 13)
        self.assertEqual(len(cat["submenus"]), 13)
        self.assertTrue(cat["authorization_rules"]["dm_only_scope"]["enforced"])
        self.assertIn("<YOUR_TELEGRAM_USER_ID>", cat["authorization_rules"]["forbidden_owner_id_values"])
        self.assertIn(
            ".pdf",
            cat["media_and_document_delivery_contracts"]["document_and_report_delivery"]["supported_document_extensions"],
        )
        self.assertIn(
            ".docx",
            cat["media_and_document_delivery_contracts"]["document_and_report_delivery"]["supported_document_extensions"],
        )

        parity = validate_command_catalog()
        self.assertTrue(parity["ok"], parity["errors"])

    def test_owner_id_strictly_rejects_empty_zero_and_placeholders(self) -> None:
        for forbidden in ("", " ", "0", self.DENYLIST_OWNER, "<YOUR_TELEGRAM_USER_ID>", "-987654321", "not_a_number"):
            res = validate_owner_telegram_id(forbidden)
            self.assertFalse(res["ok"], f"Expected rejection for {forbidden!r}")
        valid = validate_owner_telegram_id(self.SYNTHETIC_OWNER)
        self.assertTrue(valid["ok"])
        self.assertEqual(valid["owner_id"], self.SYNTHETIC_OWNER)

    def test_bot_token_regex_and_redaction(self) -> None:
        self.assertTrue(validate_bot_token_syntax(self.SYNTHETIC_TOKEN)["ok"])
        self.assertFalse(validate_bot_token_syntax("999:too_short")["ok"])
        placeholder_tok = "12345678" + ":" + "your_bot_token_placeholder_" + ("0" * 10)
        self.assertFalse(validate_bot_token_syntax(placeholder_tok)["ok"])
        masked = mask_bot_token(self.SYNTHETIC_TOKEN)
        self.assertNotIn("A" * 20, masked)
        scrubbed = redact_secrets(f"Error calling https://api.telegram.org/bot{self.SYNTHETIC_TOKEN}/getMe")
        self.assertNotIn("A" * 20, scrubbed)

    def test_single_poller_split_brain_and_container_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hh = Path(tmp)
            (hh / "gateway.pid").write_text(json.dumps({"pid": 1001, "start_time": 10.0}), encoding="utf-8")
            (hh / "gateway.lock").write_text(json.dumps({"pid": 1002, "start_time": 20.0}), encoding="utf-8")
            split = verify_single_poller(
                hh,
                process_list=[],
                container_list=[],
                pid_alive_fn=lambda _: True,
            )
            self.assertFalse(split["ok"])
            self.assertEqual(split["code"], "DUPLICATE_POLLER_CONFLICT")

            # Clean single poller
            (hh / "gateway.pid").write_text(json.dumps({"pid": 1001, "start_time": 10.0}), encoding="utf-8")
            (hh / "gateway.lock").write_text(json.dumps({"pid": 1001, "start_time": 10.0}), encoding="utf-8")
            clean = verify_single_poller(
                hh,
                process_list=[{"pid": 1001, "ppid": 1, "command": "hermes gateway run"}],
                container_list=[],
                pid_alive_fn=lambda p: p == 1001,
            )
            self.assertTrue(clean["ok"])
            self.assertEqual(clean["active_poller_count"], 1)

    def test_cli_modes_offline_configure_and_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "allinagent"
            hh = Path(tmp) / "hermes"
            secrets_dir = Path(tmp) / "secrets"
            root.mkdir()
            secrets_dir.mkdir()
            (root / "config" / "secrets").mkdir(parents=True)
            (root / "config" / "secrets" / "office-bridge-auth.json").write_text(
                json.dumps(
                    {
                        "bridgeToken": "ob_test_123",
                        "studioAccessToken": "st_test_123",
                        "allowedOwnerId": self.DENYLIST_OWNER,
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.dict(os.environ, {"ALLINAGENT_SECRETS_DIR": str(secrets_dir)}, clear=False):
                rc_off = cli_main(
                    [
                        "--offline-validate",
                        "--bot-token",
                        self.SYNTHETIC_TOKEN,
                        "--owner-id",
                        self.SYNTHETIC_OWNER,
                        "--json",
                    ]
                )
                self.assertEqual(rc_off, 0)

                cfg = configure_telegram_onboarding(
                    bot_token=self.SYNTHETIC_TOKEN,
                    owner_id=self.SYNTHETIC_OWNER,
                    platform_root=root,
                    hermes_home=hh,
                    online_check=False,
                    scan_host_processes=False,
                    scan_docker_containers=False,
                )
                self.assertTrue(cfg["ok"])
                self.assertTrue(cfg["office_bridge_auth_synced"])

                chk = check_deployment_onboarding(
                    platform_root=root,
                    hermes_home=hh,
                    scan_host_processes=False,
                    scan_docker_containers=False,
                )
                self.assertTrue(chk["ok"])

    def test_bundled_plugin_registers_59_commands_dm_only_media_and_secrets_precedence(self) -> None:
        plugin_mod = _load_bundled_plugin_module()

        class _DummyCtx:
            profile_name = "default"

            def __init__(self) -> None:
                self.commands: dict[str, Any] = {}
                self.tools: list[str] = []
                self.hooks: list[str] = []
                self.tg_wired = False

            def register_tool(self, **kwargs: Any) -> None:
                self.tools.append(kwargs["name"])

            def register_hook(self, name: str, _fn: Any) -> None:
                self.hooks.append(name)

            def register_telegram_handler(self, _fn: Any) -> None:
                self.tg_wired = True

            def register_command(self, slug: str, handler: Any, **_kwargs: Any) -> None:
                self.commands[slug] = handler

        ctx = _DummyCtx()
        plugin_mod.register(ctx)
        self.assertEqual(len(ctx.commands), 59)
        self.assertIn("unified_company_control", ctx.tools)
        self.assertIn("post_gateway_admission", ctx.hooks)
        self.assertTrue(ctx.tg_wired)

        with tempfile.TemporaryDirectory() as tmp:
            hh = Path(tmp) / "hermes"
            root = Path(tmp) / "root"
            reports_dir = Path(tmp) / "reports"
            ext_ws = Path(tmp) / "authorized-ws"
            outside_dir = Path(tmp) / "outside-untrusted"
            secrets_dir = Path(tmp) / "secrets"
            for d in (hh, root, reports_dir, ext_ws, outside_dir, secrets_dir):
                d.mkdir(parents=True, exist_ok=True)

            env_patch = {
                "HERMES_HOME": str(hh),
                "ALLINAGENT_ROOT": str(root),
                "ALLINAGENT_REPORTS_ROOT": str(reports_dir),
                "AUTHORIZED_WORKSPACES": str(ext_ws),
                "ALLINAGENT_SECRETS_DIR": str(secrets_dir),
                "TELEGRAM_BOT_TOKEN": self.SYNTHETIC_TOKEN,
            }
            with mock.patch.dict(os.environ, env_patch, clear=False):
                os.environ.pop("OFFICE_BRIDGE_TOKEN", None)
                os.environ.pop("OFFICE_BRIDGE_AUTH_TOKEN", None)

                # Reject placeholder owner ID fail-closed
                os.environ["OWNER_TELEGRAM_ID"] = self.DENYLIST_OWNER
                msg_unconf = ctx.commands["kantor"](
                    "",
                    source={"user_id": self.DENYLIST_OWNER, "chat_id": self.DENYLIST_OWNER, "chat_type": "private"},
                    platform="telegram",
                )
                self.assertIn("belum dikonfigurasi", msg_unconf)

                # Enforce Owner ID + DM-only
                os.environ["OWNER_TELEGRAM_ID"] = self.SYNTHETIC_OWNER
                msg_stranger = ctx.commands["kantor"](
                    "",
                    source={"user_id": "99999999", "chat_id": "99999999", "chat_type": "private"},
                    platform="telegram",
                )
                self.assertIn("Akses ditolak", msg_stranger)

                msg_group = ctx.commands["kantor"](
                    "",
                    source={"user_id": self.SYNTHETIC_OWNER, "chat_id": "-100999888", "chat_type": "supergroup"},
                    platform="telegram",
                )
                self.assertIn("DM Owner", msg_group)

                # Token precedence: ALLINAGENT_SECRETS_DIR -> env override wins
                (secrets_dir / "office-bridge-auth.json").write_text(
                    json.dumps({"bridgeToken": "tok_from_secrets_dir"}),
                    encoding="utf-8",
                )
                self.assertEqual(plugin_mod._runtime_settings()["bridge_token"], "tok_from_secrets_dir")
                os.environ["OFFICE_BRIDGE_TOKEN"] = "tok_from_env_primary"
                self.assertEqual(plugin_mod._runtime_settings()["bridge_token"], "tok_from_env_primary")

                # Outbound attachment path safety checks
                secret_file = root / ".env"
                secret_file.write_text("SECRET=1\n", encoding="utf-8")
                self.assertFalse(plugin_mod._is_safe_outbound_file(secret_file))
                self.assertFalse(plugin_mod._is_safe_outbound_file(secrets_dir / "office-bridge-auth.json"))

                outside_pdf = outside_dir / "escape.pdf"
                outside_pdf.write_bytes(b"%PDF-1.4\noutside\n")
                self.assertFalse(plugin_mod._is_safe_outbound_file(outside_pdf))

                report_pdf = reports_dir / "exec-report.pdf"
                report_pdf.write_bytes(b"%PDF-1.4\nreport\n")
                self.assertTrue(plugin_mod._is_safe_outbound_file(report_pdf))

                ws_docx = ext_ws / "summary.docx"
                ws_docx.write_bytes(b"PK\x03\x04docxcontent")
                self.assertTrue(plugin_mod._is_safe_outbound_file(ws_docx))

                # photo_base64 & document delivery via _deliver_bridge_attachments
                delivered_urls: list[str] = []

                class _OkUploadResp:
                    def read(self) -> bytes:
                        return b'{"ok": true}'

                    def __enter__(self):
                        return self

                    def __exit__(self, *_: Any) -> None:
                        return None

                def _fake_urlopen(req: Any, timeout: float = 10.0) -> _OkUploadResp:
                    delivered_urls.append(req.full_url)
                    return _OkUploadResp()

                with mock.patch.object(plugin_mod.urllib.request, "urlopen", side_effect=_fake_urlopen):
                    png_b64 = base64.b64encode(b"\x89PNG\r\n\x1a\nsynthetic").decode("ascii")
                    ok_photo = plugin_mod._deliver_bridge_attachments(
                        self.SYNTHETIC_OWNER,
                        {"photo_base64": png_b64},
                        "Live 3D Screenshot",
                        None,
                    )
                    self.assertTrue(ok_photo)
                    self.assertTrue(any(u.endswith("/sendPhoto") for u in delivered_urls))

                    ok_doc = plugin_mod._deliver_bridge_attachments(
                        self.SYNTHETIC_OWNER,
                        {"document_path": str(report_pdf)},
                        "Audit Report PDF",
                        None,
                    )
                    self.assertTrue(ok_doc)
                    self.assertTrue(any(u.endswith("/sendDocument") for u in delivered_urls))


if __name__ == "__main__":
    unittest.main()
