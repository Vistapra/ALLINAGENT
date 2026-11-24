#!/usr/bin/env python3
"""Unit test suite for Phase 16 `capability_discovery.py` and `windows_runner_agent.py`."""

from __future__ import annotations

import secrets
import sys
import tempfile
import unittest
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from capability_discovery import (  # noqa: E402
    detect_capability_matrix,
    resolve_capability_request,
    run_self_checks as run_discovery_self_checks,
    validate_connected_device_url,
    validate_server_workspace_path,
)
from windows_runner_agent import (  # noqa: E402
    AuthorizedWindowsRootsJail,
    HmacReplayGuard,
    enforce_least_privilege,
    run_self_checks as run_runner_self_checks,
    validate_private_bind_host,
)


class ConnectedWorkspaceUnitTests(unittest.TestCase):
    def test_discovery_self_checks(self) -> None:
        res = run_discovery_self_checks()
        self.assertTrue(res["ok"])
        self.assertGreaterEqual(res["total_checks"], 7)

    def test_windows_runner_self_checks(self) -> None:
        res = run_runner_self_checks()
        self.assertTrue(res["ok"])
        self.assertGreaterEqual(res["total_checks"], 16)

    def test_linux_server_workspace_symlink_escape_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ws = base / "workspaces"
            secret_outside = base / "outside"
            ws.mkdir()
            secret_outside.mkdir()
            target_file = secret_outside / "data.txt"
            target_file.write_text("outside", encoding="utf-8")

            link_path = ws / "escape_link"
            try:
                link_path.symlink_to(secret_outside, target_is_directory=True)
            except OSError:
                # Windows without developer mode may disallow unprivileged symlink creation; test `..` traversal
                trav = validate_server_workspace_path(
                    str(ws / ".." / "outside" / "data.txt"),
                    authorized_workspaces=[str(ws)],
                    host_os="linux",
                )
                self.assertFalse(trav["ok"])
                self.assertEqual(trav["code"], "OUTSIDE_AUTHORIZED_WORKSPACES")
                return

            esc = validate_server_workspace_path(
                str(link_path / "data.txt"),
                authorized_workspaces=[str(ws)],
                host_os="linux",
            )
            self.assertFalse(esc["ok"])
            self.assertEqual(esc["code"], "OUTSIDE_AUTHORIZED_WORKSPACES")

    def test_bare_drive_root_rejected_in_windows_jail(self) -> None:
        root_anchor = Path.cwd().anchor
        if root_anchor:
            with self.assertRaises(ValueError):
                AuthorizedWindowsRootsJail([root_anchor])

    def test_weak_or_placeholder_hmac_secret_rejected(self) -> None:
        with self.assertRaises(ValueError):
            HmacReplayGuard("too_short")
        with self.assertRaises(ValueError):
            HmacReplayGuard("replace_with_your_shared_secret_0123456789abcdef")

    def test_unpaired_and_offline_never_impair_server_features(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "workspaces"
            ws.mkdir()
            mat = detect_capability_matrix(
                env={
                    "AUTHORIZED_WORKSPACES": str(ws),
                    "CONNECTED_WINDOWS_DEVICE_URL": "http://127.0.0.1:9",
                    "CONNECTED_DEVICE_SHARED_SECRET": secrets.token_hex(32),
                },
                host_os="linux",
                probe_timeout=0.3,
            )
            self.assertTrue(mat["server_features_independent"])
            self.assertTrue(mat["server_workspace"]["available"])
            self.assertTrue(mat["windows_connected_device"]["device_offline"])

            for action in ("posix_terminal", "git", "coding", "build", "test", "source_analysis"):
                verdict = resolve_capability_request(action, target_path=str(ws), matrix=mat)
                self.assertTrue(verdict["allowed"], f"Server feature {action} must work when Windows runner is offline!")
                self.assertEqual(verdict["plane"], "server_workspace")

    def test_url_and_bind_guards(self) -> None:
        self.assertTrue(validate_connected_device_url("http://127.0.0.1:8670")["ok"])
        self.assertTrue(validate_connected_device_url("https://runner.internal.example:8670")["ok"])
        self.assertFalse(validate_connected_device_url("http://8.8.8.8:8670")["ok"])
        with self.assertRaises(ValueError):
            validate_private_bind_host("0.0.0.0")
        with self.assertRaises(PermissionError):
            enforce_least_privilege(is_admin_fn=lambda: True)


if __name__ == "__main__":
    unittest.main()
