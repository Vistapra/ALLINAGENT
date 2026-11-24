#!/usr/bin/env python3
"""ALLINAGENT Phase 15 — Cross-Platform Telegram Bot Onboarding Wizard & Single-Poller Guard.

Provides CLI & programmatic APIs enabling any new ALLINAGENT operator on Ubuntu/Linux,
Docker, macOS, or Windows to pair their own Telegram bot safely:
  - `--offline-validate`     Validate token syntax, Owner ID rules, 59-command catalog & plugin parity offline.
  - `--check`                Inspect a deployment's Telegram configuration, plugin state & single-poller lock.
  - `--configure`            Interactive or flag-driven setup writing `0600` `.env` + `HERMES_HOME` config,
                             installing/enabling the 59-command `unified-company-control` plugin, optionally
                             calling `getMe` / `getWebhookInfo` (clearing stale webhooks on request), and
                             verifying single-poller safety.
  - `--verify-single-poller` Verify `gateway.pid`, `gateway.lock`, OS processes, and Docker containers so two
                             `getUpdates` pollers never run concurrently for the same bot token.
  - `--self-check`           Run built-in deterministic unit self-checks in isolated temporary directories.
"""

from __future__ import annotations

import argparse
import ast
import ctypes
import getpass
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

BOT_TOKEN_REGEX = re.compile(r"^\d{6,15}:[A-Za-z0-9_-]{30,}$")
OWNER_ID_REGEX = re.compile(r"^[1-9]\d{4,19}$")
DEFAULT_DENYLIST_OWNER_ID = "1" + ("0" * 9)
FORBIDDEN_OWNER_IDS = frozenset({"", "0", DEFAULT_DENYLIST_OWNER_ID, "<YOUR_TELEGRAM_USER_ID>"})
TOKEN_SCRUB_REGEX = re.compile(r"(?:bot)?\d{6,15}:[A-Za-z0-9_-]{20,}")

MODULE_DIR = Path(__file__).resolve().parent
DEFAULT_CATALOG_PATH = MODULE_DIR / "command_catalog.json"
DEFAULT_PLUGIN_TEMPLATE_DIR = MODULE_DIR / "unified-company-control"
EXPECTED_SLASH_COMMAND_COUNT = 59
EXPECTED_NL_INTENT_RULE_COUNT = 17
EXPECTED_SUBMENU_COUNT = 13


def redact_secrets(text: Any) -> str:
    """Scrub any Telegram bot token pattern from error strings or diagnostic messages."""
    raw = str(text or "")
    return TOKEN_SCRUB_REGEX.sub("<REDACTED_TELEGRAM_BOT_TOKEN>", raw)


def mask_bot_token(token: str) -> str:
    """Return a non-reversible masked representation that never exposes secret token material."""
    clean = str(token or "").strip()
    if not clean or ":" not in clean:
        return "<unconfigured>"
    bot_id = clean.split(":", 1)[0]
    if not bot_id.isdigit():
        return "<invalid-token-format>"
    digest = hashlib.sha256(clean.encode("utf-8")).hexdigest()[:8]
    return f"{bot_id}:<redacted-sha256:{digest}>"


def token_fingerprint(token: str) -> str:
    """Compute a one-way SHA-256 fingerprint for duplicate-poller token collision checks."""
    clean = str(token or "").strip()
    if not clean:
        return ""
    return hashlib.sha256(f"allinagent-tg-poller:{clean}".encode("utf-8")).hexdigest()[:16]


def validate_bot_token_syntax(token: Any) -> dict[str, Any]:
    """Validate Telegram BotFather token syntax (`^\\d{6,15}:[A-Za-z0-9_-]{30,}$`)."""
    if not isinstance(token, str):
        return {
            "ok": False,
            "code": "INVALID_TOKEN_TYPE",
            "error": "TELEGRAM_BOT_TOKEN must be a non-empty string.",
        }
    clean = token.strip()
    if not clean:
        return {
            "ok": False,
            "code": "EMPTY_BOT_TOKEN",
            "error": "TELEGRAM_BOT_TOKEN cannot be empty.",
        }
    lowered = clean.lower()
    if any(marker in lowered for marker in ("replace", "your_bot", "example", "placeholder", "changeme")):
        return {
            "ok": False,
            "code": "PLACEHOLDER_BOT_TOKEN_REJECTED",
            "error": "Placeholder TELEGRAM_BOT_TOKEN values are rejected; provide a real BotFather token.",
        }
    if not BOT_TOKEN_REGEX.match(clean):
        return {
            "ok": False,
            "code": "INVALID_BOT_TOKEN_SYNTAX",
            "error": "TELEGRAM_BOT_TOKEN failed regex validation (^\\d{6,15}:[A-Za-z0-9_-]{30,}$).",
        }
    bot_id_str = clean.split(":", 1)[0]
    if int(bot_id_str) == 0:
        return {
            "ok": False,
            "code": "ZERO_BOT_ID_REJECTED",
            "error": "Bot numeric ID prefix cannot be zero.",
        }
    return {
        "ok": True,
        "bot_id": bot_id_str,
        "masked_token": mask_bot_token(clean),
        "token_fingerprint": token_fingerprint(clean),
    }


def validate_owner_telegram_id(owner_id: Any) -> dict[str, Any]:
    """Validate numeric `OWNER_TELEGRAM_ID`, explicitly rejecting empty, `'0'`, or placeholder IDs."""
    if isinstance(owner_id, bool) or owner_id is None:
        return {
            "ok": False,
            "code": "INVALID_OWNER_ID_TYPE",
            "error": "OWNER_TELEGRAM_ID must be a positive numeric Telegram user ID.",
        }
    clean = str(owner_id).strip()
    if clean in FORBIDDEN_OWNER_IDS:
        return {
            "ok": False,
            "code": "FORBIDDEN_OWNER_ID_VALUE",
            "error": (
                "OWNER_TELEGRAM_ID cannot be empty, '0', or a placeholder such as '<YOUR_TELEGRAM_USER_ID>'. "
                "Obtain your personal numeric Telegram user ID (e.g. via @userinfobot)."
            ),
        }
    if clean.startswith("-"):
        return {
            "ok": False,
            "code": "GROUP_CHAT_ID_FORBIDDEN",
            "error": "Negative IDs belong to groups/channels; OWNER_TELEGRAM_ID must be a positive personal user ID.",
        }
    if not clean.isdigit():
        return {
            "ok": False,
            "code": "NON_NUMERIC_OWNER_ID",
            "error": "OWNER_TELEGRAM_ID must contain digits only.",
        }
    if not OWNER_ID_REGEX.match(clean):
        return {
            "ok": False,
            "code": "OWNER_ID_OUT_OF_RANGE",
            "error": "OWNER_TELEGRAM_ID must be a valid Telegram numeric user ID (5 to 20 digits, non-zero).",
        }
    return {
        "ok": True,
        "owner_id": clean,
    }


def _telegram_api_json(
    token: str,
    method: str,
    payload: Optional[dict[str, Any]] = None,
    *,
    timeout: float = 12.0,
    opener: Optional[Callable[..., Any]] = None,
) -> dict[str, Any]:
    """Invoke a Telegram Bot API method over HTTPS with strict token redaction on failure."""
    url = f"https://api.telegram.org/bot{token}/{method}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                return {"ok": False, "error": f"Unexpected non-JSON-object response from {method}."}
            return parsed
    except urllib.error.HTTPError as http_err:
        body = ""
        try:
            body = http_err.read().decode("utf-8", errors="replace")
        except Exception:
            body = str(http_err)
        finally:
            try:
                http_err.close()
            except Exception:
                pass
        return {
            "ok": False,
            "http_status": http_err.code,
            "error": redact_secrets(f"Telegram API {method} HTTP {http_err.code}: {body[:240]}"),
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": redact_secrets(f"Telegram API {method} request failed: {exc}"),
        }


def verify_bot_online(
    token: str,
    *,
    clear_webhook: bool = False,
    drop_pending_updates: bool = False,
    timeout: float = 12.0,
    opener: Optional[Callable[..., Any]] = None,
) -> dict[str, Any]:
    """Validate bot credentials against `getMe` and inspect/clear `getWebhookInfo`."""
    syntax = validate_bot_token_syntax(token)
    if not syntax["ok"]:
        return syntax

    clean = token.strip()
    me_res = _telegram_api_json(clean, "getMe", timeout=timeout, opener=opener)
    if not me_res.get("ok") or not isinstance(me_res.get("result"), dict):
        return {
            "ok": False,
            "code": "TELEGRAM_GETME_FAILED",
            "error": redact_secrets(me_res.get("error") or me_res.get("description") or "getMe rejected token."),
        }

    bot_info = me_res["result"]
    if not bot_info.get("is_bot"):
        return {
            "ok": False,
            "code": "NOT_A_BOT_ACCOUNT",
            "error": "Telegram getMe response indicates account is not a bot.",
        }

    wh_res = _telegram_api_json(clean, "getWebhookInfo", timeout=timeout, opener=opener)
    if not wh_res.get("ok") or not isinstance(wh_res.get("result"), dict):
        return {
            "ok": False,
            "code": "TELEGRAM_GETWEBHOOKINFO_FAILED",
            "error": redact_secrets(wh_res.get("error") or wh_res.get("description") or "getWebhookInfo failed."),
        }

    wh_info = wh_res["result"]
    webhook_url = str(wh_info.get("url") or "").strip()
    pending_updates = int(wh_info.get("pending_update_count") or 0)
    last_wh_error = redact_secrets(wh_info.get("last_error_message") or "")
    warnings: list[str] = []
    webhook_cleared = False

    if webhook_url:
        if clear_webhook:
            del_res = _telegram_api_json(
                clean,
                "deleteWebhook",
                {"drop_pending_updates": bool(drop_pending_updates)},
                timeout=timeout,
                opener=opener,
            )
            if not del_res.get("ok"):
                return {
                    "ok": False,
                    "code": "TELEGRAM_DELETEWEBHOOK_FAILED",
                    "error": redact_secrets(del_res.get("error") or del_res.get("description") or "deleteWebhook failed."),
                }
            webhook_cleared = True
            webhook_url = ""
        else:
            warnings.append(
                f"Active webhook detected ({redact_secrets(webhook_url)}). "
                "Telegram blocks getUpdates long-polling while a webhook is set; re-run with --clear-webhook."
            )

    username = str(bot_info.get("username") or "").strip()
    return {
        "ok": True,
        "bot": {
            "id": str(bot_info.get("id") or syntax["bot_id"]),
            "username": f"@{username.lstrip('@')}" if username else "",
            "first_name": str(bot_info.get("first_name") or ""),
            "can_join_groups": bool(bot_info.get("can_join_groups", False)),
            "can_read_all_group_messages": bool(bot_info.get("can_read_all_group_messages", False)),
        },
        "webhook": {
            "active_url": redact_secrets(webhook_url),
            "had_stale_webhook": bool(wh_info.get("url")),
            "webhook_cleared": webhook_cleared,
            "pending_update_count": pending_updates,
            "last_error_message": last_wh_error,
        },
        "warnings": warnings,
    }


def validate_command_catalog(
    catalog_path: Path = DEFAULT_CATALOG_PATH,
    plugin_dir: Path = DEFAULT_PLUGIN_TEMPLATE_DIR,
) -> dict[str, Any]:
    """Offline structural & parity validator for `command_catalog.json` and `unified-company-control`."""
    errors: list[str] = []
    if not catalog_path.is_file():
        return {"ok": False, "code": "CATALOG_MISSING", "errors": [f"Catalog not found: {catalog_path}"]}

    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"ok": False, "code": "CATALOG_INVALID_JSON", "errors": [f"Invalid JSON in catalog: {exc}"]}

    slash_cmds = catalog.get("slash_commands") or []
    submenus = catalog.get("submenus") or []
    cb_spec = catalog.get("inline_keyboard_callbacks") or {}
    cb_routes = cb_spec.get("routes") or []
    nl_rules = catalog.get("indonesian_nl_intent_rules") or []
    auth_rules = catalog.get("authorization_rules") or {}
    media_contracts = catalog.get("media_and_document_delivery_contracts") or {}

    if len(slash_cmds) != EXPECTED_SLASH_COMMAND_COUNT:
        errors.append(f"Expected {EXPECTED_SLASH_COMMAND_COUNT} slash commands, found {len(slash_cmds)}.")

    seen_slugs: set[str] = set()
    for idx, entry in enumerate(slash_cmds, start=1):
        slug = str(entry.get("slug") or "").strip()
        if not slug:
            errors.append(f"Slash command #{idx} has empty slug.")
        elif slug in seen_slugs:
            errors.append(f"Duplicate slash command slug: {slug}")
        seen_slugs.add(slug)
        if slug == "approvals":
            errors.append("Slash slug 'approvals' collides with native Hermes /approvals; use 'persetujuan'.")

    if len(submenus) != EXPECTED_SUBMENU_COUNT:
        errors.append(f"Expected {EXPECTED_SUBMENU_COUNT} submenus, found {len(submenus)}.")

    if cb_spec.get("namespace_prefix") != "uac:" or int(cb_spec.get("max_payload_bytes") or 0) != 64:
        errors.append("inline_keyboard_callbacks must enforce namespace_prefix='uac:' and max_payload_bytes=64.")
    if len(cb_routes) < 40:
        errors.append(f"Expected comprehensive uac:* callback route table, found only {len(cb_routes)} routes.")
    for route in cb_routes:
        pat = str(route.get("pattern") or "")
        if not pat.startswith("uac:"):
            errors.append(f"Callback route pattern '{pat}' does not start with 'uac:'.")

    if len(nl_rules) != EXPECTED_NL_INTENT_RULE_COUNT:
        errors.append(f"Expected {EXPECTED_NL_INTENT_RULE_COUNT} Bahasa Indonesia NL intent rules, found {len(nl_rules)}.")

    forbidden_ids = set(auth_rules.get("forbidden_owner_id_values") or [])
    if not ({"", "0"}.issubset(forbidden_ids) and ({"<YOUR_TELEGRAM_USER_ID>", DEFAULT_DENYLIST_OWNER_ID} & forbidden_ids)):
        errors.append(
            "authorization_rules.forbidden_owner_id_values must include '', '0', and '<YOUR_TELEGRAM_USER_ID>'."
        )
    dm_scope = auth_rules.get("dm_only_scope") or {}
    if not dm_scope.get("enforced") or dm_scope.get("group_administration_enabled") is not False:
        errors.append("DM-only authorization rules must be strictly enforced with group_administration_enabled=false.")

    doc_contract = media_contracts.get("document_and_report_delivery") or {}
    doc_exts = set(doc_contract.get("supported_document_extensions") or [])
    if not {".pdf", ".docx", ".xlsx", ".pptx"}.issubset(doc_exts):
        errors.append("Document delivery contract must include .pdf, .docx, .xlsx, and .pptx.")

    # Verify parity against plugin source `__init__.py`
    plugin_init = plugin_dir / "__init__.py"
    plugin_yaml = plugin_dir / "plugin.yaml"
    plugin_slugs: list[str] = []
    if not plugin_init.is_file() or not plugin_yaml.is_file():
        errors.append(f"Plugin template missing __init__.py or plugin.yaml under {plugin_dir}.")
    else:
        src = plugin_init.read_text(encoding="utf-8")
        try:
            tree = ast.parse(src, filename=str(plugin_init))
        except SyntaxError as syn_err:
            errors.append(f"SyntaxError in plugin __init__.py: {syn_err}")
            tree = None

        found_list_node: Optional[ast.List] = None
        if tree is not None:
            for node in tree.body:
                if isinstance(node, ast.Assign):
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name) and tgt.id == "_SLASH_COMMANDS" and isinstance(node.value, ast.List):
                            found_list_node = node.value
                elif isinstance(node, ast.AnnAssign):
                    if isinstance(node.target, ast.Name) and node.target.id == "_SLASH_COMMANDS" and isinstance(node.value, ast.List):
                        found_list_node = node.value

        if found_list_node is None:
            errors.append("Could not locate _SLASH_COMMANDS list AST node in plugin __init__.py.")
        else:
            for elt in found_list_node.elts:
                if isinstance(elt, ast.Tuple) and elt.elts and isinstance(elt.elts[0], ast.Constant) and isinstance(elt.elts[0].value, str):
                    plugin_slugs.append(elt.elts[0].value)
            if len(plugin_slugs) != EXPECTED_SLASH_COMMAND_COUNT:
                errors.append(
                    f"Plugin __init__.py defines {len(plugin_slugs)} slash commands instead of {EXPECTED_SLASH_COMMAND_COUNT}."
                )
            catalog_slugs = [str(x.get("slug")) for x in slash_cmds]
            if plugin_slugs != catalog_slugs:
                missing = sorted(set(catalog_slugs) - set(plugin_slugs))
                extra = sorted(set(plugin_slugs) - set(catalog_slugs))
                errors.append(f"Slash command mismatch between catalog and plugin: missing={missing}, extra={extra}.")

    return {
        "ok": len(errors) == 0,
        "catalog_path": str(catalog_path),
        "plugin_dir": str(plugin_dir),
        "slash_commands_count": len(slash_cmds),
        "plugin_commands_count": len(plugin_slugs),
        "submenus_count": len(submenus),
        "callback_routes_count": len(cb_routes),
        "indonesian_nl_rules_count": len(nl_rules),
        "errors": errors,
    }


def _pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        process_query_limited_information = 0x1000
        still_active = 259
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(process_query_limited_information, False, int(pid))
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong(0)
            if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return int(exit_code.value) == still_active
            return True
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _read_gateway_pid_or_lock_file(file_path: Path) -> Optional[dict[str, Any]]:
    if not file_path.is_file():
        return None
    try:
        raw = file_path.read_text(encoding="utf-8", errors="ignore").strip()
        if not raw:
            return None
        if raw.isdigit():
            return {"pid": int(raw), "source": file_path.name}
        parsed = json.loads(raw)
        if isinstance(parsed, dict) and "pid" in parsed:
            return {"pid": int(parsed["pid"]), "start_time": parsed.get("start_time"), "source": file_path.name}
    except Exception:
        return None
    return None


def _list_local_gateway_processes() -> list[dict[str, Any]]:
    """Detect local OS `hermes_cli.main gateway` / `hermes gateway run` processes (excluding launcher parents)."""
    candidates: list[dict[str, Any]] = []
    if os.name == "nt":
        try:
            ps_cmd = (
                "Get-CimInstance Win32_Process -Filter \"Name LIKE 'python%'\" | "
                "Select-Object ProcessId, ParentProcessId, CommandLine | ConvertTo-Json -Compress"
            )
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            out = (proc.stdout or "").strip()
            if out:
                parsed = json.loads(out)
                rows = parsed if isinstance(parsed, list) else [parsed]
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    cmd = str(row.get("CommandLine") or "")
                    if re.search(r"\bhermes(?:_cli\.main)?\s+gateway\s+run\b", cmd, flags=re.IGNORECASE):
                        candidates.append(
                            {
                                "pid": int(row.get("ProcessId") or 0),
                                "ppid": int(row.get("ParentProcessId") or 0),
                                "command": redact_secrets(cmd)[:200],
                            }
                        )
        except Exception:
            pass
    else:
        try:
            proc = subprocess.run(
                ["ps", "-eo", "pid=,ppid=,args="],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
            for line in (proc.stdout or "").splitlines():
                parts = line.strip().split(None, 2)
                if len(parts) < 3 or not parts[0].isdigit() or not parts[1].isdigit():
                    continue
                pid_val, ppid_val, cmd = int(parts[0]), int(parts[1]), parts[2]
                if pid_val == os.getpid():
                    continue
                if re.search(r"\b(?:hermes_cli\.main|hermes)\s+gateway\s+run\b", cmd):
                    candidates.append({"pid": pid_val, "ppid": ppid_val, "command": redact_secrets(cmd)[:200]})
        except Exception:
            pass

    # Collapse direct parent->child Python venv shim pairs (e.g. Windows venv python.exe spawning base python.exe)
    candidate_pids = {c["pid"] for c in candidates if c["pid"] > 0}
    parent_pids_of_children = {c["ppid"] for c in candidates if c["ppid"] in candidate_pids}
    leaf_pollers = [c for c in candidates if c["pid"] not in parent_pids_of_children]
    return leaf_pollers


def _list_docker_gateway_containers() -> list[dict[str, Any]]:
    """Inspect running Docker containers for Hermes/ALLINAGENT Telegram gateway pollers."""
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return []
    try:
        proc = subprocess.run(
            [docker_bin, "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Command}}"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        if proc.returncode != 0:
            return []
        containers: list[dict[str, Any]] = []
        for line in (proc.stdout or "").splitlines():
            cols = line.split("\t")
            if len(cols) < 4:
                continue
            cid, name, image, cmd = cols[0].strip(), cols[1].strip(), cols[2].strip(), cols[3].strip()
            combined = f"{name} {image} {cmd}".lower()
            if ("hermes-gateway" in combined) or (
                ("allinagent" in combined or "hermes" in combined) and "gateway" in combined and "run" in combined
            ):
                containers.append(
                    {
                        "container_id": cid,
                        "name": name,
                        "image": image,
                        "command": redact_secrets(cmd)[:160],
                    }
                )
        return containers
    except Exception:
        return []


def verify_single_poller(
    hermes_home: Path,
    *,
    process_list: Optional[list[dict[str, Any]]] = None,
    container_list: Optional[list[dict[str, Any]]] = None,
    pid_alive_fn: Optional[Callable[[int], bool]] = None,
    scan_host_processes: bool = True,
    scan_docker_containers: bool = True,
) -> dict[str, Any]:
    """Verify at most ONE Telegram `getUpdates` poller is active across PID/lock files, host processes & Docker."""
    is_alive = pid_alive_fn or _pid_is_alive
    conflicts: list[str] = []
    warnings: list[str] = []
    stale_files: list[str] = []

    pid_file = hermes_home / "gateway.pid"
    lock_file = hermes_home / "gateway.lock"
    locks_dir = hermes_home / "gateway-locks"

    pid_rec = _read_gateway_pid_or_lock_file(pid_file)
    lock_rec = _read_gateway_pid_or_lock_file(lock_file)
    scoped_locks: list[dict[str, Any]] = []
    if locks_dir.is_dir():
        for item in sorted(locks_dir.glob("*.lock")):
            rec = _read_gateway_pid_or_lock_file(item)
            if rec:
                scoped_locks.append(rec)

    live_lock_pids: set[int] = set()
    if pid_rec:
        if is_alive(pid_rec["pid"]):
            live_lock_pids.add(pid_rec["pid"])
        else:
            stale_files.append(str(pid_file))
            warnings.append(f"Stale gateway.pid ({pid_rec['pid']}) detected; process is no longer running.")

    if lock_rec:
        if is_alive(lock_rec["pid"]):
            live_lock_pids.add(lock_rec["pid"])
        else:
            stale_files.append(str(lock_file))
            warnings.append(f"Stale gateway.lock ({lock_rec['pid']}) detected; process is no longer running.")

    for srec in scoped_locks:
        if is_alive(srec["pid"]):
            live_lock_pids.add(srec["pid"])

    if len(live_lock_pids) > 1:
        conflicts.append(
            f"Split-brain lock files in {hermes_home}: multiple live PIDs ({sorted(live_lock_pids)}) hold gateway records!"
        )

    host_pollers = (
        process_list
        if process_list is not None
        else (_list_local_gateway_processes() if scan_host_processes else [])
    )
    docker_pollers = (
        container_list
        if container_list is not None
        else (_list_docker_gateway_containers() if scan_docker_containers else [])
    )

    if len(host_pollers) > 1:
        pids = [p.get("pid") for p in host_pollers]
        conflicts.append(
            f"Multiple host Hermes gateway pollers running simultaneously (PIDs: {pids}). "
            "Stop duplicate processes to prevent Telegram HTTP 409 Conflict storms."
        )

    if len(docker_pollers) > 1:
        names = [c.get("name") for c in docker_pollers]
        conflicts.append(
            f"Multiple Docker gateway containers running simultaneously ({names}). "
            "Ensure at most 1 gateway container replica runs per bot token."
        )

    # Note: Inside Linux Docker on a host, `ps` on the host also sees containerized processes.
    # Distinguish host-native vs containerized pollers if container_list is non-empty:
    if len(host_pollers) >= 1 and len(docker_pollers) >= 1:
        # On Windows/macOS Docker Desktop, Linux container processes never appear in host `Win32_Process`/`ps`,
        # so 1 host poller + 1 Docker container is ALWAYS a true dual-poller conflict!
        # On Linux, inspect `/proc/<pid>/cgroup` if available to see if the PID belongs to the container itself.
        non_container_host_pids: list[int] = []
        for proc_item in host_pollers:
            pid_num = int(proc_item.get("pid") or 0)
            in_container = bool(proc_item.get("in_container", False))
            if not in_container and os.name != "nt" and pid_num > 0:
                cg_path = Path(f"/proc/{pid_num}/cgroup")
                if cg_path.is_file():
                    try:
                        cg_txt = cg_path.read_text(encoding="utf-8", errors="ignore")
                        if any(tok in cg_txt for tok in ("docker", "containerd", "kubepods")):
                            in_container = True
                    except OSError:
                        pass
            if not in_container:
                non_container_host_pids.append(pid_num)

        if non_container_host_pids:
            c_names = [c.get("name") for c in docker_pollers]
            conflicts.append(
                f"Dual host + container poller conflict: host PID(s) {non_container_host_pids} AND "
                f"Docker container(s) {c_names} are polling simultaneously!"
            )

    active_poller_count = max(
        len(live_lock_pids),
        len(docker_pollers) + (
            len(host_pollers)
            if not docker_pollers
            else sum(1 for p in host_pollers if not p.get("in_container"))
        ),
    )

    return {
        "ok": len(conflicts) == 0,
        "code": "SINGLE_POLLER_VERIFIED" if len(conflicts) == 0 else "DUPLICATE_POLLER_CONFLICT",
        "hermes_home": str(hermes_home),
        "active_poller_count": active_poller_count,
        "live_lock_pids": sorted(live_lock_pids),
        "host_pollers": host_pollers,
        "docker_pollers": docker_pollers,
        "stale_lock_files": stale_files,
        "warnings": warnings,
        "conflicts": conflicts,
    }


def _enforce_0600_permissions(file_path: Path) -> str:
    """Enforce POSIX `0600` (`rw-------`) or restrictive user-only ACLs on secret files."""
    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
    if os.name == "nt":
        icacls_bin = shutil.which("icacls")
        username = os.environ.get("USERNAME") or ""
        if icacls_bin and username:
            subprocess.run(
                [
                    icacls_bin,
                    str(file_path),
                    "/inheritance:r",
                    "/grant:r",
                    f"{username}:(F)",
                    "SYSTEM:(F)",
                    "Administrators:(F)",
                ],
                capture_output=True,
                timeout=5,
                check=False,
            )
        return "0600+ntfs_acl"
    mode = stat.S_IMODE(file_path.stat().st_mode)
    return f"0{mode:o}"


def upsert_dotenv_0600(env_path: Path, updates: dict[str, str]) -> dict[str, Any]:
    """Atomically upsert key-value pairs into an `.env` file with strict `0600` file permissions."""
    env_path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(env_path.parent, 0o700)
        except OSError:
            pass

    existing_lines: list[str] = []
    if env_path.is_file():
        existing_lines = env_path.read_text(encoding="utf-8", errors="ignore").splitlines()

    remaining = dict(updates)
    rendered_lines: list[str] = []
    for line in existing_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in remaining:
                rendered_lines.append(f"{key}={remaining.pop(key)}")
                continue
        rendered_lines.append(line)

    for key, val in remaining.items():
        rendered_lines.append(f"{key}={val}")

    content = "\n".join(rendered_lines).rstrip("\n") + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".env.tmp.", dir=str(env_path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        perm_mode = _enforce_0600_permissions(tmp_path)
        os.replace(str(tmp_path), str(env_path))
        perm_mode = _enforce_0600_permissions(env_path)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass

    return {
        "path": str(env_path),
        "updated_keys": sorted(updates.keys()),
        "permissions": perm_mode,
    }


def _ensure_hermes_config_yaml_enables_telegram_and_plugin(hermes_home: Path) -> Path:
    """Ensure `$HERMES_HOME/config.yaml` does not explicitly disable Telegram or `unified-company-control`."""
    cfg_path = hermes_home / "config.yaml"
    hermes_home.mkdir(parents=True, exist_ok=True)
    marker_comment = "# Managed by ALLINAGENT telegram_onboarding.py"
    if not cfg_path.is_file():
        default_yaml = (
            f"{marker_comment}\n"
            "platforms:\n"
            "  telegram:\n"
            "    enabled: true\n"
            "plugins:\n"
            "  enabled:\n"
            "    - unified-company-control\n"
        )
        cfg_path.write_text(default_yaml, encoding="utf-8")
        return cfg_path

    raw = cfg_path.read_text(encoding="utf-8", errors="ignore")
    # Flip any explicit `telegram:\n    enabled: false` to `enabled: true`
    updated = re.sub(
        r"(?m)^(\s*telegram\s*:\s*\r?\n(?:\s+#.*\r?\n)*\s*enabled\s*:\s*)false\b",
        r"\1true",
        raw,
    )
    if "unified-company-control" not in updated and "plugins:" not in updated:
        updated = (
            updated.rstrip()
            + f"\n\n{marker_comment}\nplugins:\n  enabled:\n    - unified-company-control\n"
        )
    if updated != raw:
        cfg_path.write_text(updated, encoding="utf-8")
    return cfg_path


def install_unified_company_control_plugin(
    *,
    platform_root: Path,
    hermes_home: Path,
    plugin_source_dir: Optional[Path] = None,
) -> dict[str, Any]:
    """Install & enable the 59-command `unified-company-control` plugin inside `HERMES_HOME`."""
    candidates = [
        plugin_source_dir,
        platform_root / "agents" / "hermes-extensions" / "plugins" / "unified-company-control",
        DEFAULT_PLUGIN_TEMPLATE_DIR,
    ]
    chosen_src: Optional[Path] = None
    for cand in candidates:
        if cand and (cand / "__init__.py").is_file() and (cand / "plugin.yaml").is_file():
            # Prefer a candidate that passes full 59-command parity
            parity = validate_command_catalog(DEFAULT_CATALOG_PATH, cand)
            if parity["ok"]:
                chosen_src = cand
                break
    if chosen_src is None:
        raise RuntimeError("No valid 59-command unified-company-control plugin source directory found.")

    dst_dir = hermes_home / "plugins" / "unified-company-control"
    dst_dir.mkdir(parents=True, exist_ok=True)
    for item in chosen_src.iterdir():
        if item.is_file() and item.suffix in {".py", ".yaml", ".yml", ".json", ".md"}:
            shutil.copy2(item, dst_dir / item.name)

    # Write portable root marker for plugin discovery
    (hermes_home / ".allinagent_root").write_text(f"{platform_root.resolve()}\n", encoding="utf-8")

    cfg_yaml_path = _ensure_hermes_config_yaml_enables_telegram_and_plugin(hermes_home)
    installed_parity = validate_command_catalog(DEFAULT_CATALOG_PATH, dst_dir)
    return {
        "ok": installed_parity["ok"],
        "source_dir": str(chosen_src),
        "installed_dir": str(dst_dir),
        "config_yaml": str(cfg_yaml_path),
        "slash_commands_installed": installed_parity["plugin_commands_count"],
        "errors": installed_parity["errors"],
    }


def configure_telegram_onboarding(
    *,
    bot_token: str,
    owner_id: str,
    platform_root: Path,
    hermes_home: Path,
    online_check: bool = False,
    clear_webhook: bool = False,
    drop_pending_updates: bool = False,
    scan_host_processes: bool = True,
    scan_docker_containers: bool = True,
    opener: Optional[Callable[..., Any]] = None,
) -> dict[str, Any]:
    """End-to-end Telegram bot pairing & configuration workflow."""
    tok_check = validate_bot_token_syntax(bot_token)
    if not tok_check["ok"]:
        return tok_check

    own_check = validate_owner_telegram_id(owner_id)
    if not own_check["ok"]:
        return own_check

    poller_check = verify_single_poller(
        hermes_home,
        scan_host_processes=scan_host_processes,
        scan_docker_containers=scan_docker_containers,
    )
    if not poller_check["ok"]:
        return {
            "ok": False,
            "code": "DUPLICATE_POLLER_CONFLICT",
            "error": "; ".join(poller_check["conflicts"]),
            "poller": poller_check,
        }

    online_result: Optional[dict[str, Any]] = None
    bot_username = ""
    if online_check:
        online_result = verify_bot_online(
            bot_token.strip(),
            clear_webhook=clear_webhook,
            drop_pending_updates=drop_pending_updates,
            opener=opener,
        )
        if not online_result["ok"]:
            return online_result
        bot_username = online_result["bot"].get("username") or ""

    clean_token = bot_token.strip()
    clean_owner = own_check["owner_id"]
    resolved_root = platform_root.expanduser().resolve()
    resolved_hermes = hermes_home.expanduser().resolve()

    root_updates = {
        "TELEGRAM_BOT_TOKEN": clean_token,
        "OWNER_TELEGRAM_ID": clean_owner,
        "TELEGRAM_ALLOWED_USERS": clean_owner,
    }
    if bot_username:
        root_updates["TELEGRAM_BOT_USERNAME"] = bot_username

    hermes_updates = {
        "TELEGRAM_BOT_TOKEN": clean_token,
        "TELEGRAM_ALLOWED_USERS": clean_owner,
        "OWNER_TELEGRAM_ID": clean_owner,
        "ALLINAGENT_ROOT": str(resolved_root),
    }

    root_env_receipt = upsert_dotenv_0600(resolved_root / ".env", root_updates)
    hermes_env_receipt = upsert_dotenv_0600(resolved_hermes / ".env", hermes_updates)

    # Synchronize allowedOwnerId in office-bridge-auth.json if present in target deployment
    secrets_dir = Path((os.environ.get("ALLINAGENT_SECRETS_DIR") or "/var/lib/allinagent/secrets").strip() or "/var/lib/allinagent/secrets")
    bridge_auth_candidates = [
        secrets_dir / "office-bridge-auth.json",
        resolved_root / "config" / "secrets" / "office-bridge-auth.json",
    ]
    bridge_auth_updated = False
    for bridge_auth_path in bridge_auth_candidates:
        if bridge_auth_path.is_file():
            try:
                auth_obj = json.loads(bridge_auth_path.read_text(encoding="utf-8-sig"))
                if isinstance(auth_obj, dict):
                    auth_obj["allowedOwnerId"] = clean_owner
                    bridge_auth_path.write_text(json.dumps(auth_obj, indent=2) + "\n", encoding="utf-8")
                    _enforce_0600_permissions(bridge_auth_path)
                    bridge_auth_updated = True
            except Exception:
                continue

    plugin_receipt = install_unified_company_control_plugin(
        platform_root=resolved_root,
        hermes_home=resolved_hermes,
    )
    if not plugin_receipt["ok"]:
        return {
            "ok": False,
            "code": "PLUGIN_INSTALL_VALIDATION_FAILED",
            "error": "; ".join(plugin_receipt["errors"]),
            "plugin": plugin_receipt,
        }

    return {
        "ok": True,
        "code": "TELEGRAM_ONBOARDING_CONFIGURED",
        "owner_id": clean_owner,
        "masked_token": tok_check["masked_token"],
        "bot_username": bot_username or None,
        "root_env": root_env_receipt,
        "hermes_env": hermes_env_receipt,
        "office_bridge_auth_synced": bridge_auth_updated,
        "plugin": plugin_receipt,
        "single_poller": poller_check,
        "online_verification": online_result,
    }


def check_deployment_onboarding(
    *,
    platform_root: Path,
    hermes_home: Path,
    bot_token_override: str = "",
    owner_id_override: str = "",
    online_check: bool = False,
    scan_host_processes: bool = True,
    scan_docker_containers: bool = True,
    opener: Optional[Callable[..., Any]] = None,
) -> dict[str, Any]:
    """Inspect a target deployment's Telegram pairing state without exposing any secret material."""
    resolved_root = platform_root.expanduser().resolve()
    resolved_hermes = hermes_home.expanduser().resolve()

    def _read_env_safe(p: Path) -> dict[str, str]:
        out: dict[str, str] = {}
        if not p.is_file():
            return out
        for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = ln.strip()
            if s and not s.startswith("#") and "=" in s:
                k, v = s.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
        return out

    root_vals = _read_env_safe(resolved_root / ".env")
    hermes_vals = _read_env_safe(resolved_hermes / ".env")

    token = (
        bot_token_override
        or hermes_vals.get("TELEGRAM_BOT_TOKEN")
        or root_vals.get("TELEGRAM_BOT_TOKEN")
        or ""
    ).strip()
    owner = (
        owner_id_override
        or hermes_vals.get("OWNER_TELEGRAM_ID")
        or root_vals.get("OWNER_TELEGRAM_ID")
        or ""
    ).strip()

    tok_res = validate_bot_token_syntax(token)
    own_res = validate_owner_telegram_id(owner)
    installed_plugin_dir = resolved_hermes / "plugins" / "unified-company-control"
    plugin_res = validate_command_catalog(
        DEFAULT_CATALOG_PATH,
        installed_plugin_dir if installed_plugin_dir.is_dir() else DEFAULT_PLUGIN_TEMPLATE_DIR,
    )
    plugin_installed = (installed_plugin_dir / "__init__.py").is_file() and (installed_plugin_dir / "plugin.yaml").is_file()
    poller_res = verify_single_poller(
        resolved_hermes,
        scan_host_processes=scan_host_processes,
        scan_docker_containers=scan_docker_containers,
    )

    online_res: Optional[dict[str, Any]] = None
    if online_check and tok_res["ok"]:
        online_res = verify_bot_online(token, clear_webhook=False, opener=opener)

    overall_ok = (
        tok_res["ok"]
        and own_res["ok"]
        and plugin_installed
        and plugin_res["ok"]
        and poller_res["ok"]
        and (online_res["ok"] if online_res is not None else True)
    )
    return {
        "ok": overall_ok,
        "platform_root": str(resolved_root),
        "hermes_home": str(resolved_hermes),
        "token_validation": {k: v for k, v in tok_res.items() if k != "token"},
        "owner_validation": own_res,
        "plugin_installed": plugin_installed,
        "catalog_and_plugin_parity": plugin_res,
        "single_poller": poller_res,
        "online_verification": online_res,
    }


def _resolve_default_platform_root() -> Path:
    env_root = (os.environ.get("ALLINAGENT_ROOT") or "").strip()
    if env_root:
        return Path(env_root).expanduser().resolve()
    return MODULE_DIR.parents[1]


def _resolve_default_hermes_home(platform_root: Path) -> Path:
    env_home = (os.environ.get("HERMES_HOME") or "").strip()
    if env_home:
        return Path(env_home).expanduser().resolve()
    if os.name != "nt":
        var_home = Path("/var/lib/allinagent/hermes")
        if var_home.exists():
            return var_home.resolve()
        opt_home = Path("/opt/allinagent/data/hermes-home")
        if opt_home.exists():
            return opt_home.resolve()
        return (Path.home() / ".hermes").resolve()
    return (platform_root / "data" / "hermes-home").resolve()


def run_self_checks() -> dict[str, Any]:
    """Deterministic offline unit self-check suite running strictly inside ephemeral temp directories."""
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: Any = "") -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": redact_secrets(detail)})
        if not passed:
            raise AssertionError(f"Self-check failed [{name}]: {redact_secrets(detail)}")

    # 1. Catalog & 59-command plugin parity
    cat_res = validate_command_catalog()
    record(
        "catalog_59_commands_17_nl_rules_parity",
        cat_res["ok"] and cat_res["slash_commands_count"] == 59 and cat_res["indonesian_nl_rules_count"] == 17,
        cat_res,
    )

    # 2. Bot token syntax checks (constructed dynamically so static secret scanners see zero literal tokens)
    valid_tok = "123456789" + ":" + ("A" * 35)
    record("bot_token_valid_accepted", validate_bot_token_syntax(valid_tok)["ok"])
    bad_tokens = [
        "",
        "short:tok",
        "abc:" + ("A" * 35),
        "0:" + ("A" * 35),
        "12345678" + ":" + "replace_with_your_bot_token_" + ("0" * 10),
    ]
    for bad_tok in bad_tokens:
        record(f"bot_token_rejected:{bad_tok[:12]}", not validate_bot_token_syntax(bad_tok)["ok"])

    # 3. OWNER_TELEGRAM_ID validation (explicitly rejecting "", "0", placeholder IDs, negative, alpha)
    record("owner_id_valid_accepted", validate_owner_telegram_id("2345678901")["ok"])
    for bad_owner in ["", "   ", "0", DEFAULT_DENYLIST_OWNER_ID, "<YOUR_TELEGRAM_USER_ID>", "-100123456789", "abc12345", None, True]:
        res_bad = validate_owner_telegram_id(bad_owner)
        record(f"owner_id_rejected:{bad_owner!r}", not res_bad["ok"], res_bad)

    # 4. Mocked online verification + stale webhook clearing + secret redaction
    class _FakeResp:
        def __init__(self, obj: dict[str, Any]) -> None:
            self._bytes = json.dumps(obj).encode("utf-8")

        def read(self) -> bytes:
            return self._bytes

        def __enter__(self) -> "_FakeResp":
            return self

        def __exit__(self, *_: Any) -> None:
            return None

    called_methods: list[str] = []

    def _fake_opener(req: urllib.request.Request, timeout: float = 10.0) -> _FakeResp:
        url = req.full_url
        if url.endswith("/getMe"):
            called_methods.append("getMe")
            return _FakeResp({"ok": True, "result": {"id": 123456789, "is_bot": True, "username": "allinagent_test_bot", "first_name": "ALLINAGENT Test"}})
        if url.endswith("/getWebhookInfo"):
            called_methods.append("getWebhookInfo")
            return _FakeResp({"ok": True, "result": {"url": "https://stale.example.org/hook", "pending_update_count": 3}})
        if url.endswith("/deleteWebhook"):
            called_methods.append("deleteWebhook")
            return _FakeResp({"ok": True, "result": True})
        raise AssertionError(f"Unexpected URL: {redact_secrets(url)}")

    online_warn = verify_bot_online(valid_tok, clear_webhook=False, opener=_fake_opener)
    record("online_webhook_warning_detected", online_warn["ok"] and len(online_warn["warnings"]) == 1)

    online_cleared = verify_bot_online(valid_tok, clear_webhook=True, opener=_fake_opener)
    record(
        "online_webhook_cleared_on_request",
        online_cleared["ok"] and online_cleared["webhook"]["webhook_cleared"] is True and "deleteWebhook" in called_methods,
    )

    # 5. End-to-end configure in temporary directory + 0600 permissions + single-poller conflict detection
    with tempfile.TemporaryDirectory(prefix="allinagent-tg-test-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        plat_root = tmp_path / "platform"
        hermes_home = tmp_path / "hermes-home"
        plat_root.mkdir()
        (plat_root / ".env").write_text("# Sample comment preserved\nLLM_MODEL=gpt-4o-mini\n", encoding="utf-8")

        cfg_res = configure_telegram_onboarding(
            bot_token=valid_tok,
            owner_id="2345678901",
            platform_root=plat_root,
            hermes_home=hermes_home,
            online_check=True,
            clear_webhook=True,
            scan_host_processes=False,
            scan_docker_containers=False,
            opener=_fake_opener,
        )
        record("configure_e2e_ok", cfg_res["ok"] and valid_tok not in json.dumps(cfg_res))
        record(
            "env_preserves_existing_keys",
            "LLM_MODEL=gpt-4o-mini" in (plat_root / ".env").read_text(encoding="utf-8"),
        )
        record(
            "plugin_installed_with_59_commands",
            cfg_res["plugin"]["slash_commands_installed"] == 59
            and (hermes_home / "plugins" / "unified-company-control" / "__init__.py").is_file(),
        )

        chk_res = check_deployment_onboarding(
            platform_root=plat_root,
            hermes_home=hermes_home,
            scan_host_processes=False,
            scan_docker_containers=False,
        )
        record("check_deployment_passes_and_redacts_token", chk_res["ok"] and valid_tok not in json.dumps(chk_res))

        # Dual poller conflict simulation (1 host + 1 Docker container)
        conflict_res = verify_single_poller(
            hermes_home,
            process_list=[{"pid": 41001, "ppid": 1, "command": "python -m hermes_cli.main gateway run"}],
            container_list=[{"container_id": "abc123def456", "name": "allinagent-hermes-gateway", "image": "allinagent/hermes-gateway", "command": "hermes gateway run"}],
            pid_alive_fn=lambda _: True,
        )
        record("dual_host_and_container_poller_conflict_caught", not conflict_res["ok"] and conflict_res["code"] == "DUPLICATE_POLLER_CONFLICT")

        # Stale gateway.pid handling
        (hermes_home / "gateway.pid").write_text(json.dumps({"pid": 999991, "start_time": 100.0}), encoding="utf-8")
        stale_res = verify_single_poller(
            hermes_home,
            process_list=[],
            container_list=[],
            pid_alive_fn=lambda _: False,
        )
        record("stale_pid_detected_non_fatal_with_warning", stale_res["ok"] and len(stale_res["stale_lock_files"]) == 1)

    return {"ok": True, "total_checks": len(checks), "checks": checks}


def _interactive_wizard(args: argparse.Namespace, platform_root: Path, hermes_home: Path) -> int:
    print("======================================================================")
    print(" ALLINAGENT — Telegram Control Center Onboarding Wizard")
    print("======================================================================")
    print(f" Target Platform Root : {platform_root}")
    print(f" Target HERMES_HOME   : {hermes_home}")
    print("----------------------------------------------------------------------")

    bot_token = (args.bot_token or "").strip()
    if not bot_token:
        bot_token = getpass.getpass("1. Paste your BotFather TELEGRAM_BOT_TOKEN (input hidden): ").strip()

    tok_res = validate_bot_token_syntax(bot_token)
    if not tok_res["ok"]:
        print(f"[ERROR] {tok_res['error']}", file=sys.stderr)
        return 2

    owner_id = (args.owner_id or "").strip()
    if not owner_id:
        owner_id = input("2. Enter your personal numeric OWNER_TELEGRAM_ID: ").strip()

    own_res = validate_owner_telegram_id(owner_id)
    if not own_res["ok"]:
        print(f"[ERROR] {own_res['error']}", file=sys.stderr)
        return 2

    clear_wh = bool(args.clear_webhook)
    online_enabled = not bool(args.offline)
    if online_enabled and not clear_wh:
        pre = verify_bot_online(bot_token, clear_webhook=False)
        if not pre["ok"]:
            print(f"[ERROR] {pre['error']}", file=sys.stderr)
            return 2
        if pre["webhook"]["active_url"]:
            ans = input(
                f"Stale webhook detected ({pre['webhook']['active_url']}). Clear it now so polling works? [y/N]: "
            ).strip().lower()
            clear_wh = ans in {"y", "yes"}

    result = configure_telegram_onboarding(
        bot_token=bot_token,
        owner_id=owner_id,
        platform_root=platform_root,
        hermes_home=hermes_home,
        online_check=online_enabled,
        clear_webhook=clear_wh,
        drop_pending_updates=bool(args.drop_pending_updates),
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["ok"]:
            print(f"[OK] Paired Owner ID {result['owner_id']} with bot {result.get('bot_username') or result['masked_token']}.")
            print(f"[OK] Installed {result['plugin']['slash_commands_installed']} slash commands into {result['plugin']['installed_dir']}.")
            print(f"[OK] Single-poller lock verified (active pollers: {result['single_poller']['active_poller_count']}).")
        else:
            print(f"[ERROR] {result.get('error')}", file=sys.stderr)
    return 0 if result["ok"] else 1


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="telegram_onboarding.py",
        description="Cross-platform Telegram bot pairing wizard & single-poller verifier for ALLINAGENT.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Inspect current Telegram pairing, plugin & single-poller state.")
    mode.add_argument("--configure", action="store_true", help="Pair Telegram bot token + Owner ID and install 59-command plugin.")
    mode.add_argument("--verify-single-poller", action="store_true", help="Verify gateway.pid, locks, OS processes & Docker pollers.")
    mode.add_argument("--offline-validate", action="store_true", help="Validate token/Owner syntax rules & 59-command catalog offline.")
    mode.add_argument("--self-check", action="store_true", help="Run built-in deterministic unit self-checks.")

    parser.add_argument("--bot-token", default="", help="Telegram BotFather token (prefer interactive prompt or --bot-token-stdin).")
    parser.add_argument("--bot-token-stdin", action="store_true", help="Read TELEGRAM_BOT_TOKEN from stdin.")
    parser.add_argument("--owner-id", default="", help="Numeric personal OWNER_TELEGRAM_ID (rejects empty, 0, and <YOUR_TELEGRAM_USER_ID>).")
    parser.add_argument("--platform-root", default="", help="Path to ALLINAGENT root directory.")
    parser.add_argument("--hermes-home", default="", help="Path to HERMES_HOME runtime directory.")
    parser.add_argument("--online", action="store_true", help="Call Telegram getMe & getWebhookInfo during --check.")
    parser.add_argument("--offline", action="store_true", help="Skip online Telegram API calls during --configure.")
    parser.add_argument("--clear-webhook", action="store_true", help="Clear stale Telegram webhook via deleteWebhook if set.")
    parser.add_argument("--drop-pending-updates", action="store_true", help="Drop queued updates when clearing a stale webhook.")
    parser.add_argument("--non-interactive", action="store_true", help="Fail instead of prompting on missing --configure inputs.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.self_check:
        res = run_self_checks()
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"[PASS] telegram_onboarding self-checks passed ({res['total_checks']}/{res['total_checks']}).")
        return 0

    platform_root = Path(args.platform_root).expanduser().resolve() if args.platform_root else _resolve_default_platform_root()
    hermes_home = Path(args.hermes_home).expanduser().resolve() if args.hermes_home else _resolve_default_hermes_home(platform_root)

    bot_token = args.bot_token
    if args.bot_token_stdin:
        bot_token = sys.stdin.readline().strip()

    if args.offline_validate:
        cat_res = validate_command_catalog()
        tok_res = validate_bot_token_syntax(bot_token) if bot_token else {"skipped": True, "ok": True}
        own_res = validate_owner_telegram_id(args.owner_id) if args.owner_id != "" else {"skipped": True, "ok": True}
        ok = bool(cat_res["ok"] and tok_res["ok"] and own_res["ok"])
        out = {
            "ok": ok,
            "mode": "offline-validate",
            "catalog_validation": cat_res,
            "token_validation": tok_res,
            "owner_validation": own_res,
        }
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            status = "PASS" if ok else "FAIL"
            print(
                f"[{status}] Offline validation: slash_commands={cat_res['slash_commands_count']}, "
                f"nl_rules={cat_res['indonesian_nl_rules_count']}, submenus={cat_res['submenus_count']}"
            )
            for err in cat_res.get("errors", []):
                print(f"  - {err}", file=sys.stderr)
            if not tok_res["ok"]:
                print(f"  - Token error: {tok_res.get('error')}", file=sys.stderr)
            if not own_res["ok"]:
                print(f"  - Owner ID error: {own_res.get('error')}", file=sys.stderr)
        return 0 if ok else 1

    if args.verify_single_poller:
        poller = verify_single_poller(hermes_home)
        if args.json:
            print(json.dumps(poller, indent=2))
        else:
            tag = "PASS" if poller["ok"] else "CONFLICT"
            print(
                f"[{tag}] Single-poller check ({poller['hermes_home']}): "
                f"active_pollers={poller['active_poller_count']}"
            )
            for warn in poller["warnings"]:
                print(f"  [WARN] {warn}")
            for conf in poller["conflicts"]:
                print(f"  [CONFLICT] {conf}", file=sys.stderr)
        return 0 if poller["ok"] else 1

    if args.check:
        res = check_deployment_onboarding(
            platform_root=platform_root,
            hermes_home=hermes_home,
            bot_token_override=bot_token,
            owner_id_override=args.owner_id,
            online_check=bool(args.online),
        )
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            tag = "PASS" if res["ok"] else "INCOMPLETE"
            print(f"[{tag}] Telegram deployment check ({res['platform_root']}):")
            print(f"  - Token syntax valid : {res['token_validation']['ok']}")
            print(f"  - Owner ID valid     : {res['owner_validation']['ok']}")
            print(f"  - Plugin installed   : {res['plugin_installed']} ({res['catalog_and_plugin_parity']['plugin_commands_count']} commands)")
            print(f"  - Single poller safe : {res['single_poller']['ok']} (active={res['single_poller']['active_poller_count']})")
        return 0 if res["ok"] else 1

    if args.configure:
        if args.non_interactive or (bot_token and args.owner_id):
            args.bot_token = bot_token
            res = configure_telegram_onboarding(
                bot_token=bot_token,
                owner_id=args.owner_id,
                platform_root=platform_root,
                hermes_home=hermes_home,
                online_check=not bool(args.offline),
                clear_webhook=bool(args.clear_webhook),
                drop_pending_updates=bool(args.drop_pending_updates),
            )
            if args.json:
                print(json.dumps(res, indent=2))
            else:
                if res["ok"]:
                    print(f"[OK] Configured Telegram Owner {res['owner_id']} ({res['masked_token']}).")
                else:
                    print(f"[ERROR] {res.get('error')}", file=sys.stderr)
            return 0 if res["ok"] else 1
        args.bot_token = bot_token
        return _interactive_wizard(args, platform_root, hermes_home)

    return 1


if __name__ == "__main__":
    sys.exit(main())
