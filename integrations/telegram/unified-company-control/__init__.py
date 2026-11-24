"""ALLINAGENT — Unified Autonomous AI Company Native Hermes Gateway Plugin (`unified-company-control`).

Lives strictly in user-space (`$HERMES_HOME/plugins/unified-company-control/`) with zero edits to
upstream `hermes-agent` git-tracked source files, preserving seamless upstream updates.

Capabilities:
  1. 13-Submenu `ALLINAGENT — AI COMPANY` Interactive Inline Keyboard (`CallbackQueryHandler` `^uac:`)
     with callback replay ID forwarding, fail-closed Owner DM-only validation, loading toast
     acknowledgement, and safe stale-message card fallback.
  2. All 59 canonical & backward-compatible slash commands with zero collision against native
     Hermes `/approvals` (`/persetujuan`, `/setujui`, `/tolak`).
  3. `post_gateway_admission` hook for Direct-Agent chat, `@handle` temporary mentions, and
     deterministic 17-rule Bahasa Indonesia natural-language routing.
  4. Native `sendPhoto` (`photo_path` or cross-container `photo_base64`) and `sendDocument`
     (`document_path` / `attachments` for PDF, DOCX, XLSX, PPTX, CSV, ZIP, MD) delivery strictly
     to the verified Owner DM, without ever calling `getUpdates` (preserving single-poller safety).
  5. Fail-closed `OWNER_TELEGRAM_ID` enforcement (rejects empty, `"0"`, or unconfigured
     `<YOUR_TELEGRAM_USER_ID>` / synthetic default placeholder IDs).
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import mimetypes
import os
import re
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_DEFAULT_DENYLIST_OWNER_ID = "1" + ("0" * 9)
_FORBIDDEN_OWNER_IDS = frozenset({"", "0", _DEFAULT_DENYLIST_OWNER_ID, "<YOUR_TELEGRAM_USER_ID>"})
_OWNER_ID_RE = re.compile(r"^[1-9]\d{4,19}$")
_ALLOWED_DM_CHAT_TYPES = {"private", "dm", ""}
_SENSITIVE_FILE_RE = re.compile(
    r"^(\.env(\..+)?|.*auth.*\.json|.*\.local(\..*)?|deploy-secrets.*|master\.key|id_rsa.*|id_dsa.*|id_ecdsa.*|id_ed25519.*|.*\.(pem|key|pfx|p12|kdbx)|\.git-credentials|\.netrc|\.npmrc|\.pypirc)$",
    re.IGNORECASE,
)
_FORBIDDEN_DIR_SEGMENTS = frozenset({"secrets", ".ssh", ".gnupg", ".aws", ".kube", ".git"})
_FORBIDDEN_POSIX_PREFIXES = ("/etc", "/proc", "/sys", "/root", "/boot", "/dev", "/var/run", "/run")
_MAX_DOCUMENT_BYTES = 50 * 1024 * 1024  # 50 MiB Telegram Bot API limit


def _resolve_hermes_home() -> Path:
    env_home = (os.environ.get("HERMES_HOME") or "").strip()
    if env_home:
        return Path(env_home).expanduser().resolve()
    var_lib = Path("/var/lib/allinagent/hermes")
    if var_lib.is_dir():
        return var_lib.resolve()
    return (Path.home() / ".hermes").resolve()


def _resolve_platform_root(hermes_home: Optional[Path] = None) -> Path:
    env_val = (os.environ.get("ALLINAGENT_ROOT") or "").strip()
    if env_val:
        return Path(env_val).expanduser().resolve()

    hh = hermes_home or _resolve_hermes_home()
    marker = hh / ".allinagent_root"
    if marker.is_file():
        try:
            raw = marker.read_text(encoding="utf-8").strip()
            if raw:
                return Path(raw).expanduser().resolve()
        except OSError:
            pass

    opt_default = Path("/opt/allinagent")
    if opt_default.is_dir():
        return opt_default.resolve()

    self_resolved = Path(__file__).resolve()
    for ancestor in self_resolved.parents:
        if (ancestor / "integrations" / "telegram").is_dir() or (ancestor / "agents" / "hermes-extensions").is_dir():
            return ancestor
    return self_resolved.parents[3]


def _parse_dotenv(env_path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not env_path.is_file():
        return values
    try:
        for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, val = stripped.split("=", 1)
            values[key.strip()] = val.strip().strip('"').strip("'")
    except OSError:
        pass
    return values


def _load_bridge_token(
    platform_root: Path,
    hermes_env: dict[str, str],
    root_env: dict[str, str],
) -> str:
    """Resolve Office Bridge token: env var first, then secrets dir, then legacy fallbacks."""
    for env_key in ("OFFICE_BRIDGE_TOKEN", "OFFICE_BRIDGE_AUTH_TOKEN"):
        tok = (
            os.environ.get(env_key)
            or hermes_env.get(env_key)
            or root_env.get(env_key)
            or ""
        ).strip()
        if tok:
            return tok

    secrets_dir = Path(
        (os.environ.get("ALLINAGENT_SECRETS_DIR") or "/var/lib/allinagent/secrets").strip()
        or "/var/lib/allinagent/secrets"
    ).expanduser()

    explicit_auth_file = (
        os.environ.get("OFFICE_BRIDGE_AUTH_FILE")
        or os.environ.get("OFFICE_BRIDGE_SECRET_PATH")
        or hermes_env.get("OFFICE_BRIDGE_AUTH_FILE")
        or root_env.get("OFFICE_BRIDGE_AUTH_FILE")
        or ""
    ).strip()

    candidates: list[Optional[Path]] = [
        secrets_dir / "office-bridge-auth.json",
        Path(explicit_auth_file).expanduser() if explicit_auth_file else None,
        platform_root / "config" / "secrets" / "office-bridge-auth.json",
        platform_root / "data" / "secrets" / "office-bridge-auth.json",
    ]
    for cand in candidates:
        if cand is not None and cand.is_file():
            try:
                parsed = json.loads(cand.read_text(encoding="utf-8-sig"))
                tok = str(parsed.get("bridgeToken") or parsed.get("token") or "").strip()
                if tok:
                    return tok
            except Exception:
                continue

    return (os.environ.get("ALLINAGENT_INTERNAL_TOKEN") or "").strip()


def _resolve_bridge_url(hermes_env: dict[str, str], root_env: dict[str, str]) -> str:
    for url_key in ("OFFICE_BRIDGE_TELEGRAM_URL", "OFFICE_BRIDGE_HTTP_URL", "OFFICE_BRIDGE_URL"):
        raw = (
            os.environ.get(url_key)
            or hermes_env.get(url_key)
            or root_env.get(url_key)
            or ""
        ).strip()
        if raw:
            clean = raw.rstrip("/")
            if clean.endswith("/api/office-bridge/telegram/command"):
                return clean
            return f"{clean}/api/office-bridge/telegram/command"

    bridge_host = (
        os.environ.get("OFFICE_BRIDGE_HOST")
        or hermes_env.get("OFFICE_BRIDGE_HOST")
        or root_env.get("OFFICE_BRIDGE_HOST")
        or "127.0.0.1"
    ).strip()
    bridge_port = (
        os.environ.get("OFFICE_BRIDGE_PORT")
        or hermes_env.get("OFFICE_BRIDGE_PORT")
        or root_env.get("OFFICE_BRIDGE_PORT")
        or "3210"
    ).strip()
    return f"http://{bridge_host}:{bridge_port}/api/office-bridge/telegram/command"


def _runtime_settings() -> dict[str, Any]:
    hermes_home = _resolve_hermes_home()
    platform_root = _resolve_platform_root(hermes_home)
    root_env = _parse_dotenv(platform_root / ".env")
    hermes_env = _parse_dotenv(hermes_home / ".env")

    owner_id = (
        os.environ.get("OWNER_TELEGRAM_ID")
        or hermes_env.get("OWNER_TELEGRAM_ID")
        or root_env.get("OWNER_TELEGRAM_ID")
        or ""
    ).strip()

    bot_token = (
        os.environ.get("TELEGRAM_BOT_TOKEN")
        or hermes_env.get("TELEGRAM_BOT_TOKEN")
        or root_env.get("TELEGRAM_BOT_TOKEN")
        or ""
    ).strip()

    bridge_url = _resolve_bridge_url(hermes_env, root_env)
    bridge_token = _load_bridge_token(platform_root, hermes_env, root_env)
    owner_valid = owner_id not in _FORBIDDEN_OWNER_IDS and bool(_OWNER_ID_RE.fullmatch(owner_id))

    return {
        "hermes_home": hermes_home,
        "platform_root": platform_root,
        "owner_id": owner_id if owner_valid else "",
        "owner_valid": owner_valid,
        "bot_token": bot_token,
        "bridge_url": bridge_url,
        "bridge_token": bridge_token,
    }


def _parse_authorized_workspaces(raw_env: Optional[str] = None) -> list[Path]:
    raw = (raw_env if raw_env is not None else os.environ.get("AUTHORIZED_WORKSPACES", "")).strip()
    if not raw:
        return []
    items: list[str] = []
    if raw.startswith("["):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                items.extend(str(x).strip() for x in parsed if str(x).strip())
        except Exception:
            pass
    else:
        sep = r"[;,]" if os.name == "nt" else r"[:;,]"
        items.extend(p.strip() for p in re.split(sep, raw) if p.strip())

    out: list[Path] = []
    for entry in items:
        try:
            out.append(Path(entry).expanduser().resolve())
        except OSError:
            continue
    return out


def _allowed_outbound_roots(hermes_home: Path, platform_root: Path) -> list[Path]:
    raw_candidates: list[Optional[Path]] = [
        Path(os.environ["ALLINAGENT_REPORTS_ROOT"]).expanduser()
        if os.environ.get("ALLINAGENT_REPORTS_ROOT", "").strip()
        else None,
        Path("/var/lib/allinagent/reports"),
        Path(os.environ["ALLINAGENT_WORKSPACE_ROOT"]).expanduser()
        if os.environ.get("ALLINAGENT_WORKSPACE_ROOT", "").strip()
        else None,
        Path("/workspaces"),
        *_parse_authorized_workspaces(),
        hermes_home / "cache" / "deliveries",
        platform_root / "reports",
        platform_root / "workspaces",
        platform_root / "office-data",
        platform_root,
    ]
    roots: list[Path] = []
    seen: set[str] = set()
    for item in raw_candidates:
        if item is None:
            continue
        try:
            resolved = item.resolve()
        except OSError:
            continue
        key = str(resolved).lower() if os.name == "nt" else str(resolved)
        if key not in seen:
            seen.add(key)
            roots.append(resolved)
    return roots


def _is_safe_outbound_file(candidate: Path) -> bool:
    """Verify outbound attachment/photo path is inside allowed report/workspace roots and not a secret/system file."""
    try:
        if candidate.is_symlink() or not candidate.is_file():
            return False
        resolved = candidate.resolve(strict=True)
    except OSError:
        return False

    name_lower = resolved.name.lower()
    if _SENSITIVE_FILE_RE.match(name_lower) or name_lower.startswith(".env.") or ".local." in name_lower:
        return False

    lowered_parts = {p.lower() for p in resolved.parts}
    if lowered_parts & _FORBIDDEN_DIR_SEGMENTS:
        return False

    resolved_slash = str(resolved).replace("\\", "/")
    for pref in _FORBIDDEN_POSIX_PREFIXES:
        if resolved_slash == pref or resolved_slash.startswith(pref + "/"):
            return False

    if os.name == "nt":
        sys_root = os.environ.get("SystemRoot", "").replace("\\", "/").rstrip("/").lower()
        if sys_root and (resolved_slash.lower() == sys_root or resolved_slash.lower().startswith(sys_root + "/")):
            return False

    hermes_home = _resolve_hermes_home()
    platform_root = _resolve_platform_root(hermes_home)
    allowed_roots = _allowed_outbound_roots(hermes_home, platform_root)
    if not any(resolved == root or resolved.is_relative_to(root) for root in allowed_roots):
        return False

    try:
        size = resolved.stat().st_size
    except OSError:
        return False
    return 0 < size <= _MAX_DOCUMENT_BYTES


def _call_office_bridge(
    command: str,
    args: str = "",
    *,
    caller_id: str = "",
    chat_id: str = "",
    chat_type: str = "private",
    callback_query_id: str = "",
    callback_sender_id: str = "",
    message_id: str = "",
    timeout: float = 95.0,
) -> dict[str, Any]:
    cfg = _runtime_settings()
    effective_caller = str(caller_id or cfg["owner_id"]).strip()
    if not cfg["owner_valid"] or not effective_caller or effective_caller in _FORBIDDEN_OWNER_IDS:
        return {
            "ok": False,
            "reply": "⛔ Akses ditolak: OWNER_TELEGRAM_ID belum dikonfigurasi (fail-closed).",
        }
    if not cfg["bridge_token"]:
        return {"ok": False, "reply": "⚠️ Konfigurasi token Office Bridge belum tersedia."}

    payload = json.dumps(
        {
            "command": command,
            "args": args,
            "caller_id": effective_caller,
            "chat_id": str(chat_id or ""),
            "chat_type": str(chat_type or "private"),
            "callback_query_id": str(callback_query_id or ""),
            "callback_sender_id": str(callback_sender_id or ""),
            "message_id": str(message_id or ""),
        }
    ).encode("utf-8")

    last_exc: Optional[Exception] = None
    for attempt in range(2):
        req = urllib.request.Request(
            cfg["bridge_url"],
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {cfg['bridge_token']}",
                "X-Office-Caller-Id": effective_caller,
                "X-Office-Actor-Role": "owner",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as http_err:
            try:
                body = http_err.read().decode("utf-8", errors="replace")
            finally:
                try:
                    http_err.close()
                except Exception:
                    pass
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = {"ok": False, "error": body[:240]}
            if not parsed.get("reply"):
                parsed["reply"] = f"⚠️ {parsed.get('error') or f'HTTP {http_err.code}'}"
            return parsed
        except Exception as exc:
            last_exc = exc
            if attempt == 0:
                time.sleep(0.4)
    return {"ok": False, "reply": f"⚠️ Gagal menghubungi Office Bridge: {last_exc}"}


def _send_telegram_card(
    chat_id: str,
    text: str,
    inline_keyboard: Optional[list] = None,
) -> bool:
    """One-shot HTTPS `sendMessage` with bounded retry/backoff (never calls `getUpdates`)."""
    cfg = _runtime_settings()
    if not cfg["owner_valid"] or str(chat_id).strip() != cfg["owner_id"]:
        return False
    bot_token = cfg["bot_token"]
    if not bot_token or not text:
        return False
    safe_text = text[:3950]
    for use_md in (True, False):
        body: dict[str, Any] = {
            "chat_id": cfg["owner_id"],
            "text": safe_text,
            "disable_web_page_preview": True,
        }
        if use_md:
            body["parse_mode"] = "Markdown"
        if inline_keyboard:
            body["reply_markup"] = {"inline_keyboard": inline_keyboard}
        raw_bytes = json.dumps(body).encode("utf-8")
        for attempt in range(3):
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                data=raw_bytes,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=14) as resp:
                    out = json.loads(resp.read().decode("utf-8", errors="replace"))
                    if out.get("ok"):
                        return True
                    break
            except urllib.error.HTTPError:
                break
            except Exception:
                if attempt < 2:
                    time.sleep(0.5 * (attempt + 1))
    return False


def _send_telegram_multipart_bytes(
    *,
    api_method: str,
    field_name: str,
    chat_id: str,
    file_bytes: bytes,
    filename: str,
    mime_type: str,
    caption: str = "",
    inline_keyboard: Optional[list] = None,
) -> bool:
    cfg = _runtime_settings()
    if not cfg["owner_valid"] or str(chat_id).strip() != cfg["owner_id"]:
        return False
    bot_token = cfg["bot_token"]
    if not bot_token or not file_bytes or len(file_bytes) > _MAX_DOCUMENT_BYTES:
        return False

    safe_filename = re.sub(r'[\r\n"\\]', "_", Path(filename).name or "attachment.bin")
    boundary = f"----AllInAgentBoundary{uuid.uuid4().hex}"
    parts: list[bytes] = []

    def add_field(name: str, val: str) -> None:
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{val}\r\n'.encode("utf-8")
        )

    add_field("chat_id", cfg["owner_id"])
    if caption:
        add_field("caption", caption[:950])
    if inline_keyboard:
        add_field("reply_markup", json.dumps({"inline_keyboard": inline_keyboard}))

    parts.append(
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="{field_name}"; filename="{safe_filename}"\r\n'
            f"Content-Type: {mime_type}\r\n\r\n"
        ).encode("utf-8")
        + file_bytes
        + f"\r\n--{boundary}--\r\n".encode("utf-8")
    )
    body = b"".join(parts)

    for attempt in range(2):
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{bot_token}/{api_method}",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                out = json.loads(resp.read().decode("utf-8", errors="replace"))
                if out.get("ok"):
                    return True
        except Exception:
            if attempt == 0:
                time.sleep(0.8)
    return False


def _send_telegram_multipart_file(
    *,
    api_method: str,
    field_name: str,
    chat_id: str,
    file_path: str,
    caption: str = "",
    inline_keyboard: Optional[list] = None,
    default_mime: str = "application/octet-stream",
) -> bool:
    p = Path(file_path)
    if not _is_safe_outbound_file(p):
        logger.warning("unified-company-control: blocked unsafe or missing attachment path: %s", p.name)
        return False
    mime = mimetypes.guess_type(p.name)[0] or default_mime
    return _send_telegram_multipart_bytes(
        api_method=api_method,
        field_name=field_name,
        chat_id=chat_id,
        file_bytes=p.read_bytes(),
        filename=p.name,
        mime_type=mime,
        caption=caption,
        inline_keyboard=inline_keyboard,
    )


def _send_telegram_photo(
    chat_id: str,
    photo_path: str = "",
    caption: str = "",
    inline_keyboard: Optional[list] = None,
    *,
    photo_base64: str = "",
) -> bool:
    """Deliver a PNG/JPEG screenshot directly to Owner DM via `sendPhoto` (`photo_path` or `photo_base64`)."""
    if photo_path:
        p = Path(photo_path)
        if _is_safe_outbound_file(p):
            mime = mimetypes.guess_type(p.name)[0] or "image/png"
            return _send_telegram_multipart_bytes(
                api_method="sendPhoto",
                field_name="photo",
                chat_id=chat_id,
                file_bytes=p.read_bytes(),
                filename=p.name,
                mime_type=mime,
                caption=caption,
                inline_keyboard=inline_keyboard,
            )

    if photo_base64:
        try:
            clean_b64 = photo_base64.split(",", 1)[1] if "," in photo_base64 else photo_base64
            decoded = base64.b64decode(clean_b64)
        except Exception:
            decoded = b""
        if decoded:
            return _send_telegram_multipart_bytes(
                api_method="sendPhoto",
                field_name="photo",
                chat_id=chat_id,
                file_bytes=decoded,
                filename="office-screenshot.png",
                mime_type="image/png",
                caption=caption,
                inline_keyboard=inline_keyboard,
            )

    return False


def _send_telegram_document(
    chat_id: str,
    document_path: str,
    caption: str = "",
    inline_keyboard: Optional[list] = None,
) -> bool:
    """Deliver PDF/DOCX/XLSX/PPTX/CSV/MD/ZIP reports directly to Owner DM via `sendDocument`."""
    return _send_telegram_multipart_file(
        api_method="sendDocument",
        field_name="document",
        chat_id=chat_id,
        file_path=document_path,
        caption=caption,
        inline_keyboard=inline_keyboard,
        default_mime="application/octet-stream",
    )


def _deliver_bridge_attachments(
    chat_id: str,
    res: dict[str, Any],
    reply: str,
    kb: Optional[list],
) -> bool:
    photo_path = str(res.get("photo_path") or "").strip()
    photo_b64 = str(res.get("photo_base64") or "").strip()
    if (photo_path or photo_b64) and _send_telegram_photo(
        chat_id,
        photo_path,
        reply,
        kb,
        photo_base64=photo_b64,
    ):
        return True

    doc_path = str(res.get("document_path") or "").strip()
    if doc_path and _send_telegram_document(chat_id, doc_path, reply, kb):
        return True

    attachments = res.get("attachments")
    if isinstance(attachments, list) and attachments:
        sent_any = False
        capped = attachments[:5]
        for idx, item in enumerate(capped):
            p_str = str(item.get("path") if isinstance(item, dict) else item or "").strip()
            if not p_str:
                continue
            cap = reply if idx == 0 else ""
            item_kb = kb if idx == len(capped) - 1 else None
            if _send_telegram_document(chat_id, p_str, cap, item_kb):
                sent_any = True
        if sent_any:
            return True
    return False


def _extract_chat_meta(source: Any) -> tuple[str, str, str]:
    if isinstance(source, dict):
        uid = str(source.get("user_id") or "").strip()
        cid = str(source.get("chat_id") or "").strip()
        if cid.startswith("telegram:"):
            cid = cid.split(":", 1)[1].strip()
        ctype = str(source.get("chat_type") or ("group" if cid.startswith("-") else "private")).strip().lower()
        return uid, cid, ctype
    uid = str(getattr(source, "user_id", "") or "").strip()
    cid = str(getattr(source, "chat_id", "") or "").strip()
    if cid.startswith("telegram:"):
        cid = cid.split(":", 1)[1].strip()
    raw_ct = getattr(source, "chat_type", None)
    ctype = str(getattr(raw_ct, "value", raw_ct) or ("group" if cid.startswith("-") else "private")).strip().lower()
    return uid, cid, ctype


def _is_valid_owner_dm(uid: str, cid: str, ctype: str, owner_id: str) -> bool:
    if not owner_id or uid != owner_id:
        return False
    if ctype not in _ALLOWED_DM_CHAT_TYPES:
        return False
    if cid.startswith("-") or (cid and cid != owner_id):
        return False
    return True


def _make_slash_handler(cmd_name: str):
    def _handler(raw_args: str, source: Any = None, platform: str = "", **_: Any) -> Optional[str]:
        cfg = _runtime_settings()
        if not cfg["owner_valid"]:
            return "⛔ Akses ditolak: OWNER_TELEGRAM_ID belum dikonfigurasi dengan valid (fail-closed)."
        owner_id = cfg["owner_id"]
        surf = (platform or getattr(getattr(source, "platform", None), "value", "") or "").lower()
        if surf == "telegram":
            uid, cid, ctype = _extract_chat_meta(source)
            if uid != owner_id:
                return "⛔ Akses ditolak: Kontrol perusahaan AI hanya untuk Owner resmi."
            if not _is_valid_owner_dm(uid, cid, ctype, owner_id):
                return "⛔ Akses ditolak: Kontrol perusahaan AI hanya diizinkan melalui pesan pribadi (DM Owner)."
            caller_id = uid
            chat_id = cid or owner_id
            chat_type = "dm"
        else:
            caller_id = owner_id
            chat_id = ""
            chat_type = "cli_internal"

        res = _call_office_bridge(
            cmd_name,
            raw_args or "",
            caller_id=caller_id,
            chat_id=chat_id or owner_id,
            chat_type=chat_type,
        )
        reply = str(res.get("reply") or res.get("error") or "Selesai.")
        kb = res.get("inline_keyboard")

        if surf == "telegram" and chat_id:
            if _deliver_bridge_attachments(chat_id, res, reply, kb):
                return None
            if kb and _send_telegram_card(chat_id, reply, kb):
                return None
        return reply

    return _handler


async def _on_post_gateway_admission(
    platform: str = "",
    source: Optional[dict[str, Any]] = None,
    message_id: str = "",
    text: str = "",
    **_: Any,
) -> Optional[dict[str, Any]]:
    """Route `@agent` mentions, Bahasa Indonesia natural intents, and Direct-Agent chat."""
    if (platform or "").lower() != "telegram":
        return None
    cfg = _runtime_settings()
    if not cfg["owner_valid"]:
        return None
    owner_id = cfg["owner_id"]
    uid, cid, ctype = _extract_chat_meta(source or {})
    if uid != owner_id:
        return None
    if not _is_valid_owner_dm(uid, cid, ctype, owner_id):
        return {"action": "handled", "reply": "⛔ Kontrol perusahaan AI hanya diizinkan di DM pribadi Owner."}

    clean_text = (text or "").strip()
    if not clean_text or clean_text.startswith("/"):
        return None

    res = await asyncio.to_thread(
        _call_office_bridge,
        "inbound_text",
        clean_text,
        caller_id=uid,
        chat_id=cid or owner_id,
        chat_type="dm",
        message_id=str(message_id or ""),
        timeout=95.0,
    )
    if not isinstance(res, dict) or not res.get("handled"):
        return None

    reply = str(res.get("reply") or "").strip()
    kb = res.get("inline_keyboard")

    if cid:
        sent_media = await asyncio.to_thread(_deliver_bridge_attachments, cid, res, reply, kb)
        if sent_media:
            return {"action": "handled", "reply": None}
        if reply and kb:
            delivered = await asyncio.to_thread(_send_telegram_card, cid, reply, kb)
            if delivered:
                return {"action": "handled", "reply": None}

    return {"action": "handled", "reply": reply or "✅ Instruksi dieksekusi di Virtual Office."}


def _wire_telegram_callbacks(native_app: Any, _adapter: Any = None) -> None:
    """Register PTB `CallbackQueryHandler` scoped strictly to `^uac:` on the active Telegram app."""
    if native_app is None:
        return
    try:
        from telegram import InlineKeyboardButton, InlineKeyboardMarkup
        from telegram.ext import CallbackQueryHandler
    except Exception as exc:
        logger.warning("unified-company-control: PTB import unavailable: %s", exc)
        return

    def _to_markup(rows: Any):
        if not isinstance(rows, list) or not rows:
            return None
        built = []
        for row in rows:
            if not isinstance(row, list):
                continue
            btns = [
                InlineKeyboardButton(
                    str(b.get("text", "Action"))[:38],
                    callback_data=str(b.get("callback_data", "uac:home"))[:64],
                )
                for b in row
                if isinstance(b, dict) and b.get("text") and b.get("callback_data")
            ]
            if btns:
                built.append(btns)
        return InlineKeyboardMarkup(built) if built else None

    async def _on_uac_callback(update: Any, _context: Any) -> None:
        query = getattr(update, "callback_query", None)
        if query is None:
            return
        cfg = _runtime_settings()
        if not cfg["owner_valid"]:
            await query.answer("⛔ OWNER_TELEGRAM_ID belum dikonfigurasi (fail-closed).", show_alert=True)
            return
        owner_id = cfg["owner_id"]
        user = getattr(update, "effective_user", None) or getattr(query, "from_user", None)
        uid = str(getattr(user, "id", "") or "").strip()
        if uid != owner_id:
            await query.answer("⛔ Akses ditolak: Khusus Owner resmi.", show_alert=True)
            return

        chat = getattr(update, "effective_chat", None) or getattr(getattr(query, "message", None), "chat", None)
        cid = str(getattr(chat, "id", "") or owner_id).strip()
        ctype = str(getattr(chat, "type", "private") or "private").strip().lower()
        if not _is_valid_owner_dm(uid, cid, ctype, owner_id):
            await query.answer("⛔ Hanya diizinkan di DM pribadi Owner.", show_alert=True)
            return

        cb_id = str(getattr(query, "id", "") or "")
        data = str(getattr(query, "data", "") or "uac:home")
        if data == "uac:noop":
            await query.answer("📄 Halaman aktif saat ini.")
            return

        is_slow = data.startswith(
            (
                "uac:anl",
                "uac:shot",
                "uac:ceo_del",
                "uac:meet_all",
                "uac:meet_active_folder",
                "uac:meet:discuss",
                "uac:wake_all",
                "uac:stop_all",
                "uac:wave1",
                "uac:dev:test",
                "uac:sec:scan",
            )
        )
        if is_slow:
            try:
                await query.answer("⏳ Memproses di AI Company...")
            except Exception:
                pass

        res = await asyncio.to_thread(
            _call_office_bridge,
            data,
            "",
            caller_id=uid,
            chat_id=cid,
            chat_type="private",
            callback_query_id=cb_id,
            callback_sender_id=uid,
            timeout=95.0,
        )
        reply_text = str(res.get("reply") or res.get("error") or "✅ Selesai.")[:3950]
        markup = _to_markup(res.get("inline_keyboard"))

        if not is_slow:
            toast = "✅ Diperbarui"
            if res.get("selected_agent"):
                toast = f"🎯 Agen aktif: {res['selected_agent'].get('name')}"
            elif data == "uac:pick:0":
                toast = "🔓 Kembali ke Mode Hermes Umum"
            try:
                await query.answer(toast[:180])
            except Exception:
                pass

        if await asyncio.to_thread(_deliver_bridge_attachments, cid, res, reply_text, res.get("inline_keyboard")):
            return

        edited = False
        if not data.startswith(("uac:anl", "uac:ceo_del")):
            for mode in ("Markdown", None):
                try:
                    kwargs: dict[str, Any] = {"text": reply_text, "disable_web_page_preview": True}
                    if mode:
                        kwargs["parse_mode"] = mode
                    if markup is not None:
                        kwargs["reply_markup"] = markup
                    await query.edit_message_text(**kwargs)
                    edited = True
                    break
                except Exception as edit_err:
                    err_str = str(edit_err)
                    if "Message is not modified" in err_str:
                        edited = True
                        break
                    if "message can't be edited" in err_str.lower() or "message to edit not found" in err_str.lower():
                        break
                    if mode is None:
                        break

        if not edited:
            await asyncio.to_thread(_send_telegram_card, owner_id, reply_text, res.get("inline_keyboard"))

    native_app.add_handler(CallbackQueryHandler(_on_uac_callback, pattern=r"^uac:"))
    logger.info("unified-company-control: wired ALLINAGENT Telegram CallbackQueryHandler (^uac:)")


_TOOL_SCHEMA = {
    "name": "unified_company_control",
    "description": (
        "Full remote control of the ALLINAGENT Unified Autonomous AI Company (11 Corporate Agents, CEO Delegation, "
        "Paperclip Kanban, 3D & 2D Virtual Office + Screenshot, 10-State Meeting Room, Symlink-Safe Workspace Explorer "
        "& Deep Code Analyzer, Software Development Branch/Test/Diff, Windowed Analytics, Governed Budgets, "
        "Approvals, Isolated VulnClaw Security, 15-Component Health, and Async Jobs)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": (
                    "Canonical command: 'kantor', 'agen', 'pilih', 'lepas', 'info_agen', 'daftar_skill', "
                    "'skill_agen', 'skill_info', 'skill_status', 'chat', 'ke', 'reset_sesi', 'bangunkan', "
                    "'istirahatkan', 'stop_semua', 'standar_wave1', 'pause_dispatch', 'delegasi', "
                    "'status_kantor', 'screenshot_kantor', 'meeting', 'status_meeting', 'diskusi_rapat', 'notulen', "
                    "'selesai_meeting', 'folder', 'jelajah', 'cari_folder', 'pilih_folder', 'analisis', 'dev', "
                    "'projects', 'buat_project', 'buat_task', 'daftar_task', 'cek_task', 'selesai_task', "
                    "'pause_task', 'resume_task', 'cancel_task', 'analytics', 'budget', 'set_budget', "
                    "'persetujuan', 'setujui', 'tolak', 'keamanan', 'triage_temuan', 'remediasi_temuan', "
                    "'kesehatan', 'log_error', 'pulihkan_layanan', 'update_status', 'jobs'."
                ),
            },
            "args": {
                "type": "string",
                "description": "Arguments for the command (agent, workspace path, task ID, topic, window, etc.).",
            },
        },
        "required": ["command"],
    },
}


def _tool_handler(args: dict[str, Any], **_: Any) -> str:
    cfg = _runtime_settings()
    if not cfg["owner_valid"]:
        return json.dumps(
            {
                "ok": False,
                "error": "OWNER_TELEGRAM_ID is unset or invalid placeholder (fail-closed).",
                "reply": "⛔ Akses ditolak: OWNER_TELEGRAM_ID belum dikonfigurasi dengan valid.",
            },
            ensure_ascii=False,
        )

    cmd = str((args or {}).get("command") or "kantor").strip()
    cmd_args = str((args or {}).get("args") or "").strip()
    res = _call_office_bridge(cmd, cmd_args, caller_id=cfg["owner_id"], chat_type="cli_internal", timeout=95.0)
    return json.dumps(
        {
            "ok": bool(res.get("ok", True)),
            "command": cmd,
            "reply": res.get("reply", ""),
            "receipt": res.get("receipt"),
            "selected_agent": res.get("selected_agent"),
            "created_task": res.get("created_task") or (res.get("submission") or {}).get("task"),
            "meeting": res.get("meeting"),
            "active_folder": res.get("active_folder"),
        },
        ensure_ascii=False,
    )


# Canonical 59 registered Telegram slash commands
_SLASH_COMMANDS: list[tuple[str, str, str]] = [
    ("kantor", "Dashboard utama ALLINAGENT — AI COMPANY (13 submenu)", ""),
    ("agen", "Daftar lengkap 11 agen perusahaan AI & status live", ""),
    ("pilih", "Pilih/ganti agen aktif di Telegram (1..11 atau nama)", "[1..11|nama]"),
    ("lepas", "Keluar dari kunci chat agen kembali ke Hermes umum", ""),
    ("info-agen", "Detail inspector 3D/2D & sesi untuk agen", "[1..11|nama]"),
    ("daftar-skill", "Daftar skills spesialisasi 11 agen atau per agen", "[agen]"),
    ("skill-agen", "Alias daftar skills spesialisasi per agen", "[agen]"),
    ("skill-info", "Detail sumber GitHub, commit SHA, lisensi & status skill", "<agen> [skill]"),
    ("skill-status", "Status global registry skill & security gate", ""),
    ("chat", "Kirim pesan/tugas ke agen yang sedang dipilih", "<pesan>"),
    ("ke", "Kirim instruksi sementara ke agen spesifik", "<agen> | <pesan>"),
    ("reset-sesi", "Lihat atau bersihkan riwayat sesi chat agen", "[agen] [--clear]"),
    ("bangunkan", "Aktifkan agen Standby (1..11, nama, atau semua)", "<agen|semua>"),
    ("istirahatkan", "Ubah agen menjadi mode Standby (paused)", "<agen>"),
    ("delegasi", "Instruksikan CEO membagi pekerjaan multi-agen", "<instruksi>"),
    ("pause-dispatch", "Tahan atau buka pengiriman task baru", "[pause|resume]"),
    ("stop-semua", "Emergency Stop seluruh run & pause semua agen", ""),
    ("standar-wave1", "Pulihkan 4 agen inti Wave-1 aktif + 7 Standby", ""),
    ("status-kantor", "Status 3D/2D Office, ruangan & lokasi 11 agen", "[rooms|locs]"),
    ("screenshot-kantor", "Kirim screenshot live 3D/2D Office ke Telegram", "[3d|2d]"),
    ("meeting", "Kumpulkan 11 agen di Ruang Meeting 3D & 2D", "[topik/folder]"),
    ("status-meeting", "Lihat state lifecycle rapat, kehadiran & antrean", ""),
    ("diskusi-rapat", "Jalankan diskusi Bahasa Indonesia di rapat aktif", "[agen |] [topik]"),
    ("notulen", "Hasilkan notulen, keputusan & action items rapat", "[history|--tasks]"),
    ("selesai-meeting", "Selesaikan rapat & kembalikan 11 agen ke meja", "[catatan]"),
    ("folder", "Status & pemilih folder workspace terotorisasi", "[path]"),
    ("jelajah", "Telusuri workspace terotorisasi (pagination & aman)", "[path]"),
    ("cari-folder", "Cari subfolder proyek di workspace secara aman", "<kata_kunci>"),
    ("pilih-folder", "Setel folder target aktif (tersinkron ke 3D/2D)", "<path>"),
    ("analisis", "Analisis mendalam source code & simpan laporan", "[path]"),
    ("dev", "Kontrol development (git_status, cek_diff, buat_branch, test)", "<aksi>"),
    ("projects", "Daftar & progress project di Paperclip", ""),
    ("buat-project", "Buat & aktifkan project baru di Paperclip", "<nama>"),
    ("buat-task", "Buat task baru di Paperclip (read-after-write)", "[agen |] <judul> | <desk>"),
    ("daftar-task", "Daftar task Kanban Paperclip dengan pagination", "[status] [hal]"),
    ("cek-task", "Detail task, subtasks & komentar Paperclip", "<UNI-XX>"),
    ("selesai-task", "Tandai task Paperclip selesai (done)", "<UNI-XX>"),
    ("pause-task", "Tunda task menjadi blocked", "<UNI-XX>"),
    ("resume-task", "Lanjutkan task menjadi todo", "<UNI-XX>"),
    ("cancel-task", "Batalkan task beserta run aktifnya", "<UNI-XX>"),
    ("analytics", "Analytics valid (today, yesterday, 7d, 30d, agents, runs)", "[window/view]"),
    ("budget", "Lihat pagu budget, utilisasi, alert & riwayat", "[agents|history]"),
    ("set-budget", "Atur batas budget harian/bulanan (sesuai ceiling)", "<daily|monthly> <usd>"),
    ("persetujuan", "Daftar persetujuan governance Paperclip & Hermes", ""),
    ("setujui", "Setujui permintaan approval (anti-replay)", "<approval_id>"),
    ("tolak", "Tolak permintaan approval Paperclip/Hermes", "<approval_id>"),
    ("keamanan", "Kontrol VulnClaw defensif, deps & daftar temuan", "[path|list|deps]"),
    ("triage-temuan", "Ubah state lifecycle temuan keamanan (8 state)", "<FND-ID> <STATE>"),
    ("remediasi-temuan", "Buat task remediasi otomatis dari temuan", "[FND-ID]"),
    ("kesehatan", "Pemeriksaan kesehatan 15 komponen aktual sistem", ""),
    ("log-error", "Lihat log error tersanitasi terbaru", ""),
    ("pulihkan-layanan", "Pemulihan layanan aman dengan graceful drain", "[layanan]"),
    ("update-status", "Status jadwal pemeliharaan & update terkoordinasi", ""),
    ("jobs", "Pantau atau batalkan pekerjaan panjang (async jobs)", "[cancel <id>]"),
    ("platform-status", "Alias ke pemeriksaan kesehatan sistem", ""),
    ("task-status", "Alias ke detail task Paperclip", "<UNI-XX>"),
    ("create-task", "Alias ke pembuatan task Paperclip", "<judul> | <desk>"),
    ("security-report", "Alias ke laporan keamanan defensif VulnClaw", "[path]"),
    ("help-platform", "Alias ke dashboard utama /kantor", ""),
]


def register(ctx: Any) -> None:
    if getattr(ctx, "profile_name", "default") not in ("default", "", "custom"):
        return

    ctx.register_tool(
        name="unified_company_control",
        toolset="terminal",
        schema=_TOOL_SCHEMA,
        handler=_tool_handler,
        check_fn=lambda: True,
        description=(
            "Control all 11 corporate agents, 3D/2D Virtual Office, meetings, workspaces, coding, "
            "Kanban, analytics, budgets, approvals, security & health."
        ),
        emoji="🏢",
    )

    ctx.register_hook("post_gateway_admission", _on_post_gateway_admission)
    ctx.register_telegram_handler(_wire_telegram_callbacks)

    for slug, desc, hint in _SLASH_COMMANDS:
        ctx.register_command(
            slug,
            handler=_make_slash_handler(slug.replace("-", "_")),
            description=desc,
            args_hint=hint,
        )
