#!/usr/bin/env python3
"""
AcmeBistro Synthetic Order API - Portable Verification & Security Test Harness.

Supports both:
1. Standalone Python 3 + sqlite3 execution in minimal containers (zero pip dependencies, no PHP required).
2. Native PHP CLI execution of src/** and tests/PaymentSecurityTest.php when PHP CLI is available.

CLI Modes:
  python tests/run_fixture_tests.py
      Runs all 8 Group E fixture checks in Patched Clean Mode PLUS differential verification
      confirming SYN-F01..SYN-F04 deterministically reproduce under --with-seeded-vulns. Exits 0.
  python tests/run_fixture_tests.py --with-seeded-vulns
      Executes security regression assertions against the unpatched baseline (exits 1 with 4 findings).
  python tests/run_fixture_tests.py --assert-seeded-vulns
      Asserts all 4 canonical vulnerabilities (SYN-F01..SYN-F04) trigger in baseline mode (exits 0).
  python tests/run_fixture_tests.py --python-only
      Runs portable Python + SQLite verification without invoking PHP CLI.
  python tests/run_fixture_tests.py --json
      Emits structured JSON report for multi-agent audit, triage, and PDF/DOCX compliance reporting.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Callable

FIXTURE_ROOT = Path(__file__).resolve().parent.parent

WEBHOOK_SIGNING_KEY = "whsec_acmepay_synthetic_fixture_00000000"
ALLOWED_CALLBACK_HOSTS = {"app.acmebistro.example", "checkout.acmebistro.example"}
SUPPORTED_PAYMENT_METHODS = {"card", "wallet", "bank_transfer"}
IDEMPOTENCY_TTL_SECONDS = 86400


class SyntheticOrderApiEngine:
    """Portable Python + SQLite reference engine mirroring src/Controllers, Services, and Middleware."""

    def __init__(self, seeded_vulns: bool = False) -> None:
        self.seeded_vulns = seeded_vulns
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON;")
        migration_sql = (FIXTURE_ROOT / "database" / "migrations" / "001_create_orders_and_checkouts.sql").read_text(
            encoding="utf-8"
        )
        seed_sql = (FIXTURE_ROOT / "database" / "seeds" / "001_seed_sample_orders.sql").read_text(encoding="utf-8")
        self.conn.executescript(migration_sql)
        self.conn.executescript(seed_sql)

    def close(self) -> None:
        self.conn.close()

    @staticmethod
    def _iso_utc(epoch: int) -> str:
        return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def authoritative_total_cents(self, order_id: int) -> int:
        order = self.conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        if order is None:
            raise ValueError(f"Order {order_id} not found")
        row = self.conn.execute(
            "SELECT COALESCE(SUM(quantity * unit_price_cents), 0) AS subtotal FROM order_items WHERE order_id = ?",
            (order_id,),
        ).fetchone()
        subtotal = int(row["subtotal"])
        return max(0, subtotal + int(order["tax_cents"]) - int(order["discount_cents"]))

    def _verify_ownership(self, headers: dict[str, str], order: sqlite3.Row) -> tuple[bool, str, tuple[int, dict[str, Any]] | None]:
        norm = {k.lower(): v.strip() for k, v in headers.items()}
        user_id = norm.get("x-user-id", "")
        guest_token = norm.get("x-guest-token", "")

        if not user_id and not guest_token:
            return False, "anonymous", (401, {"error": "UNAUTHENTICATED", "message": "Missing auth header."})

        if user_id and not user_id.isdigit():
            return False, "invalid", (401, {"error": "INVALID_AUTH_HEADER", "message": "X-User-Id must be numeric."})

        actor = f"user:{int(user_id)}" if user_id else f"guest:{hashlib.sha256(guest_token.encode()).hexdigest()}"

        # SYN-F02: Seeded baseline mode skips object-level ownership verification
        if self.seeded_vulns:
            return True, actor, None

        if order["user_id"] is not None:
            if not user_id or int(user_id) != int(order["user_id"]):
                return False, actor, (403, {"error": "ORDER_OWNERSHIP_VIOLATION", "message": "Forbidden order access."})
            return True, actor, None

        if order["guest_token_hash"] is not None and guest_token:
            supplied_hash = hashlib.sha256(guest_token.encode("utf-8")).hexdigest()
            if hmac.compare_digest(str(order["guest_token_hash"]), supplied_hash):
                return True, actor, None

        return False, actor, (403, {"error": "ORDER_OWNERSHIP_VIOLATION", "message": "Guest token mismatch."})

    def _validate_callback_url(self, callback_url: str | None) -> str:
        default_cb = "https://app.acmebistro.example/orders/return"
        if callback_url is None or not callback_url.strip():
            return default_cb
        trimmed = callback_url.strip()

        # SYN-F03: Seeded baseline mode allows unvalidated open redirects
        if self.seeded_vulns:
            return trimmed

        if "\\" in trimmed or any(ch in trimmed for ch in ("\r", "\n", "\x00")):
            raise ValueError("Callback URL contains illegal characters.")

        parsed = urllib.parse.urlsplit(trimmed)
        if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Callback URL must use https:// without embedded credentials.")

        if parsed.hostname.lower() not in ALLOWED_CALLBACK_HOSTS:
            raise ValueError("Callback URL host is not in allowed_callback_hosts.")

        return trimmed

    def sign_webhook(self, raw_body: str) -> str:
        digest = hmac.new(WEBHOOK_SIGNING_KEY.encode("utf-8"), raw_body.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"sha256={digest}"

    def pay_order(
        self,
        order_id: int,
        payload: dict[str, Any],
        headers: dict[str, str],
        now_epoch: int = 1768478400,
    ) -> tuple[int, dict[str, Any], dict[str, str]]:
        order = self.conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        if order is None:
            return 404, {"error": "ORDER_NOT_FOUND", "message": "Order not found."}, {}

        ok, actor, err = self._verify_ownership(headers, order)
        if not ok and err is not None:
            return err[0], err[1], {}

        norm_headers = {k.lower(): v.strip() for k, v in headers.items()}
        idem_key = norm_headers.get("idempotency-key", "")
        now_iso = self._iso_utc(now_epoch)
        expires_iso = self._iso_utc(now_epoch + IDEMPOTENCY_TTL_SECONDS)
        req_hash = hashlib.sha256(
            (actor + "|" + json.dumps(payload, sort_keys=True, separators=(",", ":"))).encode("utf-8")
        ).hexdigest()

        if idem_key:
            # SYN-F04: Patched mode purges expired keys before lookup; seeded mode skips TTL cleanup
            if not self.seeded_vulns:
                self.conn.execute("DELETE FROM checkout_idempotency_keys WHERE expires_at <= ?", (now_iso,))
                self.conn.commit()
                existing = self.conn.execute(
                    "SELECT * FROM checkout_idempotency_keys WHERE order_id = ? AND idempotency_key = ? AND expires_at > ?",
                    (order_id, idem_key, now_iso),
                ).fetchone()
            else:
                existing = self.conn.execute(
                    "SELECT * FROM checkout_idempotency_keys WHERE order_id = ? AND idempotency_key = ?",
                    (order_id, idem_key),
                ).fetchone()

            if existing is not None:
                if not self.seeded_vulns and not hmac.compare_digest(str(existing["request_hash"]), req_hash):
                    return (
                        409,
                        {"error": "IDEMPOTENCY_PAYLOAD_MISMATCH", "message": "Payload mismatch for active key."},
                        {},
                    )
                return (
                    int(existing["response_status"]),
                    json.loads(str(existing["response_body"])),
                    {"X-Idempotency-Replayed": "true"},
                )

        if str(order["status"]) == "paid":
            return 409, {"error": "ORDER_ALREADY_PAID", "message": "Order already paid."}, {}

        method = str(payload.get("payment_method", ""))
        if method not in SUPPORTED_PAYMENT_METHODS:
            return 422, {"error": "INVALID_PAYMENT_REQUEST", "message": "Unsupported payment_method."}, {}

        auth_total = self.authoritative_total_cents(order_id)
        client_amount = payload.get("amount_cents")

        # SYN-F01: Seeded baseline trusts client-supplied amount_cents; patched enforces server sum
        if self.seeded_vulns and client_amount is not None:
            if not isinstance(client_amount, int) or isinstance(client_amount, bool) or client_amount <= 0:
                return 422, {"error": "INVALID_AMOUNT", "message": "Invalid amount_cents."}, {}
            payable_cents = client_amount
        else:
            if client_amount is not None:
                if not isinstance(client_amount, int) or isinstance(client_amount, bool) or client_amount != auth_total:
                    return (
                        422,
                        {
                            "error": "AMOUNT_MISMATCH",
                            "message": "Client amount_cents does not match server authoritative total.",
                            "authoritative_total_cents": auth_total,
                        },
                        {},
                    )
            payable_cents = auth_total

        try:
            validated_cb = self._validate_callback_url(payload.get("callback_url"))
        except ValueError as exc:
            return 422, {"error": "INVALID_CALLBACK_URL", "message": str(exc)}, {}

        digest = hashlib.sha256(
            f"{order_id}|{order['order_number']}|{payable_cents}|{order['currency']}|{method}|{validated_cb}".encode(
                "utf-8"
            )
        ).hexdigest()
        checkout_id = f"chk_sandbox_{digest[:16]}"
        pay_ref = f"payref_sandbox_{order_id}_{digest[16:28]}"
        redirect_url = (
            f"https://sandbox.acmepay.example.test/checkout/{checkout_id}"
            f"?return_to={urllib.parse.quote(validated_cb, safe='')}"
        )

        self.conn.execute(
            "UPDATE orders SET status = 'checkout_initiated', payment_reference = ?, updated_at = ? WHERE id = ?",
            (pay_ref, now_iso, order_id),
        )
        body = {
            "order_id": order_id,
            "order_number": str(order["order_number"]),
            "status": "checkout_initiated",
            "amount_cents": payable_cents,
            "currency": str(order["currency"]),
            "checkout_id": checkout_id,
            "payment_reference": pay_ref,
            "redirect_url": redirect_url,
            "gateway": "AcmePaySandbox",
        }

        if idem_key:
            self.conn.execute(
                """
                INSERT INTO checkout_idempotency_keys (
                    idempotency_key, order_id, actor_fingerprint, request_hash,
                    response_status, response_body, created_at, expires_at
                ) VALUES (?, ?, ?, ?, 200, ?, ?, ?)
                """,
                (idem_key, order_id, actor, req_hash, json.dumps(body, separators=(",", ":")), now_iso, expires_iso),
            )
        self.conn.commit()
        return 200, body, {"X-Idempotency-Replayed": "false"}

    def get_status(self, order_id: int, headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
        order = self.conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        if order is None:
            return 404, {"error": "ORDER_NOT_FOUND", "message": "Order not found."}
        ok, _, err = self._verify_ownership(headers, order)
        if not ok and err is not None:
            return err[0], err[1]
        items = [
            dict(row)
            for row in self.conn.execute(
                "SELECT sku, item_name, quantity, unit_price_cents, line_total_cents FROM order_items WHERE order_id = ? ORDER BY id",
                (order_id,),
            ).fetchall()
        ]
        return 200, {
            "order_id": int(order["id"]),
            "order_number": str(order["order_number"]),
            "status": str(order["status"]),
            "currency": str(order["currency"]),
            "authoritative_total_cents": self.authoritative_total_cents(order_id),
            "payment_reference": order["payment_reference"],
            "paid_amount_cents": order["paid_amount_cents"],
            "items": items,
        }

    def handle_webhook(
        self, raw_body: str, headers: dict[str, str], now_epoch: int = 1768478430
    ) -> tuple[int, dict[str, Any]]:
        norm = {k.lower(): v.strip() for k, v in headers.items()}
        sig = norm.get("x-acmepay-signature", "")
        expected = self.sign_webhook(raw_body)
        if not sig.startswith("sha256=") or not hmac.compare_digest(expected, sig):
            return 401, {"error": "INVALID_WEBHOOK_SIGNATURE", "message": "Signature verification failed."}

        payload = json.loads(raw_body)
        event_id = str(payload["event_id"])
        event_type = str(payload["event_type"])
        order_id = int(payload["order_id"])
        pay_ref = str(payload["payment_reference"])
        amount_cents = int(payload["amount_cents"])

        if self.conn.execute("SELECT 1 FROM payment_webhook_events WHERE event_id = ?", (event_id,)).fetchone():
            return 200, {"status": "duplicate_ignored", "event_id": event_id}

        auth_total = self.authoritative_total_cents(order_id)
        if not self.seeded_vulns and event_type == "payment.succeeded" and amount_cents != auth_total:
            return 422, {"error": "WEBHOOK_AMOUNT_MISMATCH", "message": "Amount mismatch."}

        now_iso = self._iso_utc(now_epoch)
        self.conn.execute(
            """
            INSERT INTO payment_webhook_events (event_id, order_id, payment_reference, event_type, amount_cents, processed_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (event_id, order_id, pay_ref, event_type, amount_cents, now_iso),
        )
        new_status = "paid" if event_type == "payment.succeeded" else "failed"
        if new_status == "paid":
            self.conn.execute(
                "UPDATE orders SET status = 'paid', payment_reference = ?, paid_amount_cents = ?, paid_at = ?, updated_at = ? WHERE id = ?",
                (pay_ref, amount_cents, now_iso, now_iso, order_id),
            )
        else:
            self.conn.execute(
                "UPDATE orders SET status = 'failed', payment_reference = ?, updated_at = ? WHERE id = ? AND status != 'paid'",
                (pay_ref, now_iso, order_id),
            )
        self.conn.commit()
        return 200, {"status": "processed", "event_id": event_id, "order_status": new_status}


def run_static_and_manifest_checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def record(name: str, fn: Callable[[], None]) -> None:
        try:
            fn()
            checks.append({"check": name, "status": "PASS", "error": None})
        except Exception as exc:  # noqa: BLE001
            checks.append({"check": name, "status": "FAIL", "error": str(exc)})

    def check_required_files() -> None:
        required = [
            "LICENSE",
            "README.md",
            "composer.json",
            "composer.lock",
            "openapi.yaml",
            "security-manifest.json",
            "config/security.php",
            "database/migrations/001_create_orders_and_checkouts.sql",
            "database/seeds/001_seed_sample_orders.sql",
            "src/Controllers/PaymentController.php",
            "src/Services/PaymentGatewayService.php",
            "src/Middleware/IdempotencyGuard.php",
            "src/Middleware/OrderOwnershipMiddleware.php",
            "src/Kernel.php",
            "public/index.php",
            "tests/PaymentSecurityTest.php",
            "tests/run_fixture_tests.py",
        ]
        missing = [rel for rel in required if not (FIXTURE_ROOT / rel).is_file()]
        if missing:
            raise AssertionError(f"Missing required fixture files: {missing}")

    def check_privacy_and_portability() -> None:
        win_drive_re = re.compile(r"\b[A-Za-z]:\\")
        live_secret_re = re.compile(r"(sk_live_[0-9a-zA-Z]+|rk_live_[0-9a-zA-Z]+|AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{20,})")
        forbidden_net_php_re = re.compile(r"\b(curl_init|fsockopen|stream_socket_client)\s*\(")

        for path in FIXTURE_ROOT.rglob("*"):
            if path.is_dir() or "__pycache__" in path.parts:
                continue
            name_lower = path.name.lower()
            if name_lower.startswith(".env") or name_lower == "auth.json" or ".local." in name_lower:
                raise AssertionError(f"Forbidden secret/local file detected in fixture: {path.name}")

            text = path.read_text(encoding="utf-8")
            if win_drive_re.search(text):
                raise AssertionError(f"Hardcoded Windows drive path detected in {path.relative_to(FIXTURE_ROOT)}")
            if live_secret_re.search(text):
                raise AssertionError(f"Live credential pattern detected in {path.relative_to(FIXTURE_ROOT)}")
            if path.suffix == ".php" and forbidden_net_php_re.search(text):
                raise AssertionError(f"External socket/network call detected in {path.relative_to(FIXTURE_ROOT)}")

    def check_composer_and_license() -> None:
        license_txt = (FIXTURE_ROOT / "LICENSE").read_text(encoding="utf-8")
        if "MIT License" not in license_txt:
            raise AssertionError("LICENSE must be MIT License")
        composer_json = json.loads((FIXTURE_ROOT / "composer.json").read_text(encoding="utf-8"))
        composer_lock = json.loads((FIXTURE_ROOT / "composer.lock").read_text(encoding="utf-8"))
        if composer_json.get("license") != "MIT":
            raise AssertionError("composer.json license must be MIT")
        if "AcmeBistro\\OrderApi\\" not in composer_json.get("autoload", {}).get("psr-4", {}):
            raise AssertionError("Missing PSR-4 autoload namespace in composer.json")
        if not isinstance(composer_lock.get("packages"), list) or not composer_lock.get("content-hash"):
            raise AssertionError("Invalid composer.lock structure")

    def check_openapi_and_security_manifest() -> None:
        openapi_txt = (FIXTURE_ROOT / "openapi.yaml").read_text(encoding="utf-8")
        for token in (
            "/api/v1/orders/{id}/pay:",
            "/api/v1/orders/{id}/status:",
            "/api/v1/webhooks/payment:",
            "X-User-Id",
            "X-Guest-Token",
            "Idempotency-Key",
            "X-AcmePay-Signature",
        ):
            if token not in openapi_txt:
                raise AssertionError(f"openapi.yaml missing required contract element: {token}")

        manifest = json.loads((FIXTURE_ROOT / "security-manifest.json").read_text(encoding="utf-8"))
        finding_ids = [item["id"] for item in manifest.get("seeded_findings", [])]
        if finding_ids != ["SYN-F01", "SYN-F02", "SYN-F03", "SYN-F04"]:
            raise AssertionError(f"Unexpected seeded_findings IDs: {finding_ids}")

    record("fixture_required_files_present", check_required_files)
    record("privacy_zero_secrets_zero_winpaths_offline_sandbox", check_privacy_and_portability)
    record("composer_manifests_and_mit_license_valid", check_composer_and_license)
    record("openapi_and_security_manifest_contracts_valid", check_openapi_and_security_manifest)
    return checks


def run_python_engine_suite(seeded_vulns: bool) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    def run_case(name: str, fn: Callable[[], None]) -> None:
        try:
            fn()
            results.append({"test": name, "status": "PASS", "error": None})
        except Exception as exc:  # noqa: BLE001
            results.append({"test": name, "status": "FAIL", "error": str(exc)})

    def case_happy_path_and_webhook() -> None:
        eng = SyntheticOrderApiEngine(seeded_vulns=seeded_vulns)
        try:
            fk_issues = eng.conn.execute("PRAGMA foreign_key_check;").fetchall()
            assert fk_issues == [], f"SQLite foreign key issues: {fk_issues}"

            status, body, hdrs = eng.pay_order(
                1001,
                {"payment_method": "card", "callback_url": "https://app.acmebistro.example/orders/1001/done"},
                {"X-User-Id": "42", "Idempotency-Key": "idem_py_1001"},
            )
            assert status == 200 and body["amount_cents"] == 3595
            assert hdrs["X-Idempotency-Replayed"] == "false"

            status2, body2, hdrs2 = eng.pay_order(
                1001,
                {"payment_method": "card", "callback_url": "https://app.acmebistro.example/orders/1001/done"},
                {"X-User-Id": "42", "Idempotency-Key": "idem_py_1001"},
            )
            assert status2 == 200 and hdrs2["X-Idempotency-Replayed"] == "true"
            assert body2["checkout_id"] == body["checkout_id"]

            wh_raw = json.dumps(
                {
                    "event_id": "evt_py_1001",
                    "event_type": "payment.succeeded",
                    "order_id": 1001,
                    "payment_reference": body["payment_reference"],
                    "amount_cents": 3595,
                },
                separators=(",", ":"),
            )
            wh_status, wh_body = eng.handle_webhook(wh_raw, {"X-AcmePay-Signature": eng.sign_webhook(wh_raw)})
            assert wh_status == 200 and wh_body["status"] == "processed"

            st_code, st_body = eng.get_status(1001, {"X-User-Id": "42"})
            assert st_code == 200 and st_body["status"] == "paid" and st_body["paid_amount_cents"] == 3595
        finally:
            eng.close()

    def case_guest_token_and_auth() -> None:
        eng = SyntheticOrderApiEngine(seeded_vulns=seeded_vulns)
        try:
            unauth_code, _ = eng.get_status(1002, {})
            assert unauth_code == 401

            guest_code, guest_body, _ = eng.pay_order(
                1002,
                {"payment_method": "wallet"},
                {"X-Guest-Token": "guest_tok_bistro_order_1002"},
            )
            assert guest_code == 200 and guest_body["amount_cents"] == 1980

            bad_wh_code, _ = eng.handle_webhook("{}", {"X-AcmePay-Signature": "sha256=invalid"})
            assert bad_wh_code == 401
        finally:
            eng.close()

    def case_syn_f01_server_authoritative_amount() -> None:
        eng = SyntheticOrderApiEngine(seeded_vulns=seeded_vulns)
        try:
            code, body, _ = eng.pay_order(
                1001,
                {"payment_method": "card", "amount_cents": 100},
                {"X-User-Id": "42"},
            )
            assert code == 422 and body.get("error") == "AMOUNT_MISMATCH", (
                f"[SYN-F01] Expected HTTP 422 AMOUNT_MISMATCH for tampered amount_cents=100, got {code} ({body})"
            )
        finally:
            eng.close()

    def case_syn_f02_order_ownership_idor() -> None:
        eng = SyntheticOrderApiEngine(seeded_vulns=seeded_vulns)
        try:
            code, body = eng.get_status(1003, {"X-User-Id": "42"})
            assert code == 403 and body.get("error") == "ORDER_OWNERSHIP_VIOLATION", (
                f"[SYN-F02] Expected HTTP 403 on cross-user order status access, got {code}"
            )
        finally:
            eng.close()

    def case_syn_f03_callback_open_redirect() -> None:
        eng = SyntheticOrderApiEngine(seeded_vulns=seeded_vulns)
        try:
            code, body, _ = eng.pay_order(
                1001,
                {"payment_method": "card", "callback_url": "https://evil-redirect.attacker.example/phish"},
                {"X-User-Id": "42"},
            )
            assert code == 422 and body.get("error") == "INVALID_CALLBACK_URL", (
                f"[SYN-F03] Expected HTTP 422 INVALID_CALLBACK_URL on external host, got {code}"
            )
        finally:
            eng.close()

    def case_syn_f04_idempotency_ttl_cleanup() -> None:
        eng = SyntheticOrderApiEngine(seeded_vulns=seeded_vulns)
        try:
            code, body, hdrs = eng.pay_order(
                1001,
                {"payment_method": "card"},
                {"X-User-Id": "42", "Idempotency-Key": "idem_expired_legacy_key_001"},
                now_epoch=1768478900,
            )
            assert code == 200
            assert not body.get("stale_record", False), (
                "[SYN-F04] Expired 2020 idempotency key was replayed instead of being evicted"
            )
            assert hdrs.get("X-Idempotency-Replayed") == "false"
        finally:
            eng.close()

    run_case("py_happy_path_customer_checkout_and_webhook", case_happy_path_and_webhook)
    run_case("py_guest_token_and_webhook_hmac_auth", case_guest_token_and_auth)
    run_case("py_syn_f01_server_authoritative_amount", case_syn_f01_server_authoritative_amount)
    run_case("py_syn_f02_order_ownership_idor", case_syn_f02_order_ownership_idor)
    run_case("py_syn_f03_callback_open_redirect", case_syn_f03_callback_open_redirect)
    run_case("py_syn_f04_idempotency_ttl_cleanup", case_syn_f04_idempotency_ttl_cleanup)
    return results


def run_php_bridge(mode_flag: str | None) -> dict[str, Any]:
    php_bin = shutil.which("php")
    if not php_bin:
        return {"available": False, "skipped": True, "exit_code": 0, "summary": None}

    # First run syntax lint across all PHP files
    for php_file in sorted(FIXTURE_ROOT.rglob("*.php")):
        lint = subprocess.run([php_bin, "-l", str(php_file)], capture_output=True, text=True, check=False)
        if lint.returncode != 0:
            return {
                "available": True,
                "skipped": False,
                "exit_code": lint.returncode,
                "error": f"PHP syntax error in {php_file.relative_to(FIXTURE_ROOT)}: {lint.stderr or lint.stdout}",
                "summary": None,
            }

    cmd = [php_bin, str(FIXTURE_ROOT / "tests" / "PaymentSecurityTest.php"), "--json"]
    if mode_flag:
        cmd.append(mode_flag)

    env = os.environ.copy()
    env["ACME_SEEDED_VULNS"] = "0"
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)
    parsed = None
    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError:
        parsed = {"raw_stdout": proc.stdout, "raw_stderr": proc.stderr}

    return {
        "available": True,
        "skipped": False,
        "exit_code": proc.returncode,
        "stderr": proc.stderr.strip(),
        "summary": parsed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="AcmeBistro Synthetic Order API Fixture Verifier")
    parser.add_argument(
        "--with-seeded-vulns",
        action="store_true",
        help="Run regression suite against unpatched baseline mode (expects security checks to fail with exit code 1).",
    )
    parser.add_argument(
        "--assert-seeded-vulns",
        action="store_true",
        help="Verify that all 4 canonical seeded vulnerabilities (SYN-F01..SYN-F04) reproduce in baseline mode (exits 0).",
    )
    parser.add_argument(
        "--python-only",
        action="store_true",
        help="Skip PHP CLI bridge and execute strictly using Python 3 + sqlite3 standard library.",
    )
    parser.add_argument("--json", action="store_true", help="Output structured JSON verification report.")
    args = parser.parse_args()

    static_checks = run_static_and_manifest_checks()
    static_failed = [c for c in static_checks if c["status"] == "FAIL"]

    target_seeded = args.with_seeded_vulns or args.assert_seeded_vulns
    py_results = run_python_engine_suite(seeded_vulns=target_seeded)

    expected_sec_failures = [
        "py_syn_f01_server_authoritative_amount",
        "py_syn_f02_order_ownership_idor",
        "py_syn_f03_callback_open_redirect",
        "py_syn_f04_idempotency_ttl_cleanup",
    ]

    differential_baseline_ok = True
    php_clean_report: dict[str, Any] = {"available": False, "skipped": True}
    php_seeded_report: dict[str, Any] = {"available": False, "skipped": True}

    if not target_seeded:
        # In default clean verification mode, also verify differential seeded-baseline reproducibility!
        seeded_probe = run_python_engine_suite(seeded_vulns=True)
        seeded_failed_names = [r["test"] for r in seeded_probe if r["status"] == "FAIL"]
        differential_baseline_ok = seeded_failed_names == expected_sec_failures

        if not args.python_only:
            php_clean_report = run_php_bridge(None)
            php_seeded_report = run_php_bridge("--assert-seeded-vulns")
    else:
        if not args.python_only:
            flag = "--assert-seeded-vulns" if args.assert_seeded_vulns else "--with-seeded-vulns"
            php_clean_report = run_php_bridge(flag)

    py_failed_names = [r["test"] for r in py_results if r["status"] == "FAIL"]

    if args.assert_seeded_vulns:
        py_ok = py_failed_names == expected_sec_failures
        php_ok = True if php_clean_report.get("skipped") else (php_clean_report.get("exit_code") == 0)
        overall_ok = (not static_failed) and py_ok and php_ok
    elif args.with_seeded_vulns:
        # Intentionally exits 1 when seeded vulnerabilities are active and unpatched
        overall_ok = False
    else:
        py_ok = len(py_failed_names) == 0
        php_ok = True
        if not php_clean_report.get("skipped"):
            php_ok = (
                php_clean_report.get("exit_code") == 0
                and php_seeded_report.get("exit_code") == 0
                and not php_clean_report.get("stderr")
            )
        overall_ok = (not static_failed) and py_ok and differential_baseline_ok and php_ok

    report = {
        "fixture": "acmebistro/synthetic-order-api",
        "mode": "seeded_vulns" if target_seeded else "patched_clean",
        "overall_status": "PASS" if overall_ok else "FAIL",
        "python_version": sys.version.split()[0],
        "sqlite_version": sqlite3.sqlite_version,
        "static_and_manifest_checks": static_checks,
        "python_suite": {
            "total": len(py_results),
            "passed": sum(1 for r in py_results if r["status"] == "PASS"),
            "failed": len(py_failed_names),
            "results": py_results,
        },
        "differential_seeded_baseline_verified": differential_baseline_ok if not target_seeded else None,
        "php_cli_bridge": {
            "primary": php_clean_report,
            "seeded_differential": php_seeded_report if not target_seeded else None,
        },
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"=== AcmeBistro Synthetic Order API Verifier [mode={report['mode']}] ===")
        print(f"Python {report['python_version']} | SQLite {report['sqlite_version']}")
        for chk in static_checks:
            suffix = f" :: {chk['error']}" if chk["error"] else ""
            print(f"  [{chk['status']}] static::{chk['check']}{suffix}")
        for res in py_results:
            suffix = f" :: {res['error']}" if res["error"] else ""
            print(f"  [{res['status']}] {res['test']}{suffix}")
        if not target_seeded:
            diff_label = "PASS" if differential_baseline_ok else "FAIL"
            print(f"  [{diff_label}] differential::seeded_vulns_reproduce_SYN_F01_to_SYN_F04")
        if not php_clean_report.get("skipped"):
            p_status = "PASS" if php_clean_report.get("exit_code") == 0 else "FAIL"
            php_ver = (php_clean_report.get("summary") or {}).get("php_version", "unknown")
            print(f"  [{p_status}] php_cli::PaymentSecurityTest (PHP {php_ver})")
            if not target_seeded and not php_seeded_report.get("skipped"):
                ps_status = "PASS" if php_seeded_report.get("exit_code") == 0 else "FAIL"
                print(f"  [{ps_status}] php_cli::PaymentSecurityTest --assert-seeded-vulns")
        else:
            print("  [SKIP] php_cli::PaymentSecurityTest (portable Python-only mode)")
        print(f"Overall Fixture Status: {report['overall_status']}")

    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
