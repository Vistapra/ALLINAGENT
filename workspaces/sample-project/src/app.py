"""Zero-dependency HTTP/REST router for `order-billing-demo`."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from . import __version__
from .domain import (
    ValidationError,
    calculate_invoice,
    compute_request_fingerprint,
    parse_line_items,
    validate_currency,
    validate_customer_id,
    validate_tax_bps,
)
from .repository import OrderRepository


def is_sandbox_test_mode_enabled(env: dict[str, str] | None = None) -> bool:
    source = env if env is not None else os.environ
    raw = str(source.get("SANDBOX_TEST_MODE", "false")).strip().lower()
    return raw in {"1", "true", "yes", "on"}


class BillingApplication:
    """Deterministic REST application testable in-process or over HTTP."""

    def __init__(
        self,
        repository: OrderRepository | None = None,
        *,
        env: dict[str, str] | None = None,
    ) -> None:
        self.repository = repository or OrderRepository(":memory:")
        self._env = env

    def handle_request(
        self,
        method: str,
        path: str,
        body: bytes | str | dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        verb = method.upper().strip()
        clean_path = path.split("?", 1)[0].rstrip("/") or "/"
        hdrs = {k.lower(): v for k, v in (headers or {}).items()}
        sandbox_on = is_sandbox_test_mode_enabled(self._env)

        if verb == "GET" and clean_path == "/healthz":
            return 200, {
                "status": "ok",
                "service": "order-billing-demo",
                "version": __version__,
                "sandbox_test_mode": sandbox_on,
            }

        if verb == "GET" and clean_path == "/api/v1/sandbox/diagnostics":
            if not sandbox_on:
                return 403, {
                    "error": "Synthetic sandbox diagnostics endpoint is disabled unless SANDBOX_TEST_MODE=true.",
                    "code": "SANDBOX_MODE_DISABLED",
                }
            return 200, {
                "sandbox_test_mode": True,
                "synthetic_fixture": True,
                "service": "order-billing-demo",
                "order_count": self.repository.count_orders(),
                "supported_discount_codes": ["WELCOME5", "VOLUME10", "ANNUAL15"],
            }

        if verb == "POST" and clean_path == "/api/v1/invoices/preview":
            try:
                payload = self._decode_json(body)
                items = parse_line_items(payload.get("items"))
                currency = validate_currency(payload.get("currency", "USD"))
                tax_bps = validate_tax_bps(payload.get("tax_bps"), default_bps=1000)
                invoice = calculate_invoice(
                    items,
                    currency=currency,
                    tax_bps=tax_bps,
                    discount_code=payload.get("discount_code"),
                )
                return 200, invoice.to_dict()
            except ValidationError as exc:
                return 400, {"error": str(exc), "code": "VALIDATION_ERROR"}

        if verb == "POST" and clean_path == "/api/v1/orders":
            try:
                payload = self._decode_json(body)
                customer_id = validate_customer_id(payload.get("customer_id"))
                items = parse_line_items(payload.get("items"))
                currency = validate_currency(payload.get("currency", "USD"))
                tax_bps = validate_tax_bps(payload.get("tax_bps"), default_bps=1000)
                discount_code = payload.get("discount_code")
                invoice = calculate_invoice(
                    items,
                    currency=currency,
                    tax_bps=tax_bps,
                    discount_code=discount_code,
                )
                fingerprint = compute_request_fingerprint(
                    customer_id, currency, tax_bps, discount_code, items
                )
                order_doc, replayed = self.repository.create_or_replay_order(
                    customer_id=customer_id,
                    items=items,
                    invoice=invoice,
                    request_fingerprint=fingerprint,
                    idempotency_key=hdrs.get("idempotency-key"),
                )
                return (200 if replayed else 201), order_doc
            except ValidationError as exc:
                return 400, {"error": str(exc), "code": "VALIDATION_ERROR"}

        if verb == "GET" and clean_path.startswith("/api/v1/orders/"):
            order_id = clean_path.removeprefix("/api/v1/orders/").strip()
            order_doc = self.repository.get_order(order_id)
            if order_doc is None:
                return 404, {"error": f"Order '{order_id}' not found.", "code": "ORDER_NOT_FOUND"}
            return 200, order_doc

        return 404, {"error": f"Route '{verb} {clean_path}' not found.", "code": "ROUTE_NOT_FOUND"}

    @staticmethod
    def _decode_json(body: bytes | str | dict[str, Any] | None) -> dict[str, Any]:
        if isinstance(body, dict):
            return body
        if body is None or body == b"" or body == "":
            raise ValidationError("Request JSON body is required.")
        raw_text = body.decode("utf-8") if isinstance(body, bytes) else body
        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"Malformed JSON body: {exc.msg}") from exc
        if not isinstance(parsed, dict):
            raise ValidationError("Request body must be a JSON object.")
        return parsed


def run_dev_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    app = BillingApplication()

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            status, payload = app.handle_request("GET", self.path, None, dict(self.headers))
            self._send_json(status, payload)

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b""
            status, payload = app.handle_request("POST", self.path, raw, dict(self.headers))
            self._send_json(status, payload)

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            encoded = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    server = HTTPServer((host, port), _Handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    run_dev_server(
        host=os.environ.get("BILLING_HOST", "127.0.0.1"),
        port=int(os.environ.get("BILLING_PORT", "8080")),
    )
