"""Automated unit & API contract tests for `order-billing-demo`."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.app import BillingApplication
from src.domain import LineItem, ValidationError, calculate_invoice
from src.sandbox_audit_fixture import (
    build_parameterized_order_lookup,
    compute_sha256_audit_digest,
    inert_legacy_static_scan_benchmark,
)


class OrderBillingDemoTestSuite(unittest.TestCase):
    def test_healthz_defaults_sandbox_mode_off(self) -> None:
        app = BillingApplication(env={"SANDBOX_TEST_MODE": "false"})
        status, body = app.handle_request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["service"], "order-billing-demo")
        self.assertFalse(body["sandbox_test_mode"])

    def test_invoice_calculation_with_discount_and_tax(self) -> None:
        items = [
            LineItem(sku="PLAN-PRO", description="Pro Seat Subscription", quantity=2, unit_price_cents=5_000),
            LineItem(sku="ADDON-AUDIT", description="Compliance Audit Pack", quantity=1, unit_price_cents=2_000),
        ]
        # Subtotal = 12,000; VOLUME10 (10%) = 1,200; Taxable = 10,800; Tax 10% (1000 bps) = 1,080; Total = 11,880
        inv = calculate_invoice(items, currency="USD", tax_bps=1000, discount_code="VOLUME10")
        self.assertEqual(inv.subtotal_cents, 12_000)
        self.assertEqual(inv.discount_cents, 1_200)
        self.assertEqual(inv.taxable_cents, 10_800)
        self.assertEqual(inv.tax_cents, 1_080)
        self.assertEqual(inv.total_cents, 11_880)
        self.assertEqual(inv.applied_discount_code, "VOLUME10")

    def test_create_get_and_idempotent_replay_order(self) -> None:
        app = BillingApplication(env={"SANDBOX_TEST_MODE": "false"})
        payload = {
            "customer_id": "cust_demo_001",
            "currency": "EUR",
            "tax_bps": 2000,
            "discount_code": "WELCOME5",
            "items": [
                {
                    "sku": "CLOUD-NODE",
                    "description": "Dedicated Compute Node",
                    "quantity": 1,
                    "unit_price_cents": 10_000,
                }
            ],
        }
        status_1, created = app.handle_request(
            "POST",
            "/api/v1/orders",
            payload,
            headers={"Idempotency-Key": "idem-order-001"},
        )
        self.assertEqual(status_1, 201)
        self.assertFalse(created["idempotent_replay"])
        self.assertEqual(created["invoice"]["total_cents"], 11_400)

        # Replay with identical Idempotency-Key and payload returns HTTP 200 & same order_id
        status_2, replayed = app.handle_request(
            "POST",
            "/api/v1/orders",
            payload,
            headers={"Idempotency-Key": "idem-order-001"},
        )
        self.assertEqual(status_2, 200)
        self.assertTrue(replayed["idempotent_replay"])
        self.assertEqual(replayed["order_id"], created["order_id"])

        # Conflicting payload on same Idempotency-Key returns HTTP 400
        mutated = {**payload, "currency": "USD"}
        status_conflict, err_body = app.handle_request(
            "POST",
            "/api/v1/orders",
            mutated,
            headers={"Idempotency-Key": "idem-order-001"},
        )
        self.assertEqual(status_conflict, 400)
        self.assertEqual(err_body["code"], "VALIDATION_ERROR")

        # Fetch order by ID
        status_get, fetched = app.handle_request("GET", f"/api/v1/orders/{created['order_id']}")
        self.assertEqual(status_get, 200)
        self.assertEqual(fetched["customer_id"], "cust_demo_001")

    def test_sandbox_diagnostics_gate(self) -> None:
        locked_app = BillingApplication(env={"SANDBOX_TEST_MODE": "false"})
        st_locked, body_locked = locked_app.handle_request("GET", "/api/v1/sandbox/diagnostics")
        self.assertEqual(st_locked, 403)
        self.assertEqual(body_locked["code"], "SANDBOX_MODE_DISABLED")

        sandbox_app = BillingApplication(env={"SANDBOX_TEST_MODE": "true"})
        st_open, body_open = sandbox_app.handle_request("GET", "/api/v1/sandbox/diagnostics")
        self.assertEqual(st_open, 200)
        self.assertTrue(body_open["sandbox_test_mode"])
        self.assertTrue(body_open["synthetic_fixture"])

    def test_validation_rejects_sql_meta_in_customer_id_and_bad_discounts(self) -> None:
        app = BillingApplication()
        status, body = app.handle_request(
            "POST",
            "/api/v1/orders",
            {
                "customer_id": "cust' OR 1=1 --",
                "currency": "USD",
                "items": [{"sku": "SKU-1", "description": "Widget", "quantity": 1, "unit_price_cents": 500}],
            },
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["code"], "VALIDATION_ERROR")

        with self.assertRaises(ValidationError):
            calculate_invoice(
                [LineItem(sku="SKU-1", description="Widget", quantity=1, unit_price_cents=500)],
                currency="USD",
                discount_code="UNKNOWN99",
            )

    def test_inert_security_fixture_cannot_execute_unsafe_branch(self) -> None:
        sql, params = build_parameterized_order_lookup("cust_safe")
        self.assertIn("?", sql)
        self.assertEqual(params, ("cust_safe",))
        self.assertEqual(len(compute_sha256_audit_digest(b"demo")), 64)
        with self.assertRaises(RuntimeError):
            inert_legacy_static_scan_benchmark("cust_safe", b"demo")


if __name__ == "__main__":
    unittest.main()
