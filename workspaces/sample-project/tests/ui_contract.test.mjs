import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  escapeHtml,
  formatMinorUnits,
  renderInvoiceSummaryCard,
} from "../src/ui/billing_widget.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "..");

test("formatMinorUnits formats two-decimal and zero-decimal currencies accurately", () => {
  assert.equal(formatMinorUnits(11880, "USD"), "USD 118.80");
  assert.equal(formatMinorUnits(5, "EUR"), "EUR 0.05");
  assert.equal(formatMinorUnits(150000, "IDR"), "IDR 150,000");
});

test("renderInvoiceSummaryCard escapes untrusted fields to prevent XSS", () => {
  const html = renderInvoiceSummaryCard({
    order_id: 'ord_<script>alert("x")</script>',
    customer_id: "cust_123&co",
    invoice: {
      currency: "USD",
      subtotal_cents: 10000,
      discount_cents: 500,
      tax_bps: 1000,
      tax_cents: 950,
      total_cents: 10450,
      applied_discount_code: "WELCOME5",
    },
  });
  assert.ok(!html.includes("<script>"));
  assert.ok(html.includes("&lt;script&gt;"));
  assert.ok(html.includes("USD 104.50"));
  assert.ok(html.includes("WELCOME5"));
});

test("OpenAPI 3.1 contract defines all expected endpoints and MIT license", () => {
  const specPath = path.join(PROJECT_ROOT, "openapi", "openapi.yaml");
  const raw = fs.readFileSync(specPath, "utf8");
  assert.match(raw, /^openapi:\s*3\.1\.0/m);
  assert.match(raw, /identifier:\s*MIT/);
  for (const endpoint of [
    "/healthz:",
    "/api/v1/orders:",
    "/api/v1/orders/{order_id}:",
    "/api/v1/invoices/preview:",
    "/api/v1/sandbox/diagnostics:",
  ]) {
    assert.ok(raw.includes(endpoint), `Missing endpoint in OpenAPI spec: ${endpoint}`);
  }
});
