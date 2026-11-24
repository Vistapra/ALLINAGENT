/**
 * Frontend Billing Summary Presenter & Client Payload Validator (`order-billing-demo`).
 *
 * Pure ES module with zero external npm dependencies so QA & Frontend agents can
 * inspect, extend, and execute tests immediately via `node --test`.
 */

const ZERO_DECIMAL_CURRENCIES = new Set(["IDR"]);
const SUPPORTED_CURRENCIES = new Set(["USD", "EUR", "GBP", "SGD", "IDR"]);

/**
 * Escape untrusted text before embedding into HTML fragments (prevents CWE-79 DOM XSS).
 * @param {string} raw
 * @returns {string}
 */
export function escapeHtml(raw) {
  return String(raw ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Format integer minor units (cents) into a deterministic display string.
 * @param {number} amountCents
 * @param {string} currency
 * @returns {string}
 */
export function formatMinorUnits(amountCents, currency = "USD") {
  const code = String(currency || "USD").trim().toUpperCase();
  if (!SUPPORTED_CURRENCIES.has(code)) {
    throw new RangeError(`Unsupported currency code: ${code}`);
  }
  if (!Number.isSafeInteger(amountCents)) {
    throw new TypeError("amountCents must be a safe integer.");
  }
  if (ZERO_DECIMAL_CURRENCIES.has(code)) {
    return `${code} ${amountCents.toLocaleString("en-US")}`;
  }
  const sign = amountCents < 0 ? "-" : "";
  const abs = Math.abs(amountCents);
  const major = Math.floor(abs / 100).toLocaleString("en-US");
  const minor = String(abs % 100).padStart(2, "0");
  return `${sign}${code} ${major}.${minor}`;
}

/**
 * Render an XSS-safe accessible HTML invoice summary card.
 * @param {{ order_id: string, customer_id: string, invoice: Record<string, any> }} order
 * @returns {string}
 */
export function renderInvoiceSummaryCard(order) {
  if (!order || typeof order !== "object" || !order.invoice) {
    throw new TypeError("Valid order object with invoice breakdown is required.");
  }
  const inv = order.invoice;
  const ccy = inv.currency || "USD";
  const discountBadge = inv.applied_discount_code
    ? `<span class="discount-code">${escapeHtml(inv.applied_discount_code)}</span>`
    : `<span class="discount-code">NONE</span>`;

  return [
    `<section class="invoice-card" data-order-id="${escapeHtml(order.order_id)}">`,
    `  <h3>Order ${escapeHtml(order.order_id)}</h3>`,
    `  <p class="customer">Customer: ${escapeHtml(order.customer_id)}</p>`,
    `  <dl class="totals">`,
    `    <dt>Subtotal</dt><dd>${escapeHtml(formatMinorUnits(inv.subtotal_cents, ccy))}</dd>`,
    `    <dt>Discount</dt><dd>${discountBadge} -${escapeHtml(formatMinorUnits(inv.discount_cents, ccy))}</dd>`,
    `    <dt>Tax (${Number(inv.tax_bps) / 100}%)</dt><dd>${escapeHtml(formatMinorUnits(inv.tax_cents, ccy))}</dd>`,
    `    <dt>Total</dt><dd class="grand-total">${escapeHtml(formatMinorUnits(inv.total_cents, ccy))}</dd>`,
    `  </dl>`,
    `</section>`,
  ].join("\n");
}
