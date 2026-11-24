"""Pure integer-cents billing, discount, and basis-point tax calculation domain."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

SUPPORTED_CURRENCIES = frozenset({"USD", "EUR", "GBP", "SGD", "IDR"})
DISCOUNT_RATES_BPS: dict[str, int] = {
    "WELCOME5": 500,   # 5.00%
    "VOLUME10": 1000,  # 10.00%
    "ANNUAL15": 1500,  # 15.00%
}
SKU_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
CUSTOMER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


class ValidationError(ValueError):
    """Raised when incoming order or invoice payload violates domain constraints."""


@dataclass(frozen=True)
class LineItem:
    sku: str
    description: str
    quantity: int
    unit_price_cents: int

    @property
    def line_total_cents(self) -> int:
        return self.quantity * self.unit_price_cents

    def to_dict(self) -> dict[str, Any]:
        return {
            "sku": self.sku,
            "description": self.description,
            "quantity": self.quantity,
            "unit_price_cents": self.unit_price_cents,
            "line_total_cents": self.line_total_cents,
        }


@dataclass(frozen=True)
class InvoiceSummary:
    currency: str
    subtotal_cents: int
    discount_cents: int
    taxable_cents: int
    tax_bps: int
    tax_cents: int
    total_cents: int
    applied_discount_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "currency": self.currency,
            "subtotal_cents": self.subtotal_cents,
            "discount_cents": self.discount_cents,
            "taxable_cents": self.taxable_cents,
            "tax_bps": self.tax_bps,
            "tax_cents": self.tax_cents,
            "total_cents": self.total_cents,
            "applied_discount_code": self.applied_discount_code,
        }


def parse_line_items(raw_items: Any) -> list[LineItem]:
    if not isinstance(raw_items, list) or len(raw_items) == 0:
        raise ValidationError("items must be a non-empty array.")
    if len(raw_items) > 100:
        raise ValidationError("items cannot exceed 100 line items per order.")

    parsed: list[LineItem] = []
    for idx, entry in enumerate(raw_items):
        if not isinstance(entry, dict):
            raise ValidationError(f"items[{idx}] must be an object.")
        sku = str(entry.get("sku", "")).strip()
        if not SKU_RE.match(sku):
            raise ValidationError(f"items[{idx}].sku has an invalid format.")
        description = str(entry.get("description", "")).strip()
        if not description or len(description) > 200:
            raise ValidationError(f"items[{idx}].description must be 1..200 characters.")
        qty = entry.get("quantity")
        price = entry.get("unit_price_cents")
        if isinstance(qty, bool) or not isinstance(qty, int) or qty < 1 or qty > 10_000:
            raise ValidationError(f"items[{idx}].quantity must be an integer between 1 and 10000.")
        if isinstance(price, bool) or not isinstance(price, int) or price < 0 or price > 100_000_000:
            raise ValidationError(f"items[{idx}].unit_price_cents must be a non-negative integer.")
        parsed.append(
            LineItem(
                sku=sku,
                description=description,
                quantity=qty,
                unit_price_cents=price,
            )
        )
    return parsed


def validate_customer_id(raw_customer_id: Any) -> str:
    cid = str(raw_customer_id or "").strip()
    if not CUSTOMER_ID_RE.match(cid):
        raise ValidationError("customer_id must be 1..64 safe alphanumeric characters.")
    return cid


def validate_currency(raw_currency: Any) -> str:
    currency = str(raw_currency or "").strip().upper()
    if currency not in SUPPORTED_CURRENCIES:
        raise ValidationError(f"currency must be one of {sorted(SUPPORTED_CURRENCIES)}.")
    return currency


def validate_tax_bps(raw_tax_bps: Any, default_bps: int = 1000) -> int:
    if raw_tax_bps is None:
        return default_bps
    if isinstance(raw_tax_bps, bool) or not isinstance(raw_tax_bps, int) or raw_tax_bps < 0 or raw_tax_bps > 5000:
        raise ValidationError("tax_bps must be an integer between 0 and 5000.")
    return raw_tax_bps


def calculate_invoice(
    items: list[LineItem],
    *,
    currency: str,
    tax_bps: int = 1000,
    discount_code: str | None = None,
) -> InvoiceSummary:
    validated_currency = validate_currency(currency)
    validated_tax_bps = validate_tax_bps(tax_bps)
    subtotal_cents = sum(item.line_total_cents for item in items)

    normalized_code: str | None = None
    discount_bps = 0
    if discount_code is not None and str(discount_code).strip() != "":
        normalized_code = str(discount_code).strip().upper()
        if normalized_code not in DISCOUNT_RATES_BPS:
            raise ValidationError(f"Unsupported discount_code: {normalized_code}")
        discount_bps = DISCOUNT_RATES_BPS[normalized_code]

    # Half-up integer basis-point rounding: (amount * bps + 5000) // 10000
    discount_cents = (subtotal_cents * discount_bps + 5_000) // 10_000
    taxable_cents = max(0, subtotal_cents - discount_cents)
    tax_cents = (taxable_cents * validated_tax_bps + 5_000) // 10_000
    total_cents = taxable_cents + tax_cents

    return InvoiceSummary(
        currency=validated_currency,
        subtotal_cents=subtotal_cents,
        discount_cents=discount_cents,
        taxable_cents=taxable_cents,
        tax_bps=validated_tax_bps,
        tax_cents=tax_cents,
        total_cents=total_cents,
        applied_discount_code=normalized_code,
    )


def compute_request_fingerprint(customer_id: str, currency: str, tax_bps: int, discount_code: str | None, items: list[LineItem]) -> str:
    canonical = json.dumps(
        {
            "customer_id": customer_id,
            "currency": currency,
            "tax_bps": tax_bps,
            "discount_code": (discount_code or "").strip().upper() or None,
            "items": [item.to_dict() for item in items],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
