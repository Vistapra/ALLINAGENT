-- AcmeBistro Order API - Database Migration 001
-- Creates orders, order_items, checkout_idempotency_keys (with expires_at TTL), and payment_webhook_events.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_number VARCHAR(32) NOT NULL UNIQUE,
    user_id INTEGER NULL,
    guest_token_hash VARCHAR(64) NULL,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    subtotal_cents INTEGER NOT NULL DEFAULT 0 CHECK (subtotal_cents >= 0),
    tax_cents INTEGER NOT NULL DEFAULT 0 CHECK (tax_cents >= 0),
    discount_cents INTEGER NOT NULL DEFAULT 0 CHECK (discount_cents >= 0),
    total_cents INTEGER NOT NULL DEFAULT 0 CHECK (total_cents >= 0),
    status VARCHAR(24) NOT NULL DEFAULT 'pending_payment',
    payment_reference VARCHAR(64) NULL,
    paid_amount_cents INTEGER NULL,
    paid_at VARCHAR(32) NULL,
    created_at VARCHAR(32) NOT NULL,
    updated_at VARCHAR(32) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders (user_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders (status);

CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    sku VARCHAR(32) NOT NULL,
    item_name VARCHAR(120) NOT NULL,
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    unit_price_cents INTEGER NOT NULL CHECK (unit_price_cents >= 0),
    line_total_cents INTEGER NOT NULL CHECK (line_total_cents >= 0),
    FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_order_items_order_id ON order_items (order_id);

CREATE TABLE IF NOT EXISTS checkout_idempotency_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    idempotency_key VARCHAR(128) NOT NULL,
    order_id INTEGER NOT NULL,
    actor_fingerprint VARCHAR(128) NOT NULL,
    request_hash VARCHAR(64) NOT NULL,
    response_status INTEGER NOT NULL,
    response_body TEXT NOT NULL,
    created_at VARCHAR(32) NOT NULL,
    expires_at VARCHAR(32) NOT NULL,
    UNIQUE (order_id, idempotency_key),
    FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_idempotency_expires_at ON checkout_idempotency_keys (expires_at);

CREATE TABLE IF NOT EXISTS payment_webhook_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id VARCHAR(64) NOT NULL UNIQUE,
    order_id INTEGER NOT NULL,
    payment_reference VARCHAR(64) NOT NULL,
    event_type VARCHAR(48) NOT NULL,
    amount_cents INTEGER NOT NULL CHECK (amount_cents >= 0),
    processed_at VARCHAR(32) NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE
);
