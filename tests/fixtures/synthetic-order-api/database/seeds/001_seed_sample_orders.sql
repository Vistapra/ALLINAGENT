-- AcmeBistro Order API - Deterministic Synthetic Seed Data
-- Zero private identifiers; 100% fictional menu items and synthetic actors.

INSERT INTO orders (
    id, order_number, user_id, guest_token_hash, currency,
    subtotal_cents, tax_cents, discount_cents, total_cents,
    status, payment_reference, paid_amount_cents, paid_at, created_at, updated_at
) VALUES
    (
        1001, 'ORD-2026-1001', 42, NULL, 'USD',
        3450, 345, 200, 3595,
        'pending_payment', NULL, NULL, NULL,
        '2026-01-15T12:00:00Z', '2026-01-15T12:00:00Z'
    ),
    (
        1002, 'ORD-2026-1002', NULL, '37c8d8c4f2841a7ae53751668f084661c268ccbce1842933febc7c4970149901', 'USD',
        1800, 180, 0, 1980,
        'pending_payment', NULL, NULL, NULL,
        '2026-01-15T12:05:00Z', '2026-01-15T12:05:00Z'
    ),
    (
        1003, 'ORD-2026-1003', 99, NULL, 'USD',
        850, 85, 0, 935,
        'pending_payment', NULL, NULL, NULL,
        '2026-01-15T12:10:00Z', '2026-01-15T12:10:00Z'
    );

INSERT INTO order_items (order_id, sku, item_name, quantity, unit_price_cents, line_total_cents) VALUES
    (1001, 'BISTRO-BURGER', 'Truffle Mushroom Burger', 2, 1450, 2900),
    (1001, 'CITRUS-FIZZ', 'Sparkling Yuzu Lemonade', 1, 550, 550),
    (1002, 'MARGHERITA-12', 'Wood-Fired Margherita Pizza', 1, 1800, 1800),
    (1003, 'ESPRESSO-DBL', 'Double Espresso', 2, 425, 850);

-- Pre-seeded expired idempotency key (expired in 2020) for verifying SYN-F04 TTL eviction.
INSERT INTO checkout_idempotency_keys (
    idempotency_key, order_id, actor_fingerprint, request_hash,
    response_status, response_body, created_at, expires_at
) VALUES (
    'idem_expired_legacy_key_001',
    1001,
    'user:42',
    '0000000000000000000000000000000000000000000000000000000000000000',
    200,
    '{"order_id":1001,"checkout_id":"chk_stale_expired_2020","amount_cents":3595,"status":"checkout_initiated","stale_record":true}',
    '2020-01-01T00:00:00Z',
    '2020-01-02T00:00:00Z'
);
