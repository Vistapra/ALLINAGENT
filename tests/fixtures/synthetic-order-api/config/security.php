<?php

declare(strict_types=1);

/**
 * AcmeBistro Order API - Synthetic Security & Sandbox Configuration
 *
 * 100% synthetic test-only constants. Never uses real payment keys or external network calls.
 */
return [
    'app_name' => 'AcmeBistro Order API',
    'environment' => 'testing',
    'seeded_vulns' => in_array(
        strtolower((string) (getenv('ACME_SEEDED_VULNS') ?: '0')),
        ['1', 'true', 'yes', 'on'],
        true
    ),
    'allowed_callback_hosts' => [
        'app.acmebistro.example',
        'checkout.acmebistro.example',
    ],
    'idempotency_ttl_seconds' => 86400,
    'acmepay' => [
        'provider_name' => 'AcmePay Offline Sandbox Simulator',
        'checkout_base_url' => 'https://sandbox.acmepay.example.test/checkout',
        'webhook_signing_key' => 'whsec_acmepay_synthetic_fixture_00000000',
        'supported_methods' => ['card', 'wallet', 'bank_transfer'],
    ],
];
