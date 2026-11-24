<?php

declare(strict_types=1);

namespace AcmeBistro\OrderApi\Services;

use InvalidArgumentException;

/**
 * AcmePay Offline Sandbox Simulator
 *
 * Pure deterministic in-memory payment simulator.
 * NEVER performs external HTTP calls, socket connections, or real payment processing.
 */
final class PaymentGatewayService
{
    /** @var list<string> */
    private array $allowedCallbackHosts;

    /** @var list<string> */
    private array $supportedMethods;

    /**
     * @param list<string> $allowedCallbackHosts
     * @param list<string> $supportedMethods
     */
    public function __construct(
        array $allowedCallbackHosts = ['app.acmebistro.example', 'checkout.acmebistro.example'],
        private readonly string $checkoutBaseUrl = 'https://sandbox.acmepay.example.test/checkout',
        private readonly string $webhookSigningKey = 'whsec_acmepay_synthetic_fixture_00000000',
        array $supportedMethods = ['card', 'wallet', 'bank_transfer'],
        private readonly bool $seededVulns = false,
    ) {
        $this->allowedCallbackHosts = array_values(array_map('strtolower', $allowedCallbackHosts));
        $this->supportedMethods = array_values($supportedMethods);
    }

    public function validateCallbackUrl(?string $callbackUrl): string
    {
        $defaultCallback = 'https://app.acmebistro.example/orders/return';
        if ($callbackUrl === null || trim($callbackUrl) === '') {
            return $defaultCallback;
        }

        $trimmed = trim($callbackUrl);

        // SYN-F03 (Seeded Baseline Mode): Passes unvalidated callback_url straight through,
        // enabling open redirects to untrusted external domains or unsafe URI schemes.
        if ($this->seededVulns) {
            return $trimmed;
        }

        // Patched Clean Mode: Strict scheme, credential-free, backslash-free, allowlisted host check.
        if (str_contains($trimmed, '\\') || preg_match('/[\r\n\0]/', $trimmed) === 1) {
            throw new InvalidArgumentException('Callback URL contains illegal characters.');
        }

        $parts = parse_url($trimmed);
        if (!is_array($parts)) {
            throw new InvalidArgumentException('Malformed callback URL.');
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));
        $hasCredentials = isset($parts['user']) || isset($parts['pass']);

        if ($scheme !== 'https' || $host === '' || $hasCredentials) {
            throw new InvalidArgumentException('Callback URL must use https:// without embedded credentials.');
        }

        if (!in_array($host, $this->allowedCallbackHosts, true)) {
            throw new InvalidArgumentException('Callback URL host is not in allowed_callback_hosts.');
        }

        return $trimmed;
    }

    /**
     * Creates a deterministic offline AcmePay sandbox checkout session.
     *
     * @return array{
     *   checkout_id: string,
     *   payment_reference: string,
     *   redirect_url: string,
     *   gateway: string,
     *   amount_cents: int,
     *   currency: string
     * }
     */
    public function createCheckoutSession(
        int $orderId,
        string $orderNumber,
        int $amountCents,
        string $currency,
        string $paymentMethod,
        ?string $callbackUrl = null,
    ): array {
        if (!in_array($paymentMethod, $this->supportedMethods, true)) {
            throw new InvalidArgumentException('Unsupported payment_method: ' . $paymentMethod);
        }

        if ($amountCents <= 0) {
            throw new InvalidArgumentException('Payment amount_cents must be greater than zero.');
        }

        $validatedCallback = $this->validateCallbackUrl($callbackUrl);
        $digest = hash(
            'sha256',
            implode('|', [$orderId, $orderNumber, $amountCents, $currency, $paymentMethod, $validatedCallback])
        );

        $checkoutId = 'chk_sandbox_' . substr($digest, 0, 16);
        $paymentReference = 'payref_sandbox_' . $orderId . '_' . substr($digest, 16, 12);
        $redirectUrl = rtrim($this->checkoutBaseUrl, '/') . '/' . $checkoutId
            . '?return_to=' . rawurlencode($validatedCallback);

        return [
            'checkout_id' => $checkoutId,
            'payment_reference' => $paymentReference,
            'redirect_url' => $redirectUrl,
            'gateway' => 'AcmePaySandbox',
            'amount_cents' => $amountCents,
            'currency' => strtoupper($currency),
        ];
    }

    public function signWebhookPayload(string $rawBody): string
    {
        return 'sha256=' . hash_hmac('sha256', $rawBody, $this->webhookSigningKey);
    }

    public function verifyWebhookSignature(string $rawBody, ?string $signatureHeader): bool
    {
        if ($signatureHeader === null || !str_starts_with($signatureHeader, 'sha256=')) {
            return false;
        }
        $expected = $this->signWebhookPayload($rawBody);
        return hash_equals($expected, trim($signatureHeader));
    }
}
