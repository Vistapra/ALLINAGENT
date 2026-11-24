<?php

declare(strict_types=1);

namespace AcmeBistro\OrderApi\Tests;

require_once dirname(__DIR__) . '/src/bootstrap.php';

use AcmeBistro\OrderApi\Http\Request;
use AcmeBistro\OrderApi\Kernel;
use RuntimeException;
use Throwable;

if (!class_exists(\PHPUnit\Framework\TestCase::class)) {
    abstract class StandaloneTestCase
    {
        protected function assertSame(mixed $expected, mixed $actual, string $message = ''): void
        {
            if ($expected !== $actual) {
                $detail = sprintf(
                    '%s Expected %s, got %s.',
                    $message !== '' ? $message . ' -' : 'Assertion failed:',
                    var_export($expected, true),
                    var_export($actual, true)
                );
                throw new RuntimeException(trim($detail));
            }
        }

        protected function assertTrue(bool $condition, string $message = ''): void
        {
            if (!$condition) {
                throw new RuntimeException($message !== '' ? $message : 'Expected true, got false.');
            }
        }

        protected function assertFalse(bool $condition, string $message = ''): void
        {
            if ($condition) {
                throw new RuntimeException($message !== '' ? $message : 'Expected false, got true.');
            }
        }
    }

    class_alias(StandaloneTestCase::class, 'AcmeBistro\\OrderApi\\Tests\\BaseTestCase');
} else {
    class_alias(\PHPUnit\Framework\TestCase::class, 'AcmeBistro\\OrderApi\\Tests\\BaseTestCase');
}

final class PaymentSecurityTest extends BaseTestCase
{
    private bool $seededVulns;

    public function __construct(bool $seededVulns = false)
    {
        if (method_exists(BaseTestCase::class, '__construct')) {
            parent::__construct('PaymentSecurityTest');
        }
        $envSeeded = in_array(
            strtolower((string) (getenv('ACME_SEEDED_VULNS') ?: '0')),
            ['1', 'true', 'yes', 'on'],
            true
        );
        $this->seededVulns = $seededVulns || $envSeeded;
    }

    public function testHappyPathCustomerCheckoutAndWebhookSettlement(): void
    {
        $kernel = Kernel::bootFresh($this->seededVulns);
        $fixedEpoch = 1768478400; // 2026-01-15T12:00:00Z

        $payReq = Request::jsonRequest(
            'POST',
            '/api/v1/orders/1001/pay',
            [
                'payment_method' => 'card',
                'callback_url' => 'https://app.acmebistro.example/orders/1001/complete',
            ],
            [
                'X-User-Id' => '42',
                'Idempotency-Key' => 'idem_happy_1001_v1',
            ]
        );

        $payRes = $kernel->handle($payReq, $fixedEpoch);
        $this->assertSame(200, $payRes->status(), 'Expected 200 on valid customer checkout');
        $this->assertSame(3595, $payRes->data()['amount_cents'], 'Expected authoritative 3595 cents');
        $this->assertSame('false', $payRes->header('X-Idempotency-Replayed'));

        $paymentRef = (string) $payRes->data()['payment_reference'];
        $this->assertTrue(str_starts_with($paymentRef, 'payref_sandbox_1001_'));

        // Idempotent retry with identical payload returns cached session
        $retryRes = $kernel->handle($payReq, $fixedEpoch + 10);
        $this->assertSame(200, $retryRes->status());
        $this->assertSame('true', $retryRes->header('X-Idempotency-Replayed'));
        $this->assertSame($payRes->data()['checkout_id'], $retryRes->data()['checkout_id']);

        // Signed AcmePay settlement webhook marks order paid
        $webhookPayload = [
            'event_id' => 'evt_sandbox_1001_settled',
            'event_type' => 'payment.succeeded',
            'order_id' => 1001,
            'payment_reference' => $paymentRef,
            'amount_cents' => 3595,
        ];
        $rawWebhook = (string) json_encode($webhookPayload, JSON_UNESCAPED_SLASHES);
        $sig = $kernel->gateway()->signWebhookPayload($rawWebhook);

        $webhookReq = new Request(
            'POST',
            '/api/v1/webhooks/payment',
            ['Content-Type' => 'application/json', 'X-AcmePay-Signature' => $sig],
            $rawWebhook
        );
        $webhookRes = $kernel->handle($webhookReq, $fixedEpoch + 30);
        $this->assertSame(200, $webhookRes->status());
        $this->assertSame('processed', $webhookRes->data()['status']);

        // Duplicate webhook delivery is safely deduplicated
        $dupRes = $kernel->handle($webhookReq, $fixedEpoch + 35);
        $this->assertSame(200, $dupRes->status());
        $this->assertSame('duplicate_ignored', $dupRes->data()['status']);

        // Status endpoint reflects paid settlement
        $statusReq = new Request('GET', '/api/v1/orders/1001/status', ['X-User-Id' => '42']);
        $statusRes = $kernel->handle($statusReq);
        $this->assertSame(200, $statusRes->status());
        $this->assertSame('paid', $statusRes->data()['status']);
        $this->assertSame(3595, $statusRes->data()['paid_amount_cents']);
    }

    public function testGuestCheckoutAndWebhookAuthentication(): void
    {
        $kernel = Kernel::bootFresh($this->seededVulns);

        // Missing auth headers -> 401
        $unauthRes = $kernel->handle(new Request('GET', '/api/v1/orders/1002/status'));
        $this->assertSame(401, $unauthRes->status());

        // Valid guest token -> 200
        $guestPay = Request::jsonRequest(
            'POST',
            '/api/v1/orders/1002/pay',
            ['payment_method' => 'wallet'],
            ['X-Guest-Token' => 'guest_tok_bistro_order_1002']
        );
        $guestRes = $kernel->handle($guestPay, 1768478500);
        $this->assertSame(200, $guestRes->status());
        $this->assertSame(1980, $guestRes->data()['amount_cents']);

        // Forged webhook HMAC signature -> 401
        $forgedWebhook = Request::jsonRequest(
            'POST',
            '/api/v1/webhooks/payment',
            [
                'event_id' => 'evt_forged_1',
                'event_type' => 'payment.succeeded',
                'order_id' => 1002,
                'payment_reference' => 'payref_forged',
                'amount_cents' => 1980,
            ],
            ['X-AcmePay-Signature' => 'sha256=deadbeef0000']
        );
        $forgedRes = $kernel->handle($forgedWebhook);
        $this->assertSame(401, $forgedRes->status());
    }

    /**
     * SYN-F01: Server-authoritative amount calculation must reject client underpayment tampering.
     */
    public function testSynF01ServerAuthoritativeAmountEnforced(): void
    {
        $kernel = Kernel::bootFresh($this->seededVulns);

        $tamperedPay = Request::jsonRequest(
            'POST',
            '/api/v1/orders/1001/pay',
            [
                'payment_method' => 'card',
                'amount_cents' => 100, // Tampered $1.00 instead of authoritative $35.95 (3595 cents)
            ],
            ['X-User-Id' => '42']
        );

        $res = $kernel->handle($tamperedPay, 1768478600);
        $this->assertSame(
            422,
            $res->status(),
            '[SYN-F01] Client-supplied underpaid amount_cents=100 must be rejected with HTTP 422'
        );
        $this->assertSame('AMOUNT_MISMATCH', $res->data()['error'] ?? null);
    }

    /**
     * SYN-F02: Object-level order ownership check must prevent cross-user/guest IDOR access.
     */
    public function testSynF02OrderOwnershipIdorBlocked(): void
    {
        $kernel = Kernel::bootFresh($this->seededVulns);

        // User 42 attempting to inspect Order 1003 owned by User 99
        $idorStatus = new Request('GET', '/api/v1/orders/1003/status', ['X-User-Id' => '42']);
        $statusRes = $kernel->handle($idorStatus);
        $this->assertSame(
            403,
            $statusRes->status(),
            '[SYN-F02] Cross-customer GET /orders/1003/status by user 42 must be blocked with HTTP 403'
        );

        // User 42 attempting to pay Guest Order 1002
        $idorPay = Request::jsonRequest(
            'POST',
            '/api/v1/orders/1002/pay',
            ['payment_method' => 'card'],
            ['X-User-Id' => '42']
        );
        $payRes = $kernel->handle($idorPay, 1768478700);
        $this->assertSame(
            403,
            $payRes->status(),
            '[SYN-F02] Unauthorized POST /orders/1002/pay must be blocked with HTTP 403'
        );
    }

    /**
     * SYN-F03: Callback URL validation must block open redirects and non-HTTPS schemes.
     */
    public function testSynF03CallbackUrlOpenRedirectBlocked(): void
    {
        $kernel = Kernel::bootFresh($this->seededVulns);

        $evilPay = Request::jsonRequest(
            'POST',
            '/api/v1/orders/1001/pay',
            [
                'payment_method' => 'card',
                'callback_url' => 'https://evil-phishing.attacker.example/steal-token',
            ],
            ['X-User-Id' => '42']
        );

        $res = $kernel->handle($evilPay, 1768478800);
        $this->assertSame(
            422,
            $res->status(),
            '[SYN-F03] Untrusted external callback_url must be rejected with HTTP 422'
        );
        $this->assertSame('INVALID_CALLBACK_URL', $res->data()['error'] ?? null);

        $jsSchemePay = Request::jsonRequest(
            'POST',
            '/api/v1/orders/1001/pay',
            [
                'payment_method' => 'card',
                'callback_url' => 'javascript:alert(document.cookie)',
            ],
            ['X-User-Id' => '42']
        );
        $jsRes = $kernel->handle($jsSchemePay, 1768478810);
        $this->assertSame(422, $jsRes->status(), '[SYN-F03] javascript: callback_url must be rejected');
    }

    /**
     * SYN-F04: Expired idempotency keys must be purged and never replay stale checkout records.
     */
    public function testSynF04IdempotencyExpirationCleanupEnforced(): void
    {
        $kernel = Kernel::bootFresh($this->seededVulns);
        $nowEpoch = 1768478900; // 2026-01-15 (well past 2020-01-02 expires_at of seeded key)

        $reqWithExpiredKey = Request::jsonRequest(
            'POST',
            '/api/v1/orders/1001/pay',
            ['payment_method' => 'card'],
            [
                'X-User-Id' => '42',
                'Idempotency-Key' => 'idem_expired_legacy_key_001',
            ]
        );

        $res = $kernel->handle($reqWithExpiredKey, $nowEpoch);
        $this->assertSame(200, $res->status());
        $this->assertFalse(
            (bool) ($res->data()['stale_record'] ?? false),
            '[SYN-F04] Expired idempotency key must be purged rather than replaying stale 2020 checkout'
        );
        $this->assertSame('false', $res->header('X-Idempotency-Replayed'));

        // Active key reused with mutated payload must return 409 Conflict
        $mutatedReq = Request::jsonRequest(
            'POST',
            '/api/v1/orders/1001/pay',
            ['payment_method' => 'bank_transfer'],
            [
                'X-User-Id' => '42',
                'Idempotency-Key' => 'idem_expired_legacy_key_001',
            ]
        );
        $conflictRes = $kernel->handle($mutatedReq, $nowEpoch + 5);
        $this->assertSame(409, $conflictRes->status(), '[SYN-F04] Mutated payload on active key must return 409');
    }
}

if (PHP_SAPI === 'cli' && isset($_SERVER['SCRIPT_FILENAME']) && realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    $args = array_slice($argv ?? [], 1);
    $withSeededVulns = in_array('--with-seeded-vulns', $args, true);
    $assertSeededVulns = in_array('--assert-seeded-vulns', $args, true);
    $jsonOutput = in_array('--json', $args, true);

    $suite = new PaymentSecurityTest($withSeededVulns || $assertSeededVulns);
    $methods = [
        'testHappyPathCustomerCheckoutAndWebhookSettlement',
        'testGuestCheckoutAndWebhookAuthentication',
        'testSynF01ServerAuthoritativeAmountEnforced',
        'testSynF02OrderOwnershipIdorBlocked',
        'testSynF03CallbackUrlOpenRedirectBlocked',
        'testSynF04IdempotencyExpirationCleanupEnforced',
    ];

    $results = [];
    $failedCount = 0;

    foreach ($methods as $method) {
        try {
            $suite->{$method}();
            $results[] = ['test' => $method, 'status' => 'PASS', 'error' => null];
        } catch (Throwable $e) {
            $failedCount++;
            $results[] = ['test' => $method, 'status' => 'FAIL', 'error' => $e->getMessage()];
        }
    }

    $expectedSecurityFailures = [
        'testSynF01ServerAuthoritativeAmountEnforced',
        'testSynF02OrderOwnershipIdorBlocked',
        'testSynF03CallbackUrlOpenRedirectBlocked',
        'testSynF04IdempotencyExpirationCleanupEnforced',
    ];

    if ($assertSeededVulns) {
        $actualFailedNames = array_values(array_map(
            static fn (array $r): string => $r['test'],
            array_filter($results, static fn (array $r): bool => $r['status'] === 'FAIL')
        ));
        $matchedExact = $actualFailedNames === $expectedSecurityFailures;
        $exitCode = $matchedExact ? 0 : 1;
    } else {
        $exitCode = $failedCount === 0 ? 0 : 1;
    }

    $summary = [
        'runner' => 'php-cli',
        'php_version' => PHP_VERSION,
        'mode' => ($withSeededVulns || $assertSeededVulns) ? 'seeded_vulns' : 'patched_clean',
        'assert_seeded_vulns' => $assertSeededVulns,
        'total' => count($results),
        'passed' => count($results) - $failedCount,
        'failed' => $failedCount,
        'exit_code' => $exitCode,
        'results' => $results,
    ];

    if ($jsonOutput) {
        echo json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    } else {
        echo sprintf(
            "AcmeBistro PHP Security Suite [mode=%s, php=%s]\n",
            $summary['mode'],
            PHP_VERSION
        );
        foreach ($results as $r) {
            echo sprintf(
                "  [%s] %s%s\n",
                $r['status'],
                $r['test'],
                $r['error'] !== null ? ' :: ' . $r['error'] : ''
            );
        }
        echo sprintf(
            "Summary: %d/%d passed (%d failed)%s\n",
            $summary['passed'],
            $summary['total'],
            $summary['failed'],
            $assertSeededVulns ? ' [Seeded baseline reproduction verified]' : ''
        );
    }

    exit($exitCode);
}
