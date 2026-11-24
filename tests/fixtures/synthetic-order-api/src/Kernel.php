<?php

declare(strict_types=1);

namespace AcmeBistro\OrderApi;

use AcmeBistro\OrderApi\Controllers\PaymentController;
use AcmeBistro\OrderApi\Database\DatabaseManager;
use AcmeBistro\OrderApi\Http\JsonResponse;
use AcmeBistro\OrderApi\Http\Request;
use AcmeBistro\OrderApi\Middleware\IdempotencyGuard;
use AcmeBistro\OrderApi\Middleware\OrderOwnershipMiddleware;
use AcmeBistro\OrderApi\Services\PaymentGatewayService;

final class Kernel
{
    private DatabaseManager $db;
    private PaymentGatewayService $gateway;
    private PaymentController $paymentController;
    private bool $seededVulns;

    /**
     * @param array<string, mixed>|null $configOverride
     */
    public function __construct(
        ?DatabaseManager $db = null,
        ?bool $seededVulns = null,
        ?array $configOverride = null,
    ) {
        /** @var array<string, mixed> $config */
        $config = $configOverride ?? require dirname(__DIR__) . '/config/security.php';

        $this->seededVulns = $seededVulns ?? (bool) ($config['seeded_vulns'] ?? false);
        $this->db = $db ?? new DatabaseManager('sqlite::memory:');

        /** @var array<string, mixed> $acmePayConfig */
        $acmePayConfig = (array) ($config['acmepay'] ?? []);
        /** @var list<string> $allowedHosts */
        $allowedHosts = array_values((array) ($config['allowed_callback_hosts'] ?? ['app.acmebistro.example']));
        /** @var list<string> $methods */
        $methods = array_values((array) ($acmePayConfig['supported_methods'] ?? ['card', 'wallet', 'bank_transfer']));

        $this->gateway = new PaymentGatewayService(
            allowedCallbackHosts: $allowedHosts,
            checkoutBaseUrl: (string) ($acmePayConfig['checkout_base_url'] ?? 'https://sandbox.acmepay.example.test/checkout'),
            webhookSigningKey: (string) ($acmePayConfig['webhook_signing_key'] ?? 'whsec_acmepay_synthetic_fixture_00000000'),
            supportedMethods: $methods,
            seededVulns: $this->seededVulns,
        );

        $ownership = new OrderOwnershipMiddleware($this->seededVulns);
        $idempotency = new IdempotencyGuard(
            db: $this->db,
            ttlSeconds: (int) ($config['idempotency_ttl_seconds'] ?? 86400),
            seededVulns: $this->seededVulns,
        );

        $this->paymentController = new PaymentController(
            db: $this->db,
            gateway: $this->gateway,
            ownershipMiddleware: $ownership,
            idempotencyGuard: $idempotency,
            seededVulns: $this->seededVulns,
        );
    }

    public static function bootFresh(bool $seededVulns = false): self
    {
        $db = new DatabaseManager('sqlite::memory:');
        $db->migrate();
        $db->seed();
        return new self($db, $seededVulns);
    }

    public function db(): DatabaseManager
    {
        return $this->db;
    }

    public function gateway(): PaymentGatewayService
    {
        return $this->gateway;
    }

    public function isSeededVulnsEnabled(): bool
    {
        return $this->seededVulns;
    }

    public function handle(Request $request, ?int $nowEpoch = null): JsonResponse
    {
        $method = $request->method();
        $path = rtrim($request->path(), '/') ?: '/';

        if ($method === 'GET' && $path === '/api/v1/health') {
            return new JsonResponse([
                'service' => 'AcmeBistro Order API',
                'status' => 'ok',
                'mode' => $this->seededVulns ? 'seeded_vulns' : 'patched_clean',
                'gateway' => 'AcmePaySandbox',
            ], 200);
        }

        if ($method === 'POST' && preg_match('#^/api/v1/orders/(\d+)/pay$#', $path, $matches) === 1) {
            return $this->paymentController->pay($request, (int) $matches[1], $nowEpoch);
        }

        if ($method === 'GET' && preg_match('#^/api/v1/orders/(\d+)/status$#', $path, $matches) === 1) {
            return $this->paymentController->status($request, (int) $matches[1]);
        }

        if ($method === 'POST' && $path === '/api/v1/webhooks/payment') {
            return $this->paymentController->webhook($request, $nowEpoch);
        }

        return new JsonResponse([
            'error' => 'ROUTE_NOT_FOUND',
            'message' => sprintf('No route matched %s %s', $method, $path),
        ], 404);
    }
}
