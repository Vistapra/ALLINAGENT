<?php

declare(strict_types=1);

namespace AcmeBistro\OrderApi\Controllers;

use AcmeBistro\OrderApi\Database\DatabaseManager;
use AcmeBistro\OrderApi\Http\JsonResponse;
use AcmeBistro\OrderApi\Http\Request;
use AcmeBistro\OrderApi\Middleware\IdempotencyGuard;
use AcmeBistro\OrderApi\Middleware\OrderOwnershipMiddleware;
use AcmeBistro\OrderApi\Services\PaymentGatewayService;
use InvalidArgumentException;
use Throwable;

final class PaymentController
{
    public function __construct(
        private readonly DatabaseManager $db,
        private readonly PaymentGatewayService $gateway,
        private readonly OrderOwnershipMiddleware $ownershipMiddleware,
        private readonly IdempotencyGuard $idempotencyGuard,
        private readonly bool $seededVulns = false,
    ) {
    }

    /**
     * POST /api/v1/orders/{id}/pay
     */
    public function pay(Request $request, int $orderId, ?int $nowEpoch = null): JsonResponse
    {
        if (!$request->hasValidJson()) {
            return new JsonResponse([
                'error' => 'INVALID_JSON',
                'message' => 'Request body must be valid JSON.',
            ], 400);
        }

        $order = $this->db->findOrder($orderId);
        if ($order === null) {
            return new JsonResponse([
                'error' => 'ORDER_NOT_FOUND',
                'message' => 'Order not found.',
            ], 404);
        }

        $auth = $this->ownershipMiddleware->verify($request, $order);
        if (!$auth['authorized']) {
            /** @var JsonResponse $errorResponse */
            $errorResponse = $auth['error'];
            return $errorResponse;
        }

        return $this->idempotencyGuard->handle(
            $request,
            $orderId,
            $auth['actor'],
            function () use ($request, $orderId, $nowEpoch): JsonResponse {
                $freshOrder = $this->db->findOrder($orderId);
                if ($freshOrder === null) {
                    return new JsonResponse([
                        'error' => 'ORDER_NOT_FOUND',
                        'message' => 'Order not found.',
                    ], 404);
                }

                if ((string) $freshOrder['status'] === 'paid') {
                    return new JsonResponse([
                        'error' => 'ORDER_ALREADY_PAID',
                        'message' => 'Order has already been settled.',
                    ], 409);
                }

                $paymentMethod = (string) $request->input('payment_method', '');
                if ($paymentMethod === '') {
                    return new JsonResponse([
                        'error' => 'MISSING_PAYMENT_METHOD',
                        'message' => 'Field payment_method is required.',
                    ], 422);
                }

                $authoritativeTotal = $this->db->calculateAuthoritativeTotalCents($orderId);
                $clientAmountRaw = $request->input('amount_cents');

                // SYN-F01: Seeded Baseline Mode trusts client-supplied amount_cents when present.
                // Patched Clean Mode strictly enforces server-computed authoritative order total.
                if ($this->seededVulns && $clientAmountRaw !== null) {
                    if (!is_int($clientAmountRaw) || $clientAmountRaw <= 0) {
                        return new JsonResponse([
                            'error' => 'INVALID_AMOUNT',
                            'message' => 'amount_cents must be a positive integer.',
                        ], 422);
                    }
                    $payableAmountCents = $clientAmountRaw;
                } else {
                    if ($clientAmountRaw !== null) {
                        if (!is_int($clientAmountRaw) || $clientAmountRaw !== $authoritativeTotal) {
                            return new JsonResponse([
                                'error' => 'AMOUNT_MISMATCH',
                                'message' => sprintf(
                                    'Client amount_cents (%s) does not match server authoritative total (%d).',
                                    json_encode($clientAmountRaw),
                                    $authoritativeTotal
                                ),
                                'authoritative_total_cents' => $authoritativeTotal,
                            ], 422);
                        }
                    }
                    $payableAmountCents = $authoritativeTotal;
                }

                $callbackUrl = $request->input('callback_url');
                if ($callbackUrl !== null && !is_string($callbackUrl)) {
                    return new JsonResponse([
                        'error' => 'INVALID_CALLBACK_URL',
                        'message' => 'callback_url must be a string URI.',
                    ], 422);
                }

                try {
                    $session = $this->gateway->createCheckoutSession(
                        orderId: $orderId,
                        orderNumber: (string) $freshOrder['order_number'],
                        amountCents: $payableAmountCents,
                        currency: (string) $freshOrder['currency'],
                        paymentMethod: $paymentMethod,
                        callbackUrl: $callbackUrl,
                    );
                } catch (InvalidArgumentException $e) {
                    $isCallbackError = str_contains(strtolower($e->getMessage()), 'callback');
                    return new JsonResponse([
                        'error' => $isCallbackError ? 'INVALID_CALLBACK_URL' : 'INVALID_PAYMENT_REQUEST',
                        'message' => $e->getMessage(),
                    ], 422);
                }

                $nowIso = gmdate('Y-m-d\TH:i:s\Z', $nowEpoch ?? time());
                $stmt = $this->db->pdo()->prepare(
                    'UPDATE orders
                     SET status = :status, payment_reference = :payment_reference, updated_at = :updated_at
                     WHERE id = :id'
                );
                $stmt->execute([
                    ':status' => 'checkout_initiated',
                    ':payment_reference' => $session['payment_reference'],
                    ':updated_at' => $nowIso,
                    ':id' => $orderId,
                ]);

                return new JsonResponse([
                    'order_id' => $orderId,
                    'order_number' => (string) $freshOrder['order_number'],
                    'status' => 'checkout_initiated',
                    'amount_cents' => $session['amount_cents'],
                    'currency' => $session['currency'],
                    'checkout_id' => $session['checkout_id'],
                    'payment_reference' => $session['payment_reference'],
                    'redirect_url' => $session['redirect_url'],
                    'gateway' => $session['gateway'],
                ], 200);
            },
            $nowEpoch
        );
    }

    /**
     * GET /api/v1/orders/{id}/status
     */
    public function status(Request $request, int $orderId): JsonResponse
    {
        $order = $this->db->findOrder($orderId);
        if ($order === null) {
            return new JsonResponse([
                'error' => 'ORDER_NOT_FOUND',
                'message' => 'Order not found.',
            ], 404);
        }

        $auth = $this->ownershipMiddleware->verify($request, $order);
        if (!$auth['authorized']) {
            /** @var JsonResponse $errorResponse */
            $errorResponse = $auth['error'];
            return $errorResponse;
        }

        $items = $this->db->findOrderItems($orderId);
        $authoritativeTotal = $this->db->calculateAuthoritativeTotalCents($orderId);

        return new JsonResponse([
            'order_id' => (int) $order['id'],
            'order_number' => (string) $order['order_number'],
            'status' => (string) $order['status'],
            'currency' => (string) $order['currency'],
            'subtotal_cents' => (int) $order['subtotal_cents'],
            'tax_cents' => (int) $order['tax_cents'],
            'discount_cents' => (int) $order['discount_cents'],
            'authoritative_total_cents' => $authoritativeTotal,
            'payment_reference' => $order['payment_reference'],
            'paid_amount_cents' => $order['paid_amount_cents'] !== null ? (int) $order['paid_amount_cents'] : null,
            'paid_at' => $order['paid_at'],
            'items' => array_map(static fn (array $item): array => [
                'sku' => (string) $item['sku'],
                'item_name' => (string) $item['item_name'],
                'quantity' => (int) $item['quantity'],
                'unit_price_cents' => (int) $item['unit_price_cents'],
                'line_total_cents' => (int) $item['line_total_cents'],
            ], $items),
        ], 200);
    }

    /**
     * POST /api/v1/webhooks/payment
     */
    public function webhook(Request $request, ?int $nowEpoch = null): JsonResponse
    {
        $signature = $request->header('X-AcmePay-Signature');
        if (!$this->gateway->verifyWebhookSignature($request->rawBody(), $signature)) {
            return new JsonResponse([
                'error' => 'INVALID_WEBHOOK_SIGNATURE',
                'message' => 'Webhook HMAC-SHA256 signature verification failed.',
            ], 401);
        }

        if (!$request->hasValidJson()) {
            return new JsonResponse([
                'error' => 'INVALID_JSON',
                'message' => 'Webhook payload must be valid JSON.',
            ], 400);
        }

        $eventId = (string) $request->input('event_id', '');
        $eventType = (string) $request->input('event_type', '');
        $orderId = $request->input('order_id');
        $paymentReference = (string) $request->input('payment_reference', '');
        $amountCents = $request->input('amount_cents');

        if ($eventId === '' || $eventType === '' || !is_int($orderId) || $paymentReference === '' || !is_int($amountCents)) {
            return new JsonResponse([
                'error' => 'INVALID_WEBHOOK_PAYLOAD',
                'message' => 'Missing or invalid required webhook fields.',
            ], 422);
        }

        $dupStmt = $this->db->pdo()->prepare('SELECT id FROM payment_webhook_events WHERE event_id = :event_id LIMIT 1');
        $dupStmt->execute([':event_id' => $eventId]);
        if ($dupStmt->fetch() !== false) {
            return new JsonResponse([
                'status' => 'duplicate_ignored',
                'event_id' => $eventId,
            ], 200);
        }

        $order = $this->db->findOrder($orderId);
        if ($order === null) {
            return new JsonResponse([
                'error' => 'ORDER_NOT_FOUND',
                'message' => 'Referenced order does not exist.',
            ], 404);
        }

        $authoritativeTotal = $this->db->calculateAuthoritativeTotalCents($orderId);
        if (!$this->seededVulns && $eventType === 'payment.succeeded' && $amountCents !== $authoritativeTotal) {
            return new JsonResponse([
                'error' => 'WEBHOOK_AMOUNT_MISMATCH',
                'message' => 'Settled webhook amount does not match server authoritative order total.',
            ], 422);
        }

        $nowIso = gmdate('Y-m-d\TH:i:s\Z', $nowEpoch ?? time());
        $pdo = $this->db->pdo();
        $pdo->beginTransaction();

        try {
            $insertEvent = $pdo->prepare(
                'INSERT INTO payment_webhook_events (
                    event_id, order_id, payment_reference, event_type, amount_cents, processed_at
                ) VALUES (
                    :event_id, :order_id, :payment_reference, :event_type, :amount_cents, :processed_at
                )'
            );
            $insertEvent->execute([
                ':event_id' => $eventId,
                ':order_id' => $orderId,
                ':payment_reference' => $paymentReference,
                ':event_type' => $eventType,
                ':amount_cents' => $amountCents,
                ':processed_at' => $nowIso,
            ]);

            if ($eventType === 'payment.succeeded') {
                $updateOrder = $pdo->prepare(
                    'UPDATE orders
                     SET status = :status, payment_reference = :ref, paid_amount_cents = :paid_amount,
                         paid_at = :paid_at, updated_at = :updated_at
                     WHERE id = :id'
                );
                $updateOrder->execute([
                    ':status' => 'paid',
                    ':ref' => $paymentReference,
                    ':paid_amount' => $amountCents,
                    ':paid_at' => $nowIso,
                    ':updated_at' => $nowIso,
                    ':id' => $orderId,
                ]);
            } elseif ($eventType === 'payment.failed') {
                $updateOrder = $pdo->prepare(
                    'UPDATE orders
                     SET status = :status, payment_reference = :ref, updated_at = :updated_at
                     WHERE id = :id AND status != :paid_status'
                );
                $updateOrder->execute([
                    ':status' => 'failed',
                    ':ref' => $paymentReference,
                    ':updated_at' => $nowIso,
                    ':id' => $orderId,
                    ':paid_status' => 'paid',
                ]);
            } else {
                $pdo->rollBack();
                return new JsonResponse([
                    'error' => 'UNSUPPORTED_WEBHOOK_EVENT',
                    'message' => 'Unsupported event_type: ' . $eventType,
                ], 422);
            }

            $pdo->commit();
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }

        return new JsonResponse([
            'status' => 'processed',
            'event_id' => $eventId,
            'order_id' => $orderId,
            'order_status' => $eventType === 'payment.succeeded' ? 'paid' : 'failed',
        ], 200);
    }
}
