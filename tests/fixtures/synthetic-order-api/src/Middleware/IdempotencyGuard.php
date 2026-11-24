<?php

declare(strict_types=1);

namespace AcmeBistro\OrderApi\Middleware;

use AcmeBistro\OrderApi\Database\DatabaseManager;
use AcmeBistro\OrderApi\Http\JsonResponse;
use AcmeBistro\OrderApi\Http\Request;

final class IdempotencyGuard
{
    public function __construct(
        private readonly DatabaseManager $db,
        private readonly int $ttlSeconds = 86400,
        private readonly bool $seededVulns = false,
    ) {
    }

    /**
     * Purges expired idempotency records where expires_at <= $nowIso.
     */
    public function purgeExpiredKeys(string $nowIso): int
    {
        $stmt = $this->db->pdo()->prepare(
            'DELETE FROM checkout_idempotency_keys WHERE expires_at <= :now'
        );
        $stmt->execute([':now' => $nowIso]);
        return $stmt->rowCount();
    }

    /**
     * @param callable(): JsonResponse $next
     */
    public function handle(
        Request $request,
        int $orderId,
        string $actorFingerprint,
        callable $next,
        ?int $nowEpoch = null,
    ): JsonResponse {
        $key = $request->header('Idempotency-Key');
        if ($key === null || $key === '') {
            return $next()->withHeader('X-Idempotency-Replayed', 'false');
        }

        if (strlen($key) > 128) {
            return new JsonResponse([
                'error' => 'INVALID_IDEMPOTENCY_KEY',
                'message' => 'Idempotency-Key header must not exceed 128 characters.',
            ], 422);
        }

        $epoch = $nowEpoch ?? time();
        $nowIso = gmdate('Y-m-d\TH:i:s\Z', $epoch);
        $expiresIso = gmdate('Y-m-d\TH:i:s\Z', $epoch + $this->ttlSeconds);
        $requestHash = $this->computeRequestHash($request, $actorFingerprint);

        // SYN-F04: In Patched Clean Mode, proactively evict expired keys before lookup.
        // In Seeded Baseline Mode, expiration cleanup is missing, leaving stale rows in SQLite
        // and replaying expired responses after TTL expiration.
        if (!$this->seededVulns) {
            $this->purgeExpiredKeys($nowIso);
            $stmt = $this->db->pdo()->prepare(
                'SELECT * FROM checkout_idempotency_keys
                 WHERE order_id = :order_id AND idempotency_key = :key AND expires_at > :now
                 LIMIT 1'
            );
            $stmt->execute([
                ':order_id' => $orderId,
                ':key' => $key,
                ':now' => $nowIso,
            ]);
        } else {
            $stmt = $this->db->pdo()->prepare(
                'SELECT * FROM checkout_idempotency_keys
                 WHERE order_id = :order_id AND idempotency_key = :key
                 LIMIT 1'
            );
            $stmt->execute([
                ':order_id' => $orderId,
                ':key' => $key,
            ]);
        }

        $existing = $stmt->fetch();
        if (is_array($existing)) {
            if (!$this->seededVulns && !hash_equals((string) $existing['request_hash'], $requestHash)) {
                return new JsonResponse([
                    'error' => 'IDEMPOTENCY_PAYLOAD_MISMATCH',
                    'message' => 'Idempotency-Key was already used with a different request payload or actor.',
                ], 409);
            }

            $cachedPayload = json_decode((string) $existing['response_body'], true);
            return (new JsonResponse(
                is_array($cachedPayload) ? $cachedPayload : [],
                (int) $existing['response_status']
            ))->withHeader('X-Idempotency-Replayed', 'true');
        }

        $response = $next();
        if ($response->status() >= 200 && $response->status() < 300) {
            $insert = $this->db->pdo()->prepare(
                'INSERT INTO checkout_idempotency_keys (
                    idempotency_key, order_id, actor_fingerprint, request_hash,
                    response_status, response_body, created_at, expires_at
                ) VALUES (
                    :key, :order_id, :actor, :hash,
                    :status, :body, :created_at, :expires_at
                )'
            );
            $insert->execute([
                ':key' => $key,
                ':order_id' => $orderId,
                ':actor' => $actorFingerprint,
                ':hash' => $requestHash,
                ':status' => $response->status(),
                ':body' => $response->toJson(),
                ':created_at' => $nowIso,
                ':expires_at' => $expiresIso,
            ]);
        }

        return $response->withHeader('X-Idempotency-Replayed', 'false');
    }

    private function computeRequestHash(Request $request, string $actorFingerprint): string
    {
        $payload = $request->all();
        ksort($payload);
        return hash('sha256', $actorFingerprint . '|' . json_encode($payload, JSON_UNESCAPED_SLASHES));
    }
}
