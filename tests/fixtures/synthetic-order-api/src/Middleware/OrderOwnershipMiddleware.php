<?php

declare(strict_types=1);

namespace AcmeBistro\OrderApi\Middleware;

use AcmeBistro\OrderApi\Http\JsonResponse;
use AcmeBistro\OrderApi\Http\Request;

final class OrderOwnershipMiddleware
{
    public function __construct(
        private readonly bool $seededVulns = false,
    ) {
    }

    /**
     * Authenticates caller via X-User-Id or X-Guest-Token and verifies ownership of $order.
     *
     * @param array<string, mixed> $order
     * @return array{authorized: bool, actor: string, error: ?JsonResponse}
     */
    public function verify(Request $request, array $order): array
    {
        $userIdHeader = $request->header('X-User-Id');
        $guestTokenHeader = $request->header('X-Guest-Token');

        $hasUser = $userIdHeader !== null && $userIdHeader !== '';
        $hasGuest = $guestTokenHeader !== null && $guestTokenHeader !== '';

        if (!$hasUser && !$hasGuest) {
            return [
                'authorized' => false,
                'actor' => 'anonymous',
                'error' => new JsonResponse([
                    'error' => 'UNAUTHENTICATED',
                    'message' => 'Authentication required via X-User-Id or X-Guest-Token header.',
                ], 401),
            ];
        }

        if ($hasUser && !ctype_digit($userIdHeader)) {
            return [
                'authorized' => false,
                'actor' => 'invalid',
                'error' => new JsonResponse([
                    'error' => 'INVALID_AUTH_HEADER',
                    'message' => 'X-User-Id must be a positive integer.',
                ], 401),
            ];
        }

        $actor = $hasUser
            ? 'user:' . (int) $userIdHeader
            : 'guest:' . hash('sha256', (string) $guestTokenHeader);

        // SYN-F02 (Seeded Baseline Mode): Authenticates presence of caller header,
        // but omits object-level ownership binding against the target order record.
        if ($this->seededVulns) {
            return [
                'authorized' => true,
                'actor' => $actor,
                'error' => null,
            ];
        }

        // Patched Clean Mode: Enforce strict object-level ownership.
        $orderUserId = $order['user_id'] !== null ? (int) $order['user_id'] : null;
        $orderGuestHash = $order['guest_token_hash'] !== null ? (string) $order['guest_token_hash'] : null;

        if ($orderUserId !== null) {
            if (!$hasUser || (int) $userIdHeader !== $orderUserId) {
                return [
                    'authorized' => false,
                    'actor' => $actor,
                    'error' => new JsonResponse([
                        'error' => 'ORDER_OWNERSHIP_VIOLATION',
                        'message' => 'Authenticated user is not authorized to access this order.',
                    ], 403),
                ];
            }

            return [
                'authorized' => true,
                'actor' => $actor,
                'error' => null,
            ];
        }

        if ($orderGuestHash !== null && $hasGuest) {
            $suppliedHash = hash('sha256', (string) $guestTokenHeader);
            if (hash_equals($orderGuestHash, $suppliedHash)) {
                return [
                    'authorized' => true,
                    'actor' => $actor,
                    'error' => null,
                ];
            }
        }

        return [
            'authorized' => false,
            'actor' => $actor,
            'error' => new JsonResponse([
                'error' => 'ORDER_OWNERSHIP_VIOLATION',
                'message' => 'Guest token does not match the target order.',
            ], 403),
        ];
    }
}
