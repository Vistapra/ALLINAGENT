<?php

declare(strict_types=1);

namespace AcmeBistro\OrderApi\Database;

use PDO;
use RuntimeException;

final class DatabaseManager
{
    private PDO $pdo;

    public function __construct(string $dsn = 'sqlite::memory:')
    {
        $this->pdo = new PDO($dsn);
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $this->pdo->exec('PRAGMA foreign_keys = ON;');
    }

    public function pdo(): PDO
    {
        return $this->pdo;
    }

    public function migrate(?string $migrationFile = null): void
    {
        $path = $migrationFile ?? dirname(__DIR__, 2) . '/database/migrations/001_create_orders_and_checkouts.sql';
        if (!is_file($path)) {
            throw new RuntimeException('Migration file not found: ' . $path);
        }
        $sql = (string) file_get_contents($path);
        $this->pdo->exec($sql);
    }

    public function seed(?string $seedFile = null): void
    {
        $path = $seedFile ?? dirname(__DIR__, 2) . '/database/seeds/001_seed_sample_orders.sql';
        if (!is_file($path)) {
            throw new RuntimeException('Seed file not found: ' . $path);
        }
        $sql = (string) file_get_contents($path);
        $this->pdo->exec($sql);
    }

    /**
     * @return array<string, mixed>|null
     */
    public function findOrder(int $orderId): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM orders WHERE id = :id LIMIT 1');
        $stmt->execute([':id' => $orderId]);
        $row = $stmt->fetch();
        return is_array($row) ? $row : null;
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function findOrderItems(int $orderId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT sku, item_name, quantity, unit_price_cents, line_total_cents
             FROM order_items
             WHERE order_id = :order_id
             ORDER BY id ASC'
        );
        $stmt->execute([':order_id' => $orderId]);
        /** @var list<array<string, mixed>> $items */
        $items = $stmt->fetchAll();
        return $items;
    }

    /**
     * Computes server-authoritative total strictly from order_items + tax - discount.
     */
    public function calculateAuthoritativeTotalCents(int $orderId): int
    {
        $order = $this->findOrder($orderId);
        if ($order === null) {
            throw new RuntimeException('Order not found for authoritative calculation: ' . $orderId);
        }

        $stmt = $this->pdo->prepare(
            'SELECT COALESCE(SUM(quantity * unit_price_cents), 0) AS computed_subtotal
             FROM order_items
             WHERE order_id = :order_id'
        );
        $stmt->execute([':order_id' => $orderId]);
        $row = $stmt->fetch();
        $subtotal = (int) ($row['computed_subtotal'] ?? 0);
        $tax = (int) $order['tax_cents'];
        $discount = (int) $order['discount_cents'];

        return max(0, $subtotal + $tax - $discount);
    }
}
