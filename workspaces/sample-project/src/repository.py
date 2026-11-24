"""Parameterized SQLite order persistence repository (100% prepared-statement safe)."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

from .domain import InvoiceSummary, LineItem, ValidationError


class OrderRepository:
    """Thread-local or in-memory SQLite store using strictly parameterized SQL queries."""

    def __init__(self, database_path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(database_path)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS orders (
                order_id TEXT PRIMARY KEY,
                customer_id TEXT NOT NULL,
                status TEXT NOT NULL,
                idempotency_key TEXT UNIQUE,
                request_fingerprint TEXT NOT NULL,
                invoice_json TEXT NOT NULL,
                items_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        self._conn.commit()

    def create_or_replay_order(
        self,
        *,
        customer_id: str,
        items: list[LineItem],
        invoice: InvoiceSummary,
        request_fingerprint: str,
        idempotency_key: str | None = None,
    ) -> tuple[dict[str, Any], bool]:
        clean_idem = (idempotency_key or "").strip() or None
        if clean_idem is not None:
            if len(clean_idem) > 128:
                raise ValidationError("Idempotency-Key header cannot exceed 128 characters.")
            cur = self._conn.execute(
                "SELECT * FROM orders WHERE idempotency_key = ?",
                (clean_idem,),
            )
            existing = cur.fetchone()
            if existing is not None:
                if existing["request_fingerprint"] != request_fingerprint:
                    raise ValidationError("Idempotency-Key was already used with a different order payload.")
                return self._row_to_dict(existing, idempotent_replay=True), True

        order_id = f"ord_{uuid.uuid4().hex[:16]}"
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        invoice_json = json.dumps(invoice.to_dict(), sort_keys=True)
        items_json = json.dumps([item.to_dict() for item in items])

        self._conn.execute(
            """
            INSERT INTO orders (
                order_id, customer_id, status, idempotency_key,
                request_fingerprint, invoice_json, items_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                order_id,
                customer_id,
                "CONFIRMED",
                clean_idem,
                request_fingerprint,
                invoice_json,
                items_json,
                created_at,
            ),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT * FROM orders WHERE order_id = ?",
            (order_id,),
        ).fetchone()
        assert row is not None
        return self._row_to_dict(row, idempotent_replay=False), False

    def get_order(self, order_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM orders WHERE order_id = ?",
            (order_id,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row, idempotent_replay=False)

    def count_orders(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS cnt FROM orders").fetchone()
        return int(row["cnt"]) if row else 0

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row, *, idempotent_replay: bool) -> dict[str, Any]:
        return {
            "order_id": row["order_id"],
            "customer_id": row["customer_id"],
            "status": row["status"],
            "idempotent_replay": idempotent_replay,
            "created_at": row["created_at"],
            "invoice": json.loads(row["invoice_json"]),
            "items": json.loads(row["items_json"]),
        }
