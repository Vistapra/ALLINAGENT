# AcmeBistro Synthetic Order API (`acmebistro/synthetic-order-api`)

100% first-party, MIT-licensed synthetic Laravel-style PHP REST API + SQLite security benchmark fixture built for **ALLINAGENT Phase 27 Group E** multi-agent software engineering & compliance workflows.

## Safety & Privacy Guarantees

- **Zero proprietary code or business logic**: Fictional `AcmeBistro` restaurant menu (`Truffle Mushroom Burger`, `Wood-Fired Margherita Pizza`, `Double Espresso`).
- **Zero external network calls**: Uses the deterministic offline `AcmePay` sandbox simulator (`src/Services/PaymentGatewayService.php`). Never opens sockets or contacts real payment gateways.
- **Zero private identifiers or live keys**: All tokens and HMAC keys are synthetic fixture constants (`whsec_acmepay_synthetic_fixture_00000000`).

## Coverage of All 8 Group E Fixture Dimensions

1. **Laravel/PHP REST API Structure**:
   - `POST /api/v1/orders/{id}/pay` (`PaymentController::pay`)
   - `GET /api/v1/orders/{id}/status` (`PaymentController::status`)
   - `POST /api/v1/webhooks/payment` (`PaymentController::webhook`)
2. **Authentication & Order Ownership (`OrderOwnershipMiddleware`)**:
   - Authenticated customer orders via `X-User-Id` header.
   - Guest checkout orders via `X-Guest-Token` header verified with constant-time SHA-256 comparison (`hash_equals` / `hmac.compare_digest`).
3. **Synthetic Payment Workflow (`PaymentGatewayService`)**:
   - Offline `AcmePay` checkout session generator and HMAC-SHA256 webhook signature verifier (`X-AcmePay-Signature`).
4. **Dependency Manifests**:
   - `composer.json` and deterministic `composer.lock` for SBOM, dependency, and license review agents.
5. **Dual-Runtime Automated Verification**:
   - Native PHP test suite (`tests/PaymentSecurityTest.php`) for PHP 8.1+ CLI environments.
   - Zero-dependency Python 3 + `sqlite3` portable verifier (`tests/run_fixture_tests.py`) for minimal Linux containers.
6. **Relational Database Migration & Seeds**:
   - `database/migrations/001_create_orders_and_checkouts.sql` (`orders`, `order_items`, `checkout_idempotency_keys` with `expires_at` TTL, `payment_webhook_events`).
   - `database/seeds/001_seed_sample_orders.sql`.
7. **Seeded Baseline Mode (`--with-seeded-vulns`) vs. Patched Clean Mode**:
   - Toggleable via `--with-seeded-vulns` CLI flag or `ACME_SEEDED_VULNS=1` environment variable.
8. **OpenAPI 3.1 Contract & Structured Security Manifest**:
   - `openapi.yaml` and `security-manifest.json` enabling automated audit, triage, remediation, regression testing, and PDF/DOCX compliance report generation.

## Canonical Defensive Security Classes (`SYN-F01` – `SYN-F04`)

| ID | Vulnerability Class | CWE | Seeded Baseline (`--with-seeded-vulns`) | Patched Clean Mode (Default) |
|---|---|---|---|---|
| `SYN-F01` | Client-Supplied Amount Trust | CWE-840 | Trusts client `amount_cents` (`100` vs `3595`) | Enforces server `SUM(quantity * unit_price_cents) + tax - discount`; rejects mismatch with `422 AMOUNT_MISMATCH` |
| `SYN-F02` | Missing Order Ownership Check (IDOR) | CWE-639 | Verifies auth header presence without binding to `order.user_id` / `guest_token_hash` | Enforces strict ownership check; blocks cross-user/guest access with `403 ORDER_OWNERSHIP_VIOLATION` |
| `SYN-F03` | Unvalidated `callback_url` Open Redirect | CWE-601 | Passes arbitrary `callback_url` directly into redirect URL | Enforces `https://`, no userinfo/backslashes, and exact hostname match against `allowed_callback_hosts` (`422 INVALID_CALLBACK_URL`) |
| `SYN-F04` | Missing Idempotency Key Expiration Cleanup | CWE-672 | Fails to purge expired `expires_at` rows, replaying stale 2020 checkout session | Purges `expires_at <= now` before lookup, enforces SHA-256 payload binding (`409` on mismatch), and sets fresh `expires_at` TTL |

## Running Tests

```bash
# Full portable verification (runs static privacy/manifest checks + Python SQLite suite + PHP CLI bridge if installed)
python3 tests/run_fixture_tests.py

# Portable container mode (Python 3 stdlib + sqlite3 only, no PHP CLI required)
python3 tests/run_fixture_tests.py --python-only

# Verify seeded vulnerabilities deterministically reproduce
python3 tests/run_fixture_tests.py --assert-seeded-vulns

# Machine-readable JSON output for agentic pipelines
python3 tests/run_fixture_tests.py --json

# Direct PHP CLI execution
php tests/PaymentSecurityTest.php
php tests/PaymentSecurityTest.php --assert-seeded-vulns
```
