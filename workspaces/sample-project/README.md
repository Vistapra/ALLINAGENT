# Order & Billing Demo (`order-billing-demo`)

A clean, synthetic, **MIT-licensed** polyglot microservice fixture shipped with **ALLINAGENT** so operators can immediately test **Folder Picker**, **Source Code Analysis (`/analisis`)**, **11-Agent Engineering & Security Reviews**, **QA Automated Testing**, and **Defensive VulnClaw Static Scans** immediately after `git clone` with **zero external runtime dependencies**.

## Architecture Overview

```text
sample-project/
├── LICENSE                         # Permissive MIT License
├── README.md                       # Service documentation & verification commands
├── .env.example                    # Non-secret environment configuration template
├── pyproject.toml                  # Python 3.10+ package metadata (stdlib only)
├── package.json                    # Node.js 20+ UI widget & contract test runner
├── openapi/
│   └── openapi.yaml                # OpenAPI 3.1.0 REST contract specification
├── config/
│   └── sandbox-fixture.yaml        # Synthetic L1 config audit fixture (CWE-489)
├── src/
│   ├── __init__.py
│   ├── domain.py                   # Integer-cents order, discount & basis-point tax engine
│   ├── repository.py               # Parameterized SQLite repository (CWE-89 safe)
│   ├── app.py                      # Deterministic REST request router & WSGI/HTTP handler
│   ├── sandbox_audit_fixture.py    # Inert static-scan benchmark patterns (CWE-89, CWE-327)
│   └── ui/
│       └── billing_widget.mjs      # XSS-safe invoice summary presenter & client validator
└── tests/
    ├── test_order_billing.py       # Python unittest suite (domain, REST, SQLite, sandbox gate)
    └── ui_contract.test.mjs        # Node.js built-in test runner suite for UI widget & OpenAPI
```

## REST API Endpoints (`openapi/openapi.yaml`)

| Method | Path | Purpose |
| :--- | :--- | :--- |
| `GET` | `/healthz` | Service readiness & `sandbox_test_mode` status |
| `POST` | `/api/v1/orders` | Create a validated customer order (supports `Idempotency-Key` header) |
| `GET` | `/api/v1/orders/{order_id}` | Fetch persisted order details and calculated totals |
| `POST` | `/api/v1/invoices/preview` | Compute deterministic subtotal, tiered discount, and basis-point tax |
| `GET` | `/api/v1/sandbox/diagnostics` | Synthetic diagnostic probe — returns `403` unless `SANDBOX_TEST_MODE=true` |

## Running Automated QA Tests

Both test suites use standard-library test runners only (no `pip install` or `npm install` required):

```bash
# 1. Run Python backend domain, SQLite repository, and REST router unit tests
python3 -m unittest discover -s tests -p "test_*.py" -v

# 2. Run Node.js frontend billing widget & OpenAPI contract unit tests
node --test tests/ui_contract.test.mjs
```

## Synthetic Sandbox Test Mode & Defensive Security Scan Fixture

1. **Runtime Sandbox Gate (`SANDBOX_TEST_MODE`):**
   - Disabled (`false`) by default. Setting `SANDBOX_TEST_MODE=true` enables the synthetic `GET /api/v1/sandbox/diagnostics` endpoint with mock deterministic metrics for QA integration checks.
2. **Inert Static-Analysis Benchmark (`config/sandbox-fixture.yaml` & `src/sandbox_audit_fixture.py`):**
   - `src/sandbox_audit_fixture.py` is **never imported** by `src/app.py` and raises `RuntimeError` if called directly, keeping runtime execution 100% safe while providing deterministic `CWE-489`, `CWE-89`, and `CWE-327` static patterns (paired with their safe parameterized/SHA-256 remediations) to exercise **VulnClaw `codescan`**, `findings.db` deduplication, and 11-agent security review workflows.
