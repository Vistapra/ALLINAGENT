# Phase 27 Group E — 16-Step Multi-Agent Software Engineering, VulnClaw Remediation & PDF/DOCX Compliance Evidence (`E01`–`E16`)

- **Phase ID**: `PHASE-27` (`Group E`: `E01`–`E16`)
- **Status**: **`PASS` (`16 / 16` Steps Verified Live)**
- **Target Production Stack**: `<TARGET_VPS_HOSTNAME>` (`<TARGET_VPS_IPV4>`) — Ubuntu 24.04.4 LTS, `/opt/allinagent` (`v1.0.0-rc.8`)
- **Isolated Target Workspace**: `/opt/allinagent/data/workspaces/e2e-order-api-run` (`/var/lib/allinagent/workspaces/e2e-order-api-run` inside containers; baseline fixture `/opt/allinagent/data/workspaces/synthetic-order-api` preserved `100%` untouched at commit `052c538125a07107c79fd99c036a9d9da526a5ea`)
- **Paperclip Project**: `Phase 27 AcmeBistro Security Remediation` (`fd155900-fb85-48b8-9e43-dd23320224b2`, final status: `completed`)
- **Sanitization Guarantee**: Zero secrets, API keys, internal tokens, chat IDs, bot handles, or private host identifiers are stored in this document (`audit-public-release.py` verified `0` findings).

---

## 1. End-to-End 16-Step Verification Matrix (`E01`–`E16`)

| Step | Stage & Verification Objective | Participating Role / Service | Empirical Evidence Summary | Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **`E01`** | Provision isolated workspace copy `e2e-order-api-run` & multi-UID permissions (`10001:1000`, `g+rwX,o+rX`) | Host / Git / Workspace | Copied `synthetic-order-api` $\rightarrow$ `e2e-order-api-run` (`10001:1000`, mode `2775`); original `synthetic-order-api` `git status --short` empty (`052c538`) | **PASS** |
| **`E02`** | Register active workspace via Office Bridge & create Paperclip Project + 7-role Kanban tasks | `@ceo` + Office Bridge + Paperclip | `POST /api/office-bridge/folders` (`HTTP 200`), Project `fd155900-...` (`HTTP 201`), Kanban tickets `UNI-10`–`UNI-16` assigned across 7 roles | **PASS** |
| **`E03`** | Reproduce baseline flaws (`SYN-F01`–`SYN-F04`) inside `allinagent-hermes` | `@qa` / `allinagent-hermes` | `test_order_security.py --assert-baseline-vulns` (`exit 0`, all 4 flaws reproduced) + `run_fixture_tests.py --assert-seeded-vulns` (`4/4` seeded checkout flaws reproduced) | **PASS** |
| **`E04`** | Trigger live on-demand defensive scan via `office-bridge` $\rightarrow$ `http://vulnclaw:8660/scan` & `platform_cli.py` | `@security` / `allinagent-vulnclaw` | `transport: "vulnclaw_http_worker"`, `scan_id: vcs-efb1d730f98d` (`HTTP 200`, `20` files scanned in `1,863.94 ms`, `workspace_read_only: true`, `secret_env_leaked_to_child: false`) + `platform_cli` `security_report` `ok: true` | **PASS** |
| **`E05`** | Record pre-remediation static findings, severities, CWEs & SARIF `2.1.0` output | `@security` (`UNI-11`) | `9` static findings (`6 High`, `1 Medium`, `2 Low`), `sarif_version: "2.1.0"` (`9` results), credential literals automatically scrubbed (`secret = "[REDACTED_SECRET]"`) | **PASS** |
| **`E06`** | Ingest findings into SQLite `findings.db` (`FindingsStore.ingest_finding`) & verify deduplication | `@findings` / `findings_engine.py` | `12` unique findings ingested (`FND-EC2259D344` .. `FND-EE5AFEED13`); repeat ingestion deduplicated (`deduplicated: true, occurrence_count: 2`) | **PASS** |
| **`E07`** | Triage findings (`UNDER_REVIEW` $\rightarrow$ `CONFIRMED` $\rightarrow$ `REMEDIATION_REQUIRED`) & sync `/api/office-bridge/findings` | `@findings` (`UNI-12`) + Office Bridge | `10` actionable defects set to `REMEDIATION_REQUIRED`, `2` stdlib dotted-import heuristics marked `FALSE_POSITIVE`; `GET /api/office-bridge/findings` (`HTTP 200`, `open: 10`, `47` timeline events) | **PASS** |
| **`E08`** | Remediate `SYN-F01`–`SYN-F04` on isolated Git branch `fix/phase27-security-remediation` | `@backend` (`UNI-13`) | Parameterized `?` SQL + amount check (`SYN-F01`), strict `403` ownership (`SYN-F02`), `1..100` integer validation `400` + `BEGIN IMMEDIATE` stock lock `409` (`SYN-F03`), fail-closed env secret + `429` rate limit (`SYN-F04`) | **PASS** |
| **`E09`** | Add positive + negative security regression tests & commit cleanly on remediation branch | `@backend` / `@qa` | Committed `369501d` on `fix/phase27-security-remediation` (`3 files changed, 327 insertions(+), 165 deletions(-)`) | **PASS** |
| **`E10`** | Execute automated QA test suites inside `allinagent-hermes` (`100% PASS`) | `@qa` (`UNI-14`) | `test_order_security.py` (`8/8 PASS`, `exit 0`) + `run_fixture_tests.py --python-only` (`4/4` static + `6/6` runtime + differential `PASS`, `exit 0`) | **PASS** |
| **`E11`** | Re-run live VulnClaw defensive scan on remediated workspace (`0` Critical/High findings) | `@remediation` / `allinagent-vulnclaw` | `scan_id: vcs-ae64e7202936` (`HTTP 200`, `20` files scanned in `1,706.71 ms`) $\rightarrow$ **`findings_count: 0`** (`0` Critical, `0` High, `0` Medium, `0` Low) | **PASS** |
| **`E12`** | Transition all confirmed findings to `RESOLVED` & mark Paperclip Kanban tasks `done` | `@remediation` (`UNI-15`) + Paperclip | `GET /api/office-bridge/findings` (`HTTP 200`, `open: 0, resolved: 10, false_positives: 2`, `77` timeline events); all `7` Kanban tasks `UNI-10`–`UNI-16` verified `done` | **PASS** |
| **`E13`** | Generate deterministic `.pdf` & `.docx` compliance reports via `platform_cli.py` / `report_exporter.py` | `@compliance` (`UNI-16`) | Generated `phase27-acmebistro-compliance-report.pdf` (`reportlab`) & `phase27-acmebistro-compliance-report.docx` (`python-docx`) inside `allinagent-hermes` | **PASS** |
| **`E14`** | Verify `%PDF-` magic header, `PK\x03\x04` OOXML `word/document.xml` structure, sizes & SHA-256 | `@compliance` / Binary Inspector | PDF: `%PDF-1.4`, `9,317` B, `3` pages, SHA-256 `88492999...`; DOCX: `504b0304`, `17` ZIP entries (`word/document.xml` `34,501` B), `39,809` B, SHA-256 `6edc4b10...` | **PASS** |
| **`E15`** | Verify Office Bridge report listing & binary HTTP downloads (`:8202` / `:3210`) | Office Bridge (`server.js`) | Unauth `127.0.0.1:8202` rejected `HTTP 401`; auth `GET /api/office-bridge/reports` (`HTTP 200`) + `.pdf` (`200 OK`, `application/pdf`) + `.docx` (`200 OK`, OOXML MIME) exact SHA-256 match | **PASS** |
| **`E16`** | Deliver executive remediation summary + `.pdf` & `.docx` attachments to Owner Telegram DM | `hermes-exec-daemon` (`:8650`) | `POST http://127.0.0.1:8650/api/telegram/notify` $\rightarrow$ PDF+Summary (`HTTP 200`, `ok: true, delivered: true, document_sent: true, message_id: 193`) & DOCX (`message_id: 194`) | **PASS** |

---

## 2. Stage 1 Evidence — Workspace Registration, Paperclip Kanban & Baseline Reproduction (`E01`–`E03`)

### 2.1 Isolated Workspace Provisioning & Baseline Preservation (`E01`)

- Copied `/opt/allinagent/data/workspaces/synthetic-order-api` to `/opt/allinagent/data/workspaces/e2e-order-api-run` and applied multi-container POSIX ownership/permissions (`chown -R 10001:1000`, `chmod -R g+rwX,o+rX` $\rightarrow$ `10001:1000`, mode `2775`) so `allinagent-hermes` (`10001`), `allinagent-paperclip` / `allinagent-office-bridge` (`1000`), and `allinagent-vulnclaw` (`10002`, `:ro` mount) can all inspect the workspace without container restarts.
- Verified `/opt/allinagent/data/workspaces/synthetic-order-api` remained completely untouched (`git status --short` empty, `HEAD = 052c538125a07107c79fd99c036a9d9da526a5ea`).

### 2.2 Office Bridge Workspace Selection & 7-Role Paperclip Provisioning (`E02`)

- **Office Bridge Active Workspace Registration**:
  - `POST /api/office-bridge/folders` (`{"action": "select", "path": "/var/lib/allinagent/workspaces/e2e-order-api-run"}`) $\rightarrow$ `HTTP 200 OK`, `active_folder: "/var/lib/allinagent/workspaces/e2e-order-api-run"`, `pinned_count: 4`.
  - `GET /api/office-bridge/evidence?target=/var/lib/allinagent/workspaces/e2e-order-api-run` $\rightarrow$ `HTTP 200 OK`.
- **Paperclip Project & 7-Agent Kanban Hierarchy**:
  - Created Project **`Phase 27 AcmeBistro Security Remediation`** (`id: fd155900-fb85-48b8-9e43-dd23320224b2`, `HTTP 201 Created`) and 7 role-scoped Kanban issues:

| Ticket | Corporate Role (`role_slug`) | Assigned Paperclip Agent UUID | Scope | Final Status |
| :--- | :--- | :--- | :--- | :--- |
| `UNI-10` | `CEO Agent` (`ceo_agent`) | `78a51e37-cff3-440c-8ec8-5ca1c762cc0d` | Parent Executive Security Audit & Remediation Epic (`E01`–`E16`) | `done` |
| `UNI-11` | `Security Reviewer` (`security_reviewer`) | `2fe87575-bcd1-4066-8d3b-0d5c48531a7a` | On-Demand VulnClaw L1/L2 Defensive Code Scan (`E04`–`E05`) | `done` |
| `UNI-12` | `Findings Analyst` (`findings_analyst`) | `5c2402cb-4c05-4489-b398-f5dfc2dd2b70` | SARIF & `findings.db` Triage & CWE Classification (`E06`–`E07`) | `done` |
| `UNI-13` | `Backend Developer` (`backend_developer`) | `0b1ce378-5153-4f3c-a319-9826b8bcd667` | Isolated Git Branch Remediation of `SYN-F01`–`SYN-F04` (`E08`–`E09`) | `done` |
| `UNI-14` | `QA Engineer` (`qa_engineer`) | `07823b69-31d4-4875-8654-acee87fc190a` | Positive & Negative Security Regression Test Execution (`E10`) | `done` |
| `UNI-15` | `Remediation Reviewer` (`remediation_reviewer`) | `7df0d106-3a52-402e-8624-501ba287ee6e` | Post-Fix Diff Audit & VulnClaw Zero-Finding Re-Scan Gate (`E11`–`E12`) | `done` |
| `UNI-16` | `Report & Compliance Agent` (`compliance_reporter`) | `4311b82e-ba30-4720-919e-ed3f94baa4dc` | PDF/DOCX Compliance Export & Multi-Channel Delivery (`E13`–`E16`) | `done` |

### 2.3 Baseline Vulnerability Reproduction Inside `allinagent-hermes` (`E03`)

Executed inside `allinagent-hermes` (`Python 3.14.9`, `SQLite 3.53.1`) on `/var/lib/allinagent/workspaces/e2e-order-api-run` (`commit d158e5d`):

1. `python3 -B tests/test_order_security.py --json` (`UNPATCHED_EXIT_CODE=1`) and `--assert-baseline-vulns --json` (`exit_code=0`, `overall_status: "PASS"`):
   - `positive_valid_order_succeeds`: **`PASS`** (baseline app operational)
   - `syn_f01_sqli_neutralized`: **`FAIL` (Reproduced)** — `[SYN-F01] SQLi payload leaked 3 orders!` (`' OR '1'='1` dumped all multi-tenant orders; client `amount_cents=100` also accepted in `run_fixture_tests.py`)
   - `syn_f02_cross_tenant_idor_403`: **`FAIL` (Reproduced)** — `[SYN-F02] Cross-tenant IDOR on order 1003 returned HTTP 200 instead of 403!`
   - `syn_f03_negative_qty_400_and_atomic_stock_409`: **`FAIL` (Reproduced)** — `[SYN-F03] Negative quantity -5 returned HTTP 200 ({'charged_cents': -9250, 'remaining_stock': 10}) instead of 400!`
   - `syn_f04_fail_closed_secret_and_rate_limit_429`: **`FAIL` (Reproduced)** — `[SYN-F04] Service booted with hardcoded fallback secret when ACME_SIGNING_SECRET was unset!` (and `0` `429` responses across burst requests)

---

## 3. Stage 2 Evidence — Live On-Demand VulnClaw Scan & Findings Triage (`E04`–`E07`)

### 3.1 Pre-Remediation Live VulnClaw Defensive Scan (`E04`–`E05`)

Triggered via `allinagent-office-bridge` (`runDefensiveVulnclawScan` $\rightarrow$ `POST http://vulnclaw:8660/scan` authenticated via `X-Internal-Scan-Token`) and `platform_cli.py telegram-cmd security_report`:

- **Scan Metadata**:
  - `transport`: `"vulnclaw_http_worker"`
  - `vulnclaw_version`: `"0.4.1"` (`pinned_commit: "0b34878f84b089b21fcf85ecd445315f14df0672"`)
  - `scan_id`: `"vcs-efb1d730f98d"` (and `"vcs-7ad330a9cebf"` with Markdown+SARIF)
  - `workspace_read_only`: `true`
  - `subprocess_memory_reclaimed`: `true`, `secret_env_leaked_to_child`: `false`
  - `files_scanned`: `20` (`files_skipped: 5`, `scanner_duration_ms: 267`, `wall_duration_ms: 1863.94`)
  - `sarif_version`: `"2.1.0"`, `sarif_results_count`: `9`
  - **Pre-Remediation Severity Counts**: **`6 High`**, **`1 Medium`**, **`2 Low`** (`9` total static findings):
    1. `hardcoded_password` (`High`, `CWE-798`, `L1`) — `e2e-order-api-run/src/order_service.py:19` (`secret = "[REDACTED_SECRET]"`)
    2. `sql_string_concat` (`High`, `CWE-89`, `L2`) — `e2e-order-api-run/src/order_service.py:56`
    3. `command_injection` (`High`, `CWE-78`, `L2`) — `e2e-order-api-run/src/order_service.py:57`
    4. `dangerous_eval` (`High`, `CWE-95`, `L1`) — `e2e-order-api-run/tests/run_fixture_tests.py:565`
    5. `dangerous_eval` (`High`, `CWE-95`, `L1`) — `e2e-order-api-run/tests/run_fixture_tests.py:581`
    6. `command_injection` (`High`, `CWE-78`, `L2`) — `e2e-order-api-run/tests/run_fixture_tests.py:6`
    7. `unsafe_debug_true` (`Medium`, `CWE-489`, `L1`) — `e2e-order-api-run/src/order_service.py:18`
    8. `ai_hallucinated_dependency` (`Low`, `CWE-1104`, `L1`) — `e2e-order-api-run/tests/run_fixture_tests.py:36`
    9. `ai_hallucinated_dependency` (`Low`, `CWE-1104`, `L1`) — `e2e-order-api-run/tests/test_order_security.py:15`

### 3.2 `FindingsStore` Ingestion, Deduplication & Office Bridge Synchronization (`E06`–`E07`)

- Ingested all `9` `vulnclaw_codescan` records (`FND-EC2259D344` .. `FND-20A9B77C80`) plus `3` behavioral `sanitized_audit_report` records (`FND-BF19DAC87A` `SYN-F02` `CWE-639` `High`, `FND-99AC8D3264` `SYN-F03` `CWE-362` `High`, `FND-EE5AFEED13` `SYN-F04` `CWE-307` `Medium`) into `findings.db`.
- Repeat ingestion of `FND-EC2259D344` verified fingerprint deduplication (`{"deduplicated": true, "occurrence_count": 2}`).
- Triaged `10` confirmed defects to `REMEDIATION_REQUIRED` and `2` stdlib dotted-import heuristics to `FALSE_POSITIVE`.
- Verified via `GET /api/office-bridge/findings`:
  ```json
  {
    "http_status": 200,
    "ok": true,
    "available": true,
    "trust_boundary": "ISOLATED_DEFENSIVE_READONLY",
    "summary": {
      "total": 12,
      "open": 10,
      "resolved": 0,
      "false_positives": 2,
      "accepted_risks": 0,
      "by_status": {
        "REMEDIATION_REQUIRED": 10,
        "FALSE_POSITIVE": 2
      }
    },
    "timeline_events_count": 47
  }
  ```

---

## 4. Stage 3 Evidence — Branch Remediation, QA Suites & VulnClaw Re-Scan (`E08`–`E12`)

### 4.1 Isolated Branch Remediation (`E08`–`E09`)

Created branch **`fix/phase27-security-remediation`** (`HEAD = 369501d`) in `/opt/allinagent/data/workspaces/e2e-order-api-run`:

1. **`SYN-F01` (`CWE-89` / `CWE-840`)**: Replaced string-formatted SQL in `search_orders()` with parameterized `?` SQLite prepared statements scoped strictly to `WHERE user_id = ? AND order_number = ?`, and enforced server-authoritative `unit_price_cents * quantity` (`HTTP 422 AMOUNT_MISMATCH` on client tampering).
2. **`SYN-F02` (`CWE-639`)**: Enforced strict caller-to-order ownership (`int(caller_id) == int(row["user_id"])` for customer orders and constant-time `hmac.compare_digest` SHA-256 verification for guest orders), returning `HTTP 403 ORDER_OWNERSHIP_VIOLATION` on cross-tenant access.
3. **`SYN-F03` (`CWE-20` / `CWE-362` / `CWE-601`)**: Enforced strict positive integer quantity validation (`1 <= quantity <= 100`, rejecting booleans/zero/negatives with `HTTP 400 INVALID_QUANTITY`) and atomic SQLite `BEGIN IMMEDIATE` transactions with conditional `UPDATE menu_inventory SET stock = stock - ? WHERE sku = ? AND stock >= ?` (`rowcount == 1`, rolling back and returning `HTTP 409 INSUFFICIENT_STOCK` on concurrent stock exhaustion), alongside HTTPS host-allowlisted `callback_url` validation.
4. **`SYN-F04` (`CWE-798` / `CWE-489` / `CWE-307` / `CWE-672`)**: Removed the hardcoded fallback secret and `debug = True`; enforced fail-closed `ACME_SIGNING_SECRET` environment loading (`>= 16` chars, raising `RuntimeError` when unset or short), added `SlidingWindowRateLimiter` (`HTTP 429 RATE_LIMIT_EXCEEDED`), and retained SQLite `expires_at` idempotency eviction.

### 4.2 Automated Positive & Negative QA Test Execution (`E10`)

Executed inside `allinagent-hermes`:

- **`python3 -B tests/test_order_security.py --json` (`exit_code=0`, `8 / 8 PASS`)**:
  1. `01_positive_valid_customer_inventory_order_200`: **`PASS`**
  2. `02_positive_authorized_owner_and_guest_lookup_200`: **`PASS`**
  3. `03_syn_f01_sqli_payloads_neutralized`: **`PASS`**
  4. `04_syn_f01_client_amount_tampering_rejected_422`: **`PASS`**
  5. `05_syn_f02_cross_tenant_and_guest_idor_rejected_403`: **`PASS`**
  6. `06_syn_f03_negative_zero_bool_quantity_rejected_400`: **`PASS`**
  7. `07_syn_f03_atomic_begin_immediate_prevents_oversell_409`: **`PASS`** (two concurrent SQLite connections verified atomic `200` + `409` with `0` oversell)
  8. `08_syn_f04_fail_closed_env_secret_and_rate_limit_429`: **`PASS`**
- **`python3 -B tests/run_fixture_tests.py --python-only --json` (`exit_code=0`, `overall_status: "PASS"`)**:
  - `4 / 4` static/manifest/privacy checks **`PASS`** + `6 / 6` checkout/webhook/idempotency tests **`PASS`** + `differential_seeded_baseline_verified: true`.

### 4.3 Live Post-Remediation VulnClaw Re-Scan & Findings Closure (`E11`–`E12`)

- **Post-Remediation VulnClaw Scan (`POST http://vulnclaw:8660/scan` via Office Bridge)**:
  ```json
  {
    "ok": true,
    "transport": "vulnclaw_http_worker",
    "scan_id": "vcs-ae64e7202936",
    "workspace_read_only": true,
    "stats": {
      "files_scanned": 20,
      "files_skipped": 5,
      "findings_count": 0,
      "severity_counts": {},
      "scanner_duration_ms": 235.8,
      "wall_duration_ms": 1706.71,
      "subprocess_memory_reclaimed": true,
      "secret_env_leaked_to_child": false
    },
    "findings": []
  }
  ```
- **Post-Remediation `GET /api/office-bridge/findings`**:
  - `http_status: 200`, `summary: {"total": 12, "open": 0, "resolved": 10, "false_positives": 2, "accepted_risks": 0}`, `timeline_events_count: 77`.
- **Paperclip Kanban Completion**:
  - All `7` tickets (`UNI-10` through `UNI-16`) verified `status: "done"` via `GET /api/office-bridge/tasks` and Paperclip `/api/issues`.

---

## 5. Stage 4 Evidence — Real PDF & DOCX Compliance Export & Multi-Channel Delivery (`E13`–`E16`)

### 5.1 Deterministic PDF & DOCX Generation & Binary Verification (`E13`–`E14`)

Invoked `platform_cli.py export-report` (`report_exporter.export_markdown_to_pdf_and_docx`) inside `allinagent-hermes`:

| Deliverable Path | Engine | Size (Bytes) | Magic Signature & Structural Verification | SHA-256 Checksum |
| :--- | :--- | ---: | :--- | :--- |
| `/var/lib/allinagent/reports/phase27-acmebistro-compliance-report.pdf` | `reportlab` | `9,317` | `%PDF-1.4` (`estimated_pages: 3`, `valid_signature: true`) | `88492999b0d36bcd9932f21b17ed26bc9b97bf5e20968caefb9f8b186ae8f1b3` |
| `/var/lib/allinagent/reports/phase27-acmebistro-compliance-report.docx` | `python-docx` | `39,809` | `PK\x03\x04` (`504b0304`, `17` OOXML entries incl. `word/document.xml` `34,501` B) | `6edc4b10a5e05641a3842e16a90813665e30de533009c45ae1489a851e85173d` |

### 5.2 Office Bridge Report Listing & Binary Download Verification (`E15`)

- **Host Loopback Fail-Closed Gate (`http://127.0.0.1:8202/api/office-bridge/reports` without token)**: **`HTTP 401 Unauthorized`**.
- **Authenticated `GET /api/office-bridge/reports`**: **`HTTP 200 OK`** (`reports_total: 6`, listing `phase27-acmebistro-compliance-report.pdf`, `phase27-acmebistro-compliance-report.docx`, and `.md`).
- **Authenticated `GET /api/office-bridge/reports/phase27-acmebistro-compliance-report.pdf`**:
  - `HTTP 200 OK`, `Content-Type: application/pdf`, `Content-Disposition: attachment; filename="phase27-acmebistro-compliance-report.pdf"`, `9,317` bytes, `%PDF-1.4`, SHA-256 `88492999b0d36bcd9932f21b17ed26bc9b97bf5e20968caefb9f8b186ae8f1b3` (`100%` match).
- **Authenticated `GET /api/office-bridge/reports/phase27-acmebistro-compliance-report.docx`**:
  - `HTTP 200 OK`, `Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document`, `Content-Disposition: attachment; filename="phase27-acmebistro-compliance-report.docx"`, `39,809` bytes, `504b0304`, SHA-256 `6edc4b10a5e05641a3842e16a90813665e30de533009c45ae1489a851e85173d` (`100%` match).

### 5.3 Real Owner Telegram DM Delivery (`E16`)

Delivered executive remediation summary + both `.pdf` and `.docx` attachments via `POST http://127.0.0.1:8650/api/telegram/notify` inside `allinagent-hermes` (authenticated in-memory with zero secret logging):

```json
{
  "telegram_pdf_delivery": {
    "http_status": 200,
    "ok": true,
    "delivered": true,
    "message_id": 193,
    "document_sent": true
  },
  "telegram_docx_delivery": {
    "http_status": 200,
    "ok": true,
    "delivered": true,
    "message_id": 194,
    "document_sent": true
  }
}
```

---

## 6. Post-Workflow Stack Health & Cgroup Memory Footprint (`<= 1,536 MiB` Ceiling)

Zero containers were restarted during the entire 16-step workflow, and post-execution RSS remained well inside the `1,536 MiB` production ceiling:

| Container | Live Memory Usage / Limit | CPU % | Health Status |
| :--- | :--- | ---: | :--- |
| `allinagent-postgres` | `119.20 MiB / 160 MiB` | `17.26%` | `Up (healthy)` |
| `allinagent-vulnclaw` | `28.66 MiB / 64 MiB` | `0.00%` | `Up (healthy)` |
| `allinagent-hermes` | `334.60 MiB / 448 MiB` | `6.87%` | `Up (healthy)` |
| `allinagent-paperclip` | `509.50 MiB / 608 MiB` | `8.18%` | `Up (healthy)` |
| `allinagent-office-bridge` | `55.60 MiB / 112 MiB` | `1.75%` | `Up (healthy)` |
| `allinagent-office` | `62.96 MiB / 144 MiB` | `0.00%` | `Up (healthy)` |
| **Total Stack** | **`1,110.52 MiB / 1,536 MiB` (`72.30%`)** | — | **ALL 6 HEALTHY (`0` Restarts)** |
