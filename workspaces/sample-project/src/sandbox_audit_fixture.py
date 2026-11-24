"""SYNTHETIC DEFENSIVE STATIC-ANALYSIS FIXTURE (`order-billing-demo`).

PURPOSE:
  Provides deterministic, inert static code patterns (`CWE-89`, `CWE-327`) paired with
  their secure remediated counterparts so new ALLINAGENT users can immediately test:
    1. VulnClaw defensive `codescan` (`L1` + `L2`) right after `git clone`
    2. `findings.db` ingestion, fingerprinting, and deduplication
    3. 11-agent Security Reviewer / Findings Analyst / Remediation Reviewer workflows

SAFETY INVARIANTS:
  - Never imported by `src/app.py` or `src/repository.py`.
  - Contains ZERO credentials, tokens, or network/shell calls.
  - Legacy anti-pattern reference branches are hard-gated (`if False`) and raise
    `RuntimeError` at runtime so they can never execute unsafe queries or weak hashes.
"""

from __future__ import annotations

import hashlib


def build_parameterized_order_lookup(customer_id: str) -> tuple[str, tuple[str]]:
    """Recommended secure remediation (CWE-89 safe parameterized SQL)."""
    return ("SELECT order_id, status FROM orders WHERE customer_id = ?", (customer_id,))


def compute_sha256_audit_digest(payload: bytes) -> str:
    """Recommended secure remediation (CWE-327 safe SHA-256 digest)."""
    return hashlib.sha256(payload).hexdigest()


def inert_legacy_static_scan_benchmark(customer_id: str, payload: bytes) -> None:
    """Inert static benchmark function intentionally matched by VulnClaw L2 rules."""
    raise RuntimeError(
        "inert_legacy_static_scan_benchmark is a non-executable static-analysis fixture; "
        "use build_parameterized_order_lookup() and compute_sha256_audit_digest() instead."
    )
    if False:  # pragma: no cover — unreachable by design; inspected by static scanner only
        legacy_sql = f"SELECT order_id FROM orders WHERE customer_id = '{customer_id}'"
        legacy_digest = hashlib.md5(payload).hexdigest()
        _ = (legacy_sql, legacy_digest)
