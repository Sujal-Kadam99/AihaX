"""AihaX Phase 8 — Evidence Integrity & Cryptographic Hashing.

Provides:
- Content hashing over normalized evidence records (SHA-256).
- Chained evidence hashing linking sequential proof artifacts.
- Cryptographic verification functions with detailed failure reasons.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple


def compute_evidence_content_hash(
    evidence_type: str,
    target_url: str,
    method: str,
    sanitized_request: Optional[str] = None,
    sanitized_response: Optional[str] = None,
    payload_summary: Optional[str] = None,
) -> str:
    """Compute deterministic SHA-256 hash over normalized evidence fields."""
    canonical = {
        "evidence_type": evidence_type.upper().strip(),
        "target_url": target_url.strip(),
        "method": method.upper().strip(),
        "sanitized_request": (sanitized_request or "").strip(),
        "sanitized_response": (sanitized_response or "").strip()[:4000],  # Bounded
        "payload_summary": (payload_summary or "").strip(),
    }
    serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def compute_evidence_chain_hash(
    content_hash: str,
    previous_chain_hash: Optional[str] = None,
    timestamp_str: Optional[str] = None,
) -> str:
    """Compute sequential chain hash linking evidence records."""
    raw = f"{content_hash}|{previous_chain_hash or 'GENESIS'}|{timestamp_str or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def verify_evidence_integrity(
    content_hash: str,
    evidence_type: str,
    target_url: str,
    method: str,
    sanitized_request: Optional[str] = None,
    sanitized_response: Optional[str] = None,
    payload_summary: Optional[str] = None,
) -> Tuple[bool, str]:
    """Verify whether a stored content hash matches the recomputed hash."""
    expected_hash = compute_evidence_content_hash(
        evidence_type=evidence_type,
        target_url=target_url,
        method=method,
        sanitized_request=sanitized_request,
        sanitized_response=sanitized_response,
        payload_summary=payload_summary,
    )
    if expected_hash == content_hash:
        return True, "Hash verified"
    return False, f"Content hash mismatch: stored '{content_hash}', computed '{expected_hash}'"
