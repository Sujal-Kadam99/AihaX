"""AihaX Phase 8 — Evidence Cryptographic Integrity Unit Tests."""

import pytest
from backend.evidence.integrity import (
    compute_evidence_chain_hash,
    compute_evidence_content_hash,
    verify_evidence_integrity,
)


def test_content_hash_deterministic():
    h1 = compute_evidence_content_hash("PROOF", "http://example.com/api", "GET", "GET /api HTTP/1.1", "200 OK", "test")
    h2 = compute_evidence_content_hash("PROOF", "http://example.com/api", "GET", "GET /api HTTP/1.1", "200 OK", "test")
    assert h1 == h2
    assert len(h1) == 64


def test_content_hash_tamper_detected():
    h1 = compute_evidence_content_hash("PROOF", "http://example.com/api", "GET", "GET /api HTTP/1.1", "200 OK", "test")
    
    # Tamper with response
    valid, reason = verify_evidence_integrity(
        content_hash=h1,
        evidence_type="PROOF",
        target_url="http://example.com/api",
        method="GET",
        sanitized_request="GET /api HTTP/1.1",
        sanitized_response="500 Internal Server Error",  # Modified
        payload_summary="test",
    )
    assert valid is False
    assert "mismatch" in reason


def test_chain_hash_linking():
    c1 = compute_evidence_chain_hash("content_hash_1", None, "2026-08-28T12:00:00Z")
    c2 = compute_evidence_chain_hash("content_hash_2", c1, "2026-08-28T12:01:00Z")
    c3 = compute_evidence_chain_hash("content_hash_3", c2, "2026-08-28T12:02:00Z")

    assert c1 != c2
    assert c2 != c3
    assert len(c3) == 64
