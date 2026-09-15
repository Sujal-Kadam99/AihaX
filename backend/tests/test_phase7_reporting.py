"""AihaX Phase 7 — Bug Bounty Report Generator V2 Tests."""

import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock, patch


def _make_finding(
    id_="find-001",
    vuln_type="C023_SQL_Injection",
    category="injection",
    severity="high",
    verdict="Verified",
    false_positive=False,
    verification_status="REPORTABLE",
    verification_reason_code="REPRODUCED_SUCCESSFULLY",
    affected_url="http://127.0.0.1:8888/search",
    affected_param="q",
    payload="' OR 1=1--",
    proof_request="GET /search?q=%27 HTTP/1.1\nHost: 127.0.0.1:8888",
    proof_response="SQL syntax error near...",
    confidence=80,
    evidence_ids='["EVD-001"]',
    request_ids='["REQ-001"]',
    cwe_id="CWE-89",
    verification_method="Differential",
    title="SQL Injection in Search Parameter",
):
    f = MagicMock()
    f.id = id_
    f.vuln_type = vuln_type
    f.category = category
    f.severity = severity
    f.verdict = verdict
    f.false_positive = false_positive
    f.verification_status = verification_status
    f.verification_reason_code = verification_reason_code
    f.affected_url = affected_url
    f.affected_param = affected_param
    f.payload = payload
    f.proof_request = proof_request
    f.proof_response = proof_response
    f.confidence = confidence
    f.evidence_ids = evidence_ids
    f.request_ids = request_ids
    f.cwe_id = cwe_id
    f.verification_method = verification_method
    f.title = title
    f.duplicate_of = None
    f.human_review_status = "APPROVED"
    return f
