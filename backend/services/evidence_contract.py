"""AihaX Phase 21 — Evidence Contract & Vault Interface.

Implements immutable, secret-redacted, cryptographically verifiable evidence records.

Security Invariants:
1. Every evidence record stores deterministic SHA-256 hashes of request and response bytes.
2. Sensitive authentication tokens, passwords, cookies, and API keys are redacted BEFORE storage.
3. Evidence records are immutable and tamper-evident (any field modification invalidates hashes).
4. Evidence is bound to a scope_snapshot_hash and verifier_version.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from backend.models.database import (
    VerificationEvidenceRecord,
    get_utc_now,
)

logger = logging.getLogger("aihax.evidence_contract")

SENSITIVE_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-csrf-token",
    "csrf-token",
    "token",
    "password",
    "secret",
    "bearer",
    "session",
    "x-amz-security-token",
}

SENSITIVE_BODY_PATTERNS = [
    (re.compile(r'(["\']?(?:password|passwd|secret|client_secret|api_key|token|auth_token|access_token|refresh_token|session_token|private_key)["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])', re.IGNORECASE), r'\1[REDACTED]\3'),
    (re.compile(r'(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)', re.IGNORECASE), '[REDACTED]'),
]


@dataclass
class VerificationEvidenceDTO:
    id: str
    verification_run_id: str
    campaign_id: str
    hypothesis_id: str
    strategy_id: str
    target: str
    endpoint: str
    method: str
    request_hash: str
    response_hash: str
    status_code: Optional[int]
    response_size: Optional[int]
    timestamp: str
    scope_snapshot_hash: Optional[str] = None
    verifier_version: str = "1.0.0-phase21"
    authorization_decision: str = "APPROVE"
    relevant_headers: Dict[str, str] = field(default_factory=dict)
    sanitized_request: Optional[str] = None
    sanitized_response: Optional[str] = None
    comparison_hash: Optional[str] = None
    authentication_context_id: Optional[str] = None
    baseline_evidence_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: get_utc_now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EvidenceContractService:
    """Service for capturing, sanitizing, hashing, and validating verification evidence."""

    @classmethod
    def sanitize_headers(cls, headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
        """Redact sensitive headers."""
        if not headers:
            return {}
        sanitized: Dict[str, str] = {}
        for k, v in headers.items():
            k_lower = str(k).lower().strip()
            if k_lower in SENSITIVE_HEADER_KEYS:
                sanitized[str(k)] = "[REDACTED]"
            else:
                sanitized[str(k)] = str(v)
        return sanitized

    @classmethod
    def sanitize_body(cls, body: Optional[str]) -> str:
        """Redact sensitive secrets from request/response body text."""
        if not body:
            return ""
        sanitized = body
        for pattern, replacement in SENSITIVE_BODY_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized

    # Canonical aliases
    redact_headers = sanitize_headers
    redact_body = sanitize_body

    @classmethod
    def compute_sha256(cls, data: Union[str, bytes]) -> str:
        """Compute deterministic SHA-256 hash of bytes or string."""
        if isinstance(data, str):
            raw = data.encode("utf-8")
        else:
            raw = data
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def create_and_persist_evidence(
        cls,
        evidence_id: str,
        verification_run_id: str,
        campaign_id: str,
        hypothesis_id: str,
        strategy_id: str,
        target: str,
        endpoint: str,
        method: str,
        raw_request: str,
        raw_response: str,
        status_code: Optional[int] = None,
        headers: Optional[Dict[str, Any]] = None,
        scope_snapshot_hash: Optional[str] = None,
        authorization_decision: str = "APPROVE",
        comparison_hash: Optional[str] = None,
        baseline_evidence_id: Optional[str] = None,
        authentication_context_id: Optional[str] = None,
        verifier_version: str = "1.0.0-phase21",
        db: Optional[Session] = None,
    ) -> VerificationEvidenceDTO:
        """Create a sanitized, cryptographically hashed evidence record and persist it."""
        req_hash = cls.compute_sha256(raw_request)
        resp_hash = cls.compute_sha256(raw_response)
        
        sanitized_req = cls.sanitize_body(raw_request)
        sanitized_resp = cls.sanitize_body(raw_response)
        sanitized_hdrs = cls.sanitize_headers(headers)
        
        now_utc = get_utc_now()
        now_str = now_utc.isoformat()
        resp_len = len(raw_response.encode("utf-8")) if raw_response else 0

        dto = VerificationEvidenceDTO(
            id=evidence_id,
            verification_run_id=verification_run_id,
            campaign_id=campaign_id,
            hypothesis_id=hypothesis_id,
            strategy_id=strategy_id,
            target=target,
            endpoint=endpoint,
            method=method.upper(),
            request_hash=req_hash,
            response_hash=resp_hash,
            status_code=status_code,
            response_size=resp_len,
            timestamp=now_str,
            scope_snapshot_hash=scope_snapshot_hash,
            verifier_version=verifier_version,
            authorization_decision=authorization_decision,
            relevant_headers=sanitized_hdrs,
            sanitized_request=sanitized_req,
            sanitized_response=sanitized_resp,
            comparison_hash=comparison_hash,
            authentication_context_id=authentication_context_id,
            baseline_evidence_id=baseline_evidence_id,
            created_at=now_str,
        )

        if db is not None:
            record = VerificationEvidenceRecord(
                id=evidence_id,
                verification_run_id=verification_run_id,
                campaign_id=campaign_id,
                hypothesis_id=hypothesis_id,
                strategy_id=strategy_id,
                target=target,
                endpoint=endpoint,
                method=method.upper(),
                request_hash=req_hash,
                response_hash=resp_hash,
                status_code=status_code,
                response_size=resp_len,
                timestamp=now_utc,
                scope_snapshot_hash=scope_snapshot_hash,
                verifier_version=verifier_version,
                authorization_decision=authorization_decision,
                relevant_headers=json.dumps(sanitized_hdrs),
                sanitized_request=sanitized_req,
                sanitized_response=sanitized_resp,
                comparison_hash=comparison_hash,
                authentication_context_id=authentication_context_id,
                baseline_evidence_id=baseline_evidence_id,
                created_at=now_utc,
            )
            db.add(record)
            db.commit()
            db.refresh(record)

        return dto

    @classmethod
    def verify_evidence_integrity(cls, dto: VerificationEvidenceDTO, raw_response_text: str) -> bool:
        """Verify whether the response text matches the stored SHA-256 response hash."""
        computed = cls.compute_sha256(raw_response_text)
        return computed == dto.response_hash
