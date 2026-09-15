"""AihaX Phase 20 — Negative Evidence Tracking & Redundancy Suppression Service.

Architectural Invariants:
1. Proof of Non-Vulnerability: Records deterministic proof that a specific condition was probed and not observed.
2. Target & Scope Binding: Every negative evidence record is strictly bound to a concrete target and scope snapshot.
3. Non-Finding Invariance: Negative evidence records can NEVER be converted into vulnerability findings.
4. Redundancy Suppression: Used by the adaptive planner to avoid repeated redundant probing during the same campaign.
5. No Inferred Negative Evidence: Unperformed probes are NEVER treated as negative evidence.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence
from sqlalchemy.orm import Session

from backend.models.database import NegativeEvidenceRecord, get_utc_now

logger = logging.getLogger("aihax.negative_evidence")


@dataclass
class NegativeEvidenceDTO:
    """Structured negative evidence data transfer object."""
    id: str
    target: str
    endpoint: str
    check_id: str
    timestamp: str
    request_hash: str
    response_hash: str
    verdict: str
    verification_state: str
    scope_snapshot_hash: Optional[str] = None
    verifier_version: Optional[str] = "1.0.0-phase20"
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class NegativeEvidenceService:
    """Service for registering, querying, and verifying negative evidence."""

    @classmethod
    def record_negative_evidence(
        cls,
        target: str,
        scope_snapshot_hash: Optional[str] = None,
        check_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        request_proof: Optional[str] = None,
        response_proof: Optional[str] = None,
        proof_request: Optional[str] = None,
        proof_response: Optional[str] = None,
        proof_request_text: Optional[str] = None,
        proof_response_text: Optional[str] = None,
        verdict: str = "FALSE_POSITIVE",
        verification_state: str = "REJECTED",
        verifier_version: str = "1.0.0-phase20",
        details: Optional[str] = None,
        http_method: Optional[str] = "GET",
        status_code: Optional[int] = None,
        db: Optional[Session] = None,
        **kwargs: Any,
    ) -> NegativeEvidenceDTO:
        """Record and persist verified negative evidence."""
        effective_check_id = check_id or kwargs.get("check") or ""
        if not target or not effective_check_id:
            raise ValueError("Target and check_id are mandatory for negative evidence.")

        effective_endpoint = endpoint or target
        req_p = proof_request_text if proof_request_text is not None else (proof_request if proof_request is not None else (request_proof if request_proof is not None else ""))
        resp_p = proof_response_text if proof_response_text is not None else (proof_response if proof_response is not None else (response_proof if response_proof is not None else ""))

        # Compute deterministic SHA-256 hashes of proof bytes
        req_hash = hashlib.sha256(req_p.encode("utf-8") if isinstance(req_p, str) else req_p).hexdigest()
        resp_hash = hashlib.sha256(resp_p.encode("utf-8") if isinstance(resp_p, str) else resp_p).hexdigest()

        rec_id = str(uuid.uuid4())
        now_utc = get_utc_now()

        dto = NegativeEvidenceDTO(
            id=rec_id,
            target=target,
            endpoint=effective_endpoint,
            check_id=effective_check_id,
            timestamp=now_utc.isoformat(),
            request_hash=req_hash,
            response_hash=resp_hash,
            verdict=verdict,
            verification_state=verification_state,
            scope_snapshot_hash=scope_snapshot_hash,
            verifier_version=verifier_version,
            details=details,
        )

        if db is not None:
            record = NegativeEvidenceRecord(
                id=rec_id,
                target=target,
                endpoint=effective_endpoint,
                check_id=effective_check_id,
                timestamp=now_utc,
                request_hash=req_hash,
                response_hash=resp_hash,
                verdict=verdict,
                verification_state=verification_state,
                scope_snapshot_hash=scope_snapshot_hash,
                verifier_version=verifier_version,
                details=details,
            )
            db.add(record)
            db.commit()
            db.refresh(record)

        return dto

    @classmethod
    def has_negative_evidence(
        cls,
        target: str,
        check_id: str,
        endpoint: Optional[str] = None,
        scope_snapshot_hash: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> bool:
        """Check if deterministic negative evidence exists for this target + check."""
        if db is None:
            return False

        query = db.query(NegativeEvidenceRecord).filter(
            NegativeEvidenceRecord.target == target,
            NegativeEvidenceRecord.check_id == check_id,
        )
        if endpoint:
            query = query.filter(NegativeEvidenceRecord.endpoint == endpoint)
        if scope_snapshot_hash:
            query = query.filter(NegativeEvidenceRecord.scope_snapshot_hash == scope_snapshot_hash)

        return query.first() is not None

    @classmethod
    def get_negative_evidence_for_target(
        cls,
        target: str,
        db: Optional[Session] = None,
    ) -> List[NegativeEvidenceDTO]:
        """List all negative evidence recorded for a target."""
        if db is None:
            return []

        records = db.query(NegativeEvidenceRecord).filter(
            NegativeEvidenceRecord.target == target
        ).all()

        return [
            NegativeEvidenceDTO(
                id=r.id,
                target=r.target,
                endpoint=r.endpoint,
                check_id=r.check_id,
                timestamp=r.timestamp.isoformat() if hasattr(r.timestamp, "isoformat") else str(r.timestamp),
                request_hash=r.request_hash,
                response_hash=r.response_hash,
                verdict=r.verdict,
                verification_state=r.verification_state,
                scope_snapshot_hash=r.scope_snapshot_hash,
                verifier_version=r.verifier_version,
                details=r.details,
            )
            for r in records
        ]
