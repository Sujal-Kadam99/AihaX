"""AihaX Phase 8 — Content-Addressed Evidence Store (Evidence Vault).

Provides immutable, secret-redacted evidence persistence with cryptographic chain hashing.

Invariants:
- All evidence requests/responses are stripped of secrets before persistence.
- SHA-256 content hashes are calculated over sanitized content.
- Evidence records are immutable once persisted.
- Chained hashes connect sequential observations within a campaign.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.evidence.integrity import (
    compute_evidence_chain_hash,
    compute_evidence_content_hash,
    verify_evidence_integrity,
)
from backend.evidence.redaction import redact_secrets
from backend.persistence.models import EvidenceRecord
from backend.persistence.repository import CampaignRepository

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class VaultEvidenceEntry:
    """Immutable in-memory representation of an evidence vault item."""
    id: str
    campaign_id: str
    evidence_type: str
    target_url: str
    method: str
    sanitized_request: str
    sanitized_response: str
    payload_summary: str
    content_hash: str
    chain_hash: str
    created_at: str
    finding_id: Optional[str] = None
    task_id: Optional[str] = None
    request_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "evidence_id": self.id,
            "campaign_id": self.campaign_id,
            "finding_id": self.finding_id,
            "task_id": self.task_id,
            "request_id": self.request_id,
            "evidence_type": self.evidence_type,
            "target_url": self.target_url,
            "method": self.method,
            "sanitized_request": self.sanitized_request,
            "sanitized_response": self.sanitized_response,
            "payload_summary": self.payload_summary,
            "content_hash": self.content_hash,
            "chain_hash": self.chain_hash,
            "created_at": self.created_at,
        }


class EvidenceVault:
    """Evidence Vault managing persistent, immutable, secret-redacted evidence."""

    def __init__(self, repository: CampaignRepository) -> None:
        self.repo = repository

    def store_evidence(
        self,
        campaign_id: str,
        evidence_type: str,
        target_url: str,
        method: str = "GET",
        raw_request: Optional[str] = None,
        raw_response: Optional[str] = None,
        payload_summary: Optional[str] = None,
        finding_id: Optional[str] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> VaultEvidenceEntry:
        """Sanitize, hash, chain, and persist an immutable evidence item."""
        # 1. Redact all secrets before hashing or storage
        sanitized_req = redact_secrets(raw_request)
        sanitized_resp = redact_secrets(raw_response)
        sanitized_payload = redact_secrets(payload_summary)

        # 2. Compute content hash over sanitized fields
        content_hash = compute_evidence_content_hash(
            evidence_type=evidence_type,
            target_url=target_url,
            method=method,
            sanitized_request=sanitized_req,
            sanitized_response=sanitized_resp,
            payload_summary=sanitized_payload,
        )

        now_str = datetime.now(timezone.utc).isoformat()

        # 3. Retrieve latest evidence record for chain hashing
        existing_records = self.repo.get_evidence_for_campaign(campaign_id, limit=1)
        prev_chain_hash = existing_records[-1].chain_hash if existing_records else None
        chain_hash = compute_evidence_chain_hash(content_hash, prev_chain_hash, now_str)

        # 4. Persist to database repository
        evidence_id = str(uuid.uuid4())
        record = self.repo.record_evidence(
            campaign_id=campaign_id,
            evidence_type=evidence_type,
            target_url=target_url,
            content_hash=content_hash,
            method=method,
            sanitized_request=sanitized_req,
            sanitized_response=sanitized_resp,
            payload_summary=sanitized_payload,
            chain_hash=chain_hash,
            finding_id=finding_id,
            task_id=task_id,
            request_id=request_id,
            evidence_id=evidence_id,
        )

        return VaultEvidenceEntry(
            id=record.id,
            campaign_id=record.campaign_id,
            finding_id=record.finding_id,
            task_id=record.task_id,
            request_id=record.request_id,
            evidence_type=record.evidence_type,
            target_url=record.target_url,
            method=record.method,
            sanitized_request=record.sanitized_request or "",
            sanitized_response=record.sanitized_response or "",
            payload_summary=record.payload_summary or "",
            content_hash=record.content_hash,
            chain_hash=record.chain_hash or "",
            created_at=record.created_at.isoformat() if hasattr(record.created_at, "isoformat") else str(record.created_at),
        )

    def get_evidence(self, evidence_id: str) -> Optional[VaultEvidenceEntry]:
        record = self.repo.get_evidence_by_id(evidence_id)
        if not record:
            return None
        return VaultEvidenceEntry(
            id=record.id,
            campaign_id=record.campaign_id,
            finding_id=record.finding_id,
            task_id=record.task_id,
            request_id=record.request_id,
            evidence_type=record.evidence_type,
            target_url=record.target_url,
            method=record.method,
            sanitized_request=record.sanitized_request or "",
            sanitized_response=record.sanitized_response or "",
            payload_summary=record.payload_summary or "",
            content_hash=record.content_hash,
            chain_hash=record.chain_hash or "",
            created_at=record.created_at.isoformat() if hasattr(record.created_at, "isoformat") else str(record.created_at),
        )

    def list_evidence_for_campaign(self, campaign_id: str, limit: int = 100, offset: int = 0) -> List[VaultEvidenceEntry]:
        records = self.repo.get_evidence_for_campaign(campaign_id, limit=limit, offset=offset)
        return [
            VaultEvidenceEntry(
                id=r.id,
                campaign_id=r.campaign_id,
                finding_id=r.finding_id,
                task_id=r.task_id,
                request_id=r.request_id,
                evidence_type=r.evidence_type,
                target_url=r.target_url,
                method=r.method,
                sanitized_request=r.sanitized_request or "",
                sanitized_response=r.sanitized_response or "",
                payload_summary=r.payload_summary or "",
                content_hash=r.content_hash,
                chain_hash=r.chain_hash or "",
                created_at=r.created_at.isoformat() if hasattr(r.created_at, "isoformat") else str(r.created_at),
            )
            for r in records
        ]

    def verify_vault_integrity(self, campaign_id: str) -> Tuple[bool, List[str]]:
        """Verify content integrity and hash chaining across all evidence in campaign."""
        records = self.repo.get_evidence_for_campaign(campaign_id, limit=1000)
        issues: List[str] = []

        prev_chain_hash: Optional[str] = None
        for idx, rec in enumerate(records):
            valid, reason = verify_evidence_integrity(
                content_hash=rec.content_hash,
                evidence_type=rec.evidence_type,
                target_url=rec.target_url,
                method=rec.method,
                sanitized_request=rec.sanitized_request,
                sanitized_response=rec.sanitized_response,
                payload_summary=rec.payload_summary,
            )
            if not valid:
                issues.append(f"Evidence {rec.id} (index {idx}) content hash corrupted: {reason}")

        return len(issues) == 0, issues
