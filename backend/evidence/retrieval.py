"""AihaX Phase 8 — Evidence Retrieval Service.

Provides a safe, paginated, secret-free query interface for evidence records.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from backend.evidence.evidence_store import EvidenceVault, VaultEvidenceEntry
from backend.persistence.repository import CampaignRepository


class EvidenceRetrievalService:
    """Read-only query interface for the Evidence Vault."""

    def __init__(self, repository: CampaignRepository) -> None:
        self.repo = repository
        self.vault = EvidenceVault(repository)

    def get_evidence_item(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        item = self.vault.get_evidence(evidence_id)
        return item.to_dict() if item else None

    def list_campaign_evidence(
        self,
        campaign_id: str,
        limit: int = 50,
        offset: int = 0,
        evidence_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        all_for_campaign = self.repo.get_evidence_for_campaign(campaign_id)
        if evidence_type:
            all_for_campaign = [i for i in all_for_campaign if i.evidence_type.upper() == evidence_type.upper()]
        total_count = len(all_for_campaign)

        items = self.vault.list_evidence_for_campaign(campaign_id, limit=limit, offset=offset)
        if evidence_type:
            items = [i for i in items if i.evidence_type.upper() == evidence_type.upper()]

        return {
            "campaign_id": campaign_id,
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
            "items": [i.to_dict() for i in items],
        }
