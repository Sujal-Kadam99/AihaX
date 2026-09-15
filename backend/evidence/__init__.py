"""AihaX Phase 8 — Evidence Vault Package."""

from backend.evidence.evidence_manifest import (
    CampaignIntegrityReport,
    CampaignManifest,
    IntegrityCheckResult,
    ManifestBuilder,
    compute_manifest_hash,
)
from backend.evidence.evidence_store import EvidenceVault, VaultEvidenceEntry
from backend.evidence.integrity import (
    compute_evidence_chain_hash,
    compute_evidence_content_hash,
    verify_evidence_integrity,
)
from backend.evidence.redaction import (
    contains_unredacted_secrets,
    redact_dictionary,
    redact_secrets,
)
from backend.evidence.retrieval import EvidenceRetrievalService

__all__ = [
    "EvidenceVault",
    "VaultEvidenceEntry",
    "CampaignManifest",
    "CampaignIntegrityReport",
    "IntegrityCheckResult",
    "ManifestBuilder",
    "compute_manifest_hash",
    "compute_evidence_content_hash",
    "compute_evidence_chain_hash",
    "verify_evidence_integrity",
    "redact_secrets",
    "redact_dictionary",
    "contains_unredacted_secrets",
    "EvidenceRetrievalService",
]
