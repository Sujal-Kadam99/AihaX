"""AihaX Canonical Immutable Reconnaissance Snapshot Model.

Provides deterministic SHA-256 snapshot hashing, provenance tracking,
and immutable auditing across all reconnaissance observations.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.recon.recon_modes import NormalizedReconAsset, ReconExecutionMode


@dataclass(frozen=True)
class CanonicalReconSnapshot:
    """Canonical, immutable, and cryptographically verifiable reconnaissance snapshot."""
    snapshot_id: str
    campaign_id: str
    concrete_target: str
    authorization_reference: Optional[str]
    authorization_timestamp: Optional[str]
    execution_mode: str
    selected_providers: List[str]
    provider_versions: Dict[str, Optional[str]]
    provider_statuses: Dict[str, str]
    normalized_assets: List[NormalizedReconAsset]
    scope_decisions: Dict[str, str]
    provenance: Dict[str, List[str]]
    evidence_hashes: List[str]
    observations: List[Dict[str, Any]]
    graph_snapshot: Optional[Dict[str, Any]]
    warnings: List[str]
    errors: List[str]
    created_at: str
    completed_at: Optional[str]
    snapshot_hash: str

    @classmethod
    def create(
        cls,
        snapshot_id: str,
        campaign_id: str,
        concrete_target: str,
        execution_mode: ReconExecutionMode,
        selected_providers: List[str],
        provider_statuses: Dict[str, str],
        normalized_assets: List[NormalizedReconAsset],
        authorization_reference: Optional[str] = None,
        authorization_timestamp: Optional[str] = None,
        provider_versions: Optional[Dict[str, Optional[str]]] = None,
        scope_decisions: Optional[Dict[str, str]] = None,
        provenance: Optional[Dict[str, List[str]]] = None,
        evidence_hashes: Optional[List[str]] = None,
        observations: Optional[List[Dict[str, Any]]] = None,
        graph_snapshot: Optional[Dict[str, Any]] = None,
        warnings: Optional[List[str]] = None,
        errors: Optional[List[str]] = None,
        created_at: Optional[str] = None,
        completed_at: Optional[str] = None,
    ) -> CanonicalReconSnapshot:
        c_at = created_at or datetime.now(timezone.utc).isoformat()
        comp_at = completed_at or datetime.now(timezone.utc).isoformat()
        p_versions = provider_versions or {}
        s_decisions = scope_decisions or {}
        prov = provenance or {}
        ev_hashes = sorted(list(set(evidence_hashes or [])))
        obs = observations or []
        warns = warnings or []
        errs = errors or []

        # Deterministic payload for canonical SHA-256 hash
        canonical_payload = {
            "campaign_id": campaign_id,
            "concrete_target": concrete_target,
            "execution_mode": execution_mode.value if hasattr(execution_mode, "value") else str(execution_mode),
            "selected_providers": sorted(selected_providers),
            "provider_statuses": {k: provider_statuses[k] for k in sorted(provider_statuses.keys())},
            "assets": sorted([
                f"{a.asset_type}:{a.normalized_value}:{a.status}:{a.source_provider}"
                for a in normalized_assets
            ]),
            "evidence_hashes": ev_hashes,
            "scope_decisions": {k: s_decisions[k] for k in sorted(s_decisions.keys())},
        }
        serialized = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
        snap_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        return cls(
            snapshot_id=snapshot_id,
            campaign_id=campaign_id,
            concrete_target=concrete_target,
            authorization_reference=authorization_reference,
            authorization_timestamp=authorization_timestamp,
            execution_mode=execution_mode.value if hasattr(execution_mode, "value") else str(execution_mode),
            selected_providers=sorted(selected_providers),
            provider_versions=p_versions,
            provider_statuses=provider_statuses,
            normalized_assets=normalized_assets,
            scope_decisions=s_decisions,
            provenance=prov,
            evidence_hashes=ev_hashes,
            observations=obs,
            graph_snapshot=graph_snapshot,
            warnings=warns,
            errors=errs,
            created_at=c_at,
            completed_at=comp_at,
            snapshot_hash=snap_hash,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "campaign_id": self.campaign_id,
            "concrete_target": self.concrete_target,
            "authorization_reference": self.authorization_reference,
            "authorization_timestamp": self.authorization_timestamp,
            "execution_mode": self.execution_mode,
            "selected_providers": self.selected_providers,
            "provider_versions": self.provider_versions,
            "provider_statuses": self.provider_statuses,
            "normalized_assets": [a.to_dict() for a in self.normalized_assets],
            "scope_decisions": self.scope_decisions,
            "provenance": self.provenance,
            "evidence_hashes": self.evidence_hashes,
            "observations": self.observations,
            "graph_snapshot": self.graph_snapshot,
            "warnings": self.warnings,
            "errors": self.errors,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "snapshot_hash": self.snapshot_hash,
            "asset_count": len(self.normalized_assets),
        }
