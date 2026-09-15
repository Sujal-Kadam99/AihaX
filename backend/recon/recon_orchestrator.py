"""AihaX Central Reconnaissance Orchestrator.

Orchestrates multi-source reconnaissance (Subfinder, Amass, CT, DNS, HTTP, Tech, Endpoints)
under strict execution modes (AUDIT, DRY_RUN, AUTHORIZED_LIVE_RECON).

Security Invariants:
1. Single concrete target validation (wildcards strictly rejected).
2. Upstream ReconPreflightGate enforces authorization, scope, SSRF, budget, and confirmation.
3. Discovered assets are tagged NOT_EXECUTABLE by default (intelligence only, never attacked).
4. Zero external network/subprocess calls in AUDIT mode.
5. Emits canonical deterministic ReconSnapshot and links with AttackSurfaceGraph.
6. Does NOT automatically trigger vulnerability execution.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from backend.core.scope_validator import ScopeValidator, normalize_domain, validate_destination_safety
from backend.execution.tool_execution_boundary import ToolExecutionBoundary
from backend.recon.providers import (
    AmassProvider,
    BaseReconProvider,
    CertificateTransparencyProvider,
    DNSProviderAdapter,
    HttpProbeProvider,
    ProviderExecutionResult,
    SubfinderProvider,
    Sublist3rProvider,
    TechnologyFingerprintProvider,
)
from backend.recon.recon_modes import (
    NormalizedReconAsset,
    ProviderStatus,
    ProviderType,
    ReconAssetStatus,
    ReconContext,
    ReconExecutionMode,
)
from backend.recon.recon_preflight import PreflightStatus, ReconPreflightDecision, ReconPreflightGate
from backend.recon.snapshot import CanonicalReconSnapshot
from backend.services.attack_surface_graph import (
    AttackSurfaceEdgeType,
    AttackSurfaceGraphEngine,
    AttackSurfaceNodeType,
)

logger = logging.getLogger("aihax.recon_orchestrator")


class UnifiedReconOrchestrator:
    """The central orchestrator for AihaX reconnaissance operations."""

    def __init__(
        self,
        tool_boundary: Optional[ToolExecutionBoundary] = None,
        custom_providers: Optional[List[BaseReconProvider]] = None,
    ) -> None:
        self.tool_boundary = tool_boundary or ToolExecutionBoundary()
        self.providers: Dict[str, BaseReconProvider] = {}

        if custom_providers:
            for p in custom_providers:
                self.providers[p.provider_id] = p
        else:
            # Default provider suite
            subfinder = SubfinderProvider(tool_boundary=self.tool_boundary)
            amass = AmassProvider(tool_boundary=self.tool_boundary)
            sublist3r = Sublist3rProvider()
            ct = CertificateTransparencyProvider()
            dns = DNSProviderAdapter()
            http_probe = HttpProbeProvider()
            tech = TechnologyFingerprintProvider()

            for p in [subfinder, amass, sublist3r, ct, dns, http_probe, tech]:
                self.providers[p.provider_id] = p

    async def execute_recon(
        self,
        context: ReconContext,
        scope_validator: ScopeValidator,
        enabled_providers: Optional[List[str]] = None,
        db_session: Optional[Any] = None,
    ) -> CanonicalReconSnapshot:
        """Run the end-to-end reconnaissance pipeline under the specified mode."""
        snapshot_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        warnings: List[str] = []
        errors: List[str] = []
        provider_statuses: Dict[str, str] = {}
        provider_versions: Dict[str, Optional[str]] = {}
        scope_decisions: Dict[str, str] = {}
        provenance_map: Dict[str, List[str]] = {}
        evidence_hashes: List[str] = []
        all_assets: List[NormalizedReconAsset] = []
        selected_provider_ids = enabled_providers or list(self.providers.keys())

        # 1. Preflight Safety & Authorization Gate
        preflight: ReconPreflightDecision = ReconPreflightGate.evaluate(
            context=context,
            scope_validator=scope_validator,
            requested_providers=selected_provider_ids,
        )

        if not preflight.allowed:
            errors.extend(preflight.reasons)
            return CanonicalReconSnapshot.create(
                snapshot_id=snapshot_id,
                campaign_id=context.campaign_id,
                concrete_target=context.target,
                execution_mode=context.execution_mode,
                selected_providers=selected_provider_ids,
                provider_statuses={"preflight": preflight.status.value},
                normalized_assets=[],
                authorization_reference=context.authorization_record_id,
                authorization_timestamp=context.created_at,
                scope_decisions={},
                warnings=preflight.warnings,
                errors=errors,
                created_at=started_at,
            )

        warnings.extend(preflight.warnings)

        # 2. DRY_RUN Handling: Inspect planned provider actions without executing
        if context.execution_mode == ReconExecutionMode.DRY_RUN:
            for pid in selected_provider_ids:
                if pid in self.providers:
                    p = self.providers[pid]
                    res = await p.discover(context.target, context, scope_validator)
                    provider_statuses[pid] = res.status.value
                    if res.metadata:
                        warnings.append(f"DRY_RUN for {pid}: {res.metadata}")

            return CanonicalReconSnapshot.create(
                snapshot_id=snapshot_id,
                campaign_id=context.campaign_id,
                concrete_target=context.target,
                execution_mode=context.execution_mode,
                selected_providers=selected_provider_ids,
                provider_statuses=provider_statuses,
                normalized_assets=[],
                authorization_reference=context.authorization_record_id,
                authorization_timestamp=context.created_at,
                warnings=warnings,
                errors=errors,
                created_at=started_at,
            )

        # 3. Add Root Seed Target
        target_clean = normalize_domain(context.target)
        root_scope_dec = scope_validator.validate_target(f"https://{target_clean}")
        root_status = ReconAssetStatus.IN_SCOPE if root_scope_dec.allowed else ReconAssetStatus.BLOCKED_SCOPE
        root_asset = NormalizedReconAsset(
            asset_id=str(uuid.uuid4()),
            raw_value=context.target,
            normalized_value=target_clean,
            asset_type="DOMAIN",
            source_provider="seed_target",
            status=root_status,
            is_executable=False,
            metadata={"scope_decision": root_scope_dec.reason},
            evidence_hash=hashlib.sha256(context.target.encode("utf-8")).hexdigest(),
        )
        all_assets.append(root_asset)
        provenance_map[target_clean] = ["seed_target"]
        scope_decisions[target_clean] = root_scope_dec.reason

        # 4. Execute Selected Providers
        for pid in selected_provider_ids:
            if pid not in self.providers:
                provider_statuses[pid] = ProviderStatus.NOT_IMPLEMENTED.value
                errors.append(f"Provider '{pid}' requested but not available.")
                continue

            provider = self.providers[pid]
            try:
                res: ProviderExecutionResult = await provider.discover(
                    target=context.target,
                    context=context,
                    scope_validator=scope_validator,
                )
                provider_statuses[pid] = res.status.value
                if res.error_message:
                    errors.append(f"Provider '{pid}' reported error: {res.error_message}")

                if res.evidence_hash:
                    evidence_hashes.append(res.evidence_hash)
                if res.stdout_hash:
                    evidence_hashes.append(res.stdout_hash)

                for asset in res.assets:
                    # Enforce scope check on discovered asset
                    target_candidate_url = f"https://{asset.normalized_value}" if "://" not in asset.normalized_value else asset.normalized_value
                    s_dec = scope_validator.validate_target(target_candidate_url)
                    if s_dec.allowed:
                        asset.status = ReconAssetStatus.IN_SCOPE
                    else:
                        asset.status = ReconAssetStatus.BLOCKED_SCOPE

                    # Critical rule: All discovered assets are not executable by default
                    asset.is_executable = False

                    all_assets.append(asset)
                    scope_decisions[asset.normalized_value] = s_dec.reason

                    if asset.normalized_value not in provenance_map:
                        provenance_map[asset.normalized_value] = []
                    if pid not in provenance_map[asset.normalized_value]:
                        provenance_map[asset.normalized_value].append(pid)

            except Exception as e:
                provider_statuses[pid] = ProviderStatus.LIVE_FAILED.value
                errors.append(f"Unexpected provider '{pid}' exception: {str(e)}")

        # 5. Deduplicate Normalized Assets Deterministically
        deduped_assets = self._deduplicate_assets(all_assets, provenance_map)

        # 6. Populate AttackSurfaceGraphEngine
        graph_dict = None
        try:
            nodes = []
            tgt_node = AttackSurfaceGraphEngine.add_target(
                campaign_id=context.campaign_id,
                target=context.target,
                source="RECON_ORCHESTRATOR",
                db=db_session,
            )
            nodes.append(tgt_node)
            for a in deduped_assets:
                if a.asset_type in ("ENDPOINT", "SERVICE"):
                    ep_node = AttackSurfaceGraphEngine.add_endpoint(
                        campaign_id=context.campaign_id,
                        target=context.target,
                        endpoint=a.normalized_value,
                        source=",".join(provenance_map.get(a.normalized_value, [a.source_provider])),
                        db=db_session,
                    )
                    nodes.append(ep_node)

            snap_hash = AttackSurfaceGraphEngine.compute_snapshot_hash(nodes, [])
            graph_dict = {
                "snapshot_hash": snap_hash,
                "node_count": len(nodes),
                "edge_count": 0,
            }
        except Exception as e:
            logger.debug(f"Attack surface graph update skipped: {e}")

        # 7. Create Canonical ReconSnapshot
        snapshot = CanonicalReconSnapshot.create(
            snapshot_id=snapshot_id,
            campaign_id=context.campaign_id,
            concrete_target=context.target,
            execution_mode=context.execution_mode,
            selected_providers=selected_provider_ids,
            provider_statuses=provider_statuses,
            normalized_assets=deduped_assets,
            authorization_reference=context.authorization_record_id,
            authorization_timestamp=context.created_at,
            provider_versions=provider_versions,
            scope_decisions=scope_decisions,
            provenance=provenance_map,
            evidence_hashes=evidence_hashes,
            graph_snapshot=graph_dict,
            warnings=warnings,
            errors=errors,
            created_at=started_at,
            completed_at=datetime.now(timezone.utc).isoformat(),
        )

        return snapshot

    def _deduplicate_assets(
        self,
        assets: List[NormalizedReconAsset],
        provenance: Dict[str, List[str]],
    ) -> List[NormalizedReconAsset]:
        """Merge identical assets and combine provenance deterministically."""
        merged: Dict[Tuple[str, str], NormalizedReconAsset] = {}
        for a in assets:
            key = (a.asset_type, a.normalized_value)
            if key not in merged:
                merged[key] = NormalizedReconAsset(
                    asset_id=a.asset_id,
                    raw_value=a.raw_value,
                    normalized_value=a.normalized_value,
                    asset_type=a.asset_type,
                    source_provider=",".join(sorted(provenance.get(a.normalized_value, [a.source_provider]))),
                    confidence=a.confidence,
                    status=a.status,
                    is_executable=False,
                    metadata=dict(a.metadata),
                    evidence_hash=a.evidence_hash,
                    discovered_at=a.discovered_at,
                )
            else:
                existing = merged[key]
                existing.metadata.update(a.metadata)
                existing.source_provider = ",".join(sorted(provenance.get(a.normalized_value, [existing.source_provider])))

        # Return sorted list for determinism
        return sorted(merged.values(), key=lambda item: (item.asset_type, item.normalized_value))
