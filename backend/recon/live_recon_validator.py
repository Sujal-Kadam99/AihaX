"""AihaX Phase 25 — Tool-by-Tool Live Recon Validation Gate.

Provides strict, auditable, and gated validation of all 13 reconnaissance tools:
1. Subfinder
2. Sublist3r (formally NOT_IMPLEMENTED)
3. Amass
4. Certificate Transparency (crt.sh)
5. Wayback (Archive.org CDX API & waybackurls)
6. GAU (GetAllUrls)
7. DNS Enumeration (dnspython)
8. HTTP/HTTPS Probing (RequestEngine + HttpProbeEngine)
9. WhatWeb
10. Nmap
11. Gobuster
12. Nuclei (formally NOT_SELECTED_RECON_ONLY)
13. Dalfox (formally NOT_SELECTED_RECON_ONLY)

Security Invariants:
1. Strict Authorization Gate: Requires valid, active authorization record.
2. Concrete Target Only: Strictly NO wildcards.
3. Discovered Assets are DATA, not authorization (marked DISCOVERED_NOT_AUTHORIZED).
4. External tools execute exclusively through ToolExecutionBoundary using structured arguments.
5. HTTP/HTTPS requests execute exclusively through RequestEngine with ScopeValidator and anti-SSRF checks.
6. Truthful Classification: No false success; uninstalled binaries report EXECUTION_FAILED.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import shutil
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from backend.core.scope_validator import ScopeValidator, normalize_domain, validate_destination_safety
from backend.execution.tool_execution_boundary import (
    ALLOWED_TOOLS,
    ExecutionProfile,
    ToolDefinition,
    ToolExecutionBoundary,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from backend.models.database import get_utc_now
from backend.recon.http_probe import HttpProbeEngine
from backend.recon.models import DiscoveredAsset, DiscoverySource
from backend.recon.recon_modes import (
    NormalizedReconAsset,
    ProviderStatus,
    ProviderType,
    ReconAssetStatus,
    ReconContext,
    ReconExecutionMode,
)
from backend.recon.snapshot import CanonicalReconSnapshot
from backend.services.attack_surface_graph import (
    AttackSurfaceEdgeType,
    AttackSurfaceGraphEngine,
    AttackSurfaceNodeType,
)
from backend.services.discovery.crtsh_provider import CRTShProvider
from backend.services.discovery.normalizer import normalize_domain as rfc_normalize_domain
from backend.services.discovery.normalizer import normalize_url
from backend.services.discovery.wayback_provider import WaybackProvider
from backend.services.request_engine import (
    MockTransport,
    RequestEngine,
    RequestSpec,
    RequestTimeout,
)

from backend.recon.recon_tool_availability import ReconToolAvailability

logger = logging.getLogger("aihax.live_recon_validator")


# ==============================================================================
# 1. Authoritative Validation Status Enum (Section 18 & Phase 26 Section 9)
# ==============================================================================

class ToolValidationStatus(str, Enum):
    """Strict classification enum enforcing no false success."""
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    NOT_SELECTED = "NOT_SELECTED"
    NOT_SELECTED_RECON_ONLY = "NOT_SELECTED_RECON_ONLY"
    BLOCKED_AUTHORIZATION = "BLOCKED_AUTHORIZATION"
    BLOCKED_SCOPE = "BLOCKED_SCOPE"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    BLOCKED_SAFETY = "BLOCKED_SAFETY"
    BLOCKED_BUDGET = "BLOCKED_BUDGET"
    BINARY_UNAVAILABLE = "BINARY_UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    OUTPUT_INVALID = "OUTPUT_INVALID"
    PARSE_FAILED = "PARSE_FAILED"
    NORMALIZATION_FAILED = "NORMALIZATION_FAILED"
    EVIDENCE_PERSISTENCE_FAILED = "EVIDENCE_PERSISTENCE_FAILED"
    STUB_ONLY = "STUB_ONLY"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    EXECUTED_ZERO_RESULTS = "EXECUTED_ZERO_RESULTS"
    EXECUTED_RESULTS_CAPTURED = "EXECUTED_RESULTS_CAPTURED"
    EXECUTED_RESULTS_NORMALIZED = "EXECUTED_RESULTS_NORMALIZED"
    EXECUTED_RESULTS_INTEGRATED = "EXECUTED_RESULTS_INTEGRATED"
    LIVE_VALIDATED = "LIVE_VALIDATED"


# ==============================================================================
# 2. Lifecycle Events & Execution Origin (Section 20 & Phase 27)
# ==============================================================================

class ReconLifecycleEvent(str, Enum):
    RECON_TOOL_STARTED = "RECON_TOOL_STARTED"
    RECON_TOOL_EXECUTED = "RECON_TOOL_EXECUTED"
    RECON_TOOL_OUTPUT_CAPTURED = "RECON_TOOL_OUTPUT_CAPTURED"
    RECON_TOOL_OUTPUT_PARSED = "RECON_TOOL_OUTPUT_PARSED"
    RECON_TOOL_RESULTS_NORMALIZED = "RECON_TOOL_RESULTS_NORMALIZED"
    RECON_TOOL_EVIDENCE_CAPTURED = "RECON_TOOL_EVIDENCE_CAPTURED"
    RECON_TOOL_INTEGRATED = "RECON_TOOL_INTEGRATED"
    RECON_TOOL_BLOCKED = "RECON_TOOL_BLOCKED"
    RECON_TOOL_FAILED = "RECON_TOOL_FAILED"


class ExecutionOrigin(str, Enum):
    """Execution provenance origin enforcing pipeline-only certification."""
    PHASE27_CONTROLLED_PIPELINE = "PHASE27_CONTROLLED_PIPELINE"
    MANUAL_DIAGNOSTIC = "MANUAL_DIAGNOSTIC"
    MANUAL_TROUBLESHOOTING = "MANUAL_TROUBLESHOOTING"
    UNSPECIFIED = "UNSPECIFIED"


# ==============================================================================
# 3. Machine-Readable Tool Execution Record (Section 4 & Phase 27)
# ==============================================================================

@dataclass
class ToolExecutionRecord:
    """Exact machine-readable execution record required by Phase 25 Section 4 & Phase 27."""
    tool_name: str
    tool_version: Optional[str] = None
    execution_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    pipeline_run_id: Optional[str] = None
    execution_origin: ExecutionOrigin = ExecutionOrigin.UNSPECIFIED
    campaign_id: str = ""
    authorization_record_id: Optional[str] = None
    target: str = ""
    scope_snapshot_hash: Optional[str] = None
    execution_mode: str = "AUTHORIZED_LIVE_RECON"
    started_at: str = field(default_factory=lambda: get_utc_now().isoformat())
    completed_at: Optional[str] = None
    duration_ms: float = 0.0
    arguments: List[str] = field(default_factory=list)
    exit_code: Optional[int] = None
    stdout_hash: Optional[str] = None
    stderr_hash: Optional[str] = None
    raw_output_size: int = 0
    parsed_result_count: int = 0
    normalized_result_count: int = 0
    snapshot_contribution_count: int = 0
    evidence_id: Optional[str] = None
    status: ToolValidationStatus = ToolValidationStatus.NOT_SELECTED
    failure_reason: Optional[str] = None
    lifecycle_events: List[str] = field(default_factory=list)
    raw_output: Optional[str] = None
    normalized_assets: List[Dict[str, Any]] = field(default_factory=list)

    def record_event(self, event: ReconLifecycleEvent, detail: Optional[str] = None) -> None:
        entry = event.value
        if detail:
            entry = f"{entry}: {detail}"
        self.lifecycle_events.append(entry)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value if hasattr(self.status, "value") else str(self.status)
        d["execution_origin"] = (
            self.execution_origin.value
            if hasattr(self.execution_origin, "value")
            else str(self.execution_origin)
        )
        # Avoid huge raw_output in summary dumps
        if d.get("raw_output") and len(d["raw_output"]) > 1000:
            d["raw_output_truncated"] = True
            d["raw_output"] = d["raw_output"][:1000] + "... [TRUNCATED]"
        return d


# ==============================================================================
# 4. Phase 25 Validation Suite Result
# ==============================================================================

@dataclass
class Phase25ValidationSuiteResult:
    """Consolidated result of the Tool-by-Tool Live Recon Validation Gate."""
    target: str
    host: str
    base_domain: str
    campaign_id: str
    authorization_record_id: Optional[str]
    suite_status: str
    started_at: str
    completed_at: str
    total_tools_evaluated: int
    executed_tools_count: int
    live_validated_count: int
    failed_tools_count: int
    blocked_tools_count: int
    tool_records: Dict[str, ToolExecutionRecord]
    recon_snapshot: Optional[CanonicalReconSnapshot] = None
    attack_surface_graph: Optional[Dict[str, Any]] = None
    cross_tool_correlation: Dict[str, Any] = field(default_factory=dict)
    safety_audit_passed: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "host": self.host,
            "base_domain": self.base_domain,
            "campaign_id": self.campaign_id,
            "authorization_record_id": self.authorization_record_id,
            "suite_status": self.suite_status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_tools_evaluated": self.total_tools_evaluated,
            "executed_tools_count": self.executed_tools_count,
            "live_validated_count": self.live_validated_count,
            "failed_tools_count": self.failed_tools_count,
            "blocked_tools_count": self.blocked_tools_count,
            "tool_records": {k: v.to_dict() for k, v in self.tool_records.items()},
            "recon_snapshot_hash": self.recon_snapshot.snapshot_hash if self.recon_snapshot else None,
            "attack_surface_graph": self.attack_surface_graph,
            "cross_tool_correlation": self.cross_tool_correlation,
            "safety_audit_passed": self.safety_audit_passed,
        }


# ==============================================================================
# 5. Core Live Recon Validator Implementation
# ==============================================================================

class LiveReconValidationEngine:
    """Executes and classifies recon tools under Phase 25 Invariants."""

    def __init__(
        self,
        tool_boundary: Optional[ToolExecutionBoundary] = None,
        request_engine: Optional[RequestEngine] = None,
        custom_bin_dir: Optional[str] = None,
    ) -> None:
        self.tool_boundary = tool_boundary or ToolExecutionBoundary()
        self.request_engine = request_engine
        self.tool_availability = ReconToolAvailability(
            tool_boundary=self.tool_boundary,
            custom_bin_dir=custom_bin_dir,
            custom_process_runner=getattr(self.tool_boundary, "_custom_process_runner", None),
        )

    @staticmethod
    def verify_authorization(
        target: str,
        campaign_id: Optional[str] = None,
        db_session: Optional[Any] = None,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Verify explicit authorization record exists in DB for the target."""
        if not target:
            return False, None, "Target is empty."

        parsed = urlparse(target if "://" in target else f"https://{target}")
        target_norm = (parsed.hostname or target).lower()

        if db_session is not None:
            try:
                from backend.persistence.models import AuthorizationRecord, Campaign
                query = db_session.query(AuthorizationRecord)
                if campaign_id:
                    query = query.filter(AuthorizationRecord.campaign_id == campaign_id)

                records = query.all()
                now_iso = get_utc_now().isoformat()

                for r in records:
                    if r.status != "ACTIVE":
                        continue
                    if r.expires_at:
                        exp_iso = r.expires_at.isoformat() if hasattr(r.expires_at, "isoformat") else str(r.expires_at)
                        if exp_iso < now_iso:
                            continue

                    # Check campaign target
                    if r.campaign:
                        c_target = (r.campaign.target_url or "").lower()
                        c_parsed = urlparse(c_target if "://" in c_target else f"https://{c_target}")
                        c_host = (c_parsed.hostname or c_target).lower()
                        if target_norm == c_host or target.lower() == c_target:
                            return True, r.id, f"Authorized under campaign {r.campaign_id} (record: {r.id})"

                return False, None, f"No active authorization record for '{target_norm}' in database."
            except Exception as e:
                logger.warning(f"Error querying authorization records: {e}")

        # Fallback if no db session or db query failed
        return False, None, "Database session unavailable for authorization verification."

    async def execute_validation_suite(
        self,
        target: str,
        campaign_id: str,
        authorization_record_id: Optional[str] = None,
        operator_confirmed: bool = False,
        scope_assets: Optional[List[str]] = None,
        db_session: Optional[Any] = None,
        scope_snapshot_hash: Optional[str] = None,
        allow_port_scan: bool = False,
        allow_dir_scan: bool = False,
        execution_origin: ExecutionOrigin = ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE,
        pipeline_run_id: Optional[str] = None,
    ) -> Phase25ValidationSuiteResult:
        """Run the comprehensive Phase 25 validation gate."""
        start_time = get_utc_now().isoformat()
        start_ts = asyncio.get_event_loop().time()

        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = (parsed.hostname or target).lower()
        base_domain = host[4:] if host.startswith("www.") else normalize_domain(host)

        effective_scope = scope_assets or [f"https://{host}"]
        scope_validator = ScopeValidator(in_scope_assets=effective_scope)

        # Invariant 1: Single concrete target check
        if "*" in target or " " in target or "," in target:
            failed_records = self._generate_blocked_records(
                target=target,
                campaign_id=campaign_id,
                status=ToolValidationStatus.BLOCKED_SAFETY,
                reason="Target contains wildcards or multiple destinations; single concrete target required.",
                execution_origin=execution_origin,
                pipeline_run_id=pipeline_run_id,
            )
            return Phase25ValidationSuiteResult(
                target=target,
                host=host,
                base_domain=base_domain,
                campaign_id=campaign_id,
                authorization_record_id=authorization_record_id,
                suite_status=ToolValidationStatus.BLOCKED_SAFETY.value,
                started_at=start_time,
                completed_at=get_utc_now().isoformat(),
                total_tools_evaluated=13,
                executed_tools_count=0,
                live_validated_count=0,
                failed_tools_count=0,
                blocked_tools_count=13,
                tool_records=failed_records,
                safety_audit_passed=False,
            )

        # Invariant 2: Authorization Gate check
        # Must require a valid AihaX authorization record. If not provided or invalid: STOP.
        is_auth = False
        auth_rec_id = authorization_record_id
        if auth_rec_id and operator_confirmed:
            is_auth = True
        elif db_session:
            db_auth, found_id, _ = self.verify_authorization(target, campaign_id=campaign_id, db_session=db_session)
            if db_auth and found_id and operator_confirmed:
                is_auth = True
                auth_rec_id = found_id

        if not is_auth:
            logger.warning(f"STOP LIVE EXECUTION: Target '{target}' lacks valid authorization record or operator confirmation.")
            blocked_records = self._generate_blocked_records(
                target=target,
                campaign_id=campaign_id,
                status=ToolValidationStatus.BLOCKED_AUTHORIZATION,
                reason=f"STOP LIVE EXECUTION: Target '{target}' lacks valid AihaX authorization record or operator confirmation.",
                execution_origin=execution_origin,
                pipeline_run_id=pipeline_run_id,
            )
            return Phase25ValidationSuiteResult(
                target=target,
                host=host,
                base_domain=base_domain,
                campaign_id=campaign_id,
                authorization_record_id=None,
                suite_status=ToolValidationStatus.BLOCKED_AUTHORIZATION.value,
                started_at=start_time,
                completed_at=get_utc_now().isoformat(),
                total_tools_evaluated=13,
                executed_tools_count=0,
                live_validated_count=0,
                failed_tools_count=0,
                blocked_tools_count=13,
                tool_records=blocked_records,
                safety_audit_passed=True,
            )

        # Invariant 3: Destination Safety check (Anti-SSRF)
        is_safe, safety_reason = validate_destination_safety(f"https://{host}")
        if not is_safe:
            blocked_records = self._generate_blocked_records(
                target=target,
                campaign_id=campaign_id,
                status=ToolValidationStatus.BLOCKED_SAFETY,
                reason=f"Destination safety blocked target '{host}': {safety_reason}",
                execution_origin=execution_origin,
                pipeline_run_id=pipeline_run_id,
            )
            return Phase25ValidationSuiteResult(
                target=target,
                host=host,
                base_domain=base_domain,
                campaign_id=campaign_id,
                authorization_record_id=auth_rec_id,
                suite_status=ToolValidationStatus.BLOCKED_SAFETY.value,
                started_at=start_time,
                completed_at=get_utc_now().isoformat(),
                total_tools_evaluated=13,
                executed_tools_count=0,
                live_validated_count=0,
                failed_tools_count=0,
                blocked_tools_count=13,
                tool_records=blocked_records,
                safety_audit_passed=False,
            )

        # Invariant 4: ScopeValidator check
        scope_dec = scope_validator.validate_target(f"https://{host}")
        if not scope_dec.allowed:
            blocked_records = self._generate_blocked_records(
                target=target,
                campaign_id=campaign_id,
                status=ToolValidationStatus.BLOCKED_SCOPE,
                reason=f"Target '{host}' blocked by ScopeValidator: {scope_dec.reason}",
                execution_origin=execution_origin,
                pipeline_run_id=pipeline_run_id,
            )
            return Phase25ValidationSuiteResult(
                target=target,
                host=host,
                base_domain=base_domain,
                campaign_id=campaign_id,
                authorization_record_id=auth_rec_id,
                suite_status=ToolValidationStatus.BLOCKED_SCOPE.value,
                started_at=start_time,
                completed_at=get_utc_now().isoformat(),
                total_tools_evaluated=13,
                executed_tools_count=0,
                live_validated_count=0,
                failed_tools_count=0,
                blocked_tools_count=13,
                tool_records=blocked_records,
                safety_audit_passed=True,
            )

        # All Gates Passed: Proceed to Tool-by-Tool validation
        tool_records: Dict[str, ToolExecutionRecord] = {}
        all_normalized_assets: List[NormalizedReconAsset] = []
        all_evidence_hashes: List[str] = []
        provenance_map: Dict[str, List[str]] = {}

        # 1. Subfinder
        rec_subfinder = await self._validate_subfinder(
            base_domain=base_domain,
            target=target,
            campaign_id=campaign_id,
            auth_id=auth_rec_id,
            scope_validator=scope_validator,
            scope_hash=scope_snapshot_hash,
        )
        tool_records["subfinder"] = rec_subfinder
        self._ingest_tool_assets(rec_subfinder, all_normalized_assets, all_evidence_hashes, provenance_map)

        # 2. Sublist3r
        rec_sublist3r = self._validate_sublist3r(
            target=target,
            campaign_id=campaign_id,
            auth_id=auth_rec_id,
            scope_hash=scope_snapshot_hash,
        )
        tool_records["sublist3r"] = rec_sublist3r

        # 3. Amass
        rec_amass = await self._validate_amass(
            base_domain=base_domain,
            target=target,
            campaign_id=campaign_id,
            auth_id=auth_rec_id,
            scope_validator=scope_validator,
            scope_hash=scope_snapshot_hash,
        )
        tool_records["amass"] = rec_amass
        self._ingest_tool_assets(rec_amass, all_normalized_assets, all_evidence_hashes, provenance_map)

        # 4. Certificate Transparency (crt.sh)
        rec_ct = await self._validate_crtsh(
            base_domain=base_domain,
            target=target,
            campaign_id=campaign_id,
            auth_id=auth_rec_id,
            scope_validator=scope_validator,
            scope_hash=scope_snapshot_hash,
        )
        tool_records["crtsh"] = rec_ct
        self._ingest_tool_assets(rec_ct, all_normalized_assets, all_evidence_hashes, provenance_map)

        # 5. Wayback
        rec_wayback = await self._validate_wayback(
            base_domain=base_domain,
            target=target,
            campaign_id=campaign_id,
            auth_id=auth_rec_id,
            scope_validator=scope_validator,
            scope_hash=scope_snapshot_hash,
        )
        tool_records["wayback"] = rec_wayback
        self._ingest_tool_assets(rec_wayback, all_normalized_assets, all_evidence_hashes, provenance_map)

        # 6. GAU
        rec_gau = await self._validate_gau(
            base_domain=base_domain,
            target=target,
            campaign_id=campaign_id,
            auth_id=auth_rec_id,
            scope_validator=scope_validator,
            scope_hash=scope_snapshot_hash,
        )
        tool_records["gau"] = rec_gau
        self._ingest_tool_assets(rec_gau, all_normalized_assets, all_evidence_hashes, provenance_map)

        # 7. DNS Enumeration
        rec_dns = await self._validate_dns(
            base_domain=base_domain,
            target=target,
            campaign_id=campaign_id,
            auth_id=auth_rec_id,
            scope_validator=scope_validator,
            scope_hash=scope_snapshot_hash,
        )
        tool_records["dns_recon"] = rec_dns
        self._ingest_tool_assets(rec_dns, all_normalized_assets, all_evidence_hashes, provenance_map)

        # 8. HTTP / HTTPS Probing
        rec_http = await self._validate_http_probe(
            target=target,
            campaign_id=campaign_id,
            auth_id=auth_rec_id,
            scope_validator=scope_validator,
            scope_hash=scope_snapshot_hash,
        )
        tool_records["http_probe"] = rec_http
        self._ingest_tool_assets(rec_http, all_normalized_assets, all_evidence_hashes, provenance_map)

        # 9. WhatWeb
        rec_whatweb = await self._validate_whatweb(
            target=target,
            campaign_id=campaign_id,
            auth_id=auth_rec_id,
            scope_validator=scope_validator,
            scope_hash=scope_snapshot_hash,
        )
        tool_records["whatweb"] = rec_whatweb
        self._ingest_tool_assets(rec_whatweb, all_normalized_assets, all_evidence_hashes, provenance_map)

        # 10. Nmap
        rec_nmap = await self._validate_nmap(
            base_domain=base_domain,
            target=target,
            campaign_id=campaign_id,
            auth_id=auth_rec_id,
            allow_port_scan=allow_port_scan,
            scope_validator=scope_validator,
            scope_hash=scope_snapshot_hash,
        )
        tool_records["nmap"] = rec_nmap
        self._ingest_tool_assets(rec_nmap, all_normalized_assets, all_evidence_hashes, provenance_map)

        # 11. Gobuster
        rec_gobuster = await self._validate_gobuster(
            target=target,
            campaign_id=campaign_id,
            auth_id=auth_rec_id,
            allow_dir_scan=allow_dir_scan,
            scope_validator=scope_validator,
            scope_hash=scope_snapshot_hash,
        )
        tool_records["gobuster"] = rec_gobuster
        self._ingest_tool_assets(rec_gobuster, all_normalized_assets, all_evidence_hashes, provenance_map)

        # 12. Nuclei
        rec_nuclei = self._validate_nuclei(
            target=target,
            campaign_id=campaign_id,
            auth_id=auth_rec_id,
            scope_hash=scope_snapshot_hash,
        )
        tool_records["nuclei"] = rec_nuclei

        # 13. Dalfox
        rec_dalfox = self._validate_dalfox(
            target=target,
            campaign_id=campaign_id,
            auth_id=auth_rec_id,
            scope_hash=scope_snapshot_hash,
        )
        tool_records["dalfox"] = rec_dalfox

        # Add root seed target asset
        root_scope_dec = scope_validator.validate_target(target)
        root_asset = NormalizedReconAsset(
            asset_id=str(uuid.uuid4()),
            raw_value=target,
            normalized_value=host,
            asset_type="DOMAIN",
            source_provider="seed_target",
            status=ReconAssetStatus.IN_SCOPE if root_scope_dec.allowed else ReconAssetStatus.BLOCKED_SCOPE,
            is_executable=False,
            metadata={"scope_decision": root_scope_dec.reason},
            evidence_hash=hashlib.sha256(target.encode("utf-8")).hexdigest(),
        )
        all_normalized_assets.insert(0, root_asset)
        provenance_map[host] = ["seed_target"]

        # Deduplicate assets
        deduped_assets = self._deduplicate_assets(all_normalized_assets, provenance_map)

        # Attack Surface Graph Integration
        graph_dict = None
        try:
            nodes = []
            target_node = AttackSurfaceGraphEngine.add_target(
                campaign_id=campaign_id,
                target=target,
                source="PHASE25_RECON_VALIDATION",
                db=db_session,
            )
            nodes.append(target_node)
            for a in deduped_assets:
                if a.asset_type in ("ENDPOINT", "SERVICE"):
                    ep_node = AttackSurfaceGraphEngine.add_endpoint(
                        campaign_id=campaign_id,
                        target=target,
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
            logger.debug(f"Attack surface graph update in validation suite skipped: {e}")

        # Update snapshot contribution counts and enforce pipeline-only certification
        for tool_id, rec in tool_records.items():
            rec.execution_origin = execution_origin
            rec.pipeline_run_id = pipeline_run_id
            contrib = sum(1 for a in deduped_assets if a.source_provider == tool_id)
            rec.snapshot_contribution_count = contrib
            if rec.status == ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED and contrib > 0:
                # Mandatory Certification Gate: Pipeline-Only Provenance
                if rec.execution_origin != ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE:
                    rec.record_event(
                        ReconLifecycleEvent.RECON_TOOL_FAILED,
                        f"Disqualified from LIVE_VALIDATED: execution_origin is '{rec.execution_origin.value if hasattr(rec.execution_origin, 'value') else rec.execution_origin}' (requires PHASE27_CONTROLLED_PIPELINE)",
                    )
                    continue

                if not rec.pipeline_run_id:
                    rec.record_event(
                        ReconLifecycleEvent.RECON_TOOL_FAILED,
                        "Disqualified from LIVE_VALIDATED: pipeline_run_id is missing",
                    )
                    continue

                if not rec.evidence_id:
                    rec.record_event(
                        ReconLifecycleEvent.RECON_TOOL_FAILED,
                        "Disqualified from LIVE_VALIDATED: evidence_id is missing",
                    )
                    continue

                if not rec.authorization_record_id or rec.authorization_record_id != auth_rec_id:
                    rec.record_event(
                        ReconLifecycleEvent.RECON_TOOL_FAILED,
                        "Disqualified from LIVE_VALIDATED: authorization_record_id mismatch",
                    )
                    continue

                if not rec.campaign_id or rec.campaign_id != campaign_id:
                    rec.record_event(
                        ReconLifecycleEvent.RECON_TOOL_FAILED,
                        "Disqualified from LIVE_VALIDATED: campaign_id mismatch",
                    )
                    continue

                if rec.target != target:
                    rec.record_event(
                        ReconLifecycleEvent.RECON_TOOL_FAILED,
                        "Disqualified from LIVE_VALIDATED: target mismatch",
                    )
                    continue

                if scope_snapshot_hash and rec.scope_snapshot_hash != scope_snapshot_hash:
                    rec.record_event(
                        ReconLifecycleEvent.RECON_TOOL_FAILED,
                        "Disqualified from LIVE_VALIDATED: scope_snapshot_hash mismatch",
                    )
                    continue

                rec.status = ToolValidationStatus.LIVE_VALIDATED
                rec.record_event(ReconLifecycleEvent.RECON_TOOL_INTEGRATED, f"Contributed {contrib} assets to ReconSnapshot and AttackSurfaceGraph")

        # Create Canonical ReconSnapshot
        snapshot = CanonicalReconSnapshot.create(
            snapshot_id=str(uuid.uuid4()),
            campaign_id=campaign_id,
            concrete_target=target,
            execution_mode=ReconExecutionMode.AUTHORIZED_LIVE_RECON,
            selected_providers=list(tool_records.keys()),
            provider_statuses={k: v.status.value for k, v in tool_records.items()},
            normalized_assets=deduped_assets,
            authorization_reference=auth_rec_id,
            authorization_timestamp=start_time,
            evidence_hashes=all_evidence_hashes,
            graph_snapshot=graph_dict,
            provenance=provenance_map,
            created_at=start_time,
            completed_at=get_utc_now().isoformat(),
        )

        completed_time = get_utc_now().isoformat()
        live_val_count = sum(1 for r in tool_records.values() if r.status == ToolValidationStatus.LIVE_VALIDATED)
        failed_count = sum(1 for r in tool_records.values() if r.status in (
            ToolValidationStatus.EXECUTION_FAILED,
            ToolValidationStatus.BINARY_UNAVAILABLE,
            ToolValidationStatus.TIMEOUT,
            ToolValidationStatus.OUTPUT_INVALID,
            ToolValidationStatus.PARSE_FAILED,
            ToolValidationStatus.NORMALIZATION_FAILED,
            ToolValidationStatus.EVIDENCE_PERSISTENCE_FAILED,
        ))
        blocked_count = sum(1 for r in tool_records.values() if r.status in (
            ToolValidationStatus.BLOCKED_AUTHORIZATION,
            ToolValidationStatus.BLOCKED_SCOPE,
            ToolValidationStatus.BLOCKED_POLICY,
            ToolValidationStatus.BLOCKED_SAFETY,
            ToolValidationStatus.BLOCKED_BUDGET,
            ToolValidationStatus.NOT_IMPLEMENTED,
            ToolValidationStatus.STUB_ONLY,
            ToolValidationStatus.NOT_SELECTED,
            ToolValidationStatus.NOT_SELECTED_RECON_ONLY,
        ))
        exec_count = sum(1 for r in tool_records.values() if r.exit_code is not None or r.status == ToolValidationStatus.LIVE_VALIDATED)

        return Phase25ValidationSuiteResult(
            target=target,
            host=host,
            base_domain=base_domain,
            campaign_id=campaign_id,
            authorization_record_id=auth_rec_id,
            suite_status="VALIDATION_COMPLETE",
            started_at=start_time,
            completed_at=completed_time,
            total_tools_evaluated=len(tool_records),
            executed_tools_count=exec_count,
            live_validated_count=live_val_count,
            failed_tools_count=failed_count,
            blocked_tools_count=blocked_count,
            tool_records=tool_records,
            recon_snapshot=snapshot,
            attack_surface_graph=graph_dict,
            cross_tool_correlation={
                "total_raw_assets": len(all_normalized_assets),
                "total_deduplicated_assets": len(deduped_assets),
                "provenance_keys_tracked": len(provenance_map),
                "evidence_hashes_collected": len(set(all_evidence_hashes)),
            },
            safety_audit_passed=True,
        )

    # --------------------------------------------------------------------------
    # Individual Tool Validators
    # --------------------------------------------------------------------------

    async def _validate_subfinder(
        self,
        base_domain: str,
        target: str,
        campaign_id: str,
        auth_id: Optional[str],
        scope_validator: ScopeValidator,
        scope_hash: Optional[str],
    ) -> ToolExecutionRecord:
        rec = ToolExecutionRecord(
            tool_name="subfinder",
            campaign_id=campaign_id,
            authorization_record_id=auth_id,
            target=target,
            scope_snapshot_hash=scope_hash,
            arguments=["-d", base_domain, "-silent"],
        )
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_STARTED)

        # Check binary presence via ReconToolAvailability
        binary_path = self.tool_availability.resolve_binary_path("subfinder")
        if not binary_path:
            rec.completed_at = get_utc_now().isoformat()
            rec.status = ToolValidationStatus.BINARY_UNAVAILABLE
            rec.failure_reason = "Executable 'subfinder' not found on system PATH or configured tools directory."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        req = ToolExecutionRequest(
            campaign_id=campaign_id,
            target=target,
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            args=["-d", base_domain, "-silent"],
            authorization_confirmed=True,
            custom_executable_path=binary_path,
            execution_mode="AUTHORIZED_LIVE_RECON",
        )
        res = await self.tool_boundary.execute(req)
        rec.completed_at = get_utc_now().isoformat()
        rec.duration_ms = res.duration_ms
        rec.exit_code = res.exit_code
        rec.stdout_hash = res.stdout_hash
        rec.stderr_hash = res.stderr_hash
        rec.evidence_id = res.output_hash
        rec.raw_output = res.stdout

        if res.execution_status == ToolExecutionStatus.TIMEOUT.value:
            rec.status = ToolValidationStatus.TIMEOUT
            rec.failure_reason = "Subfinder execution timed out."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        if res.execution_status != ToolExecutionStatus.SUCCESS.value:
            rec.status = ToolValidationStatus.EXECUTION_FAILED
            rec.failure_reason = res.error_category or res.stderr or "Subfinder execution returned non-zero status."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        rec.record_event(ReconLifecycleEvent.RECON_TOOL_EXECUTED)
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_CAPTURED)

        try:
            raw_lines = [line.strip() for line in (res.stdout or "").splitlines() if line.strip()]
            rec.raw_output_size = len(res.stdout or "")
            rec.parsed_result_count = len(raw_lines)
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_PARSED, f"Parsed {len(raw_lines)} lines")
        except Exception as e:
            rec.status = ToolValidationStatus.PARSE_FAILED
            rec.failure_reason = f"Failed to parse Subfinder output: {e}"
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        norm_assets = []
        for line in raw_lines:
            try:
                norm_sub = normalize_domain(line)
            except Exception:
                continue
            norm_assets.append({
                "source": "subfinder",
                "source_execution_id": rec.execution_id,
                "asset": norm_sub,
                "type": "subdomain",
                "authorization_status": "DISCOVERED_NOT_AUTHORIZED",
                "is_executable": False,
                "evidence_hash": res.stdout_hash,
            })

        rec.normalized_assets = norm_assets
        rec.normalized_result_count = len(norm_assets)
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_RESULTS_NORMALIZED)

        if len(norm_assets) == 0:
            rec.status = ToolValidationStatus.EXECUTED_ZERO_RESULTS
        else:
            rec.status = ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED

        return rec

    def _validate_sublist3r(
        self,
        target: str,
        campaign_id: str,
        auth_id: Optional[str],
        scope_hash: Optional[str],
    ) -> ToolExecutionRecord:
        rec = ToolExecutionRecord(
            tool_name="sublist3r",
            campaign_id=campaign_id,
            authorization_record_id=auth_id,
            target=target,
            scope_snapshot_hash=scope_hash,
            status=ToolValidationStatus.STUB_ONLY,
            failure_reason="STUB_ONLY / PRODUCTION_CAPABILITY_NOT_IMPLEMENTED — Sublist3r is not part of the current AihaX recon implementation and was intentionally not executed.",
            completed_at=get_utc_now().isoformat(),
        )
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_BLOCKED, "SUBLIST3R_NOT_IMPLEMENTED: STUB_ONLY / PRODUCTION_CAPABILITY_NOT_IMPLEMENTED")
        return rec

    async def _validate_amass(
        self,
        base_domain: str,
        target: str,
        campaign_id: str,
        auth_id: Optional[str],
        scope_validator: ScopeValidator,
        scope_hash: Optional[str],
        custom_args: Optional[List[str]] = None,
    ) -> ToolExecutionRecord:
        amass_args = custom_args or ["enum", "-passive", "-d", base_domain, "-timeout", "1"]
        rec = ToolExecutionRecord(
            tool_name="amass",
            campaign_id=campaign_id,
            authorization_record_id=auth_id,
            target=target,
            scope_snapshot_hash=scope_hash,
            arguments=list(amass_args),
        )
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_STARTED)

        # Invariant (Phase 26 Section 3, 14): Amass passive / low-impact mode only.
        # Explicitly reject active enumeration, brute forcing, intrusive flags.
        prohibited_amass_exact_flags = {
            "-active", "-brute", "-ip", "-src", "-dir", "-p",
            "-rf", "-bl", "-demo", "-include", "-exclude"
        }
        for arg in amass_args:
            arg_lower = arg.lower().strip()
            if arg_lower in prohibited_amass_exact_flags or arg_lower.startswith("-brute") or arg_lower.startswith("-active"):
                rec.completed_at = get_utc_now().isoformat()
                rec.status = ToolValidationStatus.BLOCKED_POLICY
                rec.failure_reason = (
                    f"Unsafe Amass argument rejected: '{arg}'. "
                    "Phase 26 policy restricts Amass strictly to passive/low-impact mode ('enum -passive -d <domain>')."
                )
                rec.record_event(ReconLifecycleEvent.RECON_TOOL_BLOCKED, rec.failure_reason)
                return rec

        if "-passive" not in amass_args or "enum" not in amass_args:
            rec.completed_at = get_utc_now().isoformat()
            rec.status = ToolValidationStatus.BLOCKED_POLICY
            rec.failure_reason = "Amass invocation must explicitly specify 'enum' and '-passive'."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_BLOCKED, rec.failure_reason)
            return rec

        binary_path = self.tool_availability.resolve_binary_path("amass")
        if not binary_path:
            rec.completed_at = get_utc_now().isoformat()
            rec.status = ToolValidationStatus.BINARY_UNAVAILABLE
            rec.failure_reason = "Executable 'amass' not found on system PATH or configured tools directory."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        req = ToolExecutionRequest(
            campaign_id=campaign_id,
            target=target,
            tool_name="amass",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            args=amass_args,
            authorization_confirmed=True,
            custom_executable_path=binary_path,
            execution_mode="AUTHORIZED_LIVE_RECON",
            timeout_seconds=240,
        )
        res = await self.tool_boundary.execute(req)
        rec.completed_at = get_utc_now().isoformat()
        rec.duration_ms = res.duration_ms
        rec.exit_code = res.exit_code
        rec.stdout_hash = res.stdout_hash
        rec.stderr_hash = res.stderr_hash
        rec.evidence_id = res.output_hash
        rec.raw_output = res.stdout

        if res.execution_status == ToolExecutionStatus.TIMEOUT.value:
            rec.status = ToolValidationStatus.TIMEOUT
            rec.failure_reason = "Amass execution timed out."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        if res.execution_status != ToolExecutionStatus.SUCCESS.value:
            rec.status = ToolValidationStatus.EXECUTION_FAILED
            rec.failure_reason = res.error_category or res.stderr or "Amass execution failed."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        rec.record_event(ReconLifecycleEvent.RECON_TOOL_EXECUTED)
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_CAPTURED)

        raw_lines = [line.strip() for line in (res.stdout or "").splitlines() if line.strip() and not line.startswith("[")]
        rec.raw_output_size = len(res.stdout or "")
        rec.parsed_result_count = len(raw_lines)
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_PARSED, f"Parsed {len(raw_lines)} lines")

        norm_assets = []
        for line in raw_lines:
            try:
                norm_sub = normalize_domain(line)
            except Exception:
                continue
            norm_assets.append({
                "source": "amass",
                "source_execution_id": rec.execution_id,
                "asset": norm_sub,
                "type": "subdomain",
                "authorization_status": "DISCOVERED_NOT_AUTHORIZED",
                "is_executable": False,
                "evidence_hash": res.stdout_hash,
            })

        rec.normalized_assets = norm_assets
        rec.normalized_result_count = len(norm_assets)
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_RESULTS_NORMALIZED)

        if len(norm_assets) == 0:
            rec.status = ToolValidationStatus.EXECUTED_ZERO_RESULTS
        else:
            rec.status = ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED

        return rec

    async def _validate_crtsh(
        self,
        base_domain: str,
        target: str,
        campaign_id: str,
        auth_id: Optional[str],
        scope_validator: ScopeValidator,
        scope_hash: Optional[str],
    ) -> ToolExecutionRecord:
        rec = ToolExecutionRecord(
            tool_name="crtsh",
            campaign_id=campaign_id,
            authorization_record_id=auth_id,
            target=target,
            scope_snapshot_hash=scope_hash,
            arguments=[f"https://crt.sh/?q=%.{base_domain}&output=json"],
        )
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_STARTED)

        req_engine = self.request_engine or RequestEngine(scope_validator=scope_validator)
        crt_provider = CRTShProvider()
        t0 = asyncio.get_event_loop().time()

        try:
            discovered = await crt_provider.discover(base_domain, request_engine=req_engine)
            rec.duration_ms = (asyncio.get_event_loop().time() - t0) * 1000.0
            rec.completed_at = get_utc_now().isoformat()
            rec.exit_code = 0
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_EXECUTED)
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_CAPTURED)

            norm_assets = []
            for item in discovered:
                norm_assets.append({
                    "source": "crtsh",
                    "source_execution_id": rec.execution_id,
                    "asset": item.normalized_value,
                    "type": "subdomain",
                    "authorization_status": "DISCOVERED_NOT_AUTHORIZED",
                    "evidence_hash": item.evidence_id,
                })

            rec.parsed_result_count = len(discovered)
            rec.normalized_result_count = len(norm_assets)
            rec.normalized_assets = norm_assets
            rec.stdout_hash = hashlib.sha256(json.dumps([a["asset"] for a in norm_assets], sort_keys=True).encode("utf-8")).hexdigest()
            rec.evidence_id = rec.stdout_hash
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_PARSED)
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_RESULTS_NORMALIZED)

            if len(norm_assets) == 0:
                rec.status = ToolValidationStatus.EXECUTED_ZERO_RESULTS
            else:
                rec.status = ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED

            return rec
        except Exception as e:
            rec.completed_at = get_utc_now().isoformat()
            rec.duration_ms = (asyncio.get_event_loop().time() - t0) * 1000.0
            rec.status = ToolValidationStatus.EXECUTION_FAILED
            rec.failure_reason = f"crt.sh query failed: {str(e)}"
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

    async def _validate_wayback(
        self,
        base_domain: str,
        target: str,
        campaign_id: str,
        auth_id: Optional[str],
        scope_validator: ScopeValidator,
        scope_hash: Optional[str],
    ) -> ToolExecutionRecord:
        rec = ToolExecutionRecord(
            tool_name="wayback",
            campaign_id=campaign_id,
            authorization_record_id=auth_id,
            target=target,
            scope_snapshot_hash=scope_hash,
            arguments=[f"https://web.archive.org/cdx/search/cdx?url=*.{base_domain}/*&output=json"],
        )
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_STARTED)

        req_engine = self.request_engine or RequestEngine(scope_validator=scope_validator)
        wayback_provider = WaybackProvider()
        t0 = asyncio.get_event_loop().time()

        try:
            discovered = await wayback_provider.discover(base_domain, request_engine=req_engine)
            rec.duration_ms = (asyncio.get_event_loop().time() - t0) * 1000.0
            rec.completed_at = get_utc_now().isoformat()
            rec.exit_code = 0
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_EXECUTED)
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_CAPTURED)

            norm_assets = []
            for item in discovered:
                norm_assets.append({
                    "source": "wayback",
                    "source_execution_id": rec.execution_id,
                    "asset": item.normalized_value,
                    "type": "endpoint",
                    "authorization_status": "DISCOVERED_NOT_AUTHORIZED",
                    "evidence_hash": item.evidence_id,
                })

            rec.parsed_result_count = len(discovered)
            rec.normalized_result_count = len(norm_assets)
            rec.normalized_assets = norm_assets
            rec.stdout_hash = hashlib.sha256(json.dumps([a["asset"] for a in norm_assets], sort_keys=True).encode("utf-8")).hexdigest()
            rec.evidence_id = rec.stdout_hash
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_PARSED)
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_RESULTS_NORMALIZED)

            if len(norm_assets) == 0:
                rec.status = ToolValidationStatus.EXECUTED_ZERO_RESULTS
            else:
                rec.status = ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED

            return rec
        except Exception as e:
            rec.completed_at = get_utc_now().isoformat()
            rec.duration_ms = (asyncio.get_event_loop().time() - t0) * 1000.0
            rec.status = ToolValidationStatus.EXECUTION_FAILED
            rec.failure_reason = f"Wayback CDX query failed: {str(e)}"
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

    async def _validate_gau(
        self,
        base_domain: str,
        target: str,
        campaign_id: str,
        auth_id: Optional[str],
        scope_validator: ScopeValidator,
        scope_hash: Optional[str],
        custom_args: Optional[List[str]] = None,
    ) -> ToolExecutionRecord:
        gau_args = custom_args or ["--subs", "--threads", "4", "--providers", "wayback", base_domain]
        rec = ToolExecutionRecord(
            tool_name="gau",
            campaign_id=campaign_id,
            authorization_record_id=auth_id,
            target=target,
            scope_snapshot_hash=scope_hash,
            arguments=list(gau_args),
        )
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_STARTED)

        binary_path = self.tool_availability.resolve_binary_path("gau")
        if not binary_path:
            rec.completed_at = get_utc_now().isoformat()
            rec.status = ToolValidationStatus.BINARY_UNAVAILABLE
            rec.failure_reason = "Executable 'gau' not found on system PATH or configured tools directory."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        req = ToolExecutionRequest(
            campaign_id=campaign_id,
            target=target,
            tool_name="gau",
            execution_profile=ExecutionProfile.URL_DISCOVERY.value,
            args=gau_args,
            authorization_confirmed=True,
            custom_executable_path=binary_path,
            execution_mode="AUTHORIZED_LIVE_RECON",
            timeout_seconds=150,
        )
        res = await self.tool_boundary.execute(req)
        rec.completed_at = get_utc_now().isoformat()
        rec.duration_ms = res.duration_ms
        rec.exit_code = res.exit_code
        rec.stdout_hash = res.stdout_hash
        rec.stderr_hash = res.stderr_hash
        rec.evidence_id = res.output_hash
        rec.raw_output = res.stdout

        if res.execution_status == ToolExecutionStatus.TIMEOUT.value:
            rec.status = ToolValidationStatus.TIMEOUT
            rec.failure_reason = "GAU execution timed out."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        if res.execution_status != ToolExecutionStatus.SUCCESS.value:
            rec.status = ToolValidationStatus.EXECUTION_FAILED
            rec.failure_reason = res.error_category or res.stderr or "GAU execution failed."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        rec.record_event(ReconLifecycleEvent.RECON_TOOL_EXECUTED)
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_CAPTURED)

        try:
            raw_lines = [line.strip() for line in (res.stdout or "").splitlines() if line.strip()]
            rec.raw_output_size = len(res.stdout or "")
            rec.parsed_result_count = len(raw_lines)
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_PARSED, f"Parsed {len(raw_lines)} URLs")
        except Exception as e:
            rec.status = ToolValidationStatus.PARSE_FAILED
            rec.failure_reason = f"Failed to parse GAU output: {e}"
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        norm_assets = []
        for line in raw_lines:
            try:
                norm_u = normalize_url(line)
            except Exception:
                continue

            # Phase 26 Section 4, 15: Discovered URLs outside campaign scope must be recorded as DISCOVERED_OUT_OF_SCOPE
            scope_dec = scope_validator.validate_target(norm_u)
            if scope_dec.allowed:
                auth_status = "DISCOVERED_NOT_AUTHORIZED"
                scope_status = "IN_SCOPE"
            else:
                auth_status = "DISCOVERED_OUT_OF_SCOPE"
                scope_status = "OUT_OF_SCOPE"

            norm_assets.append({
                "source": "gau",
                "source_execution_id": rec.execution_id,
                "asset": norm_u,
                "type": "endpoint",
                "authorization_status": auth_status,
                "scope_status": scope_status,
                "is_executable": False,  # Strict invariant: never executable automatically
                "evidence_hash": res.stdout_hash,
            })

        rec.normalized_assets = norm_assets
        rec.normalized_result_count = len(norm_assets)
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_RESULTS_NORMALIZED)

        if len(norm_assets) == 0:
            rec.status = ToolValidationStatus.EXECUTED_ZERO_RESULTS
        else:
            rec.status = ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED

        return rec

    async def _validate_dns(
        self,
        base_domain: str,
        target: str,
        campaign_id: str,
        auth_id: Optional[str],
        scope_validator: ScopeValidator,
        scope_hash: Optional[str],
    ) -> ToolExecutionRecord:
        rec = ToolExecutionRecord(
            tool_name="dns_recon",
            campaign_id=campaign_id,
            authorization_record_id=auth_id,
            target=target,
            scope_snapshot_hash=scope_hash,
            arguments=["record_types=A,AAAA,CNAME,MX,NS,TXT,SOA"],
        )
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_STARTED)

        t0 = asyncio.get_event_loop().time()
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
        resolved: Dict[str, List[str]] = {}

        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5.0
            resolver.lifetime = 10.0

            for rtype in record_types:
                try:
                    answers = resolver.resolve(base_domain, rtype)
                    vals = [str(r.to_text()).strip('"') for r in answers]
                    if vals:
                        resolved[rtype] = vals
                except Exception:
                    pass

            rec.duration_ms = (asyncio.get_event_loop().time() - t0) * 1000.0
            rec.completed_at = get_utc_now().isoformat()
            rec.exit_code = 0
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_EXECUTED)
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_CAPTURED)

            norm_assets = []
            for rtype, vals in resolved.items():
                for val in vals:
                    norm_assets.append({
                        "source": "dns_recon",
                        "source_execution_id": rec.execution_id,
                        "asset": f"{base_domain}:{rtype}:{val.strip().lower()}",
                        "type": "ip_address" if rtype in ("A", "AAAA") else "dns_record",
                        "authorization_status": "DISCOVERED_NOT_AUTHORIZED",
                        "evidence_hash": hashlib.sha256(f"{rtype}:{val}".encode("utf-8")).hexdigest(),
                    })

            rec.raw_output = json.dumps(resolved)
            rec.raw_output_size = len(rec.raw_output)
            rec.parsed_result_count = sum(len(v) for v in resolved.values())
            rec.normalized_result_count = len(norm_assets)
            rec.normalized_assets = norm_assets
            rec.stdout_hash = hashlib.sha256(rec.raw_output.encode("utf-8")).hexdigest()
            rec.evidence_id = rec.stdout_hash
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_PARSED)
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_RESULTS_NORMALIZED)

            if len(norm_assets) == 0:
                rec.status = ToolValidationStatus.EXECUTED_ZERO_RESULTS
            else:
                rec.status = ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED

            return rec
        except Exception as e:
            rec.completed_at = get_utc_now().isoformat()
            rec.duration_ms = (asyncio.get_event_loop().time() - t0) * 1000.0
            rec.status = ToolValidationStatus.EXECUTION_FAILED
            rec.failure_reason = f"DNS resolution failed: {str(e)}"
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

    async def _validate_http_probe(
        self,
        target: str,
        campaign_id: str,
        auth_id: Optional[str],
        scope_validator: ScopeValidator,
        scope_hash: Optional[str],
    ) -> ToolExecutionRecord:
        rec = ToolExecutionRecord(
            tool_name="http_probe",
            campaign_id=campaign_id,
            authorization_record_id=auth_id,
            target=target,
            scope_snapshot_hash=scope_hash,
            arguments=["GET", target, "max_requests=10", "rate_limit_rps=2.0"],
        )
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_STARTED)

        t0 = asyncio.get_event_loop().time()
        url = target if "://" in target else f"https://{target}"

        # Destination safety check
        is_safe, reason = validate_destination_safety(url)
        if not is_safe:
            rec.completed_at = get_utc_now().isoformat()
            rec.status = ToolValidationStatus.BLOCKED_SAFETY
            rec.failure_reason = f"Destination safety blocked probe: {reason}"
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_BLOCKED, rec.failure_reason)
            return rec

        req_engine = self.request_engine or RequestEngine(
            scope_validator=scope_validator,
            rate_limit_rps=2.0,
        )
        probe_engine = HttpProbeEngine(request_engine=req_engine, scope_validator=scope_validator)
        parsed = urlparse(url)

        try:
            discovered_asset = DiscoveredAsset(
                asset_id=str(uuid.uuid4()),
                raw_asset=url,
                canonical_url=url,
                hostname=parsed.hostname or target,
                scheme=parsed.scheme,
                port=parsed.port or (443 if parsed.scheme == "https" else 80),
                path=parsed.path or "/",
                asset_type="WEB_APPLICATION",
                source=DiscoverySource.USER_INPUT,
                scope_status="IN_SCOPE",
            )
            probe_res = await probe_engine.probe_asset(discovered_asset)
            rec.duration_ms = (asyncio.get_event_loop().time() - t0) * 1000.0
            rec.completed_at = get_utc_now().isoformat()
            rec.exit_code = 0
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_EXECUTED)
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_CAPTURED)

            norm_assets = [{
                "source": "http_probe",
                "source_execution_id": rec.execution_id,
                "asset": url,
                "type": "service",
                "authorization_status": "DISCOVERED_NOT_AUTHORIZED",
                "status_code": probe_res.status_code,
                "server": probe_res.server_banner,
                "title": probe_res.title,
                "evidence_hash": hashlib.sha256(f"{probe_res.status_code}:{probe_res.title}".encode("utf-8")).hexdigest(),
            }]

            rec.raw_output = json.dumps({
                "status_code": probe_res.status_code,
                "headers": probe_res.headers,
                "server": probe_res.server_banner,
                "title": probe_res.title,
                "redirect_chain": probe_res.redirect_chain,
            })
            rec.raw_output_size = len(rec.raw_output)
            rec.parsed_result_count = 1
            rec.normalized_result_count = 1
            rec.normalized_assets = norm_assets
            rec.stdout_hash = hashlib.sha256(rec.raw_output.encode("utf-8")).hexdigest()
            rec.evidence_id = rec.stdout_hash
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_PARSED)
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_RESULTS_NORMALIZED)
            rec.status = ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED
            return rec
        except Exception as e:
            rec.completed_at = get_utc_now().isoformat()
            rec.duration_ms = (asyncio.get_event_loop().time() - t0) * 1000.0
            rec.status = ToolValidationStatus.EXECUTION_FAILED
            rec.failure_reason = f"HTTP probe failed: {str(e)}"
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

    async def _validate_whatweb(
        self,
        target: str,
        campaign_id: str,
        auth_id: Optional[str],
        scope_validator: ScopeValidator,
        scope_hash: Optional[str],
        custom_args: Optional[List[str]] = None,
    ) -> ToolExecutionRecord:
        whatweb_args = custom_args or ["--log-json", "-", "--quiet", target]
        rec = ToolExecutionRecord(
            tool_name="whatweb",
            campaign_id=campaign_id,
            authorization_record_id=auth_id,
            target=target,
            scope_snapshot_hash=scope_hash,
            arguments=list(whatweb_args),
        )
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_STARTED)

        # Phase 26 Section 5, 16: WhatWeb low impact, read-only, non-aggressive
        for arg in whatweb_args:
            arg_lower = arg.lower()
            if arg_lower in ("-a 3", "-a 4", "-a", "3", "4") or "--aggression" in arg_lower:
                rec.completed_at = get_utc_now().isoformat()
                rec.status = ToolValidationStatus.BLOCKED_POLICY
                rec.failure_reason = "Aggressive WhatWeb scanning modes are forbidden. Only read-only fingerprinting is permitted."
                rec.record_event(ReconLifecycleEvent.RECON_TOOL_BLOCKED, rec.failure_reason)
                return rec

        binary_path = self.tool_availability.resolve_binary_path("whatweb")
        if not binary_path:
            rec.completed_at = get_utc_now().isoformat()
            rec.status = ToolValidationStatus.BINARY_UNAVAILABLE
            rec.failure_reason = "Executable 'whatweb' not found on system PATH or configured tools directory."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        req = ToolExecutionRequest(
            campaign_id=campaign_id,
            target=target,
            tool_name="whatweb",
            execution_profile=ExecutionProfile.TECHNOLOGY_FINGERPRINTING.value,
            args=whatweb_args,
            authorization_confirmed=True,
            custom_executable_path=binary_path,
            execution_mode="AUTHORIZED_LIVE_RECON",
        )
        res = await self.tool_boundary.execute(req)
        rec.completed_at = get_utc_now().isoformat()
        rec.duration_ms = res.duration_ms
        rec.exit_code = res.exit_code
        rec.stdout_hash = res.stdout_hash
        rec.stderr_hash = res.stderr_hash
        rec.evidence_id = res.output_hash
        rec.raw_output = res.stdout

        if res.execution_status == ToolExecutionStatus.TIMEOUT.value:
            rec.status = ToolValidationStatus.TIMEOUT
            rec.failure_reason = "WhatWeb execution timed out."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        if res.execution_status != ToolExecutionStatus.SUCCESS.value:
            rec.status = ToolValidationStatus.EXECUTION_FAILED
            rec.failure_reason = res.error_category or res.stderr or "WhatWeb execution failed."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        rec.record_event(ReconLifecycleEvent.RECON_TOOL_EXECUTED)
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_CAPTURED)

        try:
            raw = (res.stdout or "").strip()
            data = []
            if raw.startswith("[") and raw.endswith("]"):
                data = json.loads(raw)
            else:
                m = re.search(r"(\[.*\])", raw, re.DOTALL)
                if m:
                    data = json.loads(m.group(1))
                else:
                    data = json.loads(raw)
        except Exception as e:
            rec.status = ToolValidationStatus.PARSE_FAILED
            rec.failure_reason = f"Failed to parse WhatWeb JSON output: {str(e)}"
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        rec.parsed_result_count = len(data) if isinstance(data, list) else 1
        norm_assets = []
        if isinstance(data, list):
            for entry in data:
                plugins = entry.get("plugins", {})
                for tech_name, tech_meta in plugins.items():
                    norm_assets.append({
                        "source": "whatweb",
                        "source_execution_id": rec.execution_id,
                        "asset": f"{target}:{tech_name.lower()}",
                        "type": "technology",
                        "authorization_status": "DISCOVERED_NOT_AUTHORIZED",
                        "is_executable": False,
                        "evidence_hash": res.stdout_hash,
                    })
        rec.normalized_assets = norm_assets
        rec.normalized_result_count = len(norm_assets)
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_RESULTS_NORMALIZED)
        rec.status = ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED if norm_assets else ToolValidationStatus.EXECUTED_ZERO_RESULTS
        return rec

    async def _validate_nmap(
        self,
        base_domain: str,
        target: str,
        campaign_id: str,
        auth_id: Optional[str],
        allow_port_scan: bool,
        scope_validator: ScopeValidator,
        scope_hash: Optional[str],
    ) -> ToolExecutionRecord:
        rec = ToolExecutionRecord(
            tool_name="nmap",
            campaign_id=campaign_id,
            authorization_record_id=auth_id,
            target=target,
            scope_snapshot_hash=scope_hash,
            arguments=["-sT", "-T4", "--open", base_domain],
        )

        # Invariant: Port scanning requires explicit program authorization
        if not allow_port_scan:
            rec.completed_at = get_utc_now().isoformat()
            rec.status = ToolValidationStatus.BLOCKED_POLICY
            rec.failure_reason = "Port scanning is not explicitly authorized under program policy for this validation gate."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_BLOCKED, rec.failure_reason)
            return rec

        rec.record_event(ReconLifecycleEvent.RECON_TOOL_STARTED)
        binary_path = self.tool_availability.resolve_binary_path("nmap")
        if not binary_path:
            rec.completed_at = get_utc_now().isoformat()
            rec.status = ToolValidationStatus.BINARY_UNAVAILABLE
            rec.failure_reason = "Executable 'nmap' not found on system PATH or configured tools directory."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        req = ToolExecutionRequest(
            campaign_id=campaign_id,
            target=target,
            tool_name="nmap",
            execution_profile=ExecutionProfile.PORT_SERVICE_DISCOVERY.value,
            args=["-sT", "-T4", "--open", base_domain],
            authorization_confirmed=True,
            custom_executable_path=binary_path,
            execution_mode="AUTHORIZED_LIVE_RECON",
        )
        res = await self.tool_boundary.execute(req)
        rec.completed_at = get_utc_now().isoformat()
        rec.duration_ms = res.duration_ms
        rec.exit_code = res.exit_code
        rec.stdout_hash = res.stdout_hash
        rec.stderr_hash = res.stderr_hash
        rec.evidence_id = res.output_hash
        rec.raw_output = res.stdout

        if res.execution_status == ToolExecutionStatus.TIMEOUT.value:
            rec.status = ToolValidationStatus.TIMEOUT
            rec.failure_reason = "Nmap execution timed out."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        if res.execution_status != ToolExecutionStatus.SUCCESS.value:
            rec.status = ToolValidationStatus.EXECUTION_FAILED
            rec.failure_reason = res.error_category or res.stderr or "Nmap execution failed."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        rec.record_event(ReconLifecycleEvent.RECON_TOOL_EXECUTED)
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_CAPTURED)

        # Parse ports
        ports_found = re.findall(r"(\d+)/(tcp|udp)\s+open\s+(\S+)", res.stdout or "")
        rec.parsed_result_count = len(ports_found)
        norm_assets = []
        for port, proto, svc in ports_found:
            norm_assets.append({
                "source": "nmap",
                "source_execution_id": rec.execution_id,
                "asset": f"{base_domain}:{port}/{proto}",
                "type": "service",
                "authorization_status": "DISCOVERED_NOT_AUTHORIZED",
                "is_executable": False,
                "evidence_hash": res.stdout_hash,
            })

        rec.normalized_assets = norm_assets
        rec.normalized_result_count = len(norm_assets)
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_RESULTS_NORMALIZED)
        rec.status = ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED if norm_assets else ToolValidationStatus.EXECUTED_ZERO_RESULTS
        return rec

    async def _validate_gobuster(
        self,
        target: str,
        campaign_id: str,
        auth_id: Optional[str],
        allow_dir_scan: bool,
        scope_validator: ScopeValidator,
        scope_hash: Optional[str],
    ) -> ToolExecutionRecord:
        rec = ToolExecutionRecord(
            tool_name="gobuster",
            campaign_id=campaign_id,
            authorization_record_id=auth_id,
            target=target,
            scope_snapshot_hash=scope_hash,
            arguments=["dir", "-u", target, "-q"],
        )

        # Invariant: Directory brute force requires explicit policy permission
        if not allow_dir_scan:
            rec.completed_at = get_utc_now().isoformat()
            rec.status = ToolValidationStatus.BLOCKED_POLICY
            rec.failure_reason = "Directory brute-forcing / fuzzing is not explicitly authorized under program policy."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_BLOCKED, rec.failure_reason)
            return rec

        rec.record_event(ReconLifecycleEvent.RECON_TOOL_STARTED)
        binary_path = self.tool_availability.resolve_binary_path("gobuster")
        if not binary_path:
            rec.completed_at = get_utc_now().isoformat()
            rec.status = ToolValidationStatus.BINARY_UNAVAILABLE
            rec.failure_reason = "Executable 'gobuster' not found on system PATH or configured tools directory."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        req = ToolExecutionRequest(
            campaign_id=campaign_id,
            target=target,
            tool_name="gobuster",
            execution_profile=ExecutionProfile.DIRECTORY_DISCOVERY.value,
            args=["dir", "-u", target, "-q"],
            authorization_confirmed=True,
            custom_executable_path=binary_path,
            execution_mode="AUTHORIZED_LIVE_RECON",
        )
        res = await self.tool_boundary.execute(req)
        rec.completed_at = get_utc_now().isoformat()
        rec.duration_ms = res.duration_ms
        rec.exit_code = res.exit_code
        rec.stdout_hash = res.stdout_hash
        rec.stderr_hash = res.stderr_hash
        rec.evidence_id = res.output_hash
        rec.raw_output = res.stdout

        if res.execution_status != ToolExecutionStatus.SUCCESS.value:
            rec.status = ToolValidationStatus.EXECUTION_FAILED
            rec.failure_reason = res.error_category or res.stderr or "Gobuster execution failed."
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_FAILED, rec.failure_reason)
            return rec

        rec.record_event(ReconLifecycleEvent.RECON_TOOL_EXECUTED)
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_OUTPUT_CAPTURED)

        raw_paths = [line.strip().split()[0] for line in (res.stdout or "").splitlines() if line.strip().startswith("/")]
        rec.parsed_result_count = len(raw_paths)
        norm_assets = []
        for p in raw_paths:
            norm_assets.append({
                "source": "gobuster",
                "source_execution_id": rec.execution_id,
                "asset": f"{target.rstrip('/')}{p}",
                "type": "endpoint",
                "authorization_status": "DISCOVERED_NOT_AUTHORIZED",
                "evidence_hash": res.stdout_hash,
            })

        rec.normalized_assets = norm_assets
        rec.normalized_result_count = len(norm_assets)
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_RESULTS_NORMALIZED)
        rec.status = ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED if norm_assets else ToolValidationStatus.EXECUTED_ZERO_RESULTS
        return rec

    def _validate_nuclei(
        self,
        target: str,
        campaign_id: str,
        auth_id: Optional[str],
        scope_hash: Optional[str],
    ) -> ToolExecutionRecord:
        rec = ToolExecutionRecord(
            tool_name="nuclei",
            campaign_id=campaign_id,
            authorization_record_id=auth_id,
            target=target,
            scope_snapshot_hash=scope_hash,
            status=ToolValidationStatus.NOT_SELECTED_RECON_ONLY,
            failure_reason="Nuclei is a vulnerability scanner; excluded from Phase 25 reconnaissance validation gate.",
            completed_at=get_utc_now().isoformat(),
        )
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_BLOCKED, "NOT_SELECTED_RECON_ONLY")
        return rec

    def _validate_dalfox(
        self,
        target: str,
        campaign_id: str,
        auth_id: Optional[str],
        scope_hash: Optional[str],
    ) -> ToolExecutionRecord:
        rec = ToolExecutionRecord(
            tool_name="dalfox",
            campaign_id=campaign_id,
            authorization_record_id=auth_id,
            target=target,
            scope_snapshot_hash=scope_hash,
            status=ToolValidationStatus.NOT_SELECTED_RECON_ONLY,
            failure_reason="Dalfox is an active XSS scanner/fuzzer; excluded from Phase 25 reconnaissance validation gate.",
            completed_at=get_utc_now().isoformat(),
        )
        rec.record_event(ReconLifecycleEvent.RECON_TOOL_BLOCKED, "NOT_SELECTED_RECON_ONLY")
        return rec

    # --------------------------------------------------------------------------
    # Ingestion & Deduplication Helpers
    # --------------------------------------------------------------------------

    def _ingest_tool_assets(
        self,
        record: ToolExecutionRecord,
        all_assets: List[NormalizedReconAsset],
        evidence_hashes: List[str],
        provenance_map: Dict[str, List[str]],
    ) -> None:
        if record.evidence_id:
            evidence_hashes.append(record.evidence_id)
        if record.stdout_hash:
            evidence_hashes.append(record.stdout_hash)

        for a in record.normalized_assets:
            val = a["asset"]
            asset_type = a.get("type", "ENDPOINT").upper()
            all_assets.append(
                NormalizedReconAsset(
                    asset_id=str(uuid.uuid4()),
                    raw_value=val,
                    normalized_value=val,
                    asset_type=asset_type,
                    source_provider=record.tool_name,
                    status=ReconAssetStatus.DISCOVERED,
                    is_executable=False,
                    metadata={"authorization_status": a.get("authorization_status", "DISCOVERED_NOT_AUTHORIZED")},
                    evidence_hash=a.get("evidence_hash"),
                )
            )
            if val not in provenance_map:
                provenance_map[val] = []
            if record.tool_name not in provenance_map[val]:
                provenance_map[val].append(record.tool_name)

    def _deduplicate_assets(
        self,
        assets: List[NormalizedReconAsset],
        provenance_map: Dict[str, List[str]],
    ) -> List[NormalizedReconAsset]:
        seen: Dict[str, NormalizedReconAsset] = {}
        for a in assets:
            key = f"{a.asset_type}:{a.normalized_value}"
            if key not in seen:
                sources = provenance_map.get(a.normalized_value, [a.source_provider])
                a.metadata["provenance_sources"] = sources
                seen[key] = a
        return list(seen.values())

    def _generate_blocked_records(
        self,
        target: str,
        campaign_id: str,
        status: ToolValidationStatus,
        reason: str,
        execution_origin: ExecutionOrigin = ExecutionOrigin.UNSPECIFIED,
        pipeline_run_id: Optional[str] = None,
    ) -> Dict[str, ToolExecutionRecord]:
        tools = [
            "subfinder", "sublist3r", "amass", "crtsh", "wayback",
            "gau", "dns_recon", "http_probe", "whatweb", "nmap",
            "gobuster", "nuclei", "dalfox"
        ]
        records = {}
        now = get_utc_now().isoformat()
        for t in tools:
            rec = ToolExecutionRecord(
                tool_name=t,
                campaign_id=campaign_id,
                target=target,
                status=status,
                failure_reason=reason,
                started_at=now,
                completed_at=now,
                execution_origin=execution_origin,
                pipeline_run_id=pipeline_run_id,
            )
            rec.record_event(ReconLifecycleEvent.RECON_TOOL_BLOCKED, reason)
            records[t] = rec
        return records
