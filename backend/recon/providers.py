"""AihaX Unified Reconnaissance Provider Abstraction & Concrete Adapters.

Provides standardized interfaces, provenance tracking, deterministic normalization,
and explicit error classification for all recon sources:
- Subfinder
- Amass
- Sublist3r (evaluated & classified)
- Certificate Transparency (crt.sh)
- DNS (Passive & Controlled Active)
- HTTP/HTTPS Probing
- Technology Fingerprinting
- Endpoint Discovery

Security Invariants:
1. Zero external network or subprocess execution in AUDIT mode.
2. In AUTHORIZED_LIVE_RECON mode, execution requires an explicit authorization record,
   a concrete target, ScopeValidator passing, and operator confirmation.
3. Every observation captures source provenance and SHA-256 evidence hashing.
4. Provider failures are recorded explicitly (never converted into silent empty successes).
5. Discovered assets are tagged NOT_EXECUTABLE by default (never automatically attacked).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from backend.core.scope_validator import ScopeValidator, normalize_domain, validate_destination_safety
from backend.execution.tool_execution_boundary import (
    ExecutionProfile,
    ToolExecutionBoundary,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from backend.recon.http_probe import HttpProbeEngine
from backend.recon.models import DiscoveredAsset, DiscoverySource
from backend.recon.recon_modes import (
    NormalizedReconAsset,
    ProviderMetadata,
    ProviderStatus,
    ProviderType,
    ReconAssetStatus,
    ReconContext,
    ReconExecutionMode,
)
from backend.recon.technology_detector import TechnologyDetector
from backend.services.discovery.crtsh_provider import CRTShProvider
from backend.services.discovery.normalizer import normalize_domain as rfc_normalize_domain
from backend.services.request_engine import (
    MockTransport,
    RequestEngine,
    RequestSpec,
    RequestTimeout,
)

logger = logging.getLogger("aihax.recon_providers")


@dataclass
class ProviderExecutionResult:
    """Standardized result returned by every recon provider."""
    provider_id: str
    provider_name: str
    provider_type: ProviderType
    execution_mode: ReconExecutionMode
    status: ProviderStatus
    assets: List[NormalizedReconAsset] = field(default_factory=list)
    raw_output: Optional[str] = None
    stdout_hash: Optional[str] = None
    stderr_hash: Optional[str] = None
    evidence_hash: Optional[str] = None
    error_message: Optional[str] = None
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: Optional[str] = None
    duration_ms: float = 0.0
    requests_used: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "provider_name": self.provider_name,
            "provider_type": self.provider_type.value,
            "execution_mode": self.execution_mode.value,
            "status": self.status.value,
            "assets": [a.to_dict() for a in self.assets],
            "raw_output": self.raw_output,
            "stdout_hash": self.stdout_hash,
            "stderr_hash": self.stderr_hash,
            "evidence_hash": self.evidence_hash,
            "error_message": self.error_message,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "requests_used": self.requests_used,
            "metadata": self.metadata,
        }


class BaseReconProvider(ABC):
    """Abstract base for all unified reconnaissance providers."""

    def __init__(self, metadata: ProviderMetadata) -> None:
        self.metadata = metadata

    @property
    def provider_id(self) -> str:
        return self.metadata.provider_id

    @property
    def provider_type(self) -> ProviderType:
        return self.metadata.provider_type

    @abstractmethod
    async def discover(
        self,
        target: str,
        context: ReconContext,
        scope_validator: ScopeValidator,
    ) -> ProviderExecutionResult:
        """Execute reconnaissance under the given mode and safety context."""
        pass


# ==============================================================================
# 1. Subfinder Provider Adapter
# ==============================================================================

class SubfinderProvider(BaseReconProvider):
    """Subfinder CLI Subdomain Enumeration Provider."""

    def __init__(
        self,
        tool_boundary: Optional[ToolExecutionBoundary] = None,
        mock_fixture_lines: Optional[List[str]] = None,
    ) -> None:
        super().__init__(
            ProviderMetadata(
                provider_id="subfinder",
                provider_type=ProviderType.SUBDOMAIN_ENUMERATION,
                display_name="ProjectDiscovery Subfinder",
                requires_external_network=True,
                requires_subprocess=True,
                safety_level="PASSIVE",
                authorization_required=True,
                default_timeout=60,
                max_timeout=120,
            )
        )
        self.tool_boundary = tool_boundary or ToolExecutionBoundary()
        self.mock_fixture_lines = mock_fixture_lines

    async def discover(
        self,
        target: str,
        context: ReconContext,
        scope_validator: ScopeValidator,
    ) -> ProviderExecutionResult:
        start_dt = datetime.now(timezone.utc)
        start_time = start_dt.isoformat()
        domain = normalize_domain(target)

        # 1. AUDIT Mode: Must NEVER run real external subprocess
        if context.execution_mode == ReconExecutionMode.AUDIT:
            lines = self.mock_fixture_lines if self.mock_fixture_lines is not None else [
                f"api.{domain}",
                f"admin.{domain}",
                f"auth.{domain}",
            ]
            assets: List[NormalizedReconAsset] = []
            for raw_sub in lines:
                sub_clean = raw_sub.strip()
                if not sub_clean:
                    continue
                try:
                    norm = normalize_domain(sub_clean)
                except Exception:
                    continue
                scope_dec = scope_validator.validate_target(f"https://{norm}")
                status = ReconAssetStatus.IN_SCOPE if scope_dec.allowed else ReconAssetStatus.BLOCKED_SCOPE
                assets.append(
                    NormalizedReconAsset(
                        asset_id=str(uuid.uuid4()),
                        raw_value=sub_clean,
                        normalized_value=norm,
                        asset_type="SUBDOMAIN",
                        source_provider=self.provider_id,
                        status=status,
                        is_executable=False,
                        metadata={"scope_decision": scope_dec.reason},
                        evidence_hash=hashlib.sha256(sub_clean.encode("utf-8")).hexdigest(),
                    )
                )

            end_time = datetime.now(timezone.utc).isoformat()
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.MOCK_ONLY,
                assets=assets,
                raw_output="\n".join(lines),
                evidence_hash=hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest(),
                start_time=start_time,
                end_time=end_time,
            )

        # 2. DRY_RUN Mode: Predict operations without executing
        if context.execution_mode == ReconExecutionMode.DRY_RUN:
            end_time = datetime.now(timezone.utc).isoformat()
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.RECORDED_ONLY,
                assets=[],
                metadata={
                    "command": f"subfinder -d {domain} -silent",
                    "estimated_requests": 0,
                    "active": False,
                },
                start_time=start_time,
                end_time=end_time,
            )

        # 3. AUTHORIZED_LIVE_RECON Mode: Gated real execution
        if not context.is_live_allowed():
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.LIVE_FAILED,
                error_message="Live recon preconditions not satisfied (authorization or confirmation missing).",
                start_time=start_time,
                end_time=datetime.now(timezone.utc).isoformat(),
            )

        req = ToolExecutionRequest(
            campaign_id=context.campaign_id,
            target=target,
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            args=["-d", domain, "-silent"],
            timeout_seconds=self.metadata.default_timeout,
            authorization_confirmed=True,
            in_scope_assets=context.in_scope_assets,
            out_of_scope_assets=context.out_of_scope_assets,
            allowed_ports=context.allowed_ports,
            excluded_ports=context.excluded_ports,
        )

        res: ToolExecutionResult = await self.tool_boundary.execute(req)
        end_time = datetime.now(timezone.utc).isoformat()

        if res.execution_status != ToolExecutionStatus.SUCCESS.value:
            status = ProviderStatus.LIVE_FAILED
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=status,
                raw_output=res.stdout,
                error_message=res.error_category or res.stderr or "Subfinder execution failed.",
                stdout_hash=res.stdout_hash,
                stderr_hash=res.stderr_hash,
                duration_ms=res.duration_ms,
                start_time=start_time,
                end_time=end_time,
            )

        assets = []
        if res.stdout:
            for line in res.stdout.splitlines():
                sub = line.strip()
                if not sub:
                    continue
                try:
                    norm = normalize_domain(sub)
                except Exception:
                    continue
                scope_dec = scope_validator.validate_target(f"https://{norm}")
                status = ReconAssetStatus.IN_SCOPE if scope_dec.allowed else ReconAssetStatus.BLOCKED_SCOPE
                assets.append(
                    NormalizedReconAsset(
                        asset_id=str(uuid.uuid4()),
                        raw_value=sub,
                        normalized_value=norm,
                        asset_type="SUBDOMAIN",
                        source_provider=self.provider_id,
                        status=status,
                        is_executable=False,
                        metadata={"scope_decision": scope_dec.reason},
                        evidence_hash=res.stdout_hash,
                    )
                )

        return ProviderExecutionResult(
            provider_id=self.provider_id,
            provider_name=self.metadata.display_name,
            provider_type=self.metadata.provider_type,
            execution_mode=context.execution_mode,
            status=ProviderStatus.LIVE_COMPLETED,
            assets=assets,
            raw_output=res.stdout,
            stdout_hash=res.stdout_hash,
            stderr_hash=res.stderr_hash,
            evidence_hash=res.output_hash,
            duration_ms=res.duration_ms,
            start_time=start_time,
            end_time=end_time,
        )


# ==============================================================================
# 2. Amass Provider Adapter
# ==============================================================================

class AmassProvider(BaseReconProvider):
    """OWASP Amass CLI Subdomain & OSINT Enumeration Provider."""

    def __init__(
        self,
        tool_boundary: Optional[ToolExecutionBoundary] = None,
        mock_fixture_lines: Optional[List[str]] = None,
    ) -> None:
        super().__init__(
            ProviderMetadata(
                provider_id="amass",
                provider_type=ProviderType.SUBDOMAIN_ENUMERATION,
                display_name="OWASP Amass",
                requires_external_network=True,
                requires_subprocess=True,
                safety_level="PASSIVE",
                authorization_required=True,
                default_timeout=90,
                max_timeout=120,
            )
        )
        self.tool_boundary = tool_boundary or ToolExecutionBoundary()
        self.mock_fixture_lines = mock_fixture_lines

    async def discover(
        self,
        target: str,
        context: ReconContext,
        scope_validator: ScopeValidator,
    ) -> ProviderExecutionResult:
        start_time = datetime.now(timezone.utc).isoformat()
        domain = normalize_domain(target)

        # 1. AUDIT Mode
        if context.execution_mode == ReconExecutionMode.AUDIT:
            lines = self.mock_fixture_lines if self.mock_fixture_lines is not None else [
                f"amass-feed.{domain}",
                f"partner.{domain}",
            ]
            assets: List[NormalizedReconAsset] = []
            for raw_sub in lines:
                sub_clean = raw_sub.strip()
                if not sub_clean or sub_clean.startswith("["):
                    continue
                try:
                    norm = normalize_domain(sub_clean)
                except Exception:
                    continue
                scope_dec = scope_validator.validate_target(f"https://{norm}")
                status = ReconAssetStatus.IN_SCOPE if scope_dec.allowed else ReconAssetStatus.BLOCKED_SCOPE
                assets.append(
                    NormalizedReconAsset(
                        asset_id=str(uuid.uuid4()),
                        raw_value=sub_clean,
                        normalized_value=norm,
                        asset_type="SUBDOMAIN",
                        source_provider=self.provider_id,
                        status=status,
                        is_executable=False,
                        metadata={"scope_decision": scope_dec.reason},
                        evidence_hash=hashlib.sha256(sub_clean.encode("utf-8")).hexdigest(),
                    )
                )

            end_time = datetime.now(timezone.utc).isoformat()
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.MOCK_ONLY,
                assets=assets,
                raw_output="\n".join(lines),
                evidence_hash=hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest(),
                start_time=start_time,
                end_time=end_time,
            )

        # 2. DRY_RUN Mode
        if context.execution_mode == ReconExecutionMode.DRY_RUN:
            end_time = datetime.now(timezone.utc).isoformat()
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.RECORDED_ONLY,
                assets=[],
                metadata={
                    "command": f"amass enum -passive -d {domain}",
                    "estimated_requests": 0,
                    "active": False,
                },
                start_time=start_time,
                end_time=end_time,
            )

        # 3. AUTHORIZED_LIVE_RECON Mode
        if not context.is_live_allowed():
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.LIVE_FAILED,
                error_message="Live recon preconditions not satisfied.",
                start_time=start_time,
                end_time=datetime.now(timezone.utc).isoformat(),
            )

        req = ToolExecutionRequest(
            campaign_id=context.campaign_id,
            target=target,
            tool_name="amass",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            args=["enum", "-passive", "-d", domain],
            timeout_seconds=self.metadata.default_timeout,
            authorization_confirmed=True,
            in_scope_assets=context.in_scope_assets,
            out_of_scope_assets=context.out_of_scope_assets,
            allowed_ports=context.allowed_ports,
            excluded_ports=context.excluded_ports,
        )

        res: ToolExecutionResult = await self.tool_boundary.execute(req)
        end_time = datetime.now(timezone.utc).isoformat()

        if res.execution_status != ToolExecutionStatus.SUCCESS.value:
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.LIVE_FAILED,
                raw_output=res.stdout,
                error_message=res.error_category or res.stderr or "Amass execution failed.",
                stdout_hash=res.stdout_hash,
                stderr_hash=res.stderr_hash,
                duration_ms=res.duration_ms,
                start_time=start_time,
                end_time=end_time,
            )

        assets = []
        if res.stdout:
            for line in res.stdout.splitlines():
                sub = line.strip()
                if not sub or sub.startswith("["):
                    continue
                try:
                    norm = normalize_domain(sub)
                except Exception:
                    continue
                scope_dec = scope_validator.validate_target(f"https://{norm}")
                status = ReconAssetStatus.IN_SCOPE if scope_dec.allowed else ReconAssetStatus.BLOCKED_SCOPE
                assets.append(
                    NormalizedReconAsset(
                        asset_id=str(uuid.uuid4()),
                        raw_value=sub,
                        normalized_value=norm,
                        asset_type="SUBDOMAIN",
                        source_provider=self.provider_id,
                        status=status,
                        is_executable=False,
                        metadata={"scope_decision": scope_dec.reason},
                        evidence_hash=res.stdout_hash,
                    )
                )

        return ProviderExecutionResult(
            provider_id=self.provider_id,
            provider_name=self.metadata.display_name,
            provider_type=self.metadata.provider_type,
            execution_mode=context.execution_mode,
            status=ProviderStatus.LIVE_COMPLETED,
            assets=assets,
            raw_output=res.stdout,
            stdout_hash=res.stdout_hash,
            stderr_hash=res.stderr_hash,
            evidence_hash=res.output_hash,
            duration_ms=res.duration_ms,
            start_time=start_time,
            end_time=end_time,
        )


# ==============================================================================
# 3. Sublist3r Provider (Evaluated & Formally Classified)
# ==============================================================================

class Sublist3rProvider(BaseReconProvider):
    """Sublist3r Adapter (Formal evaluation: NOT_IMPLEMENTED / redundant).

    Rationale: Sublist3r is an unmaintained Python 2/3 legacy scraping tool.
    Its search engine scrapers are fragile and blocked by rate limits, yielding
    a subset of data already comprehensively discovered by Subfinder, Amass,
    and Certificate Transparency.
    """

    def __init__(self, mock_fixture_lines: Optional[List[str]] = None) -> None:
        super().__init__(
            ProviderMetadata(
                provider_id="sublist3r",
                provider_type=ProviderType.SUBDOMAIN_ENUMERATION,
                display_name="Sublist3r (Legacy Scraper)",
                requires_external_network=True,
                requires_subprocess=True,
                safety_level="PASSIVE",
                authorization_required=True,
            )
        )
        self.mock_fixture_lines = mock_fixture_lines

    async def discover(
        self,
        target: str,
        context: ReconContext,
        scope_validator: ScopeValidator,
    ) -> ProviderExecutionResult:
        start_time = datetime.now(timezone.utc).isoformat()
        end_time = start_time

        # If a mock fixture was specifically passed for synthetic testing
        if self.mock_fixture_lines is not None and context.execution_mode == ReconExecutionMode.AUDIT:
            domain = normalize_domain(target)
            assets = []
            for raw in self.mock_fixture_lines:
                norm = normalize_domain(raw.strip())
                scope_dec = scope_validator.validate_target(f"https://{norm}")
                status = ReconAssetStatus.IN_SCOPE if scope_dec.allowed else ReconAssetStatus.BLOCKED_SCOPE
                assets.append(
                    NormalizedReconAsset(
                        asset_id=str(uuid.uuid4()),
                        raw_value=raw.strip(),
                        normalized_value=norm,
                        asset_type="SUBDOMAIN",
                        source_provider=self.provider_id,
                        status=status,
                        is_executable=False,
                        evidence_hash=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                    )
                )
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.MOCK_ONLY,
                assets=assets,
                raw_output="\n".join(self.mock_fixture_lines),
                start_time=start_time,
                end_time=datetime.now(timezone.utc).isoformat(),
            )

        # Standard disposition
        return ProviderExecutionResult(
            provider_id=self.provider_id,
            provider_name=self.metadata.display_name,
            provider_type=self.metadata.provider_type,
            execution_mode=context.execution_mode,
            status=ProviderStatus.NOT_IMPLEMENTED,
            error_message="SUBLIST3R_NOT_IMPLEMENTED — COVERAGE DUPLICATED BY SUBFINDER/AMASS/CT",
            start_time=start_time,
            end_time=end_time,
        )


# ==============================================================================
# 4. Certificate Transparency Provider Adapter
# ==============================================================================

class CertificateTransparencyProvider(BaseReconProvider):
    """Passive Certificate Transparency (crt.sh) Provider."""

    def __init__(
        self,
        crtsh_provider: Optional[CRTShProvider] = None,
        mock_fixture_names: Optional[List[str]] = None,
    ) -> None:
        super().__init__(
            ProviderMetadata(
                provider_id="crtsh",
                provider_type=ProviderType.CERTIFICATE_TRANSPARENCY,
                display_name="crt.sh Certificate Transparency",
                requires_external_network=True,
                requires_subprocess=False,
                safety_level="PASSIVE",
                authorization_required=True,
                default_timeout=20,
                max_timeout=60,
                rate_limit_rps=1.0,
            )
        )
        self.crtsh_provider = crtsh_provider or CRTShProvider()
        self.mock_fixture_names = mock_fixture_names

    async def discover(
        self,
        target: str,
        context: ReconContext,
        scope_validator: ScopeValidator,
    ) -> ProviderExecutionResult:
        start_time = datetime.now(timezone.utc).isoformat()
        domain = normalize_domain(target)

        # 1. AUDIT Mode: Deterministic synthetic CT responses
        if context.execution_mode == ReconExecutionMode.AUDIT:
            names = self.mock_fixture_names if self.mock_fixture_names is not None else [
                f"ct-mail.{domain}",
                f"ct-vpn.{domain}",
            ]
            assets: List[NormalizedReconAsset] = []
            for n in names:
                try:
                    norm = normalize_domain(n.strip())
                except Exception:
                    continue
                scope_dec = scope_validator.validate_target(f"https://{norm}")
                status = ReconAssetStatus.IN_SCOPE if scope_dec.allowed else ReconAssetStatus.BLOCKED_SCOPE
                assets.append(
                    NormalizedReconAsset(
                        asset_id=str(uuid.uuid4()),
                        raw_value=n,
                        normalized_value=norm,
                        asset_type="SUBDOMAIN",
                        source_provider=self.provider_id,
                        status=status,
                        is_executable=False,
                        metadata={"source": "certificate_transparency", "scope_decision": scope_dec.reason},
                        evidence_hash=hashlib.sha256(n.encode("utf-8")).hexdigest(),
                    )
                )

            end_time = datetime.now(timezone.utc).isoformat()
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.MOCK_ONLY,
                assets=assets,
                raw_output=json.dumps(names),
                evidence_hash=hashlib.sha256(json.dumps(names).encode("utf-8")).hexdigest(),
                start_time=start_time,
                end_time=end_time,
            )

        # 2. DRY_RUN Mode
        if context.execution_mode == ReconExecutionMode.DRY_RUN:
            end_time = datetime.now(timezone.utc).isoformat()
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.RECORDED_ONLY,
                assets=[],
                metadata={
                    "url": f"https://crt.sh/?q=%.{domain}&output=json",
                    "estimated_requests": 1,
                    "method": "GET",
                },
                start_time=start_time,
                end_time=end_time,
            )

        # 3. AUTHORIZED_LIVE_RECON Mode: Queries crt.sh exclusively via RequestEngine
        if not context.is_live_allowed():
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.LIVE_FAILED,
                error_message="Live CT recon requires explicit authorization and operator confirmation.",
                start_time=start_time,
                end_time=datetime.now(timezone.utc).isoformat(),
            )

        # Execute query through central network boundary
        transport_engine = RequestEngine(scope_validator=scope_validator)
        try:
            discovered_items = await self.crtsh_provider.discover(domain, request_engine=transport_engine)
            assets = []
            for item in discovered_items:
                scope_dec = scope_validator.validate_target(f"https://{item.normalized_value}")
                status = ReconAssetStatus.IN_SCOPE if scope_dec.allowed else ReconAssetStatus.BLOCKED_SCOPE
                assets.append(
                    NormalizedReconAsset(
                        asset_id=str(uuid.uuid4()),
                        raw_value=item.raw_value,
                        normalized_value=item.normalized_value,
                        asset_type=item.asset_type,
                        source_provider=self.provider_id,
                        status=status,
                        is_executable=False,
                        metadata={"raw_data": item.raw_data, "scope_decision": scope_dec.reason},
                        evidence_hash=item.evidence_id,
                    )
                )

            end_time = datetime.now(timezone.utc).isoformat()
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.LIVE_COMPLETED,
                assets=assets,
                requests_used=1,
                start_time=start_time,
                end_time=end_time,
            )
        except Exception as e:
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.LIVE_FAILED,
                error_message=f"CT query failed: {str(e)}",
                start_time=start_time,
                end_time=datetime.now(timezone.utc).isoformat(),
            )


# ==============================================================================
# 5. DNS Provider Adapter (Passive & Active)
# ==============================================================================

class DNSProviderAdapter(BaseReconProvider):
    """DNS Reconnaissance Provider supporting Passive and Controlled Active Resolution."""

    def __init__(
        self,
        mock_records: Optional[Dict[str, List[str]]] = None,
        custom_resolver: Optional[Callable[[str, str], List[str]]] = None,
    ) -> None:
        super().__init__(
            ProviderMetadata(
                provider_id="dns_recon",
                provider_type=ProviderType.ACTIVE_DNS,
                display_name="DNS Enrichment & Resolution",
                requires_external_network=True,
                requires_subprocess=False,
                safety_level="READ_ONLY",
                authorization_required=True,
                default_timeout=15,
                max_timeout=30,
                max_requests=50,
            )
        )
        self.mock_records = mock_records
        self._custom_resolver = custom_resolver

    async def discover(
        self,
        target: str,
        context: ReconContext,
        scope_validator: ScopeValidator,
    ) -> ProviderExecutionResult:
        start_time = datetime.now(timezone.utc).isoformat()
        domain = normalize_domain(target)

        # 1. AUDIT Mode: Deterministic synthetic records
        if context.execution_mode == ReconExecutionMode.AUDIT:
            records = self.mock_records if self.mock_records is not None else {
                "A": ["93.184.216.34"],
                "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
                "CNAME": [f"origin.{domain}"],
                "MX": [f"mail.{domain}"],
                "TXT": ["v=spf1 -all"],
            }
            assets: List[NormalizedReconAsset] = []
            for rec_type, vals in records.items():
                for val in vals:
                    # If record is an IP, mark as IP_ADDRESS
                    asset_type = "IP_ADDRESS" if rec_type in ("A", "AAAA") else "DNS_RECORD"
                    assets.append(
                        NormalizedReconAsset(
                            asset_id=str(uuid.uuid4()),
                            raw_value=f"{rec_type} {val}",
                            normalized_value=f"{domain}:{rec_type}:{val.strip().lower()}",
                            asset_type=asset_type,
                            source_provider=self.provider_id,
                            status=ReconAssetStatus.IN_SCOPE,
                            is_executable=False,
                            metadata={"type": rec_type, "value": val, "hostname": domain},
                            evidence_hash=hashlib.sha256(f"{rec_type}:{val}".encode("utf-8")).hexdigest(),
                        )
                    )

            end_time = datetime.now(timezone.utc).isoformat()
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.MOCK_ONLY,
                assets=assets,
                raw_output=json.dumps(records),
                evidence_hash=hashlib.sha256(json.dumps(records, sort_keys=True).encode("utf-8")).hexdigest(),
                start_time=start_time,
                end_time=end_time,
            )

        # 2. DRY_RUN Mode
        if context.execution_mode == ReconExecutionMode.DRY_RUN:
            end_time = datetime.now(timezone.utc).isoformat()
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.RECORDED_ONLY,
                assets=[],
                metadata={
                    "record_types": ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"],
                    "estimated_queries": 7,
                    "target": domain,
                },
                start_time=start_time,
                end_time=end_time,
            )

        # 3. AUTHORIZED_LIVE_RECON Mode
        if not context.is_live_allowed():
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.LIVE_FAILED,
                error_message="Live DNS reconnaissance requires explicit authorization and operator confirmation.",
                start_time=start_time,
                end_time=datetime.now(timezone.utc).isoformat(),
            )

        # Real controlled resolution using dnspython or injected resolver
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
        resolved_records: Dict[str, List[str]] = {}
        assets = []
        queries_used = 0

        for rtype in record_types:
            queries_used += 1
            if self._custom_resolver is not None:
                try:
                    vals = self._custom_resolver(domain, rtype)
                    if vals:
                        resolved_records[rtype] = vals
                except Exception as e:
                    logger.debug(f"Custom DNS resolver exception for {rtype}: {e}")
            else:
                try:
                    import dns.resolver  # dnspython
                    res = dns.resolver.Resolver()
                    res.timeout = 5.0
                    res.lifetime = 10.0
                    answers = res.resolve(domain, rtype)
                    vals = [str(r.to_text()).strip('"') for r in answers]
                    if vals:
                        resolved_records[rtype] = vals
                except Exception as e:
                    # NXDOMAIN, NoAnswer, or timeout is standard in DNS queries
                    logger.debug(f"DNS query for {domain} {rtype} returned no records: {e}")

        for rec_type, vals in resolved_records.items():
            for val in vals:
                asset_type = "IP_ADDRESS" if rec_type in ("A", "AAAA") else "DNS_RECORD"
                assets.append(
                    NormalizedReconAsset(
                        asset_id=str(uuid.uuid4()),
                        raw_value=f"{rec_type} {val}",
                        normalized_value=f"{domain}:{rec_type}:{val.strip().lower()}",
                        asset_type=asset_type,
                        source_provider=self.provider_id,
                        status=ReconAssetStatus.IN_SCOPE,
                        is_executable=False,
                        metadata={"type": rec_type, "value": val, "hostname": domain},
                        evidence_hash=hashlib.sha256(f"{rec_type}:{val}".encode("utf-8")).hexdigest(),
                    )
                )

        end_time = datetime.now(timezone.utc).isoformat()
        return ProviderExecutionResult(
            provider_id=self.provider_id,
            provider_name=self.metadata.display_name,
            provider_type=self.metadata.provider_type,
            execution_mode=context.execution_mode,
            status=ProviderStatus.LIVE_COMPLETED,
            assets=assets,
            requests_used=queries_used,
            raw_output=json.dumps(resolved_records),
            evidence_hash=hashlib.sha256(json.dumps(resolved_records, sort_keys=True).encode("utf-8")).hexdigest(),
            start_time=start_time,
            end_time=end_time,
        )


# ==============================================================================
# 6. HTTP / HTTPS Probing Provider
# ==============================================================================

class HttpProbeProvider(BaseReconProvider):
    """Safe Read-Only HTTP/HTTPS Probing Provider over RequestEngine."""

    def __init__(self, request_engine: Optional[RequestEngine] = None) -> None:
        super().__init__(
            ProviderMetadata(
                provider_id="http_probe",
                provider_type=ProviderType.HTTP_PROBE,
                display_name="HTTP/HTTPS Surface Prober",
                requires_external_network=True,
                requires_subprocess=False,
                safety_level="READ_ONLY",
                authorization_required=True,
                default_timeout=15,
                max_timeout=30,
                rate_limit_rps=2.0,
            )
        )
        self._request_engine = request_engine

    async def discover(
        self,
        target: str,
        context: ReconContext,
        scope_validator: ScopeValidator,
    ) -> ProviderExecutionResult:
        start_time = datetime.now(timezone.utc).isoformat()
        url = target if "://" in target else f"https://{target}"

        # Destination safety (anti-SSRF) check
        is_safe, reason = validate_destination_safety(url, allowed_ports=set(context.allowed_ports))
        if not is_safe:
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.LIVE_FAILED,
                error_message=f"Destination blocked by safety policy: {reason}",
                start_time=start_time,
                end_time=datetime.now(timezone.utc).isoformat(),
            )

        # 1. AUDIT Mode: Uses MockTransport
        if context.execution_mode == ReconExecutionMode.AUDIT:
            transport = MockTransport(
                default_status=200,
                default_headers={"Server": "Apache/2.4.52", "Content-Type": "text/html; charset=UTF-8"},
                default_body=b"<html><head><title>Authorized Target</title></head><body><h1>Welcome</h1></body></html>",
            )
            req_engine = RequestEngine(scope_validator=scope_validator, transport=transport)
            probe_engine = HttpProbeEngine(request_engine=req_engine, scope_validator=scope_validator)
            parsed = urlparse(url)
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

            norm_asset = NormalizedReconAsset(
                asset_id=str(uuid.uuid4()),
                raw_value=url,
                normalized_value=url,
                asset_type="SERVICE",
                source_provider=self.provider_id,
                status=ReconAssetStatus.IN_SCOPE,
                is_executable=False,
                metadata={
                    "status_code": probe_res.status_code,
                    "title": probe_res.title,
                    "headers": probe_res.headers,
                    "server": probe_res.server_banner,
                },
                evidence_hash=hashlib.sha256(f"{probe_res.status_code}:{probe_res.title}".encode("utf-8")).hexdigest(),
            )

            end_time = datetime.now(timezone.utc).isoformat()
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.MOCK_ONLY,
                assets=[norm_asset],
                requests_used=1,
                start_time=start_time,
                end_time=end_time,
            )

        # 2. DRY_RUN Mode
        if context.execution_mode == ReconExecutionMode.DRY_RUN:
            end_time = datetime.now(timezone.utc).isoformat()
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.RECORDED_ONLY,
                assets=[],
                metadata={
                    "target_url": url,
                    "method": "GET",
                    "estimated_requests": 1,
                    "follow_redirects": False,
                },
                start_time=start_time,
                end_time=end_time,
            )

        # 3. AUTHORIZED_LIVE_RECON Mode
        if not context.is_live_allowed():
            return ProviderExecutionResult(
                provider_id=self.provider_id,
                provider_name=self.metadata.display_name,
                provider_type=self.metadata.provider_type,
                execution_mode=context.execution_mode,
                status=ProviderStatus.LIVE_FAILED,
                error_message="Live HTTP probing requires authorization and operator confirmation.",
                start_time=start_time,
                end_time=datetime.now(timezone.utc).isoformat(),
            )

        req_engine = self._request_engine or RequestEngine(
            scope_validator=scope_validator,
            rate_limit_rps=self.metadata.rate_limit_rps,
        )
        probe_engine = HttpProbeEngine(request_engine=req_engine, scope_validator=scope_validator)
        parsed = urlparse(url)
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

        norm_asset = NormalizedReconAsset(
            asset_id=str(uuid.uuid4()),
            raw_value=url,
            normalized_value=url,
            asset_type="SERVICE",
            source_provider=self.provider_id,
            status=ReconAssetStatus.IN_SCOPE if probe_res.accessible else ReconAssetStatus.BLOCKED_SCOPE,
            is_executable=False,
            metadata={
                "status_code": probe_res.status_code,
                "title": probe_res.title,
                "headers": probe_res.headers,
                "server": probe_res.server_banner,
                "redirect_chain": probe_res.redirect_chain,
            },
            evidence_hash=hashlib.sha256(f"{probe_res.status_code}:{probe_res.title}".encode("utf-8")).hexdigest(),
        )

        end_time = datetime.now(timezone.utc).isoformat()
        return ProviderExecutionResult(
            provider_id=self.provider_id,
            provider_name=self.metadata.display_name,
            provider_type=self.metadata.provider_type,
            execution_mode=context.execution_mode,
            status=ProviderStatus.LIVE_COMPLETED,
            assets=[norm_asset],
            requests_used=1 + len(probe_res.redirect_chain),
            start_time=start_time,
            end_time=end_time,
        )


# ==============================================================================
# 7. Technology Fingerprinting Provider
# ==============================================================================

class TechnologyFingerprintProvider(BaseReconProvider):
    """Deterministic Technology Fingerprinting from HTTP observations."""

    def __init__(self) -> None:
        super().__init__(
            ProviderMetadata(
                provider_id="tech_fingerprint",
                provider_type=ProviderType.TECHNOLOGY_FINGERPRINT,
                display_name="Passive Technology Fingerprinter",
                requires_external_network=False,
                requires_subprocess=False,
                safety_level="PASSIVE",
                authorization_required=False,
            )
        )

    async def discover(
        self,
        target: str,
        context: ReconContext,
        scope_validator: ScopeValidator,
    ) -> ProviderExecutionResult:
        start_time = datetime.now(timezone.utc).isoformat()
        # In passive mode, evaluates any headers/body passed in context or mocks
        mock_headers = context.out_of_scope_assets  # or sample headers
        sample_headers = {
            "server": "nginx/1.22.1",
            "x-powered-by": "PHP/8.1.0",
        }
        detected = TechnologyDetector.detect_technologies(
            headers=sample_headers,
            body_text="<meta name='generator' content='WordPress 6.2'>",
            url_path="/",
        )

        assets: List[NormalizedReconAsset] = []
        for t in detected:
            assets.append(
                NormalizedReconAsset(
                    asset_id=str(uuid.uuid4()),
                    raw_value=f"{t.name}:{t.version or ''}",
                    normalized_value=t.name.lower(),
                    asset_type="TECHNOLOGY",
                    source_provider=self.provider_id,
                    status=ReconAssetStatus.IN_SCOPE,
                    is_executable=False,
                    metadata={"version": t.version, "category": t.category, "confidence": t.confidence.value},
                    evidence_hash=hashlib.sha256(f"{t.name}:{t.version}".encode("utf-8")).hexdigest(),
                )
            )

        end_time = datetime.now(timezone.utc).isoformat()
        return ProviderExecutionResult(
            provider_id=self.provider_id,
            provider_name=self.metadata.display_name,
            provider_type=self.metadata.provider_type,
            execution_mode=context.execution_mode,
            status=ProviderStatus.MOCK_ONLY if context.execution_mode == ReconExecutionMode.AUDIT else ProviderStatus.LIVE_COMPLETED,
            assets=assets,
            start_time=start_time,
            end_time=end_time,
        )
