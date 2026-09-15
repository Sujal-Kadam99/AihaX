"""AihaX Reconnaissance Execution Modes, Policies, and State Transitions.

Enforces:
1. Explicit execution modes: AUDIT (default, zero external network, zero external subprocess),
   DRY_RUN (inspection only), and AUTHORIZED_LIVE_RECON (strictly gated by policy).
2. Fail-closed preflight requirements for any live reconnaissance.
3. Separation of discovery from authorization: discovered assets are NOT automatically
   executable targets.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class ReconExecutionMode(str, Enum):
    """Authoritative execution modes for reconnaissance."""
    AUDIT = "AUDIT"
    DRY_RUN = "DRY_RUN"
    AUTHORIZED_LIVE_RECON = "AUTHORIZED_LIVE_RECON"


class ReconAssetStatus(str, Enum):
    """Lifecycle and security scope states of a discovered reconnaissance asset."""
    DISCOVERED = "DISCOVERED"
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    BLOCKED_SCOPE = "BLOCKED_SCOPE"
    BLOCKED_SAFETY = "BLOCKED_SAFETY"
    NOT_EXECUTABLE = "NOT_EXECUTABLE"
    EXECUTABLE_AFTER_AUTHORIZATION = "EXECUTABLE_AFTER_AUTHORIZATION"
    LIVE_RECON_AUTHORIZED = "LIVE_RECON_AUTHORIZED"


class ProviderStatus(str, Enum):
    """Lifecycle and operational status of a reconnaissance provider."""
    DISABLED = "DISABLED"
    MOCK_ONLY = "MOCK_ONLY"
    RECORDED_ONLY = "RECORDED_ONLY"
    LIVE_ADAPTER_READY = "LIVE_ADAPTER_READY"
    LIVE_ADAPTER_PRESENT_NOT_LIVE_VALIDATED = "LIVE_ADAPTER_PRESENT_NOT_LIVE_VALIDATED"
    LIVE_AUTHORIZED = "LIVE_AUTHORIZED"
    LIVE_RUNNING = "LIVE_RUNNING"
    LIVE_COMPLETED = "LIVE_COMPLETED"
    LIVE_FAILED = "LIVE_FAILED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"


class ProviderType(str, Enum):
    """Categories of reconnaissance capabilities."""
    SUBDOMAIN_ENUMERATION = "SUBDOMAIN_ENUMERATION"
    CERTIFICATE_TRANSPARENCY = "CERTIFICATE_TRANSPARENCY"
    PASSIVE_DNS = "PASSIVE_DNS"
    ACTIVE_DNS = "ACTIVE_DNS"
    HTTP_PROBE = "HTTP_PROBE"
    TECHNOLOGY_FINGERPRINT = "TECHNOLOGY_FINGERPRINT"
    ENDPOINT_DISCOVERY = "ENDPOINT_DISCOVERY"


@dataclass(frozen=True)
class ProviderMetadata:
    """Security and capability specification for a recon provider."""
    provider_id: str
    provider_type: ProviderType
    display_name: str
    requires_external_network: bool
    requires_subprocess: bool
    safety_level: str  # PASSIVE, READ_ONLY, ACTIVE
    authorization_required: bool = True
    active_behavior: bool = False
    default_timeout: int = 30
    max_timeout: int = 120
    max_requests: int = 100
    rate_limit_rps: float = 5.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "provider_type": self.provider_type.value,
            "display_name": self.display_name,
            "requires_external_network": self.requires_external_network,
            "requires_subprocess": self.requires_subprocess,
            "safety_level": self.safety_level,
            "authorization_required": self.authorization_required,
            "active_behavior": self.active_behavior,
            "default_timeout": self.default_timeout,
            "max_timeout": self.max_timeout,
            "max_requests": self.max_requests,
            "rate_limit_rps": self.rate_limit_rps,
        }


@dataclass
class ReconContext:
    """Runtime context passed to all reconnaissance providers."""
    campaign_id: str
    target: str
    execution_mode: ReconExecutionMode = ReconExecutionMode.AUDIT
    authorization_record_id: Optional[str] = None
    operator_id: Optional[str] = None
    operator_confirmed: bool = False
    in_scope_assets: List[str] = field(default_factory=list)
    out_of_scope_assets: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=lambda: [80, 443])
    excluded_ports: List[int] = field(default_factory=list)
    request_budget: int = 200
    concurrency_limit: int = 5
    rate_limit: float = 5.0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def is_live_allowed(self) -> bool:
        """Check if context fulfills mandatory preconditions for live recon execution."""
        return (
            self.execution_mode == ReconExecutionMode.AUTHORIZED_LIVE_RECON
            and bool(self.authorization_record_id)
            and self.operator_confirmed
            and bool(self.target)
            and "*" not in self.target
        )


@dataclass
class NormalizedReconAsset:
    """Canonical representation of any asset discovered during reconnaissance."""
    asset_id: str
    raw_value: str
    normalized_value: str
    asset_type: str  # DOMAIN, SUBDOMAIN, IP_ADDRESS, URL, ENDPOINT, SERVICE
    source_provider: str
    provider_version: Optional[str] = None
    confidence: float = 1.0
    status: ReconAssetStatus = ReconAssetStatus.DISCOVERED
    is_executable: bool = False  # Critical rule: False by default; discoveries cannot be attacked directly
    metadata: Dict[str, Any] = field(default_factory=dict)
    evidence_hash: Optional[str] = None
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "raw_value": self.raw_value,
            "normalized_value": self.normalized_value,
            "asset_type": self.asset_type,
            "source_provider": self.source_provider,
            "provider_version": self.provider_version,
            "confidence": self.confidence,
            "status": self.status.value if hasattr(self.status, "value") else str(self.status),
            "is_executable": self.is_executable,
            "metadata": self.metadata,
            "evidence_hash": self.evidence_hash,
            "discovered_at": self.discovered_at,
        }
