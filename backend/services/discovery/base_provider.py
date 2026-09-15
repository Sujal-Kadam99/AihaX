"""Base Architecture for Passive Discovery Providers in AihaX.

Defines the contract for passive third-party reconnaissance providers.
Enforces:
1. Zero direct traffic to discovered target assets.
2. Mandatory RequestEngine usage for all external HTTP queries.
3. Strict provenance tracking (source_id, request_id, evidence_id, raw_data, confidence).
4. Deterministic normalization via Phase 5.1-B normalizers.
5. Safe failure handling (zero crash, zero false vulnerability findings on HTTP errors).
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Union

from backend.services.discovery.normalizer import AssetType, normalize_domain, normalize_ip, normalize_url
from backend.services.request_engine import RequestEngine


@dataclass
class DiscoveredItem:
    """Canonical structured representation of a passively discovered asset or endpoint."""

    asset_type: str  # DOMAIN, SUBDOMAIN, IP_ADDRESS, URL, ENDPOINT
    raw_value: str
    normalized_value: str
    source_code: str  # SRC_CRTSH, SRC_WAYBACK, SRC_ALIENVAULT_OTX, SRC_DNS_RECORD
    confidence: int = 80
    raw_data: Optional[Union[dict[str, Any], list[Any], str]] = None
    source_id: Optional[str] = None
    request_id: Optional[str] = None
    evidence_id: Optional[str] = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Optional endpoint metadata
    endpoint_url: Optional[str] = None
    endpoint_path: Optional[str] = None
    endpoint_query: Optional[str] = None

    # Optional DNS metadata
    dns_records: Optional[dict[str, Any]] = None

    # Optional Technology Fingerprint metadata
    technology: Optional[str] = None
    version: Optional[str] = None
    detection_rule: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_type": self.asset_type,
            "raw_value": self.raw_value,
            "normalized_value": self.normalized_value,
            "source_code": self.source_code,
            "confidence": self.confidence,
            "raw_data": self.raw_data,
            "source_id": self.source_id,
            "request_id": self.request_id,
            "evidence_id": self.evidence_id,
            "observed_at": self.observed_at.isoformat() if isinstance(self.observed_at, datetime) else self.observed_at,
            "endpoint_url": self.endpoint_url,
            "endpoint_path": self.endpoint_path,
            "endpoint_query": self.endpoint_query,
            "dns_records": self.dns_records,
            "technology": self.technology,
            "version": self.version,
            "detection_rule": self.detection_rule,
        }


def generate_passive_evidence_id(source_code: str, domain: str, raw_item: str) -> str:
    """Generate a deterministic evidence ID for passive discovery provenance."""
    digest = hashlib.sha256(f"{source_code}:{domain}:{raw_item}".encode("utf-8")).hexdigest()[:8].upper()
    return f"EVD-PASSIVE-{digest}"


class BasePassiveProvider(ABC):
    """Abstract base class for all passive reconnaissance providers."""

    source_code: str = "SRC_BASE"
    source_name: str = "Base Passive Provider"
    default_confidence: int = 80
    rate_limit_rps: float = 2.0
    timeout_seconds: float = 15.0

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        self.config = config or {}

    @abstractmethod
    async def discover(
        self,
        domain: str,
        request_engine: RequestEngine,
        config: Optional[dict[str, Any]] = None,
    ) -> list[DiscoveredItem]:
        """Execute passive discovery for the target domain using RequestEngine.

        Must NEVER make direct network requests to the discovered targets.
        Must ONLY query the provider's dedicated public passive API via RequestEngine.
        Must normalize all output assets using Phase 5.1-B normalizers.
        Must return [] on network/HTTP/JSON errors without raising or producing vuln findings.
        """
        pass
