"""Passive discovery and asset inventory services."""

from backend.services.discovery.base_provider import (
    BasePassiveProvider,
    DiscoveredItem,
    generate_passive_evidence_id,
)
from backend.services.discovery.crtsh_provider import CRTShProvider
from backend.services.discovery.wayback_provider import WaybackProvider
from backend.services.discovery.alienvault_provider import AlienVaultProvider
from backend.services.discovery.dns_provider import DNSProvider
from backend.services.discovery.normalizer import (
    AssetType,
    normalize_asset,
    normalize_domain,
    normalize_ip,
    normalize_query,
    normalize_url,
)

__all__ = [
    "BasePassiveProvider",
    "DiscoveredItem",
    "generate_passive_evidence_id",
    "CRTShProvider",
    "WaybackProvider",
    "AlienVaultProvider",
    "DNSProvider",
    "AssetType",
    "normalize_asset",
    "normalize_domain",
    "normalize_ip",
    "normalize_query",
    "normalize_url",
]
