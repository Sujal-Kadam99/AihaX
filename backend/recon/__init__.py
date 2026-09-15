"""AihaX Reconnaissance, Asset Intelligence, and Check Orchestration Module."""

from backend.recon.asset_discovery import AssetDiscoveryEngine, PassiveFeedProvider, ScopedWordlistProvider, SubdomainDiscoveryProvider
from backend.recon.auth_mapper import AuthMapper
from backend.recon.capability_mapper import CapabilityMapper
from backend.recon.endpoint_discovery import EndpointDiscoveryEngine
from backend.recon.http_probe import HttpProbeEngine
from backend.recon.models import (
    AssetCapabilities,
    AssetType,
    AuthRequirement,
    Confidence,
    DetectedTechnology,
    DiscoveredAsset,
    DiscoveredEndpoint,
    DiscoverySource,
    EndpointType,
    HttpProbeResult,
    ReconDifferential,
    ReconResult,
)
from backend.recon.orchestrator import ReconOrchestrator
from backend.recon.technology_detector import TechnologyDetector

__all__ = [
    "AssetCapabilities",
    "AssetDiscoveryEngine",
    "AssetType",
    "AuthMapper",
    "AuthRequirement",
    "CapabilityMapper",
    "Confidence",
    "DetectedTechnology",
    "DiscoveredAsset",
    "DiscoveredEndpoint",
    "DiscoverySource",
    "EndpointDiscoveryEngine",
    "EndpointType",
    "HttpProbeEngine",
    "HttpProbeResult",
    "PassiveFeedProvider",
    "ReconDifferential",
    "ReconOrchestrator",
    "ReconResult",
    "ScopedWordlistProvider",
    "SubdomainDiscoveryProvider",
    "TechnologyDetector",
    # Phase 24 Unified Recon Architecture
    "ReconExecutionMode",
    "ReconAssetStatus",
    "ProviderStatus",
    "ProviderType",
    "ReconContext",
    "NormalizedReconAsset",
    "ReconPreflightGate",
    "ReconPreflightDecision",
    "PreflightStatus",
    "CanonicalReconSnapshot",
    "UnifiedReconOrchestrator",
    "SubfinderProvider",
    "AmassProvider",
    "Sublist3rProvider",
    "CertificateTransparencyProvider",
    "DNSProviderAdapter",
    "HttpProbeProvider",
    "TechnologyFingerprintProvider",
]

from backend.recon.recon_modes import (
    NormalizedReconAsset,
    ProviderMetadata,
    ProviderStatus,
    ProviderType,
    ReconAssetStatus,
    ReconContext,
    ReconExecutionMode,
)
from backend.recon.recon_preflight import PreflightStatus, ReconPreflightDecision, ReconPreflightGate
from backend.recon.snapshot import CanonicalReconSnapshot
from backend.recon.providers import (
    AmassProvider,
    CertificateTransparencyProvider,
    DNSProviderAdapter,
    HttpProbeProvider,
    SubfinderProvider,
    Sublist3rProvider,
    TechnologyFingerprintProvider,
)
from backend.recon.recon_orchestrator import UnifiedReconOrchestrator
