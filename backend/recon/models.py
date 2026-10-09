"""AihaX Reconnaissance and Asset Intelligence Data Models."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union


class AssetType(str, Enum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    WEB_APPLICATION = "WEB_APPLICATION"
    API = "API"
    GRAPHQL = "GRAPHQL"
    STATIC_APPLICATION = "STATIC_APPLICATION"
    AUTHENTICATED_APPLICATION = "AUTHENTICATED_APPLICATION"


class DiscoverySource(str, Enum):
    PROGRAM_SCOPE = "PROGRAM_SCOPE"
    USER_INPUT = "USER_INPUT"
    DNS_RESOLUTION = "DNS_RESOLUTION"
    CERTIFICATE_TRANSPARENCY = "CERTIFICATE_TRANSPARENCY"
    PASSIVE_FEED = "PASSIVE_FEED"
    SCOPED_WORDLIST = "SCOPED_WORDLIST"
    ROBOTS_TXT = "ROBOTS_TXT"
    SITEMAP_XML = "SITEMAP_XML"
    HTML_CRAWL = "HTML_CRAWL"
    JS_ANALYSIS = "JS_ANALYSIS"
    OPENAPI_SPEC = "OPENAPI_SPEC"


class EndpointType(str, Enum):
    PAGE = "PAGE"
    API = "API"
    GRAPHQL = "GRAPHQL"
    FILE_UPLOAD = "FILE_UPLOAD"
    AUTHENTICATION = "AUTHENTICATION"
    STATIC_ASSET = "STATIC_ASSET"
    ADMIN_INTERFACE = "ADMIN_INTERFACE"


class AuthRequirement(str, Enum):
    PUBLIC = "PUBLIC"
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    UNKNOWN = "UNKNOWN"


class Confidence(str, Enum):
    CERTAIN = "CERTAIN"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class DiscoveredAsset:
    asset_id: str
    raw_asset: str
    canonical_url: str
    hostname: str
    scheme: str
    port: int
    path: str
    asset_type: AssetType
    source: DiscoverySource
    scope_status: str  # IN_SCOPE, OUT_OF_SCOPE, DENIED_BY_DEFAULT
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    parent_asset: Optional[str] = None
    discovery_method: str = "direct"
    ip_addresses: list[str] = field(default_factory=list)
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DetectedTechnology:
    name: str
    version: Optional[str] = None
    category: str = "Web Technology"
    confidence: Confidence = Confidence.HIGH
    evidence_source: str = "HEADER"  # HEADER, COOKIE, HTML_BODY, JS_SOURCE, META_TAG, JSON_KEY
    evidence_snippet: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DiscoveredEndpoint:
    endpoint_id: str
    url: str
    path: str
    method: str = "GET"
    endpoint_type: EndpointType = EndpointType.PAGE
    source: DiscoverySource = DiscoverySource.HTML_CRAWL
    parameters: list[str] = field(default_factory=list)
    parameter_locations: dict[str, list[str]] = field(default_factory=dict)
    auth_required: AuthRequirement = AuthRequirement.UNKNOWN
    content_type: Optional[str] = None
    status_code: Optional[int] = None
    is_api: bool = False
    is_graphql: bool = False
    is_upload: bool = False
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AssetCapabilities:
    http: bool = True
    https: bool = True
    api: bool = False
    graphql: bool = False
    authentication: bool = False
    file_upload: bool = False
    browser_required: bool = False
    workflow_required: bool = False
    supported_methods: list[str] = field(default_factory=lambda: ["GET", "POST"])
    auth_type: Optional[str] = None  # None, "Bearer", "Cookie", "Basic"
    server_banner: Optional[str] = None
    technologies: list[DetectedTechnology] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "http": self.http,
            "https": self.https,
            "api": self.api,
            "graphql": self.graphql,
            "authentication": self.authentication,
            "file_upload": self.file_upload,
            "browser_required": self.browser_required,
            "workflow_required": self.workflow_required,
            "supported_methods": self.supported_methods,
            "auth_type": self.auth_type,
            "server_banner": self.server_banner,
            "technologies": [t.to_dict() for t in self.technologies],
        }


@dataclass
class HttpProbeResult:
    url: str
    status_code: int
    accessible: bool
    scheme: str
    host: str
    port: int
    headers: dict[str, str]
    content_type: str
    response_size: int
    title: Optional[str] = None
    server_banner: Optional[str] = None
    is_redirect: bool = False
    redirect_target: Optional[str] = None
    redirect_chain: list[dict[str, Any]] = field(default_factory=list)
    is_soft_404: bool = False
    rate_limited: bool = False
    retry_after: Optional[int] = None
    error: Optional[str] = None


@dataclass
class ReconResult:
    campaign_id: str
    target_domain: str
    assets_discovered: list[DiscoveredAsset] = field(default_factory=list)
    assets_in_scope: list[DiscoveredAsset] = field(default_factory=list)
    assets_out_of_scope: list[DiscoveredAsset] = field(default_factory=list)
    probed_services: list[HttpProbeResult] = field(default_factory=list)
    technologies: list[DetectedTechnology] = field(default_factory=list)
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    capabilities: dict[str, AssetCapabilities] = field(default_factory=dict)
    planned_checks: list[str] = field(default_factory=list)
    recon_duration: float = 0.0
    recon_requests_used: int = 0
    safety_events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def api_endpoints(self) -> list[DiscoveredEndpoint]:
        return [e for e in self.endpoints if e.is_api or e.endpoint_type == EndpointType.API]

    @property
    def graphql_endpoints(self) -> list[DiscoveredEndpoint]:
        return [e for e in self.endpoints if e.is_graphql or e.endpoint_type == EndpointType.GRAPHQL]

    @property
    def upload_surfaces(self) -> list[DiscoveredEndpoint]:
        return [e for e in self.endpoints if e.is_upload or e.endpoint_type == EndpointType.FILE_UPLOAD]

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "target_domain": self.target_domain,
            "assets_discovered_count": len(self.assets_discovered),
            "assets_in_scope_count": len(self.assets_in_scope),
            "assets_out_of_scope_count": len(self.assets_out_of_scope),
            "http_services_count": len(self.probed_services),
            "technologies_count": len(self.technologies),
            "endpoints_count": len(self.endpoints),
            "api_endpoints_count": len(self.api_endpoints),
            "graphql_endpoints_count": len(self.graphql_endpoints),
            "upload_surfaces_count": len(self.upload_surfaces),
            "planned_checks_count": len(self.planned_checks),
            "recon_duration": self.recon_duration,
            "recon_requests_used": self.recon_requests_used,
            "safety_events_count": len(self.safety_events),
        }


@dataclass
class ReconDifferential:
    target_domain: str
    new_assets: list[str] = field(default_factory=list)
    removed_assets: list[str] = field(default_factory=list)
    new_endpoints: list[str] = field(default_factory=list)
    removed_endpoints: list[str] = field(default_factory=list)
    new_technologies: list[str] = field(default_factory=list)
    changed_capabilities: dict[str, dict[str, Any]] = field(default_factory=dict)
