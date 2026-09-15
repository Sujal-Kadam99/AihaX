"""AihaX Asset Discovery Engine with Strict Scope Pre-Flight Gating."""

from __future__ import annotations

import logging
import uuid
from typing import Any, List, Optional, Protocol, Sequence
from urllib.parse import urlparse

from backend.core.scope_validator import ScopeDecision, ScopeValidator
from backend.recon.models import AssetType, DiscoveredAsset, DiscoverySource
from backend.services.campaign_executor import AssetNormalizer, CanonicalAsset

logger = logging.getLogger("backend.recon.asset_discovery")


class SubdomainDiscoveryProvider(Protocol):
    """Protocol for pluggable subdomain and asset discovery providers."""
    name: str

    async def discover(self, domain: str) -> list[tuple[str, DiscoverySource]]:
        ...


class ScopedWordlistProvider:
    """Discovers subdomains using a standard authorized wordlist."""
    name = "scoped_wordlist"

    def __init__(self, subdomains: Optional[list[str]] = None):
        self.subdomains = subdomains or [
            "api", "app", "auth", "admin", "dev", "stage", "cdn", "v1", "v2", "graphql", "internal"
        ]

    async def discover(self, domain: str) -> list[tuple[str, DiscoverySource]]:
        results: list[tuple[str, DiscoverySource]] = []
        clean_domain = domain.lower().lstrip(".").split(":")[0]
        for sub in self.subdomains:
            candidate = f"{sub}.{clean_domain}"
            results.append((candidate, DiscoverySource.SCOPED_WORDLIST))
        return results


class PassiveFeedProvider:
    """Configurable passive discovery feed interface (e.g. Certificate Transparency / AlienVault)."""
    name = "passive_feed"

    def __init__(self, api_key: Optional[str] = None, enabled: bool = False):
        self.api_key = api_key
        self.enabled = enabled

    async def discover(self, domain: str) -> list[tuple[str, DiscoverySource]]:
        if not self.enabled:
            logger.info("Passive feed provider disabled or unconfigured (PROVIDER_UNAVAILABLE).")
            return []
        # When enabled with credentials, queries passive certificates
        return []


class AssetDiscoveryEngine:
    """Orchestrates asset discovery with strict pre-probe ScopeValidator gating."""

    def __init__(
        self,
        scope_validator: ScopeValidator,
        providers: Optional[list[SubdomainDiscoveryProvider]] = None,
    ):
        self.scope_validator = scope_validator
        self.providers = providers or [ScopedWordlistProvider()]

    async def discover_assets(
        self,
        target: str,
        seed_assets: Optional[list[str]] = None,
        enable_subdomain_discovery: bool = True,
    ) -> tuple[list[DiscoveredAsset], list[DiscoveredAsset], list[dict[str, Any]]]:
        """Discover and classify assets, enforcing default-deny scope gating before any probing.

        Returns:
            (in_scope_assets, out_of_scope_assets, safety_events)
        """
        raw_candidates: list[tuple[str, DiscoverySource, Optional[str]]] = []
        safety_events: list[dict[str, Any]] = []

        # 1. Target root asset
        raw_candidates.append((target, DiscoverySource.USER_INPUT, None))

        # 2. Seed assets
        if seed_assets:
            for s in seed_assets:
                raw_candidates.append((s, DiscoverySource.PROGRAM_SCOPE, target))

        # 3. Provider-based discovery
        if enable_subdomain_discovery:
            parsed = urlparse(target if "://" in target else f"https://{target}")
            domain = parsed.hostname or parsed.netloc or target
            for provider in self.providers:
                try:
                    discovered = await provider.discover(domain)
                    for item, src in discovered:
                        raw_candidates.append((f"https://{item}", src, target))
                except Exception as err:
                    logger.warning("Provider %s failed during discovery: %s", getattr(provider, "name", "unknown"), err)

        # 4. Normalize and deduplicate
        seen_urls: set[str] = set()
        in_scope: list[DiscoveredAsset] = []
        out_of_scope: list[DiscoveredAsset] = []

        for raw_item, source, parent in raw_candidates:
            try:
                canonical = AssetNormalizer.normalize(raw_item)
            except Exception:
                continue

            if canonical.canonical_url in seen_urls:
                continue
            seen_urls.add(canonical.canonical_url)

            # Classify Asset Type
            asset_type = self._classify_asset_type(canonical)

            # Strict Pre-Probe Scope Evaluation
            scope_decision = self.scope_validator.validate_target(canonical.canonical_url)

            if scope_decision.allowed:
                discovered_asset = DiscoveredAsset(
                    asset_id=str(uuid.uuid4()),
                    raw_asset=raw_item,
                    canonical_url=canonical.canonical_url,
                    hostname=canonical.host,
                    scheme=canonical.scheme,
                    port=canonical.port,
                    path=canonical.path,
                    asset_type=asset_type,
                    source=source,
                    scope_status="IN_SCOPE",
                    parent_asset=parent,
                    discovery_method="automated_recon",
                )
                in_scope.append(discovered_asset)
            else:
                discovered_asset = DiscoveredAsset(
                    asset_id=str(uuid.uuid4()),
                    raw_asset=raw_item,
                    canonical_url=canonical.canonical_url,
                    hostname=canonical.host,
                    scheme=canonical.scheme,
                    port=canonical.port,
                    path=canonical.path,
                    asset_type=asset_type,
                    source=source,
                    scope_status="OUT_OF_SCOPE",
                    parent_asset=parent,
                    discovery_method="automated_recon",
                )
                out_of_scope.append(discovered_asset)
                safety_events.append({
                    "action": "asset_blocked_out_of_scope",
                    "reason": scope_decision.reason,
                    "target": canonical.canonical_url,
                })

        return in_scope, out_of_scope, safety_events

    def _classify_asset_type(self, canonical: CanonicalAsset) -> AssetType:
        """Classify asset type from structural properties."""
        host = canonical.host.lower()
        if host.startswith("api.") or "/api" in canonical.path:
            return AssetType.API
        if host.startswith("graphql.") or "/graphql" in canonical.path:
            return AssetType.GRAPHQL
        if host.startswith("auth.") or "/login" in canonical.path or "/oauth" in canonical.path:
            return AssetType.AUTHENTICATED_APPLICATION
        if host.count(".") > 1:
            return AssetType.SUBDOMAIN
        return AssetType.DOMAIN
