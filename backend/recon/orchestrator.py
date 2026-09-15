"""AihaX Reconnaissance Orchestrator & Check Planning Engine."""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Set

from backend.core.check_registry import CheckRegistry
from backend.core.scope_validator import ScopeValidator
from backend.recon.asset_discovery import AssetDiscoveryEngine
from backend.recon.auth_mapper import AuthMapper
from backend.recon.capability_mapper import CapabilityMapper
from backend.recon.endpoint_discovery import EndpointDiscoveryEngine
from backend.recon.http_probe import HttpProbeEngine
from backend.recon.models import (
    AssetCapabilities,
    DetectedTechnology,
    DiscoveredAsset,
    DiscoveredEndpoint,
    HttpProbeResult,
    ReconDifferential,
    ReconResult,
)
from backend.recon.technology_detector import TechnologyDetector
from backend.services.campaign_executor import AssetNormalizer
from backend.services.request_engine import AuthenticationContext, RequestEngine

logger = logging.getLogger("backend.recon.orchestrator")


class ReconOrchestrator:
    """End-to-end Reconnaissance & Check Planning Orchestrator."""

    def __init__(
        self,
        request_engine: RequestEngine,
        scope_validator: ScopeValidator,
        max_crawl_depth: int = 2,
        max_endpoints_per_asset: int = 100,
    ):
        self.request_engine = request_engine
        self.scope_validator = scope_validator
        self.asset_engine = AssetDiscoveryEngine(scope_validator=scope_validator)
        self.probe_engine = HttpProbeEngine(request_engine=request_engine, scope_validator=scope_validator)
        self.endpoint_engine = EndpointDiscoveryEngine(
            request_engine=request_engine,
            scope_validator=scope_validator,
            max_crawl_depth=max_crawl_depth,
            max_endpoints_per_asset=max_endpoints_per_asset,
        )
        self.auth_mapper = AuthMapper(request_engine=request_engine)

    async def execute_reconnaissance(
        self,
        campaign_id: str,
        target_domain: str,
        seed_assets: Optional[list[str]] = None,
        auth_contexts: Optional[dict[str, AuthenticationContext]] = None,
        enable_subdomain_discovery: bool = True,
    ) -> ReconResult:
        """Run full reconnaissance pipeline and produce deterministic check execution plan."""
        start_time = time.perf_counter()
        initial_calls = len(getattr(self.request_engine.transport, "calls", []))

        result = ReconResult(campaign_id=campaign_id, target_domain=target_domain)

        # 1. Asset Discovery & Pre-Probe Scope Gating
        in_scope, out_of_scope, safety_events = await self.asset_engine.discover_assets(
            target=target_domain,
            seed_assets=seed_assets,
            enable_subdomain_discovery=enable_subdomain_discovery,
        )
        result.assets_discovered = in_scope + out_of_scope
        result.assets_in_scope = in_scope
        result.assets_out_of_scope = out_of_scope
        result.safety_events.extend(safety_events)

        all_technologies: list[DetectedTechnology] = []
        all_endpoints: list[DiscoveredEndpoint] = []
        probed_services: list[HttpProbeResult] = []
        capabilities_map: dict[str, AssetCapabilities] = {}

        # 2. HTTP Probing for In-Scope Assets Only (Out-of-scope receive ZERO network bytes)
        for asset in in_scope:
            probe = await self.probe_engine.probe_asset(asset)
            probed_services.append(probe)

            # 3. Technology Detection
            techs = TechnologyDetector.detect_technologies(
                headers=probe.headers,
                body_text=probe.title,
                url_path=asset.path,
            )
            all_technologies.extend(techs)

            # 4. Endpoint Discovery
            if probe.accessible:
                eps = await self.endpoint_engine.discover_endpoints(asset=asset)
                # 5. Authentication Mapping
                mapped_eps: list[DiscoveredEndpoint] = []
                for ep in eps:
                    m = await self.auth_mapper.map_authentication_surface(ep, auth_contexts)
                    mapped_eps.append(m)
                all_endpoints.extend(mapped_eps)
            else:
                mapped_eps = []

            # 6. Capability Mapping
            caps = CapabilityMapper.derive_capabilities(
                asset=asset,
                probe_result=probe,
                technologies=techs,
                endpoints=mapped_eps,
            )
            capabilities_map[asset.canonical_url] = caps

        result.probed_services = probed_services
        result.technologies = all_technologies
        result.endpoints = all_endpoints
        result.capabilities = capabilities_map

        # 7. Check Planning (Map Capabilities to C001–C077 Checks)
        result.planned_checks = self.plan_checks_from_capabilities(capabilities_map)

        result.recon_duration = time.perf_counter() - start_time
        final_calls = len(getattr(self.request_engine.transport, "calls", []))
        result.recon_requests_used = max(0, final_calls - initial_calls)

        return result

    def plan_checks_from_capabilities(
        self,
        capabilities_map: dict[str, AssetCapabilities],
    ) -> list[str]:
        """Deterministically map discovered capabilities and tech stack to eligible C001–C077 checks."""
        planned: set[str] = set()

        # Universal web checks (applicable to all HTTP/HTTPS assets)
        planned.update([
            "C001_Open_Port_80",
            "C002_Missing_Security_Headers",
            "C003_Sensitive_Files_Exposure",
            "C004_CORS_Misconfiguration",
            "C006_Directory_Listing",
            "C007_Open_Redirect",
            "C010_TLS_Configuration",
            "C011_Technology_Exposure",
            "C013_Weak_Session_Cookie",
            "C014_Missing_Secure_Cookie",
            "C015_Missing_HttpOnly_Cookie",
            "C016_Missing_SameSite_Cookie",
            "C047_Missing_CSP",
            "C048_Weak_CSP",
            "C049_Clickjacking",
            "C050_MIME_Sniffing",
            "C051_Cross_Domain_Policy",
            "C052_Insecure_HTTP_Methods",
            "C053_Default_Setup_Page",
            "C054_Verbose_Error_Disclosure",
            "C057_Exposed_API_Keys",
            "C058_Source_Map_Exposure",
            "C059_PII_URL_Exposure",
            "C060_Comment_Information_Disclosure",
            "C061_Backup_File_Exposure",
            "C062_Database_Dump_Exposure",
            "C064_Git_Metadata_Exposure",
            "C065_Unencrypted_Transmission",
            "C066_Cleartext_Storage_Indicators",
        ])

        # Check capability-specific mappings
        for url, caps in capabilities_map.items():
            if caps.graphql:
                planned.add("C005_GraphQL_Introspection")

            if caps.file_upload:
                planned.add("C055_Dangerous_File_Upload")

            if caps.browser_required:
                planned.add("C039_DOM_XSS_Indicators")

            if caps.api:
                planned.update([
                    "C067_IDOR_Numeric_IDs",
                    "C068_IDOR_UUIDs",
                    "C069_BOLA_API",
                    "C070_Mass_Assignment",
                    "C071_Privilege_Escalation",
                    "C072_Function_Access_Control",
                ])

            if caps.authentication:
                planned.update([
                    "C012_Auth_Bypass_Indicators",
                    "C017_Session_Fixation",
                    "C018_Session_Invalidation",
                    "C019_Password_Policy_Weakness",
                    "C020_JWT_Algorithm_Weakness",
                    "C021_JWT_Claim_Validation",
                    "C022_Auth_Rate_Limit",
                    "C077_Missing_Reauthentication",
                ])

            if caps.workflow_required:
                planned.update([
                    "C073_Parameter_Tampering",
                    "C074_Workflow_Step_Skipping",
                    "C075_Race_Condition",
                    "C076_Replay_Attack",
                ])

            # Injection checks
            planned.update([
                "C023_SQL_Injection",
                "C024_Blind_SQL_Injection",
                "C025_NoSQL_Injection",
                "C026_Command_Injection_Indicators",
                "C027_OS_Command_Injection",
                "C028_SSTI",
                "C029_Header_Injection",
                "C030_CRLF_Injection",
                "C031_Path_Traversal",
                "C032_Local_File_Inclusion",
                "C033_XXE_Indicators",
                "C034_LDAP_Injection",
                "C035_EL_Injection",
                "C036_SSRF_Indicators",
                "C037_Reflected_XSS",
                "C038_Stored_XSS",
                "C040_HTML_Context_Injection",
                "C041_Attribute_Context_Injection",
                "C042_JavaScript_Context_Injection",
                "C043_URL_Context_Injection",
                "C044_Mutation_XSS",
                "C045_XSS_Filter_Bypass",
                "C046_Unsafe_HTML_Rendering",
                "C056_Path_Normalization",
            ])

        # Filter against CheckRegistry to ensure only valid implemented checks are in plan
        from backend.core.check_registry import registry
        registered = set([c.id for c in registry.list_checks()])
        final_plan = sorted([c for c in planned if c in registered])
        return final_plan

    @classmethod
    def compute_differential(
        cls,
        previous: ReconResult,
        current: ReconResult,
    ) -> ReconDifferential:
        """Compute differential change set between two reconnaissance runs."""
        prev_assets = {a.canonical_url for a in previous.assets_in_scope}
        curr_assets = {a.canonical_url for a in current.assets_in_scope}

        prev_endpoints = {e.url for e in previous.endpoints}
        curr_endpoints = {e.url for e in current.endpoints}

        prev_techs = {f"{t.name}:{t.version or ''}" for t in previous.technologies}
        curr_techs = {f"{t.name}:{t.version or ''}" for t in current.technologies}

        new_assets = sorted(list(curr_assets - prev_assets))
        removed_assets = sorted(list(prev_assets - curr_assets))
        new_endpoints = sorted(list(curr_endpoints - prev_endpoints))
        removed_endpoints = sorted(list(prev_endpoints - curr_endpoints))
        new_techs = sorted(list(curr_techs - prev_techs))

        # Changed capabilities
        changed_caps: dict[str, dict[str, Any]] = {}
        for url in curr_assets.intersection(prev_assets):
            prev_cap = previous.capabilities.get(url)
            curr_cap = current.capabilities.get(url)
            if prev_cap and curr_cap and prev_cap.to_dict() != curr_cap.to_dict():
                changed_caps[url] = {
                    "previous": prev_cap.to_dict(),
                    "current": curr_cap.to_dict(),
                }

        return ReconDifferential(
            target_domain=current.target_domain,
            new_assets=new_assets,
            removed_assets=removed_assets,
            new_endpoints=new_endpoints,
            removed_endpoints=removed_endpoints,
            new_technologies=new_techs,
            changed_capabilities=changed_caps,
        )
