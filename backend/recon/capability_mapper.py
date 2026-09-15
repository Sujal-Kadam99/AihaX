"""AihaX Asset Capability Derivation Engine."""

from __future__ import annotations

from typing import List, Optional

from backend.recon.models import (
    AssetCapabilities,
    AuthRequirement,
    DetectedTechnology,
    DiscoveredAsset,
    DiscoveredEndpoint,
    EndpointType,
    HttpProbeResult,
)


class CapabilityMapper:
    """Derives observable application capabilities strictly from evidence."""

    @classmethod
    def derive_capabilities(
        cls,
        asset: DiscoveredAsset,
        probe_result: Optional[HttpProbeResult] = None,
        technologies: Optional[list[DetectedTechnology]] = None,
        endpoints: Optional[list[DiscoveredEndpoint]] = None,
    ) -> AssetCapabilities:
        endpoints = endpoints or []
        technologies = technologies or []

        has_http = probe_result.accessible if probe_result else True
        has_https = (probe_result.scheme == "https") if probe_result else (asset.scheme == "https")

        # 1. API Capability
        has_api = (
            any(e.is_api or e.endpoint_type == EndpointType.API for e in endpoints)
            or (probe_result and "application/json" in probe_result.content_type.lower())
            or asset.hostname.lower().startswith("api.")
        )

        # 2. GraphQL Capability
        has_graphql = (
            any(e.is_graphql or e.endpoint_type == EndpointType.GRAPHQL for e in endpoints)
            or any(t.name.lower() == "graphql" for t in technologies)
            or "/graphql" in asset.canonical_url
        )

        # 3. Authentication Capability
        has_auth = (
            any(e.endpoint_type == EndpointType.AUTHENTICATION or e.auth_required == AuthRequirement.AUTHENTICATION_REQUIRED for e in endpoints)
            or (probe_result and probe_result.status_code in (401, 403))
            or asset.hostname.lower().startswith("auth.")
        )

        # 4. File Upload Capability
        has_upload = any(e.is_upload or e.endpoint_type == EndpointType.FILE_UPLOAD for e in endpoints)

        # 5. Browser Required (SPA / Client-Side Rendering)
        has_browser = any(
            t.name.lower() in ("react", "next.js", "nuxt.js", "vue", "angular") for t in technologies
        )

        # 6. Workflow Required
        has_workflow = any(
            "/checkout" in e.path or "/onboarding" in e.path or "/wizard" in e.path for e in endpoints
        )

        # 7. Collect HTTP Methods
        methods = list(set([e.method for e in endpoints if e.method] + ["GET", "POST"]))

        # 8. Determine Auth Type
        auth_type = None
        if has_auth:
            for e in endpoints:
                if e.content_type and e.content_type.startswith("AuthScheme:"):
                    auth_type = e.content_type.split(":", 1)[1]
                    break
            if not auth_type:
                auth_type = "Bearer" if has_api else "Cookie"

        return AssetCapabilities(
            http=has_http,
            https=has_https,
            api=has_api,
            graphql=has_graphql,
            authentication=has_auth,
            file_upload=has_upload,
            browser_required=has_browser,
            workflow_required=has_workflow,
            supported_methods=methods,
            auth_type=auth_type,
            server_banner=probe_result.server_banner if probe_result else None,
            technologies=technologies,
        )
