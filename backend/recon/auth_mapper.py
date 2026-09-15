"""AihaX Authentication Surface & Context Mapping Engine."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from backend.recon.models import AuthRequirement, DiscoveredEndpoint, EndpointType
from backend.services.request_engine import AuthenticationContext, RequestEngine, RequestSpec, RequestTimeout

logger = logging.getLogger("backend.recon.auth_mapper")


class AuthMapper:
    """Maps authentication surfaces, login endpoints, and context bindings deterministically."""

    def __init__(self, request_engine: RequestEngine):
        self.request_engine = request_engine

    async def map_authentication_surface(
        self,
        endpoint: DiscoveredEndpoint,
        campaign_auth_contexts: Optional[dict[str, AuthenticationContext]] = None,
    ) -> DiscoveredEndpoint:
        """Probe endpoint for authentication indicators and update auth_required status."""
        spec = RequestSpec(
            method=endpoint.method,
            url=endpoint.url,
            timeout=RequestTimeout(total=5.0),
            follow_redirects=False,
        )

        resp = await self.request_engine.execute(spec)
        headers = {k.lower(): v for k, v in resp.response_headers.items()}
        status_code = resp.response_status or 0

        # 1. Check HTTP Status Code Indicators
        if status_code in (401, 403):
            endpoint.auth_required = AuthRequirement.AUTHENTICATION_REQUIRED
            www_auth = headers.get("www-authenticate")
            if www_auth:
                endpoint.content_type = f"AuthScheme:{www_auth.split()[0]}"
            return endpoint

        # 2. Check for Login Form / Password Inputs
        if status_code == 200 and resp.response_body:
            text = resp.response_body.lower()
            if 'type="password"' in text or 'name="password"' in text or 'name="passwd"' in text:
                endpoint.endpoint_type = EndpointType.AUTHENTICATION
                endpoint.auth_required = AuthRequirement.PUBLIC  # Login form itself is publicly accessible
                return endpoint

        # 3. Check for API / OAuth Token URLs
        parsed = urlparse(endpoint.url)
        if any(p in parsed.path.lower() for p in ("/login", "/signin", "/oauth/token", "/auth/token", "/api/v1/auth")):
            endpoint.endpoint_type = EndpointType.AUTHENTICATION

        if endpoint.auth_required == AuthRequirement.UNKNOWN:
            endpoint.auth_required = AuthRequirement.PUBLIC if status_code == 200 else AuthRequirement.UNKNOWN

        return endpoint
