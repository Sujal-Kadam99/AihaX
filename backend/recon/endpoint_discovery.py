"""AihaX Endpoint Discovery Engine (Robots, Sitemap, HTML Crawler, JS Analysis, OpenAPI, GraphQL)."""

from __future__ import annotations

import json
import logging
import re
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlparse

from backend.core.scope_validator import ScopeValidator
from backend.recon.models import (
    AuthRequirement,
    DiscoveredAsset,
    DiscoveredEndpoint,
    DiscoverySource,
    EndpointType,
)
from backend.services.campaign_executor import AssetNormalizer
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout

logger = logging.getLogger("backend.recon.endpoint_discovery")


class EndpointDiscoveryEngine:
    """Safe, scope-gated endpoint discovery engine."""

    def __init__(
        self,
        request_engine: RequestEngine,
        scope_validator: ScopeValidator,
        max_crawl_depth: int = 2,
        max_endpoints_per_asset: int = 100,
    ):
        self.request_engine = request_engine
        self.scope_validator = scope_validator
        self.max_crawl_depth = max_crawl_depth
        self.max_endpoints_per_asset = max_endpoints_per_asset

    async def discover_endpoints(
        self,
        asset: DiscoveredAsset,
        crawl_html: bool = True,
        probe_apis: bool = True,
    ) -> list[DiscoveredEndpoint]:
        """Discover endpoints across robots.txt, sitemaps, HTML links/forms, JS routes, and OpenAPI."""
        base_url = asset.canonical_url.rstrip("/")
        discovered: list[DiscoveredEndpoint] = []
        seen_urls: set[str] = set()

        def add_endpoint(
            url: str,
            method: str = "GET",
            ep_type: EndpointType = EndpointType.PAGE,
            source: DiscoverySource = DiscoverySource.HTML_CRAWL,
            params: Optional[list[str]] = None,
            content_type: Optional[str] = None,
            status_code: Optional[int] = None,
            is_api: bool = False,
            is_graphql: bool = False,
            is_upload: bool = False,
            auth_req: AuthRequirement = AuthRequirement.UNKNOWN,
        ):
            # Strict scope gate before accepting endpoint
            scope_dec = self.scope_validator.validate_target(url)
            if not scope_dec.allowed:
                return

            # Keep query parameter names as observed input metadata, but do not
            # retain potentially sensitive values in the discovered URL.
            source_query_params = list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())

            # Canonical URL fingerprint
            try:
                norm = AssetNormalizer.normalize(url)
                canonical_url = norm.canonical_url
            except Exception:
                canonical_url = url

            key = f"{method}:{canonical_url}"
            if key in seen_urls:
                return
            seen_urls.add(key)

            if len(discovered) >= self.max_endpoints_per_asset:
                return

            parsed = urlparse(canonical_url)
            all_params = list(dict.fromkeys((params or []) + source_query_params))

            discovered.append(DiscoveredEndpoint(
                endpoint_id=str(uuid.uuid4()),
                url=canonical_url,
                path=parsed.path or "/",
                method=method.upper(),
                endpoint_type=ep_type,
                source=source,
                parameters=all_params,
                auth_required=auth_req,
                content_type=content_type,
                status_code=status_code,
                is_api=is_api or "/api/" in parsed.path or parsed.path.startswith("/api"),
                is_graphql=is_graphql or "/graphql" in parsed.path,
                is_upload=is_upload,
            ))

        parsed_asset = urlparse(asset.canonical_url)
        origin = f"{parsed_asset.scheme}://{parsed_asset.netloc}"

        # 1. Discover via robots.txt
        await self._discover_robots_txt(origin, add_endpoint)

        # 2. Discover via sitemap.xml
        await self._discover_sitemap_xml(origin, add_endpoint)

        # 3. Discover OpenAPI / Swagger specs
        if probe_apis:
            await self._discover_openapi_specs(origin, add_endpoint)
            await self._probe_graphql_endpoint(origin, add_endpoint)

        # 4. Crawl HTML Root & Extract Links / Forms / Scripts
        if crawl_html:
            await self._crawl_html_page(asset.canonical_url, origin, 0, add_endpoint)

        return discovered

    async def _discover_robots_txt(self, base_url: str, add_fn):
        """Parse robots.txt for disallowed and allowed paths."""
        robots_url = urljoin(base_url + "/", "robots.txt")
        spec = RequestSpec(method="GET", url=robots_url, timeout=RequestTimeout(total=5.0))
        resp = await self.request_engine.execute(spec)
        if resp.response_status == 200 and resp.response_body:
            for line in resp.response_body.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        path = parts[1].strip()
                        if path and not path.startswith("*"):
                            full_url = urljoin(base_url + "/", path.lstrip("/"))
                            add_fn(full_url, method="GET", ep_type=EndpointType.PAGE, source=DiscoverySource.ROBOTS_TXT)

    async def _discover_sitemap_xml(self, base_url: str, add_fn):
        """Parse sitemap.xml for URLs."""
        sitemap_url = urljoin(base_url + "/", "sitemap.xml")
        spec = RequestSpec(method="GET", url=sitemap_url, timeout=RequestTimeout(total=5.0))
        resp = await self.request_engine.execute(spec)
        if resp.response_status == 200 and resp.response_body and ("<urlset" in resp.response_body or "<sitemapindex" in resp.response_body):
            try:
                # Safe XML parsing: remove namespaces or match tag ends
                root = ET.fromstring(resp.response_body)
                for elem in root.iter():
                    if elem.tag.endswith("loc") and elem.text:
                        clean_loc = elem.text.strip()
                        full_url = urljoin(base_url + "/", clean_loc.lstrip("/"))
                        add_fn(full_url, method="GET", ep_type=EndpointType.PAGE, source=DiscoverySource.SITEMAP_XML)
            except Exception as err:
                logger.debug("Failed parsing sitemap.xml: %s", err)

    async def _discover_openapi_specs(self, base_url: str, add_fn):
        """Probe for OpenAPI / Swagger specifications and extract documented endpoints."""
        candidate_paths = ["/openapi.json", "/swagger.json", "/api/openapi.json", "/v1/api-docs"]
        for path in candidate_paths:
            probe_url = urljoin(base_url + "/", path.lstrip("/"))
            spec = RequestSpec(method="GET", url=probe_url, timeout=RequestTimeout(total=5.0))
            resp = await self.request_engine.execute(spec)
            if resp.response_status == 200 and resp.response_body:
                try:
                    data = json.loads(resp.response_body)
                    if isinstance(data, dict) and ("paths" in data or "swagger" in data or "openapi" in data):
                        # Register the specification endpoint itself
                        add_fn(probe_url, method="GET", ep_type=EndpointType.API, source=DiscoverySource.OPENAPI_SPEC, is_api=True)
                        paths = data.get("paths", {})
                        if isinstance(paths, dict):
                            for route, methods in paths.items():
                                if isinstance(methods, dict):
                                    for http_method, details in methods.items():
                                        if http_method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                                            params = []
                                            if isinstance(details, dict) and "parameters" in details:
                                                for p in details["parameters"]:
                                                    if isinstance(p, dict) and "name" in p:
                                                        params.append(p["name"])
                                            route_url = urljoin(base_url + "/", route.lstrip("/"))
                                            add_fn(
                                                route_url,
                                                method=http_method.upper(),
                                                ep_type=EndpointType.API,
                                                source=DiscoverySource.OPENAPI_SPEC,
                                                params=params,
                                                is_api=True,
                                            )
                        break
                except Exception:
                    continue

    async def _probe_graphql_endpoint(self, base_url: str, add_fn):
        """Safely probe for GraphQL endpoints."""
        candidates = ["/graphql", "/api/graphql", "/v1/graphql"]
        for path in candidates:
            probe_url = urljoin(base_url + "/", path.lstrip("/"))
            spec = RequestSpec(
                method="POST",
                url=probe_url,
                headers={"Content-Type": "application/json"},
                body=b'{"query":"{__typename}"}',
                timeout=RequestTimeout(total=5.0),
            )
            resp = await self.request_engine.execute(spec)
            if resp.response_status == 200 and resp.response_body and ("__typename" in resp.response_body or "data" in resp.response_body):
                add_fn(probe_url, method="POST", ep_type=EndpointType.GRAPHQL, source=DiscoverySource.HTML_CRAWL, is_graphql=True)
                break

    async def _crawl_html_page(self, current_url: str, base_url: str, depth: int, add_fn):
        """Crawl an HTML page to extract links, forms, scripts, and JS endpoints."""
        if depth > self.max_crawl_depth:
            return

        spec = RequestSpec(method="GET", url=current_url, timeout=RequestTimeout(total=5.0))
        resp = await self.request_engine.execute(spec)
        if resp.response_status != 200 or not resp.response_body:
            return

        html = resp.response_body
        headers_lower = {k.lower(): v for k, v in resp.response_headers.items()}
        content_type = headers_lower.get("content-type", "").lower()
        if not ("text/html" in content_type or "application/xhtml" in content_type or "<html" in html.lower() or "<form" in html.lower()):
            return

        # 1. Extract <a href="...">
        hrefs = re.findall(r'<a[^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for href in hrefs:
            if href.startswith("javascript:") or href.startswith("mailto:") or href.startswith("tel:"):
                continue
            full_url = urljoin(current_url, href)
            # Register in-scope link
            add_fn(full_url, method="GET", ep_type=EndpointType.PAGE, source=DiscoverySource.HTML_CRAWL)

        # 2. Extract <form action="..." method="...">
        forms = re.findall(r'<form\b([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
        for form_attrs, form_body in forms:
            action_m = re.search(r'action=["\']([^"\']*)["\']', form_attrs, re.IGNORECASE)
            method_m = re.search(r'method=["\']([^"\']*)["\']', form_attrs, re.IGNORECASE)
            enctype_m = re.search(r'enctype=["\']([^"\']*)["\']', form_attrs, re.IGNORECASE)

            action = action_m.group(1) if action_m else current_url
            method = (method_m.group(1) if method_m else "GET").upper()
            is_upload = (enctype_m and "multipart/form-data" in enctype_m.group(1).lower()) or 'type="file"' in form_body.lower()

            # Extract input parameter names
            input_names = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form_body, re.IGNORECASE)
            select_names = re.findall(r'<select[^>]+name=["\']([^"\']+)["\']', form_body, re.IGNORECASE)
            textarea_names = re.findall(r'<textarea[^>]+name=["\']([^"\']+)["\']', form_body, re.IGNORECASE)
            params = list(set(input_names + select_names + textarea_names))

            form_url = urljoin(current_url, action)
            ep_type = EndpointType.FILE_UPLOAD if is_upload else EndpointType.PAGE
            add_fn(
                form_url,
                method=method,
                ep_type=ep_type,
                source=DiscoverySource.HTML_CRAWL,
                params=params,
                is_upload=is_upload,
            )

        # 3. Extract <script src="..."> and scan external JS
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for script_src in scripts:
            js_url = urljoin(current_url, script_src)
            # If the script is within the target origin, fetch and analyze for API routes
            if self.scope_validator.validate_target(js_url).allowed:
                await self._analyze_javascript_file(js_url, base_url, add_fn)

    async def _analyze_javascript_file(self, js_url: str, base_url: str, add_fn):
        """Analyze JavaScript bundle for endpoint patterns without executing arbitrary code."""
        spec = RequestSpec(method="GET", url=js_url, timeout=RequestTimeout(total=5.0))
        resp = await self.request_engine.execute(spec)
        if resp.response_status != 200 or not resp.response_body:
            return

        js_content = resp.response_body
        # Extract literal API/REST routes from both ordinary strings and JS
        # template strings. Dynamic values are replaced with a benign marker;
        # only route and parameter names are passed to later checks.
        route_pattern = re.compile(
            r"/(?:api|rest|v[0-9]+|graphql)/[A-Za-z0-9_/${}.?=&:%-]+",
            re.IGNORECASE,
        )
        seen_routes: set[tuple[str, str]] = set()
        for match in route_pattern.finditer(js_content):
            route = re.sub(r"\$\{[^}]*\}", "1", match.group(0))
            route = route.rstrip(".,;)")
            if not route.startswith("/"):
                continue

            method = "POST" if "/graphql" in route.lower() else "GET"
            prefix = js_content[max(0, match.start() - 180):match.start()]
            for candidate_method in ("POST", "PUT", "PATCH", "DELETE"):
                if re.search(rf"\.\s*{candidate_method.lower()}\s*\([^)]*$", prefix, re.IGNORECASE):
                    method = candidate_method
                    break

            route_url = urljoin(base_url.rstrip("/") + "/", route.lstrip("/"))
            route_params = list(parse_qs(urlparse(route_url).query, keep_blank_values=True).keys())
            # Store a clean endpoint URL and carry query parameter names in
            # metadata. Parameter values from source code can be dynamic or
            # sensitive and must not be replayed as-is.
            route_url = urlparse(route_url)._replace(query="", fragment="").geturl()
            route_key = (method, route_url)
            if route_key in seen_routes:
                continue
            seen_routes.add(route_key)
            is_graphql = "/graphql" in route_url.lower()
            add_fn(
                route_url,
                method=method,
                ep_type=EndpointType.GRAPHQL if is_graphql else EndpointType.API,
                source=DiscoverySource.JS_ANALYSIS,
                params=route_params,
                is_api=True,
                is_graphql=is_graphql,
            )

        # Existing patterns cover common API client forms and versioned routes.
        api_patterns = [
            r'["\'](/api/v[0-9]/[a-zA-Z0-9_\-/]+)["\']',
            r'["\'](/api/[a-zA-Z0-9_\-/]+)["\']',
            r'["\'](/v[0-9]/[a-zA-Z0-9_\-/]+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
        ]

        for pattern in api_patterns:
            matches = re.findall(pattern, js_content)
            for m in matches:
                if m.startswith("/") or m.startswith("http://") or m.startswith("https://"):
                    full_url = urljoin(base_url + "/", m.lstrip("/"))
                    is_graphql = "/graphql" in full_url or "/graphql" in m
                    add_fn(
                        full_url,
                        method="POST" if is_graphql else "GET",
                        ep_type=EndpointType.GRAPHQL if is_graphql else EndpointType.API,
                        source=DiscoverySource.JS_ANALYSIS,
                        is_api=True,
                        is_graphql=is_graphql,
                    )
