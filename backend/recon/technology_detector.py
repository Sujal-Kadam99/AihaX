"""AihaX Deterministic Evidence-Backed Technology Fingerprinting Engine."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from backend.recon.models import Confidence, DetectedTechnology


class TechnologyDetector:
    """Detects software, frameworks, and servers strictly from observable HTTP evidence."""

    @classmethod
    def detect_technologies(
        cls,
        headers: dict[str, str],
        cookies: Optional[dict[str, str]] = None,
        body_text: Optional[str] = None,
        url_path: Optional[str] = None,
    ) -> list[DetectedTechnology]:
        technologies: list[DetectedTechnology] = []
        seen: set[str] = set()

        def add_tech(tech: DetectedTechnology):
            key = f"{tech.name}:{tech.version or ''}"
            if key not in seen:
                seen.add(key)
                technologies.append(tech)

        norm_headers = {k.lower(): v for k, v in headers.items()}
        cookies = cookies or {}
        body = body_text or ""

        # 1. Server Header Detection
        server_val = norm_headers.get("server")
        if server_val:
            server_match = re.search(r"([a-zA-Z0-9_\-]+)(?:/([0-9.]+))?", server_val)
            if server_match:
                name = server_match.group(1).title()
                version = server_match.group(2)
                add_tech(DetectedTechnology(
                    name=name,
                    version=version,
                    category="Web Server",
                    confidence=Confidence.CERTAIN,
                    evidence_source="HEADER",
                    evidence_snippet=f"Server: {server_val}",
                ))

        # 2. X-Powered-By Header
        powered_by = norm_headers.get("x-powered-by")
        if powered_by:
            pb_match = re.search(r"([a-zA-Z0-9_\-]+)(?:/([0-9.]+))?", powered_by)
            if pb_match:
                name = pb_match.group(1)
                version = pb_match.group(2)
                add_tech(DetectedTechnology(
                    name=name,
                    version=version,
                    category="Application Framework",
                    confidence=Confidence.CERTAIN,
                    evidence_source="HEADER",
                    evidence_snippet=f"X-Powered-By: {powered_by}",
                ))

        # 3. ASP.NET & Microsoft Headers
        if "x-aspnet-version" in norm_headers:
            add_tech(DetectedTechnology(
                name="ASP.NET",
                version=norm_headers["x-aspnet-version"],
                category="Application Framework",
                confidence=Confidence.CERTAIN,
                evidence_source="HEADER",
                evidence_snippet=f"X-AspNet-Version: {norm_headers['x-aspnet-version']}",
            ))
        if "x-aspnetmvc-version" in norm_headers:
            add_tech(DetectedTechnology(
                name="ASP.NET MVC",
                version=norm_headers["x-aspnetmvc-version"],
                category="Application Framework",
                confidence=Confidence.CERTAIN,
                evidence_source="HEADER",
                evidence_snippet=f"X-AspNetMvc-Version: {norm_headers['x-aspnetmvc-version']}",
            ))

        # 4. Cookie-based Framework Signatures
        cookie_names = [k.lower() for k in cookies.keys()]
        if any("phpsessid" in c for c in cookie_names):
            add_tech(DetectedTechnology(
                name="PHP",
                version=None,
                category="Programming Language",
                confidence=Confidence.HIGH,
                evidence_source="COOKIE",
                evidence_snippet="Session cookie: PHPSESSID",
            ))
        if any("jsessionid" in c for c in cookie_names):
            add_tech(DetectedTechnology(
                name="Java / Servlet",
                version=None,
                category="Application Server",
                confidence=Confidence.HIGH,
                evidence_source="COOKIE",
                evidence_snippet="Session cookie: JSESSIONID",
            ))
        if any("csrftoken" in c or "django_session" in c for c in cookie_names):
            add_tech(DetectedTechnology(
                name="Django",
                version=None,
                category="Web Framework",
                confidence=Confidence.HIGH,
                evidence_source="COOKIE",
                evidence_snippet="CSRF/Session cookie signature (Django)",
            ))
        if any("laravel_session" in c for c in cookie_names):
            add_tech(DetectedTechnology(
                name="Laravel",
                version=None,
                category="Web Framework",
                confidence=Confidence.HIGH,
                evidence_source="COOKIE",
                evidence_snippet="Session cookie: laravel_session",
            ))
        if any("connect.sid" in c for c in cookie_names):
            add_tech(DetectedTechnology(
                name="Express / Node.js",
                version=None,
                category="Web Framework",
                confidence=Confidence.HIGH,
                evidence_source="COOKIE",
                evidence_snippet="Session cookie: connect.sid",
            ))

        # 5. HTML Meta Tags & Generators
        meta_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
        if not meta_match:
            meta_match = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', body, re.IGNORECASE)
        if meta_match:
            gen_val = meta_match.group(1)
            parts = gen_val.split()
            name = parts[0]
            version = parts[1] if len(parts) > 1 and re.match(r"^[0-9.]+$", parts[1]) else None
            add_tech(DetectedTechnology(
                name=name,
                version=version,
                category="CMS / Generator",
                confidence=Confidence.CERTAIN,
                evidence_source="META_TAG",
                evidence_snippet=meta_match.group(0),
            ))

        # 6. DOM & Frontend Signatures
        if 'id="__next"' in body or "/_next/static/" in body:
            add_tech(DetectedTechnology(
                name="Next.js",
                version=None,
                category="Frontend Framework",
                confidence=Confidence.HIGH,
                evidence_source="HTML_BODY",
                evidence_snippet='Found Next.js container / script path (<div id="__next"> or /_next/static/)',
            ))
        if 'id="__nuxt"' in body or "/_nuxt/" in body:
            add_tech(DetectedTechnology(
                name="Nuxt.js",
                version=None,
                category="Frontend Framework",
                confidence=Confidence.HIGH,
                evidence_source="HTML_BODY",
                evidence_snippet='Found Nuxt.js container (<div id="__nuxt">)',
            ))
        if 'id="root"' in body and ("react" in body.lower() or "bundle.js" in body.lower()):
            add_tech(DetectedTechnology(
                name="React",
                version=None,
                category="JavaScript Library",
                confidence=Confidence.MEDIUM,
                evidence_source="HTML_BODY",
                evidence_snippet='Found React container root (<div id="root">)',
            ))
        if "wp-content/themes" in body or "wp-includes" in body:
            add_tech(DetectedTechnology(
                name="WordPress",
                version=None,
                category="CMS",
                confidence=Confidence.HIGH,
                evidence_source="HTML_BODY",
                evidence_snippet="Found WordPress asset path (wp-content/themes or wp-includes)",
            ))

        # 7. GraphQL and OpenAPI Signatures
        if "__schema" in body or '"graphql"' in body.lower() or (url_path and "/graphql" in url_path):
            add_tech(DetectedTechnology(
                name="GraphQL",
                version=None,
                category="API Architecture",
                confidence=Confidence.CERTAIN,
                evidence_source="HTML_BODY",
                evidence_snippet="GraphQL schema or route pattern observed",
            ))

        return technologies
