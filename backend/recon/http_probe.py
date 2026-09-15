"""AihaX HTTP/HTTPS Probing, Soft-404 Baseline, and Redirect Intelligence Engine."""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from backend.core.scope_validator import ScopeValidator
from backend.recon.models import DiscoveredAsset, HttpProbeResult
from backend.services.request_engine import BaseAsyncTransport, RequestEngine, RequestSpec, RequestTimeout

logger = logging.getLogger("backend.recon.http_probe")


class HttpProbeEngine:
    """Probes in-scope web assets with deterministic redirect tracking and soft-404 detection."""

    def __init__(
        self,
        request_engine: RequestEngine,
        scope_validator: ScopeValidator,
        max_redirects: int = 5,
    ):
        self.request_engine = request_engine
        self.scope_validator = scope_validator
        self.max_redirects = max_redirects

    async def probe_asset(self, asset: DiscoveredAsset) -> HttpProbeResult:
        """Probe an in-scope asset, evaluating HTTP accessibility, redirects, and soft-404 behavior."""
        target_url = asset.canonical_url
        parsed = urlparse(target_url)

        # Baseline probe
        spec = RequestSpec(
            method="GET",
            url=target_url,
            headers={"User-Agent": "AihaX-Recon-Engine/1.0 (Authorized Security Audit)"},
            timeout=RequestTimeout(total=10.0),
            follow_redirects=False,  # We follow redirects manually to enforce per-hop scope validation
        )

        resp = await self.request_engine.execute(spec)

        status_code = resp.response_status or 0
        if not resp.success and status_code == 0:
            return HttpProbeResult(
                url=target_url,
                status_code=0,
                accessible=False,
                scheme=parsed.scheme,
                host=parsed.hostname or "",
                port=parsed.port or (443 if parsed.scheme == "https" else 80),
                headers={},
                content_type="unknown",
                response_size=0,
                error=resp.transport_error.get("message") if resp.transport_error else None,
            )

        headers = {k.lower(): v for k, v in resp.response_headers.items()}
        content_type = headers.get("content-type", "")
        server_banner = headers.get("server")
        title = self._extract_title(resp.response_body or "")
        rate_limited = status_code == 429
        retry_after = int(headers.get("retry-after", "0")) if headers.get("retry-after", "").isdigit() else None

        # Redirect Chain Intelligence with Per-Hop Scope Gating
        is_redirect = status_code in (301, 302, 303, 307, 308)
        redirect_target = headers.get("location")
        redirect_chain: list[dict[str, Any]] = []

        if is_redirect and redirect_target:
            current_url = target_url
            next_url = urljoin(current_url, redirect_target)
            redirect_chain.append({
                "source": current_url,
                "status": status_code,
                "destination": next_url,
                "scope_allowed": True,
            })

            # Check if redirect destination is in-scope
            dest_scope = self.scope_validator.validate_target(next_url)
            if not dest_scope.allowed:
                redirect_chain[-1]["scope_allowed"] = False
                redirect_chain[-1]["block_reason"] = "Redirect exits authorized scope"
                logger.info("Redirect to %s blocked: exits scope.", next_url)
            else:
                # Follow subsequent hops within limits
                hops = 1
                curr_status = status_code
                curr_headers = headers
                while hops < self.max_redirects and curr_status in (301, 302, 303, 307, 308):
                    curr_loc = curr_headers.get("location")
                    if not curr_loc:
                        break
                    next_hop = urljoin(current_url, curr_loc)
                    hop_scope = self.scope_validator.validate_target(next_hop)
                    if not hop_scope.allowed:
                        redirect_chain.append({
                            "source": current_url,
                            "status": curr_status,
                            "destination": next_hop,
                            "scope_allowed": False,
                            "block_reason": "Redirect hop exits authorized scope",
                        })
                        break

                    # Fetch next hop safely
                    next_spec = RequestSpec(
                        method="GET",
                        url=next_hop,
                        headers={"User-Agent": "AihaX-Recon-Engine/1.0"},
                        timeout=RequestTimeout(total=5.0),
                        follow_redirects=False,
                    )
                    curr_resp = await self.request_engine.execute(next_spec)
                    curr_status = curr_resp.response_status or 0
                    curr_headers = {k.lower(): v for k, v in curr_resp.response_headers.items()}
                    redirect_chain.append({
                        "source": current_url,
                        "status": curr_status,
                        "destination": next_hop,
                        "scope_allowed": True,
                    })
                    current_url = next_hop
                    hops += 1

        # Deterministic Soft-404 Baseline Detection
        is_soft_404 = await self._detect_soft_404(target_url)

        return HttpProbeResult(
            url=target_url,
            status_code=status_code,
            accessible=True,
            scheme=parsed.scheme,
            host=parsed.hostname or "",
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            headers=headers,
            content_type=content_type,
            response_size=resp.response_size or len((resp.response_body or "").encode("utf-8")),
            title=title,
            server_banner=server_banner,
            is_redirect=is_redirect,
            redirect_target=redirect_target,
            redirect_chain=redirect_chain,
            is_soft_404=is_soft_404,
            rate_limited=rate_limited,
            retry_after=retry_after,
        )

    async def _detect_soft_404(self, base_url: str) -> bool:
        """Detect whether the server returns HTTP 200 with 'Not Found' semantics for non-existent paths."""
        rand_path = f"/.well-known/probe-soft404-{uuid.uuid4().hex[:12]}"
        probe_url = urljoin(base_url, rand_path)

        spec = RequestSpec(
            method="GET",
            url=probe_url,
            headers={"User-Agent": "AihaX-Recon-Engine/1.0"},
            timeout=RequestTimeout(total=5.0),
            follow_redirects=False,
        )
        resp = await self.request_engine.execute(spec)

        if resp.response_status == 200:
            body_lower = (resp.response_body or "").lower()
            soft_404_markers = [
                "404 not found", "page not found", "page cannot be found",
                "does not exist", "cannot find the page", "route not found",
                "unknown path", "nothing here", "error 404"
            ]
            if any(m in body_lower for m in soft_404_markers):
                return True
        return False

    def _extract_title(self, html: str) -> Optional[str]:
        """Safely extract HTML title using non-backtracking regex."""
        if not html:
            return None
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            clean = re.sub(r"\s+", " ", match.group(1)).strip()
            return clean[:200]
        return None
