"""Wayback Machine Archive.org CDX Passive Endpoint Discovery Provider.

Queries Archive.org CDX API for historical endpoint records without target probing.
Uses RequestEngine for all network requests.
Normalizes, deduplicates, and structures discovered URLs, paths, and parameters.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional
from urllib.parse import urlsplit

from backend.services.discovery.base_provider import (
    BasePassiveProvider,
    DiscoveredItem,
    generate_passive_evidence_id,
)
from backend.services.discovery.normalizer import (
    AssetType,
    normalize_domain,
    normalize_query,
    normalize_url,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout

logger = logging.getLogger(__name__)


class WaybackProvider(BasePassiveProvider):
    """Passive discovery provider querying Archive.org Wayback Machine CDX API."""

    source_code: str = "SRC_WAYBACK"
    source_name: str = "Archive.org Wayback Machine"
    default_confidence: int = 85
    rate_limit_rps: float = 2.0
    timeout_seconds: float = 25.0

    async def discover(
        self,
        domain: str,
        request_engine: RequestEngine,
        config: Optional[dict[str, Any]] = None,
    ) -> list[DiscoveredItem]:
        """Query Wayback CDX API for historical URLs matching the domain."""
        try:
            clean_domain = normalize_domain(domain)
        except ValueError:
            logger.warning(f"WaybackProvider: invalid input domain {domain!r}")
            return []

        url = f"https://web.archive.org/cdx/search/cdx?url=*.{clean_domain}/*&output=json&fl=original&collapse=urlkey"

        spec = RequestSpec(
            url=url,
            method="GET",
            headers={
                "User-Agent": "AihaX-Passive-Recon/1.0",
                "Accept": "application/json",
            },
            timeout=RequestTimeout(connect=5.0, read=20.0, total=self.timeout_seconds),
            authorization_confirmed=True,
        )

        evidence = await request_engine.execute(spec)

        if evidence.response_status != 200 or not evidence.response_body:
            logger.debug(f"WaybackProvider: query for {clean_domain} returned no valid response: {evidence.transport_error}")
            return []

        try:
            data = json.loads(evidence.response_body)
            if not isinstance(data, list) or len(data) <= 1:
                return []
        except Exception as err:
            logger.warning(f"WaybackProvider: failed to parse JSON from Wayback: {err}")
            return []

        discovered: list[DiscoveredItem] = []
        seen_endpoints: set[str] = set()
        seen_hosts: set[str] = set()

        # Row 0 is header e.g. ["original"]
        url_rows = data[1:]

        for row in url_rows:
            if not isinstance(row, list) or not row:
                continue

            raw_url = str(row[0]).strip()
            if not raw_url:
                continue

            try:
                norm_url = normalize_url(raw_url)
            except ValueError:
                # Malformed URL from archive, skip safely
                continue

            parsed = urlsplit(norm_url)
            host = parsed.hostname
            if not host:
                continue

            try:
                norm_host = normalize_domain(host)
            except ValueError:
                continue

            # Ensure relevant to domain
            if not (norm_host == clean_domain or norm_host.endswith(f".{clean_domain}")):
                continue

            # 1. Also discover host asset if not seen yet
            if norm_host not in seen_hosts:
                seen_hosts.add(norm_host)
                host_type = AssetType.DOMAIN.value if norm_host == clean_domain else AssetType.SUBDOMAIN.value
                host_ev_id = generate_passive_evidence_id(self.source_code, clean_domain, norm_host)
                discovered.append(
                    DiscoveredItem(
                        asset_type=host_type,
                        raw_value=host,
                        normalized_value=norm_host,
                        source_code=self.source_code,
                        confidence=self.default_confidence,
                        raw_data={"archive_url": raw_url},
                        request_id=evidence.request_id,
                        evidence_id=host_ev_id,
                    )
                )

            # 2. Endpoint Discovery
            if norm_url in seen_endpoints:
                continue
            seen_endpoints.add(norm_url)

            path = parsed.path or "/"
            query = normalize_query(parsed.query)

            evidence_id = generate_passive_evidence_id(self.source_code, clean_domain, norm_url)

            discovered.append(
                DiscoveredItem(
                    asset_type=AssetType.URL.value,
                    raw_value=raw_url,
                    normalized_value=norm_url,
                    source_code=self.source_code,
                    confidence=self.default_confidence,
                    raw_data={"archive_row": row},
                    request_id=evidence.request_id,
                    evidence_id=evidence_id,
                    endpoint_url=norm_url,
                    endpoint_path=path,
                    endpoint_query=query,
                )
            )

        return discovered
