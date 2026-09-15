"""CRT.sh Certificate Transparency Passive Discovery Provider.

Queries public Certificate Transparency logs via crt.sh without target probing.
Uses RequestEngine for all network requests.
Normalizes and deduplicates all discovered domain names.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from backend.services.discovery.base_provider import (
    BasePassiveProvider,
    DiscoveredItem,
    generate_passive_evidence_id,
)
from backend.services.discovery.normalizer import AssetType, normalize_domain
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout

logger = logging.getLogger(__name__)


class CRTShProvider(BasePassiveProvider):
    """Passive discovery provider querying crt.sh Certificate Transparency logs."""

    source_code: str = "SRC_CRTSH"
    source_name: str = "crt.sh Certificate Transparency"
    default_confidence: int = 90
    rate_limit_rps: float = 1.0
    timeout_seconds: float = 20.0

    async def discover(
        self,
        domain: str,
        request_engine: RequestEngine,
        config: Optional[dict[str, Any]] = None,
    ) -> list[DiscoveredItem]:
        """Query crt.sh for certificate transparency records matching the domain."""
        try:
            clean_domain = normalize_domain(domain)
        except ValueError:
            logger.warning(f"CRTShProvider: invalid input domain {domain!r}")
            return []

        url = f"https://crt.sh/?q=%.{clean_domain}&output=json"

        spec = RequestSpec(
            url=url,
            method="GET",
            headers={
                "User-Agent": "AihaX-Passive-Recon/1.0",
                "Accept": "application/json",
            },
            timeout=RequestTimeout(connect=5.0, read=15.0, total=self.timeout_seconds),
            authorization_confirmed=True,
        )

        evidence = await request_engine.execute(spec)

        if evidence.response_status != 200 or not evidence.response_body:
            logger.debug(f"CRTShProvider: query for {clean_domain} returned no valid response: {evidence.transport_error}")
            return []

        try:
            data = json.loads(evidence.response_body)
            if not isinstance(data, list):
                return []
        except Exception as err:
            logger.warning(f"CRTShProvider: failed to parse JSON from crt.sh: {err}")
            return []

        discovered: list[DiscoveredItem] = []
        seen_values: set[str] = set()

        for entry in data:
            if not isinstance(entry, dict):
                continue

            # Extract raw domain names from name_value and common_name
            raw_candidates: list[str] = []
            if "name_value" in entry and isinstance(entry["name_value"], str):
                # May contain multiple names separated by \n or comma
                raw_candidates.extend(entry["name_value"].split("\n"))
            if "common_name" in entry and isinstance(entry["common_name"], str):
                raw_candidates.append(entry["common_name"])

            for raw_candidate in raw_candidates:
                raw_trimmed = raw_candidate.strip()
                if not raw_trimmed:
                    continue

                try:
                    norm_val = normalize_domain(raw_trimmed)
                except ValueError:
                    # Malformed or invalid domain name in CT log, skip safely
                    continue

                # Ensure the discovered domain is relevant to the queried domain
                if not (norm_val == clean_domain or norm_val.endswith(f".{clean_domain}")):
                    continue

                if norm_val in seen_values:
                    continue
                seen_values.add(norm_val)

                # Classify type
                asset_type = (
                    AssetType.DOMAIN.value
                    if norm_val == clean_domain
                    else AssetType.SUBDOMAIN.value
                )

                evidence_id = generate_passive_evidence_id(self.source_code, clean_domain, norm_val)

                discovered.append(
                    DiscoveredItem(
                        asset_type=asset_type,
                        raw_value=raw_trimmed,
                        normalized_value=norm_val,
                        source_code=self.source_code,
                        confidence=self.default_confidence,
                        raw_data=entry,
                        request_id=evidence.request_id,
                        evidence_id=evidence_id,
                    )
                )

        return discovered
