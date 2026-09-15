"""AlienVault OTX Passive DNS Discovery Provider.

Queries AlienVault Open Threat Exchange passive DNS indicators without target probing.
Uses RequestEngine for all network requests.
Extracts and normalizes hostnames, IPv4, IPv6, and CNAME records.
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
from backend.services.discovery.normalizer import (
    AssetType,
    normalize_domain,
    normalize_ip,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout

logger = logging.getLogger(__name__)


class AlienVaultProvider(BasePassiveProvider):
    """Passive discovery provider querying AlienVault OTX passive DNS API."""

    source_code: str = "SRC_ALIENVAULT_OTX"
    source_name: str = "AlienVault OTX Passive DNS"
    default_confidence: int = 85
    rate_limit_rps: float = 3.0
    timeout_seconds: float = 20.0

    async def discover(
        self,
        domain: str,
        request_engine: RequestEngine,
        config: Optional[dict[str, Any]] = None,
    ) -> list[DiscoveredItem]:
        """Query AlienVault OTX passive DNS for the target domain."""
        try:
            clean_domain = normalize_domain(domain)
        except ValueError:
            logger.warning(f"AlienVaultProvider: invalid input domain {domain!r}")
            return []

        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{clean_domain}/passive_dns"

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
            logger.debug(f"AlienVaultProvider: query for {clean_domain} returned no valid response: {evidence.transport_error}")
            return []

        try:
            data = json.loads(evidence.response_body)
            if not isinstance(data, dict):
                return []
        except Exception as err:
            logger.warning(f"AlienVaultProvider: failed to parse JSON from AlienVault: {err}")
            return []

        records = data.get("passive_dns", [])
        if not isinstance(records, list):
            return []

        discovered: list[DiscoveredItem] = []
        seen_assets: set[tuple[str, str]] = set()

        for record in records:
            if not isinstance(record, dict):
                continue

            raw_hostname = record.get("hostname", "")
            raw_address = record.get("address", "")
            record_type = str(record.get("record_type", "")).upper()

            # 1. Process Hostname
            if raw_hostname:
                try:
                    norm_host = normalize_domain(raw_hostname)
                    if norm_host == clean_domain or norm_host.endswith(f".{clean_domain}"):
                        host_type = AssetType.DOMAIN.value if norm_host == clean_domain else AssetType.SUBDOMAIN.value
                        if (host_type, norm_host) not in seen_assets:
                            seen_assets.add((host_type, norm_host))
                            host_ev_id = generate_passive_evidence_id(self.source_code, clean_domain, norm_host)
                            
                            # Attach DNS records if present
                            dns_rec: dict[str, list[str]] = {}
                            if record_type in ("A", "AAAA", "CNAME") and raw_address:
                                dns_rec[record_type] = [raw_address]

                            discovered.append(
                                DiscoveredItem(
                                    asset_type=host_type,
                                    raw_value=raw_hostname,
                                    normalized_value=norm_host,
                                    source_code=self.source_code,
                                    confidence=self.default_confidence,
                                    raw_data=record,
                                    request_id=evidence.request_id,
                                    evidence_id=host_ev_id,
                                    dns_records=dns_rec or None,
                                )
                            )
                except ValueError:
                    pass

            # 2. Process IP address if record_type is A or AAAA
            if raw_address and record_type in ("A", "AAAA"):
                try:
                    norm_ip = normalize_ip(raw_address)
                    ip_type = AssetType.IP_ADDRESS.value
                    if (ip_type, norm_ip) not in seen_assets:
                        seen_assets.add((ip_type, norm_ip))
                        ip_ev_id = generate_passive_evidence_id(self.source_code, clean_domain, norm_ip)
                        discovered.append(
                            DiscoveredItem(
                                asset_type=ip_type,
                                raw_value=raw_address,
                                normalized_value=norm_ip,
                                source_code=self.source_code,
                                confidence=self.default_confidence,
                                raw_data=record,
                                request_id=evidence.request_id,
                                evidence_id=ip_ev_id,
                                dns_records={record_type: [norm_ip]},
                            )
                        )
                except ValueError:
                    pass

        return discovered
