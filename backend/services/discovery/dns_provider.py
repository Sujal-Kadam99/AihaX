"""Passive DNS Record Discovery Provider.

Processes passively supplied DNS observation datasets, record dumps, and zone records.
Strictly non-intrusive: Performs ZERO active dictionary brute-forcing or unauthorized zone transfers.
Normalizes all domains, subdomains, and IP addresses deterministically.
"""

from __future__ import annotations

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
from backend.services.request_engine import RequestEngine

logger = logging.getLogger(__name__)


class DNSProvider(BasePassiveProvider):
    """Passive DNS Record Provider processing structured passive DNS inputs and records."""

    source_code: str = "SRC_DNS_RECORD"
    source_name: str = "Passive DNS Record Processor"
    default_confidence: int = 95
    rate_limit_rps: float = 10.0
    timeout_seconds: float = 10.0

    async def discover(
        self,
        domain: str,
        request_engine: RequestEngine,
        config: Optional[dict[str, Any]] = None,
    ) -> list[DiscoveredItem]:
        """Process passive DNS records supplied via config or passive provider feeds.

        Config may supply 'dns_records': list of dicts, e.g.:
        [
            {"hostname": "api.example.com", "type": "A", "value": "93.184.216.34"},
            {"hostname": "cdn.example.com", "type": "CNAME", "value": "d123.cloudfront.net"},
            {"hostname": "ipv6.example.com", "type": "AAAA", "value": "2606:2800:220:1:248:1893:25c8:1946"}
        ]
        """
        try:
            clean_domain = normalize_domain(domain)
        except ValueError:
            logger.warning(f"DNSProvider: invalid input domain {domain!r}")
            return []

        config_dict = config or self.config
        records = config_dict.get("dns_records", [])
        if not isinstance(records, list):
            return []

        discovered: list[DiscoveredItem] = []
        seen_assets: set[tuple[str, str]] = set()

        for rec in records:
            if not isinstance(rec, dict):
                continue

            raw_hostname = rec.get("hostname") or rec.get("name") or ""
            rec_type = str(rec.get("type") or rec.get("record_type") or "A").upper()
            raw_value = rec.get("value") or rec.get("address") or rec.get("target") or ""

            # 1. Process Hostname
            if raw_hostname:
                try:
                    norm_host = normalize_domain(raw_hostname)
                    if norm_host == clean_domain or norm_host.endswith(f".{clean_domain}"):
                        host_type = AssetType.DOMAIN.value if norm_host == clean_domain else AssetType.SUBDOMAIN.value
                        if (host_type, norm_host) not in seen_assets:
                            seen_assets.add((host_type, norm_host))
                            host_ev_id = generate_passive_evidence_id(self.source_code, clean_domain, norm_host)
                            
                            dns_rec: dict[str, list[str]] = {}
                            if raw_value:
                                dns_rec[rec_type] = [raw_value]

                            discovered.append(
                                DiscoveredItem(
                                    asset_type=host_type,
                                    raw_value=raw_hostname,
                                    normalized_value=norm_host,
                                    source_code=self.source_code,
                                    confidence=self.default_confidence,
                                    raw_data=rec,
                                    evidence_id=host_ev_id,
                                    dns_records=dns_rec or None,
                                )
                            )
                except ValueError:
                    pass

            # 2. Process IP Addresses from A / AAAA records
            if raw_value and rec_type in ("A", "AAAA"):
                try:
                    norm_ip = normalize_ip(raw_value)
                    ip_type = AssetType.IP_ADDRESS.value
                    if (ip_type, norm_ip) not in seen_assets:
                        seen_assets.add((ip_type, norm_ip))
                        ip_ev_id = generate_passive_evidence_id(self.source_code, clean_domain, norm_ip)
                        discovered.append(
                            DiscoveredItem(
                                asset_type=ip_type,
                                raw_value=raw_value,
                                normalized_value=norm_ip,
                                source_code=self.source_code,
                                confidence=self.default_confidence,
                                raw_data=rec,
                                evidence_id=ip_ev_id,
                                dns_records={rec_type: [norm_ip]},
                            )
                        )
                except ValueError:
                    pass

        return discovered
