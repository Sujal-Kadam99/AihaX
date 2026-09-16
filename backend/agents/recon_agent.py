"""AihaX Phase 24 — ReconAgent Adapter & Recon Pipeline Integration.

The authoritative reconnaissance orchestrator for authorized single concrete targets.
All external CLI tools execute exclusively through ToolExecutionBoundary.

Security Invariants:
1. Operates on exactly ONE concrete execution target (wildcards rejected).
2. Upstream authorization and ScopeValidator gating precede all active probes.
3. Destination safety enforcement (anti-SSRF, RFC1918, metadata 169.254.169.254).
4. Zero direct subprocess or shell execution (all tool calls route through ToolExecutionBoundary).
5. Untrusted tool output normalized into structured, deduplicated observations with preserved provenance.
6. Integrates with AttackSurfaceGraphEngine to produce deterministic SHA-256 graph snapshots.
7. Zero plaintext credential persistence.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlparse

# Default wordlist path: {project_root}/wordlists/common.txt
# Resolved relative to this file so it works on any machine or in Docker.
_DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent.parent / "wordlists" / "common.txt"

from sqlalchemy.orm import Session

from backend.agents.base_agent import BaseAgent
from backend.core.redis_client import set_attack_surface
from backend.core.scope_validator import (
    ScopeDecision,
    ScopeStatus,
    ScopeValidator,
    normalize_domain,
    validate_destination_safety,
)
from backend.execution.tool_execution_boundary import (
    ExecutionProfile,
    ToolExecutionBoundary,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from backend.models.database import Scan, get_utc_now
from backend.services.attack_surface_graph import (
    AttackSurfaceEdgeType,
    AttackSurfaceGraphEngine,
    AttackSurfaceGraphSnapshotDTO,
    AttackSurfaceNodeType,
)

logger = logging.getLogger("aihax.recon_agent")


# ==============================================================================
# 1. Observation Categories and DTOs
# ==============================================================================

class ReconObservationCategory(str, Enum):
    SUBDOMAIN = "SUBDOMAIN"
    HOST = "HOST"
    IP_ADDRESS = "IP_ADDRESS"
    PORT = "PORT"
    SERVICE = "SERVICE"
    TECHNOLOGY = "TECHNOLOGY"
    ENDPOINT = "ENDPOINT"
    PARAMETER = "PARAMETER"
    DIRECTORY = "DIRECTORY"
    FILE = "FILE"
    DNS_RECORD = "DNS_RECORD"
    CERTIFICATE = "CERTIFICATE"
    CLOUD_ASSET = "CLOUD_ASSET"
    HISTORICAL_URL = "HISTORICAL_URL"
    REDIRECT = "REDIRECT"
    HEADER = "HEADER"
    COOKIE = "COOKIE"
    API_ROUTE = "API_ROUTE"
    WEBSOCKET_ENDPOINT = "WEBSOCKET_ENDPOINT"


class ReconPipelineStatus(str, Enum):
    READY = "READY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    BLOCKED_AUTHORIZATION = "BLOCKED_AUTHORIZATION"
    BLOCKED_SCOPE = "BLOCKED_SCOPE"
    BLOCKED_SAFETY = "BLOCKED_SAFETY"
    FAILED = "FAILED"


@dataclass
class ReconObservation:
    category: str
    value: str
    normalized_value: str
    discovered_by: List[str]
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    evidence_hash: Optional[str] = None
    first_seen: str = field(default_factory=lambda: get_utc_now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReconExecutionConfig:
    campaign_id: str
    target_url: str
    authorization_confirmed: bool = False
    execution_mode: str = "AUDIT"
    authorization_record_id: Optional[str] = None
    operator_confirmed: bool = False
    in_scope_assets: List[str] = field(default_factory=list)
    out_of_scope_assets: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=list)
    excluded_ports: List[int] = field(default_factory=list)
    enable_subdomain_discovery: bool = True
    enable_port_scan: bool = True
    enable_tech_detection: bool = True
    enable_url_discovery: bool = True
    enable_directory_discovery: bool = True
    enable_active_crawler: bool = True
    enable_dns_analysis: bool = True
    enable_tls_analysis: bool = True
    timeout_per_tool: int = 60
    allow_loopback: bool = False
    wordlist_path: Path = field(default_factory=lambda: _DEFAULT_WORDLIST)


@dataclass
class ReconSnapshot:
    campaign_id: str
    target: str
    status: str
    observations: List[ReconObservation]
    tool_results: Dict[str, Any]
    graph_snapshot: Optional[Dict[str, Any]]
    snapshot_hash: str
    observation_count: int
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: get_utc_now().isoformat())
    completed_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "target": self.target,
            "status": self.status,
            "observations": [o.to_dict() for o in self.observations],
            "tool_results": self.tool_results,
            "graph_snapshot": self.graph_snapshot,
            "snapshot_hash": self.snapshot_hash,
            "observation_count": self.observation_count,
            "warnings": self.warnings,
            "errors": self.errors,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


# ==============================================================================
# 2. Normalization Utilities
# ==============================================================================

def canonicalize_url(url: str) -> str:
    """Canonicalize a URL: lowercase scheme/host, normalize path, strip fragment."""
    if not url or not isinstance(url, str):
        return ""
    u = url.strip()
    if not u.lower().startswith(("http://", "https://")):
        u = "https://" + u
    try:
        parsed = urlparse(u)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        if (scheme == "http" and netloc.endswith(":80")) or (scheme == "https" and netloc.endswith(":443")):
            netloc = netloc.rsplit(":", 1)[0]
        path = parsed.path or "/"
        query = parsed.query
        normalized = f"{scheme}://{netloc}{path}"
        if query:
            normalized += f"?{query}"
        return normalized
    except Exception:
        return url.strip()


def normalize_hostname(host: str) -> str:
    """Normalize domain/hostname: lowercase, strip userinfo, ports, trailing dots."""
    return normalize_domain(host)


# ==============================================================================
# 3. ReconAgent Implementation
# ==============================================================================

class ReconAgent(BaseAgent):
    """Phase 24 Reconnaissance Agent and pipeline orchestrator."""

    agent_id = 1
    agent_name = "Recon Agent"

    def __init__(
        self,
        scan_id: Optional[str] = None,
        db: Optional[Session] = None,
        config: Optional[Dict[str, Any]] = None,
        tool_boundary: Optional[ToolExecutionBoundary] = None,
        dns_resolver: Optional[Callable[[str], Dict[str, List[str]]]] = None,
        tls_inspector: Optional[Callable[[str, int], Dict[str, Any]]] = None,
    ) -> None:
        self.scan_id = scan_id or "default-scan"
        self.db = db
        self.config = config or {}
        self.tool_boundary = tool_boundary or ToolExecutionBoundary()
        self.dns_resolver = dns_resolver
        self.tls_inspector = tls_inspector

    async def execute(self) -> Dict[str, Any]:
        """Execute recon pipeline in backwards-compatible mode for BaseAgent."""
        target_url = self.config.get("target_url") or self.config.get("target", "")
        cfg = ReconExecutionConfig(
            campaign_id=self.scan_id,
            target_url=target_url,
            authorization_confirmed=bool(self.config.get("authorization_confirmed", True)),
            in_scope_assets=self.config.get("in_scope_assets", [target_url] if target_url else []),
            out_of_scope_assets=self.config.get("out_of_scope_assets", []),
            allowed_ports=self.config.get("allowed_ports", []),
            excluded_ports=self.config.get("excluded_ports", []),
            enable_subdomain_discovery=bool(self.config.get("enable_subdomain_discovery", True)),
            enable_port_scan=bool(self.config.get("enable_port_scan", True)),
            enable_tech_detection=bool(self.config.get("enable_tech_detection", True)),
            enable_url_discovery=bool(self.config.get("enable_url_discovery", True)),
            enable_directory_discovery=bool(self.config.get("enable_directory_discovery", True)),
            enable_dns_analysis=bool(self.config.get("enable_dns_analysis", True)),
            enable_tls_analysis=bool(self.config.get("enable_tls_analysis", True)),
            timeout_per_tool=int(self.config.get("timeout_per_tool", 60)),
            allow_loopback=bool(self.config.get("allow_loopback", False)),
            wordlist_path=Path(self.config["wordlist_path"]) if "wordlist_path" in self.config else _DEFAULT_WORDLIST,
        )

        await self.check_cancelled()
        await self.publish_update("running", 10, "Starting Phase 24 Reconnaissance Pipeline...")

        snapshot = await self.execute_recon_pipeline(cfg, db=self.db)
        self.recon_snapshot = snapshot


        # Legacy attack surface dictionary format for older consumers
        attack_surface: Dict[str, Any] = {
            "domain": normalize_hostname(target_url),
            "subdomains": [o.normalized_value for o in snapshot.observations if o.category == ReconObservationCategory.SUBDOMAIN.value],
            "endpoints": [o.normalized_value for o in snapshot.observations if o.category in (ReconObservationCategory.ENDPOINT.value, ReconObservationCategory.HISTORICAL_URL.value)],
            "ports": [o.metadata for o in snapshot.observations if o.category == ReconObservationCategory.PORT.value],
            "tech_stack": [o.metadata for o in snapshot.observations if o.category == ReconObservationCategory.TECHNOLOGY.value],
            "ssl_info": next((o.metadata for o in snapshot.observations if o.category == ReconObservationCategory.CERTIFICATE.value), {}),
            "dns_records": [o.metadata for o in snapshot.observations if o.category == ReconObservationCategory.DNS_RECORD.value],
            "snapshot_hash": snapshot.snapshot_hash,
            "status": snapshot.status,
        }

        await set_attack_surface(self.scan_id, attack_surface)

        if self.db:
            scan = self.db.query(Scan).filter_by(id=self.scan_id).first()
            if scan:
                scan.tech_stack = json.dumps(attack_surface["tech_stack"])
                self.db.commit()

        await self.publish_update("completed", 100, f"Recon complete: {snapshot.observation_count} observations mapped.")
        return attack_surface

    async def execute_recon_pipeline(
        self,
        config: ReconExecutionConfig,
        db: Optional[Session] = None,
    ) -> ReconSnapshot:
        """Run the end-to-end deterministic Phase 24 reconnaissance pipeline."""
        started_at = get_utc_now().isoformat()
        warnings: List[str] = []
        errors: List[str] = []
        raw_observations: List[ReconObservation] = []
        tool_results: Dict[str, Any] = {}

        target_url = (config.target_url or "").strip()

        # 1. Single Concrete Target Precondition Validation
        if not target_url or "," in target_url or " " in target_url:
            errors.append("Target must be a single non-empty concrete URL.")
            return self._build_snapshot(
                config=config,
                status=ReconPipelineStatus.BLOCKED_SAFETY.value,
                observations=[],
                tool_results={},
                graph_snapshot=None,
                warnings=warnings,
                errors=errors,
                started_at=started_at,
            )

        if "*" in target_url:
            errors.append(f"Target '{target_url}' contains wildcards; concrete execution target required.")
            return self._build_snapshot(
                config=config,
                status=ReconPipelineStatus.BLOCKED_SAFETY.value,
                observations=[],
                tool_results={},
                graph_snapshot=None,
                warnings=warnings,
                errors=errors,
                started_at=started_at,
            )

        # 2. ScopeValidator Gating
        in_scope = config.in_scope_assets or [target_url]
        scope_validator = ScopeValidator(
            in_scope_assets=in_scope,
            out_of_scope_assets=config.out_of_scope_assets,
            allowed_ports=config.allowed_ports,
            excluded_ports=config.excluded_ports,
        )
        scope_decision = scope_validator.validate_target(target_url)
        if not scope_decision.allowed:
            errors.append(f"Target '{target_url}' blocked by ScopeValidator: {scope_decision.reason}")
            return self._build_snapshot(
                config=config,
                status=ReconPipelineStatus.BLOCKED_SCOPE.value,
                observations=[],
                tool_results={},
                graph_snapshot=None,
                warnings=warnings,
                errors=errors,
                started_at=started_at,
            )

        # 3. Destination Safety Gating (Anti-SSRF)
        is_safe, safety_reason = validate_destination_safety(
            target_url,
            allowed_ports=set(config.allowed_ports) if config.allowed_ports else None,
        )
        if not is_safe:
            errors.append(f"Target '{target_url}' blocked by Destination Safety: {safety_reason}")
            return self._build_snapshot(
                config=config,
                status=ReconPipelineStatus.BLOCKED_SAFETY.value,
                observations=[],
                tool_results={},
                graph_snapshot=None,
                warnings=warnings,
                errors=errors,
                started_at=started_at,
            )

        # 4. Authorization Gating for Active Operations
        if not config.authorization_confirmed:
            warnings.append("Authorization not confirmed: active reconnaissance tools (Nmap, Gobuster, etc.) will be disabled.")

        parsed_target = urlparse(target_url)
        domain = parsed_target.hostname or normalize_domain(target_url)
        port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)

        # Register root target observation
        raw_observations.append(
            ReconObservation(
                category=ReconObservationCategory.HOST.value,
                value=domain,
                normalized_value=normalize_hostname(domain),
                discovered_by=["seed_target"],
                confidence=1.0,
                metadata={"target_url": target_url, "scheme": parsed_target.scheme, "port": port},
            )
        )

        # 5. Subdomain Enumeration (Passive: Subfinder & Amass)
        if config.enable_subdomain_discovery:
            # Subfinder
            sub_res = await self.tool_boundary.execute(
                ToolExecutionRequest(
                    campaign_id=config.campaign_id,
                    target=target_url,
                    tool_name="subfinder",
                    execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
                    args=["-d", domain, "-silent"],
                    timeout_seconds=config.timeout_per_tool,
                    authorization_confirmed=config.authorization_confirmed,
                    execution_mode=config.execution_mode,
                    in_scope_assets=in_scope,
                    out_of_scope_assets=config.out_of_scope_assets,
                    allow_loopback=config.allow_loopback,
                ),
                db=db,
            )
            tool_results["subfinder"] = sub_res.to_dict()
            if sub_res.execution_status == ToolExecutionStatus.SUCCESS.value and sub_res.stdout:
                for line in sub_res.stdout.splitlines():
                    sub = line.strip()
                    if sub:
                        raw_observations.append(
                            ReconObservation(
                                category=ReconObservationCategory.SUBDOMAIN.value,
                                value=sub,
                                normalized_value=normalize_hostname(sub),
                                discovered_by=["subfinder"],
                                evidence_hash=sub_res.stdout_hash,
                            )
                        )

            # Amass
            amass_res = await self.tool_boundary.execute(
                ToolExecutionRequest(
                    campaign_id=config.campaign_id,
                    target=target_url,
                    tool_name="amass",
                    execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
                    args=["enum", "-passive", "-d", domain],
                    timeout_seconds=config.timeout_per_tool,
                    authorization_confirmed=config.authorization_confirmed,
                    execution_mode=config.execution_mode,
                    in_scope_assets=in_scope,
                    out_of_scope_assets=config.out_of_scope_assets,
                    allow_loopback=config.allow_loopback,
                ),
                db=db,
            )
            tool_results["amass"] = amass_res.to_dict()
            if amass_res.execution_status == ToolExecutionStatus.SUCCESS.value and amass_res.stdout:
                for line in amass_res.stdout.splitlines():
                    sub = line.strip()
                    if sub and not sub.startswith("["):
                        raw_observations.append(
                            ReconObservation(
                                category=ReconObservationCategory.SUBDOMAIN.value,
                                value=sub,
                                normalized_value=normalize_hostname(sub),
                                discovered_by=["amass"],
                                evidence_hash=amass_res.stdout_hash,
                            )
                        )

        # 6. Endpoint & Historical URL Discovery (Passive/Active: GAU & Waybackurls)
        if config.enable_url_discovery:
            # GAU
            gau_res = await self.tool_boundary.execute(
                ToolExecutionRequest(
                    campaign_id=config.campaign_id,
                    target=target_url,
                    tool_name="gau",
                    execution_profile=ExecutionProfile.URL_DISCOVERY.value,
                    args=["--subs", domain],
                    timeout_seconds=config.timeout_per_tool,
                    authorization_confirmed=config.authorization_confirmed,
                    execution_mode=config.execution_mode,
                    in_scope_assets=in_scope,
                    out_of_scope_assets=config.out_of_scope_assets,
                    allow_loopback=config.allow_loopback,
                ),
                db=db,
            )
            tool_results["gau"] = gau_res.to_dict()
            if gau_res.execution_status == ToolExecutionStatus.SUCCESS.value and gau_res.stdout:
                for line in gau_res.stdout.splitlines()[:500]:
                    url = line.strip()
                    if url:
                        canon = canonicalize_url(url)
                        raw_observations.append(
                            ReconObservation(
                                category=ReconObservationCategory.HISTORICAL_URL.value,
                                value=url,
                                normalized_value=canon,
                                discovered_by=["gau"],
                                evidence_hash=gau_res.stdout_hash,
                            )
                        )

            # Waybackurls
            wayback_res = await self.tool_boundary.execute(
                ToolExecutionRequest(
                    campaign_id=config.campaign_id,
                    target=target_url,
                    tool_name="waybackurls",
                    execution_profile=ExecutionProfile.URL_DISCOVERY.value,
                    args=["--no-subs", domain],
                    timeout_seconds=config.timeout_per_tool,
                    authorization_confirmed=config.authorization_confirmed,
                    execution_mode=config.execution_mode,
                    in_scope_assets=in_scope,
                    out_of_scope_assets=config.out_of_scope_assets,
                    allow_loopback=config.allow_loopback,
                ),
                db=db,
            )
            tool_results["waybackurls"] = wayback_res.to_dict()
            if wayback_res.execution_status == ToolExecutionStatus.SUCCESS.value and wayback_res.stdout:
                for line in wayback_res.stdout.splitlines()[:500]:
                    url = line.strip()
                    if url:
                        canon = canonicalize_url(url)
                        raw_observations.append(
                            ReconObservation(
                                category=ReconObservationCategory.HISTORICAL_URL.value,
                                value=url,
                                normalized_value=canon,
                                discovered_by=["waybackurls"],
                                evidence_hash=wayback_res.stdout_hash,
                            )
                        )

            # Katana (Active Crawler)
            if config.enable_active_crawler and config.authorization_confirmed:
                katana_res = await self.tool_boundary.execute(
                    ToolExecutionRequest(
                        campaign_id=config.campaign_id,
                        target=target_url,
                        tool_name="katana",
                        execution_profile=ExecutionProfile.URL_DISCOVERY.value,
                        args=["-u", target_url, "-silent", "-jc", "-d", "1"],
                        timeout_seconds=config.timeout_per_tool * 2,
                        authorization_confirmed=config.authorization_confirmed,
                        execution_mode=config.execution_mode,
                        in_scope_assets=in_scope,
                        out_of_scope_assets=config.out_of_scope_assets,
                        allow_loopback=config.allow_loopback,
                    ),
                    db=db,
                )
                tool_results["katana"] = katana_res.to_dict()
                if katana_res.execution_status == ToolExecutionStatus.SUCCESS.value and katana_res.stdout:
                    import json
                    for line in katana_res.stdout.splitlines()[:500]:
                        try:
                            data = json.loads(line)
                            url = data.get("request", {}).get("endpoint") or data.get("endpoint") or line.strip()
                        except:
                            url = line.strip()
                        if url and url.startswith("http"):
                            canon = canonicalize_url(url)
                            raw_observations.append(
                                ReconObservation(
                                    category=ReconObservationCategory.ENDPOINT.value,
                                    value=url,
                                    normalized_value=canon,
                                    discovered_by=["katana"],
                                    evidence_hash=katana_res.stdout_hash,
                                )
                            )

        # 7. Technology Fingerprinting (WhatWeb)
        if config.enable_tech_detection:
            whatweb_res = await self.tool_boundary.execute(
                ToolExecutionRequest(
                    campaign_id=config.campaign_id,
                    target=target_url,
                    tool_name="whatweb",
                    execution_profile=ExecutionProfile.TECHNOLOGY_FINGERPRINTING.value,
                    args=["--log-json", "-", target_url],
                    timeout_seconds=config.timeout_per_tool,
                    authorization_confirmed=config.authorization_confirmed,
                    execution_mode=config.execution_mode,
                    in_scope_assets=in_scope,
                    out_of_scope_assets=config.out_of_scope_assets,
                    allow_loopback=config.allow_loopback,
                ),
                db=db,
            )
            tool_results["whatweb"] = whatweb_res.to_dict()
            if whatweb_res.execution_status == ToolExecutionStatus.SUCCESS.value and whatweb_res.stdout:
                self._parse_whatweb_output(whatweb_res.stdout, raw_observations, whatweb_res.stdout_hash)

        # 8. Port / Service Scanning (Active: Nmap)
        if config.enable_port_scan and config.authorization_confirmed:
            nmap_res = await self.tool_boundary.execute(
                ToolExecutionRequest(
                    campaign_id=config.campaign_id,
                    target=target_url,
                    tool_name="nmap",
                    execution_profile=ExecutionProfile.PORT_SERVICE_DISCOVERY.value,
                    args=["-sT", "-T4", "--open", domain],
                    timeout_seconds=config.timeout_per_tool,
                    authorization_confirmed=config.authorization_confirmed,
                    execution_mode=config.execution_mode,
                    in_scope_assets=in_scope,
                    out_of_scope_assets=config.out_of_scope_assets,
                    allow_loopback=config.allow_loopback,
                ),
                db=db,
            )
            tool_results["nmap"] = nmap_res.to_dict()
            if nmap_res.execution_status == ToolExecutionStatus.SUCCESS.value and nmap_res.stdout:
                self._parse_nmap_output(nmap_res.stdout, domain, raw_observations, nmap_res.stdout_hash)

        # 9. Directory / File Discovery (Active: Gobuster)
        if config.enable_directory_discovery and config.authorization_confirmed:
            gobuster_res = await self.tool_boundary.execute(
                ToolExecutionRequest(
                    campaign_id=config.campaign_id,
                    target=target_url,
                    tool_name="gobuster",
                    execution_profile=ExecutionProfile.DIRECTORY_DISCOVERY.value,
                    args=["dir", "-u", target_url, "-q", "-w", str(config.wordlist_path)],
                    timeout_seconds=config.timeout_per_tool,
                    authorization_confirmed=config.authorization_confirmed,
                    execution_mode=config.execution_mode,
                    in_scope_assets=in_scope,
                    out_of_scope_assets=config.out_of_scope_assets,
                    allow_loopback=config.allow_loopback,
                ),
                db=db,
            )
            tool_results["gobuster"] = gobuster_res.to_dict()
            if gobuster_res.execution_status == ToolExecutionStatus.SUCCESS.value and gobuster_res.stdout:
                for line in gobuster_res.stdout.splitlines():
                    path_match = line.strip()
                    if path_match.startswith("/"):
                        full_ep = urljoin(target_url, path_match.split()[0])
                        raw_observations.append(
                            ReconObservation(
                                category=ReconObservationCategory.DIRECTORY.value,
                                value=path_match,
                                normalized_value=canonicalize_url(full_ep),
                                discovered_by=["gobuster"],
                                evidence_hash=gobuster_res.stdout_hash,
                            )
                        )

        # 10. Safe DNS Analysis
        if config.enable_dns_analysis:
            self._analyze_dns(domain, raw_observations)

        # 11. Safe TLS Analysis
        if config.enable_tls_analysis and parsed_target.scheme == "https":
            self._analyze_tls(domain, port, raw_observations)

        # 12. Deduplication & Provenance Aggregation
        deduped_observations = self._deduplicate_observations(raw_observations)

        # 13. Attack Surface Graph Integration
        graph_snapshot = self._populate_attack_surface_graph(AttackSurfaceGraphEngine, deduped_observations, config, db)

        # 14. Determine Pipeline Status
        pipeline_status = self._resolve_pipeline_status(tool_results, config.authorization_confirmed)

        return self._build_snapshot(
            config=config,
            status=pipeline_status,
            observations=deduped_observations,
            tool_results=tool_results,
            graph_snapshot=graph_snapshot,
            warnings=warnings,
            errors=errors,
            started_at=started_at,
        )

    # ==========================================================================
    # Parsing, Normalization & Graph Integration Helpers
    # ==========================================================================

    def _parse_whatweb_output(self, stdout: str, obs_list: List[ReconObservation], evidence_hash: Optional[str]) -> None:
        """Parse WhatWeb JSON output into technology observations."""
        try:
            entries = []
            if stdout.strip().startswith("["):
                entries = json.loads(stdout)
            elif stdout.strip().startswith("{"):
                entries = [json.loads(stdout)]
            else:
                for line in stdout.splitlines():
                    line_s = line.strip()
                    if line_s.startswith("{"):
                        try:
                            entries.append(json.loads(line_s))
                        except Exception:
                            pass

            for entry in entries:
                plugins = entry.get("plugins", {})
                for plugin_name, plugin_data in plugins.items():
                    version = None
                    if isinstance(plugin_data, dict):
                        version = plugin_data.get("version") or (plugin_data.get("string", [None])[0] if isinstance(plugin_data.get("string"), list) else None)
                    obs_list.append(
                        ReconObservation(
                            category=ReconObservationCategory.TECHNOLOGY.value,
                            value=plugin_name,
                            normalized_value=plugin_name.strip().lower(),
                            discovered_by=["whatweb"],
                            metadata={"version": version, "plugin": plugin_name},
                            evidence_hash=evidence_hash,
                        )
                    )
        except Exception as e:
            logger.debug(f"WhatWeb JSON parse fallback: {e}")

    def _parse_nmap_output(self, stdout: str, domain: str, obs_list: List[ReconObservation], evidence_hash: Optional[str]) -> None:
        """Parse Nmap port/service output into structured observations."""
        for line in stdout.splitlines():
            line_s = line.strip()
            if "/tcp" in line_s or "/udp" in line_s:
                parts = line_s.split()
                if len(parts) >= 3 and parts[1] == "open":
                    port_proto = parts[0]
                    port_num = int(port_proto.split("/")[0]) if "/" in port_proto else 0
                    proto = port_proto.split("/")[1] if "/" in port_proto else "tcp"
                    service = parts[2]
                    obs_list.append(
                        ReconObservation(
                            category=ReconObservationCategory.PORT.value,
                            value=f"{port_num}/{proto}",
                            normalized_value=f"{domain}:{port_num}",
                            discovered_by=["nmap"],
                            metadata={"port": port_num, "protocol": proto, "service": service},
                            evidence_hash=evidence_hash,
                        )
                    )

    def _analyze_dns(self, domain: str, obs_list: List[ReconObservation]) -> None:
        """Analyze DNS records safely."""
        if self.dns_resolver is not None:
            try:
                records = self.dns_resolver(domain)
                for rec_type, vals in records.items():
                    for val in vals:
                        obs_list.append(
                            ReconObservation(
                                category=ReconObservationCategory.DNS_RECORD.value,
                                value=f"{rec_type} {val}",
                                normalized_value=f"{domain}:{rec_type.upper()}:{val.strip().lower()}",
                                discovered_by=["dns_analysis"],
                                metadata={"type": rec_type.upper(), "value": val},
                            )
                        )
            except Exception as e:
                logger.debug(f"Custom DNS resolver failed: {e}")

    def _analyze_tls(self, domain: str, port: int, obs_list: List[ReconObservation]) -> None:
        """Inspect TLS certificate safely."""
        if self.tls_inspector is not None:
            try:
                tls_info = self.tls_inspector(domain, port)
                issuer = tls_info.get("issuer", "unknown")
                obs_list.append(
                    ReconObservation(
                        category=ReconObservationCategory.CERTIFICATE.value,
                        value=f"Issuer: {issuer}",
                        normalized_value=f"{domain}:tls:{issuer.lower()}",
                        discovered_by=["tls_analysis"],
                        metadata=tls_info,
                    )
                )
            except Exception as e:
                logger.debug(f"Custom TLS inspector failed: {e}")

    def _deduplicate_observations(self, observations: List[ReconObservation]) -> List[ReconObservation]:
        """Merge identical observations and aggregate discovery provenance."""
        merged: Dict[Tuple[str, str], ReconObservation] = {}

        for obs in observations:
            key = (obs.category, obs.normalized_value)
            if key not in merged:
                merged[key] = ReconObservation(
                    category=obs.category,
                    value=obs.value,
                    normalized_value=obs.normalized_value,
                    discovered_by=list(obs.discovered_by),
                    confidence=obs.confidence,
                    metadata=dict(obs.metadata),
                    evidence_hash=obs.evidence_hash,
                    first_seen=obs.first_seen,
                )
            else:
                existing = merged[key]
                # Combine provenance
                for src in obs.discovered_by:
                    if src not in existing.discovered_by:
                        existing.discovered_by.append(src)
                existing.discovered_by.sort()
                # Merge metadata
                existing.metadata.update(obs.metadata)

        # Sort observations deterministically
        sorted_obs = sorted(merged.values(), key=lambda o: (o.category, o.normalized_value))
        return sorted_obs

    def _populate_attack_surface_graph(
        self,
        engine: AttackSurfaceGraphEngine,
        observations: List[ReconObservation],
        config: ReconExecutionConfig,
        db: Optional[Session],
    ) -> Dict[str, Any]:
        """Populate AttackSurfaceGraphEngine with normalized observations."""
        nodes: List[Any] = []
        edges: List[Any] = []

        # 1. Add Target Node
        tgt_node = engine.add_target(
            campaign_id=config.campaign_id,
            target=config.target_url,
            source="RECON_AGENT",
            db=db,
        )
        nodes.append(tgt_node)

        for obs in observations:
            if obs.category in (ReconObservationCategory.HISTORICAL_URL.value, ReconObservationCategory.ENDPOINT.value, ReconObservationCategory.DIRECTORY.value):
                try:
                    parsed = urlparse(obs.normalized_value)
                    endpoint = parsed.path or "/"
                    ep_node = engine.add_endpoint(
                        campaign_id=config.campaign_id,
                        target=config.target_url,
                        endpoint=endpoint,
                        source=",".join(obs.discovered_by),
                        db=db,
                    )
                    nodes.append(ep_node)

                    # Create edge from target to endpoint
                    rel_edge = engine.add_relationship(
                        campaign_id=config.campaign_id,
                        source_node_id=tgt_node.id,
                        destination_node_id=ep_node.id,
                        edge_type=AttackSurfaceEdgeType.LINK,
                        db=db,
                    )
                    edges.append(rel_edge)

                    # Extract query parameters
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for param_name in params.keys():
                            p_node = engine.add_parameter(
                                campaign_id=config.campaign_id,
                                target=config.target_url,
                                endpoint=endpoint,
                                parameter=param_name,
                                source=",".join(obs.discovered_by),
                                db=db,
                            )
                            nodes.append(p_node)
                            p_edge = engine.add_relationship(
                                campaign_id=config.campaign_id,
                                source_node_id=ep_node.id,
                                destination_node_id=p_node.id,
                                edge_type=AttackSurfaceEdgeType.PARAMETER_RELATION,
                                db=db,
                            )
                            edges.append(p_edge)
                except Exception:
                    pass

        # Deduplicate node and edge DTOs by id
        unique_nodes = list({n.id: n for n in nodes}.values())
        unique_edges = list({e.id: e for e in edges}.values())

        snap_hash = engine.compute_snapshot_hash(unique_nodes, unique_edges)
        snapshot_dto = AttackSurfaceGraphSnapshotDTO(
            campaign_id=config.campaign_id,
            target=config.target_url,
            nodes=unique_nodes,
            edges=unique_edges,
            snapshot_hash=snap_hash,
            node_count=len(unique_nodes),
            edge_count=len(unique_edges),
        )
        return snapshot_dto.to_dict()

    def _resolve_pipeline_status(self, tool_results: Dict[str, Any], authorization_confirmed: bool) -> str:
        """Resolve overall pipeline status deterministically."""
        if not tool_results:
            return ReconPipelineStatus.COMPLETED.value

        statuses = [res.get("execution_status") for res in tool_results.values()]

        if all(s == ToolExecutionStatus.SUCCESS.value for s in statuses):
            return ReconPipelineStatus.COMPLETED.value

        if any(s == ToolExecutionStatus.SUCCESS.value for s in statuses):
            return ReconPipelineStatus.PARTIAL_SUCCESS.value

        if any(s == ToolExecutionStatus.BLOCKED_AUTHORIZATION.value for s in statuses):
            return ReconPipelineStatus.BLOCKED_AUTHORIZATION.value

        return ReconPipelineStatus.FAILED.value

    def _build_snapshot(
        self,
        config: ReconExecutionConfig,
        status: str,
        observations: List[ReconObservation],
        tool_results: Dict[str, Any],
        graph_snapshot: Optional[Dict[str, Any]],
        warnings: List[str],
        errors: List[str],
        started_at: str,
    ) -> ReconSnapshot:
        """Build deterministic ReconSnapshot with SHA-256 hash."""
        completed_at = get_utc_now().isoformat()

        # Compute deterministic content hash over sorted canonical observations & graph hash
        obs_payload = [
            f"{o.category}:{o.normalized_value}:{','.join(sorted(o.discovered_by))}"
            for o in observations
        ]
        graph_hash = graph_snapshot.get("snapshot_hash", "") if graph_snapshot else ""
        content_for_hash = json.dumps({"observations": sorted(obs_payload), "graph_hash": graph_hash}, sort_keys=True)
        snapshot_hash = hashlib.sha256(content_for_hash.encode("utf-8")).hexdigest()

        return ReconSnapshot(
            campaign_id=config.campaign_id,
            target=config.target_url,
            status=status,
            observations=observations,
            tool_results=tool_results,
            graph_snapshot=graph_snapshot,
            snapshot_hash=snapshot_hash,
            observation_count=len(observations),
            warnings=warnings,
            errors=errors,
            started_at=started_at,
            completed_at=completed_at,
        )
