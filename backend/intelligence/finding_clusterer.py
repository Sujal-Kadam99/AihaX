"""AihaX Phase 7 — Finding Clusterer.

Detects related findings without incorrectly merging distinct vulnerabilities.
Cluster dimensions: check_id, normalized endpoint path, parameter, vuln category.

Invariants:
- Findings with different check_id AND different endpoints → separate findings.
- Endpoint variants (same path, different IDs) may cluster under one IDOR finding.
- Every merge retains ALL underlying evidence IDs.
- No evidence is silently discarded.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set
from urllib.parse import urlparse

from backend.models.database import Finding


# ──────────────────────────────────────────────────────────────────────────────
# 1. CLUSTER RELATION TYPES
# ──────────────────────────────────────────────────────────────────────────────

class ClusterRelationType(str, Enum):
    EXACT_DUPLICATE      = "exact_duplicate"        # Same fingerprint (check+endpoint+param+category)
    ENDPOINT_VARIANT     = "endpoint_variant"       # Same check+param, different endpoint ID values
    PARAMETER_VARIANT    = "parameter_variant"      # Same check+endpoint, different parameter name
    ROOT_CAUSE_CLUSTER   = "root_cause_cluster"     # Same check, related endpoints (same path structure)
    INDEPENDENT_FINDING  = "independent_finding"    # Distinct finding — must NOT be merged


# ──────────────────────────────────────────────────────────────────────────────
# 2. FINDING CLUSTER
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class FindingCluster:
    """A logical grouping of related findings under one root cause."""
    cluster_id: str
    cluster_type: ClusterRelationType
    primary_finding: Finding               # Highest-confidence finding in the cluster
    member_findings: List[Finding] = field(default_factory=list)

    # Merged evidence across all members (never discarded)
    all_evidence_ids: List[str] = field(default_factory=list)
    all_request_ids: List[str] = field(default_factory=list)
    all_payloads: List[str] = field(default_factory=list)
    all_affected_urls: List[str] = field(default_factory=list)

    member_count: int = 1
    check_ids: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "cluster_type": self.cluster_type.value,
            "primary_finding_id": self.primary_finding.id,
            "primary_check_id": str(self.primary_finding.vuln_type),
            "member_count": self.member_count,
            "check_ids": sorted(self.check_ids),
            "all_affected_urls": self.all_affected_urls,
            "all_payloads": self.all_payloads[:10],  # Bounded for reporting
            "evidence_count": len(set(self.all_evidence_ids)),
        }


# ──────────────────────────────────────────────────────────────────────────────
# 3. NORMALIZATION HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _normalize_path_structure(url: str) -> str:
    """Normalize URL to a path pattern, collapsing numeric/UUID path segments.

    /api/user/123     → /api/user/{id}
    /api/user/abc-def → /api/user/{id}
    /search           → /search
    """
    try:
        parsed = urlparse(url)
        path = parsed.path
        # Collapse trailing slashes
        path = re.sub(r"/+", "/", path).rstrip("/") or "/"
        # Replace numeric path segments
        path = re.sub(r"/\d+", "/{id}", path)
        # Replace UUID-like segments
        path = re.sub(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "/{id}", path, flags=re.IGNORECASE)
        return path
    except Exception:
        return str(url).lower()


def _normalize_param(param: Optional[str]) -> str:
    if not param:
        return "GLOBAL"
    p = param.strip().lower().replace("[", ".").replace("]", "")
    return p


def _cluster_key_exact(check_id: str, url: str, param: Optional[str], category: str) -> str:
    """Exact-duplicate cluster key."""
    path = _normalize_path_structure(url)
    key = f"{check_id.upper()}|{path}|{_normalize_param(param)}|{category.lower()}"
    return hashlib.sha256(key.encode()).hexdigest()


def _cluster_key_endpoint_variant(check_id: str, url: str, param: Optional[str]) -> str:
    """Endpoint-variant cluster key (same path structure, ignores ID values)."""
    path = _normalize_path_structure(url)
    key = f"{check_id.upper()}|PATH:{path}|PARAM:{_normalize_param(param)}"
    return hashlib.sha256(key.encode()).hexdigest()


def _cluster_key_root_cause(check_id: str, category: str) -> str:
    """Root-cause cluster key (same check + category)."""
    key = f"{check_id.upper()}|CAT:{category.lower()}"
    return hashlib.sha256(key.encode()).hexdigest()


# ──────────────────────────────────────────────────────────────────────────────
# 4. FINDING CLUSTERER
# ──────────────────────────────────────────────────────────────────────────────

class FindingClusterer:
    """Clusters related findings without losing evidence or incorrectly merging distinct vulnerabilities.

    Clustering policy:
    1. EXACT_DUPLICATE — same (check, path, param, category): full merge
    2. ENDPOINT_VARIANT — same (check, path pattern, param), different numeric IDs: IDOR/BOLA cluster
    3. ROOT_CAUSE_CLUSTER — same check + category, structurally related paths: optional grouping
    4. INDEPENDENT_FINDING — different check or clearly distinct surface: kept separate

    Note: /api/user and /api/admin are NEVER auto-merged even if same check_id.
    """

    @classmethod
    def cluster_findings(cls, findings: Sequence[Finding]) -> List[FindingCluster]:
        """Group findings into clusters. Guaranteed to retain all evidence."""
        exact_groups: Dict[str, FindingCluster] = {}
        variant_groups: Dict[str, FindingCluster] = {}
        independent: List[FindingCluster] = []

        for finding in findings:
            check_id = str(finding.vuln_type or "")
            url = str(finding.affected_url or "")
            param = finding.affected_param
            category = str(finding.category or "")

            exact_key = _cluster_key_exact(check_id, url, param, category)
            variant_key = _cluster_key_endpoint_variant(check_id, url, param)

            ev_ids = cls._parse_ids(finding.evidence_ids)
            req_ids = cls._parse_ids(finding.request_ids)
            payload = finding.payload or ""

            if exact_key in exact_groups:
                # EXACT duplicate — merge fully
                g = exact_groups[exact_key]
                g.member_findings.append(finding)
                g.member_count += 1
                g.all_evidence_ids = cls._merge_ids(g.all_evidence_ids, ev_ids)
                g.all_request_ids = cls._merge_ids(g.all_request_ids, req_ids)
                if payload and payload not in g.all_payloads:
                    g.all_payloads.append(payload)
                if url not in g.all_affected_urls:
                    g.all_affected_urls.append(url)
                g.check_ids.add(check_id)
                # Promote higher-confidence finding to primary
                if finding.confidence > g.primary_finding.confidence:
                    g.primary_finding = finding

            elif variant_key in variant_groups and cls._is_id_variant(url, variant_groups[variant_key].all_affected_urls[0] if variant_groups[variant_key].all_affected_urls else url):
                # ENDPOINT_VARIANT — path is same pattern but different numeric ID
                g = variant_groups[variant_key]
                g.member_findings.append(finding)
                g.member_count += 1
                g.all_evidence_ids = cls._merge_ids(g.all_evidence_ids, ev_ids)
                g.all_request_ids = cls._merge_ids(g.all_request_ids, req_ids)
                if payload and payload not in g.all_payloads:
                    g.all_payloads.append(payload)
                if url not in g.all_affected_urls:
                    g.all_affected_urls.append(url)
                g.check_ids.add(check_id)
                if finding.confidence > g.primary_finding.confidence:
                    g.primary_finding = finding

            else:
                # New cluster
                cluster_id = exact_key
                cluster_type = ClusterRelationType.INDEPENDENT_FINDING

                # Decide if this should be an endpoint-variant group
                if variant_key in variant_groups:
                    # Variant exists but is_id_variant failed — truly independent
                    cluster_type = ClusterRelationType.INDEPENDENT_FINDING
                else:
                    # Register as a potential variant group
                    cluster_type = ClusterRelationType.INDEPENDENT_FINDING  # starts as independent

                cluster = FindingCluster(
                    cluster_id=cluster_id,
                    cluster_type=cluster_type,
                    primary_finding=finding,
                    member_findings=[finding],
                    all_evidence_ids=list(ev_ids),
                    all_request_ids=list(req_ids),
                    all_payloads=[payload] if payload else [],
                    all_affected_urls=[url] if url else [],
                    member_count=1,
                    check_ids={check_id},
                )
                exact_groups[exact_key] = cluster
                # Only register as variant-capable if it involves numeric IDs
                if _normalize_path_structure(url) != url or re.search(r"/\d+", url):
                    variant_groups[variant_key] = cluster

        # Assign final cluster types
        for cluster in exact_groups.values():
            if cluster.member_count > 1:
                # Determine actual type
                urls = cluster.all_affected_urls
                if len(set(_normalize_path_structure(u) for u in urls)) == 1 and len(urls) > 1:
                    # All same path pattern → endpoint variant (e.g., IDOR with different IDs)
                    cluster.cluster_type = ClusterRelationType.ENDPOINT_VARIANT
                elif cluster.member_count > 1:
                    cluster.cluster_type = ClusterRelationType.EXACT_DUPLICATE

        return list(exact_groups.values())

    @staticmethod
    def _parse_ids(ids_json: Optional[str]) -> List[str]:
        try:
            result = json.loads(ids_json or "[]")
            return result if isinstance(result, list) else []
        except Exception:
            return []

    @staticmethod
    def _merge_ids(existing: List[str], new_ids: List[str]) -> List[str]:
        seen = set(existing)
        merged = list(existing)
        for item in new_ids:
            if item not in seen:
                merged.append(item)
                seen.add(item)
        return merged

    @staticmethod
    def _is_id_variant(url_a: str, url_b: str) -> bool:
        """True if two URLs have the same path structure but different numeric/UUID IDs."""
        path_a = _normalize_path_structure(url_a)
        path_b = _normalize_path_structure(url_b)
        return path_a == path_b and url_a != url_b


__all__ = ["ClusterRelationType", "FindingCluster", "FindingClusterer"]
