"""AihaX Phase 23 — Attack Surface Graph Engine.

Constructs and manages an attack-surface graph of authorized target observations,
endpoints, parameters, headers, cookies, API routes, and their relationships.

Security Invariants:
1. Purely passive/in-memory data processing; zero outbound network execution.
2. Ingests only observations from explicitly authorized concrete targets.
3. Computes deterministic SHA-256 graph snapshot hashes over canonicalized nodes and edges.
4. Deduplicates nodes and edges deterministically.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from backend.models.database import (
    AttackSurfaceEdgeRecord,
    AttackSurfaceNodeRecord,
    get_utc_now,
)

logger = logging.getLogger("aihax.attack_surface_graph")


class AttackSurfaceNodeType:
    TARGET = "TARGET"
    ENDPOINT = "ENDPOINT"
    PARAMETER = "PARAMETER"
    HEADER = "HEADER"
    COOKIE = "COOKIE"
    REDIRECT = "REDIRECT"
    RESOURCE = "RESOURCE"
    API_ROUTE = "API_ROUTE"
    AUTH_SURFACE = "AUTH_SURFACE"

    ALL: Set[str] = {
        TARGET,
        ENDPOINT,
        PARAMETER,
        HEADER,
        COOKIE,
        REDIRECT,
        RESOURCE,
        API_ROUTE,
        AUTH_SURFACE,
    }


class AttackSurfaceEdgeType:
    LINK = "LINK"
    REDIRECT = "REDIRECT"
    REFERENCE = "REFERENCE"
    PARAMETER_RELATION = "PARAMETER_RELATION"
    API_RELATION = "API_RELATION"
    OBSERVED_BEHAVIOR = "OBSERVED_BEHAVIOR"

    ALL: Set[str] = {
        LINK,
        REDIRECT,
        REFERENCE,
        PARAMETER_RELATION,
        API_RELATION,
        OBSERVED_BEHAVIOR,
    }


@dataclass
class AttackSurfaceNodeDTO:
    id: str
    campaign_id: str
    target: str
    node_type: str
    canonical_url: str
    endpoint: Optional[str]
    parameter: Optional[str]
    method: Optional[str]
    source: str
    observation_hash: str
    confidence: float = 1.0
    status: str = "OBSERVED"
    created_at: str = field(default_factory=lambda: get_utc_now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackSurfaceEdgeDTO:
    id: str
    campaign_id: str
    source_node_id: str
    destination_node_id: str
    edge_type: str
    evidence_id: Optional[str]
    confidence: float = 1.0
    created_at: str = field(default_factory=lambda: get_utc_now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackSurfaceGraphSnapshotDTO:
    campaign_id: str
    target: str
    nodes: List[AttackSurfaceNodeDTO]
    edges: List[AttackSurfaceEdgeDTO]
    snapshot_hash: str
    node_count: int
    edge_count: int
    created_at: str = field(default_factory=lambda: get_utc_now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "target": self.target,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "snapshot_hash": self.snapshot_hash,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "created_at": self.created_at,
        }


class AttackSurfaceGraphEngine:
    """Deterministic, passive Attack Surface Graph engine for Phase 23."""

    @classmethod
    def compute_observation_hash(
        cls,
        target: str,
        node_type: str,
        canonical_url: str,
        endpoint: Optional[str] = None,
        parameter: Optional[str] = None,
        method: Optional[str] = None,
    ) -> str:
        """Compute a canonical SHA-256 fingerprint for a graph node."""
        normalized = f"{target.strip().lower()}:{node_type.strip().upper()}:{canonical_url.strip()}:{endpoint or ''}:{parameter or ''}:{(method or '').upper()}"
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    @classmethod
    def compute_snapshot_hash(
        cls,
        nodes: List[AttackSurfaceNodeDTO],
        edges: List[AttackSurfaceEdgeDTO],
    ) -> str:
        """Compute deterministic SHA-256 snapshot hash across canonicalized nodes and edges."""
        sorted_nodes = sorted(
            [f"{n.node_type}:{n.canonical_url}:{n.endpoint or ''}:{n.parameter or ''}:{n.method or ''}:{n.observation_hash}" for n in nodes]
        )
        sorted_edges = sorted(
            [f"{e.source_node_id}:{e.destination_node_id}:{e.edge_type}:{e.evidence_id or ''}" for e in edges]
        )
        payload = json.dumps({"nodes": sorted_nodes, "edges": sorted_edges}, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def add_target(
        cls,
        campaign_id: str,
        target: str,
        source: str = "PASSIVE_INVENTORY",
        confidence: float = 1.0,
        db: Optional[Any] = None,
    ) -> AttackSurfaceNodeDTO:
        """Register the root concrete target node."""
        clean_target = target.strip()
        obs_hash = cls.compute_observation_hash(clean_target, AttackSurfaceNodeType.TARGET, clean_target)
        node_id = f"NODE-TGT-{obs_hash[:16]}"

        node_dto = AttackSurfaceNodeDTO(
            id=node_id,
            campaign_id=campaign_id,
            target=clean_target,
            node_type=AttackSurfaceNodeType.TARGET,
            canonical_url=clean_target,
            endpoint="/",
            parameter=None,
            method="GET",
            source=source,
            observation_hash=obs_hash,
            confidence=confidence,
        )
        cls._persist_node(node_dto, db)
        return node_dto

    @classmethod
    def add_endpoint(
        cls,
        campaign_id: str,
        target: str,
        endpoint: str,
        method: str = "GET",
        source: str = "PASSIVE_INVENTORY",
        confidence: float = 1.0,
        db: Optional[Any] = None,
    ) -> AttackSurfaceNodeDTO:
        """Register an HTTP endpoint node."""
        clean_target = target.strip()
        clean_endpoint = "/" + endpoint.lstrip("/")
        canonical_url = f"{clean_target.rstrip('/')}{clean_endpoint}"
        obs_hash = cls.compute_observation_hash(
            clean_target, AttackSurfaceNodeType.ENDPOINT, canonical_url, clean_endpoint, method=method
        )
        node_id = f"NODE-EP-{obs_hash[:16]}"

        node_dto = AttackSurfaceNodeDTO(
            id=node_id,
            campaign_id=campaign_id,
            target=clean_target,
            node_type=AttackSurfaceNodeType.ENDPOINT,
            canonical_url=canonical_url,
            endpoint=clean_endpoint,
            parameter=None,
            method=method.upper(),
            source=source,
            observation_hash=obs_hash,
            confidence=confidence,
        )
        cls._persist_node(node_dto, db)
        return node_dto

    @classmethod
    def add_parameter(
        cls,
        campaign_id: str,
        target: str,
        endpoint: str,
        parameter: str,
        method: str = "GET",
        source: str = "PASSIVE_INVENTORY",
        confidence: float = 1.0,
        db: Optional[Any] = None,
    ) -> AttackSurfaceNodeDTO:
        """Register a parameter node associated with an endpoint."""
        clean_target = target.strip()
        clean_endpoint = "/" + endpoint.lstrip("/")
        canonical_url = f"{clean_target.rstrip('/')}{clean_endpoint}?{parameter}"
        obs_hash = cls.compute_observation_hash(
            clean_target, AttackSurfaceNodeType.PARAMETER, canonical_url, clean_endpoint, parameter=parameter, method=method
        )
        node_id = f"NODE-PARAM-{obs_hash[:16]}"

        node_dto = AttackSurfaceNodeDTO(
            id=node_id,
            campaign_id=campaign_id,
            target=clean_target,
            node_type=AttackSurfaceNodeType.PARAMETER,
            canonical_url=canonical_url,
            endpoint=clean_endpoint,
            parameter=parameter,
            method=method.upper(),
            source=source,
            observation_hash=obs_hash,
            confidence=confidence,
        )
        cls._persist_node(node_dto, db)
        return node_dto

    @classmethod
    def add_redirect(
        cls,
        campaign_id: str,
        target: str,
        source_endpoint: str,
        destination_url: str,
        source: str = "PASSIVE_INVENTORY",
        confidence: float = 1.0,
        db: Optional[Any] = None,
    ) -> Tuple[AttackSurfaceNodeDTO, AttackSurfaceEdgeDTO]:
        """Register a redirect target node and its corresponding redirect edge."""
        clean_target = target.strip()
        obs_hash = cls.compute_observation_hash(
            clean_target, AttackSurfaceNodeType.REDIRECT, destination_url, endpoint=source_endpoint
        )
        node_id = f"NODE-REDIR-{obs_hash[:16]}"

        node_dto = AttackSurfaceNodeDTO(
            id=node_id,
            campaign_id=campaign_id,
            target=clean_target,
            node_type=AttackSurfaceNodeType.REDIRECT,
            canonical_url=destination_url,
            endpoint=source_endpoint,
            parameter=None,
            method="GET",
            source=source,
            observation_hash=obs_hash,
            confidence=confidence,
        )
        cls._persist_node(node_dto, db)

        # Create edge from source endpoint to redirect node
        source_ep_node = cls.add_endpoint(campaign_id, target, source_endpoint, db=db)
        edge_dto = cls.add_relationship(
            campaign_id=campaign_id,
            source_node_id=source_ep_node.id,
            destination_node_id=node_id,
            edge_type=AttackSurfaceEdgeType.REDIRECT,
            confidence=confidence,
            db=db,
        )
        return node_dto, edge_dto

    @classmethod
    def add_header_observation(
        cls,
        campaign_id: str,
        target: str,
        endpoint: str,
        header_name: str,
        header_value: str = "",
        source: str = "PASSIVE_INVENTORY",
        confidence: float = 1.0,
        db: Optional[Any] = None,
    ) -> AttackSurfaceNodeDTO:
        """Register an observed interesting header node."""
        clean_target = target.strip()
        clean_endpoint = "/" + endpoint.lstrip("/")
        canonical_url = f"{clean_target.rstrip('/')}{clean_endpoint}#{header_name.lower()}"
        obs_hash = cls.compute_observation_hash(
            clean_target, AttackSurfaceNodeType.HEADER, canonical_url, endpoint=clean_endpoint, parameter=header_name.lower()
        )
        node_id = f"NODE-HDR-{obs_hash[:16]}"

        node_dto = AttackSurfaceNodeDTO(
            id=node_id,
            campaign_id=campaign_id,
            target=clean_target,
            node_type=AttackSurfaceNodeType.HEADER,
            canonical_url=canonical_url,
            endpoint=clean_endpoint,
            parameter=header_name.lower(),
            method="GET",
            source=source,
            observation_hash=obs_hash,
            confidence=confidence,
        )
        cls._persist_node(node_dto, db)
        return node_dto

    @classmethod
    def add_api_route(
        cls,
        campaign_id: str,
        target: str,
        api_path: str,
        method: str = "GET",
        source: str = "PASSIVE_INVENTORY",
        confidence: float = 1.0,
        db: Optional[Any] = None,
    ) -> AttackSurfaceNodeDTO:
        """Register an API route node."""
        clean_target = target.strip()
        clean_path = "/" + api_path.lstrip("/")
        canonical_url = f"{clean_target.rstrip('/')}{clean_path}"
        obs_hash = cls.compute_observation_hash(
            clean_target, AttackSurfaceNodeType.API_ROUTE, canonical_url, endpoint=clean_path, method=method
        )
        node_id = f"NODE-API-{obs_hash[:16]}"

        node_dto = AttackSurfaceNodeDTO(
            id=node_id,
            campaign_id=campaign_id,
            target=clean_target,
            node_type=AttackSurfaceNodeType.API_ROUTE,
            canonical_url=canonical_url,
            endpoint=clean_path,
            parameter=None,
            method=method.upper(),
            source=source,
            observation_hash=obs_hash,
            confidence=confidence,
        )
        cls._persist_node(node_dto, db)
        return node_dto

    @classmethod
    def add_relationship(
        cls,
        campaign_id: str,
        source_node_id: str,
        destination_node_id: str,
        edge_type: str,
        evidence_id: Optional[str] = None,
        confidence: float = 1.0,
        db: Optional[Any] = None,
    ) -> AttackSurfaceEdgeDTO:
        """Register a directional relationship edge between two nodes."""
        edge_id_payload = f"{campaign_id}:{source_node_id}:{destination_node_id}:{edge_type}"
        edge_id = f"EDGE-{hashlib.sha256(edge_id_payload.encode('utf-8')).hexdigest()[:16]}"

        edge_dto = AttackSurfaceEdgeDTO(
            id=edge_id,
            campaign_id=campaign_id,
            source_node_id=source_node_id,
            destination_node_id=destination_node_id,
            edge_type=edge_type,
            evidence_id=evidence_id,
            confidence=confidence,
        )
        cls._persist_edge(edge_dto, db)
        return edge_dto

    @classmethod
    def get_snapshot(
        cls,
        campaign_id: str,
        target: str = "https://account.example.com",
        db: Optional[Any] = None,
    ) -> AttackSurfaceGraphSnapshotDTO:
        """Retrieve all nodes, edges, and compute the cryptographic snapshot hash for a campaign."""
        nodes: List[AttackSurfaceNodeDTO] = []
        edges: List[AttackSurfaceEdgeDTO] = []

        if db is not None:
            db_nodes = db.query(AttackSurfaceNodeRecord).filter_by(campaign_id=campaign_id).all()
            for n in db_nodes:
                nodes.append(
                    AttackSurfaceNodeDTO(
                        id=n.id,
                        campaign_id=n.campaign_id,
                        target=n.target,
                        node_type=n.node_type,
                        canonical_url=n.canonical_url,
                        endpoint=n.endpoint,
                        parameter=n.parameter,
                        method=n.method,
                        source=n.source,
                        observation_hash=n.observation_hash,
                        confidence=n.confidence,
                        status=n.status,
                        created_at=n.created_at.isoformat() if hasattr(n.created_at, "isoformat") else str(n.created_at),
                    )
                )

            db_edges = db.query(AttackSurfaceEdgeRecord).filter_by(campaign_id=campaign_id).all()
            for e in db_edges:
                edges.append(
                    AttackSurfaceEdgeDTO(
                        id=e.id,
                        campaign_id=e.campaign_id,
                        source_node_id=e.source_node_id,
                        destination_node_id=e.destination_node_id,
                        edge_type=e.edge_type,
                        evidence_id=e.evidence_id,
                        confidence=e.confidence,
                        created_at=e.created_at.isoformat() if hasattr(e.created_at, "isoformat") else str(e.created_at),
                    )
                )

        snap_hash = cls.compute_snapshot_hash(nodes, edges)
        return AttackSurfaceGraphSnapshotDTO(
            campaign_id=campaign_id,
            target=target,
            nodes=nodes,
            edges=edges,
            snapshot_hash=snap_hash,
            node_count=len(nodes),
            edge_count=len(edges),
        )

    @classmethod
    def _persist_node(cls, node_dto: AttackSurfaceNodeDTO, db: Optional[Any]) -> None:
        if db is None:
            return
        existing = db.query(AttackSurfaceNodeRecord).filter_by(id=node_dto.id).first()
        if existing:
            return
        rec = AttackSurfaceNodeRecord(
            id=node_dto.id,
            campaign_id=node_dto.campaign_id,
            target=node_dto.target,
            node_type=node_dto.node_type,
            canonical_url=node_dto.canonical_url,
            endpoint=node_dto.endpoint,
            parameter=node_dto.parameter,
            method=node_dto.method,
            source=node_dto.source,
            observation_hash=node_dto.observation_hash,
            confidence=node_dto.confidence,
            status=node_dto.status,
        )
        db.add(rec)
        try:
            db.commit()
        except Exception:
            db.rollback()

    @classmethod
    def _persist_edge(cls, edge_dto: AttackSurfaceEdgeDTO, db: Optional[Any]) -> None:
        if db is None:
            return
        existing = db.query(AttackSurfaceEdgeRecord).filter_by(id=edge_dto.id).first()
        if existing:
            return
        rec = AttackSurfaceEdgeRecord(
            id=edge_dto.id,
            campaign_id=edge_dto.campaign_id,
            source_node_id=edge_dto.source_node_id,
            destination_node_id=edge_dto.destination_node_id,
            edge_type=edge_dto.edge_type,
            evidence_id=edge_dto.evidence_id,
            confidence=edge_dto.confidence,
        )
        db.add(rec)
        try:
            db.commit()
        except Exception:
            db.rollback()
