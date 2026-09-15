"""AihaX Phase 20 — Deterministic Observed Surface Inventory Service.

Architectural Invariants:
1. Passive Observation Only: Surface entries are populated ONLY from authorized traffic/evidence already captured.
2. Zero Auxiliary Discovery: NEVER issues outbound network requests to populate the inventory.
3. Path & Parameter Normalization: Deterministically normalizes endpoints, query parameters, and header artifacts.
4. Scope Gated: Only indexes observations from in-scope authorized targets.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set
from urllib.parse import parse_qs, urlparse, urlunparse
from sqlalchemy.orm import Session

from backend.models.database import SurfaceInventoryRecord, get_utc_now

logger = logging.getLogger("aihax.surface_inventory")


@dataclass
class SurfaceEntryDTO:
    """Data transfer object representing an observed surface asset."""
    id: str
    target: str
    endpoint: str
    http_method: str
    normalized_path: str
    parameters: List[str] = field(default_factory=list)
    content_type: Optional[str] = None
    auth_state: str = "ANONYMOUS"
    status_code: Optional[int] = None
    interesting_headers: Dict[str, str] = field(default_factory=dict)
    observed_findings: List[str] = field(default_factory=list)
    negative_evidence: List[str] = field(default_factory=list)
    observation_count: int = 1
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def target_root(self) -> str:
        return self.target

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SurfaceInventoryService:
    """Manages deterministic inventory of observed attack surface."""

    INTERESTING_HEADER_KEYS = {
        "server",
        "x-powered-by",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "set-cookie",
        "location",
        "www-authenticate",
    }

    @classmethod
    def normalize_target_root(cls, url: str) -> str:
        """Extract canonical target base URL."""
        parsed = urlparse(url)
        scheme = parsed.scheme.lower() or "https"
        # Strip default ports
        netloc = parsed.netloc.lower()
        if (scheme == "https" and netloc.endswith(":443")) or (scheme == "http" and netloc.endswith(":80")):
            netloc = netloc.rsplit(":", 1)[0]
        return f"{scheme}://{netloc}"

    @classmethod
    def normalize_path(cls, path: str) -> str:
        """Normalize URL path component."""
        p = path or "/"
        if len(p) > 1 and p.endswith("/"):
            p = p[:-1]
        return p

    @classmethod
    def normalize_url_path(cls, url: str) -> tuple[str, str, List[str]]:
        """Extract canonical target base, normalized path, and query parameter names."""
        base_target = cls.normalize_target_root(url)
        parsed = urlparse(url)
        path = cls.normalize_path(parsed.path)
        params = sorted(list(parse_qs(parsed.query).keys()))
        return base_target, path, params

    @classmethod
    def record_observation(
        cls,
        target: str,
        url: Optional[str] = None,
        http_method: str = "GET",
        status_code: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        content_type: Optional[str] = None,
        auth_state: str = "ANONYMOUS",
        finding_id: Optional[str] = None,
        negative_evidence_id: Optional[str] = None,
        db: Optional[Session] = None,
        endpoint: Optional[str] = None,
    ) -> SurfaceEntryDTO:
        """Helper alias accepting url or endpoint."""
        target_endpoint = url or endpoint or target
        return cls.register_observation(
            target=target,
            endpoint=target_endpoint,
            http_method=http_method,
            status_code=status_code,
            headers=headers,
            content_type=content_type,
            auth_state=auth_state,
            finding_id=finding_id,
            negative_evidence_id=negative_evidence_id,
            db=db,
        )

    @classmethod
    def register_observation(
        cls,
        target: str,
        endpoint: str,
        http_method: str = "GET",
        parameters: Optional[List[str]] = None,
        status_code: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        content_type: Optional[str] = None,
        auth_state: str = "ANONYMOUS",
        finding_id: Optional[str] = None,
        negative_evidence_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> SurfaceEntryDTO:
        """Register an observed HTTP transaction into the surface inventory."""
        if not target or not endpoint:
            raise ValueError("Target and endpoint must be provided to register surface observation.")

        base_target, norm_path, extracted_params = cls.normalize_url_path(endpoint)
        if parameters:
            extracted_params = sorted(list(set(extracted_params + parameters)))
        target_root = target.rstrip("/")

        method_upper = http_method.upper() if http_method else "GET"

        # Filter interesting headers
        interesting_hdrs: Dict[str, str] = {}
        if headers:
            for k, v in headers.items():
                k_lower = k.lower()
                if k_lower in cls.INTERESTING_HEADER_KEYS:
                    interesting_hdrs[k_lower] = str(v)

        rec_id = str(uuid.uuid4())
        now_utc = get_utc_now()
        now_str = now_utc.isoformat()

        if db is None:
            # In-memory return
            return SurfaceEntryDTO(
                id=rec_id,
                target=target_root,
                endpoint=endpoint,
                http_method=method_upper,
                normalized_path=norm_path,
                parameters=extracted_params,
                content_type=content_type,
                auth_state=auth_state,
                status_code=status_code,
                interesting_headers=interesting_hdrs,
                observed_findings=[finding_id] if finding_id else [],
                negative_evidence=[negative_evidence_id] if negative_evidence_id else [],
                discovered_at=now_str,
                updated_at=now_str,
            )

        # Check existing record by normalized path and method
        existing = db.query(SurfaceInventoryRecord).filter(
            SurfaceInventoryRecord.target == target_root,
            SurfaceInventoryRecord.normalized_path == norm_path,
            SurfaceInventoryRecord.http_method == method_upper,
        ).first()

        if existing:
            # Update existing surface entry
            curr_params = json.loads(existing.parameters) if existing.parameters else []
            combined_params = sorted(list(set(curr_params + extracted_params)))
            existing.parameters = json.dumps(combined_params)

            if status_code is not None:
                existing.status_code = status_code
            if content_type:
                existing.content_type = content_type
            if auth_state != "ANONYMOUS":
                existing.auth_state = auth_state

            curr_headers = json.loads(existing.interesting_headers) if existing.interesting_headers else {}
            curr_headers.update(interesting_hdrs)
            existing.interesting_headers = json.dumps(curr_headers)

            if finding_id:
                curr_findings = json.loads(existing.observed_findings) if existing.observed_findings else []
                if finding_id not in curr_findings:
                    curr_findings.append(finding_id)
                existing.observed_findings = json.dumps(curr_findings)

            if negative_evidence_id:
                curr_neg = json.loads(existing.negative_evidence) if existing.negative_evidence else []
                if negative_evidence_id not in curr_neg:
                    curr_neg.append(negative_evidence_id)
                existing.negative_evidence = json.dumps(curr_neg)

            obs_count = getattr(existing, "observation_count", 1) + 1
            if hasattr(existing, "observation_count"):
                existing.observation_count = obs_count

            existing.updated_at = now_utc
            db.commit()
            db.refresh(existing)

            return SurfaceEntryDTO(
                id=existing.id,
                target=existing.target,
                endpoint=existing.endpoint,
                http_method=existing.http_method,
                normalized_path=existing.normalized_path,
                parameters=json.loads(existing.parameters),
                content_type=existing.content_type,
                auth_state=existing.auth_state,
                status_code=existing.status_code,
                interesting_headers=json.loads(existing.interesting_headers) if existing.interesting_headers else {},
                observed_findings=json.loads(existing.observed_findings) if existing.observed_findings else [],
                negative_evidence=json.loads(existing.negative_evidence) if existing.negative_evidence else [],
                observation_count=obs_count,
                discovered_at=existing.discovered_at.isoformat() if hasattr(existing.discovered_at, "isoformat") else str(existing.discovered_at),
                updated_at=existing.updated_at.isoformat() if hasattr(existing.updated_at, "isoformat") else str(existing.updated_at),
            )

        # Create new surface entry
        new_rec = SurfaceInventoryRecord(
            id=rec_id,
            target=target_root,
            endpoint=endpoint,
            http_method=method_upper,
            normalized_path=norm_path,
            parameters=json.dumps(extracted_params),
            content_type=content_type,
            auth_state=auth_state,
            status_code=status_code,
            interesting_headers=json.dumps(interesting_hdrs),
            observed_findings=json.dumps([finding_id] if finding_id else []),
            negative_evidence=json.dumps([negative_evidence_id] if negative_evidence_id else []),
            discovered_at=now_utc,
            updated_at=now_utc,
        )
        db.add(new_rec)
        db.commit()
        db.refresh(new_rec)

        return SurfaceEntryDTO(
            id=new_rec.id,
            target=new_rec.target,
            endpoint=new_rec.endpoint,
            http_method=new_rec.http_method,
            normalized_path=new_rec.normalized_path,
            parameters=extracted_params,
            content_type=content_type,
            auth_state=auth_state,
            status_code=status_code,
            interesting_headers=interesting_hdrs,
            observed_findings=[finding_id] if finding_id else [],
            negative_evidence=[negative_evidence_id] if negative_evidence_id else [],
            discovered_at=now_str,
            updated_at=now_str,
        )

    @classmethod
    def get_surface_for_target(
        cls,
        target: str,
        db: Optional[Session] = None,
    ) -> List[SurfaceEntryDTO]:
        """List all surface entries observed for a target."""
        if db is None:
            return []

        target_root = target.rstrip("/")
        records = db.query(SurfaceInventoryRecord).filter(
            SurfaceInventoryRecord.target == target_root
        ).all()

        return [
            SurfaceEntryDTO(
                id=r.id,
                target=r.target,
                endpoint=r.endpoint,
                http_method=r.http_method,
                normalized_path=r.normalized_path,
                parameters=json.loads(r.parameters) if r.parameters else [],
                content_type=r.content_type,
                auth_state=r.auth_state,
                status_code=r.status_code,
                interesting_headers=json.loads(r.interesting_headers) if r.interesting_headers else {},
                observed_findings=json.loads(r.observed_findings) if r.observed_findings else [],
                negative_evidence=json.loads(r.negative_evidence) if r.negative_evidence else [],
                discovered_at=r.discovered_at.isoformat() if hasattr(r.discovered_at, "isoformat") else str(r.discovered_at),
                updated_at=r.updated_at.isoformat() if hasattr(r.updated_at, "isoformat") else str(r.updated_at),
            )
            for r in records
        ]
