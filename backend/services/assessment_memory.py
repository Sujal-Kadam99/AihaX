"""AihaX Phase 20 — Cross-Assessment Memory & Learning Persistence Service.

Architectural Invariants:
1. Priority-Influence Only: Memory influences check ranking & recommendation priority; NEVER alters current authorization.
2. Zero Scope Creep: Historical memory NEVER expands or modifies the current target scope boundary.
3. No Finding Manufacture: Historical findings CANNOT become current findings or replace current evidence.
4. Budget Invariance: Historical memory NEVER increases the immutable 10-request production budget cap.
5. Deterministic Memory Storage: Stores verified facts and lessons across campaigns.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse
from sqlalchemy.orm import Session

from backend.models.database import AssessmentMemoryRecord, get_utc_now

logger = logging.getLogger("aihax.assessment_memory")


@dataclass
class AssessmentLessonDTO:
    """Data transfer object for a learned assessment pattern."""
    id: str
    target: str
    lesson_type: str
    key: str
    value: str
    campaign_id: Optional[str] = None
    metadata_json: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AssessmentMemoryService:
    """Service for persisting and querying cross-assessment learning."""

    LESSON_TYPES = {
        "CHECK_PERFORMANCE",
        "FALSE_POSITIVE_PATTERN",
        "SURFACE_CHARACTERISTIC",
        "FINGERPRINT_OBSERVED",
        "NEGATIVE_PATTERN",
    }

    @classmethod
    def record_lesson(
        cls,
        target: str,
        lesson_type: str,
        key: str,
        value: str,
        campaign_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        db: Optional[Session] = None,
    ) -> AssessmentLessonDTO:
        """Record an immutable learned lesson from an assessment."""
        if not target or not lesson_type or not key:
            raise ValueError("target, lesson_type, and key are required for assessment memory.")

        if lesson_type.upper() not in cls.LESSON_TYPES:
            raise ValueError(f"Invalid lesson_type '{lesson_type}'. Must be one of {cls.LESSON_TYPES}")

        meta = metadata or {}
        rec_id = str(uuid.uuid4())
        now_utc = get_utc_now()
        now_str = now_utc.isoformat()

        dto = AssessmentLessonDTO(
            id=rec_id,
            target=target.rstrip("/"),
            lesson_type=lesson_type.upper(),
            key=key,
            value=value,
            campaign_id=campaign_id,
            metadata_json=meta,
            created_at=now_str,
        )

        if db is not None:
            record = AssessmentMemoryRecord(
                id=rec_id,
                target=target.rstrip("/"),
                lesson_type=lesson_type.upper(),
                key=key,
                value=value,
                campaign_id=campaign_id,
                metadata_json=json.dumps(meta),
                created_at=now_utc,
            )
            db.add(record)
            db.commit()
            db.refresh(record)

        return dto

    @classmethod
    def get_lessons_for_target(
        cls,
        target: str,
        lesson_type: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> List[AssessmentLessonDTO]:
        """Query stored lessons for a specific target without modifying active scope."""
        if db is None:
            return []

        target_root = target.rstrip("/")
        query = db.query(AssessmentMemoryRecord).filter(
            AssessmentMemoryRecord.target == target_root
        )

        if lesson_type:
            query = query.filter(AssessmentMemoryRecord.lesson_type == lesson_type.upper())

        records = query.all()
        return [
            AssessmentLessonDTO(
                id=r.id,
                target=r.target,
                lesson_type=r.lesson_type,
                key=r.key,
                value=r.value,
                campaign_id=r.campaign_id,
                metadata_json=json.loads(r.metadata_json) if r.metadata_json else {},
                created_at=r.created_at.isoformat() if hasattr(r.created_at, "isoformat") else str(r.created_at),
            )
            for r in records
        ]

    @classmethod
    def extract_pattern_domain(cls, target: str) -> str:
        """Extract pattern domain from target URL or host."""
        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = parsed.netloc or parsed.path or target
        if ":" in host:
            host = host.split(":")[0]
        parts = host.split(".")
        if len(parts) >= 2 and not all(p.isdigit() for p in parts):
            return f"{parts[-2]}.{parts[-1]}"
        return host

    @classmethod
    def record_campaign_learning(
        cls,
        target: str,
        check_id: str,
        finding_yield: int = 0,
        campaign_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> AssessmentLessonDTO:
        """Record learning outcome for target domain and check."""
        pattern_domain = cls.extract_pattern_domain(target)
        if finding_yield > 0:
            l_type = "CHECK_PERFORMANCE"
            val = f"VERIFIED_{finding_yield}"
        else:
            l_type = "NEGATIVE_PATTERN"
            val = "NO_FINDINGS"

        dto = cls.record_lesson(
            target=target,
            lesson_type=l_type,
            key=check_id,
            value=val,
            campaign_id=campaign_id,
            metadata={"pattern_domain": pattern_domain, "finding_yield": finding_yield},
            db=db,
        )
        # Add pattern_domain and prioritization_modifier properties for test assertions
        dto.pattern_domain = pattern_domain
        dto.check_id = check_id
        dto.prioritization_modifier = cls.get_prioritization_boost(target, check_id, db=db)
        return dto

    @classmethod
    def get_prioritization_boost(
        cls,
        target: str,
        check_id: str,
        db: Optional[Session] = None,
    ) -> float:
        """Calculate historical prioritization modifier in range [-0.20, +0.20]."""
        if db is None:
            return 0.0

        target_root = target.rstrip("/")
        pattern_dom = cls.extract_pattern_domain(target)

        records = db.query(AssessmentMemoryRecord).filter(
            AssessmentMemoryRecord.key == check_id,
        ).all()

        boost = 0.0
        for l in records:
            # Match target root or pattern domain
            rec_dom = cls.extract_pattern_domain(l.target)
            if l.target == target_root or rec_dom == pattern_dom:
                if l.lesson_type == "CHECK_PERFORMANCE":
                    boost += 0.10
                elif l.lesson_type == "FALSE_POSITIVE_PATTERN":
                    boost -= 0.15
                elif l.lesson_type == "NEGATIVE_PATTERN":
                    boost -= 0.10

        # Bounded between -0.20 and +0.20
        return max(-0.20, min(0.20, round(boost, 4)))
