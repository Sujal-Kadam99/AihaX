"""AihaX Phase 23 — Confidence Assessment Engine.

Computes mathematical, multi-factor confidence scores and deterministic rationales
for validated security findings.

Scoring Weights:
- Evidence Quality: 30%
- Differential Consistency: 25%
- Reproducibility: 25%
- Scope Confidence: 10%
- Authorization Validity: 10%

Confidence Levels:
- VERY_HIGH (>= 0.90)
- HIGH (0.75 - 0.89)
- MEDIUM (0.50 - 0.74)
- LOW (0.25 - 0.49)
- VERY_LOW (< 0.25)
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from backend.models.database import (
    Phase23ConfidenceAssessmentRecord,
    get_utc_now,
)

logger = logging.getLogger("aihax.confidence_engine")


class ConfidenceLevel:
    VERY_HIGH = "VERY_HIGH"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    VERY_LOW = "VERY_LOW"
    CONFIRMED = "CONFIRMED"
    PLAUSIBLE = "PLAUSIBLE"
    TENTATIVE = "TENTATIVE"


@dataclass
class Phase23ConfidenceAssessmentDTO:
    id: str
    validation_plan_id: str
    finding_id: str
    evidence_score: float
    consistency_score: float
    reproducibility_score: float
    scope_score: float
    authorization_score: float
    overall_score: float
    confidence_level: str
    rationale: str
    created_at: str = field(default_factory=lambda: get_utc_now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MultiDimensionalConfidenceDTO:
    """Multidimensional confidence representation separating condition, impact, reproducibility, and exploitability."""
    condition_confidence: float
    impact_confidence: float
    reproducibility_confidence: float
    exploitability_confidence: float
    overall_score: float = 0.0
    confidence_level: str = "TENTATIVE"
    rationale: str = ""
    is_hardening_only: bool = False
    overall_confidence: Optional[float] = None
    created_at: str = field(default_factory=lambda: get_utc_now().isoformat())

    def __post_init__(self):
        if self.overall_confidence is not None:
            self.overall_score = self.overall_confidence
        else:
            self.overall_confidence = self.overall_score

        if self.confidence_level == "TENTATIVE":
            if self.overall_score >= 0.85 and self.exploitability_confidence >= 0.70:
                self.confidence_level = ConfidenceLevel.CONFIRMED
            elif self.overall_score >= 0.50 or self.is_hardening_only:
                self.confidence_level = ConfidenceLevel.PLAUSIBLE
            else:
                self.confidence_level = ConfidenceLevel.TENTATIVE

    @property
    def level(self) -> str:
        return self.confidence_level

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ConfidenceEngine:
    """Computes multi-factor weighted confidence assessments for Phase 23 & Phase 24 findings."""

    @classmethod
    def calculate_multidimensional_confidence(
        cls,
        condition_confidence: Optional[float] = None,
        impact_confidence: float = 0.0,
        reproducibility_confidence: float = 0.0,
        exploitability_confidence: float = 0.0,
        scope_score: float = 1.0,
        authorization_score: float = 1.0,
        is_hardening_only: bool = False,
        condition_observed: Optional[bool] = None,
        is_reproducible: Optional[bool] = None,
        exploit_succeeded: Optional[bool] = None,
        attack_chain_viable: Optional[bool] = None,
        **kwargs: Any,
    ) -> MultiDimensionalConfidenceDTO:
        """Calculate decoupled multidimensional confidence guaranteeing condition != exploitability."""
        if condition_observed is not None:
            condition_confidence = 1.0 if condition_observed else 0.0
        elif condition_confidence is None:
            condition_confidence = 1.0

        if is_reproducible is not None:
            reproducibility_confidence = 1.0 if is_reproducible else 0.0
        if exploit_succeeded is not None:
            exploitability_confidence = 0.9 if exploit_succeeded else 0.0
        if attack_chain_viable is not None:
            impact_confidence = 0.8 if attack_chain_viable else 0.0

        cond = max(0.0, min(1.0, float(condition_confidence)))
        imp = max(0.0, min(1.0, float(impact_confidence)))
        rep = max(0.0, min(1.0, float(reproducibility_confidence)))
        exp = max(0.0, min(1.0, float(exploitability_confidence)))
        sc = max(0.0, min(1.0, float(scope_score)))
        au = max(0.0, min(1.0, float(authorization_score)))

        # INVARIANT: Hardening-only findings have strictly 0 exploitability
        if is_hardening_only:
            exp = 0.0
            imp = min(imp, 0.20)

        # INVARIANT: condition_confidence == 1.0 does NOT imply exploitability_confidence > 0
        if exp == 0.0 and not is_hardening_only:
            # When no exploitability is demonstrated, composite score is bounded
            overall = round(0.35 * cond + 0.35 * rep + 0.15 * sc + 0.15 * au, 3)
            # Cap overall score to MEDIUM if impact is zero
            if imp == 0.0:
                overall = min(overall, 0.70)
        elif is_hardening_only:
            overall = round(0.40 * cond + 0.30 * rep + 0.15 * sc + 0.15 * au, 3)
        else:
            # Full vulnerability calculation with confirmed exploitability & impact
            overall = round(0.25 * cond + 0.25 * imp + 0.25 * rep + 0.25 * exp, 3)

        if overall >= 0.90:
            level = ConfidenceLevel.VERY_HIGH
        elif overall >= 0.75:
            level = ConfidenceLevel.HIGH
        elif overall >= 0.50:
            level = ConfidenceLevel.MEDIUM
        elif overall >= 0.25:
            level = ConfidenceLevel.LOW
        else:
            level = ConfidenceLevel.VERY_LOW

        mode_desc = "Hardening Observation" if is_hardening_only else "Security Vulnerability"
        rationale = (
            f"[{mode_desc}] Condition={cond:.2f}, Impact={imp:.2f}, "
            f"Reproducibility={rep:.2f}, Exploitability={exp:.2f} -> "
            f"Composite Score={overall:.3f} ({level}). "
            f"Invariant: condition != exploitability."
        )

        return MultiDimensionalConfidenceDTO(
            condition_confidence=cond,
            impact_confidence=imp,
            reproducibility_confidence=rep,
            exploitability_confidence=exp,
            overall_score=overall,
            confidence_level=level,
            rationale=rationale,
        )

    @classmethod
    def calculate_confidence(
        cls,
        validation_plan_id: str,
        finding_id: str,
        evidence_score: float = 1.0,
        consistency_score: float = 1.0,
        reproducibility_score: float = 1.0,
        scope_score: float = 1.0,
        authorization_score: float = 1.0,
        db: Optional[Session] = None,
    ) -> Phase23ConfidenceAssessmentDTO:
        """Calculate weighted score and categorize into confidence level."""
        # Clamp inputs to [0.0, 1.0]
        ev = max(0.0, min(1.0, float(evidence_score)))
        cs = max(0.0, min(1.0, float(consistency_score)))
        rp = max(0.0, min(1.0, float(reproducibility_score)))
        sc = max(0.0, min(1.0, float(scope_score)))
        au = max(0.0, min(1.0, float(authorization_score)))

        overall = round(0.30 * ev + 0.25 * cs + 0.25 * rp + 0.10 * sc + 0.10 * au, 3)

        if overall >= 0.90:
            level = ConfidenceLevel.VERY_HIGH
        elif overall >= 0.75:
            level = ConfidenceLevel.HIGH
        elif overall >= 0.50:
            level = ConfidenceLevel.MEDIUM
        elif overall >= 0.25:
            level = ConfidenceLevel.LOW
        else:
            level = ConfidenceLevel.VERY_LOW

        rationale = (
            f"Overall confidence {overall:.3f} ({level}) calculated from "
            f"Evidence Quality={ev:.2f} (30%), Differential Consistency={cs:.2f} (25%), "
            f"Reproducibility={rp:.2f} (25%), Scope={sc:.2f} (10%), and Authorization={au:.2f} (10%)."
        )

        assessment_id = f"CONF-{uuid.uuid4().hex[:12]}"
        dto = Phase23ConfidenceAssessmentDTO(
            id=assessment_id,
            validation_plan_id=validation_plan_id,
            finding_id=finding_id,
            evidence_score=ev,
            consistency_score=cs,
            reproducibility_score=rp,
            scope_score=sc,
            authorization_score=au,
            overall_score=overall,
            confidence_level=level,
            rationale=rationale,
        )

        if db is not None:
            rec = Phase23ConfidenceAssessmentRecord(
                id=dto.id,
                validation_plan_id=dto.validation_plan_id,
                finding_id=dto.finding_id,
                evidence_score=dto.evidence_score,
                consistency_score=dto.consistency_score,
                reproducibility_score=dto.reproducibility_score,
                scope_score=dto.scope_score,
                authorization_score=dto.authorization_score,
                overall_score=dto.overall_score,
                confidence_level=dto.confidence_level,
                rationale=dto.rationale,
            )
            db.add(rec)
            try:
                db.commit()
            except Exception:
                db.rollback()

        return dto
