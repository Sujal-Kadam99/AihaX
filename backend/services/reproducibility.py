"""AihaX Phase 23 — Reproducibility Engine.

Performs deterministic comparison of independent validation observations
and computes mathematical reproducibility scores and classifications.

Security Invariants:
1. Purely deterministic comparison over canonical evidence representations.
2. Reproduction runs obey the identical safety, authorization, and rate/budget bounds.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from backend.models.database import (
    ValidationReproductionRecord,
    get_utc_now,
)

logger = logging.getLogger("aihax.reproducibility")


class ReproducibilityClassification:
    REPRODUCIBLE = "REPRODUCIBLE"
    PARTIALLY_REPRODUCIBLE = "PARTIALLY_REPRODUCIBLE"
    NOT_REPRODUCIBLE = "NOT_REPRODUCIBLE"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class ReproducibilityResultDTO:
    plan_id: str
    finding_id: str
    attempt_number: int
    result: str
    reproducibility_score: float
    evidence_hash: str
    comparison_metrics: Dict[str, Any]
    details: str
    created_at: str = field(default_factory=lambda: get_utc_now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ReproducibilityEngine:
    """Computes mathematical reproducibility scores across independent validation runs."""

    @classmethod
    def evaluate_reproduction(
        cls,
        original_observations: List[Any],
        reproduction_observations: List[Any],
        finding_id: str = "FIND-001",
        plan_id: str = "PLAN-001",
        attempt_number: int = 1,
        db: Optional[Session] = None,
    ) -> ReproducibilityResultDTO:
        """Evaluate consistency between original and reproduction observations."""
        if not original_observations or not reproduction_observations:
            return ReproducibilityResultDTO(
                plan_id=plan_id,
                finding_id=finding_id,
                attempt_number=attempt_number,
                result=ReproducibilityClassification.INCONCLUSIVE,
                reproducibility_score=0.0,
                evidence_hash=hashlib.sha256(b"INCONCLUSIVE").hexdigest(),
                comparison_metrics={"error": "Missing observation sets"},
                details="Reproduction observations could not be correlated due to empty observation sets.",
            )

        status_matches = 0
        hash_matches = 0
        norm_hash_matches = 0
        total_steps = max(len(original_observations), len(reproduction_observations))

        for i in range(min(len(original_observations), len(reproduction_observations))):
            orig = original_observations[i]
            repro = reproduction_observations[i]

            o_status = orig.status_code if hasattr(orig, "status_code") else orig.get("status_code")
            r_status = repro.status_code if hasattr(repro, "status_code") else repro.get("status_code")

            o_hash = orig.response_hash if hasattr(orig, "response_hash") else orig.get("response_hash")
            r_hash = repro.response_hash if hasattr(repro, "response_hash") else repro.get("response_hash")

            o_norm = orig.normalized_response_hash if hasattr(orig, "normalized_response_hash") else orig.get("normalized_response_hash")
            r_norm = repro.normalized_response_hash if hasattr(repro, "normalized_response_hash") else repro.get("normalized_response_hash")

            if o_status == r_status and o_status is not None:
                status_matches += 1
            if o_hash == r_hash and o_hash is not None:
                hash_matches += 1
            if o_norm == r_norm and o_norm is not None:
                norm_hash_matches += 1

        status_score = status_matches / total_steps if total_steps else 0.0
        hash_score = hash_matches / total_steps if total_steps else 0.0
        norm_score = norm_hash_matches / total_steps if total_steps else 0.0

        # Weighted calculation: status (35%), exact hash (35%), normalized structure (30%)
        overall_score = round(0.35 * status_score + 0.35 * hash_score + 0.30 * norm_score, 3)

        if overall_score >= 0.85:
            classification = ReproducibilityClassification.REPRODUCIBLE
        elif overall_score >= 0.50:
            classification = ReproducibilityClassification.PARTIALLY_REPRODUCIBLE
        else:
            classification = ReproducibilityClassification.NOT_REPRODUCIBLE

        evidence_payload = f"{plan_id}:{finding_id}:{attempt_number}:{overall_score}:{classification}"
        evidence_hash = hashlib.sha256(evidence_payload.encode("utf-8")).hexdigest()

        metrics = {
            "status_match_rate": round(status_score, 2),
            "exact_hash_match_rate": round(hash_score, 2),
            "normalized_hash_match_rate": round(norm_score, 2),
            "total_steps_compared": total_steps,
        }

        details = f"Reproduction attempt {attempt_number} yielded score {overall_score} ({classification})."

        dto = ReproducibilityResultDTO(
            plan_id=plan_id,
            finding_id=finding_id,
            attempt_number=attempt_number,
            result=classification,
            reproducibility_score=overall_score,
            evidence_hash=evidence_hash,
            comparison_metrics=metrics,
            details=details,
        )

        if db is not None:
            rec = ValidationReproductionRecord(
                id=str(uuid.uuid4()),
                validation_plan_id=plan_id,
                finding_id=finding_id,
                attempt_number=attempt_number,
                result=classification,
                evidence_hash=evidence_hash,
                reproducibility_score=overall_score,
            )
            db.add(rec)
            try:
                db.commit()
            except Exception:
                db.rollback()

        return dto
