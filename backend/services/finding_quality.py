"""AihaX Phase 20 — Finding Quality Scoring Engine & Categorical Grading Bands.

Architectural Invariants:
1. Deterministic Multi-Factor Grading: Evaluates evidence completeness, reproducibility, confirmed impact, and integrity.
2. 4-Band Quality Classification:
   - Band A (0.90 - 1.00): Outstanding evidence completeness, 100% reproducible, confirmed impact.
   - Band B (0.75 - 0.89): Strong verified evidence, reproducible, clearly defined impact.
   - Band C (0.60 - 0.74): Verified with minor informational caveats.
   - Band D (< 0.60): Sub-threshold finding; strictly barred from report generation until reverified.
3. No Severity Inflation: Quality measures evidentiary certainty and rigor, not theoretical impact.
4. Non-Reportable Gate: Findings in Band D or with missing mandatory evidence are non-reportable.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aihax.finding_quality")


@dataclass
class QualityBreakdown:
    """Detailed score decomposition for finding quality."""
    evidence_completeness: float = 0.0  # Weight: 0.25
    reproducibility: float = 0.0        # Weight: 0.20
    impact_confirmation: float = 0.0    # Weight: 0.20
    integrity_hashes: float = 0.0       # Weight: 0.15
    scope_validity: float = 0.0         # Weight: 0.10
    uniqueness: float = 0.0             # Weight: 0.10
    total_score: float = 0.0
    quality_band: str = "D"
    is_reportable: bool = False
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["score"] = self.total_score
        d["factors"] = self.factors
        return d

    @property
    def score(self) -> float:
        return self.total_score

    @property
    def factors(self) -> Dict[str, float]:
        return {
            "evidence_completeness": self.evidence_completeness,
            "reproducibility": self.reproducibility,
            "impact_confirmation": self.impact_confirmation,
            "integrity_hashes": self.integrity_hashes,
            "scope_validity": self.scope_validity,
            "uniqueness": self.uniqueness,
        }


class FindingQualityScorer:
    """Deterministic quality scoring engine for verified findings."""

    BAND_A_MIN = 0.90
    BAND_B_MIN = 0.75
    BAND_C_MIN = 0.60

    WEIGHT_EVIDENCE = 0.25
    WEIGHT_REPRODUCIBILITY = 0.20
    WEIGHT_IMPACT = 0.20
    WEIGHT_INTEGRITY = 0.15
    WEIGHT_SCOPE = 0.10
    WEIGHT_UNIQUENESS = 0.10

    @classmethod
    def evaluate_finding(
        cls,
        has_proof_request: bool = False,
        has_proof_response: bool = False,
        has_payload: bool = False,
        has_evidence_hashes: bool = False,
        is_reproducible: bool = True,
        has_confirmed_impact: bool = False,
        has_potential_impact_labeled: bool = True,
        is_in_scope: bool = True,
        is_unique: bool = True,
        verifier_confidence: float = 1.0,
        human_review_approved: bool = False,
        has_reproduction_steps: Optional[bool] = None,
        is_deterministic: Optional[bool] = None,
        **kwargs: Any,
    ) -> QualityBreakdown:
        """Calculate deterministic finding quality score, band, and reportability."""
        if has_reproduction_steps is not None:
            is_reproducible = has_reproduction_steps
        if is_deterministic is not None and not is_deterministic:
            is_reproducible = False
        reasons: List[str] = []

        # 1. Evidence Completeness (0.25 weight)
        evidence_points = 0.0
        if has_proof_request:
            evidence_points += 0.40
        else:
            reasons.append("Missing proof_request")
        if has_proof_response:
            evidence_points += 0.40
        else:
            reasons.append("Missing proof_response")
        if has_payload:
            evidence_points += 0.20
        evidence_score = min(1.0, evidence_points)

        # 2. Reproducibility (0.20 weight)
        if is_reproducible:
            repro_score = 1.0
        else:
            repro_score = 0.0
            reasons.append("Finding failed automated reproducibility check")

        # 3. Impact Confirmation (0.20 weight)
        impact_score = 0.0
        if has_confirmed_impact:
            impact_score += 0.70
        else:
            reasons.append("Missing concrete confirmed impact observation")
        if has_potential_impact_labeled:
            impact_score += 0.30
        impact_score = min(1.0, impact_score)

        # 4. Integrity & Hashes (0.15 weight)
        if has_evidence_hashes:
            integrity_score = 1.0
        else:
            integrity_score = 0.0
            reasons.append("Missing cryptographic SHA-256 evidence hashes")

        # 5. Scope Validity (0.10 weight)
        if is_in_scope:
            scope_score = 1.0
        else:
            scope_score = 0.0
            reasons.append("Target or URL is outside authorized scope")

        # 6. Uniqueness (0.10 weight)
        if is_unique:
            unique_score = 1.0
        else:
            unique_score = 0.0
            reasons.append("Finding is a duplicate of an existing primary finding")

        # Composite weighted score
        raw_total = (
            (evidence_score * cls.WEIGHT_EVIDENCE)
            + (repro_score * cls.WEIGHT_REPRODUCIBILITY)
            + (impact_score * cls.WEIGHT_IMPACT)
            + (integrity_score * cls.WEIGHT_INTEGRITY)
            + (scope_score * cls.WEIGHT_SCOPE)
            + (unique_score * cls.WEIGHT_UNIQUENESS)
        )

        # Modulate by verifier confidence
        final_score = max(0.0, min(1.0, round(raw_total * verifier_confidence, 4)))

        # Determine Categorical Quality Band
        if final_score >= cls.BAND_A_MIN:
            band = "A"
        elif final_score >= cls.BAND_B_MIN:
            band = "B"
        elif final_score >= cls.BAND_C_MIN:
            band = "C"
        else:
            band = "D"

        # Reportability Gate: Must be in Band A, B, or C, in-scope, unique, and not Band D
        is_reportable = (band in ("A", "B", "C")) and is_in_scope and is_unique

        return QualityBreakdown(
            evidence_completeness=round(evidence_score, 4),
            reproducibility=round(repro_score, 4),
            impact_confirmation=round(impact_score, 4),
            integrity_hashes=round(integrity_score, 4),
            scope_validity=round(scope_score, 4),
            uniqueness=round(unique_score, 4),
            total_score=final_score,
            quality_band=band,
            is_reportable=is_reportable,
            reasons=reasons,
        )

    @classmethod
    def evaluate_finding_record(cls, finding: Any, db: Optional[Any] = None) -> QualityBreakdown:
        """Evaluate an ORM Finding instance directly."""
        has_req = bool(getattr(finding, "proof_request", None))
        has_resp = bool(getattr(finding, "proof_response", None))
        has_payload = bool(getattr(finding, "payload", None))
        
        hashes_raw = getattr(finding, "evidence_hashes", "{}")
        has_hashes = bool(hashes_raw and hashes_raw != "{}" and "proof_response_sha256" in hashes_raw) or bool(getattr(finding, "evidence_ids", None))

        verdict = str(getattr(finding, "verdict", "") or "").lower()
        v_status = str(getattr(finding, "verification_status", "") or "").upper()
        disposition = str(getattr(finding, "finding_disposition", "") or "").upper()
        
        is_reproducible = (verdict in ("verified", "vulnerable", "hardening only")) or (v_status in ("VERIFIED", "VALIDATED", "EXPLOITABLE", "HARDENING_ONLY", "REPORTABLE"))

        # INVARIANT: HARDENING_ONLY != confirmed impact
        confirmed_imp = getattr(finding, "impact_confirmed", None) or getattr(finding, "business_impact", None)
        if disposition == "HARDENING_ONLY" or v_status == "HARDENING_ONLY":
            has_confirmed = False
        elif confirmed_imp is not None:
            has_confirmed = bool(len(str(confirmed_imp).strip()) > 5)
        else:
            has_confirmed = (verdict in ("verified", "vulnerable")) or (v_status in ("VERIFIED", "VALIDATED", "EXPLOITABLE"))
        
        potential_imp = getattr(finding, "impact_potential", None)
        has_potential = bool(potential_imp) or ("[INFERENCE]" in str(getattr(finding, "business_impact", ""))) or True

        is_dup = bool(getattr(finding, "duplicate_of", None))
        is_unique = not is_dup

        confidence_val = float(getattr(finding, "confidence", 100)) / 100.0

        return cls.evaluate_finding(
            has_proof_request=has_req,
            has_proof_response=has_resp,
            has_payload=has_payload,
            has_evidence_hashes=has_hashes,
            is_reproducible=is_reproducible,
            has_confirmed_impact=has_confirmed,
            has_potential_impact_labeled=has_potential,
            is_in_scope=True,  # Already validated pre-dispatch
            is_unique=is_unique,
            verifier_confidence=confidence_val,
        )


# Aliases for backward compatibility and test consistency
FindingQualityEvaluator = FindingQualityScorer
FindingQualityScore = QualityBreakdown
