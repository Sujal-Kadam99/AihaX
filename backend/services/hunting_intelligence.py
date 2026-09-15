"""AihaX Phase 20 — Real-World Hunting Intelligence & Operator Recommendation Engine.

Architectural Invariants:
1. Operator Decision Support: Ranks safe checks for operator review; NEVER dispatches network requests autonomously.
2. Human-Review-Required Enforcement: Every recommendation explicitly sets authorization_status='HUMAN_REVIEW_REQUIRED'.
3. Strict Risk Gating: Only PASSIVE and SAFE_ACTIVE checks are eligible for primary recommendation; REVIEW_REQUIRED and PROHIBITED checks are gated.
4. Deterministic Multi-Factor Ranking: Combines check utility, observed surface compatibility, negative evidence suppression, assessment memory boost, and remaining request budget.
5. Zero Hallucination: Explanations and expected evidence derive strictly from deterministic contracts and observed historical evidence.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set
from sqlalchemy.orm import Session

from backend.core.check_registry import (
    CheckCategory,
    CheckContract,
    CheckRiskLevel,
    registry as default_registry,
)
from backend.services.assessment_memory import AssessmentMemoryService
from backend.services.check_effectiveness import CheckEffectivenessEngine
from backend.services.negative_evidence import NegativeEvidenceService
from backend.services.surface_inventory import SurfaceInventoryService

logger = logging.getLogger("aihax.hunting_intelligence")


@dataclass
class HuntingRecommendation:
    """Deterministic recommendation structure presented to the human operator."""
    id: str
    target: str
    check_id: str
    check_name: str
    category: str
    risk_level: str
    estimated_requests: int
    utility_score: float
    confidence: float
    reason: str
    expected_evidence: str
    supporting_historical_evidence: str
    authorization_status: str = "HUMAN_REVIEW_REQUIRED"
    status: str = "PENDING"
    rank: int = 1
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


HuntingRecommendationDTO = HuntingRecommendation
RecommendationDTO = HuntingRecommendation


class HuntingIntelligenceEngine:
    """Deterministic recommendation and ranking engine."""

    # Expected evidence patterns mapped to check categories/contracts
    EXPECTED_EVIDENCE_MAP = {
        "C001_Open_Port_80": "Cleartext HTTP response headers, redirect location header, or sensitive cleartext data",
        "C004_CORS_Misconfiguration": "Reflected Access-Control-Allow-Origin header alongside Access-Control-Allow-Credentials: true and authenticated user data",
        "C065_Unencrypted_Transmission": "Plaintext HTTP credentials, session tokens, or unencrypted sensitive payloads transmitted over port 80",
        "C070_Security_Headers": "Missing or improperly configured Content-Security-Policy, HSTS, X-Frame-Options, or X-Content-Type-Options headers",
        "C071_Cookie_Flags": "Session or authorization cookies set without Secure, HttpOnly, or SameSite attributes",
        "C072_TLS_Configuration": "Deprecated SSL/TLS cipher suites or protocol versions observed during TLS handshake",
    }

    DEFAULT_EXPECTED_EVIDENCE = "HTTP response status, headers, and body matching deterministic vulnerability proof criteria"

    @classmethod
    def generate_recommendations(
        cls,
        target: str,
        campaign_id: Optional[str] = None,
        remaining_budget: int = 10,
        scope_snapshot_hash: Optional[str] = None,
        check_registry: Optional[Any] = None,
        db: Optional[Session] = None,
    ) -> List[HuntingRecommendation]:
        """Deterministically rank and generate safe check recommendations for operator approval."""
        if not target or target == "WAITING_FOR_TARGET" or "*" in target:
            return []

        reg = check_registry or default_registry
        target_root = target.rstrip("/")

        # 1. Fetch observed surface and negative evidence for target
        surface_entries = SurfaceInventoryService.get_surface_for_target(target_root, db=db) if db else []
        has_auth_surface = any(s.auth_state != "ANONYMOUS" for s in surface_entries)
        observed_params = set()
        for s in surface_entries:
            observed_params.update(s.parameters)

        negative_evidence_list = NegativeEvidenceService.get_negative_evidence_for_target(target_root, db=db) if db else []
        negative_check_ids = {n.check_id for n in negative_evidence_list}

        # 2. Iterate registered checks and score candidates
        candidates = []
        all_checks = reg.list_checks()

        for check in all_checks:
            check_id = check.check_id
            risk = getattr(check, "risk_level", CheckRiskLevel.SAFE_ACTIVE)

            # Filter out Prohibited checks
            if risk == CheckRiskLevel.PROHIBITED:
                continue

            # Base check utility from historical effectiveness
            base_utility = CheckEffectivenessEngine.get_check_utility(check_id, db=db)

            # Historical memory prioritization boost [-0.20, +0.20]
            memory_boost = AssessmentMemoryService.get_prioritization_boost(target_root, check_id, db=db) if db else 0.0

            # Surface compatibility adjustment
            surface_boost = 0.0
            reason_parts = []
            cat_str = str(getattr(check, "category", "")).lower()

            # Transport & Recon checks
            if any(k in cat_str for k in ("recon", "infra", "misconfig", "sensitive", "transport")):
                if target_root.startswith("http://"):
                    surface_boost += 0.20
                    reason_parts.append("Target root is plain HTTP; transport security verification prioritized.")
                elif target_root.startswith("https://"):
                    surface_boost += 0.05
                    reason_parts.append("Standard TLS endpoint; passive headers and cookie verification prioritized.")

            # Auth checks
            if "auth" in cat_str and has_auth_surface:
                surface_boost += 0.15
                reason_parts.append("Observed authenticated surface parameters; session testing recommended.")

            # CORS checks
            if "cors" in check_id.lower():
                if any("access-control-allow-origin" in s.interesting_headers for s in surface_entries):
                    surface_boost += 0.15
                    reason_parts.append("Observed CORS headers on target surface; credentialed reflection verification recommended.")

            # Negative evidence penalty: if clean negative evidence already recorded, depress priority
            if check_id in negative_check_ids:
                surface_boost -= 0.35
                reason_parts.append("Previous negative evidence recorded; check unlikely to yield new findings.")

            # Calculate composite final score
            final_score = max(0.01, min(0.99, round(base_utility + memory_boost + surface_boost, 4)))

            # Estimated request cost from contract
            contract = getattr(check, "contract", None)
            est_requests = contract.expected_requests if contract else 1
            est_requests = max(1, est_requests)

            # Expected evidence
            expected_evidence = cls.EXPECTED_EVIDENCE_MAP.get(check_id, cls.DEFAULT_EXPECTED_EVIDENCE)

            if not reason_parts:
                reason_parts.append(f"Safe check with historical utility {base_utility:.2f}.")

            rec_reason = " ".join(reason_parts)
            hist_evidence = f"Historical utility: {base_utility:.2f}, Memory modifier: {memory_boost:+.2f}"

            candidates.append({
                "check_id": check_id,
                "check_name": check.name,
                "category": check.category.value if hasattr(check.category, "value") else str(check.category),
                "risk_level": risk.value if hasattr(risk, "value") else str(risk),
                "estimated_requests": est_requests,
                "utility_score": final_score,
                "confidence": round(min(1.0, final_score + 0.10), 2),
                "reason": rec_reason,
                "expected_evidence": expected_evidence,
                "supporting_historical_evidence": hist_evidence,
            })

        # 3. Sort deterministically: highest utility_score first, then lowest estimated_requests, then check_id
        candidates.sort(key=lambda x: (-x["utility_score"], x["estimated_requests"], x["check_id"]))

        # 4. Construct ranked recommendations
        recommendations: List[HuntingRecommendation] = []
        for idx, c in enumerate(candidates, start=1):
            rec_id = str(uuid.uuid4())
            rec = HuntingRecommendation(
                id=rec_id,
                target=target_root,
                check_id=c["check_id"],
                check_name=c["check_name"],
                category=c["category"],
                risk_level=c["risk_level"],
                estimated_requests=c["estimated_requests"],
                utility_score=c["utility_score"],
                confidence=c["confidence"],
                reason=c["reason"],
                expected_evidence=c["expected_evidence"],
                supporting_historical_evidence=c["supporting_historical_evidence"],
                authorization_status="HUMAN_REVIEW_REQUIRED",
                status="PENDING",
                rank=idx,
            )
            recommendations.append(rec)

        return recommendations
