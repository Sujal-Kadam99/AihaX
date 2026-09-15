"""AihaX Phase 7 — Confidence Engine.

Deterministic multi-path confidence scoring for verified findings.

Invariants:
- Confidence is strictly independent from severity (HIGH severity + MEDIUM confidence is valid).
- Confidence is NOT inflated by repeated identical heuristic observations.
- No LLM involvement in confidence scoring.
- Score is computed from discrete, traceable evidence signals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ──────────────────────────────────────────────────────────────────────────────
# 1. CONFIDENCE LEVEL
# ──────────────────────────────────────────────────────────────────────────────

class ConfidenceLevel(str, Enum):
    CERTAIN = "CERTAIN"   # 90–100: repeated reproduction + negative control + independent verification
    HIGH    = "HIGH"      # 75–89:  deterministic reproduction confirmed
    MEDIUM  = "MEDIUM"    # 50–74:  strong differential but not fully independently verified
    LOW     = "LOW"       # 0–49:   candidate only / heuristic only


# ──────────────────────────────────────────────────────────────────────────────
# 2. CONFIDENCE SIGNALS (input dataclass)
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ConfidenceSignals:
    """Discrete boolean signals driving confidence calculation.

    Each signal must map to a specific observable evidence item.
    Do not set signals to True based on LLM suggestion.
    """
    # Reproduction signals
    deterministically_reproduced: bool = False      # Finding was actively reproduced
    math_canary_confirmed: bool = False             # Mathematical canary (e.g., 7*7=49) confirmed
    baseline_differential_verified: bool = False    # Clear baseline vs mutation differential
    reflection_in_correct_context: bool = False     # Canary reflected in expected context

    # Control signals
    negative_control_passed: bool = False           # Benign input produced clean response
    false_positive_control_verified: bool = False   # Explicitly verified NOT a false positive

    # Independent path signals
    independent_verification_paths: int = 0        # Count of independent verification methods used
    # Each independent path adds confidence (capped at 3 to prevent inflation)

    # Evidence quality signals
    evidence_hash_valid: bool = False              # SHA-256 evidence hash matches stored value
    proof_request_present: bool = False            # Actual HTTP request captured
    proof_response_present: bool = False           # Actual HTTP response captured
    response_consistent_across_repeats: bool = False  # Same signal across multiple requests

    # Reduction signals (confidence penalties)
    heuristic_only: bool = False                   # Only heuristic match, no reproduction
    missing_baseline: bool = False                 # No baseline comparison available
    inconsistent_responses: bool = False           # Response signal was inconsistent
    passive_observation_only: bool = False         # Passive check, no active verification
    client_side_static_only: bool = False          # Only static source code reflection (DOM XSS)

    # Authentication context
    auth_context_verified: bool = False            # Auth context was explicitly verified


@dataclass
class ConfidenceAssessment:
    """Output of ConfidenceEngine — deterministic confidence with rationale."""
    level: ConfidenceLevel
    score: int                            # 0–100 raw integer score
    signals_used: ConfidenceSignals
    explanation: str = ""
    independent_paths_counted: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "score": self.score,
            "explanation": self.explanation,
            "independent_paths_counted": self.independent_paths_counted,
            "signals": {
                "deterministically_reproduced": self.signals_used.deterministically_reproduced,
                "math_canary_confirmed": self.signals_used.math_canary_confirmed,
                "baseline_differential_verified": self.signals_used.baseline_differential_verified,
                "reflection_in_correct_context": self.signals_used.reflection_in_correct_context,
                "negative_control_passed": self.signals_used.negative_control_passed,
                "false_positive_control_verified": self.signals_used.false_positive_control_verified,
                "independent_verification_paths": self.signals_used.independent_verification_paths,
                "evidence_hash_valid": self.signals_used.evidence_hash_valid,
                "proof_request_present": self.signals_used.proof_request_present,
                "proof_response_present": self.signals_used.proof_response_present,
                "response_consistent_across_repeats": self.signals_used.response_consistent_across_repeats,
                "heuristic_only": self.signals_used.heuristic_only,
                "missing_baseline": self.signals_used.missing_baseline,
                "inconsistent_responses": self.signals_used.inconsistent_responses,
                "passive_observation_only": self.signals_used.passive_observation_only,
                "client_side_static_only": self.signals_used.client_side_static_only,
                "auth_context_verified": self.signals_used.auth_context_verified,
            },
        }


# ──────────────────────────────────────────────────────────────────────────────
# 3. CONFIDENCE ENGINE
# ──────────────────────────────────────────────────────────────────────────────

class ConfidenceEngine:
    """Deterministic multi-path confidence scorer.

    Rules:
    - Candidate only → LOW
    - Strong differential → MEDIUM
    - Repeated deterministic reproduction → HIGH
    - Repeated + negative control + independent path → CERTAIN

    Duplicate identical heuristics do NOT inflate confidence beyond MEDIUM.
    """

    @classmethod
    def assess(cls, signals: ConfidenceSignals) -> ConfidenceAssessment:
        """Compute confidence level and score from discrete evidence signals."""
        score = 0
        paths = min(max(0, signals.independent_verification_paths), 3)

        # ── Primary reproduction signals ─────────────────────────────────────
        if signals.deterministically_reproduced:
            score += 35
        if signals.math_canary_confirmed:
            score += 30
        if signals.baseline_differential_verified:
            score += 25
        if signals.reflection_in_correct_context:
            score += 20

        # ── Control signals ──────────────────────────────────────────────────
        if signals.negative_control_passed:
            score += 15
        if signals.false_positive_control_verified:
            score += 15

        # ── Independent paths (each path adds diminishing value) ─────────────
        # Cap at 3 paths to prevent inflation
        score += paths * 8

        # ── Evidence quality ─────────────────────────────────────────────────
        if signals.evidence_hash_valid:
            score += 5
        if signals.proof_request_present:
            score += 3
        if signals.proof_response_present:
            score += 3
        if signals.response_consistent_across_repeats:
            score += 5
        if signals.auth_context_verified:
            score += 5

        # ── Penalties ────────────────────────────────────────────────────────
        if signals.heuristic_only:
            score = min(score, 45)  # Cap heuristic-only at MEDIUM floor
        if signals.missing_baseline:
            score -= 20
        if signals.inconsistent_responses:
            score -= 25
        if signals.passive_observation_only:
            score = min(score, 40)  # Passive observations cap at LOW ceiling
        if signals.client_side_static_only:
            score = min(score, 40)  # Static client-side reflection caps at LOW

        score = max(0, min(100, score))

        # ── Level mapping ────────────────────────────────────────────────────
        if score >= 90:
            level = ConfidenceLevel.CERTAIN
        elif score >= 75:
            level = ConfidenceLevel.HIGH
        elif score >= 50:
            level = ConfidenceLevel.MEDIUM
        else:
            level = ConfidenceLevel.LOW

        explanation = cls._build_explanation(signals, score, level, paths)

        return ConfidenceAssessment(
            level=level,
            score=score,
            signals_used=signals,
            explanation=explanation,
            independent_paths_counted=paths,
        )

    @classmethod
    def from_finding_evidence(
        cls,
        proof_request: Optional[str],
        proof_response: Optional[str],
        verification_reason_code: Optional[str],
        evidence_ids: Optional[str],
        evidence_hash_valid: bool = False,
        is_false_positive: bool = False,
    ) -> ConfidenceAssessment:
        """Build ConfidenceSignals from raw Finding fields and assess.

        This bridges the ORM Finding model to ConfidenceSignals without
        requiring the caller to manually construct signals.
        """
        reason = str(verification_reason_code or "").upper()

        deterministically_reproduced = "REPRODUCED_SUCCESSFULLY" in reason
        math_canary = "MATH_CANARY" in reason or "PROPERTY_DEMONSTRATED" in reason
        baseline_diff = "BASELINE" in reason and ("DIFFERENTIAL" in reason or deterministically_reproduced)
        negative_control = "NEGATIVE_CONTROL" in reason or "FALSE_POSITIVE" not in reason
        heuristic_only = "HEURISTIC_ONLY" in reason
        missing_baseline = "MISSING_BASELINE" in reason
        passive = "PASSIVE" in reason or (not proof_request and not proof_response)
        inconsistent = "INCONSISTENT" in reason

        signals = ConfidenceSignals(
            deterministically_reproduced=deterministically_reproduced,
            math_canary_confirmed=math_canary,
            baseline_differential_verified=baseline_diff,
            negative_control_passed=negative_control and not is_false_positive,
            false_positive_control_verified=not is_false_positive,
            evidence_hash_valid=evidence_hash_valid,
            proof_request_present=bool(proof_request),
            proof_response_present=bool(proof_response),
            heuristic_only=heuristic_only,
            missing_baseline=missing_baseline,
            passive_observation_only=passive,
            inconsistent_responses=inconsistent,
            independent_verification_paths=1 if deterministically_reproduced else 0,
        )
        return cls.assess(signals)

    @staticmethod
    def _build_explanation(
        signals: ConfidenceSignals,
        score: int,
        level: ConfidenceLevel,
        paths: int,
    ) -> str:
        parts = []
        if signals.deterministically_reproduced:
            parts.append("deterministically reproduced")
        if signals.math_canary_confirmed:
            parts.append("mathematical canary confirmed")
        if signals.baseline_differential_verified:
            parts.append("baseline differential verified")
        if signals.reflection_in_correct_context:
            parts.append("canary reflected in correct context")
        if signals.negative_control_passed:
            parts.append("negative control passed")
        if signals.false_positive_control_verified:
            parts.append("false-positive control verified")
        if paths > 0:
            parts.append(f"{paths} independent verification path(s)")
        if signals.heuristic_only:
            parts.append("PENALTY: heuristic-only match (capped)")
        if signals.missing_baseline:
            parts.append("PENALTY: no baseline comparison")
        if signals.inconsistent_responses:
            parts.append("PENALTY: inconsistent responses")
        if signals.passive_observation_only:
            parts.append("PENALTY: passive observation only")
        if signals.client_side_static_only:
            parts.append("PENALTY: client-side static reflection only")
        if not parts:
            parts.append("no reproduction signals — candidate state only")
        return f"Confidence {level.value} (score={score}): {'; '.join(parts)}."


__all__ = ["ConfidenceLevel", "ConfidenceSignals", "ConfidenceAssessment", "ConfidenceEngine"]
