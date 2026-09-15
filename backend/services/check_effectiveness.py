"""AihaX Phase 20 — Deterministic Check Effectiveness Model & Scoring Engine.

Architectural Invariants:
1. Deterministic Utility Scoring: Calculates reproducible check utility bounded strictly in [0.0, 1.0].
   Formula: utility = (verification_rate * 0.35) + (evidence_quality * 0.30) + (uniqueness * 0.20) + (impact_signal * 0.15)
2. Zero-Hallucination & Zero-LLM: Scoring is 100% mathematical and derived from observed verification outcomes.
3. Explainable Metric Decomposition: Every score component is exposed with clear mathematical provenance.
4. Fail-Safe Defaults: Safely handles unexecuted checks with baseline conservative priors.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence
from sqlalchemy.orm import Session

from backend.models.database import CheckEffectivenessRecord, get_utc_now

logger = logging.getLogger("aihax.check_effectiveness")


@dataclass
class CheckMetrics:
    """Deterministic metrics container for a security check."""
    check_id: str = ""
    executions: int = 0
    candidates: int = 0
    verified: int = 0
    rejected: int = 0
    inconclusive: int = 0
    duplicates: int = 0
    evidence_complete: int = 0
    evidence_incomplete: int = 0
    total_requests: int = 0
    average_requests: float = 0.0
    verification_rate: float = 0.0
    evidence_quality: float = 0.0
    uniqueness: float = 0.0
    impact_signal: float = 0.0
    utility: float = 0.0
    times_executed: int = 0
    times_verified: int = 0
    times_false_positive: int = 0
    times_duplicate: int = 0
    utility_score: float = 0.0
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        if not self.times_executed:
            self.times_executed = self.executions
        if not self.times_verified:
            self.times_verified = self.verified
        if not self.times_false_positive:
            self.times_false_positive = self.rejected
        if not self.times_duplicate:
            self.times_duplicate = self.duplicates
        if not self.utility_score:
            self.utility_score = self.utility

    @property
    def uniqueness_rate(self) -> float:
        return self.uniqueness

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


CheckEffectivenessDTO = CheckMetrics


class CheckEffectivenessEngine:
    """Deterministic check effectiveness calculator and registry."""

    # Formula Weights (Sum = 1.00)
    WEIGHT_VERIFICATION = 0.35
    WEIGHT_EVIDENCE = 0.30
    WEIGHT_UNIQUENESS = 0.20
    WEIGHT_IMPACT = 0.15

    @classmethod
    def calculate_utility_score(
        cls,
        verification_rate: float,
        evidence_quality: float,
        uniqueness: float = 1.0,
        impact_signal: float = 0.5,
        uniqueness_rate: Optional[float] = None,
    ) -> float:
        """Calculate bounded multi-factor utility score directly from component rates."""
        unq_val = uniqueness_rate if uniqueness_rate is not None else uniqueness
        vr = max(0.0, min(1.0, float(verification_rate)))
        eq = max(0.0, min(1.0, float(evidence_quality)))
        uq = max(0.0, min(1.0, float(unq_val)))
        im = max(0.0, min(1.0, float(impact_signal)))

        raw = (
            (vr * cls.WEIGHT_VERIFICATION)
            + (eq * cls.WEIGHT_EVIDENCE)
            + (uq * cls.WEIGHT_UNIQUENESS)
            + (im * cls.WEIGHT_IMPACT)
        )
        return max(0.0, min(1.0, round(raw, 4)))

    @classmethod
    def record_finding_outcome(
        cls,
        check_id: str,
        is_verified: bool,
        evidence_quality: float = 1.0,
        is_duplicate: bool = False,
        severity_weight: float = 0.5,
        is_false_positive: bool = False,
        impact_weight: Optional[float] = None,
        db: Optional[Session] = None,
    ) -> CheckMetrics:
        """Helper alias to record finding verification / false positive outcome."""
        if is_false_positive:
            is_verified = False
        eff_weight = impact_weight if impact_weight is not None else severity_weight
        verdict = "VERIFIED" if is_verified else "REJECTED"
        sev_label = "HIGH" if eff_weight >= 0.7 else "MEDIUM"
        is_ev_complete = bool(is_verified and evidence_quality >= 0.6)
        return cls.record_outcome(
            check_id=check_id,
            verdict=verdict,
            is_duplicate=is_duplicate,
            evidence_complete=is_ev_complete,
            requests_spent=1,
            severity=sev_label,
            db=db,
        )

    @classmethod
    def calculate_utility(
        cls,
        executions: int,
        candidates: int,
        verified: int,
        rejected: int,
        inconclusive: int,
        duplicates: int,
        evidence_complete: int,
        evidence_incomplete: int,
        total_requests: int = 0,
        high_severity_count: int = 0,
    ) -> CheckMetrics:
        """Calculate bounded, deterministic utility score and metric breakdown."""
        # Enforce non-negative integers
        executions = max(0, int(executions))
        candidates = max(0, int(candidates))
        verified = max(0, int(verified))
        rejected = max(0, int(rejected))
        inconclusive = max(0, int(inconclusive))
        duplicates = max(0, int(duplicates))
        evidence_complete = max(0, int(evidence_complete))
        evidence_incomplete = max(0, int(evidence_incomplete))
        total_requests = max(0, int(total_requests))
        high_severity_count = max(0, int(high_severity_count))

        # Average requests per execution
        avg_requests = float(total_requests) / float(executions) if executions > 0 else 0.0

        if executions == 0 and candidates == 0:
            # Cold-start prior: unexecuted checks receive neutral baseline (0.50)
            verification_rate = 0.50
            evidence_quality = 0.50
            uniqueness = 1.00
            impact_signal = 0.50
        else:
            # 1. Verification Rate: Verified / Total Candidates (or Verified / Executions if candidates > 0)
            total_evaluated = verified + rejected + inconclusive
            if total_evaluated > 0:
                verification_rate = float(verified) / float(total_evaluated)
            elif candidates > 0:
                verification_rate = float(verified) / float(candidates)
            else:
                verification_rate = 0.0

            # 2. Evidence Quality: Complete / (Complete + Incomplete)
            total_evidence = evidence_complete + evidence_incomplete
            if total_evidence > 0:
                evidence_quality = float(evidence_complete) / float(total_evidence)
            elif verified > 0:
                evidence_quality = 1.00
            else:
                evidence_quality = 0.50 if candidates == 0 else 0.0

            # 3. Uniqueness: 1.0 - (Duplicates / (Verified + Duplicates))
            total_found = verified + duplicates
            if total_found > 0:
                duplicate_rate = float(duplicates) / float(total_found)
                uniqueness = max(0.0, 1.0 - duplicate_rate)
            else:
                uniqueness = 1.00

            # 4. Impact Signal: High Severity Ratio or presence of verified findings
            if verified > 0:
                impact_signal = min(1.0, 0.50 + (0.50 * (float(high_severity_count) / float(verified))))
            elif candidates > 0:
                impact_signal = 0.20
            else:
                impact_signal = 0.50

        # Bounding all component scores strictly [0.0, 1.0]
        verification_rate = max(0.0, min(1.0, verification_rate))
        evidence_quality = max(0.0, min(1.0, evidence_quality))
        uniqueness = max(0.0, min(1.0, uniqueness))
        impact_signal = max(0.0, min(1.0, impact_signal))

        # Composite utility score calculation
        raw_utility = (
            (verification_rate * cls.WEIGHT_VERIFICATION)
            + (evidence_quality * cls.WEIGHT_EVIDENCE)
            + (uniqueness * cls.WEIGHT_UNIQUENESS)
            + (impact_signal * cls.WEIGHT_IMPACT)
        )
        utility = max(0.0, min(1.0, round(raw_utility, 4)))

        return CheckMetrics(
            check_id="",
            executions=executions,
            candidates=candidates,
            verified=verified,
            rejected=rejected,
            inconclusive=inconclusive,
            duplicates=duplicates,
            evidence_complete=evidence_complete,
            evidence_incomplete=evidence_incomplete,
            total_requests=total_requests,
            average_requests=round(avg_requests, 2),
            verification_rate=round(verification_rate, 4),
            evidence_quality=round(evidence_quality, 4),
            uniqueness=round(uniqueness, 4),
            impact_signal=round(impact_signal, 4),
            utility=utility,
        )

    @classmethod
    def record_outcome(
        cls,
        check_id: str,
        verdict: str,
        is_duplicate: bool = False,
        evidence_complete: bool = True,
        requests_spent: int = 1,
        severity: str = "MEDIUM",
        db: Optional[Session] = None,
    ) -> CheckMetrics:
        """Record a single check execution outcome and persist/update effectiveness."""
        if not check_id:
            raise ValueError("check_id cannot be empty")

        if db is None:
            # In-memory computation for testing / stateless execution
            is_verified = verdict.upper() in ("VERIFIED", "VULNERABLE")
            is_rejected = verdict.upper() in ("REJECTED", "FALSE_POSITIVE")
            is_inconclusive = verdict.upper() in ("INCONCLUSIVE", "UNVERIFIED")
            metrics = cls.calculate_utility(
                executions=1,
                candidates=1 if (is_verified or is_rejected) else 0,
                verified=1 if is_verified else 0,
                rejected=1 if is_rejected else 0,
                inconclusive=1 if is_inconclusive else 0,
                duplicates=1 if is_duplicate else 0,
                evidence_complete=1 if evidence_complete else 0,
                evidence_incomplete=0 if evidence_complete else 1,
                total_requests=requests_spent,
                high_severity_count=1 if (is_verified and severity.upper() in ("HIGH", "CRITICAL")) else 0,
            )
            metrics.check_id = check_id
            return metrics

        # Query existing record or create new
        record = db.query(CheckEffectivenessRecord).filter(CheckEffectivenessRecord.check_id == check_id).first()
        if not record:
            record = CheckEffectivenessRecord(
                check_id=check_id,
                executions=0,
                candidates=0,
                verified=0,
                rejected=0,
                inconclusive=0,
                duplicates=0,
                evidence_complete=0,
                evidence_incomplete=0,
                total_requests=0,
                average_requests=0.0,
                verification_rate=0.0,
                evidence_quality=0.0,
                uniqueness=1.0,
                impact_signal=0.5,
                utility=0.5,
                updated_at=get_utc_now(),
            )
            db.add(record)

        record.executions += 1
        record.total_requests += max(0, requests_spent)

        is_verified = verdict.upper() in ("VERIFIED", "VULNERABLE")
        is_rejected = verdict.upper() in ("REJECTED", "FALSE_POSITIVE")
        is_inconclusive = verdict.upper() in ("INCONCLUSIVE", "UNVERIFIED")

        if is_verified:
            record.candidates += 1
            record.verified += 1
        elif is_rejected:
            record.candidates += 1
            record.rejected += 1
        elif is_inconclusive:
            record.inconclusive += 1

        if is_duplicate:
            record.duplicates += 1

        if evidence_complete:
            record.evidence_complete += 1
        else:
            record.evidence_incomplete += 1

        high_sev = 1 if (is_verified and severity.upper() in ("HIGH", "CRITICAL")) else 0
        computed = cls.calculate_utility(
            executions=record.executions,
            candidates=record.candidates,
            verified=record.verified,
            rejected=record.rejected,
            inconclusive=record.inconclusive,
            duplicates=record.duplicates,
            evidence_complete=record.evidence_complete,
            evidence_incomplete=record.evidence_incomplete,
            total_requests=record.total_requests,
            high_severity_count=high_sev,
        )

        record.average_requests = computed.average_requests
        record.verification_rate = computed.verification_rate
        record.evidence_quality = computed.evidence_quality
        record.uniqueness = computed.uniqueness
        record.impact_signal = computed.impact_signal
        record.utility = computed.utility
        record.updated_at = get_utc_now()

        db.commit()
        db.refresh(record)

        computed.check_id = check_id
        return computed

    @classmethod
    def get_check_utility(cls, check_id: str, db: Optional[Session] = None) -> float:
        """Retrieve utility score for check_id or default 0.50 if unexecuted."""
        if db is not None:
            rec = db.query(CheckEffectivenessRecord).filter(CheckEffectivenessRecord.check_id == check_id).first()
            if rec:
                return float(rec.utility)
        return 0.50

    @classmethod
    def get_check_effectiveness(cls, check_id: str, db: Optional[Session] = None) -> CheckMetrics:
        """Retrieve check metrics for check_id or return default cold start baseline."""
        if db is not None:
            rec = db.query(CheckEffectivenessRecord).filter(CheckEffectivenessRecord.check_id == check_id).first()
            if rec:
                return CheckMetrics(
                    check_id=rec.check_id,
                    executions=rec.executions,
                    candidates=rec.candidates,
                    verified=rec.verified,
                    rejected=rec.rejected,
                    inconclusive=rec.inconclusive,
                    duplicates=rec.duplicates,
                    evidence_complete=rec.evidence_complete,
                    evidence_incomplete=rec.evidence_incomplete,
                    total_requests=rec.total_requests,
                    average_requests=rec.average_requests,
                    verification_rate=rec.verification_rate,
                    evidence_quality=rec.evidence_quality,
                    uniqueness=rec.uniqueness,
                    impact_signal=rec.impact_signal,
                    utility=rec.utility,
                    times_executed=rec.executions,
                    times_verified=rec.verified,
                    times_false_positive=rec.rejected,
                    times_duplicate=rec.duplicates,
                    utility_score=rec.utility,
                    updated_at=rec.updated_at.isoformat() if hasattr(rec.updated_at, "isoformat") else str(rec.updated_at),
                )
        return CheckMetrics(
            check_id=check_id,
            executions=0,
            candidates=0,
            verified=0,
            rejected=0,
            inconclusive=0,
            duplicates=0,
            evidence_complete=0,
            evidence_incomplete=0,
            total_requests=0,
            average_requests=0.0,
            verification_rate=0.0,
            evidence_quality=0.0,
            uniqueness=1.0,
            impact_signal=0.5,
            utility=0.50,
            times_executed=0,
            times_verified=0,
            times_false_positive=0,
            times_duplicate=0,
            utility_score=0.50,
        )

    @classmethod
    def get_all_effectiveness(cls, db: Optional[Session] = None) -> List[CheckMetrics]:
        """Retrieve all check effectiveness records sorted deterministically by utility DESC."""
        if db is None:
            return []
        records = db.query(CheckEffectivenessRecord).order_by(CheckEffectivenessRecord.utility.desc(), CheckEffectivenessRecord.check_id.asc()).all()
        return [
            CheckMetrics(
                check_id=r.check_id,
                executions=r.executions,
                candidates=r.candidates,
                verified=r.verified,
                rejected=r.rejected,
                inconclusive=r.inconclusive,
                duplicates=r.duplicates,
                evidence_complete=r.evidence_complete,
                evidence_incomplete=r.evidence_incomplete,
                total_requests=r.total_requests,
                average_requests=r.average_requests,
                verification_rate=r.verification_rate,
                evidence_quality=r.evidence_quality,
                uniqueness=r.uniqueness,
                impact_signal=r.impact_signal,
                utility=r.utility,
                times_executed=r.executions,
                times_verified=r.verified,
                times_false_positive=r.rejected,
                times_duplicate=r.duplicates,
                utility_score=r.utility,
                updated_at=r.updated_at.isoformat() if hasattr(r.updated_at, "isoformat") else str(r.updated_at),
            )
            for r in records
        ]
