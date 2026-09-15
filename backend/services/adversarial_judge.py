from dataclasses import dataclass, field
from typing import List, Optional
from backend.models.database import FindingDisposition

@dataclass
class Claim:
    role: str
    verdict: str  # "REAL" or "FALSE_POSITIVE" or "NEUTRAL"
    confidence: float  # 0.0 to 1.0
    is_hard_rule: bool = False
    reasoning: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)

@dataclass
class FinalVerdict:
    disposition: str
    confidence_score: int  # 0 to 100
    explanation: str

class VerificationSkeptic:
    @classmethod
    def evaluate(cls, vuln_type: str, proof_request: str, proof_response: str) -> tuple[Claim, any]:
        from backend.services.false_positive_gate import FalsePositiveGate
        
        fp_result = FalsePositiveGate.evaluate(
            vuln_type=vuln_type,
            proof_request=proof_request,
            proof_response=proof_response,
        )
        
        reasons = []
        if fp_result.reason:
            reasons.append(fp_result.reason)
            
        if fp_result.is_false_positive:
            claim = Claim(
                role="SKEPTIC",
                verdict="FALSE_POSITIVE",
                confidence=1.0,
                is_hard_rule=True,
                reasoning=reasons,
                evidence_refs=[fp_result.rule_triggered] if fp_result.rule_triggered else []
            )
        elif getattr(fp_result, "historical_fp_signal", False):
            claim = Claim(
                role="SKEPTIC",
                verdict="FALSE_POSITIVE",
                confidence=getattr(fp_result, "confidence_penalty", 0.5),
                reasoning=[f"Historical FP Match (distance: {getattr(fp_result, 'historical_fp_distance', 'unknown')})"],
                evidence_refs=["CHROMADB_HISTORICAL_MATCH"]
            )
        else:
            claim = Claim(role="SKEPTIC", verdict="NEUTRAL", confidence=0.0)
            
        return claim, fp_result

class VerificationProsecutor:
    @classmethod
    def evaluate(cls, evidence_chain: list, vuln_type: str, baseline_evidence: dict = None, dual_identity_evidence: dict = None) -> tuple[Claim, any]:
        from backend.services.reproducibility_evaluator import ReproducibilityEvaluator
        
        repro_result = ReproducibilityEvaluator.evaluate(
            evidence_chain=evidence_chain,
            vuln_type=vuln_type,
            baseline_evidence=baseline_evidence,
            dual_identity_evidence=dual_identity_evidence,
        )
        
        if repro_result.is_reproduced:
            claim = Claim(
                role="PROSECUTOR",
                verdict="REAL",
                confidence=repro_result.reproducibility_score or 1.0,
                reasoning=[repro_result.rationale] if repro_result.rationale else ["Successfully reproduced"],
                evidence_refs=["REPRO_EVALUATOR"]
            )
        else:
            claim = Claim(
                role="PROSECUTOR",
                verdict="NEUTRAL",
                confidence=repro_result.reproducibility_score or 0.0,
                reasoning=[repro_result.rationale] if repro_result.rationale else ["Failed to reproduce"],
                evidence_refs=["REPRO_EVALUATOR"]
            )
            
        return claim, repro_result

class AdversarialJudge:
    @classmethod
    def reconcile(cls, prosecutor: Claim, skeptic: Claim) -> FinalVerdict:
        if skeptic.is_hard_rule:
            return FinalVerdict(FindingDisposition.FALSE_POSITIVE.value, 10, "Skeptic hard rule triggered. Deterministic false positive.")
            
        p_conf = prosecutor.confidence if prosecutor.verdict == "REAL" else 0.0
        s_conf = skeptic.confidence if skeptic.verdict == "FALSE_POSITIVE" else 0.0
        
        def _get_level(c: float) -> str:
            if c >= 0.6: return "HIGH"
            if c >= 0.3: return "MEDIUM"
            return "LOW"
            
        p_level = _get_level(p_conf)
        s_level = _get_level(s_conf)
        
        reasoning = f"Prosecutor: {p_level} ({p_conf:.2f}), Skeptic: {s_level} ({s_conf:.2f}). "
        
        # 9-cell Decision Matrix
        if p_level == "HIGH":
            if s_level == "HIGH":
                return FinalVerdict(FindingDisposition.NEEDS_HUMAN_REVIEW.value, 50, reasoning + "Strong conflicting evidence. Needs human review.")
            elif s_level == "MEDIUM":
                return FinalVerdict(FindingDisposition.VALIDATED.value, 80, reasoning + "Prosecutor dominates, but with moderate skeptic doubts.")
            else: # LOW
                return FinalVerdict(FindingDisposition.VALIDATED.value, 95, reasoning + "Clear validation with no significant FP signal.")
                
        elif p_level == "MEDIUM":
            if s_level == "HIGH":
                return FinalVerdict(FindingDisposition.FALSE_POSITIVE.value, 10, reasoning + "Skeptic strongly dominates moderate prosecutor claims.")
            elif s_level == "MEDIUM":
                return FinalVerdict(FindingDisposition.INCONCLUSIVE.value, 40, reasoning + "Moderate conflicting signals. Inconclusive.")
            else: # LOW
                return FinalVerdict(FindingDisposition.HARDENING_ONLY.value, 50, reasoning + "Moderate proof with no FP signal. Likely hardening.")
                
        else: # p_level == LOW
            if s_level == "HIGH":
                return FinalVerdict(FindingDisposition.FALSE_POSITIVE.value, 10, reasoning + "Strong FP signal with weak prosecutor.")
            elif s_level == "MEDIUM":
                return FinalVerdict(FindingDisposition.FALSE_POSITIVE.value, 10, reasoning + "Moderate FP signal with weak prosecutor.")
            else: # LOW
                return FinalVerdict(FindingDisposition.INCONCLUSIVE.value, 30, reasoning + "Weak signals on both sides.")
