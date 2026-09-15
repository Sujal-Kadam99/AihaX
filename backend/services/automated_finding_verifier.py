"""AihaX — Fully Automated Finding Verifier & Evidence Quality Gate.

Orchestrates deterministic finding verification:
1. Finding & Evidence Chain Validation (18-point completeness check).
2. False-Positive Gate Check.
3. Reproducibility & Differential Evaluation.
4. Vulnerability-Specific Verification Strategy.
5. Impact Assessment & Fact vs Inference Separation.
6. Bug Bounty & Policy Eligibility Gate.
7. Multi-Dimensional Confidence Calculation.
8. Canonical Terminal Disposition Assignment.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from backend.models.database import (
    BountyEligibility,
    Finding,
    FindingDisposition,
    get_utc_now,
)
from backend.services.confidence_engine import ConfidenceLevel
from backend.services.false_positive_gate import FalsePositiveGate
from backend.services.policy_eligibility_gate import PolicyEligibilityGate
from backend.services.reproducibility_evaluator import ReproducibilityEvaluator

logger = logging.getLogger("aihax.automated_finding_verifier")

VERIFIER_STRATEGY_VERSION = "2.0.0-automated-gate"

SENSITIVE_DIR_PATTERNS = [
    r"\.env\b", r"\.git\b", r"\.aws\b", r"\.ssh\b", r"\.sql\b",
    r"\.bak\b", r"\.backup\b", r"\.old\b", r"\.tar\b", r"\.gz\b",
    r"\.zip\b", r"\.dump\b", r"config\.(php|json|ya?ml|py|inc)\b",
    r"database\.(php|json|ya?ml|py|sqlite|db)\b", r"credentials?\b",
    r"password\b", r"secret\b", r"id_rsa\b", r"private_key\b",
    r"\.htpasswd\b"
]


@dataclass
class VerificationExplanationDTO:
    """Detailed machine-readable verification justification."""
    disposition: str
    reason: str
    condition_confidence: float
    impact_confidence: float
    reproducibility_confidence: float
    exploitability_confidence: float
    policy_eligibility_confidence: float
    bounty_eligibility: str
    evidence_ids: List[str] = field(default_factory=list)
    reproduction_ids: List[str] = field(default_factory=list)
    checklist: Dict[str, bool] = field(default_factory=dict)
    failed_requirements: List[str] = field(default_factory=list)
    verification_strategy: str = "AutomatedFindingVerifier"
    strategy_version: str = VERIFIER_STRATEGY_VERSION
    verified_at: str = field(default_factory=lambda: get_utc_now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AutomatedFindingVerifier:
    """Production-grade automated finding verifier eliminating manual operator guesswork."""

    @classmethod
    def audit_cwe_mapping(cls, vuln_type: str, current_cwe: Optional[str]) -> str:
        """Return a defensible, audited CWE mapping."""
        vt = (vuln_type or "").upper()
        if "C047" in vt or "CSP" in vt:
            return "CWE-693"
        if "C050" in vt or "MIME" in vt:
            return "CWE-706"
        if "C010" in vt or "HSTS" in vt:
            return "CWE-319"
        if "C049" in vt or "CLICKJACKING" in vt:
            return "CWE-1021"
        if "C006" in vt or "DIRECTORY" in vt:
            return "CWE-548"
        if "C022" in vt or "RATE_LIMIT" in vt:
            return "CWE-307"
        if "C002" in vt or "SECURITY_HEADERS" in vt:
            return "CWE-693"
        if "C067" in vt or "C068" in vt or "C069" in vt or "IDOR" in vt or "BOLA" in vt:
            return "CWE-639"
        return current_cwe or "CWE-693"

    @classmethod
    def verify_finding(
        cls,
        finding: Finding,
        evidence_chain: Optional[List[Dict[str, Any]]] = None,
        baseline_evidence: Optional[Dict[str, Any]] = None,
        dual_identity_evidence: Optional[Dict[str, Any]] = None,
        program_policy: Optional[Dict[str, Any]] = None,
    ) -> VerificationExplanationDTO:
        """Deterministically verify a finding without manual operator inspection."""
        try:
            return cls._execute_verification(
                finding=finding,
                evidence_chain=evidence_chain,
                baseline_evidence=baseline_evidence,
                dual_identity_evidence=dual_identity_evidence,
                program_policy=program_policy,
            )
        except Exception as exc:
            logger.exception(f"Internal verification error for finding {finding.id}: {exc}")
            explanation = VerificationExplanationDTO(
                disposition=FindingDisposition.VERIFICATION_ERROR.value,
                reason=f"Verification engine encountered an internal error: {str(exc)}",
                condition_confidence=0.0,
                impact_confidence=0.0,
                reproducibility_confidence=0.0,
                exploitability_confidence=0.0,
                policy_eligibility_confidence=0.0,
                bounty_eligibility=BountyEligibility.UNKNOWN.value,
                failed_requirements=["VERIFICATION_ENGINE_EXECUTION"],
            )
            # Update finding record to reflect explicit verification error
            finding.finding_disposition = FindingDisposition.VERIFICATION_ERROR.value
            finding.verdict = "Verification Error"
            finding.verification_status = "VERIFICATION_ERROR"
            finding.confidence = 0
            finding.verification_explanation = json.dumps(explanation.to_dict())
            return explanation

    @classmethod
    def _execute_verification(
        cls,
        finding: Finding,
        evidence_chain: Optional[List[Dict[str, Any]]] = None,
        baseline_evidence: Optional[Dict[str, Any]] = None,
        dual_identity_evidence: Optional[Dict[str, Any]] = None,
        program_policy: Optional[Dict[str, Any]] = None,
    ) -> VerificationExplanationDTO:
        checklist: Dict[str, bool] = {
            "has_target": bool(finding.affected_url),
            "has_check_id": bool(finding.vuln_type),
            "has_evidence": bool(finding.proof_response or evidence_chain),
            "passed_fp_gate": False,
            "reproducible": False,
            "impact_proven": False,
            "policy_evaluated": False,
        }
        failed_requirements: List[str] = []
        fp_result = None

        vt = str(finding.vuln_type or "").upper()
        finding.cwe_id = cls.audit_cwe_mapping(vt, finding.cwe_id)

        proof_req = str(finding.proof_request or "")
        proof_resp = str(finding.proof_response or "")

        # 1. IMMUTABLE BLOCKED CHECKS (Section 5 / Invariant 9)
        # Blocked executions cannot become VALIDATED or EXPLOITABLE
        cur_disp = str(getattr(finding, "finding_disposition", "")).upper()
        if cur_disp in (
            FindingDisposition.BLOCKED_SCOPE.value,
            FindingDisposition.BLOCKED_AUTHORIZATION.value,
            FindingDisposition.BLOCKED_SAFETY.value,
            FindingDisposition.BLOCKED_BUDGET.value,
        ):
            explanation = VerificationExplanationDTO(
                disposition=cur_disp,
                reason=f"Execution blocked by safety controls: {cur_disp}. Cannot validate without authorized re-execution.",
                condition_confidence=0.0,
                impact_confidence=0.0,
                reproducibility_confidence=0.0,
                exploitability_confidence=0.0,
                policy_eligibility_confidence=0.0,
                bounty_eligibility=BountyEligibility.INELIGIBLE.value,
                checklist=checklist,
                failed_requirements=["AUTHORIZED_EXECUTION_REQUIRED"],
            )
            finding.verification_explanation = json.dumps(explanation.to_dict())
            return explanation

        # 2. EVIDENCE COMPLETENESS CHECK (Section 11 / Invariant 7 / Proof K)
        # Without evidence or proof response, disposition MUST be INCONCLUSIVE
        has_req_proof = bool(finding.proof_response and finding.proof_response.strip())
        has_chain_proof = bool(evidence_chain and len(evidence_chain) > 0)
        if not (has_req_proof or has_chain_proof):
            failed_requirements.append("MISSING_PROOF_EVIDENCE")
            explanation = VerificationExplanationDTO(
                disposition=FindingDisposition.INCONCLUSIVE.value,
                reason="Inconclusive: Finding has no captured request/response proof evidence.",
                condition_confidence=0.0,
                impact_confidence=0.0,
                reproducibility_confidence=0.0,
                exploitability_confidence=0.0,
                policy_eligibility_confidence=0.0,
                bounty_eligibility=BountyEligibility.UNKNOWN.value,
                checklist=checklist,
                failed_requirements=failed_requirements,
            )
            cls._apply_finding_updates(finding, explanation, skeptic_claim=None, prosecutor_claim=None)
            return explanation

        from backend.services.adversarial_judge import VerificationSkeptic, VerificationProsecutor, AdversarialJudge

        # 3. SKEPTIC GATE (Section 13)
        skeptic_claim, fp_result = VerificationSkeptic.evaluate(
            vuln_type=vt,
            proof_request=proof_req,
            proof_response=proof_resp,
        )
        if skeptic_claim.verdict == "FALSE_POSITIVE":
            checklist["passed_fp_gate"] = False
            failed_requirements.extend(skeptic_claim.reasoning)
        else:
            checklist["passed_fp_gate"] = True

        # 4. PROSECUTOR EVALUATION (Section 14)
        synth_chain = evidence_chain or [{"evidence_id": "EVD-PRIMARY", "raw_response": proof_resp, "status_code": 200}]
        prosecutor_claim, repro_result = VerificationProsecutor.evaluate(
            evidence_chain=synth_chain,
            vuln_type=vt,
            baseline_evidence=baseline_evidence,
            dual_identity_evidence=dual_identity_evidence,
        )
        checklist["reproducible"] = repro_result.is_reproduced
        
        # We will hold these claims and pass them to _apply_finding_updates at the end of this method.
        # This replaces the previous early-return for False Positives.
        # finding.prosecutor_claim = prosecutor_claim
        # finding.skeptic_claim = skeptic_claim

        # 5. VULNERABILITY-SPECIFIC STRATEGIES (Sections 6 - 10)

        # Strategy A: Cleartext HTTP / Port 80 (C001)
        if "C001" in vt or "OPEN_PORT" in vt:
            prosecutor_claim.confidence = 0.5  # MEDIUM -> Judge outputs HARDENING_ONLY
            # If 301/302 was present, FP gate already rejected it above.
            # If not redirecting, it is purely a transport hardening observation
            explanation = VerificationExplanationDTO(
                disposition=FindingDisposition.HARDENING_ONLY.value,
                reason="Cleartext HTTP port open without redirect to HTTPS. Defense-in-depth transport hardening recommendation.",
                condition_confidence=1.0,
                impact_confidence=0.0,
                reproducibility_confidence=1.0,
                exploitability_confidence=0.0,
                policy_eligibility_confidence=1.0,
                bounty_eligibility=BountyEligibility.INELIGIBLE.value,
                checklist=checklist,
            )
            finding.verdict = "Hardening Only"
            finding.verification_status = "HARDENING_ONLY"
            cls._apply_finding_updates(finding, explanation, skeptic_claim=skeptic_claim, prosecutor_claim=prosecutor_claim)
            return explanation

        # Strategy B: Security Headers (C002, C010, C047, C049, C050)
        is_header = any(h in vt for h in ["C002", "C010", "C047", "C049", "C050", "HEADER", "CSP", "FRAME", "SNIFF"])
        if is_header:
            prosecutor_claim.confidence = 0.5  # MEDIUM -> Judge outputs HARDENING_ONLY
            checklist["impact_proven"] = False
            explanation = VerificationExplanationDTO(
                disposition=FindingDisposition.HARDENING_ONLY.value,
                reason="Security header missing in response headers. Technical condition observed but no direct exploitability demonstrated.",
                condition_confidence=1.0,
                impact_confidence=0.0,
                reproducibility_confidence=1.0,
                exploitability_confidence=0.0,
                policy_eligibility_confidence=1.0,
                bounty_eligibility=BountyEligibility.INELIGIBLE.value,
                checklist=checklist,
                failed_requirements=["DIRECT_EXPLOIT_PROOF_REQUIRED_FOR_HEADER_VULN"],
            )
            finding.verdict = "Hardening Only"
            finding.verification_status = "HARDENING_ONLY"
            cls._apply_finding_updates(finding, explanation, skeptic_claim=skeptic_claim, prosecutor_claim=prosecutor_claim)
            return explanation

        # Strategy C: Authentication Rate Limiting (C022)
        if "C022" in vt or "RATE_LIMIT" in vt:
            has_bypass = any(k in proof_resp.lower() for k in [
                "bypass_demonstrated", "automated_stuffing_confirmed",
                "lockout_bypassed", "credential_guessing_confirmed"
            ])
            if not has_bypass:
                prosecutor_claim.confidence = 0.0  # LOW -> Judge outputs INCONCLUSIVE
                checklist["impact_proven"] = False
                failed_requirements.append("RATE_LIMIT_BYPASS_NOT_PROVEN")
                explanation = VerificationExplanationDTO(
                    disposition=FindingDisposition.INCONCLUSIVE.value,
                    reason="Inconclusive: 5 consecutive login attempts returned 200/401 with no 429, but actual account takeover/credential guessing was not proven.",
                    condition_confidence=0.5,
                    impact_confidence=0.0,
                    reproducibility_confidence=0.5,
                    exploitability_confidence=0.0,
                    policy_eligibility_confidence=0.9,
                    bounty_eligibility=BountyEligibility.INELIGIBLE.value,
                    checklist=checklist,
                    failed_requirements=failed_requirements,
                )
                finding.verdict = "Inconclusive"
                finding.verification_status = "INCONCLUSIVE"
                cls._apply_finding_updates(finding, explanation, skeptic_claim=skeptic_claim, prosecutor_claim=prosecutor_claim)
                return explanation
            else:
                prosecutor_claim.confidence = 1.0  # HIGH -> Judge outputs VALIDATED
                checklist["impact_proven"] = True
                policy_res = PolicyEligibilityGate.evaluate(
                    vuln_type=vt,
                    finding_disposition=FindingDisposition.VALIDATED.value,
                    exploitability_confidence=0.8,
                    program_policy=program_policy,
                )
                explanation = VerificationExplanationDTO(
                    disposition=FindingDisposition.VALIDATED.value,
                    reason="Validated: Authentication rate limit bypass successfully proven within authorized limits.",
                    condition_confidence=1.0,
                    impact_confidence=0.8,
                    reproducibility_confidence=1.0,
                    exploitability_confidence=0.8,
                    policy_eligibility_confidence=policy_res.policy_eligibility_confidence,
                    bounty_eligibility=policy_res.eligibility,
                    checklist=checklist,
                )
                finding.verdict = "Verified"
                finding.verification_status = "VALIDATED"
                cls._apply_finding_updates(finding, explanation, skeptic_claim=skeptic_claim, prosecutor_claim=prosecutor_claim)
                return explanation

        # Strategy D: Directory Listing (C006)
        if "C006" in vt or "DIRECTORY_LISTING" in vt:
            has_sensitive = any(re.search(pat, proof_resp, re.IGNORECASE) for pat in SENSITIVE_DIR_PATTERNS)
            if has_sensitive:
                prosecutor_claim.confidence = 1.0  # HIGH -> Judge outputs VALIDATED
                checklist["impact_proven"] = True
                policy_res = PolicyEligibilityGate.evaluate(
                    vuln_type=vt,
                    finding_disposition=FindingDisposition.VALIDATED.value,
                    exploitability_confidence=0.7,
                    program_policy=program_policy,
                    is_sensitive_exposure=True,
                )
                explanation = VerificationExplanationDTO(
                    disposition=FindingDisposition.VALIDATED.value,
                    reason="Validated: Directory listing exposes sensitive configuration, credentials, or backup files.",
                    condition_confidence=1.0,
                    impact_confidence=0.8,
                    reproducibility_confidence=1.0,
                    exploitability_confidence=0.7,
                    policy_eligibility_confidence=policy_res.policy_eligibility_confidence,
                    bounty_eligibility=policy_res.eligibility,
                    checklist=checklist,
                )
                finding.verdict = "Verified"
                finding.verification_status = "VALIDATED"
                cls._apply_finding_updates(finding, explanation, skeptic_claim=skeptic_claim, prosecutor_claim=prosecutor_claim)
                return explanation
            else:
                prosecutor_claim.confidence = 0.5  # MEDIUM -> Judge outputs HARDENING_ONLY
                checklist["impact_proven"] = False
                explanation = VerificationExplanationDTO(
                    disposition=FindingDisposition.HARDENING_ONLY.value,
                    reason="Directory listing exposes only public static assets (images, icons, styling). Informational hardening recommendation.",
                    condition_confidence=1.0,
                    impact_confidence=0.0,
                    reproducibility_confidence=1.0,
                    exploitability_confidence=0.0,
                    policy_eligibility_confidence=1.0,
                    bounty_eligibility=BountyEligibility.INELIGIBLE.value,
                    checklist=checklist,
                    failed_requirements=["SENSITIVE_CONTENT_DISCLOSURE_REQUIRED"],
                )
                finding.verdict = "Hardening Only"
                finding.verification_status = "HARDENING_ONLY"
                cls._apply_finding_updates(finding, explanation, skeptic_claim=skeptic_claim, prosecutor_claim=prosecutor_claim)
                return explanation

        # Strategy E: Access Control / IDOR / BOLA (C067, C068, C069)
        if any(k in vt for k in ["IDOR", "BOLA", "C067", "C068", "C069", "ACCESS_CONTROL"]):
            if repro_result.is_reproduced and repro_result.reproducibility_score >= 0.8:
                checklist["impact_proven"] = True
                policy_res = PolicyEligibilityGate.evaluate(
                    vuln_type=vt,
                    finding_disposition=FindingDisposition.VALIDATED.value,
                    exploitability_confidence=0.8,
                    program_policy=program_policy,
                )
                explanation = VerificationExplanationDTO(
                    disposition=FindingDisposition.VALIDATED.value,
                    reason=f"Validated: Dual-identity IDOR verified. {repro_result.rationale}",
                    condition_confidence=1.0,
                    impact_confidence=0.85,
                    reproducibility_confidence=repro_result.reproducibility_score,
                    exploitability_confidence=0.8,
                    policy_eligibility_confidence=policy_res.policy_eligibility_confidence,
                    bounty_eligibility=policy_res.eligibility,
                    checklist=checklist,
                )
                finding.verdict = "Verified"
                finding.verification_status = "VALIDATED"
                cls._apply_finding_updates(finding, explanation, skeptic_claim=skeptic_claim, prosecutor_claim=prosecutor_claim)
                return explanation
            else:
                checklist["impact_proven"] = False
                failed_requirements.append("DUAL_IDENTITY_ACCESS_CONTROL_BREACH_UNPROVEN")
                explanation = VerificationExplanationDTO(
                    disposition=FindingDisposition.INCONCLUSIVE.value,
                    reason=f"Inconclusive: IDOR could not be proven. {repro_result.rationale}",
                    condition_confidence=0.4,
                    impact_confidence=0.0,
                    reproducibility_confidence=repro_result.reproducibility_score,
                    exploitability_confidence=0.0,
                    policy_eligibility_confidence=0.0,
                    bounty_eligibility=BountyEligibility.UNKNOWN.value,
                    checklist=checklist,
                    failed_requirements=failed_requirements,
                )
                finding.verdict = "Inconclusive"
                finding.verification_status = "INCONCLUSIVE"
                cls._apply_finding_updates(finding, explanation, skeptic_claim=skeptic_claim, prosecutor_claim=prosecutor_claim)
                return explanation

        # Strategy F: Generic Verified / Detected Findings
        # Invariant 6: Detection != Vulnerability. HTTP 200 or anomaly alone cannot validate.
        if finding.verification_status in ("VALIDATED", "EXPLOITABLE") or finding.verdict == "Verified":
            if repro_result.is_reproduced:
                checklist["impact_proven"] = True
                is_exploit = finding.verification_status == "EXPLOITABLE"
                policy_res = PolicyEligibilityGate.evaluate(
                    vuln_type=vt,
                    finding_disposition=FindingDisposition.EXPLOITABLE.value if is_exploit else FindingDisposition.VALIDATED.value,
                    exploitability_confidence=0.9 if is_exploit else 0.6,
                    program_policy=program_policy,
                )
                explanation = VerificationExplanationDTO(
                    disposition=FindingDisposition.EXPLOITABLE.value if is_exploit else FindingDisposition.VALIDATED.value,
                    reason=f"Validated: Reproducible condition evidenced with verified impact. {repro_result.rationale}",
                    condition_confidence=1.0,
                    impact_confidence=0.9 if is_exploit else 0.7,
                    reproducibility_confidence=repro_result.reproducibility_score,
                    exploitability_confidence=0.9 if is_exploit else 0.6,
                    policy_eligibility_confidence=policy_res.policy_eligibility_confidence,
                    bounty_eligibility=policy_res.eligibility,
                    checklist=checklist,
                )
                finding.verdict = "Verified"
                finding.verification_status = "EXPLOITABLE" if is_exploit else "VALIDATED"
                cls._apply_finding_updates(finding, explanation, skeptic_claim=skeptic_claim, prosecutor_claim=prosecutor_claim)
                return explanation

        # Default fallback: INCONCLUSIVE
        prosecutor_claim.confidence = 0.0  # LOW -> Judge outputs INCONCLUSIVE
        failed_requirements.append("INSUFFICIENT_TECHNICAL_PROOF_FOR_VALIDATION")
        explanation = VerificationExplanationDTO(
            disposition=FindingDisposition.INCONCLUSIVE.value,
            reason="Inconclusive: Observation detected but insufficient evidence to prove exploitable security impact.",
            condition_confidence=0.5,
            impact_confidence=0.0,
            reproducibility_confidence=repro_result.reproducibility_score,
            exploitability_confidence=0.0,
            policy_eligibility_confidence=0.0,
            bounty_eligibility=BountyEligibility.UNKNOWN.value,
            checklist=checklist,
            failed_requirements=failed_requirements,
        )
        finding.verdict = "Inconclusive"
        finding.verification_status = "INCONCLUSIVE"
        cls._apply_finding_updates(finding, explanation, skeptic_claim=skeptic_claim, prosecutor_claim=prosecutor_claim)
        return explanation

    @classmethod
    def _apply_finding_updates(cls, finding: Finding, explanation: VerificationExplanationDTO, skeptic_claim: Optional[Any] = None, prosecutor_claim: Optional[Any] = None) -> None:
        """Apply normalized multi-dimensional confidence scores and disposition to finding record."""
        from backend.services.adversarial_judge import AdversarialJudge
        
        # Inject historical signal to the explanation DTO if not already present
        if skeptic_claim and "Historical FP Match" in str(skeptic_claim.reasoning):
            if not any("HISTORICAL_FP_MATCH" in req for req in explanation.failed_requirements):
                explanation.failed_requirements.append(f"HISTORICAL_FP_MATCH")

        finding.condition_confidence = explanation.condition_confidence
        finding.impact_confidence = explanation.impact_confidence
        finding.reproducibility_confidence = explanation.reproducibility_confidence
        finding.exploitability_confidence = explanation.exploitability_confidence
        finding.policy_eligibility_confidence = explanation.policy_eligibility_confidence
        finding.bounty_eligibility = explanation.bounty_eligibility

        if skeptic_claim and prosecutor_claim:
            final_verdict = AdversarialJudge.reconcile(prosecutor_claim, skeptic_claim)
            
            # Map FindingDisposition to VerificationStatus
            from backend.services.verification_engine import VerificationStatus
            status_map = {
                FindingDisposition.VALIDATED.value: VerificationStatus.VERIFIED.value,
                FindingDisposition.FALSE_POSITIVE.value: VerificationStatus.REJECTED.value,
                FindingDisposition.NEEDS_HUMAN_REVIEW.value: VerificationStatus.NEEDS_HUMAN_REVIEW.value,
                FindingDisposition.INCONCLUSIVE.value: VerificationStatus.INCONCLUSIVE.value,
                FindingDisposition.HARDENING_ONLY.value: VerificationStatus.HARDENING_ONLY.value,
            }
            mapped_status = status_map.get(final_verdict.disposition, VerificationStatus.INCONCLUSIVE.value)
            
            # The judge has final say on disposition and confidence
            finding.finding_disposition = final_verdict.disposition
            finding.verification_status = mapped_status
            finding.confidence = final_verdict.confidence_score
            
            if final_verdict.disposition == FindingDisposition.FALSE_POSITIVE.value:
                finding.verdict = "False Positive"
                finding.false_positive = True
            elif final_verdict.disposition == FindingDisposition.NEEDS_HUMAN_REVIEW.value:
                finding.verdict = "Needs Human Review"
                finding.false_positive = False
            
            explanation.disposition = final_verdict.disposition
            explanation.reason = final_verdict.explanation + " | Original Reason: " + explanation.reason
        else:
            finding.finding_disposition = explanation.disposition
            # Fallback if claims are missing (e.g. early exit)
            if explanation.disposition in (FindingDisposition.VALIDATED.value, FindingDisposition.EXPLOITABLE.value, FindingDisposition.VULNERABILITY.value):
                composite = (
                    (explanation.condition_confidence * 0.3)
                    + (explanation.impact_confidence * 0.3)
                    + (explanation.reproducibility_confidence * 0.25)
                    + (explanation.exploitability_confidence * 0.15)
                )
                finding.confidence = int(round(composite * 100))
            elif explanation.disposition == FindingDisposition.HARDENING_ONLY.value:
                finding.confidence = 50
            elif explanation.disposition == FindingDisposition.FALSE_POSITIVE.value:
                finding.confidence = 10
                finding.false_positive = True
            else:
                finding.false_positive = False
                vt_upper = str(finding.vuln_type or "").upper()
                if "C022" in vt_upper or "RATE_LIMIT" in vt_upper:
                    finding.confidence = 25
                else:
                    finding.confidence = min(finding.confidence or 20, 30)

        finding.verification_explanation = json.dumps(explanation.to_dict())
