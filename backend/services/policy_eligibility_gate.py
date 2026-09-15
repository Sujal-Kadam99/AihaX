"""AihaX — Policy & Bug Bounty Eligibility Gate.

Enforces deterministic distinction between TECHNICAL VALIDITY and BUG BOUNTY ELIGIBILITY:
1. Technically valid findings may still be excluded by program policy.
2. Hardening observations (e.g. missing headers, benign directory listings) are ineligible for bounty awards.
3. Common out-of-scope classes (DoS, rate-limit without account takeover, self-XSS, logout CSRF) are explicitly flagged.
4. When program rules are unspecified, eligibility defaults to UNKNOWN.
5. Invariant: Policy unknown CANNOT become automatically ELIGIBLE (Proof L).
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from backend.models.database import BountyEligibility

logger = logging.getLogger("aihax.policy_eligibility_gate")

STANDARD_EXCLUSION_PATTERNS = [
    ("C002", "Missing security headers without demonstrated exploit chain are excluded by standard bounty policy."),
    ("C010", "TLS configuration weaknesses (missing HSTS, cipher suites) are excluded as hardening recommendations."),
    ("C047", "Missing CSP without script injection proof is excluded as hardening."),
    ("C049", "Missing X-Frame-Options on pages without sensitive state-changing actions is excluded."),
    ("C050", "Missing X-Content-Type-Options without executable MIME abuse is excluded."),
    ("C022", "Missing rate limiting without credential guessing / takeover proof is excluded."),
    ("C006_BENIGN", "Directory listing containing only public static assets (images, fonts, scripts) is excluded."),
    ("DOS", "Denial of Service (DoS/DDoS) is strictly out of scope for bug bounty programs."),
    ("SELF_XSS", "Self-XSS without social engineering chain is excluded."),
    ("LOGOUT_CSRF", "Logout CSRF without session fixation impact is excluded."),
    ("SPF_DMARC", "Missing SPF/DMARC/DKIM records without verifiable mail spoofing impact are excluded."),
]


@dataclass
class PolicyEligibilityResult:
    """Outcome of policy and bounty eligibility evaluation."""
    eligibility: str  # ELIGIBLE, INELIGIBLE, UNKNOWN
    policy_eligibility_confidence: float  # 0.0 to 1.0
    rationale: str
    is_hardening_only: bool = False
    policy_name: Optional[str] = None
    applicable_exclusions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PolicyEligibilityGate:
    """Deterministic evaluator separating technical finding reality from bounty eligibility."""

    @classmethod
    def evaluate(
        cls,
        vuln_type: str,
        finding_disposition: str,
        exploitability_confidence: float,
        program_policy: Optional[Dict[str, Any]] = None,
        is_sensitive_exposure: bool = False,
    ) -> PolicyEligibilityResult:
        """Evaluate bounty eligibility based on finding class, disposition, and program policy."""
        vt = (vuln_type or "").upper()
        disp = (finding_disposition or "").upper()

        # 1. Non-vulnerabilities and false positives are strictly INELIGIBLE
        if disp in ("FALSE_POSITIVE", "REJECTED", "NOT_APPLICABLE"):
            return PolicyEligibilityResult(
                eligibility=BountyEligibility.INELIGIBLE.value,
                policy_eligibility_confidence=1.0,
                rationale="False positives and non-applicable checks are completely ineligible for bounty.",
            )

        # 2. Hardening-only findings are strictly INELIGIBLE
        if disp == "HARDENING_ONLY":
            return PolicyEligibilityResult(
                eligibility=BountyEligibility.INELIGIBLE.value,
                policy_eligibility_confidence=1.0,
                rationale="Hardening-only findings (missing headers, benign directories) are out of scope for bug bounties.",
                is_hardening_only=True,
                applicable_exclusions=["HARDENING_RECOMMENDATION_EXCLUDED"],
            )

        # 3. Check standard out-of-scope exclusions
        for prefix, reason in STANDARD_EXCLUSION_PATTERNS:
            if prefix in vt:
                # If C006 directory listing has sensitive exposure proven, it can be eligible
                if prefix == "C006_BENIGN" and is_sensitive_exposure:
                    continue
                # If C022 has exploitability confidence > 0.7 (actual credential bypass proven), it can be eligible
                if prefix == "C022" and exploitability_confidence >= 0.7:
                    continue

                return PolicyEligibilityResult(
                    eligibility=BountyEligibility.INELIGIBLE.value,
                    policy_eligibility_confidence=0.95,
                    rationale=reason,
                    applicable_exclusions=[prefix],
                )

        # 4. Custom Program Policy if provided
        if program_policy:
            excluded_types = [t.upper() for t in program_policy.get("excluded_vuln_types", [])]
            for exc in excluded_types:
                if exc in vt:
                    return PolicyEligibilityResult(
                        eligibility=BountyEligibility.INELIGIBLE.value,
                        policy_eligibility_confidence=1.0,
                        rationale=f"Vulnerability type '{vuln_type}' is explicitly excluded by program policy.",
                        policy_name=program_policy.get("name"),
                        applicable_exclusions=[exc],
                    )

            included_types = [t.upper() for t in program_policy.get("in_scope_vuln_types", [])]
            if included_types and any(inc in vt for inc in included_types):
                if disp in ("VALIDATED", "EXPLOITABLE", "VULNERABILITY") and exploitability_confidence >= 0.5:
                    return PolicyEligibilityResult(
                        eligibility=BountyEligibility.ELIGIBLE.value,
                        policy_eligibility_confidence=0.9,
                        rationale=f"Vulnerability type '{vuln_type}' is explicitly eligible under program policy.",
                        policy_name=program_policy.get("name"),
                    )

        # 5. Verified high-impact vulnerabilities without explicit policy
        high_impact_classes = ["IDOR", "BOLA", "RCE", "SQLI", "SSRF", "AUTH_BYPASS", "CREDENTIAL_LEAK"]
        if any(h in vt for h in high_impact_classes) and disp in ("VALIDATED", "EXPLOITABLE", "VULNERABILITY"):
            if program_policy is None:
                # Invariant (Proof L): Policy unknown CANNOT become automatically ELIGIBLE
                return PolicyEligibilityResult(
                    eligibility=BountyEligibility.UNKNOWN.value,
                    policy_eligibility_confidence=0.0,
                    rationale="Finding is technically validated, but program policy rules are unavailable. Eligibility remains UNKNOWN.",
                )
            else:
                return PolicyEligibilityResult(
                    eligibility=BountyEligibility.ELIGIBLE.value,
                    policy_eligibility_confidence=0.85,
                    rationale="High-impact verified vulnerability within standard bounty scope.",
                )

        # Default fallback: UNKNOWN
        return PolicyEligibilityResult(
            eligibility=BountyEligibility.UNKNOWN.value,
            policy_eligibility_confidence=0.0,
            rationale="Bounty eligibility cannot be conclusively determined from available policy rules.",
        )
