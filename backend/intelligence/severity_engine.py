"""AihaX Phase 7 — Severity Engine.

Evidence-driven, deterministic severity assessment.

Invariants:
- Severity is calculated from structured evidence factors, NOT from LLM output.
- Severity and confidence are strictly independent (e.g., HIGH severity + MEDIUM confidence is valid).
- The assessment model follows a structured impact × exploitability × context formula.
- No hallucination: all factors must map to observable finding properties.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from backend.models.database import Finding


# ──────────────────────────────────────────────────────────────────────────────
# 1. SEVERITY ENUM
# ──────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ──────────────────────────────────────────────────────────────────────────────
# 2. SEVERITY FACTORS
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class SeverityFactors:
    """Structured factors driving the severity calculation."""
    # Impact axes
    data_exposure: bool = False          # Finding exposes sensitive data
    privilege_boundary_crossed: bool = False   # Auth/privilege escalation
    scope_crossing: bool = False         # Crosses from app → OS / cloud
    code_execution: bool = False         # Finding implies RCE or template execution
    data_integrity: bool = False         # Can write/modify data
    availability_impact: bool = False    # Can cause denial of service

    # Exploitability axes
    authentication_required: bool = False   # Requires auth to exploit (reduces risk)
    interaction_required: bool = False      # Requires user interaction (reduces risk)
    exploitable_remotely: bool = True      # Remote exploitability
    deterministically_reproducible: bool = False  # Can be reproduced reliably

    # Context axes
    affects_session: bool = False        # Affects session/auth tokens
    affects_admin_surface: bool = False  # Affects admin interface
    passive_only: bool = False           # Purely passive observation (reduces severity)
    safe_encoding_present: bool = False  # Output is safely encoded (reduces xss severity)


@dataclass
class SeverityAssessment:
    """Output of the SeverityEngine — deterministic severity with full rationale."""
    severity: Severity
    score: int                    # 0–100 raw score before thresholding
    factors: SeverityFactors
    evidence_ids: List[str] = field(default_factory=list)
    override_reason: Optional[str] = None  # Only set if check contract overrides
    explanation: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "score": self.score,
            "explanation": self.explanation,
            "override_reason": self.override_reason,
            "evidence_ids": self.evidence_ids,
            "factors": {
                "data_exposure": self.factors.data_exposure,
                "privilege_boundary_crossed": self.factors.privilege_boundary_crossed,
                "scope_crossing": self.factors.scope_crossing,
                "code_execution": self.factors.code_execution,
                "data_integrity": self.factors.data_integrity,
                "availability_impact": self.factors.availability_impact,
                "authentication_required": self.factors.authentication_required,
                "interaction_required": self.factors.interaction_required,
                "exploitable_remotely": self.factors.exploitable_remotely,
                "deterministically_reproducible": self.factors.deterministically_reproducible,
                "affects_session": self.factors.affects_session,
                "affects_admin_surface": self.factors.affects_admin_surface,
                "passive_only": self.factors.passive_only,
                "safe_encoding_present": self.factors.safe_encoding_present,
            },
        }


# ──────────────────────────────────────────────────────────────────────────────
# 3. CHECK-LEVEL SEVERITY ANCHORS (from check contracts / CWE knowledge)
# ──────────────────────────────────────────────────────────────────────────────

# Maps check number prefix → minimum severity floor
_CHECK_SEVERITY_FLOOR: Dict[str, Severity] = {
    # Critical floors
    "C023": Severity.HIGH,    # SQL Injection
    "C024": Severity.HIGH,    # Blind SQL Injection
    "C025": Severity.MEDIUM,  # NoSQL Injection
    "C026": Severity.HIGH,    # Command Injection Indicators
    "C027": Severity.CRITICAL, # OS Command Injection
    "C028": Severity.HIGH,    # SSTI
    "C032": Severity.HIGH,    # LFI
    "C033": Severity.HIGH,    # XXE
    "C034": Severity.HIGH,    # LDAP Injection
    "C035": Severity.HIGH,    # EL Injection
    "C036": Severity.HIGH,    # SSRF
    "C067": Severity.HIGH,    # IDOR Numeric
    "C068": Severity.MEDIUM,  # IDOR UUID
    "C069": Severity.HIGH,    # BOLA
    "C071": Severity.HIGH,    # Privilege Escalation
    # High floors
    "C037": Severity.MEDIUM,  # Reflected XSS (can be MEDIUM without interaction required flag)
    "C038": Severity.HIGH,    # Stored XSS
    "C020": Severity.HIGH,    # JWT Algorithm Weakness
    "C021": Severity.MEDIUM,  # JWT Claim Validation
    "C031": Severity.HIGH,    # Path Traversal
    # Medium floors
    "C004": Severity.MEDIUM,  # CORS Misconfiguration
    "C008": Severity.HIGH,    # Subdomain Takeover
    "C009": Severity.MEDIUM,  # Exposed Admin
    "C012": Severity.MEDIUM,  # Auth Bypass
    "C017": Severity.MEDIUM,  # Session Fixation
    "C018": Severity.MEDIUM,  # Session Invalidation
    "C055": Severity.HIGH,    # Dangerous File Upload
    "C075": Severity.MEDIUM,  # Race Condition
    "C076": Severity.MEDIUM,  # Replay Attack
    "C077": Severity.MEDIUM,  # Missing Reauthentication
    # Low / Info floors
    "C001": Severity.INFO,
    "C002": Severity.LOW,
    "C003": Severity.MEDIUM,
    "C006": Severity.LOW,
    "C007": Severity.MEDIUM,
    "C010": Severity.MEDIUM,
    "C011": Severity.INFO,
    "C013": Severity.LOW,
    "C014": Severity.LOW,
    "C015": Severity.LOW,
    "C016": Severity.LOW,
    "C019": Severity.MEDIUM,
    "C022": Severity.MEDIUM,
    "C029": Severity.LOW,
    "C030": Severity.MEDIUM,
    "C039": Severity.MEDIUM,
    "C040": Severity.MEDIUM,
    "C041": Severity.MEDIUM,
    "C042": Severity.MEDIUM,
    "C043": Severity.LOW,
    "C044": Severity.MEDIUM,
    "C045": Severity.MEDIUM,
    "C046": Severity.MEDIUM,
    "C047": Severity.MEDIUM,
    "C048": Severity.LOW,
    "C049": Severity.LOW,
    "C050": Severity.LOW,
    "C051": Severity.LOW,
    "C052": Severity.LOW,
    "C053": Severity.LOW,
    "C054": Severity.LOW,
    "C056": Severity.MEDIUM,
    "C057": Severity.HIGH,
    "C058": Severity.INFO,
    "C059": Severity.LOW,
    "C060": Severity.INFO,
    "C061": Severity.MEDIUM,
    "C062": Severity.HIGH,
    "C063": Severity.HIGH,
    "C064": Severity.MEDIUM,
    "C065": Severity.MEDIUM,
    "C066": Severity.MEDIUM,
    "C070": Severity.HIGH,
    "C072": Severity.HIGH,
    "C073": Severity.MEDIUM,
    "C074": Severity.MEDIUM,
    "C005": Severity.INFO,
}

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_SEVERITY_SCORE_MAP = {Severity.INFO: 5, Severity.LOW: 25, Severity.MEDIUM: 50, Severity.HIGH: 75, Severity.CRITICAL: 95}


def _max_severity(a: Severity, b: Severity) -> Severity:
    return a if _SEVERITY_ORDER.index(a) >= _SEVERITY_ORDER.index(b) else b


def _score_to_severity(score: int) -> Severity:
    if score >= 90:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 45:
        return Severity.MEDIUM
    if score >= 20:
        return Severity.LOW
    return Severity.INFO


# ──────────────────────────────────────────────────────────────────────────────
# 4. SEVERITY ENGINE
# ──────────────────────────────────────────────────────────────────────────────

class SeverityEngine:
    """Deterministic, evidence-driven severity calculator.

    LLM MUST NOT control the final severity value.
    All inputs must derive from observable finding properties.
    """

    @classmethod
    def assess(
        cls,
        finding: Finding,
        evidence_ids: Optional[List[str]] = None,
    ) -> SeverityAssessment:
        """Derive a deterministic severity assessment from a finding.

        Args:
            finding: The Finding ORM object.
            evidence_ids: Optional list of evidence IDs to attach.

        Returns:
            SeverityAssessment with severity, score, and full factor breakdown.
        """
        check_id = str(finding.vuln_type or "")
        m = re.match(r"^(C\d{3})", check_id)
        check_prefix = m.group(1) if m else ""

        factors = cls._derive_factors(finding, check_prefix)
        raw_score = cls._compute_score(factors)
        computed_severity = _score_to_severity(raw_score)

        # Apply floor from check contract knowledge
        floor = _CHECK_SEVERITY_FLOOR.get(check_prefix, Severity.INFO)
        final_severity = _max_severity(computed_severity, floor)

        # Also respect the stored severity if it's higher (e.g., manual triage)
        stored = cls._parse_stored_severity(finding.severity)
        final_severity = _max_severity(final_severity, stored)

        override_reason = None
        if final_severity != computed_severity:
            override_reason = (
                f"Severity raised from {computed_severity.value} to {final_severity.value} "
                f"by check floor ({floor.value}) or stored value ({stored.value if stored else 'none'})"
            )

        explanation = cls._build_explanation(factors, computed_severity, final_severity, check_prefix)

        return SeverityAssessment(
            severity=final_severity,
            score=raw_score,
            factors=factors,
            evidence_ids=evidence_ids or [],
            override_reason=override_reason,
            explanation=explanation,
        )

    @staticmethod
    def _parse_stored_severity(severity_str: Optional[str]) -> Severity:
        if not severity_str:
            return Severity.INFO
        try:
            return Severity(str(severity_str).lower())
        except ValueError:
            return Severity.INFO

    @staticmethod
    def _derive_factors(finding: Finding, check_prefix: str) -> SeverityFactors:
        """Derive SeverityFactors deterministically from finding fields."""
        check_id_upper = str(finding.vuln_type or "").upper()
        payload = str(finding.payload or "")
        proof_resp = str(finding.proof_response or "")
        reason = str(finding.verification_reason_code or "").upper()

        # Data exposure checks
        data_exposure = check_prefix in {
            "C003", "C057", "C059", "C061", "C062", "C063", "C064", "C066",
        } or "EXPOSURE" in check_id_upper or "DISCLOSURE" in check_id_upper

        # Privilege boundary
        priv_boundary = check_prefix in {
            "C067", "C068", "C069", "C071", "C072",
        } or "PRIVILEGE" in check_id_upper or "ESCALATION" in check_id_upper

        # Scope crossing (RCE, SSTI, command injection)
        scope_crossing = check_prefix in {"C027", "C028", "C032", "C033", "C035", "C036"}

        # Code execution indicators
        code_exec = check_prefix in {"C023", "C024", "C025", "C026", "C027", "C028", "C035"}
        if payload and re.search(r"\$\(\(|\{\{|eval\(|exec\(|system\(|subprocess", payload, re.IGNORECASE):
            code_exec = True

        # Data integrity
        data_integrity = check_prefix in {
            "C023", "C024", "C025", "C038", "C055", "C070",
        }

        # Availability
        availability_impact = check_prefix in {"C075"} or "RACE" in check_id_upper

        # Auth required
        auth_required = "AUTH_REQUIRED" in reason or check_prefix in {
            "C067", "C068", "C069", "C070", "C071", "C072", "C077",
        }

        # Interaction required (stored XSS needs victim interaction, reflected doesn't)
        interaction_required = check_prefix in {"C037", "C039", "C044"}

        # Session / admin
        affects_session = check_prefix in {
            "C013", "C014", "C015", "C016", "C017", "C018", "C020", "C021",
        }
        affects_admin = "ADMIN" in check_id_upper or check_prefix == "C009"

        # Passive only (no active verification)
        passive_only = check_prefix in {
            "C001", "C005", "C011", "C058", "C060",
        } and "REPRODUCED_SUCCESSFULLY" not in reason

        # Safe encoding
        safe_encoding = "INPUT_SAFELY_ENCODED" in reason

        # Deterministic reproduction
        reproduced = "REPRODUCED_SUCCESSFULLY" in reason or "PROPERTY_DEMONSTRATED" in reason

        return SeverityFactors(
            data_exposure=data_exposure,
            privilege_boundary_crossed=priv_boundary,
            scope_crossing=scope_crossing,
            code_execution=code_exec,
            data_integrity=data_integrity,
            availability_impact=availability_impact,
            authentication_required=auth_required,
            interaction_required=interaction_required,
            exploitable_remotely=True,  # All web findings are remotely exploitable by default
            deterministically_reproducible=reproduced,
            affects_session=affects_session,
            affects_admin_surface=affects_admin,
            passive_only=passive_only,
            safe_encoding_present=safe_encoding,
        )

    @staticmethod
    def _compute_score(factors: SeverityFactors) -> int:
        score = 0

        # Impact
        if factors.code_execution:
            score += 40
        if factors.scope_crossing:
            score += 30
        if factors.privilege_boundary_crossed:
            score += 25
        if factors.data_integrity:
            score += 20
        if factors.data_exposure:
            score += 15
        if factors.affects_session:
            score += 15
        if factors.affects_admin_surface:
            score += 10
        if factors.availability_impact:
            score += 10

        # Exploitability
        if factors.exploitable_remotely:
            score += 10
        if factors.deterministically_reproducible:
            score += 5

        # Reductions
        if factors.authentication_required:
            score -= 10
        if factors.interaction_required:
            score -= 15
        if factors.passive_only:
            score -= 20
        if factors.safe_encoding_present:
            score -= 30

        return max(0, min(100, score))

    @staticmethod
    def _build_explanation(
        factors: SeverityFactors,
        computed: Severity,
        final: Severity,
        check_prefix: str,
    ) -> str:
        parts = []
        if factors.code_execution:
            parts.append("code execution indicators present")
        if factors.scope_crossing:
            parts.append("scope crossing (application → system)")
        if factors.privilege_boundary_crossed:
            parts.append("privilege boundary violation")
        if factors.data_exposure:
            parts.append("sensitive data exposure")
        if factors.data_integrity:
            parts.append("data integrity impact")
        if factors.affects_session:
            parts.append("session/authentication impact")
        if factors.affects_admin_surface:
            parts.append("admin surface affected")
        if factors.authentication_required:
            parts.append("exploitation requires authentication")
        if factors.interaction_required:
            parts.append("user interaction required")
        if factors.passive_only:
            parts.append("passive observation only (no active exploitation)")
        if factors.safe_encoding_present:
            parts.append("output safely encoded (XSS mitigated)")
        if not parts:
            parts.append(f"check {check_prefix} default floor applied")
        base = "; ".join(parts)
        if final != computed:
            return f"{base}. Computed: {computed.value}, Applied floor raised to: {final.value}."
        return f"{base}. Computed severity: {final.value}."


__all__ = ["Severity", "SeverityFactors", "SeverityAssessment", "SeverityEngine"]
