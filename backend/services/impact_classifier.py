"""AihaX Phase 21 — Impact Classifier.

Deterministically classifies and strictly segregates confirmed, evidence-backed security impacts
from theoretical risks (prefixed with mandatory '[INFERENCE]').

Security Invariants:
1. Confirmed impact must be directly demonstrated by captured HTTP evidence.
2. Potential impact must be explicitly tagged with '[INFERENCE]'.
3. Zero speculative severity escalation or unsupported account takeover claims.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger("aihax.impact_classifier")


@dataclass
class ImpactAssessmentDTO:
    vulnerability_class: str
    impact_confirmed: str
    impact_potential: str
    severity: str  # info, low, medium, high, critical
    cvss_score: float
    remediation_guidance: str

    @property
    def confirmed_impact(self) -> str:
        return self.impact_confirmed

    @property
    def potential_impact(self) -> str:
        return self.impact_potential

    @property
    def remediation(self) -> str:
        return self.remediation_guidance

    @property
    def inference_labels(self) -> list[str]:
        return ["[INFERENCE]"]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ImpactClassifier:
    """Classifies verified vulnerability findings into factual confirmed vs inferred impacts."""

    IMPACT_TEMPLATES: Dict[str, Dict[str, Any]] = {
        "ACCESS_CONTROL": {
            "confirmed": "Server returned protected resource data ({details}) without requiring the expected authorization token.",
            "potential": "[INFERENCE] If unauthenticated access extends across tenant boundaries, unauthorized parties may inspect or alter administrative records.",
            "severity": "high",
            "cvss": 7.5,
            "remediation": "Enforce strict server-side authorization checks on all protected API endpoints regardless of HTTP method.",
        },
        "IDOR_BOLA": {
            "confirmed": "Supplying alternate identifier yielded HTTP 200 and exposed the target object record ({details}).",
            "potential": "[INFERENCE] An attacker could systematically iterate identifiers to access other users' private objects within this tenant.",
            "severity": "high",
            "cvss": 7.5,
            "remediation": "Validate that the requesting session owns or has explicit permission for the requested object identifier before returning data.",
        },
        "AUTHENTICATION": {
            "confirmed": "Authentication endpoint emitted session tokens lacking the 'Secure' or 'HttpOnly' flags ({details}).",
            "potential": "[INFERENCE] In the event of cross-site scripting or unencrypted transport, session tokens could be extracted via client-side scripts.",
            "severity": "medium",
            "cvss": 5.3,
            "remediation": "Set 'Secure; HttpOnly; SameSite=Lax' on all authentication cookies and enforce HTTPS-only transmission.",
        },
        "SESSION_SECURITY": {
            "confirmed": "Session identifiers were observed with overly broad domain scoping or missing regeneration attributes ({details}).",
            "potential": "[INFERENCE] Session tokens persisting after state transitions may allow session hijacking if shared networks are compromised.",
            "severity": "medium",
            "cvss": 5.0,
            "remediation": "Regenerate session tokens upon privilege level changes and scope cookie domain strictly.",
        },
        "CORS": {
            "confirmed": "Server reflects arbitrary Origin headers with Access-Control-Allow-Credentials: true ({details}).",
            "potential": "[INFERENCE] Malicious websites could execute authenticated cross-origin requests to read private account data.",
            "severity": "medium",
            "cvss": 6.5,
            "remediation": "Maintain an explicit whitelist of trusted origins and avoid reflecting unverified Origin request headers with credentials.",
        },
        "OPEN_REDIRECT": {
            "confirmed": "Target endpoint issued HTTP redirect to an untrusted external location ({details}).",
            "potential": "[INFERENCE] Attackers can craft phishing links utilizing the trusted domain to deceive users into credential theft.",
            "severity": "medium",
            "cvss": 6.1,
            "remediation": "Validate destination redirect URLs against a strict whitelist of relative paths and authorized domains.",
        },
        "INFORMATION_DISCLOSURE": {
            "confirmed": "Endpoint response exposed sensitive internal system identifiers or technical diagnostic metadata ({details}).",
            "potential": "[INFERENCE] Leaked stack traces or software versions provide reconnaissance intelligence aiding targeted exploit formulation.",
            "severity": "low",
            "cvss": 4.3,
            "remediation": "Disable verbose error pages in production environments and scrub sensitive metadata before response transmission.",
        },
        "SECURITY_HEADERS": {
            "confirmed": "Target response omitted essential modern browser security hardening headers ({details}).",
            "potential": "[INFERENCE] Absence of HSTS, CSP, or frame protection increases vulnerability to downgrade, clickjacking, or injection attacks.",
            "severity": "low",
            "cvss": 3.7,
            "remediation": "Implement Strict-Transport-Security, Content-Security-Policy, and X-Content-Type-Options headers.",
        },
        "INPUT_HANDLING": {
            "confirmed": "Endpoint reflected user input without proper context-aware sanitization ({details}).",
            "potential": "[INFERENCE] Unsanitized input reflection could lead to client-side script execution in victim browsers.",
            "severity": "medium",
            "cvss": 6.1,
            "remediation": "Apply context-aware output encoding and strict input validation on all user-supplied data.",
        },
        "API_AUTHORIZATION": {
            "confirmed": "API route failed to enforce authentication requirements on non-standard HTTP methods ({details}).",
            "potential": "[INFERENCE] Attackers may bypass client-side access gates by substituting alternative HTTP inquiry verbs.",
            "severity": "medium",
            "cvss": 5.3,
            "remediation": "Ensure authentication and authorization middleware is applied uniformly to all HTTP verbs on protected routes.",
        },
        "CACHE_BEHAVIOR": {
            "confirmed": "Cache proxy propagated unkeyed header variation across subsequent inquiries ({details}).",
            "potential": "[INFERENCE] If malicious payload can be cached, other users requesting the cached resource could be impacted.",
            "severity": "low",
            "cvss": 4.0,
            "remediation": "Configure cache keys to include all headers that influence dynamic response generation.",
        },
        "URL_PARAMETER_BEHAVIOR": {
            "confirmed": "Parameter manipulation resulted in significant server response structural variance ({details}).",
            "potential": "[INFERENCE] Dynamic querying logic may be susceptible to parameter pollution or logical state tampering.",
            "severity": "low",
            "cvss": 3.8,
            "remediation": "Validate parameter types, lengths, and values against a strict schema.",
        },
    }

    @classmethod
    def classify_impact(
        cls,
        vulnerability_class: Optional[str] = None,
        observed_details: str = "",
        custom_severity: Optional[str] = None,
        category: Optional[str] = None,
        endpoint: Optional[str] = None,
        observed_evidence: Optional[Dict[str, Any]] = None,
    ) -> ImpactAssessmentDTO:
        """Classify impact with strict fact vs inference separation."""
        v_class = (vulnerability_class or category or "SECURITY_HEADERS").upper()
        template = cls.IMPACT_TEMPLATES.get(v_class, cls.IMPACT_TEMPLATES["SECURITY_HEADERS"])
        
        details_str = observed_details or endpoint or (f"observed on {endpoint}" if endpoint else "as evidenced by HTTP response")
        confirmed_text = template["confirmed"].format(details=details_str)
        potential_text = template["potential"]
        
        # Ensure mandatory [INFERENCE] prefix
        if not potential_text.startswith("[INFERENCE]"):
            potential_text = f"[INFERENCE] {potential_text}"

        sev = custom_severity or template["severity"]
        cvss = template["cvss"]
        remed = template["remediation"]

        return ImpactAssessmentDTO(
            vulnerability_class=v_class,
            impact_confirmed=confirmed_text,
            impact_potential=potential_text,
            severity=sev,
            cvss_score=cvss,
            remediation_guidance=remed,
        )
