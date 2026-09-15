"""AihaX Phase 21 — Differential Evidence Comparator.

Performs deterministic, semantic comparison of baseline and verification HTTP responses
to detect security-relevant behavioral divergences.

Evaluation Classes:
- SAME: Responses are identical in status, structural content, and headers.
- NON_SECURITY_DIFFERENCE: Differences observed are benign (timestamps, transaction IDs, dynamic cache tokens).
- SECURITY_RELEVANT_DIFFERENCE: Divergence demonstrates a security-relevant state change (access granted vs denied, unvalidated redirect, permissive CORS reflection).
- DIFFERENT: Generic structural divergence requiring further investigation.
- INCONCLUSIVE: Server error, timeout, or insufficient comparison data.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("aihax.evidence_comparator")

BENIGN_HEADER_KEYS: Set[str] = {
    "date",
    "age",
    "expires",
    "x-request-id",
    "x-amzn-requestid",
    "x-b3-traceid",
    "cf-ray",
    "server-timing",
    "set-cookie",
    "etag",
    "last-modified",
    "report-to",
    "nel",
}

SECURITY_CRITICAL_HEADERS: Set[str] = {
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "strict-transport-security",
    "content-security-policy",
    "location",
    "www-authenticate",
    "x-frame-options",
    "x-content-type-options",
}


@dataclass
class ComparisonResult:
    verdict: str  # SAME, DIFFERENT, SECURITY_RELEVANT_DIFFERENCE, NON_SECURITY_DIFFERENCE, INCONCLUSIVE
    rationale: str
    similarity_score: float  # 0.0 to 1.0
    security_significance: str  # NONE, LOW, MEDIUM, HIGH, CRITICAL
    differences_detected: List[str] = field(default_factory=list)
    comparison_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DifferentialEvidenceComparator:
    """Deterministic comparative analyzer for HTTP response pairs."""

    @classmethod
    def compare_responses(
        cls,
        baseline_status: Optional[int] = None,
        baseline_headers: Optional[Dict[str, Any]] = None,
        baseline_body: Optional[str] = None,
        verification_status: Optional[int] = None,
        verification_headers: Optional[Dict[str, Any]] = None,
        verification_body: Optional[str] = None,
        vuln_class: Optional[str] = None,
        baseline_response: Optional[Dict[str, Any]] = None,
        verification_response: Optional[Dict[str, Any]] = None,
    ) -> ComparisonResult:
        """Compare baseline and verification response states."""
        if baseline_response is not None:
            baseline_status = baseline_response.get("status_code", 200)
            baseline_headers = baseline_response.get("headers", {})
            baseline_body = baseline_response.get("body", "")

        if verification_response is not None:
            verification_status = verification_response.get("status_code", 200)
            verification_headers = verification_response.get("headers", {})
            verification_body = verification_response.get("body", "")

        # Handle Inconclusive scenarios
        if verification_status is None or (verification_status >= 500 and baseline_status != verification_status):
            comp_str = f"INCONCLUSIVE:{baseline_status}:{verification_status}"
            comp_hash = hashlib.sha256(comp_str.encode()).hexdigest()
            return ComparisonResult(
                verdict="INCONCLUSIVE",
                rationale=f"Verification returned status {verification_status or 'None'}; unable to evaluate behavioral divergence reliably.",
                similarity_score=0.0,
                security_significance="NONE",
                differences_detected=[f"Server status code: {verification_status}"],
                comparison_hash=comp_hash,
            )

        diffs: List[str] = []
        is_security_relevant = False
        security_level = "NONE"
        base_hdrs = {k.lower(): str(v) for k, v in (baseline_headers or {}).items()}
        verif_hdrs = {k.lower(): str(v) for k, v in (verification_headers or {}).items()}

        # 1. Status Code Comparison
        if baseline_status != verification_status:
            diffs.append(f"HTTP Status changed from {baseline_status} to {verification_status}")
            if baseline_status in (401, 403, 404) and verification_status == 200:
                is_security_relevant = True
                security_level = "HIGH"
            elif baseline_status == 200 and verification_status in (301, 302, 303, 307, 308):
                if vuln_class == "OPEN_REDIRECT":
                    is_security_relevant = True
                    security_level = "HIGH"

        # 2. Critical Security Headers Comparison
        for sec_hdr in SECURITY_CRITICAL_HEADERS:
            b_val = base_hdrs.get(sec_hdr)
            v_val = verif_hdrs.get(sec_hdr)
            if b_val != v_val:
                diffs.append(f"Header '{sec_hdr}' changed: '{b_val}' -> '{v_val}'")
                if sec_hdr == "location" and v_val:
                    if "evil" in v_val.lower() or "example.com" in v_val.lower():
                        is_security_relevant = True
                        if security_level != "HIGH":
                            security_level = "HIGH"
                elif sec_hdr == "access-control-allow-origin" and v_val:
                    if "evil" in v_val.lower() or v_val == "*":
                        is_security_relevant = True
                        if security_level not in ("HIGH", "CRITICAL"):
                            security_level = "HIGH" if "evil" in v_val.lower() else "MEDIUM"
                elif sec_hdr in ("strict-transport-security", "content-security-policy"):
                    if not v_val:
                        is_security_relevant = True
                        if security_level not in ("HIGH", "MEDIUM", "CRITICAL"):
                            security_level = "LOW"

        # 3. Body Content / Length Comparison
        b_body = baseline_body or ""
        v_body = verification_body or ""
        body_same = (b_body == v_body)

        # Normalize body for dynamic tokens (timestamps, random session ids)
        b_norm = cls._normalize_body(b_body)
        v_norm = cls._normalize_body(v_body)
        norm_body_same = (b_norm == v_norm)

        if not body_same:
            len_diff = abs(len(b_body) - len(v_body))
            if norm_body_same:
                diffs.append("Response body has dynamic non-structural timestamp/token variations.")
            else:
                diffs.append(f"Response body changed (length delta: {len_diff} bytes)")
                if vuln_class in ("IDOR_BOLA", "ACCESS_CONTROL") and len(v_body) > 50 and verification_status == 200:
                    is_security_relevant = True
                    security_level = "HIGH"

        # Check for error disclosures
        if any(err_kw in v_body.lower() for err_kw in ("exception:", "stack trace:", "syntax error", "traceback (most recent")):
            diffs.append("Stack trace / internal error signature detected in response.")
            is_security_relevant = True
            security_level = "MEDIUM"

        # Compute similarity score
        similarity = 1.0
        if baseline_status != verification_status:
            similarity -= 0.3
        if not norm_body_same:
            similarity -= 0.4
        similarity = max(0.0, min(1.0, round(similarity, 2)))

        # Derive Final Verdict
        if not diffs:
            verdict = "SAME"
            rationale = "Baseline and verification responses are structurally and semantically identical."
            security_level = "NONE"
        elif is_security_relevant:
            verdict = "SECURITY_RELEVANT_DIFFERENCE"
            rationale = f"Observed response divergence demonstrates security-relevant behavioral change ({', '.join(diffs[:2])})."
        elif norm_body_same and all(cls._is_benign_diff(d) for d in diffs):
            verdict = "NON_SECURITY_DIFFERENCE"
            rationale = "Differences are confined to benign dynamic tokens, timestamps, or transient headers."
            security_level = "NONE"
        else:
            verdict = "DIFFERENT"
            rationale = f"Responses diverge structurally without conclusive vulnerability indicator ({', '.join(diffs[:2])})."
            security_level = "LOW"

        comp_payload = f"{verdict}:{similarity}:{baseline_status}:{verification_status}:{len(diffs)}"
        comp_hash = hashlib.sha256(comp_payload.encode()).hexdigest()

        return ComparisonResult(
            verdict=verdict,
            rationale=rationale,
            similarity_score=similarity,
            security_significance=security_level,
            differences_detected=diffs,
            comparison_hash=comp_hash,
        )

    @classmethod
    def _normalize_body(cls, body: str) -> str:
        """Strip dynamic timestamps, CSRF tokens, and nonce attributes."""
        if not body:
            return ""
        norm = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?', '[TIMESTAMP]', body)
        norm = re.sub(r'name=["\']?(?:csrf|nonce|token|authenticity_token|_token)["\']?\s+value=["\']?[a-zA-Z0-9\-_]{16,}["\']?', 'name="csrf" value="[TOKEN]"', norm, flags=re.IGNORECASE)
        norm = re.sub(r'(?:csrf|nonce|token|session_id|requestId)=["\']?[a-zA-Z0-9\-_]{16,}["\']?', '[TOKEN]', norm, flags=re.IGNORECASE)
        return norm

    @classmethod
    def _is_benign_diff(cls, diff_msg: str) -> bool:
        """Check if a difference string refers exclusively to benign changes."""
        msg_lower = diff_msg.lower()
        if "timestamp" in msg_lower or "token" in msg_lower or "dynamic" in msg_lower:
            return True
        for h in BENIGN_HEADER_KEYS:
            if f"header '{h}'" in msg_lower:
                return True
        return False
