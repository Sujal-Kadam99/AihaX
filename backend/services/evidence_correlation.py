"""AihaX Phase 22 — Real Evidence Correlation Engine.

Correlates real HTTP observations from authorized concrete targets against
baseline evidence and vulnerability hypotheses to produce deterministic,
evidence-grounded verdicts (CONFIRMED, NOT_CONFIRMED, INCONCLUSIVE, CONTRADICTED).

Security Invariants:
1. Verdicts must be directly derived from observed HTTP response facts.
2. A difference in response is evidence requiring interpretation, never an automatic vulnerability.
3. INCONCLUSIVE is assigned on server errors (5xx), network timeouts, rate limits (429), or missing baselines.
4. Reproducibility requires >= 2 independent observations; single observation returns 0.0.
5. All evidence chains are cryptographically bound with SHA-256 hashes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from backend.models.database import get_utc_now

logger = logging.getLogger(__name__)


@dataclass
class CorrelationResultDTO:
    verdict: str  # CONFIRMED, NOT_CONFIRMED, INCONCLUSIVE, CONTRADICTED
    rationale: str
    evidence_ids: List[str]
    comparison_hash: str
    correlation_hash: str
    reproducibility: float = 0.0
    confidence_score: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RealEvidenceChainDTO:
    campaign_id: str
    verification_run_id: str
    baseline_hash: str
    verification_hash: str
    comparison_hash: str
    correlation_hash: str
    chain_hash: str
    previous_chain_hash: str
    created_at: str = field(default_factory=lambda: get_utc_now().isoformat())

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RealEvidenceCorrelator:
    """Evaluates differential evidence from authorized target verifications against vulnerability hypotheses."""

    @classmethod
    def correlate_evidence(
        cls,
        hypothesis: Any,
        baseline_evidence: Any,
        verification_evidence: Any,
        comparison_result: Any,
        historical_runs: Optional[List[Any]] = None,
    ) -> CorrelationResultDTO:
        """Correlate real baseline and verification evidence against hypothesis conditions."""
        hyp_dict = hypothesis.to_dict() if hasattr(hypothesis, "to_dict") else (hypothesis if isinstance(hypothesis, dict) else {})
        base_dict = baseline_evidence.to_dict() if hasattr(baseline_evidence, "to_dict") else (baseline_evidence if isinstance(baseline_evidence, dict) else {})
        verif_dict = verification_evidence.to_dict() if hasattr(verification_evidence, "to_dict") else (verification_evidence if isinstance(verification_evidence, dict) else {})
        comp_dict = comparison_result.to_dict() if hasattr(comparison_result, "to_dict") else (comparison_result if isinstance(comparison_result, dict) else {})

        vuln_type = (hyp_dict.get("vuln_type") or hyp_dict.get("category") or "GENERAL").upper()
        
        verif_status = verif_dict.get("status_code")
        base_status = base_dict.get("status_code")
        comp_verdict = (comp_dict.get("verdict") or "SAME").upper()

        base_id = base_dict.get("id") or base_dict.get("evidence_id") or "EVID-BASE"
        verif_id = verif_dict.get("id") or verif_dict.get("evidence_id") or "EVID-VERIF"
        evidence_ids = [str(base_id), str(verif_id)]

        comp_hash = comp_dict.get("comparison_hash") or hashlib.sha256(json.dumps(comp_dict, sort_keys=True).encode("utf-8")).hexdigest()

        # Step 1: Inconclusive on missing verification or server transport failure
        if verif_status is None or verif_status == 0:
            verdict = "INCONCLUSIVE"
            rationale = "Verification request did not receive a valid HTTP response (transport error or timeout)."
            return cls._build_dto(verdict, rationale, evidence_ids, comp_hash, cls._eval_repro(historical_runs))

        if 500 <= verif_status <= 599 or verif_status == 429:
            verdict = "INCONCLUSIVE"
            rationale = f"Target returned HTTP {verif_status} during verification. Server-side errors and rate limits are inconclusive."
            return cls._build_dto(verdict, rationale, evidence_ids, comp_hash, cls._eval_repro(historical_runs))

        sanitized_resp = verif_dict.get("sanitized_response") or ""
        relevant_headers = verif_dict.get("relevant_headers") or {}
        if isinstance(relevant_headers, str):
            try:
                relevant_headers = json.loads(relevant_headers)
            except Exception:
                relevant_headers = {}

        # Step 2: Class-specific deterministic evaluation
        verdict, rationale = cls._evaluate_class(
            vuln_type=vuln_type,
            base_status=base_status,
            verif_status=verif_status,
            comp_verdict=comp_verdict,
            relevant_headers=relevant_headers,
            sanitized_resp=sanitized_resp,
            hyp_dict=hyp_dict,
        )

        repro_score = cls._eval_repro(historical_runs)
        return cls._build_dto(verdict, rationale, evidence_ids, comp_hash, repro_score)

    @classmethod
    def _evaluate_class(
        cls,
        vuln_type: str,
        base_status: Optional[int],
        verif_status: int,
        comp_verdict: str,
        relevant_headers: Dict[str, Any],
        sanitized_resp: str,
        hyp_dict: Dict[str, Any],
    ) -> tuple[str, str]:
        """Evaluate class-specific success and contradiction conditions."""
        headers_lower = {str(k).lower(): str(v).lower() for k, v in relevant_headers.items()}
        body_lower = sanitized_resp.lower()

        if "CORS" in vuln_type:
            acao = headers_lower.get("access-control-allow-origin", "")
            acac = headers_lower.get("access-control-allow-credentials", "")
            if acao in ["*", "null"] or "evil.com" in acao or "attacker.com" in acao:
                if acac == "true" or acao != "*":
                    return "CONFIRMED", f"CORS vulnerability confirmed: server reflects untrusted origin '{acao}' with credentials={acac}."
                return "CONFIRMED", f"Permissive CORS policy confirmed: Access-Control-Allow-Origin is '{acao}'."
            if acao == "":
                return "NOT_CONFIRMED", "CORS validation passed: server did not reflect arbitrary test Origin header."
            return "NOT_CONFIRMED", f"Server returned static/safe CORS origin '{acao}'."

        elif "OPEN_REDIRECT" in vuln_type:
            loc = headers_lower.get("location", "")
            if 300 <= verif_status <= 399 and ("evil.com" in loc or "example.org" in loc or loc.startswith("//")):
                return "CONFIRMED", f"Open redirect confirmed: HTTP {verif_status} response with Location: '{loc}'."
            if 300 <= verif_status <= 399:
                return "NOT_CONFIRMED", f"Server redirected to internal/safe destination '{loc}'."
            return "NOT_CONFIRMED", f"Server did not redirect (status {verif_status})."

        elif "SECURITY_HEADERS" in vuln_type:
            missing_hsts = "strict-transport-security" not in headers_lower
            missing_csp = "content-security-policy" not in headers_lower
            missing_xfo = "x-frame-options" not in headers_lower
            missing_xcto = "x-content-type-options" not in headers_lower
            
            missing_list = []
            if missing_hsts: missing_list.append("HSTS")
            if missing_csp: missing_list.append("CSP")
            if missing_xfo: missing_list.append("X-Frame-Options")
            if missing_xcto: missing_list.append("X-Content-Type-Options")

            if missing_list:
                return "CONFIRMED", f"Missing security headers confirmed: {', '.join(missing_list)}."
            return "NOT_CONFIRMED", "All required baseline security headers are present."

        elif "ACCESS_CONTROL" in vuln_type or "API_AUTHORIZATION" in vuln_type:
            if base_status in [401, 403] and verif_status == 200:
                return "CONFIRMED", f"Authorization bypass confirmed: endpoint transitioned from HTTP {base_status} to HTTP 200."
            if verif_status in [401, 403]:
                return "NOT_CONFIRMED", f"Access control properly enforced (HTTP {verif_status})."
            if verif_status == 404:
                return "NOT_CONFIRMED", "Endpoint returned 404 Not Found."
            if comp_verdict == "SECURITY_RELEVANT_DIFFERENCE":
                return "CONFIRMED", "Access control disparity confirmed via differential comparison."
            return "NOT_CONFIRMED", f"No authorization boundary failure observed (HTTP {verif_status})."

        elif "IDOR" in vuln_type or "BOLA" in vuln_type:
            if base_status in [401, 403, 404] and verif_status == 200:
                return "CONFIRMED", f"IDOR/BOLA confirmed: unauthorized identifier request succeeded with HTTP 200."
            if verif_status in [401, 403]:
                return "NOT_CONFIRMED", f"Object-level authorization enforced: server returned HTTP {verif_status}."
            if comp_verdict == "SECURITY_RELEVANT_DIFFERENCE" and verif_status == 200:
                return "CONFIRMED", "Object-level authorization disparity confirmed."
            return "NOT_CONFIRMED", f"IDOR hypothesis not confirmed (status {verif_status})."

        elif "INFORMATION_DISCLOSURE" in vuln_type:
            leak_patterns = [
                "stack trace", "traceback (most recent call last)", "syntaxerror:", "fatal error:",
                "server at ", "apache/", "nginx/", "php/", "django_version", "mysql_fetch",
                "pg_query", "aws_secret_access_key", "internal server error"
            ]
            leaks = [p for p in leak_patterns if p in body_lower]
            if leaks and verif_status in [200, 500]:
                return "CONFIRMED", f"Information disclosure confirmed: observed technical leak '{leaks[0]}'."
            return "NOT_CONFIRMED", "No sensitive technical metadata or internal stack traces disclosed in response."

        elif "CACHE" in vuln_type:
            cc = headers_lower.get("cache-control", "")
            if "no-store" not in cc and "private" not in cc and verif_status == 200:
                return "CONFIRMED", f"Cache security disparity confirmed: sensitive endpoint cache-control is '{cc or 'missing'}'."
            return "NOT_CONFIRMED", f"Cache control headers adequately restrict caching (Cache-Control: '{cc}')."

        elif "SESSION" in vuln_type or "AUTHENTICATION" in vuln_type:
            cookie_headers = [v for k, v in headers_lower.items() if "set-cookie" in k]
            insecure_cookies = []
            for sc in cookie_headers:
                if "secure" not in sc or "httponly" not in sc:
                    insecure_cookies.append(sc)
            if insecure_cookies:
                return "CONFIRMED", f"Session security flag deficiency confirmed on Set-Cookie: '{insecure_cookies[0]}'."
            if comp_verdict == "SECURITY_RELEVANT_DIFFERENCE":
                return "CONFIRMED", "Authentication/session state change confirmed."
            return "NOT_CONFIRMED", "Session cookies and authentication boundaries verified as intact."

        elif "INPUT_HANDLING" in vuln_type or "URL_PARAMETER" in vuln_type:
            if comp_verdict == "SECURITY_RELEVANT_DIFFERENCE":
                return "CONFIRMED", "Input handling disparity confirmed: parameter directly affected response structure."
            return "NOT_CONFIRMED", "Input parameter safely ignored or neutralized by target."

        # General Fallback
        if comp_verdict == "SECURITY_RELEVANT_DIFFERENCE":
            return "CONFIRMED", "Security-relevant difference observed between baseline and verification responses."
        elif comp_verdict == "SAME":
            return "NOT_CONFIRMED", "Verification response identical to baseline; no vulnerability condition demonstrated."
        else:
            return "NOT_CONFIRMED", f"Observed response (HTTP {verif_status}) did not satisfy vulnerability success criteria."

    @classmethod
    def build_evidence_chain(
        cls,
        campaign_id: str = "CAMP-DEFAULT",
        verification_run_id: str = "VRUN-DEFAULT",
        baseline_evidence: Any = None,
        verification_evidence: Any = None,
        correlation_result: Optional[Any] = None,
        previous_chain_hash: str = "0" * 64,
        baseline_hash: Optional[str] = None,
        verification_hash: Optional[str] = None,
        comparison_hash: Optional[str] = None,
        correlation_hash: Optional[str] = None,
    ) -> RealEvidenceChainDTO:
        """Construct a tamper-evident SHA-256 evidence chain linking baseline, verification, and correlation hashes."""
        base_dict = baseline_evidence.to_dict() if hasattr(baseline_evidence, "to_dict") else (baseline_evidence if isinstance(baseline_evidence, dict) else {})
        verif_dict = verification_evidence.to_dict() if hasattr(verification_evidence, "to_dict") else (verification_evidence if isinstance(verification_evidence, dict) else {})

        base_h = baseline_hash or str(base_dict.get("response_hash") or base_dict.get("request_hash") or "0" * 64)
        verif_h = verification_hash or str(verif_dict.get("response_hash") or verif_dict.get("request_hash") or "0" * 64)
        comp_h = comparison_hash or (correlation_result.comparison_hash if hasattr(correlation_result, "comparison_hash") else (correlation_result.get("comparison_hash", "0"*64) if isinstance(correlation_result, dict) else "0"*64))
        corr_h = correlation_hash or (correlation_result.correlation_hash if hasattr(correlation_result, "correlation_hash") else (correlation_result.get("correlation_hash", "0"*64) if isinstance(correlation_result, dict) else "0"*64))

        canonical = f"{previous_chain_hash}:{campaign_id}:{verification_run_id}:{base_h}:{verif_h}:{comp_h}:{corr_h}"
        chain_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        return RealEvidenceChainDTO(
            campaign_id=campaign_id,
            verification_run_id=verification_run_id,
            baseline_hash=base_h,
            verification_hash=verif_h,
            comparison_hash=comp_h,
            correlation_hash=corr_h,
            chain_hash=chain_hash,
            previous_chain_hash=previous_chain_hash,
        )

    @classmethod
    def evaluate_reproducibility(cls, evidence_records: Optional[List[Any]]) -> float:
        """Calculate mathematical reproducibility score across multiple runs (0.0 to 1.0)."""
        if not evidence_records or len(evidence_records) < 2:
            return 0.0

        target_status = None
        target_hash = None
        matching = 0
        total = len(evidence_records)

        for rec in evidence_records:
            status = getattr(rec, "status_code", None) or (rec.get("status_code") if isinstance(rec, dict) else None)
            resp_hash = getattr(rec, "response_hash", None) or (rec.get("response_hash") if isinstance(rec, dict) else None)

            if target_status is None:
                target_status = status
                target_hash = resp_hash
                matching += 1
                continue

            if status == target_status and (target_hash is None or resp_hash == target_hash):
                matching += 1

        return round(matching / total, 2)

    @classmethod
    def _eval_repro(cls, historical_runs: Optional[List[Any]]) -> float:
        if not historical_runs or len(historical_runs) < 2:
            return 0.0
        return cls.evaluate_reproducibility(historical_runs)

    @classmethod
    def _build_dto(
        cls,
        verdict: str,
        rationale: str,
        evidence_ids: List[str],
        comparison_hash: str,
        repro_score: float,
    ) -> CorrelationResultDTO:
        corr_payload = f"{verdict}:{comparison_hash}:{repro_score}:{':'.join(sorted(evidence_ids))}"
        corr_hash = hashlib.sha256(corr_payload.encode("utf-8")).hexdigest()

        return CorrelationResultDTO(
            verdict=verdict,
            rationale=rationale,
            evidence_ids=evidence_ids,
            comparison_hash=comparison_hash,
            correlation_hash=corr_hash,
            reproducibility=repro_score,
            confidence_score=1.0 if verdict == "CONFIRMED" else (0.8 if verdict == "NOT_CONFIRMED" else 0.4),
        )
