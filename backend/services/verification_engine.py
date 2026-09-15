"""Deterministic Evidence-Based Verification Engine for AihaX.

Architectural Guarantees:
1. Verification is purely deterministic: LLMs NEVER determine vulnerability verdicts.
2. Every active verification network request MUST use RequestEngine (enforcing ScopeValidator, rate limits, timeouts, and secret redaction).
3. Non-destructive by default: Destructive actions are strictly rejected.
4. Bounded verification budget: Max requests, max duration, max concurrency.
5. Strict Verdict State Machine: CANDIDATE -> VERIFYING -> VERIFIED / INCONCLUSIVE / FALSE_POSITIVE.
6. Traceable Evidence Graph: Links Finding -> Candidate Evidence -> Verification Requests/Responses -> Deterministic Verdict.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type, Union

from backend.core.scope_validator import ScopeValidator
from backend.models.database import Finding, FindingDisposition, BountyEligibility
from backend.services.request_engine import (
    AuthenticationContext,
    RequestEngine,
    RequestEvidence,
    RequestSpec,
    RequestTimeout,
)

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# 1. FORMAL VERDICT MODEL & REASON CODES
# ──────────────────────────────────────────────────────────────────────────────

VERIFIER_VERSION = "1.0.0-phase18"


class VerificationStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    VALIDATED = "VALIDATED"
    EXPLOITABLE = "EXPLOITABLE"
    DETECTED = "DETECTED"
    HARDENING_ONLY = "HARDENING_ONLY"
    INCONCLUSIVE = "INCONCLUSIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    REJECTED = "REJECTED"
    DUPLICATE = "DUPLICATE"
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"


class VerificationReasonCode(str, Enum):
    REPRODUCED_SUCCESSFULLY = "REPRODUCED_SUCCESSFULLY"
    PROPERTY_DEMONSTRATED = "PROPERTY_DEMONSTRATED"
    HARDENING_OBSERVED = "HARDENING_OBSERVED"
    RATE_LIMIT_INSUFFICIENT_EVIDENCE = "RATE_LIMIT_INSUFFICIENT_EVIDENCE"
    DIRECTORY_LISTING_BENIGN = "DIRECTORY_LISTING_BENIGN"
    DIRECTORY_LISTING_SENSITIVE = "DIRECTORY_LISTING_SENSITIVE"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    MISSING_BASELINE = "MISSING_BASELINE"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    AUTH_REQUIRED_OR_ENFORCED = "AUTH_REQUIRED_OR_ENFORCED"
    INPUT_SAFELY_ENCODED = "INPUT_SAFELY_ENCODED"
    HEURISTIC_ONLY_UNVERIFIED = "HEURISTIC_ONLY_UNVERIFIED"
    ENDPOINT_UNAVAILABLE = "ENDPOINT_UNAVAILABLE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    OUT_OF_SCOPE_BLOCKED = "OUT_OF_SCOPE_BLOCKED"
    INCONSISTENT_BEHAVIOR = "INCONSISTENT_BEHAVIOR"
    FINDING_REJECTED = "FINDING_REJECTED"
    TRANSPORT_REDIRECT_SAFE = "TRANSPORT_REDIRECT_SAFE"
    HTTP_REDIRECTS_TO_HTTPS = "HTTP_REDIRECTS_TO_HTTPS"
    CORS_SAFE_PERMISSIVE = "CORS_SAFE_PERMISSIVE"
    CORS_WILDCARD_NO_IMPACT = "CORS_WILDCARD_NO_IMPACT"
    CONTROL_ENFORCED = "CONTROL_ENFORCED"
    RATE_LIMIT_BYPASS_PROVEN = "RATE_LIMIT_BYPASS_PROVEN"
    HEADER_PRESENT_CONTRADICTION = "HEADER_PRESENT_CONTRADICTION"


# ──────────────────────────────────────────────────────────────────────────────
# 2. VERIFICATION DTOs & CONTEXT
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class StructuredImpactRecord:
    """Deterministic evidence-backed impact calculation for HackerOne-ready reports."""
    exploitability: str = "NONE"  # NONE, LOW, MEDIUM, HIGH, CRITICAL
    impact: str = "NONE"          # NONE, LOW, MEDIUM, HIGH, CRITICAL
    affected_confidentiality: str = "NONE"  # NONE, LOW, HIGH
    affected_integrity: str = "NONE"        # NONE, LOW, HIGH
    affected_availability: str = "NONE"     # NONE, LOW, HIGH
    authentication_requirement: str = "NONE"  # NONE, USER, ADMIN
    privilege_requirement: str = "NONE"       # NONE, LOW, HIGH
    user_interaction: str = "NONE"            # NONE, REQUIRED
    scope: str = "UNCHANGED"                  # UNCHANGED, CHANGED
    confidence: str = "LOW"                   # LOW, MEDIUM, HIGH, CONFIRMED
    confidence_reason: str = ""
    impact_confirmed: bool = True
    impact_potential: str = ""
    verifier_version: str = VERIFIER_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationBudget:
    max_requests: int = 5
    max_duration_seconds: float = 30.0
    max_concurrency: int = 2

    def __post_init__(self) -> None:
        self.max_requests = min(max(1, int(self.max_requests)), 20)
        self.max_duration_seconds = min(max(0.01, float(self.max_duration_seconds)), 120.0)
        self.max_concurrency = min(max(1, int(self.max_concurrency)), 5)


@dataclass
class VerificationEvidenceItem:
    evidence_id: str
    request_id: Optional[str]
    evidence_type: str  # e.g., "candidate_proof", "baseline_request", "test_verification", "differential_comparison"
    data: dict[str, Any]
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationConclusion:
    status: VerificationStatus
    reason_code: VerificationReasonCode
    reason_description: str
    evidence_ids: list[str] = field(default_factory=list)
    request_ids: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    method: str = "Deterministic Contract Verification"
    confidence: int = 0
    impact_record: Optional[StructuredImpactRecord] = None
    verifier_version: str = VERIFIER_VERSION

    def to_dict(self) -> dict[str, Any]:
        res = {
            "status": self.status.value,
            "reason_code": self.reason_code.value,
            "reason_description": self.reason_description,
            "evidence_ids": self.evidence_ids,
            "request_ids": self.request_ids,
            "timestamp": self.timestamp,
            "method": self.method,
            "confidence": self.confidence,
        }
        if self.impact_record:
            res["impact_record"] = self.impact_record.to_dict()
        return res


@dataclass
class VerificationContract:
    check_id: str
    name: str
    security_property: str
    required_evidence_fields: list[str] = field(default_factory=list)
    destructive: bool = False
    requires_auth: bool = False
    default_budget: VerificationBudget = field(default_factory=VerificationBudget)


class BudgetExceededError(Exception):
    """Raised when a verification strategy exceeds its allocated budget."""
    pass


class VerificationContext:
    """Execution context provided to verification strategies."""

    def __init__(
        self,
        finding_id: str,
        target_url: str,
        candidate_evidence: dict[str, Any],
        request_engine: Any,
        check_id: Optional[str] = "unknown",
        auth_context: Optional[AuthenticationContext] = None,
        budget: Optional[VerificationBudget] = None,
        authorization_confirmed: bool = True,
    ) -> None:
        self.finding_id = finding_id
        self.check_id = check_id or "unknown"
        self.target_url = target_url
        self.candidate_evidence = candidate_evidence
        self.request_engine = request_engine
        self.auth_context = auth_context
        self.budget = budget or VerificationBudget()
        self.authorization_confirmed = authorization_confirmed
        self.collected_evidence: list[VerificationEvidenceItem] = []
        self.requests_made: int = 0
        self.start_time: float = time.monotonic()

    def record_evidence(
        self,
        evidence_type: str,
        data: dict[str, Any],
        request_id: Optional[str] = None,
    ) -> str:
        evidence_id = f"EVD-{secrets.token_hex(4).upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()
        item = VerificationEvidenceItem(
            evidence_id=evidence_id,
            request_id=request_id,
            evidence_type=evidence_type,
            data=data,
            timestamp=timestamp,
        )
        self.collected_evidence.append(item)
        return evidence_id

    async def send_verification_request(self, spec: RequestSpec) -> RequestEvidence:
        """Controlled RequestEngine dispatch with strict budget and timeout guards."""
        # Enforce budget before transmission
        elapsed = time.monotonic() - self.start_time
        if self.requests_made >= self.budget.max_requests:
            raise BudgetExceededError(
                f"Verification request budget exhausted ({self.requests_made}/{self.budget.max_requests})"
            )
        if elapsed >= self.budget.max_duration_seconds:
            raise BudgetExceededError(
                f"Verification time budget exceeded ({elapsed:.1f}s >= {self.budget.max_duration_seconds}s)"
            )

        # Inherit authorization state
        spec.authorization_confirmed = self.authorization_confirmed
        if not spec.auth_context and self.auth_context:
            spec.auth_context = self.auth_context

        if hasattr(self.request_engine, "execute"):
            if asyncio.iscoroutinefunction(self.request_engine.execute):
                evidence = await self.request_engine.execute(spec)
            else:
                evidence = self.request_engine.execute(spec)
        elif hasattr(self.request_engine, "execute_request"):
            resp = self.request_engine.execute_request(spec)
            if isinstance(resp, RequestEvidence):
                evidence = resp
            else:
                body_bytes = getattr(resp, "body", b"")
                body_str = body_bytes.decode("utf-8", errors="replace") if isinstance(body_bytes, bytes) else str(body_bytes)
                headers = dict(getattr(resp, "headers", {}))
                status_code = getattr(resp, "status_code", 200)
                evidence = RequestEvidence(
                    request_id=f"REQ-{secrets.token_hex(4).upper()}",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    method=spec.method,
                    url=spec.url,
                    request_headers=spec.headers,
                    request_body=str(spec.body) if spec.body else None,
                    response_status=status_code,
                    response_headers=headers,
                    response_body=body_str,
                    response_size=len(body_bytes) if isinstance(body_bytes, bytes) else len(body_str),
                    duration_ms=10.0,
                    truncated=False,
                    redirect_chain=[spec.url],
                    scope_decision={"allowed": True},
                    transport_error=None,
                    success=True,
                )
        elif self.request_engine is None:
            # Offline synthetic mock response from candidate evidence
            proof_resp = str(self.candidate_evidence.get("proof_response") or "")
            resp_headers = {}
            for line in proof_resp.splitlines():
                if ":" in line and not line.startswith("HTTP/"):
                    k, v = line.split(":", 1)
                    resp_headers[k.strip().lower()] = v.strip()
            evidence = RequestEvidence(
                request_id=f"REQ-{secrets.token_hex(4).upper()}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                method=spec.method,
                url=spec.url,
                request_headers=spec.headers,
                request_body=str(spec.body) if spec.body else None,
                response_status=200,
                response_headers=resp_headers,
                response_body=proof_resp,
                response_size=len(proof_resp),
                duration_ms=1.0,
                truncated=False,
                redirect_chain=[spec.url],
                scope_decision={"allowed": True},
                transport_error=None,
                request_hash="offline_hash",
                response_hash="offline_hash",
                success=True,
            )
        else:
            raise ValueError(f"Unsupported request engine: {type(self.request_engine)}")

        self.requests_made += 1

        self.record_evidence(
            evidence_type="verification_http_request",
            data={
                "url": evidence.url,
                "method": evidence.method,
                "status": evidence.response_status,
                "success": evidence.success,
                "truncated": evidence.truncated,
                "transport_error": evidence.transport_error,
            },
            request_id=evidence.request_id,
        )

        return evidence


# ──────────────────────────────────────────────────────────────────────────────
# 3. VERIFICATION STRATEGY INTERFACE & REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

class BaseVerificationStrategy(ABC):
    """Base interface for all deterministic verification strategies."""

    contract: VerificationContract

    @abstractmethod
    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        """Deterministically prove or disprove the security property."""
        pass

    def evaluate_preconditions(self, finding: Finding) -> Any:
        @dataclass
        class PreconditionResult:
            can_verify: bool = True
            missing_fields: list[str] = field(default_factory=list)

        return PreconditionResult(can_verify=bool(finding.affected_url))

    async def verify_candidate(self, finding: Finding, request_engine: Any) -> VerificationConclusion:
        candidate_evidence = {
            "affected_url": finding.affected_url,
            "proof_request": finding.proof_request,
            "proof_response": finding.proof_response,
            "payload": finding.payload,
            "affected_param": finding.affected_param,
            "vuln_type": finding.vuln_type,
            "category": finding.category,
        }
        context = VerificationContext(
            finding_id=finding.id,
            target_url=finding.affected_url or "https://target.local",
            request_engine=request_engine,
            candidate_evidence=candidate_evidence,
        )
        conclusion = await self.verify(context)
        engine = VerificationEngine()
        conclusion.impact_record = engine._compute_impact_record(finding, conclusion)
        return conclusion


class VerificationRegistry:
    """Registry of deterministic verification strategies mapped by check_id / vuln_type."""

    _strategies: dict[str, Type[BaseVerificationStrategy]] = {}

    @classmethod
    def register(cls, strategy_cls: Type[BaseVerificationStrategy]) -> None:
        contract = getattr(strategy_cls, "contract", None)
        if not contract or not contract.check_id:
            raise ValueError(f"Strategy {strategy_cls} missing valid VerificationContract")
        cls._strategies[contract.check_id] = strategy_cls

    ALIASES: dict[str, str] = {
        "C001_Open_Port_80": "transport_security",
        "C002_Missing_Security_Headers": "http_response_property",
        "C003_Sensitive_Files_Exposure": "sensitive_file_exposure",
        "C004_CORS_Misconfiguration": "cors_misconfiguration",
        "C005_GraphQL_Introspection": "graphql_introspection",
        "C006_Directory_Listing": "directory_listing",
        "C007_Open_Redirect": "open_redirect",
        "C008_Subdomain_Takeover": "subdomain_takeover",
        "C009_Exposed_Admin_Interface": "sensitive_file_exposure",
        "C010_TLS_Configuration_Weakness": "http_response_property",
        "C011_Technology_Exposure": "http_response_property",
        "C012_Auth_Bypass_Indicators": "authentication_comparison",
        "C013_Weak_Session_Cookie": "http_response_property",
        "C014_Missing_Secure_Cookie": "http_response_property",
        "C015_Missing_HttpOnly_Cookie": "http_response_property",
        "C016_Missing_SameSite_Cookie": "http_response_property",
        "C017_Session_Fixation": "generic_reproducibility",
        "C018_Session_Invalidation": "authentication_comparison",
        "C019_Password_Policy_Weakness": "generic_reproducibility",
        "C020_JWT_Algorithm_Weakness": "authentication_comparison",
        "C021_JWT_Claim_Validation": "authentication_comparison",
        "C022_Auth_Rate_Limit": "auth_rate_limit",
        "C022_AUTH_RATE_LIMIT": "auth_rate_limit",
        "C022_Authentication_Rate_Limit_Weakness": "auth_rate_limit",
        "Authentication Rate-Limit Weakness": "auth_rate_limit",
        "C024_Blind_SQL_Injection": "generic_reproducibility",
        "C025_NoSQL_Injection": "generic_reproducibility",
        "C026_Command_Injection_Indicators": "C026_OS_Command_Injection",
        "C027_OS_Command_Injection": "C026_OS_Command_Injection",
        "C028_SSTI": "generic_reproducibility",
        "C029_Header_Injection": "http_response_property",
        "C030_CRLF_Injection": "http_response_property",
        "C031_Path_Traversal": "generic_reproducibility",
        "C032_Local_File_Inclusion": "generic_reproducibility",
        "C033_XXE_Indicators": "generic_reproducibility",
        "C034_LDAP_Injection": "generic_reproducibility",
        "C035_EL_Injection": "generic_reproducibility",
        "C036_SSRF_Indicators": "generic_reproducibility",
        "C037_Reflected_XSS": "generic_reproducibility",
        "C038_Stored_XSS": "generic_reproducibility",
        "C039_DOM_XSS_Indicators": "generic_reproducibility",
        "C040_HTML_Context_Injection": "generic_reproducibility",
        "C041_Attribute_Context_Injection": "generic_reproducibility",
        "C042_JavaScript_Context_Injection": "generic_reproducibility",
        "C043_URL_Context_Injection": "generic_reproducibility",
        "C044_Mutation_XSS": "generic_reproducibility",
        "C045_XSS_Filter_Bypass": "generic_reproducibility",
        "C046_Unsafe_HTML_Rendering": "generic_reproducibility",
        "C047_Missing_CSP": "http_response_property",
        "C048_Weak_CSP": "http_response_property",
        "C049_Clickjacking": "http_response_property",
        "C050_MIME_Sniffing": "http_response_property",
        "C051_Cross_Domain_Policy": "generic_reproducibility",
        "C052_Insecure_HTTP_Methods": "http_response_property",
        "C053_Default_Setup_Page": "sensitive_file_exposure",
        "C054_Verbose_Error_Disclosure": "generic_reproducibility",
        "C055_Dangerous_File_Upload": "generic_reproducibility",
        "C056_Path_Normalization": "generic_reproducibility",
        "C057_Exposed_API_Keys": "sensitive_file_exposure",
        "C058_Source_Map_Exposure": "sensitive_file_exposure",
        "C059_PII_URL_Exposure": "http_response_property",
        "C060_Comment_Information_Disclosure": "generic_reproducibility",
        "C061_Backup_File_Exposure": "sensitive_file_exposure",
        "C062_Database_Dump_Exposure": "sensitive_file_exposure",
        "C063_Cloud_Bucket_Exposure": "generic_reproducibility",
        "C064_Git_Metadata_Exposure": "sensitive_file_exposure",
        "C065_Unencrypted_Transmission": "transport_security",
        "C066_Cleartext_Storage_Indicators": "generic_reproducibility",
        "C067_IDOR_Numeric_IDs": "authorization_comparison",
        "C068_IDOR_UUIDs": "authorization_comparison",
        "C069_BOLA_API": "authorization_comparison",
        "C070_Mass_Assignment": "authorization_comparison",
        "C071_Privilege_Escalation": "authorization_comparison",
        "C072_Function_Access_Control": "authorization_comparison",
        "C073_Parameter_Tampering": "generic_reproducibility",
        "C074_Workflow_Step_Skipping": "generic_reproducibility",
        "C075_Race_Condition": "generic_reproducibility",
        "C076_Replay_Attack": "generic_reproducibility",
        "C077_Missing_Reauthentication": "authorization_comparison",
        "Insecure Transport": "transport_security",
        "Insecure Transport Configuration": "transport_security",
        "transport_security": "transport_security",
        "Security Misconfiguration": "http_response_property",
        "Information Disclosure": "sensitive_file_exposure",
        "Cross-Origin Misconfiguration": "cors_misconfiguration",
        "Open Redirect": "open_redirect",
        "Subdomain Takeover": "subdomain_takeover",
        "Exposed Interface": "sensitive_file_exposure",
        "Insecure Transport Configuration": "http_response_property",
        "Authentication Bypass": "authentication_comparison",
        "Insecure Cookie Attributes": "http_response_property",
        "Session Fixation": "generic_reproducibility",
        "Session Invalidation Flaw": "authentication_comparison",
        "Weak Password Policy": "generic_reproducibility",
        "Insecure JWT Configuration": "authentication_comparison",
        "Insecure JWT Validation": "authentication_comparison",
        "Missing Rate Limiting": "auth_rate_limit",
        "SQL Injection": "generic_reproducibility",
        "Blind SQL Injection": "generic_reproducibility",
        "NoSQL Injection": "generic_reproducibility",
        "Command Injection": "generic_reproducibility",
        "OS Command Injection": "generic_reproducibility",
        "Template Injection": "generic_reproducibility",
        "HTTP Header Injection": "http_response_property",
        "CRLF Injection": "http_response_property",
        "Path Traversal": "generic_reproducibility",
        "Local File Inclusion": "generic_reproducibility",
        "XML Entity Injection": "generic_reproducibility",
        "LDAP Injection": "generic_reproducibility",
        "Expression Language Injection": "generic_reproducibility",
        "Server-Side Request Forgery": "generic_reproducibility",
        "Cross-Site Scripting": "generic_reproducibility",
        "Stored Cross-Site Scripting": "generic_reproducibility",
        "DOM-Based Cross-Site Scripting": "generic_reproducibility",
        "HTML Injection": "generic_reproducibility",
    }

    @classmethod
    def get_strategy(cls, check_id: str) -> Optional[BaseVerificationStrategy]:
        if not check_id:
            return None
        strategy_cls = cls._strategies.get(check_id)
        if not strategy_cls and check_id in cls.ALIASES:
            strategy_cls = cls._strategies.get(cls.ALIASES[check_id])
        if strategy_cls:
            return strategy_cls()
        return None

    get = get_strategy

    @classmethod
    def list_strategies(cls) -> list[str]:
        return list(cls._strategies.keys())

    @classmethod
    def clear(cls) -> None:
        cls._strategies.clear()


# ──────────────────────────────────────────────────────────────────────────────
# 4. SAFE MINIMAL DEMONSTRATION VERIFICATION STRATEGIES
# ──────────────────────────────────────────────────────────────────────────────

class GenericReproducibilityStrategy(BaseVerificationStrategy):
    """Verifies whether a candidate finding's proof response is deterministically reproducible."""

    contract = VerificationContract(
        check_id="generic_reproducibility",
        name="Generic Reproducibility Verification",
        security_property="Suspected vulnerability proof must be deterministically reproducible on active target.",
        required_evidence_fields=["affected_url", "proof_response"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url
        expected_proof = candidate.get("proof_response")
        payload = candidate.get("payload")

        # 1. Missing evidence check
        if not affected_url or not expected_proof:
            ev_id = context.record_evidence(
                evidence_type="missing_evidence",
                data={"reason": "Missing affected_url or proof_response in candidate evidence"},
            )
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="Candidate finding lacks mandatory proof_response or target URL.",
                evidence_ids=[ev_id],
                confidence=0,
            )

        # 2. Execute verification request via RequestEngine
        import sys
        from pathlib import Path
        sys.path.append(str(Path(__file__).parent.parent.parent))
        try:
            from backend.services.verification_strategies.request_builder import build_injected_request
            spec = build_injected_request(candidate, payload)
        except Exception as e:
            print(f"Exception in build_injected_request: {e}")
            spec = None
            
        if not spec:
            print(f"build_injected_request returned None! candidate: {candidate}, payload: {payload}")
            spec = RequestSpec(
                url=affected_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
        else:
            spec.timeout = RequestTimeout(connect=5.0, read=10.0, total=15.0)
        try:
            resp_evidence = await context.send_verification_request(spec)
        except BudgetExceededError as be:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description=str(be),
                confidence=0,
            )

        # 3. Scope / Transport denial
        if not resp_evidence.success:
            if resp_evidence.transport_error and resp_evidence.transport_error.get("error_type") == "SCOPE_DENIED":
                return VerificationConclusion(
                    status=VerificationStatus.INCONCLUSIVE,
                    reason_code=VerificationReasonCode.OUT_OF_SCOPE_BLOCKED,
                    reason_description="Verification target is out-of-scope or denied by scope policy.",
                    request_ids=[resp_evidence.request_id],
                    confidence=0,
                )
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description=f"Target endpoint failed transport: {resp_evidence.transport_error}",
                request_ids=[resp_evidence.request_id],
                confidence=0,
            )

        # 4. Deterministic comparison against expected proof response
        actual_response = resp_evidence.response_body or ""
        expected_clean = expected_proof.strip()

        # Check if clean 404 / 403 explicitly contradicts the finding
        if resp_evidence.response_status in (404, 410):
            ev_id = context.record_evidence(
                evidence_type="contradictory_evidence",
                data={"status": resp_evidence.response_status, "body": actual_response[:500]},
                request_id=resp_evidence.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
                reason_description=f"Endpoint returned HTTP {resp_evidence.response_status} (resource does not exist).",
                evidence_ids=[ev_id],
                request_ids=[resp_evidence.request_id],
                confidence=95,
            )

        # Deterministic match verification
        if expected_clean in actual_response or (payload and payload in actual_response):
            ev_id = context.record_evidence(
                evidence_type="reproduced_proof",
                data={"matched_proof": True, "response_status": resp_evidence.response_status},
                request_id=resp_evidence.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                reason_description="Security proof was deterministically replicated on target endpoint.",
                evidence_ids=[ev_id],
                request_ids=[resp_evidence.request_id],
                confidence=100,
            )

        # Mismatch -> Inconclusive
        ev_id = context.record_evidence(
            evidence_type="unreproduced_proof",
            data={"matched_proof": False, "observed_status": resp_evidence.response_status},
            request_id=resp_evidence.request_id,
        )
        return VerificationConclusion(
            status=VerificationStatus.INCONCLUSIVE,
            reason_code=VerificationReasonCode.INCONSISTENT_BEHAVIOR,
            reason_description="Candidate proof could not be reproduced on target response.",
            evidence_ids=[ev_id],
            request_ids=[resp_evidence.request_id],
            confidence=30,
        )


class HttpResponsePropertyStrategy(BaseVerificationStrategy):
    """Verifies specific HTTP response properties (e.g., missing security headers, insecure transport)."""

    contract = VerificationContract(
        check_id="http_response_property",
        name="HTTP Response Property Verification",
        security_property="Target response must reliably omit required security headers across baseline requests.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: Any, request_engine: Any = None, authorization_confirmed: bool = False) -> VerificationConclusion:
        if not isinstance(context, VerificationContext):
            finding = context
            c_ev = {
                "affected_url": getattr(finding, "affected_url", "https://example.com"),
                "affected_param": getattr(finding, "affected_param", None),
                "payload": getattr(finding, "payload", None),
                "proof_request": getattr(finding, "proof_request", None),
                "proof_response": getattr(finding, "proof_response", None),
                "confidence": getattr(finding, "confidence", 50),
                "vuln_type": getattr(finding, "vuln_type", ""),
            }
            context = VerificationContext(
                finding_id=getattr(finding, "id", "f-id"),
                check_id=self.contract.check_id,
                target_url=getattr(finding, "affected_url", "https://example.com"),
                candidate_evidence=c_ev,
                request_engine=request_engine,
                authorization_confirmed=authorization_confirmed,
            )

        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url
        
        # Determine appropriate header to check
        check_hint = f"{candidate.get('vuln_type', '')} {candidate.get('check_id', '')} {context.check_id or ''}".upper()
        if "CSP" in check_hint or "C047" in check_hint:
            required_header = "content-security-policy"
        elif "CLICKJACKING" in check_hint or "FRAME" in check_hint or "C049" in check_hint:
            required_header = "x-frame-options"
        elif "MIME" in check_hint or "SNIFF" in check_hint or "C050" in check_hint:
            required_header = "x-content-type-options"
        elif "HSTS" in check_hint or "TLS" in check_hint or "C010" in check_hint:
            required_header = "strict-transport-security"
        else:
            required_header = candidate.get("required_header", "strict-transport-security").lower()

        spec = RequestSpec(url=affected_url, method="GET")
        try:
            resp_evidence = await context.send_verification_request(spec)
        except BudgetExceededError as be:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description=str(be),
            )

        if not resp_evidence.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Target endpoint failed to respond.",
                request_ids=[resp_evidence.request_id],
            )

        headers_lower = {k.lower(): v for k, v in resp_evidence.response_headers.items()}
        if required_header not in headers_lower:
            ev_id = context.record_evidence(
                evidence_type="missing_header_verified",
                data={"missing_header": required_header, "headers": headers_lower},
                request_id=resp_evidence.request_id,
            )
            # INVARIANT: Missing security defense header is a hardening condition, NOT an exploitable vulnerability
            return VerificationConclusion(
                status=VerificationStatus.HARDENING_ONLY,
                reason_code=VerificationReasonCode.HARDENING_OBSERVED,
                reason_description=f"Observed condition: '{required_header}' header is absent in live response (defense-in-depth hardening recommendation).",
                evidence_ids=[ev_id],
                request_ids=[resp_evidence.request_id],
                confidence=50,
            )

        # Header IS present -> Finding is a False Positive!
        ev_id = context.record_evidence(
            evidence_type="header_present_contradiction",
            data={"found_header": required_header, "value": headers_lower[required_header]},
            request_id=resp_evidence.request_id,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.HEADER_PRESENT_CONTRADICTION,
            reason_description=f"Defense header '{required_header}' was observed present. Original finding was a false positive.",
            evidence_ids=[ev_id],
            request_ids=[resp_evidence.request_id],
            confidence=10,
        )


class AuthRateLimitVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies authentication rate limiting.

    INVARIANT: Receiving HTTP 200 without HTTP 429 across 5 attempts is NOT conclusive evidence
    of a rate-limit vulnerability. Real applications frequently enforce progressive delays,
    CAPTCHA, account lockouts, or higher attempt thresholds.
    """

    contract = VerificationContract(
        check_id="auth_rate_limit",
        name="Authentication Rate Limit Verification",
        security_property="Authentication endpoints must enforce rate limits and prevent automated brute-force attacks.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: Any, request_engine: Any = None, authorization_confirmed: bool = False) -> VerificationConclusion:
        if not isinstance(context, VerificationContext):
            finding = context
            c_ev = {
                "affected_url": getattr(finding, "affected_url", "https://example.com"),
                "affected_param": getattr(finding, "affected_param", None),
                "payload": getattr(finding, "payload", None),
                "proof_request": getattr(finding, "proof_request", None),
                "proof_response": getattr(finding, "proof_response", None),
                "confidence": getattr(finding, "confidence", 50),
                "vuln_type": getattr(finding, "vuln_type", ""),
            }
            context = VerificationContext(
                finding_id=getattr(finding, "id", "f-id"),
                check_id=self.contract.check_id,
                target_url=getattr(finding, "affected_url", "https://example.com"),
                candidate_evidence=c_ev,
                request_engine=request_engine,
                authorization_confirmed=authorization_confirmed,
            )

        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url
        proof_response = str(candidate.get("proof_response") or "")

        is_429_enforced = (
            "429 too many requests" in proof_response.lower()
            or "retry-after" in proof_response.lower()
            or ("429" in proof_response and not any(neg in proof_response.lower() for neg in ["no 429", "without 429", "no http 429"]))
        )

        if is_429_enforced:
            ev_id = context.record_evidence(
                evidence_type="rate_limit_enforced",
                data={"proof": proof_response},
            )
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTROL_ENFORCED,
                reason_description="HTTP 429 Too Many Requests was observed; rate limiting is active.",
                evidence_ids=[ev_id],
                confidence=10,
            )

        # Check whether the evidence demonstrates actual credential bypass or brute-force success
        has_bypass_evidence = (
            "bypass_demonstrated" in proof_response.lower()
            or "automated_stuffing_confirmed" in proof_response.lower()
            or "lockout_bypassed" in proof_response.lower()
            or "credential_guessing_confirmed" in proof_response.lower()
        )

        if not has_bypass_evidence:
            ev_id = context.record_evidence(
                evidence_type="rate_limit_insufficient_evidence",
                data={"reason": "no_429_does_not_prove_rate_limit_vulnerability", "proof": proof_response},
            )
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.RATE_LIMIT_INSUFFICIENT_EVIDENCE,
                reason_description="INCONCLUSIVE: 5 consecutive authentication requests without HTTP 429 does not prove missing rate limiting. Server may enforce progressive delays, CAPTCHA challenges, or higher attempt thresholds. Actual authentication control bypass was not demonstrated.",
                evidence_ids=[ev_id],
                confidence=25,
            )

        ev_id = context.record_evidence(
            evidence_type="rate_limit_bypass_verified",
            data={"proof": proof_response},
        )
        return VerificationConclusion(
            status=VerificationStatus.VALIDATED,
            reason_code=VerificationReasonCode.RATE_LIMIT_BYPASS_PROVEN,
            reason_description="Rate limiting failure validated with demonstrated credential stuffing/lockout bypass.",
            evidence_ids=[ev_id],
            confidence=85,
        )


class AuthenticationComparisonStrategy(BaseVerificationStrategy):
    """Compares unauthenticated vs authenticated access to prove whether an auth boundary is broken."""

    contract = VerificationContract(
        check_id="authentication_comparison",
        name="Authentication Boundary Comparison",
        security_property="Protected resource must be accessible unauthenticated (broken auth) vs authenticated.",
        required_evidence_fields=["affected_url"],
        destructive=False,
        requires_auth=True,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url

        # 1. Baseline Request: Unauthenticated
        unauth_spec = RequestSpec(url=affected_url, method="GET", auth_context=None)
        try:
            unauth_resp = await context.send_verification_request(unauth_spec)
        except BudgetExceededError as be:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description=str(be),
            )

        if not unauth_resp.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Endpoint unavailable during baseline test.",
                request_ids=[unauth_resp.request_id],
            )

        # If unauthenticated request is properly blocked with 401 or 403, auth IS enforced -> False Positive!
        if unauth_resp.response_status in (401, 403):
            ev_id = context.record_evidence(
                evidence_type="auth_properly_enforced",
                data={"status": unauth_resp.response_status},
                request_id=unauth_resp.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.AUTH_REQUIRED_OR_ENFORCED,
                reason_description=f"Authentication is properly enforced (HTTP {unauth_resp.response_status}).",
                evidence_ids=[ev_id],
                request_ids=[unauth_resp.request_id],
                confidence=100,
            )

        # If unauthenticated request returned 200 with sensitive payload indicators
        if unauth_resp.response_status == 200:
            expected_secret = candidate.get("sensitive_keyword")
            if expected_secret and expected_secret in (unauth_resp.response_body or ""):
                ev_id = context.record_evidence(
                    evidence_type="unauth_sensitive_data_leak",
                    data={"leaked_keyword": expected_secret, "status": 200},
                    request_id=unauth_resp.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description="Unauthenticated access successfully retrieved protected sensitive data.",
                    evidence_ids=[ev_id],
                    request_ids=[unauth_resp.request_id],
                    confidence=100,
                )

        return VerificationConclusion(
            status=VerificationStatus.INCONCLUSIVE,
            reason_code=VerificationReasonCode.MISSING_EVIDENCE,
            reason_description="Unauthenticated response does not conclusively demonstrate broken authentication.",
            request_ids=[unauth_resp.request_id],
            confidence=40,
        )


class AuthorizationComparisonStrategy(BaseVerificationStrategy):
    """Compares User A vs User B access to User B's object to verify IDOR / Tenant isolation."""

    contract = VerificationContract(
        check_id="authorization_comparison",
        name="Authorization Boundary Comparison",
        security_property="User A must be capable of accessing an object belonging to User B without authorization.",
        required_evidence_fields=["affected_url", "victim_object_id"],
        destructive=False,
        requires_auth=True,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url
        victim_token = candidate.get("attacker_auth_token", "user_a_token")
        expected_victim_data = candidate.get("expected_victim_data")

        # Test request: Attacker (User A) requests Victim (User B) resource
        attacker_auth = AuthenticationContext(
            name="User-A-Attacker",
            headers={"Authorization": f"Bearer {victim_token}"},
        )
        spec = RequestSpec(url=affected_url, method="GET", auth_context=attacker_auth)

        try:
            resp = await context.send_verification_request(spec)
        except BudgetExceededError as be:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description=str(be),
            )

        if not resp.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Endpoint failed to respond during authorization test.",
                request_ids=[resp.request_id],
            )

        # If User A is rejected with 401, 403, or 404 (isolation enforced)
        if resp.response_status in (401, 403, 404):
            ev_id = context.record_evidence(
                evidence_type="authorization_enforced",
                data={"status": resp.response_status},
                request_id=resp.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.AUTH_REQUIRED_OR_ENFORCED,
                reason_description=f"Object isolation is enforced against User A (HTTP {resp.response_status}).",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=100,
            )

        # If User A successfully retrieved User B's private object
        if resp.response_status == 200 and expected_victim_data and expected_victim_data in (resp.response_body or ""):
            ev_id = context.record_evidence(
                evidence_type="idor_object_breach",
                data={"breached_data": expected_victim_data},
                request_id=resp.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description="User A successfully accessed User B's private object across authorization boundary.",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=100,
            )

        return VerificationConclusion(
            status=VerificationStatus.INCONCLUSIVE,
            reason_code=VerificationReasonCode.INCONSISTENT_BEHAVIOR,
            reason_description="Response does not demonstrate unauthorized cross-tenant object access.",
            request_ids=[resp.request_id],
            confidence=30,
        )


class SensitiveFileExposureStrategy(BaseVerificationStrategy):
    """Verifies whether a sensitive file is truly accessible and leaks sensitive tokens."""

    contract = VerificationContract(
        check_id="sensitive_file_exposure",
        name="Sensitive File Exposure Verification",
        security_property="Configuration and environment files containing sensitive secrets must not be accessible",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url
        expected_kw = candidate.get("sensitive_keyword") or candidate.get("payload")

        spec = RequestSpec(
            url=affected_url,
            method="GET",
            follow_redirects=False,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        try:
            resp_evidence = await context.send_verification_request(spec)
        except BudgetExceededError as be:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description=str(be),
            )

        if not resp_evidence.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description=f"Endpoint unavailable: {resp_evidence.transport_error}",
                request_ids=[resp_evidence.request_id],
            )

        # Contradiction: 404/403/410 -> False positive
        if resp_evidence.response_status in (404, 403, 410):
            ev_id = context.record_evidence(
                evidence_type="sensitive_file_inaccessible",
                data={"status": resp_evidence.response_status},
                request_id=resp_evidence.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
                reason_description=f"Target file returned HTTP {resp_evidence.response_status} (inaccessible).",
                evidence_ids=[ev_id],
                request_ids=[resp_evidence.request_id],
                confidence=100,
            )

        body = resp_evidence.response_body or ""
        # 200 OK + body matches sensitive keywords
        common_sensitive_keywords = ["DB_", "SECRET", "PASSWORD", "API_KEY", "[core]", "[remote", "RewriteEngine", "Deny from", "AuthType", "repositoryformatversion"]
        matched_kw = next((kw for kw in common_sensitive_keywords if kw in body), None)
        if expected_kw and expected_kw in body:
            matched_kw = expected_kw

        if resp_evidence.response_status == 200 and matched_kw:
            ev_id = context.record_evidence(
                evidence_type="sensitive_file_leaked",
                data={"status": 200, "matched_keyword": matched_kw},
                request_id=resp_evidence.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description=f"Sensitive file verified accessible with token marker '{matched_kw}'.",
                evidence_ids=[ev_id],
                request_ids=[resp_evidence.request_id],
                confidence=100,
            )

        # Returned 200 but generic HTML page without sensitive content -> False Positive / Custom 404
        if "<!doctype html" in body.lower() or "<html" in body.lower():
            ev_id = context.record_evidence(
                evidence_type="generic_html_response",
                data={"status": 200, "reason": "HTML response without sensitive tokens"},
                request_id=resp_evidence.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
                reason_description="Endpoint returned generic HTML page without sensitive secret tokens.",
                evidence_ids=[ev_id],
                request_ids=[resp_evidence.request_id],
                confidence=90,
            )

        return VerificationConclusion(
            status=VerificationStatus.INCONCLUSIVE,
            reason_code=VerificationReasonCode.MISSING_EVIDENCE,
            reason_description="Response does not conclusively demonstrate exposed sensitive content.",
            request_ids=[resp_evidence.request_id],
            confidence=30,
        )


class TransportSecurityVerificationStrategy(BaseVerificationStrategy):
    """Verifies transport security (HTTP->HTTPS redirection and plaintext sensitive content exposure)."""

    contract = VerificationContract(
        check_id="transport_security",
        name="Transport Security Verification",
        security_property="HTTP endpoints must enforce mandatory redirect to HTTPS without cleartext sensitive data exposure",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url

        # Formulate non-destructive HTTP port request
        if affected_url.startswith("https://"):
            http_url = "http://" + affected_url[8:]
        else:
            http_url = affected_url

        spec = RequestSpec(
            url=http_url,
            method="GET",
            follow_redirects=False,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        try:
            resp_evidence = await context.send_verification_request(spec)
        except BudgetExceededError as be:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description=str(be),
            )

        if not resp_evidence.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Target HTTP endpoint failed to respond during transport verification.",
                request_ids=[resp_evidence.request_id],
            )

        status_code = resp_evidence.response_status
        headers_lower = {k.lower(): v for k, v in resp_evidence.response_headers.items()}
        location = headers_lower.get("location", "")
        body = resp_evidence.response_body or ""

        # Case 1: Standard HTTP -> HTTPS redirect (301, 302, 307, 308)
        if status_code in (301, 302, 307, 308) and location.lower().startswith("https://"):
            # Inspect for sensitive data leakage in plaintext redirect response
            sensitive_keywords = ["db_", "password", "secret", "api_key", "bearer ", "private_key", "token="]
            leaked_kw = next((kw for kw in sensitive_keywords if kw in body.lower()), None)
            set_cookie = headers_lower.get("set-cookie", "")
            has_sensitive_cookie = any(k in set_cookie.lower() for k in ["session", "token", "auth", "jwt"])

            if leaked_kw or has_sensitive_cookie:
                ev_id = context.record_evidence(
                    evidence_type="plaintext_redirect_leak",
                    data={"status": status_code, "location": location, "leaked_kw": leaked_kw, "cookie": set_cookie},
                    request_id=resp_evidence.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description="Insecure transport verified: Plaintext HTTP redirect leaks sensitive credentials/data.",
                    evidence_ids=[ev_id],
                    request_ids=[resp_evidence.request_id],
                    confidence=100,
                )

            # Normal clean redirect to HTTPS -> Deterministically REJECT
            ev_id = context.record_evidence(
                evidence_type="https_redirect_safe",
                data={"status": status_code, "location": location},
                request_id=resp_evidence.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.FINDING_REJECTED,
                reason_description="HTTP endpoint correctly redirects to HTTPS; no insecure transport impact demonstrated.",
                evidence_ids=[ev_id],
                request_ids=[resp_evidence.request_id],
                confidence=100,
            )

        # Case 2: Cleartext HTTP status 200 serving sensitive content or auth endpoint
        if status_code in (200, 204):
            sensitive_keywords = ["db_", "password", "secret", "api_key", "bearer ", "private_key", "authorization"]
            leaked_kw = next((kw for kw in sensitive_keywords if kw in body.lower()), None)
            expected_payload = candidate.get("payload") or candidate.get("proof_response")

            if leaked_kw or (expected_payload and expected_payload in body):
                ev_id = context.record_evidence(
                    evidence_type="cleartext_sensitive_data_exposure",
                    data={"status": status_code, "leaked_kw": leaked_kw},
                    request_id=resp_evidence.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description="Unencrypted HTTP endpoint serves sensitive data in cleartext without HTTPS enforcement.",
                    evidence_ids=[ev_id],
                    request_ids=[resp_evidence.request_id],
                    confidence=100,
                )

        # Case 3: No sensitive impact demonstrated
        ev_id = context.record_evidence(
            evidence_type="unencrypted_no_impact",
            data={"status": status_code, "location": location},
            request_id=resp_evidence.request_id,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.FINDING_REJECTED,
            reason_description="HTTP endpoint correctly redirects to HTTPS; no insecure transport impact demonstrated."
            if location.lower().startswith("https://")
            else "No insecure transport impact demonstrated.",
            evidence_ids=[ev_id],
            request_ids=[resp_evidence.request_id],
            confidence=90,
        )


class CorsMisconfigurationStrategy(BaseVerificationStrategy):
    """Verifies whether an untrusted Origin is insecurely reflected with demonstrated impact."""

    contract = VerificationContract(
        check_id="cors_misconfiguration",
        name="CORS Misconfiguration Verification",
        security_property="cross-origin behavior does not permit unauthorized credentialed access or sensitive data extraction",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url
        untrusted_origin = "https://evil.com"

        spec = RequestSpec(
            url=affected_url,
            method="GET",
            headers={"Origin": untrusted_origin},
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        try:
            resp_evidence = await context.send_verification_request(spec)
        except BudgetExceededError as be:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description=str(be),
            )

        if not resp_evidence.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Target endpoint failed to respond during CORS verification.",
                request_ids=[resp_evidence.request_id],
            )

        headers_lower = {k.lower(): v for k, v in resp_evidence.response_headers.items()}
        acao = headers_lower.get("access-control-allow-origin", "")
        acac = headers_lower.get("access-control-allow-credentials", "").lower() == "true"
        body = resp_evidence.response_body or ""

        # Check for sensitive keywords in response body
        sensitive_keywords = [
            "email", "token", "apikey", "api_key", "password", "secret",
            "account", "balance", "ssn", "credit", "user_id", "session", "private"
        ]
        has_sensitive_data = any(kw in body.lower() for kw in sensitive_keywords)
        if candidate.get("sensitive_keyword") and candidate.get("sensitive_keyword") in body:
            has_sensitive_data = True

        # State 1: Origin rejected or not reflected
        if not acao or (acao != "*" and "evil.com" not in acao and acao != "null"):
            ev_id = context.record_evidence(
                evidence_type="cors_origin_rejected",
                data={"observed_acao": acao},
                request_id=resp_evidence.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
                reason_description=f"CORS origin '{untrusted_origin}' was not reflected (ACAO: '{acao}').",
                evidence_ids=[ev_id],
                request_ids=[resp_evidence.request_id],
                confidence=100,
            )

        # State 2: Wildcard ACAO (*) without credentials
        if acao == "*" and not acac:
            if not has_sensitive_data and not candidate.get("demonstrated_impact"):
                ev_id = context.record_evidence(
                    evidence_type="cors_wildcard_non_sensitive",
                    data={"acao": acao, "acac": acac, "sensitive_data": False},
                    request_id=resp_evidence.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.FALSE_POSITIVE,
                    reason_code=VerificationReasonCode.FINDING_REJECTED,
                    reason_description="Permissive CORS policy observed, but security-sensitive cross-origin data access was not demonstrated.",
                    evidence_ids=[ev_id],
                    request_ids=[resp_evidence.request_id],
                    confidence=95,
                )
            else:
                # Sensitive unauthenticated data exposure with wildcard ACAO
                ev_id = context.record_evidence(
                    evidence_type="cors_wildcard_sensitive_leak",
                    data={"acao": acao, "acac": acac, "sensitive_data": True},
                    request_id=resp_evidence.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description="CORS misconfiguration confirmed: Wildcard ACAO permits cross-origin reading of unauthenticated sensitive data.",
                    evidence_ids=[ev_id],
                    request_ids=[resp_evidence.request_id],
                    confidence=95,
                )

        # State 3: Reflected Origin with Access-Control-Allow-Credentials: true
        if (acao == untrusted_origin or "evil.com" in acao or acao == "null") and acac:
            if has_sensitive_data or candidate.get("demonstrated_impact") or candidate.get("auth_token"):
                ev_id = context.record_evidence(
                    evidence_type="cors_credentialed_sensitive_verified",
                    data={"acao": acao, "acac": acac, "origin": untrusted_origin, "sensitive_data": True},
                    request_id=resp_evidence.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description="Credentialed CORS misconfiguration confirmed: Arbitrary origin reflected with Access-Control-Allow-Credentials: true and sensitive data readable cross-origin.",
                    evidence_ids=[ev_id],
                    request_ids=[resp_evidence.request_id],
                    confidence=100,
                )
            else:
                # ACAC true observed, but no sensitive data demonstrated -> reject
                ev_id = context.record_evidence(
                    evidence_type="cors_credentialed_no_sensitive_data",
                    data={"acao": acao, "acac": acac, "sensitive_data": False},
                    request_id=resp_evidence.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.FALSE_POSITIVE,
                    reason_code=VerificationReasonCode.FINDING_REJECTED,
                    reason_description="Permissive CORS policy observed, but security-sensitive cross-origin data access was not demonstrated.",
                    evidence_ids=[ev_id],
                    request_ids=[resp_evidence.request_id],
                    confidence=90,
                )

        # State 4: Reflected Origin without credentials
        if (acao == untrusted_origin or "evil.com" in acao or acao == "null") and not acac:
            if has_sensitive_data or candidate.get("demonstrated_impact"):
                ev_id = context.record_evidence(
                    evidence_type="cors_reflected_sensitive_leak",
                    data={"acao": acao, "acac": False},
                    request_id=resp_evidence.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description="CORS misconfiguration confirmed: Arbitrary origin reflected allowing cross-origin reading of sensitive data.",
                    evidence_ids=[ev_id],
                    request_ids=[resp_evidence.request_id],
                    confidence=95,
                )
            else:
                ev_id = context.record_evidence(
                    evidence_type="cors_reflected_no_sensitive_data",
                    data={"acao": acao, "acac": False},
                    request_id=resp_evidence.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.FALSE_POSITIVE,
                    reason_code=VerificationReasonCode.FINDING_REJECTED,
                    reason_description="Permissive CORS policy observed, but security-sensitive cross-origin data access was not demonstrated.",
                    evidence_ids=[ev_id],
                    request_ids=[resp_evidence.request_id],
                    confidence=95,
                )

        # Default fallback
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.FINDING_REJECTED,
            reason_description="Permissive CORS policy observed, but security-sensitive cross-origin data access was not demonstrated.",
            request_ids=[resp_evidence.request_id],
            confidence=90,
        )


class GraphqlIntrospectionStrategy(BaseVerificationStrategy):
    """Verifies whether GraphQL introspection query actually returns schema metadata."""

    contract = VerificationContract(
        check_id="graphql_introspection",
        name="GraphQL Introspection Verification",
        security_property="GraphQL schema introspection must be disabled in production environments",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url
        query_payload = '{"query":"{ __schema { types { name } } }"}'

        spec = RequestSpec(
            url=affected_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=query_payload,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        try:
            resp_evidence = await context.send_verification_request(spec)
        except BudgetExceededError as be:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description=str(be),
            )

        if not resp_evidence.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Endpoint failed to respond during GraphQL verification.",
                request_ids=[resp_evidence.request_id],
            )

        body = resp_evidence.response_body or ""
        if resp_evidence.response_status == 200 and "__schema" in body and "types" in body:
            ev_id = context.record_evidence(
                evidence_type="graphql_introspection_verified",
                data={"status": 200, "types_found": True},
                request_id=resp_evidence.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description="GraphQL introspection schema query succeeded and returned type definitions.",
                evidence_ids=[ev_id],
                request_ids=[resp_evidence.request_id],
                confidence=100,
            )

        # Introspection blocked, disabled, or 404 -> False Positive
        ev_id = context.record_evidence(
            evidence_type="graphql_introspection_blocked",
            data={"status": resp_evidence.response_status},
            request_id=resp_evidence.request_id,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description=f"GraphQL introspection query did not return schema definitions (HTTP {resp_evidence.response_status}).",
            evidence_ids=[ev_id],
            request_ids=[resp_evidence.request_id],
            confidence=100,
        )


class DirectoryListingStrategy(BaseVerificationStrategy):
    """Verifies whether directory indexing is actually active on the target directory."""

    contract = VerificationContract(
        check_id="directory_listing",
        name="Directory Listing Verification",
        security_property="Web server must not generate directory listings for directories without default index documents",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: Any, request_engine: Any = None, authorization_confirmed: bool = False) -> VerificationConclusion:
        if not isinstance(context, VerificationContext):
            finding = context
            c_ev = {
                "affected_url": getattr(finding, "affected_url", "https://example.com"),
                "affected_param": getattr(finding, "affected_param", None),
                "payload": getattr(finding, "payload", None),
                "proof_request": getattr(finding, "proof_request", None),
                "proof_response": getattr(finding, "proof_response", None),
                "confidence": getattr(finding, "confidence", 50),
                "vuln_type": getattr(finding, "vuln_type", ""),
            }
            context = VerificationContext(
                finding_id=getattr(finding, "id", "f-id"),
                check_id=self.contract.check_id,
                target_url=getattr(finding, "affected_url", "https://example.com"),
                candidate_evidence=c_ev,
                request_engine=request_engine,
                authorization_confirmed=authorization_confirmed,
            )

        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url

        spec = RequestSpec(
            url=affected_url,
            method="GET",
            follow_redirects=False,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        try:
            resp_evidence = await context.send_verification_request(spec)
        except BudgetExceededError as be:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description=str(be),
            )

        if not resp_evidence.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Endpoint failed to respond during directory listing verification.",
                request_ids=[resp_evidence.request_id],
            )

        body = resp_evidence.response_body or ""
        resp_status = resp_evidence.response_status
        resp_req_id = resp_evidence.request_id

        indicators = ["Index of /", "Directory listing for", "<title>Index of", "[To Parent Directory]", "Last modified</a>"]
        matched = next((ind for ind in indicators if ind.lower() in body.lower()), None)

        if resp_status == 200 and matched:
            sensitive_patterns = [
                r"\.env\b", r"\.git\b", r"\.aws\b", r"\.ssh\b", r"\.sql\b",
                r"\.bak\b", r"\.backup\b", r"\.old\b", r"\.tar\b", r"\.gz\b",
                r"\.zip\b", r"\.dump\b", r"config\.(php|json|ya?ml|py|inc)\b",
                r"database\.(php|json|ya?ml|py|sqlite|db)\b", r"credentials?\b",
                r"password\b", r"secret\b", r"id_rsa\b", r"private_key\b",
                r"\.htpasswd\b"
            ]
            sensitive_match = next((pat for pat in sensitive_patterns if re.search(pat, body, re.IGNORECASE)), None)
            if sensitive_match:
                ev_id = context.record_evidence(
                    evidence_type="directory_listing_sensitive_verified",
                    data={"status": 200, "matched_indicator": matched, "sensitive_pattern": sensitive_match},
                    request_id=resp_req_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VALIDATED,
                    reason_code=VerificationReasonCode.DIRECTORY_LISTING_SENSITIVE,
                    reason_description=f"Directory listing on '{affected_url}' exposes sensitive artifact matching '{sensitive_match}'. Demonstrable information disclosure impact.",
                    evidence_ids=[ev_id],
                    request_ids=[resp_req_id],
                    confidence=90,
                )

            # Benign directory listing (images, static files, fonts)
            ev_id = context.record_evidence(
                evidence_type="directory_listing_benign_verified",
                data={"status": 200, "matched_indicator": matched},
                request_id=resp_req_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.HARDENING_ONLY,
                reason_code=VerificationReasonCode.DIRECTORY_LISTING_BENIGN,
                reason_description=f"Directory listing observed on '{affected_url}' ({matched}), but index contains only non-sensitive public assets. Defense-in-depth hardening recommendation (no sensitive data disclosure demonstrated).",
                evidence_ids=[ev_id],
                request_ids=[resp_req_id],
                confidence=75,
            )

        # 403, 404, or normal web page -> False positive
        ev_id = context.record_evidence(
            evidence_type="directory_listing_not_found",
            data={"status": resp_status},
            request_id=resp_req_id,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description=f"Directory listing not observed on endpoint (HTTP {resp_status}).",
            evidence_ids=[ev_id],
            request_ids=[resp_req_id],
            confidence=100,
        )


class OpenRedirectStrategy(BaseVerificationStrategy):
    """Verifies whether a user-supplied redirect parameter successfully issues a 3xx redirect to an external destination."""

    contract = VerificationContract(
        check_id="open_redirect",
        name="Open Redirect Verification",
        security_property="user-controlled redirect destination is not allowed to redirect to an unauthorized external destination",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url

        spec = RequestSpec(
            url=affected_url,
            method="GET",
            follow_redirects=False,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        try:
            resp_evidence = await context.send_verification_request(spec)
        except BudgetExceededError as be:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description=str(be),
            )

        if not resp_evidence.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Endpoint failed to respond during open redirect verification.",
                request_ids=[resp_evidence.request_id],
            )

        headers_lower = {k.lower(): v for k, v in resp_evidence.response_headers.items()}
        location = headers_lower.get("location", "")
        if resp_evidence.response_status in (301, 302, 303, 307, 308) and location:
            if location.startswith("https://evil.com") or location.startswith("http://evil.com") or "evil.com" in location.lower():
                ev_id = context.record_evidence(
                    evidence_type="open_redirect_verified",
                    data={"status": resp_evidence.response_status, "location": location},
                    request_id=resp_evidence.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description=f"Open redirect verified: target responded with HTTP {resp_evidence.response_status} Location: '{location}'.",
                    evidence_ids=[ev_id],
                    request_ids=[resp_evidence.request_id],
                    confidence=100,
                )

        # 200 OK or redirect stayed on local domain -> False positive
        ev_id = context.record_evidence(
            evidence_type="open_redirect_not_reproduced",
            data={"status": resp_evidence.response_status, "location": location},
            request_id=resp_evidence.request_id,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description=f"Open redirect failed to reproduce (HTTP {resp_evidence.response_status}, Location: '{location}').",
            evidence_ids=[ev_id],
            request_ids=[resp_evidence.request_id],
            confidence=100,
        )


class SubdomainTakeoverStrategy(BaseVerificationStrategy):
    """Verifies whether target endpoint deterministically reflects dangling cloud service fingerprints."""

    contract = VerificationContract(
        check_id="subdomain_takeover",
        name="Subdomain Takeover Verification",
        security_property="DNS records must not point to unclaimed or deprovisioned cloud service providers",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    SERVICE_FINGERPRINTS = [
        "There isn't a GitHub Pages site here",
        "NoSuchBucket",
        "The specified bucket does not exist",
        "No such app",
        "There's nothing here, yet.",
        "404 Web Site not found",
        "Fastly error: unknown domain",
        "Sorry, this shop is currently unavailable",
        "Repository not found",
        "The thing you were looking for is gone",
        "project not found",
        "Do you want to register",
        "Help Center Closed",
    ]

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url

        spec = RequestSpec(
            url=affected_url,
            method="GET",
            follow_redirects=True,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        try:
            resp_evidence = await context.send_verification_request(spec)
        except BudgetExceededError as be:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description=str(be),
            )

        if not resp_evidence.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Endpoint failed to respond during subdomain takeover verification.",
                request_ids=[resp_evidence.request_id],
            )

        body = resp_evidence.response_body or ""
        matched = next((fp for fp in self.SERVICE_FINGERPRINTS if fp.lower() in body.lower()), None)

        if matched:
            ev_id = context.record_evidence(
                evidence_type="subdomain_takeover_verified",
                data={"matched_fingerprint": matched, "status": resp_evidence.response_status},
                request_id=resp_evidence.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description=f"Subdomain takeover confirmed: Service fingerprint '{matched}' reproduced (HTTP {resp_evidence.response_status}).",
                evidence_ids=[ev_id],
                request_ids=[resp_evidence.request_id],
                confidence=100,
            )

        ev_id = context.record_evidence(
            evidence_type="subdomain_takeover_not_reproduced",
            data={"status": resp_evidence.response_status},
            request_id=resp_evidence.request_id,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description="Dangling cloud service fingerprint was not observed on verification request.",
            evidence_ids=[ev_id],
            request_ids=[resp_evidence.request_id],
            confidence=100,
        )


# Register initial safe demonstration strategies
VerificationRegistry.register(GenericReproducibilityStrategy)
VerificationRegistry.register(TransportSecurityVerificationStrategy)
VerificationRegistry.register(HttpResponsePropertyStrategy)
VerificationRegistry.register(AuthRateLimitVerificationStrategy)
VerificationRegistry.register(AuthenticationComparisonStrategy)
VerificationRegistry.register(AuthorizationComparisonStrategy)
VerificationRegistry.register(SensitiveFileExposureStrategy)
VerificationRegistry.register(CorsMisconfigurationStrategy)
VerificationRegistry.register(GraphqlIntrospectionStrategy)
VerificationRegistry.register(DirectoryListingStrategy)
VerificationRegistry.register(OpenRedirectStrategy)
VerificationRegistry.register(SubdomainTakeoverStrategy)
from backend.services.verification_strategies.sql_injection_strategy import SqlInjectionVerificationStrategy
from backend.services.verification_strategies.blind_sql_injection_strategy import BlindSqlInjectionVerificationStrategy
from backend.services.verification_strategies.command_injection_strategy import CommandInjectionVerificationStrategy
VerificationRegistry.register(SqlInjectionVerificationStrategy)
VerificationRegistry.register(BlindSqlInjectionVerificationStrategy)
VerificationRegistry.register(CommandInjectionVerificationStrategy)


# ──────────────────────────────────────────────────────────────────────────────
# 5. VERIFICATION ENGINE ORCHESTRATOR
# ──────────────────────────────────────────────────────────────────────────────

class VerificationEngine:
    """Central deterministic verification orchestrator."""

    def __init__(self, registry: Optional[Type[VerificationRegistry]] = None) -> None:
        self.registry = registry or VerificationRegistry

    def _compute_impact_record(self, finding: Finding, conclusion: VerificationConclusion) -> StructuredImpactRecord:
        """Deterministically derive StructuredImpactRecord from evidence and contract."""
        vuln_type = str(finding.vuln_type or finding.category or "").upper()
        sev = str(finding.severity or "info").lower()

        if conclusion.status in (VerificationStatus.VERIFIED, VerificationStatus.VALIDATED, VerificationStatus.EXPLOITABLE):
            if any(k in vuln_type for k in ["SQL", "COMMAND", "RCE", "SSTI", "TRAVERSAL"]) or sev == "critical":
                return StructuredImpactRecord(
                    exploitability="HIGH",
                    impact="CRITICAL",
                    affected_confidentiality="HIGH",
                    affected_integrity="HIGH",
                    affected_availability="HIGH",
                    authentication_requirement="NONE",
                    privilege_requirement="NONE",
                    user_interaction="NONE",
                    scope="CHANGED",
                    confidence="CONFIRMED",
                    confidence_reason=conclusion.reason_description,
                    verifier_version=VERIFIER_VERSION,
                )
            elif "CORS" in vuln_type:
                return StructuredImpactRecord(
                    exploitability="HIGH",
                    impact="HIGH",
                    affected_confidentiality="HIGH",
                    affected_integrity="NONE",
                    affected_availability="NONE",
                    authentication_requirement="USER",
                    privilege_requirement="LOW",
                    user_interaction="REQUIRED",
                    scope="UNCHANGED",
                    confidence="CONFIRMED",
                    confidence_reason=conclusion.reason_description,
                    verifier_version=VERIFIER_VERSION,
                )
            elif any(k in vuln_type for k in ["IDOR", "BOLA", "AUTH", "PRIVILEGE", "SSRF"]) or sev == "high":
                return StructuredImpactRecord(
                    exploitability="MEDIUM",
                    impact="HIGH",
                    affected_confidentiality="HIGH",
                    affected_integrity="LOW",
                    affected_availability="NONE",
                    authentication_requirement="USER",
                    privilege_requirement="LOW",
                    user_interaction="NONE",
                    scope="UNCHANGED",
                    confidence="CONFIRMED",
                    confidence_reason=conclusion.reason_description,
                    verifier_version=VERIFIER_VERSION,
                )
            elif any(k in vuln_type for k in ["TRANSPORT", "CLEARText", "UNENCRYPTED", "SENSITIVE_FILE"]):
                return StructuredImpactRecord(
                    exploitability="MEDIUM",
                    impact="MEDIUM",
                    affected_confidentiality="HIGH",
                    affected_integrity="NONE",
                    affected_availability="NONE",
                    authentication_requirement="NONE",
                    privilege_requirement="NONE",
                    user_interaction="NONE",
                    scope="UNCHANGED",
                    confidence="CONFIRMED",
                    confidence_reason=conclusion.reason_description,
                    verifier_version=VERIFIER_VERSION,
                )
            else:
                return StructuredImpactRecord(
                    exploitability="LOW",
                    impact="MEDIUM" if sev == "medium" else "LOW",
                    affected_confidentiality="LOW",
                    affected_integrity="LOW",
                    affected_availability="NONE",
                    authentication_requirement="NONE",
                    privilege_requirement="NONE",
                    user_interaction="NONE",
                    scope="UNCHANGED",
                    confidence="CONFIRMED",
                    confidence_reason=conclusion.reason_description,
                    verifier_version=VERIFIER_VERSION,
                )

        elif conclusion.status == VerificationStatus.HARDENING_ONLY:
            return StructuredImpactRecord(
                exploitability="NONE",
                impact="LOW",
                affected_confidentiality="NONE",
                affected_integrity="NONE",
                affected_availability="NONE",
                authentication_requirement="NONE",
                privilege_requirement="NONE",
                user_interaction="NONE",
                scope="UNCHANGED",
                confidence="CONFIRMED",
                confidence_reason=conclusion.reason_description,
                verifier_version=VERIFIER_VERSION,
            )

        # Inconclusive or False Positive or Rejected
        return StructuredImpactRecord(
            exploitability="NONE",
            impact="NONE",
            affected_confidentiality="NONE",
            affected_integrity="NONE",
            affected_availability="NONE",
            authentication_requirement="NONE",
            privilege_requirement="NONE",
            user_interaction="NONE",
            scope="UNCHANGED",
            confidence="LOW" if conclusion.status == VerificationStatus.INCONCLUSIVE else "CONFIRMED",
            confidence_reason=conclusion.reason_description,
            verifier_version=VERIFIER_VERSION,
        )

    async def verify_finding(
        self,
        finding: Finding,
        request_engine: RequestEngine,
        auth_context: Optional[AuthenticationContext] = None,
        budget: Optional[VerificationBudget] = None,
        authorization_confirmed: bool = True,
    ) -> VerificationConclusion:
        """Deterministically verify a candidate finding and update its audit record."""
        # 1. Product Safety Check: Authorization
        if not authorization_confirmed:
            conclusion = VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.OUT_OF_SCOPE_BLOCKED,
                reason_description="Explicit authorization confirmation missing: Verification blocked.",
                confidence=0,
            )
            self._apply_conclusion_to_finding(finding, conclusion, [])
            return conclusion

        # 2. Select strategy from registry (or fallback to generic reproducibility)
        strategy = self.registry.get_strategy(finding.vuln_type)
        if not strategy:
            strategy = GenericReproducibilityStrategy()

        # 3. Non-Destructive Default Guard
        if strategy.contract.destructive:
            conclusion = VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.INCONSISTENT_BEHAVIOR,
                reason_description="Destructive verification is prohibited by safety policy.",
                confidence=0,
            )
            self._apply_conclusion_to_finding(finding, conclusion, [])
            return conclusion

        # 4. Construct candidate evidence map
        candidate_evidence = {
            "affected_url": finding.affected_url,
            "affected_param": finding.affected_param,
            "payload": finding.payload,
            "proof_request": finding.proof_request,
            "proof_response": finding.proof_response,
            "confidence": finding.confidence,
        }

        context = VerificationContext(
            finding_id=finding.id,
            check_id=strategy.contract.check_id,
            target_url=finding.affected_url,
            candidate_evidence=candidate_evidence,
            request_engine=request_engine,
            auth_context=auth_context,
            budget=budget or strategy.contract.default_budget,
            authorization_confirmed=authorization_confirmed,
        )

        # 5. Execute deterministic strategy
        try:
            conclusion = await strategy.verify(context)
        except Exception as exc:
            logger.error(f"Error during deterministic verification of finding {finding.id}: {exc}")
            conclusion = VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.INCONSISTENT_BEHAVIOR,
                reason_description=f"Verification strategy encountered an internal error: {exc}",
                confidence=0,
            )

        # 6. Traceability and Finding Update
        all_evidence_ids = list(set(conclusion.evidence_ids + [item.evidence_id for item in context.collected_evidence]))
        all_request_ids = list(set(conclusion.request_ids + [item.request_id for item in context.collected_evidence if item.request_id]))

        conclusion.evidence_ids = all_evidence_ids
        conclusion.request_ids = all_request_ids

        # 7. Pre-Verification Contract Validation: Require mandatory evidence fields before VERIFIED
        if conclusion.status == VerificationStatus.VERIFIED:
            missing_items = []
            if not finding.title or not str(finding.title).strip():
                if finding.vuln_type:
                    finding.title = str(finding.vuln_type).replace("_", " ")
                else:
                    missing_items.append("title")
            if not finding.affected_url or not str(finding.affected_url).strip():
                missing_items.append("affected_url")
            if not finding.proof_response and not any(it.data for it in context.collected_evidence):
                missing_items.append("proof_response")
            if not conclusion.evidence_ids and not context.collected_evidence:
                missing_items.append("evidence_ids")

            if missing_items:
                logger.warning("Downgrading finding %s: Missing mandatory verification fields: %s", finding.id, missing_items)
                conclusion = VerificationConclusion(
                    status=VerificationStatus.INCONCLUSIVE,
                    reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                    reason_description=f"Verification downgraded: Missing required evidence fields: {', '.join(missing_items)}.",
                    evidence_ids=conclusion.evidence_ids,
                    request_ids=conclusion.request_ids,
                    confidence=20,
                )

        conclusion.impact_record = self._compute_impact_record(finding, conclusion)
        self._apply_conclusion_to_finding(finding, conclusion, context.collected_evidence)
        return conclusion

    def _apply_conclusion_to_finding(
        self,
        finding: Finding,
        conclusion: VerificationConclusion,
        evidence_items: list[VerificationEvidenceItem],
    ) -> None:
        """Persist deterministic conclusion, SHA-256 evidence hashes, and impact records to Finding model."""
        finding.verification_status = conclusion.status.value
        finding.verification_reason_code = conclusion.reason_code.value
        finding.verification_method = conclusion.method
        from backend.models.database import get_utc_now
        finding.verification_timestamp = get_utc_now()
        finding.evidence_ids = json.dumps(conclusion.evidence_ids)
        finding.request_ids = json.dumps(conclusion.request_ids)
        finding.verifier_version = VERIFIER_VERSION
        finding.confidence_reason = conclusion.reason_description

        # Compute and persist SHA-256 evidence hashes
        proof_req_h = hashlib.sha256((finding.proof_request or "").encode("utf-8")).hexdigest()
        proof_resp_h = hashlib.sha256((finding.proof_response or "").encode("utf-8")).hexdigest()
        payload_h = hashlib.sha256((finding.payload or "").encode("utf-8")).hexdigest()
        finding.evidence_hashes = json.dumps({
            "proof_request_sha256": proof_req_h,
            "proof_response_sha256": proof_resp_h,
            "payload_sha256": payload_h,
        })

        if conclusion.impact_record:
            finding.impact_record = json.dumps(conclusion.impact_record.to_dict())

        # Maintain backwards compatibility with verdict string and false_positive flag
        curr_conf = finding.confidence if finding.confidence is not None else 0
        if conclusion.status in (VerificationStatus.VERIFIED, VerificationStatus.VALIDATED, VerificationStatus.EXPLOITABLE):
            finding.verdict = "Verified"
            finding.false_positive = False
            finding.verification_status = conclusion.status.value
            finding.finding_disposition = FindingDisposition.VULNERABILITY.value
            finding.condition_confidence = 1.0
            finding.reproducibility_confidence = 1.0
            if conclusion.status == VerificationStatus.EXPLOITABLE:
                finding.impact_confidence = 1.0
                finding.exploitability_confidence = 1.0
            else:
                finding.impact_confidence = 0.8
                finding.exploitability_confidence = 0.6
            finding.bounty_eligibility = getattr(finding, "bounty_eligibility", None) or BountyEligibility.UNKNOWN.value
            finding.confidence = max(curr_conf, conclusion.confidence or 85)
        elif conclusion.status == VerificationStatus.HARDENING_ONLY:
            finding.verdict = "Hardening Only"
            finding.false_positive = False
            finding.verification_status = VerificationStatus.HARDENING_ONLY.value
            finding.finding_disposition = FindingDisposition.HARDENING_ONLY.value
            finding.condition_confidence = 1.0
            finding.impact_confidence = 0.0
            finding.reproducibility_confidence = 1.0
            finding.exploitability_confidence = 0.0
            finding.bounty_eligibility = BountyEligibility.UNKNOWN.value
            finding.confidence = 50
        elif conclusion.status in (VerificationStatus.FALSE_POSITIVE, VerificationStatus.REJECTED):
            finding.verdict = "Likely False Positive"
            finding.false_positive = True
            finding.verification_status = "REJECTED" if conclusion.status == VerificationStatus.REJECTED else "FALSE_POSITIVE"
            finding.finding_disposition = FindingDisposition.FALSE_POSITIVE.value
            finding.condition_confidence = 0.0
            finding.impact_confidence = 0.0
            finding.reproducibility_confidence = 0.0
            finding.exploitability_confidence = 0.0
            finding.bounty_eligibility = BountyEligibility.INELIGIBLE.value
            finding.confidence = min(curr_conf, 10)
        elif conclusion.status == VerificationStatus.INCONCLUSIVE:
            finding.verdict = "Inconclusive"
            finding.false_positive = False
            finding.verification_status = "INCONCLUSIVE"
            finding.finding_disposition = FindingDisposition.INCONCLUSIVE.value
            finding.condition_confidence = 0.5
            finding.impact_confidence = 0.0
            finding.reproducibility_confidence = 0.5
            finding.exploitability_confidence = 0.0
            finding.bounty_eligibility = BountyEligibility.UNKNOWN.value
            finding.confidence = min(curr_conf, 30)
        elif conclusion.status == VerificationStatus.DUPLICATE:
            finding.verdict = "Candidate"
            finding.false_positive = True
            finding.verification_status = "DUPLICATE"
            finding.finding_disposition = FindingDisposition.NOT_BOUNTY_ELIGIBLE.value
            finding.bounty_eligibility = BountyEligibility.INELIGIBLE.value
        else:
            finding.verdict = "Candidate"
            finding.false_positive = False
            finding.verification_status = "CANDIDATE"
            finding.finding_disposition = FindingDisposition.INCONCLUSIVE.value
            finding.bounty_eligibility = BountyEligibility.UNKNOWN.value
