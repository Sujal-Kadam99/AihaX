"""AihaX Phase 21 — Verification Strategy Engine.

Defines deterministic, bounded verification strategies for hypothesis validation.

Security Invariants:
1. Maximum request budget for any strategy is bounded (<= 10 requests, typically 1-2).
2. Allowed HTTP methods strictly restricted to {GET, HEAD, OPTIONS}.
3. Every strategy provides explicit success, failure, and inconclusive evaluation conditions.
4. If the required strategy budget exceeds remaining campaign budget -> BLOCKED_BUDGET.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from sqlalchemy.orm import Session

from backend.models.database import (
    VerificationStrategyRecord,
    get_utc_now,
)
from backend.services.vulnerability_hypothesis import VulnerabilityClass

logger = logging.getLogger("aihax.verification_strategy")

LOCKED_ALLOWED_METHODS: Set[str] = {"GET", "HEAD", "OPTIONS"}
LOCKED_MAX_STRATEGY_BUDGET: int = 10
LOCKED_PRODUCTION_BUDGET: int = 10
LOCKED_RATE_LIMIT_RPS: int = 2
LOCKED_MAX_CONCURRENCY: int = 1


@dataclass
class VerificationStrategyDTO:
    strategy_id: str
    vulnerability_class: str
    prerequisite_evidence: List[str]
    request_budget: int
    allowed_methods: List[str]
    expected_observations: List[str]
    success_conditions: List[str]
    failure_conditions: List[str]
    inconclusive_conditions: List[str]
    safety_constraints: List[str]
    created_at: str = field(default_factory=lambda: get_utc_now().isoformat())

    @property
    def method(self) -> str:
        return self.allowed_methods[0] if self.allowed_methods else "GET"

    @property
    def endpoint_template(self) -> str:
        return "/"

    @property
    def parameters(self) -> Dict[str, Any]:
        return {}

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StrategyValidationResult:
    is_valid: bool
    status: str  # VALID, BLOCKED_BUDGET, BLOCKED_METHOD, BLOCKED_SCOPE, BLOCKED_SAFETY
    reason: str
    required_requests: int
    allowed_methods: List[str] = field(default_factory=lambda: ["GET", "HEAD", "OPTIONS"])

    @property
    def feasible(self) -> bool:
        return self.is_valid

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class VerificationStrategyEngine:
    """Registry and execution contract validator for safe verification experiments."""

    # Canonical bounded strategies for each vulnerability class
    BUILTIN_STRATEGIES: Dict[str, VerificationStrategyDTO] = {
        "STRAT-SEC-HDR-01": VerificationStrategyDTO(
            strategy_id="STRAT-SEC-HDR-01",
            vulnerability_class=VulnerabilityClass.SECURITY_HEADERS,
            prerequisite_evidence=["Endpoint reachable via HTTP/HTTPS"],
            request_budget=1,
            allowed_methods=["GET", "HEAD"],
            expected_observations=["HSTS (Strict-Transport-Security)", "CSP (Content-Security-Policy)", "X-Content-Type-Options"],
            success_conditions=["Critical security header missing or set to unsafe permissive value (e.g. unsafe-inline without nonce)"],
            failure_conditions=["All standard protective headers present with strict directives (e.g. HSTS max-age >= 31536000)"],
            inconclusive_conditions=["Target endpoint returned 5xx server error or transport timed out"],
            safety_constraints=["Zero payload injection", "Passive header inspection only", "Max 1 request"],
        ),
        "STRAT-REDIRECT-01": VerificationStrategyDTO(
            strategy_id="STRAT-REDIRECT-01",
            vulnerability_class=VulnerabilityClass.OPEN_REDIRECT,
            prerequisite_evidence=["Observed redirect parameter in URL structure"],
            request_budget=2,
            allowed_methods=["GET", "HEAD"],
            expected_observations=["HTTP 301/302/303/307/308 redirect code", "Location header containing arbitrary destination"],
            success_conditions=["Server responds with 30x and Location header reflects arbitrary test domain without validation"],
            failure_conditions=["Server validates destination, normalizes to relative path, returns 400 Bad Request, or ignores parameter"],
            inconclusive_conditions=["Redirect leads to external login flow or intermediate identity provider without open redirect"],
            safety_constraints=["Test destination uses benign example.com or non-routable host", "Never follow out-of-scope redirect destination", "Max 2 requests"],
        ),
        "STRAT-IDOR-01": VerificationStrategyDTO(
            strategy_id="STRAT-IDOR-01",
            vulnerability_class=VulnerabilityClass.IDOR_BOLA,
            prerequisite_evidence=["Valid baseline object identifier and response in authorized context"],
            request_budget=2,
            allowed_methods=["GET", "HEAD"],
            expected_observations=["HTTP 200 vs 401/403/404 response comparison", "Object state differential"],
            success_conditions=["Controlled alternate identifier returns HTTP 200 with unauthorized resource data"],
            failure_conditions=["Alternate identifier returns HTTP 401 Unauthorized, 403 Forbidden, or 404 Not Found"],
            inconclusive_conditions=["Both requests return identical generic error or empty collection"],
            safety_constraints=["Only test authorized paired test fixtures", "Zero brute force enumeration", "Max 2 requests"],
        ),
        "STRAT-CORS-01": VerificationStrategyDTO(
            strategy_id="STRAT-CORS-01",
            vulnerability_class=VulnerabilityClass.CORS,
            prerequisite_evidence=["API endpoint responding to web clients"],
            request_budget=2,
            allowed_methods=["GET", "OPTIONS"],
            expected_observations=["Access-Control-Allow-Origin header", "Access-Control-Allow-Credentials header"],
            success_conditions=["Access-Control-Allow-Origin reflects test origin alongside Access-Control-Allow-Credentials: true"],
            failure_conditions=["Access-Control-Allow-Origin is static allowlisted domain or lacks Allow-Credentials: true"],
            inconclusive_conditions=["CORS headers not emitted on test endpoint or OPTIONS method disabled"],
            safety_constraints=["Test origin uses benign https://evil.example.com", "No cross-origin data exfiltration", "Max 2 requests"],
        ),
        "STRAT-AUTH-01": VerificationStrategyDTO(
            strategy_id="STRAT-AUTH-01",
            vulnerability_class=VulnerabilityClass.AUTHENTICATION,
            prerequisite_evidence=["Authentication/login endpoint identified"],
            request_budget=1,
            allowed_methods=["GET", "HEAD", "OPTIONS"],
            expected_observations=["Set-Cookie header attributes (Secure, HttpOnly, SameSite)", "Transport TLS enforcement"],
            success_conditions=["Session cookies lack Secure or HttpOnly flags over transport"],
            failure_conditions=["All session cookies strictly configure Secure; HttpOnly; SameSite=Lax/Strict"],
            inconclusive_conditions=["Authentication interface uses non-cookie token headers via client JavaScript"],
            safety_constraints=["Zero credential guessing or brute force", "Max 1 request"],
        ),
        "STRAT-SESSION-01": VerificationStrategyDTO(
            strategy_id="STRAT-SESSION-01",
            vulnerability_class=VulnerabilityClass.SESSION_SECURITY,
            prerequisite_evidence=["Session endpoint identified"],
            request_budget=1,
            allowed_methods=["GET", "HEAD"],
            expected_observations=["Cookie path, domain scoping, and expiry parameters"],
            success_conditions=["Session cookie domain overly broad (e.g. parent domain without host prefix) or cleartext scope"],
            failure_conditions=["Session cookies strictly scoped to host with appropriate expiry"],
            inconclusive_conditions=["No session cookies present in response"],
            safety_constraints=["Zero session theft or hijacking", "Max 1 request"],
        ),
        "STRAT-INFO-01": VerificationStrategyDTO(
            strategy_id="STRAT-INFO-01",
            vulnerability_class=VulnerabilityClass.INFORMATION_DISCLOSURE,
            prerequisite_evidence=["Error or status endpoint observed"],
            request_budget=1,
            allowed_methods=["GET", "HEAD"],
            expected_observations=["Response body pattern matching stack traces, internal paths, or environment secrets"],
            success_conditions=["Response body discloses server stack trace, internal database queries, or unredacted keys"],
            failure_conditions=["Generic sanitized error message returned (e.g. 'Internal Server Error' without details)"],
            inconclusive_conditions=["Response body is empty or non-HTML/non-JSON binary stream"],
            safety_constraints=["Zero destructive fault injection", "Max 1 request"],
        ),
        "STRAT-PARAM-01": VerificationStrategyDTO(
            strategy_id="STRAT-PARAM-01",
            vulnerability_class=VulnerabilityClass.URL_PARAMETER_BEHAVIOR,
            prerequisite_evidence=["Observed query parameter on endpoint"],
            request_budget=2,
            allowed_methods=["GET", "HEAD"],
            expected_observations=["Response body reflection or status code variation under benign boundary input"],
            success_conditions=["Parameter value reflected unencoded in HTML response or generates anomalous structural variance"],
            failure_conditions=["Parameter properly HTML-encoded, validated, or ignored by application logic"],
            inconclusive_conditions=["Response identical with dynamic token variations"],
            safety_constraints=["Only benign boundary markers (e.g. aihax_test_val)", "Zero exploit payloads", "Max 2 requests"],
        ),
        "STRAT-API-AUTH-01": VerificationStrategyDTO(
            strategy_id="STRAT-API-AUTH-01",
            vulnerability_class=VulnerabilityClass.API_AUTHORIZATION,
            prerequisite_evidence=["API endpoint observed in surface inventory"],
            request_budget=2,
            allowed_methods=["GET", "HEAD", "OPTIONS"],
            expected_observations=["Status code under unauthenticated vs authenticated context"],
            success_conditions=["Protected API endpoint returns HTTP 200 with sensitive payload without Authorization header"],
            failure_conditions=["API endpoint consistently returns HTTP 401 Unauthorized or 403 Forbidden without token"],
            inconclusive_conditions=["API endpoint is publicly intended without authentication requirements"],
            safety_constraints=["Read-only GET inquiry", "Max 2 requests"],
        ),
        "STRAT-CACHE-01": VerificationStrategyDTO(
            strategy_id="STRAT-CACHE-01",
            vulnerability_class=VulnerabilityClass.CACHE_BEHAVIOR,
            prerequisite_evidence=["Caching headers present in baseline response"],
            request_budget=2,
            allowed_methods=["GET", "HEAD"],
            expected_observations=["Cache-Control, Age, CF-Cache-Status headers across consecutive requests"],
            success_conditions=["Unkeyed test header reflected in cached response served to subsequent request"],
            failure_conditions=["Cache properly keys headers or bypasses cache on custom header variations"],
            inconclusive_conditions=["Endpoint does not cache or upstream cache disabled"],
            safety_constraints=["Benign test header X-Aihax-Probe: 1", "Max 2 requests"],
        ),
    }

    @classmethod
    def get_strategy(cls, strategy_id: str, db: Optional[Session] = None) -> Optional[VerificationStrategyDTO]:
        """Fetch strategy by ID from builtins or database."""
        if strategy_id in cls.BUILTIN_STRATEGIES:
            return cls.BUILTIN_STRATEGIES[strategy_id]

        if db is not None:
            rec = db.query(VerificationStrategyRecord).filter_by(strategy_id=strategy_id).first()
            if rec:
                return cls._record_to_dto(rec)

        return None

    @classmethod
    def get_strategy_for_class(cls, vuln_class: str) -> VerificationStrategyDTO:
        """Fetch canonical strategy for a given vulnerability class."""
        for strat in cls.BUILTIN_STRATEGIES.values():
            if strat.vulnerability_class == vuln_class:
                return strat

        # Fallback default strategy
        return cls.BUILTIN_STRATEGIES["STRAT-SEC-HDR-01"]

    @classmethod
    def get_all_strategies(cls) -> List[VerificationStrategyDTO]:
        """Return all built-in strategies as DTOs."""
        return list(cls.BUILTIN_STRATEGIES.values())

    @classmethod
    def validate_strategy_feasibility(
        cls,
        strategy: VerificationStrategyDTO,
        remaining_budget: int,
        target_url: str,
        http_method: str = "GET",
    ) -> StrategyValidationResult:
        """Validate if a strategy is safe, in-scope, and executable within budget."""
        # 1. Concrete target validation
        if not target_url or "*" in target_url or target_url.strip() == "":
            return StrategyValidationResult(
                is_valid=False,
                status="BLOCKED_SCOPE",
                reason="Wildcard or empty target URLs are strictly forbidden from execution.",
                required_requests=strategy.request_budget,
                allowed_methods=strategy.allowed_methods,
            )

        # 2. HTTP Method restriction
        method_upper = http_method.upper()
        if method_upper not in LOCKED_ALLOWED_METHODS or method_upper not in strategy.allowed_methods:
            return StrategyValidationResult(
                is_valid=False,
                status="BLOCKED_METHOD",
                reason=f"HTTP method '{method_upper}' is not permitted for strategy '{strategy.strategy_id}'. Allowed: {strategy.allowed_methods}",
                required_requests=strategy.request_budget,
                allowed_methods=strategy.allowed_methods,
            )

        # 3. Budget headroom validation
        if remaining_budget < strategy.request_budget:
            return StrategyValidationResult(
                is_valid=False,
                status="BLOCKED_BUDGET",
                reason=f"Insufficient budget: strategy requires {strategy.request_budget} requests, but only {remaining_budget} remain.",
                required_requests=strategy.request_budget,
                allowed_methods=strategy.allowed_methods,
            )

        # 4. Strategy budget hard ceiling (<= 10)
        if strategy.request_budget > LOCKED_MAX_STRATEGY_BUDGET:
            return StrategyValidationResult(
                is_valid=False,
                status="BLOCKED_SAFETY",
                reason=f"Strategy budget {strategy.request_budget} exceeds maximum production cap of {LOCKED_MAX_STRATEGY_BUDGET}.",
                required_requests=strategy.request_budget,
                allowed_methods=strategy.allowed_methods,
            )

        return StrategyValidationResult(
            is_valid=True,
            status="VALID",
            reason="Strategy verified for safe execution within production budget.",
            required_requests=strategy.request_budget,
            allowed_methods=strategy.allowed_methods,
        )

    @classmethod
    def check_feasibility(
        cls,
        strategy: VerificationStrategyDTO,
        target_url: str = "",
        campaign_budget_remaining: int = 10,
        remaining_budget: Optional[int] = None,
        method: str = "GET",
        http_method: Optional[str] = None,
        **kwargs: Any,
    ) -> StrategyValidationResult:
        rem_budget = remaining_budget if remaining_budget is not None else campaign_budget_remaining
        m = http_method if http_method is not None else method
        return cls.validate_strategy_feasibility(strategy, rem_budget, target_url, m)

    @staticmethod
    def _record_to_dto(rec: VerificationStrategyRecord) -> VerificationStrategyDTO:
        prereqs = json.loads(rec.prerequisite_evidence) if rec.prerequisite_evidence else []
        methods = json.loads(rec.allowed_methods) if rec.allowed_methods else ["GET"]
        expected = json.loads(rec.expected_observations) if rec.expected_observations else []
        success = json.loads(rec.success_conditions) if rec.success_conditions else []
        failure = json.loads(rec.failure_conditions) if rec.failure_conditions else []
        inconcl = json.loads(rec.inconclusive_conditions) if rec.inconclusive_conditions else []
        safety = json.loads(rec.safety_constraints) if rec.safety_constraints else []

        return VerificationStrategyDTO(
            strategy_id=rec.strategy_id,
            vulnerability_class=rec.vulnerability_class,
            prerequisite_evidence=prereqs,
            request_budget=rec.request_budget,
            allowed_methods=methods,
            expected_observations=expected,
            success_conditions=success,
            failure_conditions=failure,
            inconclusive_conditions=inconcl,
            safety_constraints=safety,
            created_at=rec.created_at.isoformat() if hasattr(rec.created_at, "isoformat") else str(rec.created_at),
        )
