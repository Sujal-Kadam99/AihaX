"""AihaX Phase 23 — Validation Plan Safety Analyzer.

Performs deterministic multi-point safety validation of multi-step validation plans
and individual plan execution steps prior to dispatch.

Security Invariants:
1. Full plan is evaluated before execution starts.
2. Every step is re-validated immediately before dispatch.
3. Fails closed with explicit diagnostic blocking decision codes on any safety violation.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from backend.core.scope_validator import PROHIBITED_PORTS, validate_destination_safety
from backend.models.database import get_utc_now

logger = logging.getLogger("aihax.plan_safety")

LOCKED_ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}
LOCKED_MAX_BUDGET = 10
LOCKED_MAX_CONCURRENCY = 1
LOCKED_MAX_RATE_RPS = 2.0


class ValidationPlanSafetyDecision:
    SAFE = "SAFE"
    BLOCKED_SCOPE = "BLOCKED_SCOPE"
    BLOCKED_AUTHORIZATION = "BLOCKED_AUTHORIZATION"
    BLOCKED_METHOD = "BLOCKED_METHOD"
    BLOCKED_BUDGET = "BLOCKED_BUDGET"
    BLOCKED_RATE = "BLOCKED_RATE"
    BLOCKED_CONCURRENCY = "BLOCKED_CONCURRENCY"
    BLOCKED_DESTINATION = "BLOCKED_DESTINATION"
    BLOCKED_POLICY = "BLOCKED_POLICY"


@dataclass
class ValidationPlanSafetyResultDTO:
    is_safe: bool
    decision: str
    reason: str
    violations: List[str] = field(default_factory=list)
    validated_at: str = field(default_factory=lambda: get_utc_now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ValidationPlanSafetyAnalyzer:
    """Evaluates validation plans and steps against strict production safety constraints."""

    @classmethod
    def analyze_plan(
        cls,
        plan: Any,
        campaign: Optional[Any] = None,
        operator_approval: Optional[Any] = None,
        allow_loopback: bool = False,
    ) -> ValidationPlanSafetyResultDTO:
        """Comprehensive evaluation of a validation plan prior to dispatch."""
        plan_dict = plan.to_dict() if hasattr(plan, "to_dict") else (plan if isinstance(plan, dict) else {})
        target = plan_dict.get("target") or ""
        steps = plan_dict.get("steps") or []
        allowed_methods = set(plan_dict.get("allowed_methods") or ["GET"])
        estimated_reqs = plan_dict.get("estimated_requests", len(steps))
        safety_c = plan_dict.get("safety_constraints") or {}

        violations: List[str] = []

        # 1. Target & Scope Check
        if not target or "*" in target or "://" not in target:
            return ValidationPlanSafetyResultDTO(
                is_safe=False,
                decision=ValidationPlanSafetyDecision.BLOCKED_SCOPE,
                reason=f"Target '{target}' is not a valid single concrete URL. Wildcards fail closed.",
                violations=["Invalid or wildcard target URL."],
            )

        # 2. Destination Safety Check
        dest_safe, dest_err = validate_destination_safety(target, allow_loopback=allow_loopback)
        if not dest_safe:
            return ValidationPlanSafetyResultDTO(
                is_safe=False,
                decision=ValidationPlanSafetyDecision.BLOCKED_DESTINATION,
                reason=f"Destination '{target}' failed safety validation: {dest_err}",
                violations=[dest_err or "Destination prohibited."],
            )

        # 3. Method Whitelist Check
        prohibited_plan_methods = allowed_methods - LOCKED_ALLOWED_METHODS
        if prohibited_plan_methods:
            return ValidationPlanSafetyResultDTO(
                is_safe=False,
                decision=ValidationPlanSafetyDecision.BLOCKED_METHOD,
                reason=f"Plan contains prohibited HTTP methods: {prohibited_plan_methods}. Only GET/HEAD/OPTIONS allowed.",
                violations=[f"Prohibited method: {m}" for m in prohibited_plan_methods],
            )

        for s in steps:
            s_dict = s.to_dict() if hasattr(s, "to_dict") else (s if isinstance(s, dict) else {})
            s_method = (s_dict.get("method") or "GET").upper()
            if s_method not in LOCKED_ALLOWED_METHODS:
                return ValidationPlanSafetyResultDTO(
                    is_safe=False,
                    decision=ValidationPlanSafetyDecision.BLOCKED_METHOD,
                    reason=f"Step '{s_dict.get('id')}' specifies prohibited HTTP method '{s_method}'.",
                    violations=[f"Step method prohibited: {s_method}"],
                )

        # 4. Budget Constraint Check
        if estimated_reqs > LOCKED_MAX_BUDGET or len(steps) > LOCKED_MAX_BUDGET:
            return ValidationPlanSafetyResultDTO(
                is_safe=False,
                decision=ValidationPlanSafetyDecision.BLOCKED_BUDGET,
                reason=f"Plan estimated requests ({estimated_reqs}) exceeds maximum limit ({LOCKED_MAX_BUDGET}).",
                violations=["Request count exceeds budget lock of 10."],
            )

        # 5. Concurrency & Rate Limit Check
        concurrency = safety_c.get("max_concurrency", 1)
        rate_rps = safety_c.get("rate_limit_rps", 2.0)
        if concurrency > LOCKED_MAX_CONCURRENCY:
            return ValidationPlanSafetyResultDTO(
                is_safe=False,
                decision=ValidationPlanSafetyDecision.BLOCKED_CONCURRENCY,
                reason=f"Plan concurrency ({concurrency}) exceeds locked maximum ({LOCKED_MAX_CONCURRENCY}).",
                violations=["Concurrency exceeds 1."],
            )
        if rate_rps > LOCKED_MAX_RATE_RPS:
            return ValidationPlanSafetyResultDTO(
                is_safe=False,
                decision=ValidationPlanSafetyDecision.BLOCKED_RATE,
                reason=f"Plan rate limit ({rate_rps} RPS) exceeds locked maximum ({LOCKED_MAX_RATE_RPS} RPS).",
                violations=["Rate limit exceeds 2.0 RPS."],
            )

        # 6. Operator Authorization Check (if provided)
        if operator_approval is not None:
            auth_status = getattr(operator_approval, "status", None) or (
                operator_approval.get("status") if isinstance(operator_approval, dict) else None
            )
            if auth_status not in ("APPROVED", "OPERATOR_APPROVED", "CONFIRMED"):
                return ValidationPlanSafetyResultDTO(
                    is_safe=False,
                    decision=ValidationPlanSafetyDecision.BLOCKED_AUTHORIZATION,
                    reason=f"Operator approval status is '{auth_status}', expected 'APPROVED'.",
                    violations=["Plan requires explicit operator approval."],
                )

        return ValidationPlanSafetyResultDTO(
            is_safe=True,
            decision=ValidationPlanSafetyDecision.SAFE,
            reason="Validation plan passed all safety, method, budget, scope, and destination gates.",
            violations=[],
        )

    @classmethod
    def validate_step_safety(
        cls,
        step: Any,
        target: str,
        remaining_budget: int = 10,
        allow_loopback: bool = False,
    ) -> ValidationPlanSafetyResultDTO:
        """Validate an individual step immediately prior to dispatch."""
        step_dict = step.to_dict() if hasattr(step, "to_dict") else (step if isinstance(step, dict) else {})
        method = (step_dict.get("method") or "GET").upper()
        endpoint = step_dict.get("endpoint") or "/"
        cost = step_dict.get("request_cost", 1)

        # Method check
        if method not in LOCKED_ALLOWED_METHODS:
            return ValidationPlanSafetyResultDTO(
                is_safe=False,
                decision=ValidationPlanSafetyDecision.BLOCKED_METHOD,
                reason=f"Step method '{method}' is prohibited. Only GET, HEAD, OPTIONS allowed.",
                violations=[f"Prohibited method: {method}"],
            )

        # Budget check
        if remaining_budget < cost:
            return ValidationPlanSafetyResultDTO(
                is_safe=False,
                decision=ValidationPlanSafetyDecision.BLOCKED_BUDGET,
                reason=f"Remaining budget ({remaining_budget}) is insufficient for step cost ({cost}).",
                violations=["Insufficient budget."],
            )

        # Full URL construction & destination safety
        clean_target = target.strip().rstrip("/")
        clean_ep = "/" + endpoint.lstrip("/")
        full_url = f"{clean_target}{clean_ep}"

        dest_safe, dest_err = validate_destination_safety(full_url, allow_loopback=allow_loopback)
        if not dest_safe:
            return ValidationPlanSafetyResultDTO(
                is_safe=False,
                decision=ValidationPlanSafetyDecision.BLOCKED_DESTINATION,
                reason=f"Step URL '{full_url}' failed safety check: {dest_err}",
                violations=[dest_err or "Destination prohibited."],
            )

        return ValidationPlanSafetyResultDTO(
            is_safe=True,
            decision=ValidationPlanSafetyDecision.SAFE,
            reason=f"Step '{step_dict.get('id')}' is safe for dispatch.",
            violations=[],
        )
