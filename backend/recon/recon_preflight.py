"""AihaX Reconnaissance Preflight Safety & Authorization Gate.

Fails closed unless all required preconditions (mode, target concreteness,
authorization, scope, anti-SSRF destination safety, budgets, operator confirmation)
are strictly satisfied before any reconnaissance provider executes.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from backend.core.scope_validator import ScopeValidator, normalize_domain, validate_destination_safety
from backend.recon.recon_modes import ReconContext, ReconExecutionMode

logger = logging.getLogger("aihax.recon_preflight")


class PreflightStatus(str, Enum):
    """Authoritative decision statuses returned by ReconPreflightGate."""
    READY = "READY"
    BLOCKED_AUTHORIZATION = "BLOCKED_AUTHORIZATION"
    BLOCKED_SCOPE = "BLOCKED_SCOPE"
    BLOCKED_SAFETY = "BLOCKED_SAFETY"
    BLOCKED_BUDGET = "BLOCKED_BUDGET"
    BLOCKED_MODE = "BLOCKED_MODE"
    BLOCKED_TARGET = "BLOCKED_TARGET"
    BLOCKED_PROVIDER = "BLOCKED_PROVIDER"


# Approved providers allowlist
APPROVED_PROVIDERS: Set[str] = {
    "subfinder",
    "amass",
    "sublist3r",
    "crtsh",
    "dns_recon",
    "http_probe",
    "tech_fingerprint",
    "endpoint_discovery",
    "scoped_wordlist",
}


@dataclass
class ReconPreflightDecision:
    """Evaluation result from ReconPreflightGate."""
    status: PreflightStatus
    allowed: bool
    reasons: List[str] = field(default_factory=list)
    target: str = ""
    normalized_target: str = ""
    execution_mode: str = ReconExecutionMode.AUDIT.value
    approved_providers: List[str] = field(default_factory=list)
    blocked_providers: List[str] = field(default_factory=list)
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "allowed": self.allowed,
            "reasons": self.reasons,
            "target": self.target,
            "normalized_target": self.normalized_target,
            "execution_mode": self.execution_mode,
            "approved_providers": self.approved_providers,
            "blocked_providers": self.blocked_providers,
            "evaluated_at": self.evaluated_at,
            "warnings": self.warnings,
        }


class ReconPreflightGate:
    """Preflight safety gate that evaluates targets, authorizations, and policies before recon."""

    @classmethod
    def evaluate(
        cls,
        context: ReconContext,
        scope_validator: ScopeValidator,
        requested_providers: Optional[List[str]] = None,
    ) -> ReconPreflightDecision:
        reasons: List[str] = []
        warnings: List[str] = []
        target = (context.target or "").strip()

        # 1. Target Validation: Non-empty and concrete (strictly NO wildcards)
        if not target or "," in target or " " in target:
            return ReconPreflightDecision(
                status=PreflightStatus.BLOCKED_TARGET,
                allowed=False,
                reasons=["Target must be a non-empty, single concrete host or URL."],
                target=target,
                execution_mode=context.execution_mode.value,
            )

        if "*" in target:
            return ReconPreflightDecision(
                status=PreflightStatus.BLOCKED_TARGET,
                allowed=False,
                reasons=[f"Target '{target}' contains wildcards; a concrete execution target is strictly required."],
                target=target,
                execution_mode=context.execution_mode.value,
            )

        try:
            parsed = urlparse(target if "://" in target else f"https://{target}")
            norm_target = parsed.hostname or normalize_domain(target)
        except Exception as e:
            return ReconPreflightDecision(
                status=PreflightStatus.BLOCKED_TARGET,
                allowed=False,
                reasons=[f"Failed to normalize target '{target}': {str(e)}"],
                target=target,
                execution_mode=context.execution_mode.value,
            )

        # 2. Execution Mode Validation
        if context.execution_mode not in (
            ReconExecutionMode.AUDIT,
            ReconExecutionMode.DRY_RUN,
            ReconExecutionMode.AUTHORIZED_LIVE_RECON,
        ):
            return ReconPreflightDecision(
                status=PreflightStatus.BLOCKED_MODE,
                allowed=False,
                reasons=[f"Invalid or unrecognized recon execution mode: '{context.execution_mode}'."],
                target=target,
                normalized_target=norm_target,
                execution_mode=str(context.execution_mode),
            )

        target_url = f"{parsed.scheme or 'https'}://{norm_target}"

        # 3. Destination Safety (Anti-SSRF, RFC1918, Cloud Metadata)
        is_safe, safety_reason = validate_destination_safety(
            target_url,
            allowed_ports=set(context.allowed_ports) if context.allowed_ports else None,
        )
        if not is_safe:
            return ReconPreflightDecision(
                status=PreflightStatus.BLOCKED_SAFETY,
                allowed=False,
                reasons=[f"Target '{target_url}' blocked by Destination Safety (Anti-SSRF): {safety_reason}"],
                target=target,
                normalized_target=norm_target,
                execution_mode=context.execution_mode.value,
            )

        # 4. ScopeValidator Preflight Gating
        scope_dec = scope_validator.validate_target(target_url)
        if not scope_dec.allowed:
            return ReconPreflightDecision(
                status=PreflightStatus.BLOCKED_SCOPE,
                allowed=False,
                reasons=[f"Target '{target_url}' blocked by ScopeValidator: {scope_dec.reason}"],
                target=target,
                normalized_target=norm_target,
                execution_mode=context.execution_mode.value,
            )

        # 5. Budget Check
        if context.request_budget <= 0:
            return ReconPreflightDecision(
                status=PreflightStatus.BLOCKED_BUDGET,
                allowed=False,
                reasons=[f"Configured request budget is zero or negative ({context.request_budget})."],
                target=target,
                normalized_target=norm_target,
                execution_mode=context.execution_mode.value,
            )

        # 6. Provider Allowlist Check
        providers_to_check = requested_providers or list(APPROVED_PROVIDERS)
        approved: List[str] = []
        blocked: List[str] = []
        for p in providers_to_check:
            p_clean = p.strip().lower()
            if p_clean in APPROVED_PROVIDERS:
                approved.append(p_clean)
            else:
                blocked.append(p_clean)

        if blocked:
            return ReconPreflightDecision(
                status=PreflightStatus.BLOCKED_PROVIDER,
                allowed=False,
                reasons=[f"Requested provider(s) not in approved allowlist: {', '.join(blocked)}"],
                target=target,
                normalized_target=norm_target,
                execution_mode=context.execution_mode.value,
                approved_providers=approved,
                blocked_providers=blocked,
            )

        # 7. AUTHORIZED_LIVE_RECON Preconditions
        if context.execution_mode == ReconExecutionMode.AUTHORIZED_LIVE_RECON:
            if not context.authorization_record_id:
                return ReconPreflightDecision(
                    status=PreflightStatus.BLOCKED_AUTHORIZATION,
                    allowed=False,
                    reasons=["Authorized live recon requires a valid authorization_record_id."],
                    target=target,
                    normalized_target=norm_target,
                    execution_mode=context.execution_mode.value,
                )
            if not context.operator_confirmed:
                return ReconPreflightDecision(
                    status=PreflightStatus.BLOCKED_AUTHORIZATION,
                    allowed=False,
                    reasons=["Authorized live recon requires explicit operator confirmation (human-in-the-loop gate)."],
                    target=target,
                    normalized_target=norm_target,
                    execution_mode=context.execution_mode.value,
                )

        if context.execution_mode == ReconExecutionMode.AUDIT:
            warnings.append("AUDIT mode active: real external providers disabled; deterministic synthetic fixtures will be used.")
        elif context.execution_mode == ReconExecutionMode.DRY_RUN:
            warnings.append("DRY_RUN mode active: inspecting planned commands/requests without execution.")

        return ReconPreflightDecision(
            status=PreflightStatus.READY,
            allowed=True,
            reasons=["All preflight safety, scope, authorization, and policy gates passed."],
            target=target,
            normalized_target=norm_target,
            execution_mode=context.execution_mode.value,
            approved_providers=approved,
            blocked_providers=[],
            warnings=warnings,
        )
