"""AihaX Phase 23 — Validation Plan Builder.

Transforms correlated vulnerability hypotheses into bounded, deterministic,
multi-step validation plans adhering to hard production safety limits.

Security Invariants:
1. All plans default to authorization_status = 'HUMAN_REVIEW_REQUIRED' and status = 'DRAFT'.
2. Live request budget is strictly capped to <= 10 requests (preferred 2-5 steps).
3. HTTP methods are restricted strictly to {'GET', 'HEAD', 'OPTIONS'}; zero mutation methods.
4. Each step defines explicit expected observations, success conditions, and stopping conditions.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from backend.models.database import (
    ValidationPlanRecord,
    ValidationPlanStepRecord,
    get_utc_now,
)

logger = logging.getLogger("aihax.validation_plan")

LOCKED_ALLOWED_METHODS = ["GET", "HEAD", "OPTIONS"]
MAX_PLAN_REQUESTS = 10


@dataclass
class ValidationPlanStepDTO:
    id: str
    validation_plan_id: str
    step_number: int
    method: str
    endpoint: str
    request_template: Dict[str, Any]
    prerequisite_step: Optional[int]
    expected_observation: str
    success_condition: str
    failure_condition: str
    request_cost: int = 1
    status: str = "PENDING"
    created_at: str = field(default_factory=lambda: get_utc_now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationPlanDTO:
    id: str
    campaign_id: str
    hypothesis_id: str
    target: str
    plan_version: str
    steps: List[ValidationPlanStepDTO]
    estimated_requests: int
    allowed_methods: List[str]
    success_conditions: List[str]
    failure_conditions: List[str]
    inconclusive_conditions: List[str]
    safety_constraints: Dict[str, Any]
    authorization_status: str = "HUMAN_REVIEW_REQUIRED"
    status: str = "DRAFT"
    operator_approval_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: get_utc_now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "campaign_id": self.campaign_id,
            "hypothesis_id": self.hypothesis_id,
            "target": self.target,
            "plan_version": self.plan_version,
            "steps": [s.to_dict() for s in self.steps],
            "estimated_requests": self.estimated_requests,
            "allowed_methods": self.allowed_methods,
            "success_conditions": self.success_conditions,
            "failure_conditions": self.failure_conditions,
            "inconclusive_conditions": self.inconclusive_conditions,
            "safety_constraints": self.safety_constraints,
            "authorization_status": self.authorization_status,
            "status": self.status,
            "operator_approval_id": self.operator_approval_id,
            "created_at": self.created_at,
        }


class ValidationPlanBuilder:
    """Constructs bounded, deterministic multi-step validation plans for Phase 23."""

    @classmethod
    def build_plan(
        cls,
        hypothesis: Any,
        campaign_id: str,
        target: str,
        db: Optional[Session] = None,
    ) -> ValidationPlanDTO:
        """Construct a bounded 2-5 step validation plan from a vulnerability hypothesis."""
        hyp_dict = hypothesis.to_dict() if hasattr(hypothesis, "to_dict") else (hypothesis if isinstance(hypothesis, dict) else {})
        hyp_id = hyp_dict.get("hypothesis_id") or hyp_dict.get("id") or "HYP-UNKNOWN"
        endpoint = hyp_dict.get("endpoint") or "/"
        vuln_class = (hyp_dict.get("vulnerability_class") or "GENERAL").upper()
        clean_target = target.strip()

        plan_id = f"PLAN-{hashlib.sha256(f'{campaign_id}:{hyp_id}:{clean_target}'.encode()).hexdigest()[:16]}"
        steps: List[ValidationPlanStepDTO] = []

        # Step 1: Baseline Request
        s1_id = f"STEP-{plan_id}-1"
        s1 = ValidationPlanStepDTO(
            id=s1_id,
            validation_plan_id=plan_id,
            step_number=1,
            method="GET",
            endpoint=endpoint,
            request_template={"headers": {"Accept": "*/*"}},
            prerequisite_step=None,
            expected_observation=f"Baseline HTTP 200/403 response for '{endpoint}'",
            success_condition="status_code in [200, 301, 302, 401, 403, 404]",
            failure_condition="status_code >= 500 or status_code == 0",
            request_cost=1,
        )
        steps.append(s1)

        # Step 2: Controlled Probe Request
        s2_id = f"STEP-{plan_id}-2"
        probe_template: Dict[str, Any] = {"headers": {"Accept": "*/*"}}
        if "CORS" in vuln_class:
            probe_template["headers"]["Origin"] = "https://evil.example.com"
        elif "OPEN_REDIRECT" in vuln_class:
            param_key = hyp_dict.get("parameter") or "redirect_uri"
            endpoint = f"{endpoint}?{param_key}=https://evil.example.com"
        elif "IDOR" in vuln_class or "BOLA" in vuln_class:
            param_key = hyp_dict.get("parameter") or "id"
            endpoint = f"{endpoint}?{param_key}=9999999"

        s2 = ValidationPlanStepDTO(
            id=s2_id,
            validation_plan_id=plan_id,
            step_number=2,
            method="GET",
            endpoint=endpoint,
            request_template=probe_template,
            prerequisite_step=1,
            expected_observation=f"Differential response indicating {vuln_class} vulnerability condition",
            success_condition="comparison_verdict == 'SECURITY_RELEVANT_DIFFERENCE'",
            failure_condition="status_code in [401, 403, 404] or comparison_verdict == 'SAME'",
            request_cost=1,
        )
        steps.append(s2)

        # Step 3: Confirmation / Reproducibility Check
        s3_id = f"STEP-{plan_id}-3"
        s3 = ValidationPlanStepDTO(
            id=s3_id,
            validation_plan_id=plan_id,
            step_number=3,
            method="GET",
            endpoint=endpoint,
            request_template=probe_template,
            prerequisite_step=2,
            expected_observation="Independent reproduction confirming identical differential result",
            success_condition="reproduction_score >= 0.8",
            failure_condition="reproduction_score < 0.5",
            request_cost=1,
        )
        steps.append(s3)

        estimated_reqs = min(len(steps), MAX_PLAN_REQUESTS)
        safety_constraints = {
            "max_concurrency": 1,
            "rate_limit_rps": 2.0,
            "max_requests": estimated_reqs,
            "allowed_methods": LOCKED_ALLOWED_METHODS,
            "strict_destination_safety": True,
        }

        plan_dto = ValidationPlanDTO(
            id=plan_id,
            campaign_id=campaign_id,
            hypothesis_id=hyp_id,
            target=clean_target,
            plan_version="1.0.0-phase23",
            steps=steps,
            estimated_requests=estimated_reqs,
            allowed_methods=LOCKED_ALLOWED_METHODS,
            success_conditions=["All planned steps demonstrate security-relevant differential and reproduce."],
            failure_conditions=["Target enforces defenses (HTTP 401/403) or identical baseline."],
            inconclusive_conditions=["HTTP 500 server error, 429 rate limit, or transport timeout."],
            safety_constraints=safety_constraints,
            authorization_status="HUMAN_REVIEW_REQUIRED",
            status="DRAFT",
        )

        if db:
            cls.persist_plan(plan_dto, db)

        return plan_dto

    @classmethod
    def persist_plan(cls, plan_dto: ValidationPlanDTO, db: Session) -> ValidationPlanRecord:
        """Persist validation plan and its steps to database."""
        existing = db.query(ValidationPlanRecord).filter_by(id=plan_dto.id).first()
        if existing:
            existing.status = plan_dto.status
            existing.authorization_status = plan_dto.authorization_status
            existing.operator_approval_id = plan_dto.operator_approval_id
            db.commit()
            return existing

        plan_rec = ValidationPlanRecord(
            id=plan_dto.id,
            campaign_id=plan_dto.campaign_id,
            hypothesis_id=plan_dto.hypothesis_id,
            target=plan_dto.target,
            plan_version=plan_dto.plan_version,
            steps_json=json.dumps([s.to_dict() for s in plan_dto.steps]),
            estimated_requests=plan_dto.estimated_requests,
            allowed_methods=json.dumps(plan_dto.allowed_methods),
            success_conditions=json.dumps(plan_dto.success_conditions),
            failure_conditions=json.dumps(plan_dto.failure_conditions),
            inconclusive_conditions=json.dumps(plan_dto.inconclusive_conditions),
            safety_constraints=json.dumps(plan_dto.safety_constraints),
            authorization_status=plan_dto.authorization_status,
            status=plan_dto.status,
            operator_approval_id=plan_dto.operator_approval_id,
        )
        db.add(plan_rec)

        for step in plan_dto.steps:
            step_rec = ValidationPlanStepRecord(
                id=step.id,
                validation_plan_id=step.validation_plan_id,
                step_number=step.step_number,
                method=step.method,
                endpoint=step.endpoint,
                request_template=json.dumps(step.request_template),
                prerequisite_step=step.prerequisite_step,
                expected_observation=step.expected_observation,
                success_condition=step.success_condition,
                failure_condition=step.failure_condition,
                request_cost=step.request_cost,
                status=step.status,
            )
            db.add(step_rec)

        db.commit()
        return plan_rec

    @classmethod
    def get_plan_by_id(cls, plan_id: str, db: Session) -> Optional[ValidationPlanDTO]:
        """Fetch validation plan and steps by ID."""
        rec = db.query(ValidationPlanRecord).filter_by(id=plan_id).first()
        if not rec:
            return None
        return cls._record_to_dto(rec, db)

    @classmethod
    def get_plans_for_campaign(cls, campaign_id: str, db: Session) -> List[ValidationPlanDTO]:
        """Fetch all validation plans for a campaign."""
        recs = db.query(ValidationPlanRecord).filter_by(campaign_id=campaign_id).all()
        return [cls._record_to_dto(r, db) for r in recs]

    @classmethod
    def _record_to_dto(cls, rec: ValidationPlanRecord, db: Session) -> ValidationPlanDTO:
        step_recs = (
            db.query(ValidationPlanStepRecord)
            .filter_by(validation_plan_id=rec.id)
            .order_by(ValidationPlanStepRecord.step_number.asc())
            .all()
        )
        steps = [
            ValidationPlanStepDTO(
                id=s.id,
                validation_plan_id=s.validation_plan_id,
                step_number=s.step_number,
                method=s.method,
                endpoint=s.endpoint,
                request_template=json.loads(s.request_template) if s.request_template else {},
                prerequisite_step=s.prerequisite_step,
                expected_observation=s.expected_observation or "",
                success_condition=s.success_condition or "",
                failure_condition=s.failure_condition or "",
                request_cost=s.request_cost,
                status=s.status,
                created_at=s.created_at.isoformat() if hasattr(s.created_at, "isoformat") else str(s.created_at),
            )
            for s in step_recs
        ]

        allowed_methods = json.loads(rec.allowed_methods) if rec.allowed_methods else LOCKED_ALLOWED_METHODS
        success_conds = json.loads(rec.success_conditions) if rec.success_conditions else []
        failure_conds = json.loads(rec.failure_conditions) if rec.failure_conditions else []
        inconcl_conds = json.loads(rec.inconclusive_conditions) if rec.inconclusive_conditions else []
        safety_c = json.loads(rec.safety_constraints) if rec.safety_constraints else {}

        return ValidationPlanDTO(
            id=rec.id,
            campaign_id=rec.campaign_id,
            hypothesis_id=rec.hypothesis_id,
            target=rec.target,
            plan_version=rec.plan_version,
            steps=steps,
            estimated_requests=rec.estimated_requests,
            allowed_methods=allowed_methods,
            success_conditions=success_conds,
            failure_conditions=failure_conds,
            inconclusive_conditions=inconcl_conds,
            safety_constraints=safety_c,
            authorization_status=rec.authorization_status,
            status=rec.status,
            operator_approval_id=rec.operator_approval_id,
            created_at=rec.created_at.isoformat() if hasattr(rec.created_at, "isoformat") else str(rec.created_at),
        )
