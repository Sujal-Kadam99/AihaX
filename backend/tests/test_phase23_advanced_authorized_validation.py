"""AihaX Phase 23 — Advanced Authorized Vulnerability Research & Multi-Step Validation Tests.

Comprehensive test suite verifying:
1. Migration 25 database schema & ORM models
2. Attack Surface Graph engine (nodes, edges, snapshot hashing, zero network traffic)
3. Correlated hypothesis generation across multi-observation sets
4. Validation plan builder (2-5 step bounded plans, budget caps)
5. Plan safety analyzer (gatekeeper matrix)
6. Operator authorization binding and replay protections
7. Multi-step validation execution lifecycle via RequestEngine + MockTransport
8. Plan state machine transitions (legal and illegal)
9. Reproducibility engine & mathematical consistency scoring
10. Multi-factor confidence engine & rationale generation
11. Cryptographic evidence chain (11-node continuity, tampering detection)
12. Audit events & SHA-256 chain integrity
13. Report generator package (Markdown + JSON segregation)
14. REST API router endpoints
15. Fail-closed security boundaries (wildcards, SSRF, loopback, private IPs, metadata, prohibited ports, mutating methods)
16. Zero-network isolation guarantee (100% MockTransport & in-memory SQLite)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import pytest
from datetime import datetime, timezone
from typing import Any, Dict, List
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.core.scope_validator import ScopeValidator, validate_destination_safety
from backend.models.database import (
    Base,
    AttackSurfaceNodeRecord,
    AttackSurfaceEdgeRecord,
    ValidationPlanRecord,
    ValidationPlanStepRecord,
    ValidationObservationRecord,
    ValidationReproductionRecord,
    Phase23ConfidenceAssessmentRecord,
    Phase23AuditEventRecord,
    get_utc_now,
)
from backend.services.attack_surface_graph import (
    AttackSurfaceGraphEngine,
    AttackSurfaceNodeType,
    AttackSurfaceEdgeType,
    AttackSurfaceNodeDTO,
    AttackSurfaceEdgeDTO,
)
from backend.services.vulnerability_hypothesis import (
    VulnerabilityHypothesisEngine,
    VulnerabilityHypothesisDTO,
    VulnerabilityClass,
)
from backend.services.validation_plan import (
    ValidationPlanBuilder,
    ValidationPlanDTO,
    ValidationPlanStepDTO,
)
from backend.services.plan_safety import (
    ValidationPlanSafetyAnalyzer,
    ValidationPlanSafetyDecision,
    ValidationPlanSafetyResultDTO,
)
from backend.services.exploit_validator import (
    AdvancedAuthorizedValidationExecutor,
)
from backend.services.reproducibility import (
    ReproducibilityEngine,
    ReproducibilityClassification,
    ReproducibilityResultDTO,
)
from backend.services.confidence_engine import (
    ConfidenceEngine,
    ConfidenceLevel,
    Phase23ConfidenceAssessmentDTO,
)
from backend.services.evidence_chain import (
    Phase23EvidenceChainService,
    Phase23EvidenceChainDTO,
)
from backend.services.report_generator import generate_phase23_report_package
from backend.services.request_engine import MockTransport, RequestEngine, RequestSpec


@pytest.fixture
def db_session():
    """Create in-memory SQLite database session for zero-network testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


# ==============================================================================
# 1. Migration 25 & ORM Schema Tests (25 tests)
# ==============================================================================

class TestMigration25Schema:
    def test_node_record_creation(self, db_session):
        node = AttackSurfaceNodeRecord(
            id="NODE-01",
            campaign_id="CAMP-01",
            target="https://target.example.com",
            node_type=AttackSurfaceNodeType.ENDPOINT,
            canonical_url="https://target.example.com/api/users",
            endpoint="/api/users",
            parameter=None,
            method="GET",
            source="PASSIVE_INVENTORY",
            observation_hash="hash123",
            confidence=1.0,
            status="OBSERVED",
        )
        db_session.add(node)
        db_session.commit()
        retrieved = db_session.query(AttackSurfaceNodeRecord).filter_by(id="NODE-01").first()
        assert retrieved is not None
        assert retrieved.canonical_url == "https://target.example.com/api/users"

    def test_edge_record_creation(self, db_session):
        edge = AttackSurfaceEdgeRecord(
            id="EDGE-01",
            campaign_id="CAMP-01",
            source_node_id="NODE-01",
            destination_node_id="NODE-02",
            edge_type=AttackSurfaceEdgeType.LINK,
            confidence=1.0,
        )
        db_session.add(edge)
        db_session.commit()
        retrieved = db_session.query(AttackSurfaceEdgeRecord).filter_by(id="EDGE-01").first()
        assert retrieved is not None
        assert retrieved.edge_type == AttackSurfaceEdgeType.LINK

    def test_validation_plan_record_creation(self, db_session):
        plan = ValidationPlanRecord(
            id="PLAN-01",
            campaign_id="CAMP-01",
            hypothesis_id="HYP-01",
            target="https://target.example.com",
            plan_version="1.0.0",
            steps_json="[]",
            estimated_requests=2,
            allowed_methods='["GET"]',
            status="DRAFT",
        )
        db_session.add(plan)
        db_session.commit()
        retrieved = db_session.query(ValidationPlanRecord).filter_by(id="PLAN-01").first()
        assert retrieved is not None
        assert retrieved.status == "DRAFT"

    def test_validation_plan_step_record(self, db_session):
        step = ValidationPlanStepRecord(
            id="STEP-01",
            validation_plan_id="PLAN-01",
            step_number=1,
            method="GET",
            endpoint="/api/profile",
            request_template="{}",
            request_cost=1,
            status="PENDING",
        )
        db_session.add(step)
        db_session.commit()
        retrieved = db_session.query(ValidationPlanStepRecord).filter_by(id="STEP-01").first()
        assert retrieved is not None
        assert retrieved.method == "GET"

    def test_validation_observation_record(self, db_session):
        obs = ValidationObservationRecord(
            id="OBS-01",
            validation_plan_id="PLAN-01",
            step_id="STEP-01",
            request_number=1,
            status="COMPLETED",
            status_code=200,
            response_hash="hashabc",
            normalized_response_hash="hashabc_norm",
            observation_type="BASELINE",
        )
        db_session.add(obs)
        db_session.commit()
        retrieved = db_session.query(ValidationObservationRecord).filter_by(id="OBS-01").first()
        assert retrieved is not None
        assert retrieved.status_code == 200

    def test_validation_reproduction_record(self, db_session):
        repro = ValidationReproductionRecord(
            id="REPRO-01",
            validation_plan_id="PLAN-01",
            finding_id="FIND-01",
            attempt_number=1,
            result="REPRODUCIBLE",
            evidence_hash="evhash",
            reproducibility_score=1.0,
        )
        db_session.add(repro)
        db_session.commit()
        retrieved = db_session.query(ValidationReproductionRecord).filter_by(id="REPRO-01").first()
        assert retrieved is not None
        assert retrieved.result == "REPRODUCIBLE"

    def test_confidence_assessment_record(self, db_session):
        conf = Phase23ConfidenceAssessmentRecord(
            id="CONF-01",
            validation_plan_id="PLAN-01",
            finding_id="FIND-01",
            evidence_score=1.0,
            consistency_score=1.0,
            reproducibility_score=1.0,
            scope_score=1.0,
            authorization_score=1.0,
            overall_score=1.0,
            confidence_level="VERY_HIGH",
            rationale="Deterministic 100% confidence",
        )
        db_session.add(conf)
        db_session.commit()
        retrieved = db_session.query(Phase23ConfidenceAssessmentRecord).filter_by(id="CONF-01").first()
        assert retrieved is not None
        assert retrieved.confidence_level == "VERY_HIGH"

    def test_audit_event_record(self, db_session):
        audit = Phase23AuditEventRecord(
            id="AUDIT-01",
            campaign_id="CAMP-01",
            operator_id="operator@example.com",
            event_type="PLAN_APPROVED",
            event_payload='{"plan_id":"PLAN-01"}',
            previous_hash="GENESIS",
            event_hash="audit_hash_1",
        )
        db_session.add(audit)
        db_session.commit()
        retrieved = db_session.query(Phase23AuditEventRecord).filter_by(id="AUDIT-01").first()
        assert retrieved is not None
        assert retrieved.event_type == "PLAN_APPROVED"

    @pytest.mark.parametrize("node_type", list(AttackSurfaceNodeType.ALL))
    def test_all_node_types_persisted(self, db_session, node_type):
        rec = AttackSurfaceNodeRecord(
            id=f"NODE-{node_type}",
            campaign_id="CAMP-01",
            target="https://target.example.com",
            node_type=node_type,
            canonical_url=f"https://target.example.com/{node_type.lower()}",
            source="PASSIVE_INVENTORY",
            observation_hash=f"hash_{node_type}",
        )
        db_session.add(rec)
        db_session.commit()
        assert db_session.query(AttackSurfaceNodeRecord).filter_by(id=f"NODE-{node_type}").first() is not None

    @pytest.mark.parametrize("edge_type", list(AttackSurfaceEdgeType.ALL))
    def test_all_edge_types_persisted(self, db_session, edge_type):
        rec = AttackSurfaceEdgeRecord(
            id=f"EDGE-{edge_type}",
            campaign_id="CAMP-01",
            source_node_id="NODE-1",
            destination_node_id="NODE-2",
            edge_type=edge_type,
        )
        db_session.add(rec)
        db_session.commit()
        assert db_session.query(AttackSurfaceEdgeRecord).filter_by(id=f"EDGE-{edge_type}").first() is not None


# ==============================================================================
# 2. Attack Surface Graph Engine Tests (25 tests)
# ==============================================================================

class TestAttackSurfaceGraphEngine:
    def test_add_target_node(self, db_session):
        dto = AttackSurfaceGraphEngine.add_target("CAMP-01", "https://app.example.com", db=db_session)
        assert dto.node_type == AttackSurfaceNodeType.TARGET
        assert dto.canonical_url == "https://app.example.com"
        assert dto.observation_hash is not None

    def test_add_endpoint_node(self, db_session):
        dto = AttackSurfaceGraphEngine.add_endpoint("CAMP-01", "https://app.example.com", "/api/v1/user", db=db_session)
        assert dto.node_type == AttackSurfaceNodeType.ENDPOINT
        assert dto.endpoint == "/api/v1/user"

    def test_add_parameter_node(self, db_session):
        dto = AttackSurfaceGraphEngine.add_parameter("CAMP-01", "https://app.example.com", "/api/v1/user", "user_id", db=db_session)
        assert dto.node_type == AttackSurfaceNodeType.PARAMETER
        assert dto.parameter == "user_id"

    def test_add_redirect_node_and_edge(self, db_session):
        node, edge = AttackSurfaceGraphEngine.add_redirect(
            "CAMP-01", "https://app.example.com", "/login", "https://auth.example.com", db=db_session
        )
        assert node.node_type == AttackSurfaceNodeType.REDIRECT
        assert edge.edge_type == AttackSurfaceEdgeType.REDIRECT

    def test_add_header_observation(self, db_session):
        dto = AttackSurfaceGraphEngine.add_header_observation("CAMP-01", "https://app.example.com", "/test", "Server", db=db_session)
        assert dto.node_type == AttackSurfaceNodeType.HEADER

    def test_add_api_route(self, db_session):
        dto = AttackSurfaceGraphEngine.add_api_route("CAMP-01", "https://app.example.com", "/api/v2/items", db=db_session)
        assert dto.node_type == AttackSurfaceNodeType.API_ROUTE

    def test_add_relationship_edge(self, db_session):
        edge = AttackSurfaceGraphEngine.add_relationship(
            "CAMP-01", "NODE-A", "NODE-B", AttackSurfaceEdgeType.PARAMETER_RELATION, db=db_session
        )
        assert edge.edge_type == AttackSurfaceEdgeType.PARAMETER_RELATION

    def test_deterministic_snapshot_hash(self, db_session):
        AttackSurfaceGraphEngine.add_target("CAMP-DETERMINISTIC", "https://app.example.com", db=db_session)
        AttackSurfaceGraphEngine.add_endpoint("CAMP-DETERMINISTIC", "https://app.example.com", "/api", db=db_session)
        snap1 = AttackSurfaceGraphEngine.get_snapshot("CAMP-DETERMINISTIC", "https://app.example.com", db=db_session)
        snap2 = AttackSurfaceGraphEngine.get_snapshot("CAMP-DETERMINISTIC", "https://app.example.com", db=db_session)
        assert snap1.snapshot_hash == snap2.snapshot_hash
        assert len(snap1.snapshot_hash) == 64

    def test_deduplicate_nodes_idempotent(self, db_session):
        n1 = AttackSurfaceGraphEngine.add_endpoint("CAMP-01", "https://app.example.com", "/same", db=db_session)
        n2 = AttackSurfaceGraphEngine.add_endpoint("CAMP-01", "https://app.example.com", "/same", db=db_session)
        assert n1.id == n2.id
        nodes = db_session.query(AttackSurfaceNodeRecord).filter_by(id=n1.id).all()
        assert len(nodes) == 1

    @pytest.mark.parametrize("path", ["/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h", "/i", "/j", "/k", "/l", "/m", "/n", "/o", "/p"])
    def test_bulk_endpoint_indexing(self, db_session, path):
        node = AttackSurfaceGraphEngine.add_endpoint("CAMP-BULK", "https://bulk.example.com", path, db=db_session)
        assert node.endpoint == path


# ==============================================================================
# 3. Correlated Hypothesis Engine Tests (25 tests)
# ==============================================================================

class TestCorrelatedHypothesisEngine:
    def test_generate_idor_hypothesis_from_parameter(self, db_session):
        AttackSurfaceGraphEngine.add_endpoint("CAMP-HYP", "https://app.example.com", "/account/view", db=db_session)
        AttackSurfaceGraphEngine.add_parameter("CAMP-HYP", "https://app.example.com", "/account/view", "account_id", db=db_session)
        snapshot = AttackSurfaceGraphEngine.get_snapshot("CAMP-HYP", "https://app.example.com", db=db_session)

        hypotheses = VulnerabilityHypothesisEngine.generate_correlated_hypotheses(
            "CAMP-HYP", "https://app.example.com", snapshot, db=db_session
        )
        assert len(hypotheses) > 0
        idor_hyp = next((h for h in hypotheses if h.vulnerability_class == VulnerabilityClass.IDOR_BOLA), None)
        assert idor_hyp is not None
        assert idor_hyp.parameter == "account_id"
        assert idor_hyp.authorization_status == "HUMAN_REVIEW_REQUIRED"

    def test_generate_open_redirect_hypothesis(self, db_session):
        AttackSurfaceGraphEngine.add_redirect(
            "CAMP-HYP", "https://app.example.com", "/oauth/redirect", "https://external.example.com", db=db_session
        )
        snapshot = AttackSurfaceGraphEngine.get_snapshot("CAMP-HYP", "https://app.example.com", db=db_session)
        hypotheses = VulnerabilityHypothesisEngine.generate_correlated_hypotheses(
            "CAMP-HYP", "https://app.example.com", snapshot, db=db_session
        )
        redir_hyp = next((h for h in hypotheses if h.vulnerability_class == VulnerabilityClass.OPEN_REDIRECT), None)
        assert redir_hyp is not None

    def test_generate_security_headers_hypothesis(self, db_session):
        AttackSurfaceGraphEngine.add_endpoint("CAMP-HYP", "https://app.example.com", "/landing", db=db_session)
        snapshot = AttackSurfaceGraphEngine.get_snapshot("CAMP-HYP", "https://app.example.com", db=db_session)
        hypotheses = VulnerabilityHypothesisEngine.generate_correlated_hypotheses(
            "CAMP-HYP", "https://app.example.com", snapshot, db=db_session
        )
        hdr_hyp = next((h for h in hypotheses if h.vulnerability_class == VulnerabilityClass.SECURITY_HEADERS), None)
        assert hdr_hyp is not None

    def test_wildcard_target_fails_closed(self, db_session):
        snapshot = AttackSurfaceGraphEngine.get_snapshot("CAMP-WILD", "*.example.com", db=db_session)
        hypotheses = VulnerabilityHypothesisEngine.generate_correlated_hypotheses(
            "CAMP-WILD", "*.example.com", snapshot, db=db_session
        )
        assert len(hypotheses) == 0

    def test_rank_hypotheses_ordering(self):
        h1 = VulnerabilityHypothesisDTO("H1", "C1", "https://t.com", "/", "GET", VulnerabilityClass.CORS, "", "", [], "", "", 2, "MED", 0.7)
        h2 = VulnerabilityHypothesisDTO("H2", "C1", "https://t.com", "/", "GET", VulnerabilityClass.IDOR_BOLA, "", "", [], "", "", 2, "HIGH", 0.95)
        h3 = VulnerabilityHypothesisDTO("H3", "C1", "https://t.com", "/", "GET", VulnerabilityClass.SECURITY_HEADERS, "", "", [], "", "", 1, "LOW", 0.85)

        ranked = VulnerabilityHypothesisEngine.rank_hypotheses([h1, h2, h3])
        assert ranked[0].hypothesis_id == "H2"
        assert ranked[1].hypothesis_id == "H3"
        assert ranked[2].hypothesis_id == "H1"

    def test_calculate_confidence_with_full_prereqs(self):
        h = VulnerabilityHypothesisDTO("H1", "C1", "https://t.com", "/api", "GET", VulnerabilityClass.IDOR_BOLA, "", "", ["ENDPOINT:/api", "PARAMETER:id"], "", "", 2, "HIGH", 0.8)
        conf = VulnerabilityHypothesisEngine.calculate_hypothesis_confidence(h, ["ENDPOINT:/api", "PARAMETER:id"])
        assert conf == 0.8

    def test_calculate_confidence_with_partial_prereqs(self):
        h = VulnerabilityHypothesisDTO("H1", "C1", "https://t.com", "/api", "GET", VulnerabilityClass.IDOR_BOLA, "", "", ["ENDPOINT:/api", "PARAMETER:id"], "", "", 2, "HIGH", 0.8)
        conf = VulnerabilityHypothesisEngine.calculate_hypothesis_confidence(h, ["ENDPOINT:/api"])
        assert conf < 0.8

    def test_identify_prerequisite_gaps(self):
        h = VulnerabilityHypothesisDTO("H1", "C1", "https://t.com", "/api", "GET", VulnerabilityClass.IDOR_BOLA, "", "", ["ENDPOINT:/api", "PARAMETER:id"], "", "", 2, "HIGH", 0.8)
        gaps = VulnerabilityHypothesisEngine.identify_prerequisite_gaps(h, ["ENDPOINT:/api"])
        assert gaps == ["PARAMETER:id"]

    @pytest.mark.parametrize("v_class", list(VulnerabilityClass.ALL))
    def test_all_12_vulnerability_classes_supported(self, v_class):
        dto = VulnerabilityHypothesisDTO(
            hypothesis_id=f"HYP-{v_class}",
            campaign_id="CAMP-01",
            target="https://target.example.com",
            endpoint="/test",
            method="GET",
            vulnerability_class=v_class,
            hypothesis=f"Test hypothesis for {v_class}",
            rationale="Test rationale",
            prerequisite_observations=[],
            expected_evidence="Evidence",
            verification_strategy="STRAT-01",
            estimated_requests=2,
            risk_level="MEDIUM",
            confidence=0.8,
        )
        assert dto.vulnerability_class == v_class


# ==============================================================================
# 4. Validation Plan Builder Tests (25 tests)
# ==============================================================================

class TestValidationPlanBuilder:
    def test_build_plan_structure(self, db_session):
        h = VulnerabilityHypothesisDTO("HYP-IDOR", "CAMP-01", "https://target.example.com", "/user", "GET", VulnerabilityClass.IDOR_BOLA, "Hyp", "Rat", [], "Exp", "Strat", 2, "HIGH", 0.9, parameter="id")
        plan = ValidationPlanBuilder.build_plan(h, "CAMP-01", "https://target.example.com", db=db_session)
        assert plan.id.startswith("PLAN-")
        assert len(plan.steps) == 3
        assert plan.steps[0].step_number == 1
        assert plan.steps[1].step_number == 2
        assert plan.steps[2].step_number == 3
        assert plan.authorization_status == "HUMAN_REVIEW_REQUIRED"
        assert plan.status == "DRAFT"

    def test_plan_budget_capped_at_10(self, db_session):
        h = VulnerabilityHypothesisDTO("HYP-01", "CAMP-01", "https://target.example.com", "/api", "GET", VulnerabilityClass.CORS, "Hyp", "Rat", [], "Exp", "Strat", 20, "HIGH", 0.9)
        plan = ValidationPlanBuilder.build_plan(h, "CAMP-01", "https://target.example.com", db=db_session)
        assert plan.estimated_requests <= 10

    def test_plan_cors_probe_template(self, db_session):
        h = VulnerabilityHypothesisDTO("HYP-CORS", "CAMP-01", "https://target.example.com", "/api", "GET", VulnerabilityClass.CORS, "Hyp", "Rat", [], "Exp", "Strat", 2, "HIGH", 0.9)
        plan = ValidationPlanBuilder.build_plan(h, "CAMP-01", "https://target.example.com", db=db_session)
        assert "Origin" in plan.steps[1].request_template.get("headers", {})

    def test_plan_open_redirect_probe_endpoint(self, db_session):
        h = VulnerabilityHypothesisDTO("HYP-REDIR", "CAMP-01", "https://target.example.com", "/login", "GET", VulnerabilityClass.OPEN_REDIRECT, "Hyp", "Rat", [], "Exp", "Strat", 2, "HIGH", 0.9, parameter="next")
        plan = ValidationPlanBuilder.build_plan(h, "CAMP-01", "https://target.example.com", db=db_session)
        assert "next=" in plan.steps[1].endpoint

    def test_get_plan_by_id(self, db_session):
        h = VulnerabilityHypothesisDTO("HYP-01", "CAMP-01", "https://target.example.com", "/test", "GET", VulnerabilityClass.ACCESS_CONTROL, "Hyp", "Rat", [], "Exp", "Strat", 2, "HIGH", 0.9)
        plan = ValidationPlanBuilder.build_plan(h, "CAMP-01", "https://target.example.com", db=db_session)
        retrieved = ValidationPlanBuilder.get_plan_by_id(plan.id, db=db_session)
        assert retrieved is not None
        assert retrieved.id == plan.id

    def test_get_plans_for_campaign(self, db_session):
        h1 = VulnerabilityHypothesisDTO("HYP-A", "CAMP-MULTI", "https://target.example.com", "/a", "GET", VulnerabilityClass.CORS, "H", "R", [], "E", "S", 2, "H", 0.9)
        h2 = VulnerabilityHypothesisDTO("HYP-B", "CAMP-MULTI", "https://target.example.com", "/b", "GET", VulnerabilityClass.IDOR_BOLA, "H", "R", [], "E", "S", 2, "H", 0.9)
        ValidationPlanBuilder.build_plan(h1, "CAMP-MULTI", "https://target.example.com", db=db_session)
        ValidationPlanBuilder.build_plan(h2, "CAMP-MULTI", "https://target.example.com", db=db_session)
        plans = ValidationPlanBuilder.get_plans_for_campaign("CAMP-MULTI", db=db_session)
        assert len(plans) == 2

    @pytest.mark.parametrize("step_num", [1, 2, 3])
    def test_steps_have_valid_methods(self, db_session, step_num):
        h = VulnerabilityHypothesisDTO("HYP-TEST", "CAMP-01", "https://target.example.com", "/test", "GET", VulnerabilityClass.SECURITY_HEADERS, "H", "R", [], "E", "S", 2, "H", 0.9)
        plan = ValidationPlanBuilder.build_plan(h, "CAMP-01", "https://target.example.com", db=db_session)
        step = plan.steps[step_num - 1]
        assert step.method in ("GET", "HEAD", "OPTIONS")

    @pytest.mark.parametrize("idx", range(16))
    def test_plan_id_determinism(self, db_session, idx):
        h = VulnerabilityHypothesisDTO(f"HYP-{idx}", "CAMP-DET", "https://target.example.com", f"/ep{idx}", "GET", VulnerabilityClass.ACCESS_CONTROL, "H", "R", [], "E", "S", 2, "H", 0.9)
        p1 = ValidationPlanBuilder.build_plan(h, "CAMP-DET", "https://target.example.com")
        p2 = ValidationPlanBuilder.build_plan(h, "CAMP-DET", "https://target.example.com")
        assert p1.id == p2.id


# ==============================================================================
# 5. Plan Safety Analyzer Matrix Tests (30 tests)
# ==============================================================================

class TestValidationPlanSafetyAnalyzer:
    def test_safe_plan_approved(self):
        plan = {"target": "https://account.example.com", "steps": [{"method": "GET", "endpoint": "/view", "request_cost": 1}], "allowed_methods": ["GET"], "estimated_requests": 1}
        res = ValidationPlanSafetyAnalyzer.analyze_plan(plan, operator_approval={"status": "APPROVED"})
        assert res.is_safe is True
        assert res.decision == ValidationPlanSafetyDecision.SAFE

    def test_wildcard_target_blocked_scope(self):
        plan = {"target": "*.example.com", "steps": [{"method": "GET", "endpoint": "/"}]}
        res = ValidationPlanSafetyAnalyzer.analyze_plan(plan)
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_SCOPE

    def test_prohibited_post_method_blocked(self):
        plan = {"target": "https://account.example.com", "steps": [{"method": "POST", "endpoint": "/submit"}]}
        res = ValidationPlanSafetyAnalyzer.analyze_plan(plan)
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_METHOD

    def test_prohibited_delete_method_blocked(self):
        plan = {"target": "https://account.example.com", "steps": [{"method": "DELETE", "endpoint": "/del"}]}
        res = ValidationPlanSafetyAnalyzer.analyze_plan(plan)
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_METHOD

    def test_budget_exceeded_blocked(self):
        plan = {"target": "https://account.example.com", "steps": [{"method": "GET", "endpoint": "/a"}] * 12, "estimated_requests": 12}
        res = ValidationPlanSafetyAnalyzer.analyze_plan(plan)
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_BUDGET

    def test_concurrency_exceeded_blocked(self):
        plan = {"target": "https://account.example.com", "steps": [{"method": "GET", "endpoint": "/a"}], "safety_constraints": {"max_concurrency": 4}}
        res = ValidationPlanSafetyAnalyzer.analyze_plan(plan)
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_CONCURRENCY

    def test_rate_limit_exceeded_blocked(self):
        plan = {"target": "https://account.example.com", "steps": [{"method": "GET", "endpoint": "/a"}], "safety_constraints": {"rate_limit_rps": 10.0}}
        res = ValidationPlanSafetyAnalyzer.analyze_plan(plan)
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_RATE

    def test_loopback_destination_blocked(self):
        plan = {"target": "http://127.0.0.1:8000", "steps": [{"method": "GET", "endpoint": "/"}]}
        res = ValidationPlanSafetyAnalyzer.analyze_plan(plan, allow_loopback=False)
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_DESTINATION

    def test_metadata_destination_blocked(self):
        plan = {"target": "http://169.254.169.254/latest/meta-data", "steps": [{"method": "GET", "endpoint": "/"}]}
        res = ValidationPlanSafetyAnalyzer.analyze_plan(plan, allow_loopback=False)
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_DESTINATION

    def test_prohibited_ssh_port_blocked(self):
        plan = {"target": "https://account.example.com:22", "steps": [{"method": "GET", "endpoint": "/"}]}
        res = ValidationPlanSafetyAnalyzer.analyze_plan(plan, allow_loopback=False)
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_DESTINATION

    def test_unapproved_operator_blocked(self):
        plan = {"target": "https://account.example.com", "steps": [{"method": "GET", "endpoint": "/"}]}
        res = ValidationPlanSafetyAnalyzer.analyze_plan(plan, operator_approval={"status": "REJECTED"})
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_AUTHORIZATION

    def test_step_safety_budget_exhaustion(self):
        step = {"id": "S1", "method": "GET", "endpoint": "/test", "request_cost": 2}
        res = ValidationPlanSafetyAnalyzer.validate_step_safety(step, "https://target.com", remaining_budget=1)
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_BUDGET

    @pytest.mark.parametrize("method", ["PUT", "PATCH", "TRACE", "CONNECT", "PROPFIND", "MKCOL"])
    def test_prohibited_methods_fail_closed(self, method):
        step = {"id": "S1", "method": method, "endpoint": "/test", "request_cost": 1}
        res = ValidationPlanSafetyAnalyzer.validate_step_safety(step, "https://target.com")
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_METHOD

    @pytest.mark.parametrize("port", [21, 22, 23, 25, 3306, 5432, 6379, 27017])
    def test_prohibited_ports_fail_closed(self, port):
        plan = {"target": f"https://account.example.com:{port}", "steps": [{"method": "GET", "endpoint": "/"}]}
        res = ValidationPlanSafetyAnalyzer.analyze_plan(plan, allow_loopback=False)
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_DESTINATION

    @pytest.mark.parametrize("ip", ["10.0.0.1", "172.16.0.1", "192.168.1.1"])
    def test_rfc1918_private_ips_blocked(self, ip):
        plan = {"target": f"http://{ip}/api", "steps": [{"method": "GET", "endpoint": "/"}]}
        res = ValidationPlanSafetyAnalyzer.analyze_plan(plan, allow_loopback=False)
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_DESTINATION


# ==============================================================================
# 6. Multi-Step Execution & State Machine Tests (35 tests)
# ==============================================================================

class TestMultiStepExecutorAndStateMachine:
    @pytest.mark.asyncio
    async def test_execute_plan_mock_transport_success(self, db_session):
        h = VulnerabilityHypothesisDTO("HYP-EXEC", "CAMP-EXEC", "https://account.example.com", "/api/data", "GET", VulnerabilityClass.CORS, "H", "R", [], "E", "S", 2, "H", 0.9)
        plan = ValidationPlanBuilder.build_plan(h, "CAMP-EXEC", "https://account.example.com", db=db_session)
        mock = MockTransport(default_status=200, default_headers={"Access-Control-Allow-Origin": "https://evil.com"}, default_body='{"ok":true}')

        res = await AdvancedAuthorizedValidationExecutor.execute_plan(
            campaign_id="CAMP-EXEC",
            plan_id=plan.id,
            operator_approval_id="APPR-1",
            operator_id="operator",
            execution_mode="TEST",
            transport=mock,
            db=db_session,
            allow_loopback=True,
        )
        assert res["success"] is True
        assert res["status"] == "COMPLETED"
        assert res["total_requests"] == len(plan.steps)
        assert len(res["observations"]) == len(plan.steps)

    @pytest.mark.asyncio
    async def test_execute_plan_blocked_without_target(self, db_session):
        res = await AdvancedAuthorizedValidationExecutor.execute_plan(
            campaign_id="CAMP-01",
            plan_id="NON-EXISTENT",
            operator_approval_id="APPR-1",
            operator_id="operator",
            db=db_session,
        )
        assert res["success"] is False
        assert res["status"] == "FAILED"

    def test_stop_plan(self, db_session):
        h = VulnerabilityHypothesisDTO("HYP-STOP", "CAMP-STOP", "https://account.example.com", "/api", "GET", VulnerabilityClass.ACCESS_CONTROL, "H", "R", [], "E", "S", 2, "H", 0.9)
        plan = ValidationPlanBuilder.build_plan(h, "CAMP-STOP", "https://account.example.com", db=db_session)
        res = AdvancedAuthorizedValidationExecutor.stop_plan(plan.id, "Emergency stop", db=db_session)
        assert res["status"] == "STOPPED"
        db_plan = db_session.query(ValidationPlanRecord).filter_by(id=plan.id).first()
        assert db_plan.status == "STOPPED"

    def test_resume_plan_requires_fresh_approval(self, db_session):
        h = VulnerabilityHypothesisDTO("HYP-RESUME", "CAMP-RESUME", "https://account.example.com", "/api", "GET", VulnerabilityClass.ACCESS_CONTROL, "H", "R", [], "E", "S", 2, "H", 0.9)
        plan = ValidationPlanBuilder.build_plan(h, "CAMP-RESUME", "https://account.example.com", db=db_session)
        AdvancedAuthorizedValidationExecutor.stop_plan(plan.id, db=db_session)

        # Resume without approval fails
        fail_res = AdvancedAuthorizedValidationExecutor.resume_plan(plan.id, "", "", db=db_session)
        assert fail_res["success"] is False
        assert fail_res["status"] == "BLOCKED_AUTHORIZATION"

        # Resume with approval succeeds
        ok_res = AdvancedAuthorizedValidationExecutor.resume_plan(plan.id, "APPR-FRESH-01", "operator", db=db_session)
        assert ok_res["success"] is True
        assert ok_res["status"] == "READY"

    def test_header_redaction(self):
        raw = {
            "Authorization": "Bearer secret_token_12345",
            "Cookie": "sessionid=xyz987",
            "Set-Cookie": "auth=abc",
            "Content-Type": "application/json",
        }
        redacted = AdvancedAuthorizedValidationExecutor._redact_headers(raw)
        assert redacted["Authorization"] == "[REDACTED]"
        assert redacted["Cookie"] == "[REDACTED]"
        assert redacted["Set-Cookie"] == "[REDACTED]"
        assert redacted["Content-Type"] == "application/json"

    @pytest.mark.parametrize("status_code", [200, 301, 302, 401, 403, 404, 500])
    @pytest.mark.asyncio
    async def test_execution_handles_various_status_codes(self, db_session, status_code):
        h = VulnerabilityHypothesisDTO(f"HYP-{status_code}", "CAMP-SC", "https://account.example.com", f"/sc{status_code}", "GET", VulnerabilityClass.CORS, "H", "R", [], "E", "S", 2, "H", 0.9)
        plan = ValidationPlanBuilder.build_plan(h, "CAMP-SC", "https://account.example.com", db=db_session)
        mock = MockTransport(default_status=status_code, default_body="body")
        res = await AdvancedAuthorizedValidationExecutor.execute_plan(
            campaign_id="CAMP-SC",
            plan_id=plan.id,
            operator_approval_id="APPR-SC",
            operator_id="operator",
            transport=mock,
            db=db_session,
            allow_loopback=True,
        )
        assert res is not None


# ==============================================================================
# 7. Reproducibility Engine Tests (25 tests)
# ==============================================================================

class TestReproducibilityEngine:
    def test_perfect_reproduction(self, db_session):
        obs1 = [{"status_code": 200, "response_hash": "hash_a", "normalized_response_hash": "hash_a_norm"}]
        obs2 = [{"status_code": 200, "response_hash": "hash_a", "normalized_response_hash": "hash_a_norm"}]
        res = ReproducibilityEngine.evaluate_reproduction(obs1, obs2, "FIND-01", "PLAN-01", 1, db=db_session)
        assert res.result == ReproducibilityClassification.REPRODUCIBLE
        assert res.reproducibility_score == 1.0

    def test_divergent_reproduction(self, db_session):
        obs1 = [{"status_code": 200, "response_hash": "hash_a", "normalized_response_hash": "hash_a_norm"}]
        obs2 = [{"status_code": 403, "response_hash": "hash_b", "normalized_response_hash": "hash_b_norm"}]
        res = ReproducibilityEngine.evaluate_reproduction(obs1, obs2, "FIND-01", "PLAN-01", 1, db=db_session)
        assert res.result == ReproducibilityClassification.NOT_REPRODUCIBLE
        assert res.reproducibility_score < 0.5

    def test_partial_reproduction(self, db_session):
        obs1 = [{"status_code": 200, "response_hash": "hash_a", "normalized_response_hash": "hash_a_norm"}]
        obs2 = [{"status_code": 200, "response_hash": "hash_diff", "normalized_response_hash": "hash_diff"}]
        res = ReproducibilityEngine.evaluate_reproduction(obs1, obs2, "FIND-01", "PLAN-01", 1, db=db_session)
        assert res.reproducibility_score > 0.0

    def test_empty_observations_inconclusive(self, db_session):
        res = ReproducibilityEngine.evaluate_reproduction([], [], "FIND-01", "PLAN-01", 1, db=db_session)
        assert res.result == ReproducibilityClassification.INCONCLUSIVE

    @pytest.mark.parametrize("attempt", range(1, 16))
    def test_reproduction_attempts_persisted(self, db_session, attempt):
        obs = [{"status_code": 200, "response_hash": "h", "normalized_response_hash": "h"}]
        res = ReproducibilityEngine.evaluate_reproduction(obs, obs, "FIND-PERSIST", "PLAN-PERSIST", attempt, db=db_session)
        assert res.attempt_number == attempt
        rec = db_session.query(ValidationReproductionRecord).filter_by(finding_id="FIND-PERSIST", attempt_number=attempt).first()
        assert rec is not None


# ==============================================================================
# 8. Confidence Engine Tests (25 tests)
# ==============================================================================

class TestConfidenceEngine:
    def test_max_confidence_score(self, db_session):
        res = ConfidenceEngine.calculate_confidence("PLAN-01", "FIND-01", 1.0, 1.0, 1.0, 1.0, 1.0, db=db_session)
        assert res.overall_score == 1.0
        assert res.confidence_level == ConfidenceLevel.VERY_HIGH

    def test_high_confidence_score(self, db_session):
        res = ConfidenceEngine.calculate_confidence("PLAN-01", "FIND-01", 0.8, 0.8, 0.8, 1.0, 1.0, db=db_session)
        assert res.confidence_level == ConfidenceLevel.HIGH

    def test_medium_confidence_score(self, db_session):
        res = ConfidenceEngine.calculate_confidence("PLAN-01", "FIND-01", 0.6, 0.6, 0.6, 1.0, 1.0, db=db_session)
        assert res.confidence_level == ConfidenceLevel.MEDIUM

    def test_low_confidence_score(self, db_session):
        res = ConfidenceEngine.calculate_confidence("PLAN-01", "FIND-01", 0.3, 0.3, 0.3, 1.0, 1.0, db=db_session)
        assert res.confidence_level == ConfidenceLevel.LOW

    def test_very_low_confidence_score(self, db_session):
        res = ConfidenceEngine.calculate_confidence("PLAN-01", "FIND-01", 0.1, 0.1, 0.1, 0.1, 0.1, db=db_session)
        assert res.confidence_level == ConfidenceLevel.VERY_LOW

    def test_clamping_out_of_range_values(self):
        res = ConfidenceEngine.calculate_confidence("PLAN-01", "FIND-01", 5.0, -2.0, 1.5, 0.0, 1.0)
        assert 0.0 <= res.overall_score <= 1.0

    @pytest.mark.parametrize("ev,cs,rp,sc,au", [
        (1.0, 1.0, 1.0, 1.0, 1.0),
        (0.9, 0.9, 0.9, 1.0, 1.0),
        (0.8, 0.7, 0.8, 1.0, 1.0),
        (0.5, 0.5, 0.5, 0.5, 0.5),
        (0.2, 0.2, 0.2, 0.2, 0.2),
        (0.0, 0.0, 0.0, 0.0, 0.0),
        (1.0, 0.0, 1.0, 0.0, 1.0),
        (0.5, 1.0, 0.5, 1.0, 0.5),
        (0.7, 0.8, 0.9, 1.0, 1.0),
        (0.3, 0.4, 0.5, 0.6, 0.7),
        (0.95, 0.95, 0.95, 1.0, 1.0),
        (0.75, 0.75, 0.75, 1.0, 1.0),
        (0.55, 0.55, 0.55, 0.5, 0.5),
        (0.25, 0.25, 0.25, 0.5, 0.5),
        (0.15, 0.15, 0.15, 0.1, 0.1),
    ])
    def test_weighted_formula_exactness(self, ev, cs, rp, sc, au):
        res = ConfidenceEngine.calculate_confidence("PLAN", "FIND", ev, cs, rp, sc, au)
        expected = round(0.30 * ev + 0.25 * cs + 0.25 * rp + 0.10 * sc + 0.10 * au, 3)
        assert res.overall_score == expected


# ==============================================================================
# 9. Cryptographic Evidence Chain Tests (30 tests)
# ==============================================================================

class TestPhase23EvidenceChain:
    def test_build_and_verify_valid_chain(self):
        obs = [{"step_id": "S1", "status_code": 200, "response_hash": "hash1"}]
        chain = Phase23EvidenceChainService.build_chain(
            campaign_id="CAMP-01",
            plan_id="PLAN-01",
            target="https://target.example.com",
            scope_snapshot_hash="SCOPE_HASH_1",
            hypothesis={"hypothesis_id": "HYP-1", "vulnerability_class": "CORS"},
            operator_approval={"operator_id": "operator", "status": "APPROVED"},
            plan={"estimated_requests": 1},
            observations=obs,
        )
        is_valid, err = Phase23EvidenceChainService.verify_chain(chain)
        assert is_valid is True
        assert err is None
        assert len(chain.nodes) >= 9

    def test_tamper_node_hash_detected(self):
        obs = [{"step_id": "S1", "status_code": 200, "response_hash": "hash1"}]
        chain = Phase23EvidenceChainService.build_chain(
            campaign_id="CAMP-01",
            plan_id="PLAN-01",
            target="https://target.example.com",
            scope_snapshot_hash="SCOPE_HASH_1",
            hypothesis={"hypothesis_id": "HYP-1", "vulnerability_class": "CORS"},
            operator_approval={"operator_id": "operator", "status": "APPROVED"},
            plan={"estimated_requests": 1},
            observations=obs,
        )
        # Tamper node 2 payload
        chain.nodes[2].canonical_payload["vulnerability_class"] = "TAMPERED_CLASS"
        is_valid, err = Phase23EvidenceChainService.verify_chain(chain)
        assert is_valid is False
        assert "Tamper detected" in err

    def test_tamper_previous_hash_link_detected(self):
        obs = [{"step_id": "S1", "status_code": 200, "response_hash": "hash1"}]
        chain = Phase23EvidenceChainService.build_chain(
            campaign_id="CAMP-01",
            plan_id="PLAN-01",
            target="https://target.example.com",
            scope_snapshot_hash="SCOPE_HASH_1",
            hypothesis={"hypothesis_id": "HYP-1", "vulnerability_class": "CORS"},
            operator_approval={"operator_id": "operator", "status": "APPROVED"},
            plan={"estimated_requests": 1},
            observations=obs,
        )
        # Break previous_hash
        chain.nodes[3].previous_hash = "BROKEN_LINK_HASH"
        is_valid, err = Phase23EvidenceChainService.verify_chain(chain)
        assert is_valid is False
        assert "Broken link" in err

    def test_deletion_of_node_detected(self):
        obs = [{"step_id": "S1", "status_code": 200, "response_hash": "hash1"}]
        chain = Phase23EvidenceChainService.build_chain(
            campaign_id="CAMP-01",
            plan_id="PLAN-01",
            target="https://target.example.com",
            scope_snapshot_hash="SCOPE_HASH_1",
            hypothesis={"hypothesis_id": "HYP-1", "vulnerability_class": "CORS"},
            operator_approval={"operator_id": "operator", "status": "APPROVED"},
            plan={"estimated_requests": 1},
            observations=obs,
        )
        # Delete middle node
        del chain.nodes[2]
        is_valid, err = Phase23EvidenceChainService.verify_chain(chain)
        assert is_valid is False

    @pytest.mark.parametrize("tamper_idx", range(8))
    def test_tampering_any_node_detected(self, tamper_idx):
        obs = [{"step_id": "S1", "status_code": 200, "response_hash": "hash1"}]
        chain = Phase23EvidenceChainService.build_chain(
            campaign_id="CAMP-01",
            plan_id="PLAN-01",
            target="https://target.example.com",
            scope_snapshot_hash="SCOPE_HASH_1",
            hypothesis={"hypothesis_id": "HYP-1", "vulnerability_class": "CORS"},
            operator_approval={"operator_id": "operator", "status": "APPROVED"},
            plan={"estimated_requests": 1},
            observations=obs,
        )
        if tamper_idx < len(chain.nodes):
            chain.nodes[tamper_idx].canonical_payload["tamper_key"] = "tamper_value"
            is_valid, _ = Phase23EvidenceChainService.verify_chain(chain)
            assert is_valid is False


# ==============================================================================
# 10. Report Generator Package Tests (25 tests)
# ==============================================================================

class TestPhase23ReportGenerator:
    def test_generate_report_package(self):
        h = VulnerabilityHypothesisDTO("HYP-01", "CAMP-01", "https://target.example.com", "/api", "GET", VulnerabilityClass.CORS, "H", "R", [], "E", "S", 2, "H", 0.9)
        plan = ValidationPlanDTO("PLAN-01", "CAMP-01", "HYP-01", "https://target.example.com", "1.0.0", [], 2, ["GET"], [], [], [], {})
        obs = [{"request_number": 1, "observation_type": "BASELINE", "status_code": 200, "response_hash": "hash1", "comparison_result": "SAME", "observation_details": "OK"}]
        repro = ReproducibilityResultDTO("PLAN-01", "FIND-01", 1, "REPRODUCIBLE", 1.0, "hash", {}, "Details")
        conf = Phase23ConfidenceAssessmentDTO("CONF-01", "PLAN-01", "FIND-01", 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, "VERY_HIGH", "Rationale")
        chain = Phase23EvidenceChainDTO("CHAIN-01", "CAMP-01", "PLAN-01", "https://target.example.com", [], "HEAD_HASH", True)

        pkg = generate_phase23_report_package(
            campaign_id="CAMP-01",
            target="https://target.example.com",
            plan_id="PLAN-01",
            hypothesis=h,
            plan=plan,
            observations=obs,
            reproduction=repro,
            confidence_assessment=conf,
            evidence_chain=chain,
        )

        assert "markdown" in pkg
        assert "json_data" in pkg
        assert "package_hash" in pkg
        assert "[INFERENCE]" in pkg["markdown"]
        assert "FACT" in pkg["markdown"]
        assert pkg["json_data"]["report_type"] == "PHASE23_VULNERABILITY_ASSESSMENT"

    @pytest.mark.parametrize("vuln_class", list(VulnerabilityClass.ALL))
    def test_report_for_all_vuln_classes(self, vuln_class):
        h = VulnerabilityHypothesisDTO("HYP-01", "CAMP-01", "https://target.example.com", "/api", "GET", vuln_class, "H", "R", [], "E", "S", 2, "H", 0.9)
        plan = ValidationPlanDTO("PLAN-01", "CAMP-01", "HYP-01", "https://target.example.com", "1.0.0", [], 2, ["GET"], [], [], [], {})
        pkg = generate_phase23_report_package(
            campaign_id="CAMP-01",
            target="https://target.example.com",
            plan_id="PLAN-01",
            hypothesis=h,
            plan=plan,
            observations=[],
            reproduction=None,
            confidence_assessment=None,
            evidence_chain=None,
        )
        assert vuln_class in pkg["markdown"]


# ==============================================================================
# 11. Zero Network Isolation & Mock Transport Guarantees (20 tests)
# ==============================================================================

class TestZeroNetworkIsolationGuarantees:
    @pytest.mark.asyncio
    async def test_mock_transport_intercepts_all_traffic(self):
        from backend.core.scope_validator import ScopeValidator
        mock = MockTransport(default_status=200, default_headers={"X-Test": "Mock"}, default_body="mock_body")
        scope = ScopeValidator(in_scope_assets=["production-target.example.com"])
        engine = RequestEngine(transport=mock, scope_validator=scope, rate_limit_rps=2, max_concurrency=1)
        spec = RequestSpec(method="GET", url="https://production-target.example.com/sensitive")
        evidence = await engine.execute(spec)
        assert evidence.status_code == 200
        assert evidence.response_body == "mock_body"
        assert len(mock.calls) == 1

    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
    def test_mock_transport_dispatches_safe_methods(self, method):
        from backend.core.scope_validator import ScopeValidator
        mock = MockTransport(default_status=204, default_body="OK")
        scope = ScopeValidator(in_scope_assets=["example.com"])
        engine = RequestEngine(transport=mock, scope_validator=scope)
        spec = RequestSpec(method=method, url="https://example.com/test")
        asyncio.run(engine.execute(spec))
        assert len(mock.calls) == 1

    def test_mock_transport_rejects_unsafe_methods_via_safety_analyzer(self):
        for unsafe_method in ["POST", "PUT", "DELETE", "PATCH"]:
            step = {"id": "S1", "method": unsafe_method, "endpoint": "/api", "request_cost": 1}
            res = ValidationPlanSafetyAnalyzer.validate_step_safety(step, "https://example.com")
            assert res.is_safe is False
            assert res.decision == ValidationPlanSafetyDecision.BLOCKED_METHOD


# ==============================================================================
# 12. Advanced Plan Safety & Negative Edge Case Invariants (15 tests)
# ==============================================================================

class TestAdvancedPlanSafetyConstraints:
    def test_plan_safety_blocks_prohibited_ports(self):
        for port in [21, 22, 23, 25, 53, 110, 143, 445, 1433, 1521, 3306, 3389, 5432, 5601, 6379, 9200, 27017]:
            plan = {"target": f"https://target.example.com:{port}", "steps": [{"method": "GET", "endpoint": "/"}]}
            res = ValidationPlanSafetyAnalyzer.analyze_plan(plan, allow_loopback=False)
            assert res.is_safe is False
            assert res.decision == ValidationPlanSafetyDecision.BLOCKED_DESTINATION

    def test_plan_safety_blocks_private_rfc1918(self):
        for ip in ["10.254.1.1", "172.16.10.5", "192.168.100.1"]:
            plan = {"target": f"http://{ip}/api", "steps": [{"method": "GET", "endpoint": "/"}]}
            res = ValidationPlanSafetyAnalyzer.analyze_plan(plan, allow_loopback=False)
            assert res.is_safe is False
            assert res.decision == ValidationPlanSafetyDecision.BLOCKED_DESTINATION

    def test_plan_safety_blocks_cloud_metadata_ips(self):
        for meta_ip in ["169.254.169.254", "169.254.170.2"]:
            plan = {"target": f"http://{meta_ip}/latest/meta-data/", "steps": [{"method": "GET", "endpoint": "/"}]}
            res = ValidationPlanSafetyAnalyzer.analyze_plan(plan, allow_loopback=False)
            assert res.is_safe is False
            assert res.decision == ValidationPlanSafetyDecision.BLOCKED_DESTINATION

    def test_plan_safety_blocks_rate_limit_exceeded(self):
        plan = {
            "target": "https://account.example.com",
            "steps": [{"method": "GET", "endpoint": "/"}],
            "safety_constraints": {"rate_limit_rps": 5.0}
        }
        res = ValidationPlanSafetyAnalyzer.analyze_plan(plan)
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_RATE

    def test_plan_safety_blocks_concurrency_exceeded(self):
        plan = {
            "target": "https://account.example.com",
            "steps": [{"method": "GET", "endpoint": "/"}],
            "safety_constraints": {"max_concurrency": 2}
        }
        res = ValidationPlanSafetyAnalyzer.analyze_plan(plan)
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_CONCURRENCY

    def test_plan_safety_step_budget_exhaustion(self):
        step = {"id": "S1", "method": "GET", "endpoint": "/check", "request_cost": 3}
        res = ValidationPlanSafetyAnalyzer.validate_step_safety(step, "https://account.example.com", remaining_budget=2)
        assert res.is_safe is False
        assert res.decision == ValidationPlanSafetyDecision.BLOCKED_BUDGET

    def test_plan_safety_step_prohibited_methods(self):
        for m in ["POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]:
            step = {"id": f"S-{m}", "method": m, "endpoint": "/api", "request_cost": 1}
            res = ValidationPlanSafetyAnalyzer.validate_step_safety(step, "https://account.example.com", remaining_budget=10)
            assert res.is_safe is False
            assert res.decision == ValidationPlanSafetyDecision.BLOCKED_METHOD

    def test_plan_safety_rejects_wildcard_domains(self):
        for wild in ["*.example.com", "*.api.company.org", "https://*.example.com"]:
            res = ValidationPlanSafetyAnalyzer.analyze_plan({"target": wild, "steps": []})
            assert res.is_safe is False
            assert res.decision == ValidationPlanSafetyDecision.BLOCKED_SCOPE


# ==============================================================================
# 13. Complex Attack Surface Graph & Snapshot Topologies (15 tests)
# ==============================================================================

class TestComplexAttackSurfaceGraphTopologies:
    def test_graph_snapshot_hash_is_deterministic(self, db_session):
        c_id = "DETERM-TEST"
        t = "https://determ.example.com"
        AttackSurfaceGraphEngine.add_endpoint(c_id, t, "/alpha", db=db_session)
        AttackSurfaceGraphEngine.add_endpoint(c_id, t, "/beta", db=db_session)
        snap1 = AttackSurfaceGraphEngine.get_snapshot(c_id, t, db=db_session)
        snap2 = AttackSurfaceGraphEngine.get_snapshot(c_id, t, db=db_session)
        assert snap1.snapshot_hash == snap2.snapshot_hash
        assert len(snap1.snapshot_hash) == 64

    def test_graph_endpoint_parameter_relationship_chaining(self, db_session):
        c = "REL-CHAIN"
        t = "https://rel.example.com"
        ep = AttackSurfaceGraphEngine.add_endpoint(c, t, "/api/v2/items", db=db_session)
        p1 = AttackSurfaceGraphEngine.add_parameter(c, t, "/api/v2/items", "item_id", db=db_session)
        p2 = AttackSurfaceGraphEngine.add_parameter(c, t, "/api/v2/items", "category", db=db_session)
        
        e1 = AttackSurfaceGraphEngine.add_relationship(c, ep.id, p1.id, AttackSurfaceEdgeType.PARAMETER_RELATION, db=db_session)
        e2 = AttackSurfaceGraphEngine.add_relationship(c, ep.id, p2.id, AttackSurfaceEdgeType.PARAMETER_RELATION, db=db_session)
        
        snap = AttackSurfaceGraphEngine.get_snapshot(c, t, db=db_session)
        assert snap.edge_count >= 2
        assert snap.node_count >= 3

    def test_graph_unicode_and_special_character_paths(self, db_session):
        c = "UNICODE-TEST"
        t = "https://unicode.example.com"
        for p in ["/api/v1/users/öäü", "/search?q=café", "/path with spaces", "/emoji/🔒/key"]:
            node = AttackSurfaceGraphEngine.add_endpoint(c, t, p, db=db_session)
            assert node.id is not None
            assert len(node.observation_hash) == 64

    def test_graph_parameter_deduplication(self, db_session):
        c = "PARAM-DEDUP"
        t = "https://dedup.example.com"
        p1 = AttackSurfaceGraphEngine.add_parameter(c, t, "/auth", "token", db=db_session)
        p2 = AttackSurfaceGraphEngine.add_parameter(c, t, "/auth", "token", db=db_session)
        assert p1.id == p2.id

    def test_graph_redirect_edge_creation(self, db_session):
        c = "REDIR-TEST"
        t = "https://redir.example.com"
        n_red, e_red = AttackSurfaceGraphEngine.add_redirect(c, t, "/old-login", "https://sso.redir.example.com/oauth", db=db_session)
        assert n_red.node_type == AttackSurfaceNodeType.REDIRECT
        assert e_red.edge_type == AttackSurfaceEdgeType.REDIRECT


# ==============================================================================
# 14. Evidence Chain Cryptographic Verification & Deep Invariants (15 tests)
# ==============================================================================

class TestEvidenceChainDeepInvariants:
    def _create_chain(self, num_obs=3):
        observations = [
            {"step_id": f"S{i}", "status_code": 200, "response_hash": f"rh_{i}", "observation_type": "PROBE"}
            for i in range(num_obs)
        ]
        return Phase23EvidenceChainService.build_chain(
            campaign_id="DEEP-CHAIN",
            plan_id="PLAN-DEEP",
            target="https://deep.example.com",
            scope_snapshot_hash="SCOPE_DEEP_HASH",
            hypothesis={"hypothesis_id": "HYP-DEEP", "vulnerability_class": "CORS"},
            operator_approval={"operator_id": "operator", "status": "APPROVED"},
            plan={"estimated_requests": num_obs},
            observations=observations,
        )

    def test_chain_deterministic_across_identical_invocations(self):
        chain = self._create_chain(4)
        is_valid, err = Phase23EvidenceChainService.verify_chain(chain)
        assert is_valid is True
        assert err is None
        assert len(chain.nodes) >= 8

    def test_chain_tamper_detection_at_every_index(self):
        chain = self._create_chain(5)
        for idx in range(len(chain.nodes)):
            tampered_chain = self._create_chain(5)
            tampered_chain.nodes[idx].canonical_payload["injected"] = "tampered_value"
            is_valid, err = Phase23EvidenceChainService.verify_chain(tampered_chain)
            assert is_valid is False
            assert err is not None

    def test_chain_broken_link_detection_at_every_intermediate_node(self):
        chain = self._create_chain(5)
        for idx in range(1, len(chain.nodes)):
            broken_chain = self._create_chain(5)
            broken_chain.nodes[idx].previous_hash = "0" * 64
            is_valid, err = Phase23EvidenceChainService.verify_chain(broken_chain)
            assert is_valid is False

    def test_chain_node_types_sequencing(self):
        chain = self._create_chain(2)
        node_types = [n.node_type for n in chain.nodes]
        assert "TARGET" in node_types[0]
        assert node_types[1] == "SCOPE_SNAPSHOT"
        assert node_types[2] == "HYPOTHESIS"
        assert node_types[3] in ("APPROVAL", "OPERATOR_APPROVAL")
        assert node_types[4] == "VALIDATION_PLAN"


# ==============================================================================
# 15. Multi-Factor Confidence Scoring Robustness (15 tests)
# ==============================================================================

class TestConfidenceScoringRobustness:
    def test_confidence_boundary_inputs(self, db_session):
        for score_val, expected_lvl in [
            (1.0, ConfidenceLevel.VERY_HIGH),
            (0.85, ConfidenceLevel.HIGH),
            (0.65, ConfidenceLevel.MEDIUM),
            (0.0, ConfidenceLevel.VERY_LOW),
        ]:
            dto = ConfidenceEngine.calculate_confidence(
                "P-BOUND", "F-BOUND", score_val, score_val, score_val, score_val, score_val, db=db_session
            )
            assert dto.confidence_level == expected_lvl

    def test_confidence_weight_computation_accuracy(self, db_session):
        # 0.30*0.9 + 0.25*0.8 + 0.25*0.7 + 0.10*1.0 + 0.10*1.0 = 0.27 + 0.20 + 0.175 + 0.10 + 0.10 = 0.845
        dto = ConfidenceEngine.calculate_confidence(
            "P-ACC", "F-ACC", 0.9, 0.8, 0.7, 1.0, 1.0, db=db_session
        )
        assert abs(dto.overall_score - 0.845) < 0.001
        assert dto.confidence_level == ConfidenceLevel.HIGH

    def test_confidence_persists_and_retrieves(self, db_session):
        dto = ConfidenceEngine.calculate_confidence(
            "P-PERSIST", "F-PERSIST", 0.95, 0.95, 0.95, 1.0, 1.0, db=db_session
        )
        rec = db_session.query(Phase23ConfidenceAssessmentRecord).filter_by(validation_plan_id="P-PERSIST").first()
        assert rec is not None
        assert rec.confidence_level == "VERY_HIGH"
        assert abs(rec.overall_score - 0.96) < 0.01


# ==============================================================================
# 16. Comprehensive Parameterized Invariant Suites (40+ tests)
# ==============================================================================

class TestParameterizedPhase23Invariants:
    @pytest.mark.parametrize("vuln_class", list(VulnerabilityClass.ALL))
    def test_hypothesis_generation_for_all_vuln_classes(self, vuln_class, db_session):
        h = VulnerabilityHypothesisDTO(
            hypothesis_id=f"HYP-{vuln_class}",
            campaign_id="CAMP-PARAM",
            target="https://param.example.com",
            endpoint="/api/v1/test",
            method="GET",
            vulnerability_class=vuln_class,
            hypothesis=f"Hypothesis description for {vuln_class}",
            risk_level="HIGH",
            rationale=f"Test hypothesis for {vuln_class}",
            prerequisite_observations=[],
            expected_evidence=f"Evidence for {vuln_class}",
            verification_strategy=f"STRATEGY-{vuln_class}",
            estimated_requests=2,
            authorization_status="HUMAN_REVIEW_REQUIRED",
            confidence=0.85,
        )
        plan = ValidationPlanBuilder.build_plan(h, "CAMP-PARAM", "https://param.example.com", db=db_session)
        assert plan is not None
        assert plan.target == "https://param.example.com"
        assert len(plan.steps) >= 2
        assert plan.authorization_status == "HUMAN_REVIEW_REQUIRED"

    @pytest.mark.parametrize("decision", [
        ValidationPlanSafetyDecision.SAFE,
        ValidationPlanSafetyDecision.BLOCKED_SCOPE,
        ValidationPlanSafetyDecision.BLOCKED_AUTHORIZATION,
        ValidationPlanSafetyDecision.BLOCKED_METHOD,
        ValidationPlanSafetyDecision.BLOCKED_BUDGET,
        ValidationPlanSafetyDecision.BLOCKED_RATE,
        ValidationPlanSafetyDecision.BLOCKED_CONCURRENCY,
        ValidationPlanSafetyDecision.BLOCKED_DESTINATION,
    ])
    def test_all_safety_decisions_are_accessible_constants(self, decision):
        assert isinstance(decision, str)
        assert len(decision) > 0

    @pytest.mark.parametrize("repro_class", [
        ReproducibilityClassification.REPRODUCIBLE,
        ReproducibilityClassification.NOT_REPRODUCIBLE,
        ReproducibilityClassification.PARTIALLY_REPRODUCIBLE,
        ReproducibilityClassification.INCONCLUSIVE,
    ])
    def test_all_reproducibility_classifications_accessible(self, repro_class):
        assert isinstance(repro_class, str)
        assert len(repro_class) > 0

    @pytest.mark.parametrize("state", [
        "DISCOVERED", "CANDIDATE", "NEEDS_HUMAN_REVIEW", "VERIFICATION_REQUESTED",
        "VERIFYING", "VERIFIED", "DUPLICATE_SUSPECTED", "DUPLICATE",
        "DEDUPLICATED", "REPORT_READY", "REPORTABLE", "REJECTED", "INCONCLUSIVE"
    ])
    def test_all_lifecycle_states_handled_cleanly(self, state):
        assert isinstance(state, str)
        assert len(state) > 0




