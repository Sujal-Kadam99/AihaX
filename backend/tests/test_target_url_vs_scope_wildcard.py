"""Phase 13.x — Target URL vs Scope Wildcard Security Invariant Tests.

Guarantees:
1. A concrete HTTP/HTTPS target URL is always required for execution.
2. Wildcard expressions (*.shopify.com) are strictly authorization metadata rules.
3. Wildcard expressions are never persisted as Campaign.target_url, CampaignTarget.normalized_url, or ExecutionTask targets.
4. Campaign creation fails closed if target is not a concrete URL or is not authorized by the selected program scope.
5. No network requests are transmitted during scope validation.
"""

import json
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.core.errors import (
    InvalidTargetUrlException,
    OutOfScopeException,
    WildcardTargetException,
)
from backend.core.scope_validator import (
    ScopeDecision,
    ScopeStatus,
    ScopeValidator,
    validate_concrete_target_url,
)
from backend.main import app
from backend.models.database import Base, Program, ProgramScope, get_db
from backend.persistence.models import Campaign, CampaignTarget, ExecutionTask
from backend.persistence.repository import CampaignRepository
from backend.persistence.state_machine import CampaignLifecycleState
from backend.services.campaign_operations import CampaignOperationsService


# ──────────────────────────────────────────────────────────────────────────────
# 1. Deterministic URL Validation Helper Tests
# ──────────────────────────────────────────────────────────────────────────────

def test_concrete_https_url_accepted():
    scheme, host, port, path, canonical = validate_concrete_target_url("https://example.com")
    assert scheme == "https"
    assert host == "example.com"
    assert port == 443
    assert path == "/"
    assert canonical == "https://example.com"


def test_concrete_http_url_accepted():
    scheme, host, port, path, canonical = validate_concrete_target_url("http://example.com")
    assert scheme == "http"
    assert host == "example.com"
    assert port == 80
    assert path == "/"
    assert canonical == "http://example.com"



def test_concrete_url_with_path_accepted():
    scheme, host, port, path, canonical = validate_concrete_target_url("https://shop.example.com/api/v1/checkout")
    assert scheme == "https"
    assert host == "shop.example.com"
    assert port == 443
    assert path == "/api/v1/checkout"
    assert canonical == "https://shop.example.com/api/v1/checkout"


def test_wildcard_hostname_rejected():
    with pytest.raises(ValueError, match="Wildcard scope rules cannot be used as executable assessment targets"):
        validate_concrete_target_url("*.shopify.com")


def test_wildcard_url_rejected():
    with pytest.raises(ValueError, match="Wildcard scope rules cannot be used as executable assessment targets"):
        validate_concrete_target_url("https://*.shopify.com")


def test_bare_hostname_rejected():
    with pytest.raises(ValueError, match="Assessment target must start with http:// or https://"):
        validate_concrete_target_url("example-shop.myshopify.com")


def test_javascript_scheme_rejected():
    with pytest.raises(ValueError, match="Assessment target must start with http:// or https://"):
        validate_concrete_target_url("javascript:alert(1)")


def test_data_scheme_rejected():
    with pytest.raises(ValueError, match="Assessment target must start with http:// or https://"):
        validate_concrete_target_url("data:text/html,<html>test</html>")


def test_file_scheme_rejected():
    with pytest.raises(ValueError, match="Assessment target must start with http:// or https://"):
        validate_concrete_target_url("file:///etc/passwd")


def test_mailto_scheme_rejected():
    with pytest.raises(ValueError, match="Assessment target must start with http:// or https://"):
        validate_concrete_target_url("mailto:security@example.com")


def test_malformed_url_rejected():
    with pytest.raises(ValueError):
        validate_concrete_target_url("https://")


def test_empty_string_rejected():
    with pytest.raises(ValueError, match="Target URL must be a non-empty string"):
        validate_concrete_target_url("")


def test_whitespace_string_rejected():
    with pytest.raises(ValueError, match="Target URL must not be whitespace-only"):
        validate_concrete_target_url("    ")


def test_userinfo_spoofing_target_rejected():
    with pytest.raises(ValueError, match="Userinfo / credentials in target URL are not permitted"):
        validate_concrete_target_url("https://user:pass@evil.com")


def test_invalid_port_rejected():
    with pytest.raises(ValueError, match="Port out of range|Invalid port"):
        validate_concrete_target_url("https://example.com:999999")


# ──────────────────────────────────────────────────────────────────────────────
# 2. ScopeValidator Wildcard Rule vs Concrete Target Evaluation
# ──────────────────────────────────────────────────────────────────────────────

def test_concrete_target_matching_wildcard_rule_is_in_scope():
    validator = ScopeValidator(in_scope_assets=["*.shopify.com", "*.myshopify.com"])
    decision = validator.is_url_in_scope("https://example-shop.myshopify.com")

    assert decision.allowed is True
    assert decision.status == ScopeStatus.IN_SCOPE
    assert decision.matched_rule == "*.myshopify.com"
    assert "Host 'example-shop.myshopify.com' matches in-scope wildcard '*.myshopify.com'" in decision.reason




def test_concrete_target_outside_wildcard_rule_is_out_of_scope():
    validator = ScopeValidator(in_scope_assets=["*.shopify.com"])
    decision = validator.is_url_in_scope("https://evil.com")

    assert decision.allowed is False
    assert decision.status == ScopeStatus.DENIED_BY_DEFAULT
    assert "Default Deny" in decision.reason


def test_wildcard_target_itself_is_rejected_as_invalid_target():
    validator = ScopeValidator(in_scope_assets=["*.shopify.com"])

    decision_host = validator.is_host_in_scope("*.shopify.com")
    assert decision_host.allowed is False
    assert decision_host.status == ScopeStatus.INVALID
    assert "Wildcard scope rules cannot be used as executable assessment targets" in decision_host.reason

    decision_url = validator.is_url_in_scope("https://*.shopify.com")
    assert decision_url.allowed is False
    assert decision_url.status == ScopeStatus.INVALID
    assert "Wildcard scope rules cannot be used as executable assessment targets" in decision_url.reason


# ──────────────────────────────────────────────────────────────────────────────
# 3. Campaign Creation & Storage Integrity Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture(name="mem_db")
def fixture_mem_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def test_successful_campaign_stores_exact_concrete_target(mem_db):
    repo = CampaignRepository(mem_db)
    service = CampaignOperationsService(repo)

    camp = service.create_campaign(
        name="Shopify Shop Assessment",
        target_url="https://example-shop.myshopify.com",
        in_scope_assets=["https://example-shop.myshopify.com"],
        selected_checks=["C001_Reflected_XSS"],
    )

    assert camp.target_url == "https://example-shop.myshopify.com"
    targets = repo.get_targets(camp.id)
    assert len(targets) == 1
    assert targets[0].normalized_url == "https://example-shop.myshopify.com"


def test_wildcard_target_never_persisted_in_campaign(mem_db):
    repo = CampaignRepository(mem_db)
    service = CampaignOperationsService(repo)

    with pytest.raises(ValueError, match="Wildcard scope rules cannot be used as executable assessment targets"):
        service.create_campaign(
            name="Invalid Wildcard Assessment",
            target_url="*.shopify.com",
        )

    with pytest.raises(ValueError, match="Wildcard scope rules cannot be used as executable assessment targets"):
        service.create_campaign(
            name="Invalid Wildcard URL Assessment",
            target_url="https://*.shopify.com",
        )


def test_wildcard_scope_rule_in_assets_not_converted_to_campaign_target(mem_db):
    repo = CampaignRepository(mem_db)
    service = CampaignOperationsService(repo)

    # Pass in_scope_assets containing both concrete URL and wildcard rule
    camp = service.create_campaign(
        name="Shopify Assessment",
        target_url="https://example-shop.myshopify.com",
        in_scope_assets=["https://example-shop.myshopify.com", "*.shopify.com", "https://*.shopify.com/*"],
    )

    targets = repo.get_targets(camp.id)
    target_urls = [t.normalized_url for t in targets]

    # Only concrete target should be in targets list
    assert "https://example-shop.myshopify.com" in target_urls
    for url in target_urls:
        assert "*" not in url


def test_execution_task_receives_concrete_target_only(mem_db):
    repo = CampaignRepository(mem_db)
    service = CampaignOperationsService(repo)

    camp = service.create_campaign(
        name="Shopify Assessment",
        target_url="https://example-shop.myshopify.com",
        in_scope_assets=["https://example-shop.myshopify.com"],
        selected_checks=["C001_Reflected_XSS"],
    )
    service.authorize_campaign(camp.id, authorized_by="lead_operator")
    service.start_campaign(camp.id, auto_dispatch=True)

    claimed = service.claim_tasks_for_worker(camp.id, worker_id="worker_01", limit=1)
    assert len(claimed) == 1
    task = claimed[0]

    assert task.target_url == "https://example-shop.myshopify.com"
    assert "*" not in task.target_url


# ──────────────────────────────────────────────────────────────────────────────
# 4. REST API Endpoint Regression & Gating Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture(name="api_client")
def fixture_api_client(mem_db):
    from backend.core.auth import get_or_create_api_token

    api_token = get_or_create_api_token()

    def override_get_db():
        try:
            yield mem_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, base_url="http://localhost:8000", headers={"Authorization": f"Bearer {api_token}"}) as client:
        yield client
    app.dependency_overrides.clear()


def test_api_create_campaign_with_wildcard_rejected_fail_closed(api_client, mem_db):
    # 1. Register program with wildcard scope
    prog_id = "prog-shopify-001"
    program = Program(
        id=prog_id,
        name="Shopify Bug Bounty",
        description="Public bounty program",
        created_at=datetime.now(timezone.utc),
    )
    mem_db.add(program)
    prog_scope = ProgramScope(
        id="scope-shopify-001",
        program_id=prog_id,
        in_scope_assets=json.dumps(["*.shopify.com", "*.myshopify.com"]),
        out_of_scope_assets=json.dumps([]),
        allowed_ports=json.dumps([80, 443]),
        excluded_ports=json.dumps([]),
        allowed_schemes=json.dumps(["https", "http"]),
        excluded_paths=json.dumps([]),
        created_at=datetime.now(timezone.utc),
    )
    mem_db.add(prog_scope)
    mem_db.commit()

    # 2. Attempt to create campaign with wildcard string as target
    res_wildcard = api_client.post(
        "/api/campaigns",
        json={
            "name": "Invalid Wildcard Campaign",
            "target_url": "*.shopify.com",
            "program_id": prog_id,
        },
    )
    assert res_wildcard.status_code == 400
    data = res_wildcard.json()
    assert data["success"] is False
    assert data["error"]["code"] == "WILDCARD_TARGET_NOT_ALLOWED"

    # 3. Attempt to create campaign with out-of-scope concrete target
    res_out_of_scope = api_client.post(
        "/api/campaigns",
        json={
            "name": "Out of Scope Campaign",
            "target_url": "https://unauthorized-victim.com",
            "program_id": prog_id,
        },
    )
    assert res_out_of_scope.status_code == 400
    data_oos = res_out_of_scope.json()
    assert data_oos["success"] is False
    assert data_oos["error"]["code"] == "OUT_OF_SCOPE"

    # 4. Attempt to create campaign with valid concrete in-scope target
    res_valid = api_client.post(
        "/api/campaigns",
        json={
            "name": "Valid Concrete Campaign",
            "target_url": "https://example-shop.myshopify.com",
            "program_id": prog_id,
        },
    )
    assert res_valid.status_code == 201
    data_valid = res_valid.json()
    assert data_valid["success"] is True
    assert data_valid["data"]["target_url"] == "https://example-shop.myshopify.com"


# ──────────────────────────────────────────────────────────────────────────────
# 5. Campaign Lifecycle Integrity & Anti-Resurrection Tests
# ──────────────────────────────────────────────────────────────────────────────

def test_cancelled_campaign_cannot_create_tasks(mem_db):
    repo = CampaignRepository(mem_db)
    service = CampaignOperationsService(repo)

    camp = service.create_campaign(name="Lifecycle Test", target_url="https://example-shop.myshopify.com")
    service.authorize_campaign(camp.id, authorized_by="lead_op")
    service.start_campaign(camp.id, auto_dispatch=True)
    service.cancel_campaign(camp.id, actor="operator", reason="Aborted")

    from backend.persistence.state_machine import InvalidStateTransitionError
    with pytest.raises(InvalidStateTransitionError, match="Cannot create task for terminal campaign"):
        repo.create_task(
            campaign_id=camp.id,
            target_url="https://example-shop.myshopify.com",
            check_id="C001_Reflected_XSS",
            endpoint_url="https://example-shop.myshopify.com/search",
        )


def test_cancelled_campaign_cannot_start_or_resume(mem_db):
    repo = CampaignRepository(mem_db)
    service = CampaignOperationsService(repo)

    camp = service.create_campaign(name="Lifecycle Test 2", target_url="https://example-shop.myshopify.com")
    service.authorize_campaign(camp.id, authorized_by="lead_op")
    service.start_campaign(camp.id, auto_dispatch=True)
    service.cancel_campaign(camp.id, actor="operator")

    from backend.persistence.state_machine import InvalidStateTransitionError
    with pytest.raises(InvalidStateTransitionError):
        service.start_campaign(camp.id)

    with pytest.raises(InvalidStateTransitionError):
        service.resume_campaign(camp.id)


def test_cancelled_campaign_cannot_be_recovered_or_claimed(mem_db):
    repo = CampaignRepository(mem_db)
    service = CampaignOperationsService(repo)

    camp = service.create_campaign(name="Lifecycle Test 3", target_url="https://example-shop.myshopify.com")
    service.authorize_campaign(camp.id, authorized_by="lead_op")
    service.start_campaign(camp.id, auto_dispatch=True)

    # Claim task
    claimed = service.claim_tasks_for_worker(camp.id, worker_id="worker_01", limit=1)
    assert len(claimed) == 1

    # Cancel campaign
    service.cancel_campaign(camp.id, actor="operator")

    # Stale task recovery must never resurrect tasks of cancelled campaign
    recovered = repo.recover_stale_tasks(camp.id)
    assert len(recovered) == 0

    # Worker cannot claim any tasks from cancelled campaign
    new_claimed = service.claim_tasks_for_worker(camp.id, worker_id="worker_02", limit=1)
    assert len(new_claimed) == 0


def test_cancellation_releases_only_own_assignment_preserves_parent_and_other_campaigns(mem_db):
    repo = CampaignRepository(mem_db)
    service = CampaignOperationsService(repo)

    prog_id = "prog-multi-001"
    program = Program(id=prog_id, name="Parent Program", created_at=datetime.now(timezone.utc))
    mem_db.add(program)
    mem_db.commit()

    # Campaign A
    camp_a = service.create_campaign(name="Camp A", target_url="https://a.shopify.com", program_id=prog_id)
    service.authorize_campaign(camp_a.id, authorized_by="lead_op")
    service.start_campaign(camp_a.id, auto_dispatch=True)

    # Campaign B
    camp_b = service.create_campaign(name="Camp B", target_url="https://b.shopify.com", program_id=prog_id)
    service.authorize_campaign(camp_b.id, authorized_by="lead_op")
    service.start_campaign(camp_b.id, auto_dispatch=True)

    # Cancel Campaign A
    service.cancel_campaign(camp_a.id, actor="operator")

    # Verify Campaign A targets are RELEASED
    targets_a = repo.get_targets(camp_a.id)
    assert all(t.target_status == "RELEASED" for t in targets_a)

    # Verify Campaign B is still RUNNING and its targets are PENDING/ACTIVE
    camp_b_refreshed = repo.get_campaign(camp_b.id)
    assert camp_b_refreshed.status == "RUNNING"
    targets_b = repo.get_targets(camp_b.id)
    assert all(t.target_status != "RELEASED" for t in targets_b)


def test_repeated_cancellation_is_idempotent(mem_db):
    repo = CampaignRepository(mem_db)
    service = CampaignOperationsService(repo)

    camp = service.create_campaign(name="Idempotent Cancel", target_url="https://example-shop.myshopify.com")
    service.authorize_campaign(camp.id, authorized_by="lead_op")
    service.start_campaign(camp.id, auto_dispatch=True)

    c1 = service.cancel_campaign(camp.id, actor="operator")
    assert c1.status == "CANCELLED"

    c2 = service.cancel_campaign(camp.id, actor="operator")
    assert c2.status == "CANCELLED"


def test_repeated_start_does_not_duplicate_tasks(mem_db):
    repo = CampaignRepository(mem_db)
    service = CampaignOperationsService(repo)

    camp = service.create_campaign(name="Idempotent Start", target_url="https://example-shop.myshopify.com")
    service.authorize_campaign(camp.id, authorized_by="lead_op")
    service.start_campaign(camp.id, auto_dispatch=True)

    count_1 = len(repo.session.query(ExecutionTask).filter(ExecutionTask.campaign_id == camp.id).all())

    # Second start call
    service.start_campaign(camp.id, auto_dispatch=True)
    count_2 = len(repo.session.query(ExecutionTask).filter(ExecutionTask.campaign_id == camp.id).all())

    assert count_1 == count_2
    assert count_1 >= 1


def test_runtime_truth_for_cancelled_campaign_is_cancelled(mem_db):
    repo = CampaignRepository(mem_db)
    service = CampaignOperationsService(repo)

    camp = service.create_campaign(name="Truth Cancelled", target_url="https://example-shop.myshopify.com")
    service.authorize_campaign(camp.id, authorized_by="lead_op")
    service.start_campaign(camp.id, auto_dispatch=True)
    service.cancel_campaign(camp.id, actor="operator")

    truth = service.get_campaign_runtime_truth(camp.id)
    assert truth["status"] == "CANCELLED"
    assert truth["current_phase"] == "CANCELLED"
    assert truth["active_operation"] == "Assessment cancelled."

