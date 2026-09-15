"""AihaX — End-to-End Automated Finding Verification Gate Proofs (A through L).

Deterministic tests proving the 12 canonical verification guarantees:
- Proof A: Validated finding end-to-end
- Proof B: Hardening only (security headers)
- Proof C: Rate limit inconclusive (5x 401 with no 429)
- Proof D: Directory listing benign (images)
- Proof E: Directory listing sensitive (.env / credentials)
- Proof F: False positive (HTTP 301 redirect to HTTPS)
- Proof G: IDOR / BOLA dual-identity verification
- Proof H: Missing evidence yields INCONCLUSIVE
- Proof I: Evidence persistence error
- Proof J: Verifier internal error yields VERIFICATION_ERROR
- Proof K: Incomplete evidence cannot validate
- Proof L: Policy unknown cannot become automatically eligible
"""

import json
import pytest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.models.database import (
    Base,
    BountyEligibility,
    Finding,
    FindingDisposition,
    Scan,
)
from backend.persistence.models import Campaign
from backend.services.automated_finding_verifier import (
    AutomatedFindingVerifier,
    VerificationExplanationDTO,
)
from backend.services.execution_events import (
    ExecutionEventManager,
    ExecutionEventType,
)


@pytest.fixture
def in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


class TestAutomatedVerificationProofsAthroughL:
    """Rigorous execution of Proofs A through L without external network traffic."""

    def test_proof_a_validated_finding_end_to_end(self, in_memory_db):
        """Proof A: Validated finding end-to-end with proven impact and policy."""
        scan = Scan(id="scan-proof-a", target_url="https://app.target.local")
        in_memory_db.add(scan)
        in_memory_db.commit()

        finding = Finding(
            id="f-proof-a",
            scan_id=scan.id,
            agent_id=1,
            title="Exposed Database Configuration File",
            vuln_type="C006_DIRECTORY_LISTING",
            category="disclosure",
            severity="high",
            affected_url="https://app.target.local/backup/",
            proof_request="GET /backup/ HTTP/1.1",
            proof_response="Index of /backup/\n database.sql\n .env\n DB_PASSWORD=Secret_12345",
            verification_status="CANDIDATE",
        )
        in_memory_db.add(finding)
        in_memory_db.commit()

        policy = {"name": "TargetBounty", "in_scope_vuln_types": ["C006_DIRECTORY_LISTING"]}
        explanation = AutomatedFindingVerifier.verify_finding(finding, program_policy=policy)
        in_memory_db.commit()

        assert explanation.disposition == FindingDisposition.VALIDATED.value
        assert finding.finding_disposition == FindingDisposition.VALIDATED.value
        assert finding.verdict == "Verified"
        assert finding.impact_confidence >= 0.8
        assert finding.condition_confidence == 1.0
        assert finding.confidence >= 70
        assert finding.bounty_eligibility == BountyEligibility.ELIGIBLE.value

    def test_proof_b_hardening_only_security_headers(self, in_memory_db):
        """Proof B: Security headers observation yields HARDENING_ONLY."""
        finding = Finding(
            id="f-proof-b",
            scan_id="scan-proof-b",
            agent_id=1,
            title="Missing Content Security Policy",
            vuln_type="C047_Missing_CSP",
            category="headers",
            severity="low",
            affected_url="https://app.target.local/",
            proof_request="GET / HTTP/1.1",
            proof_response="HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html><body>App</body></html>",
        )
        explanation = AutomatedFindingVerifier.verify_finding(finding)

        assert explanation.disposition == FindingDisposition.HARDENING_ONLY.value
        assert finding.finding_disposition == FindingDisposition.HARDENING_ONLY.value
        assert finding.verdict == "Hardening Only"
        assert finding.condition_confidence == 1.0
        assert finding.impact_confidence == 0.0
        assert finding.exploitability_confidence == 0.0
        assert finding.confidence == 50
        assert finding.bounty_eligibility == BountyEligibility.INELIGIBLE.value

    def test_proof_c_rate_limiting_inconclusive(self, in_memory_db):
        """Proof C: 5x 401 with no 429 yields INCONCLUSIVE."""
        finding = Finding(
            id="f-proof-c",
            scan_id="scan-proof-c",
            agent_id=1,
            title="Authentication Rate-Limit Weakness",
            vuln_type="C022_Auth_Rate_Limit",
            category="auth",
            severity="medium",
            affected_url="https://app.target.local/login",
            proof_request="POST /login HTTP/1.1",
            proof_response="5 consecutive login attempts returned 401 Unauthorized (no 429 triggered)",
        )
        explanation = AutomatedFindingVerifier.verify_finding(finding)

        assert explanation.disposition == FindingDisposition.INCONCLUSIVE.value
        assert finding.finding_disposition == FindingDisposition.INCONCLUSIVE.value
        assert finding.verdict == "Inconclusive"
        assert finding.impact_confidence == 0.0
        assert finding.confidence <= 30

    def test_proof_d_directory_listing_benign(self, in_memory_db):
        """Proof D: Benign directory listing (/images/) yields HARDENING_ONLY."""
        finding = Finding(
            id="f-proof-d",
            scan_id="scan-proof-d",
            agent_id=1,
            title="Directory Listing Enabled",
            vuln_type="C006_Directory_Listing",
            category="info",
            severity="low",
            affected_url="https://app.target.local/images/",
            proof_request="GET /images/ HTTP/1.1",
            proof_response="Index of /images/\n logo.png\n icon.svg\n favicon.ico",
        )
        explanation = AutomatedFindingVerifier.verify_finding(finding)

        assert explanation.disposition == FindingDisposition.HARDENING_ONLY.value
        assert finding.finding_disposition == FindingDisposition.HARDENING_ONLY.value
        assert finding.verdict == "Hardening Only"
        assert finding.impact_confidence == 0.0
        assert finding.bounty_eligibility == BountyEligibility.INELIGIBLE.value

    def test_proof_e_directory_listing_sensitive(self, in_memory_db):
        """Proof E: Directory listing containing .env / credentials yields VALIDATED."""
        finding = Finding(
            id="f-proof-e",
            scan_id="scan-proof-e",
            agent_id=1,
            title="Directory Listing Enabled",
            vuln_type="C006_Directory_Listing",
            category="info",
            severity="high",
            affected_url="https://app.target.local/conf/",
            proof_request="GET /conf/ HTTP/1.1",
            proof_response="Index of /conf/\n config.json\n .env\n private_key.pem",
        )
        policy = {"name": "TargetBounty", "in_scope_vuln_types": ["C006_DIRECTORY_LISTING"]}
        explanation = AutomatedFindingVerifier.verify_finding(finding, program_policy=policy)

        assert explanation.disposition == FindingDisposition.VALIDATED.value
        assert finding.finding_disposition == FindingDisposition.VALIDATED.value
        assert finding.verdict == "Verified"
        assert finding.impact_confidence >= 0.8
        assert finding.bounty_eligibility == BountyEligibility.ELIGIBLE.value

    def test_proof_f_false_positive_http_301_to_https(self, in_memory_db):
        """Proof F: Cleartext HTTP port 80 redirecting 301 to HTTPS yields FALSE_POSITIVE."""
        finding = Finding(
            id="f-proof-f",
            scan_id="scan-proof-f",
            agent_id=1,
            title="Open Cleartext HTTP Port 80",
            vuln_type="C001_Open_Port_80",
            category="network",
            severity="medium",
            affected_url="http://app.target.local/",
            proof_request="GET / HTTP/1.1\r\nHost: app.target.local",
            proof_response="HTTP/1.1 301 Moved Permanently\r\nLocation: https://app.target.local/\r\n\r\n",
        )
        explanation = AutomatedFindingVerifier.verify_finding(finding)

        assert explanation.disposition == FindingDisposition.FALSE_POSITIVE.value
        assert finding.finding_disposition == FindingDisposition.FALSE_POSITIVE.value
        assert finding.false_positive is True

    def test_proof_g_idor_dual_identity(self, in_memory_db):
        """Proof G: Dual-identity test confirms IDOR access differential."""
        finding = Finding(
            id="f-proof-g",
            scan_id="scan-proof-g",
            agent_id=1,
            title="Insecure Direct Object Reference on User Profile",
            vuln_type="C068_IDOR_PROFILE",
            category="authz",
            severity="high",
            affected_url="https://app.target.local/api/users/9912",
            proof_request="GET /api/users/9912 HTTP/1.1",
            proof_response="{\"user_id\": 9912, \"email\": \"victim@test.local\", \"ssn\": \"123-45-6789\"}",
        )
        dual_id = {
            "account_a": {
                "status_code": 200,
                "auth_token": "TOKEN_VICTIM_A",
                "body": "{\"user_id\": 9912, \"email\": \"victim@test.local\", \"ssn\": \"123-45-6789\"}",
            },
            "account_b": {
                "status_code": 200,
                "auth_token": "TOKEN_ATTACKER_B",
                "body": "{\"user_id\": 9912, \"email\": \"victim@test.local\", \"ssn\": \"123-45-6789\"}",
            },
            "target_resource_id": "9912",
        }
        policy = {"name": "TestProg", "in_scope_vuln_types": ["C068_IDOR_PROFILE"]}
        explanation = AutomatedFindingVerifier.verify_finding(
            finding=finding,
            dual_identity_evidence=dual_id,
            program_policy=policy,
        )

        assert explanation.disposition == FindingDisposition.VALIDATED.value
        assert finding.finding_disposition == FindingDisposition.VALIDATED.value
        assert finding.verdict == "Verified"
        assert finding.impact_confidence >= 0.8
        assert finding.reproducibility_confidence >= 0.9

    def test_proof_h_missing_evidence_yields_inconclusive(self, in_memory_db):
        """Proof H: Finding created without proof response or evidence chain yields INCONCLUSIVE."""
        finding = Finding(
            id="f-proof-h",
            scan_id="scan-proof-h",
            agent_id=1,
            title="Suspected SSRF",
            vuln_type="C016_SSRF",
            category="injection",
            severity="critical",
            affected_url="https://app.target.local/webhook",
            proof_request="",
            proof_response="",  # No evidence
        )
        explanation = AutomatedFindingVerifier.verify_finding(finding, evidence_chain=[])

        assert explanation.disposition == FindingDisposition.INCONCLUSIVE.value
        assert finding.finding_disposition == FindingDisposition.INCONCLUSIVE.value
        assert "MISSING_PROOF_EVIDENCE" in explanation.failed_requirements
        assert finding.confidence <= 30

    def test_proof_i_evidence_persistence_error_recorded(self, in_memory_db):
        """Proof I: Evidence persistence failure event recorded in event chain."""
        camp = Campaign(id="camp-proof-i", name="Proof I Campaign", target_url="https://app.target.local")
        in_memory_db.add(camp)
        in_memory_db.commit()

        mgr = ExecutionEventManager(session=in_memory_db)
        evt = mgr.record_event(
            campaign_id="camp-proof-i",
            event_type=ExecutionEventType.EVIDENCE_PERSISTENCE_ERROR,
            target_url="https://app.target.local",
            reason="Disk write failed for cryptographic evidence payload",
        )
        in_memory_db.commit()

        assert evt.event_type == ExecutionEventType.EVIDENCE_PERSISTENCE_ERROR.value
        assert evt.event_hash is not None
        assert "Disk write failed" in evt.reason

    def test_proof_j_verification_engine_failure_yields_verification_error(self, in_memory_db):
        """Proof J: Verifier internal exception yields explicit VERIFICATION_ERROR state."""
        finding = Finding(
            id="f-proof-j",
            scan_id="scan-proof-j",
            agent_id=1,
            title="Broken Object Level Authorization",
            vuln_type="C068_BOLA",
            category="authz",
            severity="high",
            affected_url="https://app.target.local/api/items",
            proof_response="HTTP/1.1 200 OK",
        )
        with patch.object(AutomatedFindingVerifier, "_execute_verification", side_effect=Exception("Strategy crash simulation")):
            explanation = AutomatedFindingVerifier.verify_finding(finding)

        assert explanation.disposition == FindingDisposition.VERIFICATION_ERROR.value
        assert finding.finding_disposition == FindingDisposition.VERIFICATION_ERROR.value
        assert finding.verdict == "Verification Error"
        assert finding.confidence == 0
        assert "Strategy crash simulation" in explanation.reason

    def test_proof_k_incomplete_evidence_cannot_validate(self, in_memory_db):
        """Proof K Invariant: Condition detected but incomplete evidence CANNOT become VALIDATED."""
        finding = Finding(
            id="f-proof-k",
            scan_id="scan-proof-k",
            agent_id=1,
            title="Potential Remote Code Execution",
            vuln_type="C018_COMMAND_INJECTION",
            category="rce",
            severity="critical",
            affected_url="https://app.target.local/ping",
            proof_request="POST /ping HTTP/1.1",
            proof_response=None,  # Missing response evidence!
            verification_status="CANDIDATE",
        )
        explanation = AutomatedFindingVerifier.verify_finding(finding, evidence_chain=[])

        assert explanation.disposition != FindingDisposition.VALIDATED.value
        assert explanation.disposition == FindingDisposition.INCONCLUSIVE.value
        assert finding.finding_disposition == FindingDisposition.INCONCLUSIVE.value
        assert finding.verdict != "Verified"

    def test_proof_l_policy_unknown_cannot_become_eligible(self, in_memory_db):
        """Proof L Invariant: Finding is technically valid, but policy unknown CANNOT become ELIGIBLE."""
        finding = Finding(
            id="f-proof-l",
            scan_id="scan-proof-l",
            agent_id=1,
            title="Critical SQL Injection in User Search",
            vuln_type="SQLI_SEARCH",
            category="injection",
            severity="critical",
            affected_url="https://app.target.local/search?q='",
            proof_request="GET /search?q=' HTTP/1.1",
            proof_response="HTTP/1.1 500 Internal Error\r\n\r\npg_query(): syntax error near ''''",
            verification_status="VALIDATED",
            verdict="Verified",
        )
        # Policy is None -> Program policy rules unknown
        explanation = AutomatedFindingVerifier.verify_finding(finding, program_policy=None)

        assert explanation.disposition in (FindingDisposition.VALIDATED.value, FindingDisposition.EXPLOITABLE.value)
        assert explanation.bounty_eligibility == BountyEligibility.UNKNOWN.value
        assert explanation.policy_eligibility_confidence == 0.0
        assert finding.bounty_eligibility == BountyEligibility.UNKNOWN.value
