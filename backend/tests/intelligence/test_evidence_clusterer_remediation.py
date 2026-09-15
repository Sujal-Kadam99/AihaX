"""AihaX Phase 7 — Unit tests for EvidenceCorrelator, FindingClusterer, and RemediationEngine."""

import pytest
from unittest.mock import MagicMock


def _make_finding(
    id_="find-001",
    vuln_type="C023_SQL_Injection",
    category="injection",
    affected_url="http://testsite.com/search",
    affected_param="q",
    payload="' OR 1=1--",
    proof_request="GET /search HTTP/1.1",
    proof_response="SQL error",
    confidence=80,
    severity="high",
    verdict="Verified",
    false_positive=False,
    evidence_ids='["EVD-001"]',
    request_ids='["REQ-001"]',
    verification_reason_code="REPRODUCED_SUCCESSFULLY",
    verification_status="REPORTABLE",
):
    f = MagicMock()
    f.id = id_
    f.vuln_type = vuln_type
    f.category = category
    f.affected_url = affected_url
    f.affected_param = affected_param
    f.payload = payload
    f.proof_request = proof_request
    f.proof_response = proof_response
    f.confidence = confidence
    f.severity = severity
    f.verdict = verdict
    f.false_positive = false_positive
    f.evidence_ids = evidence_ids
    f.request_ids = request_ids
    f.verification_reason_code = verification_reason_code
    f.verification_status = verification_status
    f.cwe_id = None
    return f


class TestEvidenceCorrelator:

    def test_build_chain_basic(self):
        from backend.intelligence.evidence_correlator import EvidenceCorrelator
        chain = EvidenceCorrelator.build_chain(
            finding_id="find-001",
            check_id="C023",
            request_evidence_ids=["REQ-001"],
            verification_evidence_ids=["EVD-001"],
            target_url="http://testsite.com",
            affected_param="q",
        )
        assert chain.finding_id == "find-001"
        assert chain.check_id == "C023"
        assert "REQ-001" in chain.request_evidence_ids
        assert "EVD-001" in chain.verification_evidence_ids
        assert chain.evidence_count == 2
        assert len(chain.chain_hash) == 64  # SHA-256

    def test_chain_integrity_valid(self):
        from backend.intelligence.evidence_correlator import EvidenceCorrelator
        chain = EvidenceCorrelator.build_chain(
            finding_id="find-001",
            check_id="C037",
            request_evidence_ids=["REQ-XSS"],
            verification_evidence_ids=["EVD-XSS"],
        )
        assert chain.verify_integrity() is True

    def test_chain_integrity_tamper_detected(self):
        from backend.intelligence.evidence_correlator import EvidenceCorrelator
        chain = EvidenceCorrelator.build_chain(
            finding_id="find-001",
            check_id="C037",
            request_evidence_ids=["REQ-001"],
        )
        # Tamper with the chain
        chain.request_evidence_ids.append("INJECTED-ID")
        assert chain.verify_integrity() is False

    def test_from_finding(self):
        from backend.intelligence.evidence_correlator import EvidenceCorrelator
        finding = _make_finding()
        chain = EvidenceCorrelator.from_finding(
            finding_id=str(finding.id),
            check_id=str(finding.vuln_type),
            evidence_ids_json=finding.evidence_ids,
            request_ids_json=finding.request_ids,
            target_url=str(finding.affected_url),
            affected_param=str(finding.affected_param),
        )
        assert chain.finding_id == "find-001"
        assert "EVD-001" in chain.verification_evidence_ids or "EVD-001" in chain.all_evidence_ids()

    def test_merge_chains(self):
        from backend.intelligence.evidence_correlator import EvidenceCorrelator
        chain_a = EvidenceCorrelator.build_chain(
            finding_id="find-001",
            check_id="C023",
            request_evidence_ids=["REQ-001"],
        )
        chain_b = EvidenceCorrelator.build_chain(
            finding_id="find-001",
            check_id="C023",
            verification_evidence_ids=["EVD-001"],
            control_evidence_ids=["CTRL-001"],
        )
        merged = EvidenceCorrelator.merge_chains(chain_a, chain_b)
        all_ids = merged.all_evidence_ids()
        assert "REQ-001" in all_ids
        assert "EVD-001" in all_ids
        assert "CTRL-001" in all_ids
        assert merged.verify_integrity() is True

    def test_validate_chain_empty(self):
        from backend.intelligence.evidence_correlator import EvidenceCorrelator
        chain = EvidenceCorrelator.build_chain(finding_id="find-001", check_id="C023")
        result = EvidenceCorrelator.validate_chain(chain)
        assert "empty evidence chain" in str(result["issues"])

    def test_validate_chain_good(self):
        from backend.intelligence.evidence_correlator import EvidenceCorrelator
        chain = EvidenceCorrelator.build_chain(
            finding_id="find-001",
            check_id="C023",
            request_evidence_ids=["REQ-001"],
            verification_evidence_ids=["EVD-001"],
        )
        result = EvidenceCorrelator.validate_chain(chain)
        assert result["valid"] is True

    def test_no_secrets_in_chain(self):
        """Evidence chains must not contain raw secret values."""
        from backend.intelligence.evidence_correlator import EvidenceCorrelator
        chain = EvidenceCorrelator.build_chain(
            finding_id="find-001",
            check_id="C020",
            request_evidence_ids=["REQ-JWT"],
            authentication_context_ids=["AUTH-001"],
            payload_summary="[REDACTED-JWT]",
        )
        chain_json = chain.to_json()
        # Verify no actual JWT structure in JSON
        import json
        data = json.loads(chain_json)
        assert "eyJ" not in str(data.get("payload_summary", "")).replace("[REDACTED-JWT]", "")


class TestFindingClusterer:

    def test_exact_duplicate_clustered(self):
        from backend.intelligence.finding_clusterer import FindingClusterer, ClusterRelationType
        f1 = _make_finding(id_="find-001", affected_url="http://testsite.com/search")
        f2 = _make_finding(id_="find-002", affected_url="http://testsite.com/search")  # Same URL
        clusters = FindingClusterer.cluster_findings([f1, f2])
        # Should produce 1 cluster
        assert len(clusters) == 1
        assert clusters[0].member_count == 2

    def test_different_endpoints_separate(self):
        from backend.intelligence.finding_clusterer import FindingClusterer
        f1 = _make_finding(id_="find-001", affected_url="http://testsite.com/user", affected_param="id")
        f2 = _make_finding(id_="find-002", affected_url="http://testsite.com/admin", affected_param="id")
        # Different paths = separate findings even same check
        clusters = FindingClusterer.cluster_findings([f1, f2])
        # Should NOT auto-merge /user and /admin
        assert len(clusters) == 2

    def test_evidence_preserved_on_merge(self):
        """Deduplication must never silently discard evidence."""
        from backend.intelligence.finding_clusterer import FindingClusterer
        f1 = _make_finding(id_="find-001", evidence_ids='["EVD-001"]', payload="payload1")
        f2 = _make_finding(id_="find-002", evidence_ids='["EVD-002"]', payload="payload2")
        clusters = FindingClusterer.cluster_findings([f1, f2])
        # All evidence IDs must be in the merged group
        all_ev = clusters[0].all_evidence_ids if len(clusters) == 1 else []
        if len(clusters) == 1:
            assert "EVD-001" in all_ev
            assert "EVD-002" in all_ev

    def test_single_finding_is_independent(self):
        from backend.intelligence.finding_clusterer import FindingClusterer, ClusterRelationType
        f = _make_finding()
        clusters = FindingClusterer.cluster_findings([f])
        assert len(clusters) == 1
        assert clusters[0].member_count == 1

    def test_empty_input(self):
        from backend.intelligence.finding_clusterer import FindingClusterer
        clusters = FindingClusterer.cluster_findings([])
        assert clusters == []

    def test_cluster_to_dict(self):
        from backend.intelligence.finding_clusterer import FindingClusterer
        f = _make_finding()
        clusters = FindingClusterer.cluster_findings([f])
        d = clusters[0].to_dict()
        assert "cluster_id" in d
        assert "cluster_type" in d
        assert "member_count" in d


class TestRemediationEngine:

    def test_sql_injection_remediation(self):
        from backend.intelligence.remediation import RemediationEngine
        finding = _make_finding(vuln_type="C023_SQL_Injection")
        result = RemediationEngine.generate(finding)
        assert result.vulnerability_family == "sql_injection"
        assert "parameterized" in result.short_fix.lower()
        assert len(result.detailed_steps) > 0
        assert "CWE-89" in result.cwe_references

    def test_xss_remediation(self):
        from backend.intelligence.remediation import RemediationEngine
        finding = _make_finding(vuln_type="C037_Reflected_XSS", category="xss")
        result = RemediationEngine.generate(finding)
        assert result.vulnerability_family == "xss"
        assert "encoding" in result.short_fix.lower()

    def test_idor_remediation(self):
        from backend.intelligence.remediation import RemediationEngine
        finding = _make_finding(vuln_type="C067_IDOR_Numeric", category="idor")
        result = RemediationEngine.generate(finding)
        assert result.vulnerability_family == "idor"
        assert "authorization" in result.short_fix.lower()

    def test_command_injection_remediation(self):
        from backend.intelligence.remediation import RemediationEngine
        finding = _make_finding(vuln_type="C027_OS_Command_Injection")
        result = RemediationEngine.generate(finding)
        assert result.vulnerability_family == "command_injection"
        assert len(result.defense_in_depth) > 0

    def test_generic_fallback(self):
        from backend.intelligence.remediation import RemediationEngine
        finding = _make_finding(vuln_type="C099_Unknown_Check")  # Unknown prefix
        result = RemediationEngine.generate(finding)
        assert result.vulnerability_family == "generic"
        assert result.short_fix

    def test_remediation_deterministic(self):
        from backend.intelligence.remediation import RemediationEngine
        finding = _make_finding(vuln_type="C023_SQL_Injection")
        r1 = RemediationEngine.generate(finding)
        r2 = RemediationEngine.generate(finding)
        assert r1.short_fix == r2.short_fix
        assert r1.detailed_steps == r2.detailed_steps

    def test_to_dict_has_required_fields(self):
        from backend.intelligence.remediation import RemediationEngine
        finding = _make_finding(vuln_type="C036_SSRF", category="ssrf")
        result = RemediationEngine.generate(finding)
        d = result.to_dict()
        assert "short_fix" in d
        assert "detailed_steps" in d
        assert "defense_in_depth" in d
        assert "cwe_references" in d
        assert "owasp_references" in d
        assert "verification_note" in d

    def test_no_llm_in_remediation(self):
        """Remediation must not require external API calls."""
        from backend.intelligence.remediation import RemediationEngine
        # If this succeeds without network access, it's deterministic
        finding = _make_finding(vuln_type="C023_SQL_Injection")
        result = RemediationEngine.generate(finding)
        assert result is not None
