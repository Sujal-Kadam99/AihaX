"""Tests for Bug Bounty Report Generation and Evidence Integrity."""

import pytest
from backend.models.database import Finding
from backend.services.bug_bounty_generator import BugBountyReportGenerator


@pytest.mark.asyncio
async def test_report_generator_filters_unverified_and_false_positives():
    generator = BugBountyReportGenerator()

    verified_finding = Finding(
        id="f-1",
        title="Sensitive Files Exposure",
        vuln_type="C003_Sensitive_Files_Exposure",
        category="Reconnaissance & Asset Exposure",
        severity="high",
        confidence=90,
        affected_url="https://example.com/.env",
        proof_request="GET /.env HTTP/1.1",
        proof_response="DB_PASSWORD=secret",
        verdict="Verified",
        false_positive=False,
    )

    unverified_candidate = Finding(
        id="f-2",
        title="SQL Injection Candidate",
        vuln_type="C023_SQL_Injection",
        category="Injection",
        severity="critical",
        confidence=40,
        affected_url="https://example.com/items?id=1",
        verdict="Inconclusive",
        false_positive=False,
    )

    false_positive_finding = Finding(
        id="f-3",
        title="Soft 404 False Positive",
        vuln_type="C003_Sensitive_Files_Exposure",
        category="Reconnaissance & Asset Exposure",
        severity="high",
        confidence=10,
        affected_url="https://example.com/.env",
        verdict="False Positive",
        false_positive=True,
    )

    reports = await generator.generate_for_findings([
        verified_finding,
        unverified_candidate,
        false_positive_finding,
    ])

    # Only the genuine VERIFIED finding must produce a report DTO
    assert len(reports) == 1
    assert reports[0].title == "Sensitive Files Exposure"
    assert reports[0].affected_url == "https://example.com/.env"
    assert reports[0].proof_of_concept.request == "GET /.env HTTP/1.1"
    assert reports[0].proof_of_concept.response == "DB_PASSWORD=secret"


@pytest.mark.asyncio
async def test_anti_hallucination_preserves_deterministic_poc_data():
    generator = BugBountyReportGenerator()

    finding = Finding(
        id="f-4",
        title="OS Command Injection",
        vuln_type="C027_OS_Command_Injection",
        category="Injection",
        severity="critical",
        confidence=100,
        affected_url="https://example.com/api/ping",
        affected_param="host",
        payload="; expr 31330 + 7 ;",
        proof_request="POST /api/ping HTTP/1.1\r\nhost=; expr 31330 + 7 ;",
        proof_response="31337",
        verdict="Verified",
        false_positive=False,
    )

    reports = await generator.generate_for_findings([finding])
    assert len(reports) == 1
    dto = reports[0]

    # PoC fields must match exact bytes
    assert dto.proof_of_concept.payload == "; expr 31330 + 7 ;"
    assert dto.proof_of_concept.response == "31337"
    assert dto.proof_of_concept.request == "POST /api/ping HTTP/1.1\r\nhost=; expr 31330 + 7 ;"
