"""Real-target validation for Batch B strategies against ephemeral Flask app on port 5005."""

import asyncio
import sys
sys.path.insert(0, ".")

# Auto-clean port 5005 before anything else
from scratch.kill_scratch_ports import kill as kill_ports
kill_ports([5005])

from backend.services.verification_engine import (
    VerificationContext,
    VerificationBudget,
    VerificationStatus,
    VerificationEngine,
)
from backend.services.request_engine import RequestEngine, AiohttpTransport
from backend.services.verification_strategies.directory_listing_strategy import DirectoryListingVerificationStrategy
from backend.services.verification_strategies.verbose_error_strategy import VerboseErrorVerificationStrategy
from backend.services.verification_strategies.default_credentials_strategy import DefaultCredentialsVerificationStrategy
from backend.core.scope_validator import ScopeValidator
from backend.models.database import Finding


def make_real_engine():
    scope = ScopeValidator(in_scope_assets=["http://127.0.0.1:5005", "http://localhost:5005"], out_of_scope_assets=[])
    transport = AiohttpTransport()
    return RequestEngine(scope_validator=scope, transport=transport)


async def test_directory_listing():
    engine = make_real_engine()
    budget = VerificationBudget(max_requests=5, max_duration_seconds=30)
    candidate = {"affected_url": "http://127.0.0.1:5005/files/"}
    context = VerificationContext(
        finding_id="f-dir", check_id="C006_Directory_Listing",
        target_url="http://127.0.0.1:5005",
        candidate_evidence=candidate, request_engine=engine,
        budget=budget, authorization_confirmed=True,
    )
    strategy = DirectoryListingVerificationStrategy()
    conclusion = await strategy.verify(context)
    print(f"[Directory Listing] Status: {conclusion.status.value}, Confidence: {conclusion.confidence}")
    print(f"  Reason: {conclusion.reason_description}")
    assert conclusion.status == VerificationStatus.VERIFIED, f"Expected VERIFIED, got {conclusion.status.value}"
    print("  ✓ VERIFIED\n")


async def test_verbose_error():
    engine = make_real_engine()
    budget = VerificationBudget(max_requests=10, max_duration_seconds=30)
    candidate = {"affected_url": "http://127.0.0.1:5005/error-page"}
    context = VerificationContext(
        finding_id="f-err", check_id="C054_Verbose_Error_Disclosure",
        target_url="http://127.0.0.1:5005",
        candidate_evidence=candidate, request_engine=engine,
        budget=budget, authorization_confirmed=True,
    )
    strategy = VerboseErrorVerificationStrategy()
    conclusion = await strategy.verify(context)
    print(f"[Verbose Error] Status: {conclusion.status.value}, Confidence: {conclusion.confidence}")
    print(f"  Reason: {conclusion.reason_description}")
    assert conclusion.status == VerificationStatus.VERIFIED, f"Expected VERIFIED, got {conclusion.status.value}"
    print("  ✓ VERIFIED\n")


async def test_default_credentials():
    engine = make_real_engine()
    budget = VerificationBudget(max_requests=10, max_duration_seconds=30)
    candidate = {
        "affected_url": "http://127.0.0.1:5005/login",
        "username_field": "username",
        "password_field": "password",
    }
    context = VerificationContext(
        finding_id="f-cred", check_id="C012_Default_Credentials",
        target_url="http://127.0.0.1:5005",
        candidate_evidence=candidate, request_engine=engine,
        budget=budget, authorization_confirmed=True,
    )
    strategy = DefaultCredentialsVerificationStrategy()
    conclusion = await strategy.verify(context)
    print(f"[Default Credentials] Status: {conclusion.status.value}, Confidence: {conclusion.confidence}")
    print(f"  Reason: {conclusion.reason_description}")
    assert conclusion.status == VerificationStatus.VERIFIED, f"Expected VERIFIED, got {conclusion.status.value}"
    print("  ✓ VERIFIED\n")


async def test_via_verification_engine():
    """Also validate through the full VerificationEngine pipeline (Finding -> strategy dispatch)."""
    engine = make_real_engine()
    ve = VerificationEngine()

    # Directory listing through engine pipeline
    finding_dir = Finding(
        id="find-C006", scan_id="scan-123", agent_id=1,
        title="Directory Listing", vuln_type="C006_Directory_Listing",
        category="Misconfiguration", severity="Low", confidence=80,
        affected_url="http://127.0.0.1:5005/files/",
        proof_request="GET /files/ HTTP/1.1\r\nHost: 127.0.0.1:5005\r\n\r\n",
        proof_response="Index of /files/",
        false_positive=False,
    )
    conclusion = await ve.verify_finding(finding_dir, engine, True)
    print(f"[Engine Pipeline - Dir Listing] Status: {conclusion.status.value}")
    print(f"  Reason: {conclusion.reason_description}")

    # Verbose error through engine pipeline
    finding_err = Finding(
        id="find-C054", scan_id="scan-123", agent_id=1,
        title="Verbose Error", vuln_type="C054_Verbose_Error_Disclosure",
        category="Misconfiguration", severity="Low", confidence=95,
        affected_url="http://127.0.0.1:5005/error-page",
        proof_request="GET /error-page?aihax_error_probe[]=x HTTP/1.1\r\nHost: 127.0.0.1:5005\r\n\r\n",
        proof_response="Traceback (most recent call last):",
        false_positive=False,
    )
    conclusion = await ve.verify_finding(finding_err, engine, True)
    print(f"[Engine Pipeline - Verbose Error] Status: {conclusion.status.value}")
    print(f"  Reason: {conclusion.reason_description}")

    # Default credentials through engine pipeline
    finding_cred = Finding(
        id="find-C012-Cred", scan_id="scan-123", agent_id=1,
        title="Default Credentials", vuln_type="C012_Default_Credentials",
        category="Authentication", severity="High", confidence=80,
        affected_url="http://127.0.0.1:5005/login",
        proof_request="POST /login HTTP/1.1\r\nHost: 127.0.0.1:5005\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=admin",
        proof_response="Welcome",
        false_positive=False,
    )
    conclusion = await ve.verify_finding(finding_cred, engine, True)
    print(f"[Engine Pipeline - Default Creds] Status: {conclusion.status.value}")
    print(f"  Reason: {conclusion.reason_description}")


async def main():
    print("=" * 70)
    print("BATCH B REAL-TARGET VALIDATION")
    print("=" * 70)
    
    await test_directory_listing()
    await test_verbose_error()
    await test_default_credentials()
    
    print("-" * 70)
    print("Testing through VerificationEngine pipeline:")
    print("-" * 70)
    await test_via_verification_engine()
    
    print("=" * 70)
    print("ALL 3 BATCH B STRATEGIES: VERIFIED ✓")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
