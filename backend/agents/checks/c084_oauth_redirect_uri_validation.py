"""C084 — OAuth/SSO Redirect URI Validation Weakness Check for AihaX."""

from __future__ import annotations

from typing import Any, Dict, Optional
import urllib.parse

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C084OAuthRedirectURIValidation(BaseCheck):
    contract = CheckContract(
        id="C084_OAuth_Redirect_URI_Validation",
        name="OAuth/SSO Redirect URI Validation Weakness",
        category=CheckCategory.AUTH,
        description="Detects OAuth 2.0 authorization endpoints accepting arbitrary, wildcard, or unvalidated redirect_uri parameters.",
        severity=Severity.HIGH,
        vulnerability_type="OAuth Redirect URI Validation Flaw",
        cwe="CWE-601",
        owasp_category="A01:2021-Broken Access Control",
        security_property="OAuth authorization servers must strictly validate redirect_uri against pre-registered exact URI allowlists.",
        remediation_guidance="Enforce exact string matching for redirect_uri parameters and reject subdomains, path traversals, or open redirects.",
        references=["https://portswigger.net/web-security/oauth"],
        verification_strategy="oauth_redirect_uri",
        required_evidence=["affected_url", "proof_request"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        oauth_path = any(token in parsed.path.lower() for token in ("oauth", "authorize", "/connect/"))
        oauth_query = "client_id" in params and "response_type" in params
        if not (oauth_path or oauth_query):
            # Do not probe an ordinary application root and infer an OAuth issue from
            # its generic single-page-app response.
            return None
        
        # Test if target is an OAuth authorization endpoint or has redirect_uri
        untrusted_redirect = "https://evil-oauth-receiver.test/callback"
        if "redirect_uri" in params or "oauth" in parsed.path.lower() or "auth" in parsed.path.lower():
            params["redirect_uri"] = [untrusted_redirect]
            if "client_id" not in params:
                params["client_id"] = ["aihax_client_test"]
            if "response_type" not in params:
                params["response_type"] = ["code"]
            
            new_query = urllib.parse.urlencode(params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        else:
            test_url = f"{target_url}?client_id=aihax_client_test&response_type=code&redirect_uri={urllib.parse.quote(untrusted_redirect)}"

        spec = RequestSpec(
            url=test_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        resp_evidence = await request_engine.execute(spec)
        if not resp_evidence.success:
            return None

        status = resp_evidence.response_status
        location = resp_evidence.response_headers.get("location", "")

        # If server redirected to untrusted URI or presented authorization dialog without rejecting redirect_uri
        if untrusted_redirect in location or (
            status in (200, 302)
            and "application/json" in next(
                (value for key, value in resp_evidence.response_headers.items() if key.lower() == "content-type"),
                "",
            ).lower()
            and "invalid_request" not in location
            and "invalid_redirect" not in (resp_evidence.response_body or "")
        ):
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=test_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=self.contract.severity,
                candidate_reason=f"OAuth endpoint accepted untrusted redirect_uri '{untrusted_redirect}' without immediate 400 rejection.",
                request_ids=[resp_evidence.request_id],
                evidence_ids=[resp_evidence.evidence_id],
                observed_data={
                    "untrusted_redirect": untrusted_redirect,
                    "location_header": location,
                    "status": status,
                },
                payload=f"redirect_uri={untrusted_redirect}",
                proof_request=f"GET {test_url} HTTP/1.1",
                proof_response=f"HTTP/1.1 {status}\r\nLocation: {location}",
                confidence=75,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C084OAuthRedirectURIValidation)
