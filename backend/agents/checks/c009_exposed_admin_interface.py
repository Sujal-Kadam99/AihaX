"""C009 — Exposed Administrative Interface Check for AihaX."""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlparse

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C009ExposedAdminInterface(BaseCheck):
    contract = CheckContract(
        id="C009_Exposed_Admin_Interface",
        name="Exposed Administrative Interface",
        category=CheckCategory.RECON,
        description="Detects publicly accessible administration panels, management consoles, and dashboard interfaces that should be restricted to internal networks.",
        severity=Severity.MEDIUM,
        vulnerability_type="Exposed Interface",
        cwe="CWE-200",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Administrative and management consoles must not be publicly exposed without network access controls",
        remediation_guidance="Restrict administrative endpoints using IP whitelisting, VPN access controls, or strong multi-factor authentication.",
        references=[
            "https://cwe.mitre.org/data/definitions/200.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
        ],
        verification_strategy="sensitive_file_exposure",
        required_evidence=["affected_url", "proof_response", "admin_marker"],
        destructive=False,
    )

    ADMIN_PATHS = [
        ("/admin/", ["admin login", "dashboard", "administration", "django administration", "control panel"]),
        ("/administrator/", ["joomla! administration", "administrator login"]),
        ("/wp-admin/", ["wordpress", "wp-login.php", "wp-submit"]),
        ("/manager/html", ["tomcat web application manager", "tomcat manager"]),
        ("/actuator", ["_links", "self", "health"]),
        ("/actuator/health", ["\"status\":\"UP\"", "\"status\":\"DOWN\""]),
        ("/kibana", ["kibana", "kbn-name"]),
        ("/cpanel", ["cpanel", "webhost manager"]),
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")

        fallback_candidate: Optional[CheckResult] = None

        for path, markers in self.ADMIN_PATHS:
            test_url = urljoin(base + "/", path.lstrip("/"))
            spec = RequestSpec(
                url=test_url,
                method="GET",
                follow_redirects=True,
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )

            resp_evidence = await request_engine.execute(spec)
            if not resp_evidence.success:
                continue

            status = resp_evidence.response_status
            body = (resp_evidence.response_body or "").lower()

            # Candidate finding: 200 OK or 401 Unauthorized (confirming existence of basic-auth admin panel)
            if status in (200, 401):
                matched_marker = next((m for m in markers if m in body), None)
                # Unauthenticated administrative panel / metrics exposure vs protected prompt
                is_unauthenticated_panel = status == 200 and matched_marker in ("_links", "self", "health", "\"status\":\"up\"", "\"status\":\"down\"", "kibana", "dashboard", "control panel")
                if matched_marker or status == 401:
                    proof_info = f"HTTP {status} at {test_url}" + (f" - Marker: '{matched_marker}'" if matched_marker else " - Auth Required Header")
                    candidate = CheckResult(
                        check_id=self.contract.id,
                        title=self.contract.name,
                        target=target_url,
                        affected_url=test_url,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.HIGH if is_unauthenticated_panel else Severity.LOW,
                        candidate_reason=f"Publicly accessible administrative interface identified at '{test_url}' (HTTP {status})." + (" (Unauthenticated console access)" if is_unauthenticated_panel else " (Authentication required)"),
                        request_ids=[resp_evidence.request_id],
                        evidence_ids=[resp_evidence.evidence_id],
                        observed_data={
                            "path": path,
                            "status": status,
                            "matched_marker": matched_marker,
                            "unauthenticated_panel": is_unauthenticated_panel,
                        },
                        payload=None,
                        proof_response=proof_info,
                        confidence=90 if is_unauthenticated_panel else 70,
                        verification_status="CANDIDATE",
                    )
                    if is_unauthenticated_panel:
                        return candidate
                    elif fallback_candidate is None:
                        fallback_candidate = candidate

        return fallback_candidate


# Register check
registry.register(C009ExposedAdminInterface)
