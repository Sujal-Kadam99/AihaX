"""C071 — Privilege Escalation Indicators Check for AihaX."""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urljoin

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import AuthenticationContext, RequestEngine, RequestSpec, RequestTimeout


class C071PrivilegeEscalation(BaseCheck):
    contract = CheckContract(
        id="C071_Privilege_Escalation",
        name="Privilege Escalation Indicators",
        category=CheckCategory.BUSINESS_LOGIC,
        description="Detects vertical privilege escalation vulnerabilities where administrative API routes (/api/admin/users, /api/admin/settings) are accessible to standard unprivileged user tokens.",
        severity=Severity.CRITICAL,
        vulnerability_type="Broken Access Control",
        cwe="CWE-269",
        owasp_category="A01:2021-Broken Access Control",
        security_property="Administrative API endpoints must enforce role-based access control (RBAC) and reject non-admin identities",
        remediation_guidance="Enforce centralized authorization middleware (e.g. @has_role('ADMIN')) across all administrative controllers.",
        references=[
            "https://cwe.mitre.org/data/definitions/269.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
        ],
        verification_strategy="authorization_comparison",
        required_evidence=["affected_url", "proof_response", "unauthorized_access_proof"],
        destructive=False,
    )

    ADMIN_ROUTES = [
        "/api/admin/users",
        "/api/admin/settings",
        "/api/admin/config",
        "/api/v1/admin/dashboard",
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        auth_token = config.get("user_token") or config.get("auth_token")
        auth_ctx = None
        if auth_token:
            auth_ctx = AuthenticationContext(
                name="StandardUserAuth",
                headers={"Authorization": f"Bearer {auth_token}"},
            )

        base = target_url.rstrip("/")
        for route in self.ADMIN_ROUTES:
            admin_url = urljoin(base + "/", route.lstrip("/"))
            spec = RequestSpec(
                url=admin_url,
                method="GET",
                auth_context=auth_ctx,
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            resp = await request_engine.execute(spec)
            if not resp.success:
                continue

            # If an admin route responds 200 OK with data when invoked by standard/unauthenticated user
            if resp.response_status == 200 and len(resp.response_body or "") > 30:
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=admin_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.CRITICAL,
                    candidate_reason=f"Privileged administrative endpoint '{admin_url}' returned HTTP 200 OK without verifying admin role privileges.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"admin_url": admin_url, "status": resp.response_status},
                    payload=None,
                    proof_response=f"Admin Route Returned HTTP 200: {(resp.response_body or '')[:150]}",
                    confidence=85,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C071PrivilegeEscalation)
