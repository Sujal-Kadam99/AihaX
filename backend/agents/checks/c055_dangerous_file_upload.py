"""C055 — Dangerous File Upload Permitted Check for AihaX."""

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
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C055DangerousFileUpload(BaseCheck):
    contract = CheckContract(
        id="C055_Dangerous_File_Upload",
        name="Dangerous File Upload Permitted",
        category=CheckCategory.MISCONFIG,
        description="Detects unvalidated file upload handlers that accept executable file extensions (.php, .jsp, .asp, .html) without extension filtering or content validation.",
        severity=Severity.HIGH,
        vulnerability_type="Unrestricted File Upload",
        cwe="CWE-434",
        owasp_category="A04:2021-Insecure Design",
        security_property="File upload handlers must validate file extensions against a strict allowlist and store files outside execution roots",
        remediation_guidance="Enforce an allowlist of permitted non-executable extensions (e.g. .jpg, .png, .pdf), validate MIME headers, and store uploads in isolated object storage.",
        references=[
            "https://cwe.mitre.org/data/definitions/434.html",
            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "accepted_extension"],
        destructive=False,
    )

    UPLOAD_PATHS = ["/api/upload", "/upload", "/api/v1/upload", "/file/upload", "/api/files"]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")
        boundary = "----AihaxBoundaryUploadCanary123"
        # Harmless non-executable text payload simulating a .php upload attempt
        multipart_body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="aihax_audit_test.php"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
            f"aihax_upload_harmless_canary_test\r\n"
            f"--{boundary}--\r\n"
        )

        for path in self.UPLOAD_PATHS:
            upload_url = urljoin(base + "/", path.lstrip("/"))
            spec = RequestSpec(
                url=upload_url,
                method="POST",
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                body=multipart_body,
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            resp = await request_engine.execute(spec)
            if not resp.success:
                continue

            # If the server accepts the upload with 200/201 and mentions success or filename
            if resp.response_status in (200, 201) and ("aihax_audit_test.php" in (resp.response_body or "") or "success" in (resp.response_body or "").lower()):
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=upload_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.HIGH,
                    candidate_reason=f"Upload endpoint '{upload_url}' accepted an executable extension (.php) with HTTP {resp.response_status}.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"upload_url": upload_url, "status": resp.response_status},
                    payload='filename="aihax_audit_test.php"',
                    proof_response=f"Upload Accepted: HTTP {resp.response_status} with body: {(resp.response_body or '')[:150]}",
                    confidence=85,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C055DangerousFileUpload)
