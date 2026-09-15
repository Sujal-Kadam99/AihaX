from backend.services.verification_engine import (
    VerificationStatus,
    VerificationReasonCode,
    VerificationConclusion,
    BaseVerificationStrategy,
    VerificationContext,
    VerificationContract,
)
from backend.services.verification_strategies.request_builder import build_injected_request
import uuid
import re

class FileUploadVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies Dangerous File Uploads using a benign canary file.
    """
    
    contract = VerificationContract(
        check_id="C055_Dangerous_File_Upload",
        name="File Upload Verification",
        security_property="Server must restrict dangerous file extensions.",
        required_evidence_fields=["proof_request"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        if context.budget.max_requests <= 1:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description="Verification budget exhausted.",
            )

        injected_req = build_injected_request(candidate, "")
        if not injected_req:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="Could not reconstruct proof request.",
            )

        # Inject benign canary .php payload
        canary_id = str(uuid.uuid4())
        canary_content = f"<?php echo 'AihaX_Upload_Test_{canary_id}'; ?>"
        filename = f"test_{canary_id}.php"

        if injected_req.body and isinstance(injected_req.body, str) and "boundary=" in injected_req.headers.get("Content-Type", ""):
            # Simple multipart replacement
            injected_req.body = re.sub(
                r'filename="[^"]+"',
                f'filename="{filename}"',
                injected_req.body
            )
            # Inject content
            injected_req.body = re.sub(
                r'(\r\n\r\n)(.*?)(\r\n--)',
                f'\\1{canary_content}\\3',
                injected_req.body,
                flags=re.DOTALL
            )
        else:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="Proof request does not appear to be multipart/form-data or lacks clear boundaries.",
            )

        context.budget.max_requests -= 1
        response = await context.request_engine.execute(injected_req)
        
        ev_id_upload = context.record_evidence(
            evidence_type="file_upload_attempt",
            data={"status": response.status_code, "filename": filename},
            request_id=response.request_id,
        )

        if response.status_code not in (200, 201, 302):
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
                reason_description=f"Server rejected dangerous file upload (status {response.status_code}).",
                evidence_ids=[ev_id_upload],
                request_ids=[response.request_id],
                confidence=100,
            )

        # Attempt to find the uploaded file URL in the response
        upload_url = None
        match = re.search(r'(https?://[^"\'\s]+' + re.escape(filename) + r')', response.response_body or "")
        if match:
            upload_url = match.group(1)
        elif "/" in (response.response_body or ""):
            # Look for relative path
            rel_match = re.search(r'(/[^"\'\s]*?' + re.escape(filename) + r')', response.response_body or "")
            if rel_match:
                from urllib.parse import urljoin
                upload_url = urljoin(context.target_url, rel_match.group(1))

        if not upload_url:
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                reason_description=f"Upload accepted, but couldn't verify access URL. Manual check recommended.",
                evidence_ids=[ev_id_upload],
                request_ids=[response.request_id],
                confidence=80,
            )

        # Verify access
        from backend.services.request_engine import RequestSpec
        verify_spec = RequestSpec(url=upload_url, method="GET")
        context.budget.max_requests -= 1
        verify_response = await context.request_engine.execute(verify_spec)

        ev_id_access = context.record_evidence(
            evidence_type="file_access_attempt",
            data={"status": verify_response.status_code, "body": verify_response.response_body},
            request_id=verify_response.request_id,
        )

        if canary_id in (verify_response.response_body or ""):
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                reason_description=f"Canary file uploaded and executed successfully at {upload_url}",
                evidence_ids=[ev_id_upload, ev_id_access],
                request_ids=[response.request_id, verify_response.request_id],
                confidence=100,
            )

        return VerificationConclusion(
            status=VerificationStatus.VERIFIED,
            reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
            reason_description=f"File uploaded to {upload_url} but did not execute (status {verify_response.status_code}).",
            evidence_ids=[ev_id_upload, ev_id_access],
            request_ids=[response.request_id, verify_response.request_id],
            confidence=90,
        )
