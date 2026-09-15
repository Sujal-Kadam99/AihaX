"""Verbose Error / Stack Trace Disclosure Verification Strategy.

Replays a malformed request to the affected endpoint and checks if the
response contains stack trace patterns, framework version strings, or
file path disclosures.
"""

import re
from backend.services.verification_engine import (
    VerificationStatus,
    VerificationReasonCode,
    VerificationConclusion,
    BaseVerificationStrategy,
    VerificationContext,
    VerificationContract,
)
from backend.services.request_engine import RequestSpec, RequestTimeout


class VerboseErrorVerificationStrategy(BaseVerificationStrategy):
    """
    Dedicated verification strategy for C054 Verbose Error / Stack Trace findings.

    Sends a request designed to trigger error responses (malformed query params,
    invalid types) and checks for stack trace patterns in the response body.
    """

    contract = VerificationContract(
        check_id="C054_Verbose_Error_Disclosure",
        name="Verbose Error / Stack Trace Verification",
        security_property="Production applications must suppress detailed exception traces.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    STACK_PATTERNS = [
        ("Python Traceback", re.compile(r"Traceback \(most recent call last\):", re.I)),
        ("Java Stack Trace", re.compile(r"java\.lang\.[a-zA-Z0-9_]+Exception:", re.I)),
        ("Java Catalina Trace", re.compile(r"at org\.apache\.catalina\.", re.I)),
        ("ASP.NET Error", re.compile(r"Server Error in '/' Application\.|Microsoft .NET Framework", re.I)),
        ("PHP Fatal Error", re.compile(r"Fatal error:\s*Uncaught exception|Warning:.*on line \d+", re.I)),
        ("Django Debug Page", re.compile(r"You're seeing this error because you have <code>DEBUG = True</code>", re.I)),
        ("Flask Debug Traceback", re.compile(r"Traceback.*File\s+\".*\.py\",\s+line\s+\d+", re.I | re.S)),
        ("File Path Disclosure", re.compile(r"(?:[A-Z]:\\|/(?:home|var|usr|opt|srv)/)[^\s<>\"']+\.(?:py|php|rb|java|cs|js)", re.I)),
    ]

    # Error-triggering payloads (benign, non-destructive)
    ERROR_PROBES = [
        "?aihax_error_probe[]=invalid_array_type",
        "?id=1%27",  # SQL-like quote to trigger error
        "?__debug__=1",
    ]

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        if context.budget.max_requests <= 0:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description="Verification budget exhausted.",
            )

        affected_url = candidate.get("affected_url") or context.target_url
        base_url = affected_url.split("?")[0]  # Strip existing query params

        for probe in self.ERROR_PROBES:
            if context.budget.max_requests <= 0:
                break

            test_url = f"{base_url}{probe}"
            spec = RequestSpec(
                url=test_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )

            context.budget.max_requests -= 1
            response = await context.request_engine.execute(spec)

            if not response.success:
                continue

            body = response.response_body or ""
            for frame_name, pattern in self.STACK_PATTERNS:
                match = pattern.search(body)
                if match:
                    snippet = body[max(0, match.start() - 30):min(len(body), match.end() + 100)]
                    snippet = snippet.replace("\n", " ").replace("\r", " ")[:200]

                    ev_id = context.record_evidence(
                        evidence_type="verbose_error_verified",
                        data={
                            "frame_name": frame_name,
                            "probe": probe,
                            "status": response.response_status,
                            "snippet": snippet,
                        },
                        request_id=response.request_id,
                    )

                    return VerificationConclusion(
                        status=VerificationStatus.VERIFIED,
                        reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                        reason_description=(
                            f"Verbose error disclosure confirmed: {frame_name} leaked "
                            f"at '{test_url}'. Snippet: {snippet[:100]}..."
                        ),
                        evidence_ids=[ev_id],
                        request_ids=[response.request_id],
                        confidence=95,
                    )

        # No stack trace found across all probes
        ev_id = context.record_evidence(
            evidence_type="verbose_error_not_found",
            data={"probes_tested": len(self.ERROR_PROBES)},
            request_id="N/A",
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description="No stack trace or verbose error disclosure observed across error-triggering probes.",
            evidence_ids=[ev_id],
            confidence=100,
        )
