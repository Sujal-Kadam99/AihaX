from types import SimpleNamespace

import pytest

from backend.services.vta_tool_adapters import VulnerabilityToolAdapters


class Boundary:
    def __init__(self, execution_status):
        self.execution_status = execution_status

    async def execute(self, request, db=None):
        return SimpleNamespace(
            execution_status=self.execution_status,
            tool_version="test-version",
            sanitized_args=request.args,
            timeout_seconds=request.timeout_seconds,
            exit_code=0 if self.execution_status == "SUCCESS" else None,
            parsed_summary={},
            stdout_hash=None,
            stderr_hash=None,
            output_hash="evidence-hash" if self.execution_status == "SUCCESS" else None,
            error_category=None if self.execution_status == "SUCCESS" else "blocked by safety gate",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("execution_status", "expected_status", "executed"),
    [("SUCCESS", "COMPLETED", True), ("BLOCKED_SAFETY", "BLOCKED_SAFETY", False)],
)
async def test_cli_adapter_returns_execution_and_evidence_status(execution_status, expected_status, executed):
    adapter = VulnerabilityToolAdapters(boundary=Boundary(execution_status))
    result = await adapter.run(
        name="nikto",
        target_url="https://example.com",
        hypotheses=[SimpleNamespace(hypothesis_id="hyp-1", check_id="C002", endpoint="https://example.com", parameter=None)],
        campaign_id="fixture",
        authorization_confirmed=True,
        in_scope_assets=["https://example.com"],
        out_of_scope_assets=[],
        rate_limit_rps=1,
        max_requests=5,
    )

    assert result["status"] == expected_status
    assert result["executed"] is executed
    assert result["evidence_hash"] == ("evidence-hash" if executed else None)
