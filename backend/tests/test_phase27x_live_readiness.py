import pytest
import asyncio
from unittest.mock import patch, MagicMock
from backend.execution.tool_execution_boundary import ToolExecutionBoundary, ToolExecutionRequest, ExecutionProfile, CapabilityClass
from backend.recon.live_recon_validator import LiveReconValidationEngine, ToolValidationStatus
from backend.recon.recon_tool_availability import ReconToolAvailability, ReconToolAvailabilityStatus

class TestPhase27xLiveReadinessNegativeControls:
    
    @pytest.fixture
    def boundary(self):
        def mock_runner(cmd, args, timeout):
            return 0, b"Mock version 1.0.0\n", b""
        return ToolExecutionBoundary(process_runner=mock_runner)
        
    @pytest.fixture
    def engine(self, boundary):
        return LiveReconValidationEngine(tool_boundary=boundary)

    @pytest.mark.asyncio
    async def test_a_missing_authorization_returns_auth_required(self, engine):
        # Tools with active capabilities should return AUTH_REQUIRED if no auth is explicitly proved
        with patch.object(engine.tool_availability, "resolve_binary_path", return_value="/bin/nmap"):
            res = await engine.tool_availability.diagnose_tool("nmap")
            assert res.status == ReconToolAvailabilityStatus.AUTH_REQUIRED.value
            
            res_dalfox = await engine.tool_availability.diagnose_tool("dalfox")
            assert res_dalfox.status == ReconToolAvailabilityStatus.AUTH_REQUIRED.value

    @pytest.mark.asyncio
    async def test_f_missing_capability_permission_blocked_policy(self, engine):
        # Ensure that if we run nmap/gobuster through validation without policy it yields BLOCKED_POLICY
        from backend.core.scope_validator import ScopeValidator
        sv = ScopeValidator()
        with patch.object(engine.tool_availability, "resolve_binary_path", return_value="/bin/nmap"):
            res = await engine._validate_nmap("mitacsc.ac.in", "mitacsc.ac.in", "CAMP-1", "AUTH-1", False, sv, "hash")
            assert res.status == ToolValidationStatus.BLOCKED_POLICY.value

        with patch.object(engine.tool_availability, "resolve_binary_path", return_value="/bin/gobuster"):
            res = await engine._validate_gobuster("mitacsc.ac.in", "CAMP-1", "AUTH-1", False, sv, "hash")
            assert res.status == ToolValidationStatus.BLOCKED_POLICY.value

    @pytest.mark.asyncio
    async def test_g_missing_human_approval_blocked(self, engine):
        # Nuclei and Dalfox should be NOT_SELECTED_RECON_ONLY when running recon validation
        with patch.object(engine.tool_availability, "resolve_binary_path", return_value="/bin/nuclei"):
            res = engine._validate_nuclei("mitacsc.ac.in", "CAMP-1", "AUTH-1", "hash")
            if asyncio.iscoroutine(res):
                res = await res
            assert res.status == ToolValidationStatus.NOT_SELECTED_RECON_ONLY.value

        with patch.object(engine.tool_availability, "resolve_binary_path", return_value="/bin/dalfox"):
            res = engine._validate_dalfox("mitacsc.ac.in", "CAMP-1", "AUTH-1", "hash")
            if asyncio.iscoroutine(res):
                res = await res
            assert res.status == ToolValidationStatus.NOT_SELECTED_RECON_ONLY.value

    @pytest.mark.asyncio
    async def test_n_diagnostic_never_live_validated(self, engine):
        tools = ["nmap", "gobuster", "nuclei", "dalfox"]
        with patch.object(engine.tool_availability, "resolve_binary_path", return_value="/bin/mock_tool"):
            for t in tools:
                res = await engine.tool_availability.diagnose_tool(t)
                assert res.status != ToolValidationStatus.LIVE_VALIDATED.value

    @pytest.mark.asyncio
    async def test_s_tool_execution_boundary_bypass_blocked(self, boundary):
        # Attempt to inject shell commands or use unknown tools
        req = ToolExecutionRequest(
            campaign_id="CAMP-1",
            target="mitacsc.ac.in",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            in_scope_assets=["mitacsc.ac.in"],
            args=["-d", "mitacsc.ac.in", ";", "id"]
        )
        res = await boundary.execute(req)
        assert res.execution_status == "BLOCKED_ARGUMENT"
        assert "Dangerous shell metacharacter" in res.error_category
