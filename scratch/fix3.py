import sys

with open('backend/tests/test_phase26_tool_validation.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

with open('scratch/fix3.py', 'w', encoding='utf-8') as f:
    f.writelines(lines[:113])
    f.write('    @patch("backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path", return_value=None)\n')
    f.write('    @pytest.mark.asyncio\n')
    f.write('    async def test_binary_missing_returns_binary_unavailable(self, mock_resolve):\n')
    f.write('        """When binary is absent, diagnostics must report BINARY_UNAVAILABLE (no fake success)."""\n')
    f.write('        diag = ReconToolAvailability()\n')
    f.write('        res = await diag.diagnose_tool("subfinder")\n')
    f.write('        # In current environment, subfinder CLI is not installed\n')
    f.write('        assert res.installed is False\n')
    f.write('        assert res.status == ReconToolAvailabilityStatus.BINARY_UNAVAILABLE.value\n')
    f.write('        assert res.execution_supported is False\n')
    f.writelines(lines[123:])
    @patch("backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path", return_value=None)
    @pytest.mark.asyncio
    async def test_binary_missing_returns_binary_unavailable(self, mock_resolve):
        """When binary is absent, diagnostics must report BINARY_UNAVAILABLE (no fake success)."""
        diag = ReconToolAvailability()
        res = await diag.diagnose_tool("subfinder")
        # In current environment, subfinder CLI is not installed
        assert res.installed is False
        assert res.status == ReconToolAvailabilityStatus.BINARY_UNAVAILABLE.value
        assert res.execution_supported is False
