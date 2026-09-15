import pytest
from backend.recon.recon_tool_availability import ReconToolAvailability, ReconToolAvailabilityStatus

@pytest.mark.asyncio
async def test_internal_adapters_recognized():
    """Test that wayback, dns_recon, and http_probe are recognized as internal adapters."""
    availability = ReconToolAvailability()
    
    adapters = ["wayback", "dns_recon", "http_probe", "crtsh"]
    for adapter in adapters:
        res = await availability.diagnose_tool(adapter)
        assert res.implementation_type == "INTERNAL_ADAPTER"
        assert res.adapter is True
        assert res.installed is True
        assert res.status in (ReconToolAvailabilityStatus.AVAILABLE.value, ReconToolAvailabilityStatus.AUTH_REQUIRED.value)
        assert res.binary == "INTERNAL_ADAPTER"

@pytest.mark.asyncio
async def test_missing_adapter_not_available():
    """Test that a genuinely missing adapter is NOT incorrectly reported AVAILABLE."""
    availability = ReconToolAvailability()
    
    res = await availability.diagnose_tool("missing_fake_adapter")
    assert res.installed is False
    assert res.status == "NOT_IMPLEMENTED"
