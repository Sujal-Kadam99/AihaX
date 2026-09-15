import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from backend.services.orchestrator import _run_with_retry
from backend.agents.base_agent import BaseAgent, ScanCancelledException

class DummyAgent(BaseAgent):
    def __init__(self, should_fail_times=0):
        super().__init__(scan_id="test_scan", db=MagicMock(), config={})
        self.should_fail_times = should_fail_times
        self.attempts = 0
        self.run_called = False

    async def execute(self):
        self.attempts += 1
        if self.attempts <= self.should_fail_times:
            raise Exception("Temporary failure")
        self.run_called = True

@pytest.mark.asyncio
async def test_run_with_retry_success():
    agent = DummyAgent(should_fail_times=0)
    await _run_with_retry(agent, max_retries=2)
    assert agent.run_called
    assert agent.attempts == 1

@pytest.mark.asyncio
async def test_run_with_retry_recovers():
    # Fails twice, succeeds on 3rd attempt (attempt 0, 1, 2)
    agent = DummyAgent(should_fail_times=2)
    with patch("asyncio.sleep", new_callable=AsyncMock):
        await _run_with_retry(agent, max_retries=2)
    assert agent.run_called
    assert agent.attempts == 3

@pytest.mark.asyncio
async def test_run_with_retry_fails():
    agent = DummyAgent(should_fail_times=3)
    with patch("asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(Exception):
            await _run_with_retry(agent, max_retries=2)
    assert not agent.run_called
    assert agent.attempts == 3

@pytest.mark.asyncio
async def test_run_with_retry_cancelled():
    class CancelAgent(BaseAgent):
        def __init__(self):
            super().__init__(scan_id="test_scan", db=MagicMock(), config={})
            
        async def execute(self):
            raise ScanCancelledException("Cancelled")
            
    agent = CancelAgent()
    with pytest.raises(ScanCancelledException):
        await _run_with_retry(agent, max_retries=2)
