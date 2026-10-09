import pytest

from backend.services.zap_adapter import ZapAdapter, _scope_hosts


class NeverCalledClient:
    def __init__(self):
        self.calls = []

    async def run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {"status": "COMPLETED", "alerts": []}


@pytest.mark.asyncio
async def test_zap_adapter_blocks_target_outside_authorized_scope_before_api_call():
    client = NeverCalledClient()
    adapter = ZapAdapter(client=client)
    result = await adapter.scan(
        target_url="https://other.example/",
        in_scope_assets=["https://example.com"],
        out_of_scope_assets=[],
        authorization_confirmed=True,
        authorization_record_id="auth-1",
    )
    assert result["status"] == "BLOCKED_SCOPE"
    assert not client.calls


@pytest.mark.asyncio
async def test_zap_active_scan_requires_explicit_authorization_and_selection():
    client = NeverCalledClient()
    adapter = ZapAdapter(client=client)
    result = await adapter.scan(
        target_url="https://example.com/",
        in_scope_assets=["https://example.com"],
        out_of_scope_assets=[],
        authorization_confirmed=False,
        authorization_record_id=None,
        active_scan=True,
        tool_selected=True,
    )
    assert result["status"] == "BLOCKED_AUTHORIZATION"
    assert not client.calls


def test_zap_context_patterns_preserve_path_scope_and_wildcard_boundaries():
    included = _scope_hosts(["https://*.example.com/app"])[0]
    excluded = _scope_hosts(["https://admin.example.com/private"])[0]
    assert "example\\.com" in included
    assert "/app" in included
    assert "admin\\.example\\.com" in excluded
    assert "/private" in excluded
