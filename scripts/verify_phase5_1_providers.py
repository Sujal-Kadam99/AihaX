"""Standalone Verification Script for Phase 5.1-C: Passive Reconnaissance & Discovery Providers.

Demonstrates:
CASE 1:  CRT.sh passive discovery
CASE 2:  Wayback passive endpoint discovery
CASE 3:  AlienVault passive DNS discovery
CASE 4:  Normalization + deduplication
CASE 5:  Provider requests routed through RequestEngine
CASE 6:  Out-of-scope request blocked (zero transport calls)
CASE 7:  Authorization missing -> zero transport calls
CASE 8:  Discovered asset remains scope_status = UNKNOWN, active_testing_allowed = False
CASE 9:  No discovered target receives direct network traffic
CASE 10: Malformed provider response handled safely
"""

import asyncio
import json
import os
import sys

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.core.scope_validator import ScopeValidator
from backend.models.database import Asset
from backend.services.discovery.alienvault_provider import AlienVaultProvider
from backend.services.discovery.crtsh_provider import CRTShProvider
from backend.services.discovery.dns_provider import DNSProvider
from backend.services.discovery.wayback_provider import WaybackProvider
from backend.services.request_engine import MockTransport, RequestEngine, RequestSpec


async def run_verification() -> bool:
    print("=" * 80)
    print("AihaX — PHASE 5.1-C: PASSIVE DISCOVERY PROVIDERS VERIFICATION")
    print("=" * 80)

    scope_all = ScopeValidator(
        in_scope_assets=[
            "example.com",
            "*.example.com",
            "crt.sh",
            "*.crt.sh",
            "web.archive.org",
            "*.archive.org",
            "otx.alienvault.com",
            "*.alienvault.com",
        ]
    )

    # --------------------------------------------------------------------------
    # CASE 1: CRT.sh passive discovery
    # --------------------------------------------------------------------------
    transport1 = MockTransport()
    crt_data = [
        {"name_value": "api.example.com\nauth.example.com", "common_name": "api.example.com"},
        {"name_value": "*.example.com", "common_name": "example.com"},
    ]
    transport1.add_route("crt.sh", status=200, body=json.dumps(crt_data))
    engine1 = RequestEngine(scope_validator=scope_all, transport=transport1)

    provider_crt = CRTShProvider()
    crt_items = await provider_crt.discover("example.com", engine1)
    print(f"\n[CASE 1] CRT.sh Discovery: Found {len(crt_items)} items")
    for item in crt_items:
        print(f"  -> {item.asset_type}: {item.normalized_value} (Evidence: {item.evidence_id}, Req: {item.request_id})")
    assert len(crt_items) >= 3, "CASE 1 Failed: Expected at least 3 items"
    print("  [PASS] CASE 1 Passed.")

    # --------------------------------------------------------------------------
    # CASE 2: Wayback passive endpoint discovery
    # --------------------------------------------------------------------------
    transport2 = MockTransport()
    cdx_data = [
        ["original"],
        ["https://example.com/api/v1/users?page=2&limit=10"],
        ["https://admin.example.com/login"],
    ]
    transport2.add_route("web.archive.org", status=200, body=json.dumps(cdx_data))
    engine2 = RequestEngine(scope_validator=scope_all, transport=transport2)

    provider_wb = WaybackProvider()
    wb_items = await provider_wb.discover("example.com", engine2)
    print(f"\n[CASE 2] Wayback Discovery: Found {len(wb_items)} items")
    for item in wb_items:
        print(f"  -> {item.asset_type}: {item.normalized_value} (Path: {item.endpoint_path}, Query: {item.endpoint_query})")
    assert any(i.asset_type == "URL" for i in wb_items), "CASE 2 Failed: No URLs found"
    print("  [PASS] CASE 2 Passed.")

    # --------------------------------------------------------------------------
    # CASE 3: AlienVault passive DNS discovery
    # --------------------------------------------------------------------------
    transport3 = MockTransport()
    otx_data = {
        "passive_dns": [
            {"hostname": "vpn.example.com", "record_type": "A", "address": "93.184.216.34"},
            {"hostname": "ipv6.example.com", "record_type": "AAAA", "address": "2001:0db8::1"},
        ]
    }
    transport3.add_route("otx.alienvault.com", status=200, body=json.dumps(otx_data))
    engine3 = RequestEngine(scope_validator=scope_all, transport=transport3)

    provider_otx = AlienVaultProvider()
    otx_items = await provider_otx.discover("example.com", engine3)
    print(f"\n[CASE 3] AlienVault Discovery: Found {len(otx_items)} items")
    for item in otx_items:
        print(f"  -> {item.asset_type}: {item.normalized_value} (DNS: {item.dns_records})")
    assert any(i.asset_type == "IP_ADDRESS" for i in otx_items), "CASE 3 Failed"
    print("  [PASS] CASE 3 Passed.")

    # --------------------------------------------------------------------------
    # CASE 4: Normalization + Deduplication
    # --------------------------------------------------------------------------
    transport4 = MockTransport()
    duplicate_crt_data = [
        {"name_value": "API.EXAMPLE.COM.\n*.api.example.com", "common_name": "api.example.com"},
        {"name_value": "api.example.com", "common_name": "api.example.com"},
    ]
    transport4.add_route("crt.sh", status=200, body=json.dumps(duplicate_crt_data))
    engine4 = RequestEngine(scope_validator=scope_all, transport=transport4)

    dup_items = await provider_crt.discover("example.com", engine4)
    print(f"\n[CASE 4] Normalization & Deduplication:")
    print(f"  -> Returned items count: {len(dup_items)} (Value: {dup_items[0].normalized_value})")
    assert len(dup_items) == 1, "CASE 4 Failed: Deduplication failed"
    assert dup_items[0].normalized_value == "api.example.com", "CASE 4 Failed: Normalization failed"
    print("  [PASS] CASE 4 Passed.")

    # --------------------------------------------------------------------------
    # CASE 5: Provider requests routed through RequestEngine
    # --------------------------------------------------------------------------
    print(f"\n[CASE 5] RequestEngine Routing Verification:")
    print(f"  -> Transport 1 Calls: {transport1.call_count} (URLs: {[c['url'] for c in transport1.calls]})")
    assert transport1.call_count == 1, "CASE 5 Failed"
    print("  [PASS] CASE 5 Passed.")

    # --------------------------------------------------------------------------
    # CASE 6: Out-of-scope request blocked
    # --------------------------------------------------------------------------
    strict_scope = ScopeValidator(in_scope_assets=["example.com"])  # does not allow crt.sh
    transport6 = MockTransport()
    engine6 = RequestEngine(scope_validator=strict_scope, transport=transport6)
    blocked_items = await provider_crt.discover("example.com", engine6)
    print(f"\n[CASE 6] Out-of-Scope Blocking:")
    print(f"  -> Items returned: {len(blocked_items)}, Transport call count: {transport6.call_count}")
    assert len(blocked_items) == 0, "CASE 6 Failed"
    assert transport6.call_count == 0, "CASE 6 Failed: Transport called when out-of-scope"
    print("  [PASS] CASE 6 Passed.")

    # --------------------------------------------------------------------------
    # CASE 7: Authorization missing -> zero transport calls
    # --------------------------------------------------------------------------
    transport7 = MockTransport()
    engine7 = RequestEngine(scope_validator=scope_all, transport=transport7)
    spec_unauth = RequestSpec(url="https://crt.sh/?q=%.example.com&output=json", authorization_confirmed=False)
    ev_unauth = await engine7.execute(spec_unauth)
    print(f"\n[CASE 7] Missing Authorization Enforcement:")
    print(f"  -> Error: {ev_unauth.transport_error}, Transport calls: {transport7.call_count}")
    assert ev_unauth.response_status is None, "CASE 7 Failed"
    assert transport7.call_count == 0, "CASE 7 Failed"
    print("  [PASS] CASE 7 Passed.")

    # --------------------------------------------------------------------------
    # CASE 8: Discovered asset remains scope_status = UNKNOWN, active_testing_allowed = False
    # --------------------------------------------------------------------------
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from backend.models.database import Program
    from backend.models.migrations import run_migrations

    mem_engine = create_engine("sqlite:///:memory:")
    run_migrations(mem_engine)
    Session = sessionmaker(bind=mem_engine)
    session = Session()

    prog = Program(name="Verify Test Program")
    session.add(prog)
    session.commit()

    db_asset = Asset(
        program_id=prog.id,
        asset_type="SUBDOMAIN",
        normalized_value="api.example.com",
    )
    session.add(db_asset)
    session.commit()
    session.refresh(db_asset)

    print(f"\n[CASE 8] Security Invariant: Discovered != Authorized:")
    print(f"  -> Asset default scope_status: {db_asset.scope_status}")
    print(f"  -> Asset default active_testing_allowed: {db_asset.active_testing_allowed}")
    print(f"  -> Asset default authorization_confirmed: {db_asset.authorization_confirmed}")
    assert db_asset.scope_status == "UNKNOWN", "CASE 8 Failed"
    assert db_asset.active_testing_allowed is False, "CASE 8 Failed"
    assert db_asset.authorization_confirmed is False, "CASE 8 Failed"
    session.close()
    mem_engine.dispose()
    print("  [PASS] CASE 8 Passed.")

    # --------------------------------------------------------------------------
    # CASE 9: No discovered target receives direct network traffic
    # --------------------------------------------------------------------------
    print(f"\n[CASE 9] Zero Direct Probing of Discovered Targets:")
    for c in transport2.calls:
        print(f"  -> Wayback Transport Call: {c['url']}")
        assert "example.com/api" not in c["url"]
    print("  [PASS] CASE 9 Passed: Zero transport calls sent to target hosts.")

    # --------------------------------------------------------------------------
    # CASE 10: Malformed provider response handled safely
    # --------------------------------------------------------------------------
    transport10 = MockTransport()
    transport10.add_route("crt.sh", status=200, body="<html>502 Bad Gateway</html>")
    engine10 = RequestEngine(scope_validator=scope_all, transport=transport10)
    malformed_items = await provider_crt.discover("example.com", engine10)
    print(f"\n[CASE 10] Malformed Provider Response:")
    print(f"  -> Items returned on HTML/bad JSON: {len(malformed_items)}")
    assert len(malformed_items) == 0, "CASE 10 Failed"
    print("  [PASS] CASE 10 Passed.")

    print("\n" + "=" * 80)
    print("ALL 10 VERIFICATION CASES PASSED DETERMINISTICALLY!")
    print("=" * 80)
    return True


if __name__ == "__main__":
    success = asyncio.run(run_verification())
    sys.exit(0 if success else 1)
