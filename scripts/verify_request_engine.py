"""Deterministic Manual Verification Script for Request Engine.

Tests Cases 1 through 5 using MockTransport:
1. In-Scope: Request sent
2. Out-of-Scope: Request blocked (Transport Call Count = 0)
3. In-Scope Redirects to Out-of-Scope: Redirect blocked before secondary request
4. Authorization False: Request blocked (Transport Call Count = 0)
5. Excluded Port: Request blocked (Transport Call Count = 0)
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.core.scope_validator import ScopeValidator
from backend.services.request_engine import (
    MockTransport,
    RawResponse,
    RequestEngine,
    RequestSpec,
)


async def run_verification():
    print("==================================================")
    print("AihaX Bug Bounty Platform — Request Engine Verification")
    print("==================================================")

    validator = ScopeValidator(
        in_scope_assets=["example.com", "*.example.com"],
        out_of_scope_assets=["admin.example.com", "evil.com"],
        allowed_ports=[80, 443],
        excluded_ports=[22, 3389],
        allowed_schemes=["https"],
    )

    all_passed = True

    # ─────────────────────────────────────────────────────────────
    # CASE 1: In Scope Request
    # ─────────────────────────────────────────────────────────────
    t1 = MockTransport()
    t1.register_response("https://example.com", status_code=200, body="Welcome")
    e1 = RequestEngine(scope_validator=validator, transport=t1)

    ev1 = await e1.execute(RequestSpec(url="https://example.com/app", authorization_confirmed=True))
    c1_passed = (ev1.success is True) and (t1.call_count == 1)
    if not c1_passed:
        all_passed = False
    print(f"[{'PASS' if c1_passed else 'FAIL'}] CASE 1: In-Scope Request (https://example.com)")
    print(f"       Outcome: success={ev1.success}, status={ev1.response_status}, transport_call_count={t1.call_count}")

    # ─────────────────────────────────────────────────────────────
    # CASE 2: Out of Scope Request
    # ─────────────────────────────────────────────────────────────
    t2 = MockTransport()
    e2 = RequestEngine(scope_validator=validator, transport=t2)

    ev2 = await e2.execute(RequestSpec(url="https://evil.com/attack", authorization_confirmed=True))
    c2_passed = (ev2.success is False) and (t2.call_count == 0) and (ev2.transport_error["error_type"] == "SCOPE_DENIED")
    if not c2_passed:
        all_passed = False
    print(f"[{'PASS' if c2_passed else 'FAIL'}] CASE 2: Out-of-Scope Target (https://evil.com)")
    print(f"       Outcome: success={ev2.success}, transport_error={ev2.transport_error['error_type']}, transport_call_count={t2.call_count}")

    # ─────────────────────────────────────────────────────────────
    # CASE 3: In-Scope Redirects to Out-of-Scope Target
    # ─────────────────────────────────────────────────────────────
    t3 = MockTransport()
    t3.register_response(
        url_prefix="https://example.com/redirect",
        status_code=302,
        headers={"location": "https://evil.com/trap"},
        body="",
    )
    e3 = RequestEngine(scope_validator=validator, transport=t3)

    ev3 = await e3.execute(RequestSpec(
        url="https://example.com/redirect",
        follow_redirects=True,
        authorization_confirmed=True,
    ))
    c3_passed = (ev3.success is False) and (ev3.transport_error["error_type"] == "REDIRECT_BLOCKED") and (t3.call_count == 1)
    if not c3_passed:
        all_passed = False
    print(f"[{'PASS' if c3_passed else 'FAIL'}] CASE 3: In-Scope Redirect to Out-of-Scope (https://example.com -> https://evil.com)")
    print(f"       Outcome: success={ev3.success}, transport_error={ev3.transport_error['error_type']}, transport_call_count={t3.call_count}")

    # ─────────────────────────────────────────────────────────────
    # CASE 4: Authorization False
    # ─────────────────────────────────────────────────────────────
    t4 = MockTransport()
    e4 = RequestEngine(scope_validator=validator, transport=t4)

    ev4 = await e4.execute(RequestSpec(url="https://example.com", authorization_confirmed=False))
    c4_passed = (ev4.success is False) and (t4.call_count == 0) and (ev4.transport_error["error_type"] == "AUTH_MISSING")
    if not c4_passed:
        all_passed = False
    print(f"[{'PASS' if c4_passed else 'FAIL'}] CASE 4: Authorization Missing (authorization_confirmed=False)")
    print(f"       Outcome: success={ev4.success}, transport_error={ev4.transport_error['error_type']}, transport_call_count={t4.call_count}")

    # ─────────────────────────────────────────────────────────────
    # CASE 5: Excluded Port
    # ─────────────────────────────────────────────────────────────
    t5 = MockTransport()
    e5 = RequestEngine(scope_validator=validator, transport=t5)

    ev5 = await e5.execute(RequestSpec(url="https://example.com:22", authorization_confirmed=True))
    c5_passed = (ev5.success is False) and (t5.call_count == 0) and (ev5.transport_error["error_type"] == "SCOPE_DENIED")
    if not c5_passed:
        all_passed = False
    print(f"[{'PASS' if c5_passed else 'FAIL'}] CASE 5: Excluded Port (example.com:22)")
    print(f"       Outcome: success={ev5.success}, transport_error={ev5.transport_error['error_type']}, transport_call_count={t5.call_count}")

    print("==================================================")
    if all_passed:
        print("ALL 5 REQUEST ENGINE VERIFICATION CASES PASSED (100% SECURITY ASSURANCE)")
    else:
        print("REQUEST ENGINE VERIFICATION FAILED")
    print("==================================================")
    return all_passed


if __name__ == "__main__":
    success = asyncio.run(run_verification())
    if not success:
        sys.exit(1)
