import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.core.scope_validator import ScopeStatus, ScopeValidator


def run_scope_matrix():
    print("==================================================")
    print("AihaX Bug Bounty Platform — Scope Verification Matrix")
    print("==================================================")

    validator = ScopeValidator(
        in_scope_assets=[
            "example.com",
            "*.example.com",
            "https://partner.com/api/*",
        ],
        out_of_scope_assets=[
            "admin.example.com",
            "billing.example.com",
            "https://partner.com/api/internal/*",
        ],
        allowed_ports=[80, 443, 8443],
        excluded_ports=[8080, 22, 3389],
        allowed_schemes=["https", "http"],
        excluded_paths=["/admin/*", "/metrics"],
    )

    test_cases = [
        # (name, target, expected_allowed, expected_status)
        ("1. Exact Domain Match", "https://example.com", True, ScopeStatus.IN_SCOPE),
        ("2. Subdomain Wildcard Match", "https://api.example.com/v1", True, ScopeStatus.IN_SCOPE),
        ("3. Deep Subdomain Match", "https://dev.auth.example.com", True, ScopeStatus.IN_SCOPE),
        ("4. Explicit Subdomain Exclusion", "https://admin.example.com", False, ScopeStatus.OUT_OF_SCOPE),
        ("5. Explicit Billing Exclusion", "https://billing.example.com/checkout", False, ScopeStatus.OUT_OF_SCOPE),
        ("6. Malicious Suffix Attack", "https://example.com.evil.com", False, ScopeStatus.DENIED_BY_DEFAULT),
        ("7. Malicious Prefix Attack", "https://evil-example.com", False, ScopeStatus.DENIED_BY_DEFAULT),
        ("8. Userinfo Spoofing Attack", "https://example.com@evil.com/app", False, ScopeStatus.DENIED_BY_DEFAULT),
        ("9. Query String Bypass Attack", "https://evil.com/?q=https://example.com", False, ScopeStatus.DENIED_BY_DEFAULT),
        ("10. Fragment Preservation", "https://example.com/app#overview", True, ScopeStatus.IN_SCOPE),
        ("11. Excluded Port Block", "https://example.com:8080/data", False, ScopeStatus.OUT_OF_SCOPE),
        ("12. Excluded Path Block", "https://example.com/admin/config", False, ScopeStatus.OUT_OF_SCOPE),
        ("13. Allowed Path In Scope", "https://partner.com/api/v1/users", True, ScopeStatus.IN_SCOPE),
        ("14. Excluded Sub-Path Block", "https://partner.com/api/internal/secrets", False, ScopeStatus.OUT_OF_SCOPE),
        ("15. Unrelated Foreign Host", "https://attacker.org", False, ScopeStatus.DENIED_BY_DEFAULT),
    ]

    all_passed = True
    results = []

    for name, target, expected_allowed, expected_status in test_cases:
        decision = validator.is_url_in_scope(target)
        passed = (decision.allowed == expected_allowed) and (decision.status == expected_status)
        if not passed:
            all_passed = False

        status_str = "PASS" if passed else "FAIL"
        results.append({
            "name": name,
            "target": target,
            "allowed": decision.allowed,
            "status": decision.status.value,
            "passed": passed,
            "reason": decision.reason,
        })
        print(f"[{status_str}] {name}")
        print(f"       Target: {target}")
        print(f"       Outcome: allowed={decision.allowed}, status={decision.status.value}")
        print(f"       Reason: {decision.reason}\n")

    print("==================================================")
    if all_passed:
        print(f"ALL {len(test_cases)} SCOPE MATRIX TESTS PASSED (100% DETERMINISTIC SAFETY)")
    else:
        print("SCOPE MATRIX FAILED — INVESTIGATE OUTCOMES")
    print("==================================================")

    return all_passed, results


if __name__ == "__main__":
    success, _ = run_scope_matrix()
    if not success:
        sys.exit(1)
