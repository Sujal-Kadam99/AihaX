"""Comprehensive Security Tests for ScopeValidator and Asset Normalization.

Tests all 20+ requirements including safe wildcard isolation, userinfo attack resistance,
exclusion precedence, path filters, port constraints, and default deny.
"""

import pytest

from backend.core.scope_validator import (
    ScopeDecision,
    ScopeStatus,
    ScopeValidator,
    normalize_domain,
    normalize_url,
)


class TestAssetNormalization:
    def test_normalize_domain_cases_and_spaces(self):
        assert normalize_domain("  ExAmPlE.CoM  ") == "example.com"
        assert normalize_domain("API.Example.com.") == "api.example.com"

    def test_normalize_domain_strips_ports_and_creds(self):
        assert normalize_domain("admin:secret@api.example.com:8443") == "api.example.com"
        assert normalize_domain("target.com:8080") == "target.com"

    def test_normalize_url_userinfo_defense(self):
        # Userinfo spoofing attack: user tries to trick validator with example.com in auth section
        scheme, host, port, path = normalize_url("https://example.com@evil.com/dashboard")
        assert host == "evil.com"
        assert scheme == "https"
        assert port == 443
        assert path == "/dashboard"

    def test_normalize_url_with_custom_port_and_path(self):
        scheme, host, port, path = normalize_url("http://api.target.com:8000/v1/users?id=123#fragment")
        assert scheme == "http"
        assert host == "api.target.com"
        assert port == 8000
        assert path == "/v1/users"

    def test_normalize_url_malformed_raises(self):
        with pytest.raises(ValueError):
            normalize_url("")
        with pytest.raises(ValueError):
            normalize_url("ftp://unsupported.com")


class TestScopeValidatorPrecedenceAndSecurity:
    def test_exact_domain_match(self):
        validator = ScopeValidator(in_scope_assets=["example.com"])
        res = validator.is_host_in_scope("example.com")
        assert res.allowed is True
        assert res.status == ScopeStatus.IN_SCOPE
        assert res.matched_rule == "example.com"

    def test_subdomain_match_with_wildcard(self):
        validator = ScopeValidator(in_scope_assets=["*.example.com"])
        res = validator.is_host_in_scope("api.example.com")
        assert res.allowed is True
        assert res.status == ScopeStatus.IN_SCOPE

        res_deep = validator.is_host_in_scope("auth.api.example.com")
        assert res_deep.allowed is True
        assert res_deep.status == ScopeStatus.IN_SCOPE

    def test_wildcard_does_not_implicitly_match_root(self):
        # Strict wildcard isolation: *.example.com does not include root example.com
        validator = ScopeValidator(in_scope_assets=["*.example.com"])
        res = validator.is_host_in_scope("example.com")
        assert res.allowed is False
        assert res.status == ScopeStatus.DENIED_BY_DEFAULT

    def test_wildcard_isolation_from_malicious_suffixes(self):
        # Prevent example.com.evil.com from matching *.example.com
        validator = ScopeValidator(in_scope_assets=["*.example.com"])
        res = validator.is_host_in_scope("example.com.evil.com")
        assert res.allowed is False
        assert res.status == ScopeStatus.DENIED_BY_DEFAULT

    def test_wildcard_isolation_from_prefix_collision(self):
        # Prevent evil-example.com from matching *.example.com
        validator = ScopeValidator(in_scope_assets=["*.example.com"])
        res = validator.is_host_in_scope("evil-example.com")
        assert res.allowed is False
        assert res.status == ScopeStatus.DENIED_BY_DEFAULT

    def test_explicit_exclusion_overrides_wildcard_inclusion(self):
        # Precedence: EXPLICIT EXCLUSION > WILDCARD INCLUSION
        validator = ScopeValidator(
            in_scope_assets=["*.example.com"],
            out_of_scope_assets=["admin.example.com"],
        )
        res_allowed = validator.is_host_in_scope("api.example.com")
        assert res_allowed.allowed is True

        res_blocked = validator.is_host_in_scope("admin.example.com")
        assert res_blocked.allowed is False
        assert res_blocked.status == ScopeStatus.OUT_OF_SCOPE
        assert "explicitly marked out-of-scope" in res_blocked.reason

    def test_explicit_exclusion_overrides_explicit_inclusion(self):
        # Precedence: EXPLICIT EXCLUSION > EXPLICIT INCLUSION
        validator = ScopeValidator(
            in_scope_assets=["test.example.com"],
            out_of_scope_assets=["test.example.com"],
        )
        res = validator.is_host_in_scope("test.example.com")
        assert res.allowed is False
        assert res.status == ScopeStatus.OUT_OF_SCOPE

    def test_url_validation_userinfo_scope_bypass_blocked(self):
        # An attacker attempts: https://example.com@evil.com/
        validator = ScopeValidator(in_scope_assets=["example.com"])
        res = validator.is_url_in_scope("https://example.com@evil.com/login")
        assert res.allowed is False
        assert res.status == ScopeStatus.DENIED_BY_DEFAULT
        assert "evil.com" in res.reason

    def test_url_validation_query_string_scope_bypass_blocked(self):
        # An attacker attempts: https://evil.com/?q=https://example.com
        validator = ScopeValidator(in_scope_assets=["example.com"])
        res = validator.is_url_in_scope("https://evil.com/?q=https://example.com")
        assert res.allowed is False
        assert res.status == ScopeStatus.DENIED_BY_DEFAULT

    def test_url_validation_fragment_handling(self):
        validator = ScopeValidator(in_scope_assets=["example.com"])
        res = validator.is_url_in_scope("https://example.com/profile#settings")
        assert res.allowed is True
        assert res.status == ScopeStatus.IN_SCOPE

    def test_port_restriction_enforcement(self):
        validator = ScopeValidator(
            in_scope_assets=["example.com"],
            allowed_ports=[80, 443],
            excluded_ports=[8080],
        )
        assert validator.is_port_in_scope("example.com", 443).allowed is True
        assert validator.is_port_in_scope("example.com", 8080).allowed is False
        assert validator.is_port_in_scope("example.com", 22).allowed is False

    def test_scheme_restriction(self):
        validator = ScopeValidator(
            in_scope_assets=["example.com"],
            allowed_schemes=["https"],
        )
        assert validator.is_url_in_scope("https://example.com/app").allowed is True
        assert validator.is_url_in_scope("http://example.com/app").allowed is False

    def test_excluded_paths_rule(self):
        validator = ScopeValidator(
            in_scope_assets=["example.com"],
            excluded_paths=["/admin/*", "/internal/metrics"],
        )
        assert validator.is_url_in_scope("https://example.com/api/v1/data").allowed is True
        assert validator.is_url_in_scope("https://example.com/admin/users").allowed is False
        assert validator.is_url_in_scope("https://example.com/internal/metrics").allowed is False

    def test_default_deny_when_empty_scope(self):
        validator = ScopeValidator(in_scope_assets=[])
        res = validator.is_host_in_scope("example.com")
        assert res.allowed is False
        assert res.status == ScopeStatus.DENIED_BY_DEFAULT

    def test_invalid_target_handling(self):
        validator = ScopeValidator(in_scope_assets=["example.com"])
        res = validator.is_host_in_scope("")
        assert res.allowed is False
        assert res.status == ScopeStatus.INVALID

    def test_phase2_request_engine_hook(self):
        validator = ScopeValidator(
            in_scope_assets=["api.example.com"],
            excluded_paths=["/auth/logout"],
        )
        # Hook signature for Phase 2 Request Engine
        dec1 = validator.validate_request("https://api.example.com/v1/feed", method="GET")
        assert dec1.allowed is True

        dec2 = validator.validate_request("https://api.example.com/auth/logout", method="POST")
        assert dec2.allowed is False
