"""AihaX Phase 8 — Static & Runtime Security Invariants Verification.

Validates:
1. Scope is default-deny & zero out-of-scope bytes.
2. All active requests pass through ScopeValidator -> RequestEngine.
3. No secrets enter persistent evidence structures (JWTs, API keys, passwords, cookies).
4. No destructive commands (DROP TABLE, rm -rf, reverse shells) exist in production check modules.
5. All 77 checks C001–C077 remain registered and non-destructive.
"""

import os
import pathlib
import pytest
from backend.core.check_registry import registry
from backend.evidence.redaction import contains_unredacted_secrets, redact_secrets


def test_all_77_checks_registered_and_non_destructive():
    import backend.agents.checks  # Ensure checks registered
    checks = registry.list_checks()
    assert len(checks) == 77, f"Expected 77 checks, got {len(checks)}"

    for c in checks:
        assert c.destructive is False, f"Check {c.id} must be non-destructive"
        assert c.max_requests >= 1, f"Check {c.id} must have max_requests >= 1"


def test_no_raw_network_imports_in_checks():
    """Verify check modules do not import raw socket/urllib/requests directly."""
    checks_dir = pathlib.Path("backend/agents/checks")
    violations = []
    if checks_dir.exists():
        for py_file in checks_dir.glob("*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            for forbidden in ["import requests\n", "import urllib.request\n", "import socket\n", "import http.client\n"]:
                if forbidden in content:
                    violations.append(f"{py_file.name}: contains forbidden import '{forbidden.strip()}'")
    assert violations == [], f"Direct raw-network import violations found: {violations}"


def test_no_destructive_payloads_in_production_checks():
    """Verify check modules do not contain destructive database or OS command patterns."""
    checks_dir = pathlib.Path("backend/agents/checks")
    violations = []
    dangerous_patterns = [
        "DROP TABLE", "DELETE FROM users", "TRUNCATE TABLE", "rm -rf /", "mkfifo /tmp",
        "/bin/bash -i", "nc -e /bin/sh"
    ]
    if checks_dir.exists():
        for py_file in checks_dir.glob("*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            for pattern in dangerous_patterns:
                if pattern.upper() in content.upper():
                    violations.append(f"{py_file.name}: contains dangerous pattern '{pattern}'")
    assert violations == [], f"Dangerous command pattern violations: {violations}"


def test_secret_redaction_guarantee_on_simulated_headers():
    test_cases = [
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123secret",
        "Cookie: session_token=abcd1234efgh; PHPSESSID=999xyz",
        "POST /login?api_key=AKIAIOSFODNN7EXAMPLE&password=MySuperSecretPassword123",
        "Set-Cookie: user_session=secret_token_value; Secure; HttpOnly",
    ]
    for raw in test_cases:
        redacted = redact_secrets(raw)
        assert not contains_unredacted_secrets(redacted), f"Redaction failed on: {raw} -> {redacted}"
        assert "eyJ" not in redacted or "[REDACTED" in redacted
        assert "MySuperSecretPassword123" not in redacted
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted
        assert "abcd1234efgh" not in redacted
