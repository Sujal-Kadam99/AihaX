"""AihaX Phase 8 — Secret Redaction Engine Unit Tests."""

import pytest
from backend.evidence.redaction import (
    contains_unredacted_secrets,
    redact_dictionary,
    redact_secrets,
)


def test_jwt_redaction():
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    redacted = redact_secrets(text)
    assert "eyJ" not in redacted or "[REDACTED" in redacted
    assert "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" not in redacted


def test_password_redaction():
    text = "POST /login HTTP/1.1\n\nusername=admin&password=SuperSecretPassword!&token=xyz"
    redacted = redact_secrets(text)
    assert "SuperSecretPassword!" not in redacted
    assert "[REDACTED]" in redacted


def test_cookie_redaction():
    text = "Cookie: session_id=abc123secret; auth_token=999xyz\nUser-Agent: Mozilla"
    redacted = redact_secrets(text)
    assert "abc123secret" not in redacted
    assert "999xyz" not in redacted


def test_aws_key_redaction():
    text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    redacted = redact_secrets(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED-AWS-KEY]" in redacted


def test_redact_dictionary_recursive():
    payload = {
        "user": "alice",
        "password": "mypassword",
        "auth_details": {
            "token": "tok_12345",
            "metadata": "public",
        },
        "headers": ["Cookie: sess=secret123", "Host: example.com"],
    }
    redacted = redact_dictionary(payload)
    assert redacted["password"] == "[REDACTED]"
    assert redacted["auth_details"]["token"] == "[REDACTED]"
    assert redacted["auth_details"]["metadata"] == "public"
    assert "secret123" not in str(redacted["headers"])


def test_contains_unredacted_secrets_detector():
    unredacted = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.some_secret_sig"
    assert contains_unredacted_secrets(unredacted) is True

    redacted = "Authorization: Bearer [REDACTED]"
    assert contains_unredacted_secrets(redacted) is False
