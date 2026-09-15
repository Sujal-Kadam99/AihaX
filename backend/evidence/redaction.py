"""AihaX Phase 8 — Evidence Vault Secret Redaction Engine.

Ensures sensitive authentication materials, tokens, passwords, cookies,
and API keys are completely stripped before entering persistent storage.

Invariants:
- Secrets NEVER enter persistent evidence.
- Redaction is deterministic and non-reversible in storage.
- Covers headers, URL queries, JSON bodies, form data, and raw text.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Union

# Comprehensive secret redaction patterns
REDACTION_PATTERNS: List[tuple[re.Pattern, str]] = [
    # Authorization header values (Bearer, Basic, Token)
    (re.compile(r"(Authorization:\s*(?:Bearer|Basic|Token|Digest)\s+)[^\s\r\n]+", re.IGNORECASE), r"\1[REDACTED]"),
    # Cookie header values
    (re.compile(r"(Cookie:\s*)[^\r\n]+", re.IGNORECASE), r"\1[REDACTED]"),
    # Set-Cookie headers in responses
    (re.compile(r"(Set-Cookie:\s*)[^\r\n]+", re.IGNORECASE), r"\1[REDACTED]"),
    # JWT tokens (header.payload.signature)
    (re.compile(r"eyJ[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]+"), "[REDACTED-JWT]"),
    # AWS Access Key IDs
    (re.compile(r"(AKIA|ASIA)[A-Z0-9]{16}", re.IGNORECASE), r"[REDACTED-AWS-KEY]"),
    # API key patterns (URL param or JSON field)
    (re.compile(r"((?:api[_\-]?key|apikey|secret|token|auth[_\-]?token|access[_\-]?token)[\"']?\s*[:=]\s*[\"']?)[^\s&,\}\]\r\n\"']+", re.IGNORECASE), r"\1[REDACTED]"),
    # Password parameters & fields
    (re.compile(r"((?:password|passwd|pwd|pass)[\"']?\s*[:=]\s*[\"']?)[^\s&,\}\]\r\n\"']+", re.IGNORECASE), r"\1[REDACTED]"),
    # Session identifiers
    (re.compile(r"((?:session[_\-]?id|sess[_\-]?id|sid|phpsessid|jsessionid|asp\.net_sessionid)[\"']?\s*[:=]\s*[\"']?)[^\s&,\}\]\r\n\"']+", re.IGNORECASE), r"\1[REDACTED]"),
    # Private RSA / EC / PGP keys
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "[REDACTED-PRIVATE-KEY]"),
    # Generic bearer tokens
    (re.compile(r"(bearer\s+)[a-zA-Z0-9\-._~+/]+=*", re.IGNORECASE), r"\1[REDACTED]"),
]


def redact_secrets(text: Optional[str]) -> str:
    """Apply all secret redaction patterns to a text string."""
    if not text:
        return ""
    result = str(text)
    for pattern, replacement in REDACTION_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_dictionary(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively redact string values and sensitive keys in a dictionary."""
    sensitive_keys = {
        "password", "passwd", "pwd", "secret", "token", "authorization",
        "cookie", "set-cookie", "api_key", "apikey", "session", "access_token", "refresh_token"
    }
    redacted: Dict[str, Any] = {}
    for k, v in data.items():
        k_lower = str(k).lower()
        if isinstance(v, dict):
            redacted[k] = redact_dictionary(v)
        elif isinstance(v, list):
            redacted[k] = [
                redact_dictionary(i) if isinstance(i, dict) else (redact_secrets(i) if isinstance(i, str) else i)
                for i in v
            ]
        elif any(s == k_lower or f"_{s}" in k_lower or f"{s}_" in k_lower for s in sensitive_keys):
            redacted[k] = "[REDACTED]"
        elif isinstance(v, str):
            redacted[k] = redact_secrets(v)
        else:
            redacted[k] = v
    return redacted


def contains_unredacted_secrets(text: Optional[str]) -> bool:
    """Check if text contains patterns matching unredacted secrets."""
    if not text:
        return False
    suspicious_patterns = [
        r"eyJ[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]+",
        r"(AKIA|ASIA)[A-Z0-9]{16}",
        r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
        r"Authorization:\s*Bearer\s+(?!\[REDACTED\])[a-zA-Z0-9\-_.]+",
    ]
    for p in suspicious_patterns:
        if re.search(p, text):
            return True
    return False
