# AihaX Phase 8 — Evidence Vault & Secret Redaction Engine

## 1. Non-Negotiable Contract: Zero Secrets in Persistent Evidence
Sensitive authentication material must never enter persistent storage.
The Evidence Vault (`backend/evidence/`) enforces strict pre-storage redaction across:
* `Authorization: Bearer ...` (JWT tokens and bearer strings replaced with `[REDACTED-JWT]` or `[REDACTED]`)
* `Cookie: ...` & `Set-Cookie: ...` (session cookies replaced with `[REDACTED]`)
* Passwords, API keys, AWS access keys (`AKIA...`), and private cryptographic keys

## 2. Cryptographic Content Hashing (SHA-256)
Evidence records are content-addressed:
```python
content_hash = SHA256(canonical_json({
    "evidence_type": evidence_type,
    "target_url": target_url,
    "method": method,
    "sanitized_request": sanitized_request,
    "sanitized_response": sanitized_response,
    "payload_summary": payload_summary,
}))
```

## 3. Evidence Hash Chaining
Sequential evidence artifacts within a campaign are linked via cryptographic hash chaining:
```python
chain_hash = SHA256(content_hash + "|" + previous_chain_hash + "|" + timestamp)
```
Any database modification, row deletion, or payload modification is immediately flagged during `verify_campaign_integrity()`.
