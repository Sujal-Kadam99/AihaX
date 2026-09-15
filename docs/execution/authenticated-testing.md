# Authenticated Vulnerability Testing & Privilege Escalation

## 1. Overview

AihaX supports authenticated bug bounty testing using isolated `AuthenticationContext` structures. Checks requiring authentication (such as C070 Mass Assignment, C071 Privilege Escalation, and C072 Insecure Direct Object Reference) evaluate permissions across roles while strictly maintaining authorization boundaries.

---

## 2. Authentication Context Structure

```python
@dataclass
class AuthenticationContext:
    name: str  # e.g., "admin_user", "tenant_a_member", "tenant_b_member"
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    roles: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
```

---

## 3. Privilege Escalation & Authorization Matrix Testing

When testing for authorization flaws:
1. **Unauthenticated Baseline**: Request executed without credentials $\rightarrow$ Expects `401 Unauthorized` or `403 Forbidden`.
2. **Low-Privilege User A**: Request executed with User A session $\rightarrow$ Captures baseline resource state.
3. **Cross-Tenant User B Mutation**: Low-privilege User B attempts to access or modify User A's resource:
   - If response status is `200 OK` and resource data for User A is exposed $\rightarrow$ **IDOR Candidate** confirmed.
   - If response status is `403 Forbidden` $\rightarrow$ **Access Denied (Secure)**.
4. **Vertical Privilege Escalation**: Regular user session sends administrative request:
   - If administrative operation succeeds without admin role $\rightarrow$ **Privilege Escalation Candidate** confirmed.

---

## 4. Sensitive Credential Redaction Invariant

Whenever an `AuthenticationContext` is attached to a `RequestSpec`:
- Header values for `Authorization`, `Cookie`, `X-Api-Key`, `Token`, and `Secret` are cryptographically redacted in logs and audit artifacts.
- Cryptographic SHA-256 hashes of credentials verify execution integrity without exposing plaintext tokens.
