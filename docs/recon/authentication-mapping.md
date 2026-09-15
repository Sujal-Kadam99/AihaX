# Authentication Surface & Context Mapping Engine

## 1. Authentication Surface Mapping

The `AuthMapper` module inspects discovered endpoints to determine whether authentication is required, what authentication scheme is enforced, and how campaign `AuthenticationContext` instances should bind to targets.

### Detection Criteria
1. **HTTP Status Codes**:
   - `401 Unauthorized`: Endpoint strictly requires authentication. Inspects `WWW-Authenticate` header (e.g. `Bearer`, `Basic`, `Digest`, `Negotiate`).
   - `403 Forbidden`: Authenticated or authorized role required.
2. **Login Form Indicators**:
   - HTML containing `type="password"`, `name="password"`, `name="passwd"`, `name="pwd"`.
   - Endpoint classified as `EndpointType.AUTHENTICATION` with `auth_required = AuthRequirement.PUBLIC` (login form itself is publicly accessible).
3. **URL & Path Conventions**:
   - URLs containing `/login`, `/signin`, `/oauth/token`, `/auth/token`, `/api/v1/auth`.

---

## 2. Authentication Requirement States

```python
class AuthRequirement(str, Enum):
    PUBLIC = "PUBLIC"                                   # Accessible without credentials
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED" # Returns 401/403 or requires session
    OPTIONAL = "OPTIONAL"                               # Differential response with/without token
    UNKNOWN = "UNKNOWN"                                 # Unprobed or unverified
```

---

## 3. Campaign Authentication Context Binding

When a campaign provides configured authentication profiles (e.g. `user_a`, `user_b`, `admin_user`), `AuthMapper` maps endpoints to appropriate execution contexts for C067–C077 access control checks (IDOR, BOLA, BFLA, Privilege Escalation).
