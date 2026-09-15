# AihaX Authorized Live Reconnaissance Mode

## Mandatory Live Preflight Checklist

Authorized Live Recon Mode may invoke real providers (Subfinder, Amass, crt.sh, DNS resolution, HTTP probing) only after **all** of the following conditions are verified:

1. **Operator Selection**: The operator explicitly selects `AUTHORIZED_LIVE_RECON` mode.
2. **Valid Authorization Record**: A non-expired authorization record ID is supplied.
3. **Concrete Target**: Target is a single, concrete URL/host (e.g. `https://authorized.example.com`). Wildcard-only targets (`*.example.com`) are rejected.
4. **Scope Gating**: The concrete target passes `ScopeValidator`.
5. **Destination Safety (Anti-SSRF)**: Destination resolves to a non-private, non-metadata IP.
6. **Provider Policy**: Every requested provider is in the approved allowlist.
7. **Budgets Configured**: Request budgets and concurrency limits are non-zero.
8. **Operator Confirmation**: Explicit human confirmation with warning acknowledgment.
9. **Audit Trail**: Execution ID and preflight approval are recorded in the audit trail.

If any check fails, execution fails closed with `BLOCKED_AUTHORIZATION`, `BLOCKED_SCOPE`, `BLOCKED_SAFETY`, `BLOCKED_TARGET`, or `BLOCKED_BUDGET`.
