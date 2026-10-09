# AihaX Authorized Live Reconnaissance Mode

## Mandatory Live Preflight Checklist

Authorized Live Recon Mode may invoke real providers (Subfinder, Amass, crt.sh, DNS resolution, HTTP probing) only after **all** of the following conditions are verified:

1. **Operator Selection**: The operator explicitly starts a `mode=live` recon run. Passive OSINT and low-impact HTTP discovery are included; active service and path discovery are opt-in per run.
2. **Valid Authorization Record**: A non-expired authorization record ID and a written-scope reference (client ticket, contract, or equivalent) are recorded.
3. **Concrete Target**: Target is a single, concrete URL/host (e.g. `https://authorized.example.com`). Wildcard-only targets (`*.example.com`) are rejected.
4. **Scope Gating**: The concrete target passes `ScopeValidator`.
5. **Destination Safety (Anti-SSRF)**: Destination resolves to a non-private, non-metadata IP.
6. **Provider Policy**: Every requested provider is in the approved allowlist.
7. **Budgets Configured**: Request budgets and concurrency limits are non-zero. Optional Nmap discovery is restricted to TCP 80, 443, 8080, and 8443 with `-T2`; optional Gobuster discovery uses the bundled small wordlist and two workers.
8. **Operator Confirmation**: Explicit human confirmation with warning acknowledgment.
9. **Audit Trail**: Execution ID and preflight approval are recorded in the audit trail.

If any check fails, execution fails closed with `BLOCKED_AUTHORIZATION`, `BLOCKED_SCOPE`, `BLOCKED_SAFETY`, `BLOCKED_TARGET`, or `BLOCKED_BUDGET`.

## Operator launch behavior

The campaign recon modal requires all four operator acknowledgments on every live run. It offers two additional opt-ins: `service_discovery` (the bounded web-port Nmap profile) and `content_discovery` (the bounded wordlist profile). Only selected profiles are enabled in the server-side validation engine, and the selected capabilities are recorded in the audit event. Nuclei and Dalfox remain excluded because this is a reconnaissance run, not vulnerability testing.

The older `ReconAgent` defaults to `AUDIT` and treats authorization as absent unless the caller explicitly supplies it. This prevents a normal scan configuration from silently entering live subprocess mode. Use the operator live recon workflow for campaigns that need passive and active live discovery.
