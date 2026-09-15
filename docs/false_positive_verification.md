# AihaX — False Positive Verification Controls

## Deterministic False-Positive Rules
The `FalsePositiveGate` eliminates spurious scanner alerts via strict rules:
1. **Transport Redirection**: Cleartext HTTP (Port 80) responses returning HTTP 301, 302, 307, or 308 with `Location: https://` are classified as `FALSE_POSITIVE` with 100% confidence penalty.
2. **Contradictory Header Presence**: Findings claiming missing CSP, X-Frame-Options, HSTS, or X-Content-Type-Options are verified against the raw response headers. If present, the finding is marked `FALSE_POSITIVE`.
3. **Access Control Enforcement**: Findings claiming authorization bypass or IDOR that received HTTP 401, 403, or "Access Denied" are classified as `FALSE_POSITIVE`.
4. **Generic Server Error Pages**: Findings claiming information disclosure based on default Apache, Nginx, or Cloudflare 404/500 templates are rejected as `FALSE_POSITIVE`.
